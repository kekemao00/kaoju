#!/usr/bin/env python3
"""免费节点订阅普查（ss / vmess / vless / trojan 等）：只做最新快照的静态分析。

口径：
- “节点”= (协议, 主机, 端口, 凭据, 传输参数) 去重后的一条，只有名称不同的算同一个；“端点”= (主机, 端口)。
  传输参数指分享链接的查询参数（vmess 取 net、host、path、sni、tls）。经 CDN 中转的节点常常
  主机和凭据相同、只有 host/sni/path 不同，它们指向不同的后端，所以算不同节点。
- 只解析分享链接里写明的字段，不连接任何节点，所以这里没有可用率。
- “要求跳过证书校验”指链接里带 allowInsecure / insecure / skip-cert-verify 之类的标志。

用法：
  python3 nodes_census.py --nodes-dir <克隆目录> --ipdb-dir <ASN 库目录> --out out/
"""
from __future__ import annotations

import argparse
import base64
import bisect
import collections
import csv
import ipaddress
import json
import pathlib
import re
import sys
import urllib.parse

SOURCES = [
    ("barry-far/V2ray-config", "barry-far__V2ray-config", "All_Configs_Sub.txt"),
    ("MatinGhanbari/v2ray-configs", "MatinGhanbari__v2ray-configs", "subscriptions/base64/all_sub.txt"),
    ("mahdibland/V2RayAggregator", "mahdibland__V2RayAggregator", "sub/sub_merge.txt"),
    ("mheidari98/.proxy", "mheidari98__.proxy", "all"),
    ("peasoft/NoMoreWalls", "peasoft__NoMoreWalls", "list_raw.txt"),
    ("chengaopan/AutoMergePublicNodes", "chengaopan__AutoMergePublicNodes", "list_raw.txt"),
    ("mfuu/v2ray", "mfuu__v2ray", "sub"),
    ("aiboboxx/v2rayfree", "aiboboxx__v2rayfree", "sub"),
    ("Pawdroid/Free-servers", "Pawdroid__Free-servers", "sub"),
    ("snakem982/proxypool", "snakem982__proxypool", "source/v2ray-2.txt"),
    ("roosterkid/openproxylist (V2RAY)", "roosterkid__openproxylist", "V2RAY_RAW.txt"),
]

TLS_SCHEMES = {"trojan", "vless", "vmess", "hysteria2", "hy2", "tuic", "hysteria", "anytls"}
INSECURE_KEYS = ("allowinsecure", "insecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify")
TRUE_VALUES = {"1", "true", "yes"}
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def b64decode_loose(s: str) -> bytes | None:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return None


def load_text(path: pathlib.Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if "://" in raw[:4000]:
        return raw
    dec = b64decode_loose("".join(raw.split()))
    return dec.decode("utf-8", errors="replace") if dec else raw


def parse_uri(line: str):
    """返回 dict(scheme, host, port, cred, insecure, tls) 或 None。"""
    m = re.match(r"^([a-zA-Z0-9]+)://(.*)$", line.strip())
    if not m:
        return None
    scheme, rest = m.group(1).lower(), m.group(2)
    if scheme == "hy2":
        scheme = "hysteria2"
    try:
        if scheme == "vmess":
            dec = b64decode_loose(rest.split("#")[0].split("?")[0])
            if not dec:
                return None
            j = json.loads(dec.decode("utf-8", errors="replace"))
            host = str(j.get("add", "")).strip().lower()
            port = int(str(j.get("port", "0")).strip() or 0)
            insecure = any(str(j.get(k, "")).lower() in TRUE_VALUES for k in
                           ("allowInsecure", "skip-cert-verify", "insecure")) or j.get("verify_cert") is False
            extra = tuple(str(j.get(k, "")).strip().lower() for k in ("net", "host", "path", "sni", "tls"))
            return {"scheme": scheme, "host": host, "port": port, "cred": str(j.get("id", "")), "extra": extra,
                    "insecure": insecure, "tls": str(j.get("tls", "")).lower() in ("tls", "reality", "xtls"),
                    "net": norm_net(str(j.get("net", ""))), "sec": str(j.get("tls", "")).strip().lower() or "none"}
        if scheme == "ssr":
            dec = b64decode_loose(rest)
            if not dec:
                return None
            main = dec.decode("utf-8", errors="replace").split("/?")[0]
            parts = main.split(":")
            if len(parts) < 6:
                return None
            return {"scheme": scheme, "host": ":".join(parts[:-5]).lower(), "port": int(parts[-5]),
                    "cred": ":".join(parts[-4:]), "extra": (), "insecure": False, "tls": False}
        if scheme == "ss":
            body = rest.split("#")[0]
            if "@" not in body:
                dec = b64decode_loose(body.split("?")[0])
                if not dec:
                    return None
                body = dec.decode("utf-8", errors="replace")
                cred, _, hp = body.rpartition("@")
            else:
                cred, _, hp = body.rpartition("@")
                dec = b64decode_loose(urllib.parse.unquote(cred))
                if dec and b":" in dec:
                    cred = dec.decode("utf-8", errors="replace")
            plugin = hp.partition("?")[2].lower()
            hp = hp.split("?")[0].split("/")[0]
            host, _, port = hp.rpartition(":")
            return {"scheme": scheme, "host": host.strip("[]").lower(), "port": int(port), "cred": cred,
                    "extra": (plugin,), "insecure": False, "tls": False}
        # 通用形式：scheme://cred@host:port?query#name
        u = urllib.parse.urlsplit(f"{scheme}://{rest}")
        if not u.hostname or not u.port:
            return None
        q = {k.lower(): v[0].lower() for k, v in urllib.parse.parse_qs(u.query).items() if v}
        insecure = any(q.get(k, "") in TRUE_VALUES for k in INSECURE_KEYS)
        sec = q.get("security", "")
        if scheme == "vless":
            tls = sec in ("tls", "reality", "xtls")
        elif scheme in ("trojan", "hysteria2", "tuic", "hysteria", "anytls"):
            tls = sec != "none"
        else:
            tls = False
        return {"scheme": scheme, "host": u.hostname.lower(), "port": u.port,
                "cred": urllib.parse.unquote(u.username or "") + ":" + urllib.parse.unquote(u.password or ""),
                "extra": tuple(sorted(q.items())), "insecure": insecure, "tls": tls,
                "net": norm_net(q.get("type", "")), "sec": sec or ("tls" if scheme == "trojan" else "none"),
                "flow": q.get("flow", ""), "enc": q.get("encryption", "")}
    except Exception:
        return None


# sing-box 文档（docs/configuration/shared/v2ray-transport.md）列出的传输：HTTP、WebSocket、QUIC、gRPC、HTTPUpgrade；
# 不带传输层时就是裸 TCP。分享链接里的 raw 是 Xray 对 tcp 的新叫法，h2 对应 HTTP 传输。
SINGBOX_TRANSPORTS = {"tcp", "ws", "grpc", "http", "h2", "httpupgrade", "quic"}


def norm_net(v: str) -> str:
    v = v.strip().lower()
    if v in ("", "raw"):
        return "tcp"
    if v == "splithttp":
        return "xhttp"
    return v if re.fullmatch(r"[a-z0-9]+", v) else "other"


class RangeDB:
    def __init__(self, csv_path: pathlib.Path):
        self.starts, self.ends, self.values = [], [], []
        with csv_path.open(newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                self.starts.append(int(ipaddress.IPv4Address(row[0])))
                self.ends.append(int(ipaddress.IPv4Address(row[1])))
                self.values.append((row[2], row[3]))

    def lookup(self, ip: str):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect.bisect_right(self.starts, n) - 1
        return self.values[i] if i >= 0 and n <= self.ends[i] else None


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def top_n(counter, n):
    """按次数从多到少取前 n 个；次数相同的按名称排，保证每次运行的结果一样。"""
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes-dir", required=True, type=pathlib.Path)
    ap.add_argument("--ipdb-dir", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args()
    asn_db = RangeDB(next(args.ipdb_dir.glob("**/asn-ipv4.csv")))

    per_source, keys, all_nodes = [], {}, {}
    for name, d, rel in SOURCES:
        path = args.nodes_dir / d / rel
        if not path.exists():
            print(f"[nodes] missing {path}", file=sys.stderr)
            continue
        text = load_text(path)
        uri_lines = [ln for ln in text.splitlines() if "://" in ln and not ln.lstrip().startswith("#")]
        nodes, unparsed = {}, 0
        for ln in uri_lines:
            n = parse_uri(ln)
            if n is None or not n["host"] or not (1 <= n["port"] <= 65535):
                unparsed += 1
                continue
            nodes.setdefault((n["scheme"], n["host"], n["port"], n["cred"], n["extra"]), n)
        by_scheme = collections.Counter(k[0] for k in nodes)
        tls_nodes = [n for n in nodes.values() if n["scheme"] in TLS_SCHEMES and n["tls"]]
        insecure = sum(1 for n in tls_nodes if n["insecure"])
        hosts = {k[1] for k in nodes}
        ip_hosts = {h for h in hosts if IPV4_RE.match(h)}
        asn = collections.Counter()
        for h in ip_hosts:
            a = asn_db.lookup(h)
            asn[a if a else ("?", "未匹配")] += 1
        top = top_n(asn, 1)
        per_source.append({
            "name": name, "uri_lines": len(uri_lines), "unparsed": unparsed, "unique_nodes": len(nodes),
            "unique_endpoints": len({(k[1], k[2]) for k in nodes}), "unique_hosts": len(hosts),
            "ip_literal_host_pct": pct(len(ip_hosts), len(hosts)),
            "by_scheme": dict(by_scheme.most_common()),
            "tls_nodes": len(tls_nodes), "tls_insecure_flag": insecure,
            "tls_insecure_pct": pct(insecure, len(tls_nodes)),
            "cloudflare_ip_host_pct": pct(asn.get(("13335", "Cloudflare, Inc."), 0), len(ip_hosts)),
            "top_asn": top[0][0][1] if top else None, "top_asn_pct": pct(top[0][1], len(ip_hosts)) if top else None,
            "workers_pages_hosts": sum(1 for h in hosts if h.endswith((".workers.dev", ".pages.dev"))),
        })
        keys[name] = set(nodes)
        for k, n in nodes.items():
            all_nodes.setdefault(k, n)
        print(f"[nodes] {name}: lines={len(uri_lines)} nodes={len(nodes)} unparsed={unparsed}", file=sys.stderr)

    names = list(keys)
    counts = collections.Counter()
    for n in names:
        counts.update(keys[n])
    for s in per_source:
        k = keys[s["name"]]
        s["exclusive"] = sum(1 for x in k if counts[x] == 1)
        s["exclusive_pct"] = pct(s["exclusive"], len(k))
    overlap = {a: {b: pct(len(keys[a] & keys[b]), len(keys[a])) for b in names} for a in names}

    union = set(counts)
    scheme_all = collections.Counter(k[0] for k in union)
    pool_tls = [n for n in all_nodes.values() if n["scheme"] in TLS_SCHEMES and n["tls"]]
    pool_insecure = sum(1 for n in pool_tls if n["insecure"])
    pool_hosts = {k[1] for k in union}
    pool_ip_hosts = {h for h in pool_hosts if IPV4_RE.match(h)}
    pool_asn = collections.Counter()
    for h in pool_ip_hosts:
        a = asn_db.lookup(h)
        pool_asn[a if a else ("?", "未匹配")] += 1
    # 传输方式构成（只看 vless / vmess / trojan，ss 没有这一层）
    transport = collections.defaultdict(collections.Counter)
    reality = vision = 0
    for k, n in all_nodes.items():
        if k[0] in ("vless", "vmess", "trojan"):
            transport[k[0]][n.get("net", "tcp")] += 1
            reality += n.get("sec") == "reality"
            vision += n.get("flow", "").startswith("xtls-rprx-vision")
    transport_total = collections.Counter()
    for c in transport.values():
        transport_total.update(c)
    n3 = sum(transport_total.values())
    not_in_singbox = {t: c for t, c in transport_total.most_common() if t not in SINGBOX_TRANSPORTS}
    # vless 的 encryption 参数：sing-box 只支持 none。Xray 新增的加密方式（mlkem768x25519plus 等）连不了
    vless_enc = sum(1 for k, n in all_nodes.items()
                    if k[0] == "vless" and n.get("enc", "") not in ("", "none"))
    out_of_reach = sum(1 for k, n in all_nodes.items() if k[0] in ("vless", "vmess", "trojan") and (
        n.get("net", "tcp") not in SINGBOX_TRANSPORTS or (k[0] == "vless" and n.get("enc", "") not in ("", "none"))))

    result = {
        "sources": per_source,
        "transport": {
            "nodes_vless_vmess_trojan": n3,
            "by_scheme": {s: dict(c.most_common()) for s, c in transport.items()},
            "total": dict(transport_total.most_common()),
            "not_in_singbox": {"nodes": sum(not_in_singbox.values()),
                               "pct_of_vless_vmess_trojan": pct(sum(not_in_singbox.values()), n3),
                               "pct_of_all_nodes": pct(sum(not_in_singbox.values()), len(union)),
                               "by_transport": not_in_singbox},
            "vless_encryption_not_none": vless_enc,
            "out_of_reach_for_singbox": {"nodes": out_of_reach, "pct_of_vless_vmess_trojan": pct(out_of_reach, n3),
                                         "pct_of_all_nodes": pct(out_of_reach, len(union))},
            "reality_nodes": reality, "vision_flow_nodes": vision,
        },
        "pool": {"sum_of_sizes": sum(len(keys[n]) for n in names), "unique_nodes": len(union),
                 "unique_endpoints": len({(k[1], k[2]) for k in union}),
                 "unique_hosts": len(pool_hosts),
                 "ip_literal_hosts": len(pool_ip_hosts),
                 "by_scheme": dict(scheme_all.most_common()),
                 "tls_nodes": len(pool_tls), "tls_insecure_flag": pool_insecure,
                 "tls_insecure_pct": pct(pool_insecure, len(pool_tls)),
                 "top_asn_of_ip_hosts": [{"asn": a[0], "name": a[1], "hosts": c,
                                          "share_pct": pct(c, len(pool_ip_hosts))}
                                         for a, c in top_n(pool_asn, 8)],
                 "workers_pages_hosts": sum(1 for h in pool_hosts if h.endswith((".workers.dev", ".pages.dev")))},
        "overlap_pct_row_in_col": overlap,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "nodes_summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    with (args.out / "nodes_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        cols = ["name", "uri_lines", "unparsed", "unique_nodes", "unique_endpoints", "unique_hosts",
                "ip_literal_host_pct", "tls_nodes", "tls_insecure_flag", "tls_insecure_pct",
                "cloudflare_ip_host_pct", "top_asn", "top_asn_pct", "workers_pages_hosts",
                "exclusive", "exclusive_pct"]
        w.writerow(cols + ["by_scheme"])
        for s in per_source:
            w.writerow([s[c] for c in cols] + [json.dumps(s["by_scheme"])])
    with (args.out / "nodes_overlap_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["row_contained_in_col_pct"] + names)
        for a in names:
            w.writerow([a] + [overlap[a][b] for b in names])
    print(json.dumps(result["pool"], ensure_ascii=False))


if __name__ == "__main__":
    main()
