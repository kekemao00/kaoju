#!/usr/bin/env python3
"""事实提取：把一条运行记录（obsproxy 的事件 + 驱动的结果）提炼成一个“事实”字典。

口径见 ../PROTOCOL.md“矩阵”一节，事件格式见 ../harness/EVENTS.md，运行记录的格式见 README.md。
只用 Python 标准库。derive() 是纯函数：同样的记录得到同样的事实，不读文件、不看时钟。

    python3 runner/derive.py --raw out/raw --out out/observations

对 out/raw/<列>.jsonl.gz 的每一列写 out/observations/<列>.json：

    {"derive_version": 1, "variant": "<列>", "cases": {"<用例>": {"<遍数>": {事实}}}}

键按字典序写出，同样的输入逐字节相同，便于比较。

事实的字段（没有的列表是 []，没有的值是 null）：

- variant、case、repeat
- run：这次运行能不能用。skipped（"only" 或 null）、unsupported（驱动给的原因或 null）、has_result、
  driver_timeout、driver_exit、runner_errors、pcap_status、pcap_problems、tcpdump_dropped、
  events_complete（第一条是 start、最后一条是 end）、late_events、log_errors、k_mismatches
- profile：start 事件里实际生效的配置
- proxy_conn_count、proxy_conns：代理端口上的连接（按接受的先后）。每条有 conn、first_byte（两位十六进制）、
  first_hex、first_kind、n_first_read、end_by、end_close、end_reason、bytes_in、bytes_out
- direct_conn_count、direct_conns：源站端口上的直连，字段同上，另有 listener
- http_requests：代理端口上的请求，按事件的先后（即时间）。conn、seq、form、method、target、version、
  header_names、headers、k、auth（present、scheme、raw、result、user、user_hex、pass_hex、lenient）、
  body_len、body_sha256、error、t；responses 是代理对它回的全部响应（含 1xx），
  response 是其中最后一个非 1xx 的（status、reason、by、cause、close、header_names），proxy_generated 即 by == "proxy"
- tunnels：tunnel、via、conn、req_seq、target_host、target_port、mapped；first（kind、n_first_read、early_bytes、hex、
  record_len、tls_complete、sni、alpn）；close_by、bytes_c2s、bytes_s2c；
  opener：建立它的 CONNECT 的 auth 判定和用户（via=connect），或同一条连接上 socks5_auth 的用户（via=socks5）
- origin_conns：oconn、conn、via、tunnel、listener、tls、alpn、error
- origin_requests：k、via、tunnel、conn、oconn、seq、req_seq、method、path、query、proto、host、header_names、headers、
  has_proxy_authorization、body_len、body_sha256、action、status、tls
- socks：每条 SOCKS5 连接一项。conn、greeting（methods、raw_hex）、selected、auth（user、user_hex、pass_hex、ulen、plen、
  status、result）、request（cmd、atyp、host、port、raw_hex）、reply（rep、cause）
- actions：what、how、k、conn、tunnel、oconn
- steps：驱动的每一步（并发的子步骤摊平）。id、op、ok、status、default_text、extra_text、extra_how
- markers：每一步的 default_text、extra_text 里四个记号各自是否出现

k 从请求目标（http_request.target）或查询串（origin_request.query）的查询参数里取，不用事件自带的 k；
两者不一致的个数记在 run.k_mismatches，供排查仪器。
"""

import argparse
import gzip
import json
import os
import sys
import urllib.parse

DERIVE_VERSION = 1

MARKERS = {
    "reason": "KaojuReasonMarker",
    "header": "KaojuHeaderMarker",
    "status": "KaojuStatusMarker",
    "body": "KaojuBodyMarker",
}

def k_from_query(query):
    """查询串里第一个 k 参数（百分号解码以后）；没有就是 None。"""
    if not query:
        return None
    try:
        vals = urllib.parse.parse_qs(query, keep_blank_values=True, errors="replace").get("k")
    except ValueError:
        return None
    return vals[0] if vals else None


def k_from_target(form, target):
    """从请求目标里取 k。CONNECT 的目标是“主机:端口”，没有查询串。"""
    if form == "connect" or not target:
        return None
    q = target.partition("#")[0].partition("?")[2]
    return k_from_query(q)


def _names(headers):
    return [h[0] for h in headers or [] if isinstance(h, (list, tuple)) and h]


def _headers(headers):
    return [[h[0], h[1] if len(h) > 1 else ""] for h in headers or [] if isinstance(h, (list, tuple)) and h]


def _auth(a):
    a = a or {}
    return {
        "present": bool(a.get("present")),
        "scheme": a.get("scheme"),
        "raw": a.get("raw"),
        "result": a.get("result") or "none",
        "user": a.get("user"),
        "user_hex": a.get("user_hex"),
        "pass_hex": a.get("pass_hex"),
        "lenient": bool(a.get("lenient")),
    }


def _flatten_steps(steps, out):
    for s in steps or []:
        if not isinstance(s, dict):
            continue
        out.append(
            {
                "id": s.get("id"),
                "op": s.get("op"),
                "ok": s.get("ok"),
                "status": s.get("status"),
                "default_text": s.get("default_text"),
                "extra_text": s.get("extra_text"),
                "extra_how": s.get("extra_how"),
            }
        )
        if isinstance(s.get("steps"), list):
            _flatten_steps(s["steps"], out)
    return out


def _marker_hits(text):
    text = text or ""
    return {name: (word in text) for name, word in MARKERS.items()}


def _run_status(rec):
    result = rec.get("result")
    driver = rec.get("driver") or {}
    pc = rec.get("pcap_check") or {}
    td = rec.get("tcpdump") or {}
    events = rec.get("events") or []
    complete = bool(events) and events[0].get("ev") == "start" and events[-1].get("ev") == "end"
    return {
        "skipped": rec.get("skipped"),
        "unsupported": (result or {}).get("unsupported") if isinstance(result, dict) else None,
        "has_result": isinstance(result, dict),
        "driver_timeout": bool(driver.get("timeout")),
        "driver_exit": driver.get("exit"),
        "runner_errors": list(rec.get("runner_errors") or []),
        "pcap_status": pc.get("status"),
        "pcap_problems": len(pc.get("problems") or []),
        "tcpdump_dropped": td.get("dropped"),
        "events_complete": complete,
        "late_events": sum(1 for e in events if e.get("late")),
        "log_errors": sum(1 for e in events if e.get("ev") == "log_error"),
        "k_mismatches": 0,
    }


def derive(rec):
    """一条运行记录 -> 事实字典。纯函数。"""
    events = rec.get("events") or []
    run = _run_status(rec)
    facts = {
        "variant": rec.get("variant"),
        "case": rec.get("case"),
        "repeat": rec.get("repeat"),
        "run": run,
        "profile": None,
        "proxy_conn_count": 0,
        "proxy_conns": [],
        "direct_conn_count": 0,
        "direct_conns": [],
        "http_requests": [],
        "tunnels": [],
        "origin_conns": [],
        "origin_requests": [],
        "socks": [],
        "actions": [],
        "steps": [],
        "markers": {},
    }

    conns = {}  # conn -> 连接的事实
    order = []  # 接受的先后
    responses = {}  # (conn, seq) -> [响应…]
    requests = []
    tunnels = {}
    tunnel_order = []
    socks = {}
    socks_order = []

    def sock(conn):
        if conn not in socks:
            socks[conn] = {"conn": conn, "greeting": None, "selected": None, "auth": None, "request": None, "reply": None}
            socks_order.append(conn)
        return socks[conn]

    for e in events:
        ev = e.get("ev")
        c = e.get("conn")
        if ev == "start":
            facts["profile"] = e.get("profile")
        elif ev == "accept":
            conns[c] = {
                "conn": c,
                "listener": e.get("listener"),
                "first_byte": None,
                "first_hex": None,
                "first_kind": None,
                "n_first_read": None,
                "end_by": None,
                "end_close": None,
                "end_reason": None,
                "bytes_in": None,
                "bytes_out": None,
            }
            order.append(c)
        elif ev == "first_bytes":
            d = conns.get(c)
            if d is not None and d["first_hex"] is None:
                hx = e.get("hex") or ""
                d["first_hex"] = hx
                d["first_byte"] = hx[:2] if len(hx) >= 2 else None
                d["first_kind"] = e.get("kind")
                d["n_first_read"] = e.get("n_first_read")
        elif ev == "conn_end":
            d = conns.get(c)
            if d is not None:
                d["end_by"] = e.get("by")
                d["end_close"] = e.get("close")
                d["end_reason"] = e.get("reason")
                d["bytes_in"] = e.get("bytes_in")
                d["bytes_out"] = e.get("bytes_out")
        elif ev == "http_request":
            k = k_from_target(e.get("form"), e.get("target"))
            if k != e.get("k"):
                run["k_mismatches"] += 1
            requests.append(
                {
                    "conn": c,
                    "seq": e.get("seq"),
                    "t": e.get("t"),
                    "form": e.get("form"),
                    "method": e.get("method"),
                    "target": e.get("target"),
                    "version": e.get("version"),
                    "header_names": _names(e.get("headers")),
                    "headers": _headers(e.get("headers")),
                    "k": k,
                    "auth": _auth(e.get("auth")),
                    "body_len": e.get("body_len"),
                    "body_sha256": e.get("body_sha256"),
                    "error": e.get("error"),
                    "responses": [],
                    "response": None,
                    "proxy_generated": None,
                }
            )
        elif ev == "http_response":
            responses.setdefault((c, e.get("seq")), []).append(
                {
                    "status": e.get("status"),
                    "reason": e.get("reason"),
                    "by": e.get("by"),
                    "cause": e.get("cause"),
                    "close": e.get("close"),
                    "header_names": _names(e.get("headers")),
                }
            )
        elif ev == "tunnel_open":
            t = e.get("tunnel")
            tunnels[t] = {
                "tunnel": t,
                "via": e.get("via"),
                "conn": c,
                "req_seq": e.get("req_seq"),
                "target_host": e.get("target_host"),
                "target_port": e.get("target_port"),
                "mapped": e.get("mapped"),
                "first": None,
                "close_by": None,
                "bytes_c2s": None,
                "bytes_s2c": None,
                "opener": None,
            }
            tunnel_order.append(t)
        elif ev == "tunnel_first_bytes":
            d = tunnels.get(e.get("tunnel"))
            if d is not None and d["first"] is None:
                tls = e.get("tls") or {}
                d["first"] = {
                    "kind": e.get("kind"),
                    "n_first_read": e.get("n_first_read"),
                    "early_bytes": e.get("early_bytes"),
                    "hex": e.get("hex"),
                    "record_len": tls.get("record_len"),
                    "tls_complete": tls.get("complete"),
                    "sni": tls.get("sni"),
                    "alpn": list(tls.get("alpn") or []) if e.get("tls") is not None else None,
                }
        elif ev == "tunnel_close":
            d = tunnels.get(e.get("tunnel"))
            if d is not None:
                d["close_by"] = e.get("by")
                d["bytes_c2s"] = e.get("bytes_c2s")
                d["bytes_s2c"] = e.get("bytes_s2c")
        elif ev == "socks5_greeting":
            sock(c)["greeting"] = {"methods": list(e.get("methods") or []), "raw_hex": e.get("raw_hex")}
        elif ev == "socks5_method":
            sock(c)["selected"] = e.get("selected")
        elif ev == "socks5_auth":
            sock(c)["auth"] = {
                "user": e.get("user"),
                "user_hex": e.get("user_hex"),
                "pass_hex": e.get("pass_hex"),
                "ulen": e.get("ulen"),
                "plen": e.get("plen"),
                "status": e.get("status"),
                "result": e.get("result"),
            }
        elif ev == "socks5_request":
            sock(c)["request"] = {
                "cmd": e.get("cmd"),
                "atyp": e.get("atyp"),
                "host": e.get("host"),
                "port": e.get("port"),
                "raw_hex": e.get("raw_hex"),
            }
        elif ev == "socks5_reply":
            sock(c)["reply"] = {"rep": e.get("rep"), "cause": e.get("cause")}
        elif ev == "origin_conn":
            facts["origin_conns"].append(
                {
                    "oconn": e.get("oconn"),
                    "conn": c,
                    "via": e.get("via"),
                    "tunnel": e.get("tunnel"),
                    "listener": e.get("listener"),
                    "tls": e.get("tls"),
                    "alpn": e.get("alpn"),
                    "error": e.get("error"),
                }
            )
        elif ev == "origin_request":
            k = k_from_query(e.get("query"))
            if k != e.get("k"):
                run["k_mismatches"] += 1
            facts["origin_requests"].append(
                {
                    "k": k,
                    "via": e.get("via"),
                    "tunnel": e.get("tunnel"),
                    "conn": c,
                    "oconn": e.get("oconn"),
                    "seq": e.get("seq"),
                    "req_seq": e.get("req_seq"),
                    "method": e.get("method"),
                    "path": e.get("path"),
                    "query": e.get("query"),
                    "proto": e.get("proto"),
                    "host": e.get("host"),
                    "header_names": _names(e.get("headers")),
                    "headers": _headers(e.get("headers")),
                    "has_proxy_authorization": bool(e.get("has_proxy_authorization")),
                    "body_len": e.get("body_len"),
                    "body_sha256": e.get("body_sha256"),
                    "action": e.get("action"),
                    "status": e.get("status"),
                    "tls": e.get("tls"),
                }
            )
        elif ev == "action":
            facts["actions"].append(
                {
                    "what": e.get("what"),
                    "how": e.get("how"),
                    "k": e.get("k"),
                    "conn": c,
                    "tunnel": e.get("tunnel"),
                    "oconn": e.get("oconn"),
                }
            )

    # 响应挂到请求上（100 的 http_response 排在它的 http_request 之前，所以放到最后统一挂）
    by_conn_seq = {}
    for r in requests:
        rs = responses.get((r["conn"], r["seq"]), [])
        r["responses"] = rs
        final = [x for x in rs if not (isinstance(x.get("status"), int) and 100 <= x["status"] < 200)]
        if final:
            r["response"] = final[-1]
            r["proxy_generated"] = final[-1].get("by") == "proxy"
        by_conn_seq[(r["conn"], r["seq"])] = r
    facts["http_requests"] = requests

    for t in tunnel_order:
        d = tunnels[t]
        if d["via"] == "connect":
            req = by_conn_seq.get((d["conn"], d["req_seq"]))
            if req is not None:
                a = req["auth"]
                d["opener"] = {"kind": "connect", "auth_result": a["result"], "user": a["user"], "user_hex": a["user_hex"]}
        elif d["via"] == "socks5":
            a = (socks.get(d["conn"]) or {}).get("auth")
            d["opener"] = {
                "kind": "socks5",
                "auth_result": a["result"] if a else "none",
                "user": a["user"] if a else None,
                "user_hex": a["user_hex"] if a else None,
            }
        facts["tunnels"].append(d)

    facts["socks"] = [socks[c] for c in socks_order]
    for c in order:
        d = conns[c]
        if d["listener"] == "proxy":
            facts["proxy_conns"].append(d)
        else:
            facts["direct_conns"].append(d)
    facts["proxy_conn_count"] = len(facts["proxy_conns"])
    facts["direct_conn_count"] = len(facts["direct_conns"])

    result = rec.get("result")
    if isinstance(result, dict):
        facts["steps"] = _flatten_steps(result.get("steps"), [])
    for s in facts["steps"]:
        if s["id"] is None:
            continue
        facts["markers"][str(s["id"])] = {
            "default": _marker_hits(s["default_text"]),
            "extra": _marker_hits(s["extra_text"]),
        }
    return facts


def read_raw(path):
    """读 out/raw/<列>.jsonl.gz，返回记录的列表。"""
    recs = []
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                recs.append(json.loads(line))
    return recs


def derive_column(recs, variant=None):
    """一列的全部记录 -> observations 文件的内容。"""
    cases = {}
    for rec in recs:
        f = derive(rec)
        cases.setdefault(str(rec.get("case")), {})[str(rec.get("repeat"))] = f
        if variant is None:
            variant = rec.get("variant")
    return {"derive_version": DERIVE_VERSION, "variant": variant, "cases": cases}


def raw_columns(raw_dir):
    """raw 目录里有哪些列：{列名: 路径}。"""
    out = {}
    if not os.path.isdir(raw_dir):
        return out
    for name in sorted(os.listdir(raw_dir)):
        if name.endswith(".jsonl.gz"):
            out[name[: -len(".jsonl.gz")]] = os.path.join(raw_dir, name)
    return out


def dump_json(obj, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, sort_keys=True, indent=1)
        fh.write("\n")
    os.replace(tmp, path)


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    default_out = os.path.join(os.path.dirname(here), "out")
    ap = argparse.ArgumentParser(description="从运行记录里提取事实")
    ap.add_argument("--raw", default=os.path.join(default_out, "raw"), help="out/raw 目录")
    ap.add_argument("--out", default=os.path.join(default_out, "observations"), help="输出目录")
    args = ap.parse_args(argv)

    cols = raw_columns(args.raw)
    if not cols:
        print("derive: %s 里没有 <列>.jsonl.gz" % args.raw, file=sys.stderr)
        return 1
    os.makedirs(args.out, exist_ok=True)
    for col, path in cols.items():
        recs = read_raw(path)
        obs = derive_column(recs, col)
        dump_json(obs, os.path.join(args.out, col + ".json"))
        runs = sum(len(v) for v in obs["cases"].values())
        print("derive: %s：%d 个用例，%d 次运行" % (col, len(obs["cases"]), runs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
