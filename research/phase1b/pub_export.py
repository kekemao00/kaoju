#!/usr/bin/env python3
"""把真实的分析库导出成可以公开的库（决策 D16，`PUBLIC.md`）。只用标准库。

    python3 pub_export.py --db <真实库> --record <模块记下的中间结果> --key <密钥文件> --out <公开库> \
        [--summary summary.json] [--preflight preflight.txt] [--named-from out/]

- **白名单**：`SPEC` 里列出的列才进公开库，每列写明怎么处理；没列出的列（各表的 raw、Go 错误原文、banner、请求头原文……）一律不出。
  真实库里出现了 `SPEC` 没提到的表或列，导出照常进行、在报告里列出来（它们没有进公开库）。
- **假名**：见 `pub_pseudo.py`。密钥文件不存在时新建一把（32 字节随机数），不进仓库、不进公开库。
- **等价的代表值**：分析模块对几列自由文本只做固定的判断（是不是 judge 的名字、是不是原样、属于哪一类）。这些列在公开库里换成
  “在这些判断下结果相同”的代表值，每一种都在导出时用模块自己的函数或同一条 SQL 逐个核对过（`check_*`）；核对不过就停。
- **随库带上的中间结果**：证据文件算出的东西（证书链校验、正文里的链接、AWS 地址段）由模块在真实库上记下（`pubdb.Recorder`），
  这里脱敏后放进 `pub_*` 表。

本脚本读真实库，输出里不打印任何地址、主机名、哈希的原值；报告只有计数。
"""
import argparse
import collections
import glob
import json
import os
import re
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pub_pseudo  # noqa: E402
import pubdb  # noqa: E402

PUBLIC_VERSION = "1"
JUDGE_HOST = "judge.invalid"          # judge 主机名的假名；多于一个名字时是 judge2.invalid、judge3.invalid……
BATCH = 20000

# ---------------------------------------------------------------- 每列怎么处理
#
# keep      原样（枚举、计数、毫秒数、时间、探测器自己生成的编号）
# cand      候选键：代理 ip:port → 假名地址:端口；节点编号 → 假名；control:* 原样
# node      节点编号（12 位十六进制）→ 假名
# ip        地址 → 假名（不是地址的文本 → 不透明的记号）
# p24       /24 前缀 → 假 /24（out/ 里已经点了名的保持原样）
# hash      证据哈希、正文哈希 → 假名
# leaf      叶子证书哈希 → 假名
# nonce     探测器给每个请求生成的随机串 → 同长度的假名
# nonempty  只留“有没有”：非空 → 'x'
# 其余名字  见下面同名的 t_<名字> 方法（等价的代表值）

K, C, N, IP, P24, H, LEAF, NE = "keep", "cand", "node", "ip", "p24", "hash", "leaf", "nonempty"

REC = [("rid", K), ("file_id", K), ("ts", K), ("ts_epoch", K)]
_JUDGE_REQ = REC + [("remote", IP), ("tls", K), ("tls_ver", K), ("cipher", K), ("sni", "host"), ("alpn", K), ("hello_fp", K),
                    ("method", K), ("target", "target"), ("proto", K), ("host", "host"), ("nonce", "nonce"), ("age_s", K), ("kind", K),
                    ("req_canary", K), ("status", K), ("err", NE), ("n", K)]

SPEC = {
    "att": REC + [
        ("visit", K), ("cand", C), ("proto", K), ("dst", "dst"), ("kind", K), ("arm", K), ("nonce", "nonce"),
        ("tcp_ok", K), ("tcp_ms", K), ("tcp_class", K), ("tcp_code", K), ("tcp_sniff", K),
        ("hs_ok", K), ("hs_ms", K), ("hs_class", K), ("hs_code", K), ("hs_sniff", K),
        ("tls_ok", K), ("tls_ms", K), ("tls_class", K), ("tls_ver", K), ("tls_cipher", K), ("tls_leaf", LEAF),
        ("tls_subj", "subj"), ("tls_issuer", "issuer"), ("tls_self", K), ("tls_sniff", K),
        ("http_ok", K), ("http_ms", K), ("http_class", K), ("http_code", K), ("http_sniff", K), ("http_len", K), ("http_sha", H),
        ("http_pre", K), ("http_suf", K), ("http_sim", K), ("http_canary", K), ("http_flags", K), ("http_added", K), ("http_ev", H),
        ("class", K), ("ip", IP), ("ev", H), ("ms", K), ("cand_kind", K), ("cand_ip", IP), ("cand_port", K), ("prefix24", P24),
        ("tls_detail_enum", K)],
    "att_http_added": [("rid", K), ("att_rid", K), ("header", K)],
    "att_http_flag": [("rid", K), ("att_rid", K), ("flag", K)],
    "visit": REC + [
        ("visit", K), ("cand", C), ("group", K), ("n", K), ("prev", K), ("state", K), ("full", K), ("listed", K), ("labels", K),
        ("tried", K), ("ok", K), ("auth", K), ("aborted", K), ("next_min", K), ("ms", K), ("cand_ip", IP), ("cand_port", K),
        ("prefix24", P24), ("n_ok", K)],
    "visit_ok": [("rid", K), ("visit_rid", K), ("visit", K), ("cand", C), ("ts", K), ("ts_epoch", K), ("proto", K)],
    "visit_tried": [("rid", K), ("visit_rid", K), ("visit", K), ("cand", C), ("seq", K), ("proto", K)],
    "npre": REC + [
        ("round", K), ("node", N), ("dns_ok", K), ("dns_ms", K), ("dns_class", K), ("dns_code", K), ("dns_sniff", K), ("ips", "json_ips"),
        ("tcp_ok", K), ("tcp_ms", K), ("tcp_class", K), ("tcp_code", K), ("tcp_sniff", K), ("class", K), ("n_ips", K)],
    "npre_ip": [("rid", K), ("npre_rid", K), ("node", N), ("round", K), ("seq", K), ("ip", IP)],
    "nerr": REC + [("round", K), ("node", N), ("arm", K), ("msg", "nerr_msg")],
    "nround": REC + [
        ("round", K), ("known", K), ("listed", K), ("supported", K), ("backoff", K), ("tcp_ok", K), ("probed", K), ("ok_strict", K),
        ("ok_linked", K), ("bad_config", K), ("batches", K), ("ms", K), ("err", NE)],
    "stat": REC + [("up_min", K), ("visits", K), ("records", K), ("pool", K)],
    "stat_pool": [("rid", K), ("stat_rid", K), ("ts", K), ("ts_epoch", K), ("key", K), ("value", K)],
    "start": REC + [
        ("resumed_candidates", K), ("load_err", NE), ("http_port", "port_rank"), ("https_port", "port_rank"), ("probe", "probe"),
        ("payload_sha256", "json_hashes"), ("judge_host_sha8", "sha8"), ("judge_ip_sha8", "sha8"), ("raw", "start_raw")],
    "stop": REC + [("visits", K)],
    "version": REC + [("version", K)],
    "error": REC + [("what", K)],
    "req": _JUDGE_REQ,
    "noise": _JUDGE_REQ,
    "tls_fail": _JUDGE_REQ,
    "noise_dropped": _JUDGE_REQ,
    "req_dropped": _JUDGE_REQ,
    "req_header": [("rid", K), ("req_rid", K), ("nonce", "nonce"), ("seq", K), ("name", K), ("value", "header_value")],
    "snap": REC + [
        ("src", K), ("label", K), ("status", K), ("err", NE), ("bytes", K), ("n", K), ("q_lines", K), ("q_garbage", K),
        ("q_hostname", K), ("q_no_port", K), ("q_bad_range", K), ("q_duplicate", K), ("q_with_credentials", K), ("base", K), ("agg", K),
        ("ms", K), ("changed", K), ("n_add", K), ("n_del", K)],
    "list_event": [("rid", K), ("snap_rid", K), ("ts", K), ("ts_epoch", K), ("src", K), ("label", K), ("cand", C), ("event", K),
                   ("base", K), ("cand_ip", IP), ("cand_port", K), ("prefix24", P24)],
    "agg_sample": REC + [("src", K), ("union", K), ("exclusive", K), ("sample", K), ("seed", K)],
    "agg_member": [("rid", K), ("agg_sample_rid", K), ("ts", K), ("ts_epoch", K), ("src", K), ("seq", K), ("cand", C), ("cand_ip", IP),
                   ("cand_port", K), ("prefix24", P24)],
    "nsnap": REC + [
        ("src", K), ("status", K), ("err", NE), ("bytes", K), ("lines", K), ("unparsed", K), ("n", K), ("base", K), ("changed", K),
        ("ms", K), ("n_add", K), ("n_del", K)],
    "node_event": [("rid", K), ("nsnap_rid", K), ("ts", K), ("ts_epoch", K), ("src", K), ("node", N), ("event", K), ("base", K)],
    "node": REC + [
        ("src", K), ("id", N), ("scheme", K), ("host", "node_host"), ("method", K), ("aid", K), ("flow", K), ("net", K), ("sec", K),
        ("insecure", K), ("why", K)],
    "cands": [
        ("rid", K), ("key", C), ("ip", IP), ("port", K), ("prefix24", P24), ("group", K), ("srcs", K), ("n_srcs", K), ("listed", K),
        ("labels", K), ("label_names", K), ("ts", K), ("ts_epoch", K), ("first_seen", K), ("first_seen_epoch", K), ("delisted_at", K),
        ("delisted_at_epoch", K), ("next", K), ("next_epoch", K), ("visits", K), ("fails", K), ("state", K), ("state_name", K),
        ("ok_mask", K), ("ok_protos", K), ("ever_ok", K), ("last_ok", K), ("last_ok_epoch", K), ("last_full", K), ("last_full_epoch", K),
        ("last_extra", K), ("last_extra_epoch", K)],
    "cand_src": [("rid", K), ("key", C), ("src_idx", K), ("src_name", K), ("labels", K), ("label_names", K)],
    "files": [("id", K), ("name", K), ("prefix", K), ("hour", K), ("compressed", K), ("bytes", K), ("status", K), ("records", K),
              ("bad_lines", K), ("first_ts", K), ("last_ts", K), ("note", K)],
    "file_kind": [("file_id", K), ("k", K), ("n", K)],
    "evidence": [("hash", H), ("ext", K), ("bytes", K), ("path", "ev_path")],
    "misc": [("rid", K), ("file_id", K), ("k", K), ("ts", K), ("ts_epoch", K)],
    "bad_line": [("rid", K), ("file_id", K), ("lineno", K), ("why", K)],
    "self_ips": [("ip", IP), ("source", K), ("n", K)],
    "self_names": [("name", "judge_name"), ("source", K), ("n", K)],
    "self_leaf": [("leaf", LEAF), ("source", K), ("n", K), ("first_ts", K), ("last_ts", K)],
}

# 不建成表的：meta 单独处理（按键），sqlite_stat1 由 ANALYZE 重新生成
SPECIAL_TABLES = {"meta", "sqlite_stat1"}

# meta 里原样带上的键；其余要么换假名（下面单列），要么不出
META_KEEP = [
    "ingest_version", "ingested_at_utc", "python", "sqlite", "ingest_seconds", "files_read", "records_total", "records_by_kind",
    "first_ts", "last_ts", "duplicate_hour_files", "unknown_fields", "misplaced_kinds", "judge_leaf_observed_count",
    "judge_leaf_pem_present", "judge_leaf_pem_matches_observed", "judge_leaf_tls_ok_extra_count", "payload_len", "state_cands",
    "state_tz_offsets", "state_sampled", "state_mtime_utc", "sources_sha256", "sources_names", "cand_src_names", "cand_src_check",
    "evidence_files", "evidence_bytes", "summary_json", "output_whitelist", "output_rules"]
META_DROP = ["data_dir", "state_file", "sources_file"]                       # 本机路径
META_PSEUDO = ["judge_host_sha8", "judge_ip_sha8", "judge_leaf_observed", "judge_leaf_pem_sha256", "judge_leaf_tls_ok_extra"]

# start.probe 里带出来的配置项：数值、布尔和端口清单；exclude_file（本机路径）等其余的不出
PROBE_KEEP_TYPES = (int, float, bool)

# IP 出现在哪些列（第一遍登记用）
IP_COLUMNS = [("cands", "ip"), ("att", "cand_ip"), ("att", "ip"), ("visit", "cand_ip"), ("list_event", "cand_ip"), ("agg_member", "cand_ip"),
              ("req", "remote"), ("noise", "remote"), ("tls_fail", "remote"), ("noise_dropped", "remote"), ("req_dropped", "remote"),
              ("npre_ip", "ip"), ("node", "host"), ("self_ips", "ip")]


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def qid(name):
    return '"%s"' % name.replace('"', '""')


# ---------------------------------------------------------------- 组织名、DN

DN_ESC = re.compile(r'([,+\\])')


def dn_escape(v):
    return DN_ESC.sub(r"\\\1", v)


class Exporter:
    def __init__(self, src, dst, ps, record=None):
        self.src, self.dst, self.ps, self.record = src, dst, ps, record
        self.cache = {k: {} for k in ("ip", "cand", "node", "hash", "leaf", "p24", "subj", "issuer", "host", "nerr", "org", "nonce")}
        self.report = collections.OrderedDict()
        self.judge_names = {}      # 真实名字（小写）→ 假名
        self.judge_ips = []        # 真实地址（self_ips 全部来源、非空）
        self.org_keep = set()      # 至少出现在 ORG_MIN_IPS 个代理 IP 上的组织名：原样
        self.ports = {}
        self.mm = None             # m_mitm（dn_parts、name_matches、safe_text）
        self.checks = collections.Counter()

    # ---- 准备

    def prepare(self, named24):
        src = self.src
        names = [r[0] for r in src.execute("SELECT DISTINCT name FROM self_names WHERE name IS NOT NULL AND name != ''")]
        for i, low in enumerate(sorted({n.strip().lower().rstrip(".") for n in names}, key=lambda x: self.ps.mac("judge-name", x))):
            self.judge_names[low] = JUDGE_HOST if i == 0 else "judge%d.invalid" % (i + 1)
        self.judge_ips = [r[0] for r in src.execute("SELECT DISTINCT ip FROM self_ips WHERE ip IS NOT NULL AND ip != ''")]
        seen = set()
        for table, col in IP_COLUMNS:
            if not self.has(table, col):
                continue
            t0 = time.time()
            n = 0
            for (v,) in src.execute("SELECT DISTINCT %s FROM %s WHERE %s IS NOT NULL" % (qid(col), qid(table), qid(col))):
                if isinstance(v, str) and "." in v and ":" not in v:
                    seen.add(v)
                    n += 1
            log("  登记地址 %s.%s：%d 个不同值，%.0f 秒" % (table, col, n, time.time() - t0))
        if self.has("npre", "ips"):
            for (v,) in src.execute("SELECT DISTINCT ips FROM npre WHERE ips IS NOT NULL"):
                for x in json.loads(v) or []:
                    if isinstance(x, str) and "." in x and ":" not in x:
                        seen.add(x)
        self.ps.prepare(seen, self.judge_ips, named24=named24)
        self.report["登记的 IPv4（不同值）"] = len(seen)
        self.report["公网 /24"] = len(self.ps.slot)
        self.report["保持原样的 /24（out/ 里点了名的）"] = len(self.ps.keep24)
        self.report["judge 的名字个数"] = len(self.judge_names)
        self.report["judge 的地址个数（不含回环）"] = len(self.ps.judge)
        import m_mitm
        self.mm = m_mitm
        self._org_counts()

    def has(self, table, col=None):
        cols = [r[1] for r in self.src.execute("PRAGMA table_info(%s)" % qid(table))]
        return bool(cols) and (col is None or col in cols)

    def _org_counts(self):
        """证书上的组织名各出现在多少个不同的代理 IP 上；达到 m_mitm.ORG_MIN_IPS 的原样保留，其余换假名。
        口径比 m_mitm.org_ip_counts 宽（全部代理尝试，不限目的地和窗口；证据里的叶子信息也算），只会多留、不会少留模块要印出来的名字。"""
        ips = collections.defaultdict(set)
        dn_get = self.mm.dn_get
        for ip, subj, iss in self.src.execute("""SELECT DISTINCT cand_ip, tls_subj, tls_issuer FROM att
                                                 WHERE cand_kind = 'proxy' AND (tls_subj IS NOT NULL OR tls_issuer IS NOT NULL)"""):
            for dn in (subj, iss):
                for o in dn_get(dn, "O") if dn else ():
                    ips[o].add(ip)
                    ips[o.strip()].add(ip)
        if self.record is not None and self._rec_has("chains_leafinfo"):
            ev_ips = collections.defaultdict(set)
            for ip, ev in self.src.execute("SELECT DISTINCT cand_ip, ev FROM att WHERE cand_kind = 'proxy' AND ev IS NOT NULL"):
                ev_ips[ev].add(ip)
            for ev, so, io in self.record.execute("SELECT ev, subject_org, issuer_org FROM rec_chains_leafinfo"):
                for t in (so, io):
                    for o in (json.loads(t) if t else []) or []:
                        ips[o] |= ev_ips.get(ev, set())
                        ips[o.strip()] |= ev_ips.get(ev, set())
        self.org_keep = {o for o, s in ips.items() if len(s) >= self.mm.ORG_MIN_IPS}
        self.report["证书上的组织名（不同值）"] = len(ips)
        self.report["其中原样保留的（至少 %d 个代理 IP）" % self.mm.ORG_MIN_IPS] = len(self.org_keep)

    def _rec_has(self, name):
        return self.record.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", ("rec_" + name,)).fetchone() is not None

    # ---- 各列的处理（row 是 sqlite3.Row，v 是这一列的值）

    def t_keep(self, v, row):
        return v

    def t_ip(self, v, row):
        if v is None or v == "":
            return v
        c = self.cache["ip"]
        out = c.get(v)
        if out is None:
            out = self.ps.ip(v)
            if out is None:                      # 不是地址：不透明的记号，相等关系保留
                out = "x-" + self.ps.ident("not-ip", v, 12)
                self.checks["不是地址的“地址”值（换成记号）"] += 1
            elif pub_pseudo._parse(v) is not None and str(pub_pseudo._parse(v)) != v:
                raise SystemExit("地址的写法不规范（规范化以后与别的值相等关系可能变）：停下，先看这一类值怎么处理")
            c[v] = out
        return out

    def t_cand(self, v, row):
        if v is None:
            return None
        c = self.cache["cand"]
        out = c.get(v)
        if out is None:
            out = c[v] = self.ps.cand(v)
        return out

    def t_node(self, v, row):
        if v is None or v == "":
            return v
        c = self.cache["node"]
        out = c.get(v)
        if out is None:
            out = c[v] = self.ps.ident("node", v)
        return out

    def t_p24(self, v, row):
        if v is None:
            return None
        c = self.cache["p24"]
        out = c.get(v)
        if out is None:
            out = c[v] = self.ps.prefix24(v)
        return out

    def t_hash(self, v, row):
        if v is None or v == "":
            return v
        c = self.cache["hash"]
        out = c.get(v)
        if out is None:
            out = c[v] = self.ps.ident("hash", v)
        return out

    def t_leaf(self, v, row):
        if v is None or v == "":
            return v
        c = self.cache["leaf"]
        out = c.get(v)
        if out is None:
            out = c[v] = self.ps.ident("leaf", v)
        return out

    def t_nonce(self, v, row):
        """探测器给每个请求生成的随机 nonce（att、judge 的记录、请求头三处）。模块只按它连接和分组；换成同长度的假名（决策 D16）。"""
        if v is None or v == "":
            return v
        c = self.cache["nonce"]
        out = c.get(v)
        if out is None:
            out = c[v] = self.ps.ident("nonce", v, len(v))
        return out

    def t_nonempty(self, v, row):
        return v if v is None or v == "" else "x"

    def t_dst(self, v, row):
        # obs:<名> 里的名字是配置里的观察者名；带点号（像主机名）的不放行
        if v is not None and v.startswith("obs:") and not re.fullmatch(r"obs:[A-Za-z0-9_-]+", v):
            raise SystemExit("att.dst 里的观察者名不是简单的名字，停下")
        return v

    def t_judge_name(self, v, row):
        if v is None or v == "":
            return v
        return self.judge_names[v.strip().lower().rstrip(".")]

    def t_host(self, v, row):
        """Host 头、SNI：是 judge 的名字 → 假名（端口保留）；别的 → 不透明的记号。模块只判断“是不是 judge 的名字”。"""
        if v is None or v == "":
            return v
        c = self.cache["host"]
        out = c.get(v)
        if out is None:
            low = v.lower()
            name, port = (low.rsplit(":", 1) + [None])[:2] if low.count(":") == 1 else (low, None)
            if name in self.judge_names:
                out = self.judge_names[name] + ((":" + port) if port is not None else "")
            elif low in self.judge_names:
                out = self.judge_names[low]
            else:
                out = "h-%s.invalid" % self.ps.ident("host", low, 12)
            c[v] = out
        return out

    def t_node_host(self, v, row):
        """节点的入口：地址 → 假名地址；主机名 → 不透明的记号。"""
        if v is None or v == "":
            return v
        fake = self.ps.ip(v) if pub_pseudo.is_ip(v) else None
        return fake if fake is not None else "h-%s.invalid" % self.ps.ident("host", v.lower(), 12)

    def t_target(self, v, row):
        """请求行里的目标。模块只看两件事：是不是绝对 URI（含 "://"）、是不是恰好 "/"。"""
        if v is None or v == "":
            return v
        if v == "/":
            return "/"
        tag = self.ps.ident("target", v, 12)
        if "://" in v:
            return "http://%s/x/%s" % (JUDGE_HOST, tag)
        return ("/x/" if v.startswith("/") else "x-") + tag

    def t_ev_path(self, v, row):
        h = self.t_hash(row["hash"], row)
        return "evidence/%s/%s.%s" % (h[:2], h, row["ext"])

    def t_json_ips(self, v, row):
        if v is None:
            return None
        return json.dumps([self.t_ip(x, row) for x in json.loads(v) or []], separators=(",", ":"))

    def t_json_hashes(self, v, row):
        """start.payload_sha256：{载荷种类: 哈希}。哈希换假名（h 载荷的哈希能用来验证对 judge 主机名的猜测）。"""
        if v is None:
            return None
        d = json.loads(v)
        if isinstance(d, dict):
            return json.dumps({k: self.ps.ident("payload", str(x)) for k, x in d.items()}, separators=(",", ":"), sort_keys=True)
        return json.dumps(self.ps.ident("payload", json.dumps(d, sort_keys=True)))

    def t_sha8(self, v, row):
        return v if v is None or v == "" else self.ps.ident("sha8", v)

    def t_port_rank(self, v, row):
        """judge 的监听端口：只留“第几种”（模块只数有几种不同的值）。"""
        if v is None:
            return None
        return self.ports.setdefault(v, len(self.ports) + 1)

    def _probe(self, text):
        d = json.loads(text) if text else None
        if not isinstance(d, dict):
            return None
        out = {}
        for k, x in d.items():
            if isinstance(x, PROBE_KEEP_TYPES) or x is None:
                out[k] = x
            elif isinstance(x, list) and all(isinstance(i, int) for i in x):
                out[k] = x
        return out

    def t_probe(self, v, row):
        d = self._probe(v)
        return None if d is None else json.dumps(d, separators=(",", ":"))

    def t_start_raw(self, v, row):
        """start.raw：模块只从里面取 probe 的几个数值配置项（json_extract(raw, '$.probe.…')、skip_ports）。只留这一节。"""
        d = self._probe(json.dumps((json.loads(v) or {}).get("probe"))) if v else None
        return json.dumps({"probe": d or {}}, separators=(",", ":"))

    def t_nerr_msg(self, v, row):
        """sing-box 的错误原文 → 它在 m_nodes.NERR_CASE 下的类别对应的代表值。"""
        if v is None:
            return None
        c = self.cache["nerr"]
        out = c.get(v)
        if out is None:
            cls = self._nerr_class(v)
            out = c[v] = NERR_REP[cls]
        return out

    def _nerr_class(self, msg):
        return self._mem.execute("SELECT " + self._nerr_case + " FROM (SELECT ? AS msg)", (msg,)).fetchone()[0]

    def org(self, o):
        """组织名：达到门槛的原样；其余换成假名，并且保持它在 m_mitm.safe_text / m_posthoc._issuer_org 下落进同一类。"""
        c = self.cache["org"]
        out = c.get(o)
        if out is not None:
            return out
        s = o.strip()
        cls = self._org_class(o, self._guard_real)
        if s == "" or ((o in self.org_keep or s in self.org_keep) and cls in ("plain", "domain")):
            out = o          # 达到门槛、又不含地址和 judge 身份的：原样（模块会把它印进 out/）
        else:
            tag = "org-" + self.ps.ident("org", s, 10)
            out = {"addr": tag + "@hidden", "judge": tag + " " + JUDGE_HOST, "domain": tag + ".example", "plain": tag}[cls]
        c[o] = out
        return out

    def _dn(self, v, with_cn):
        mm = self.mm
        parts = []
        for k, val in mm.dn_parts(v):
            if k == "CN" and with_cn:
                if val == "":
                    parts.append("CN=")
                elif mm.name_matches(val, self._hosts_real, self._ips_real):
                    parts.append("CN=" + JUDGE_HOST)
                else:
                    parts.append("CN=cn-" + self.ps.ident("cn", val, 10))
            elif k == "O":
                parts.append("O=" + dn_escape(self.org(val)))
        # 末尾的 X= 不参与任何判断，只为了让不同的原值仍然互不相同（按这一列连接、数不同值的查询结果不变）
        parts.append("X=" + self.ps.ident("dn", v, 12))
        return ",".join(parts)

    def t_subj(self, v, row):
        """证书主题（Go pkix.Name.String()，截到 120 字符）。模块用它做三件事：有没有 CN、CN 是不是 judge 的名字、取组织名 O。
        公开库里只留 CN（judge 的名字 → 假名，别的 → 记号）和 O（见 org()），其余属性不出。"""
        if v is None:
            return None
        c = self.cache["subj"]
        out = c.get(v)
        if out is None:
            out = c[v] = self._dn(v, True)
            self._check_dn(v, out, True)
        return out

    def t_issuer(self, v, row):
        """证书签发者：模块只取组织名 O。CN 不出（公开证书的签发者 CN 没有用处，自签证书的签发者 CN 就是主题 CN）。"""
        if v is None:
            return None
        c = self.cache["issuer"]
        out = c.get(v)
        if out is None:
            out = c[v] = self._dn(v, False)
            self._check_dn(v, out, False)
        return out

    def _check_dn(self, real, fake, with_cn):
        mm = self.mm
        want_o = [self.org(o) for o in mm.dn_get(real, "O")]
        got_o = mm.dn_get(fake, "O")
        if [o.strip() for o in want_o] != got_o:
            raise SystemExit("核对不过：证书名字换成代表值以后，组织名的个数或内容对不上")
        if with_cn:
            a = mm.dn_get(real, "CN")
            b = mm.dn_get(fake, "CN")
            fa = (bool(a), any(mm.name_matches(x, self._hosts_real, self._ips_real) for x in a))
            fb = (bool(b), any(mm.name_matches(x, self._hosts_fake, self._ips_fake) for x in b))
            if fa != fb:
                raise SystemExit("核对不过：证书主题换成代表值以后，“有没有 CN / CN 是不是 judge 的名字”变了")
        for o_real, o_fake in zip(mm.dn_get(real, "O"), got_o):
            if self._org_class(o_real, self._guard_real) != self._org_class(o_fake, self._guard_fake):
                raise SystemExit("核对不过：组织名换成假名以后，在 safe_text / _issuer_org 下的类别变了")
        self.checks["证书名字（不同值）逐个核对"] += 1

    def _org_class(self, o, guard):
        s = o.strip()
        if not s:
            return "empty"
        if self.mm.HOSTPORT_RE.search(s) or self.mm.IPV4_RE.search(s) or "@" in s:
            return "addr"
        if any(h and h in s.lower() for h in guard):
            return "judge"
        if DOMAIN_RE.search(s):
            return "domain"
        return "plain"

    def t_header_value(self, v, row):
        """judge 收到的请求头的值。模块对它做的判断只有三种，公开库里的值在这三种判断下结果不变：
        - User-Agent / Accept / Accept-Language / Accept-Encoding：是不是探测器发出的原值（原值是公开的常量，原样保留；别的 → 记号）；
        - Cookie 与 X-Probe-Canary：Cookie 是不是 "pc=" 加上金丝雀的值（两者换成同一个假名函数下的值，相等关系保留）；
        - Host 以外的头：值里有没有探测器自己的地址（有 → 留下那个地址的假名；别的内容不出）。"""
        if v is None:
            return None
        name = row["name"]
        sent = SENT_VALUES.get(name)
        if name == "X-Probe-Canary":
            base = self.ps.ident("canary", v, max(8, min(64, len(v)))) if v != "" else ""
        elif name == "Cookie":
            base = ("pc=" + (self.ps.ident("canary", v[3:], max(8, min(64, len(v) - 3))) if v[3:] != "" else "")) if v.startswith("pc=") \
                else ("" if v == "" else "c-" + self.ps.ident("cookie", v, 16))
        elif sent is not None:
            base = v if v == sent or v == "" else "changed-" + self.ps.ident("hv", v, 12)
        else:
            base = ""
        if name == "Host" or v == "":
            return base
        hits = [self.cache["ip"].get(ip) or self.t_ip(ip, None) for ip in self.judge_ips if ip in v]
        if not hits:
            return base
        self.checks["请求头的值里带出探测器地址（留下假名）"] += 1
        return (base + " " if base else "") + " ".join(hits)

    # ---- 复制一张表

    def copy_table(self, table, spec):
        src, dst = self.src, self.dst
        info = {r[1]: r for r in src.execute("PRAGMA table_info(%s)" % qid(table))}
        if not info:
            return None
        cols = [(c, how) for c, how in spec if c in info]
        missing = [c for c, _ in spec if c not in info]
        dropped = [c for c in info if c not in {c for c, _ in spec}]
        pk = [c for c, _ in cols if info[c][5]]
        defs = ["%s %s%s" % (qid(c), info[c][2] or "", " PRIMARY KEY" if pk == [c] else "") for c, _how in cols]
        if len(pk) > 1:
            defs.append("PRIMARY KEY (%s)" % ", ".join(qid(c) for c in pk))
        dst.execute("CREATE TABLE %s (%s)" % (qid(table), ", ".join(defs)))
        sel = "SELECT %s FROM %s ORDER BY rowid" % (", ".join(qid(c) for c, _ in cols), qid(table))
        fns = [(i, getattr(self, "t_" + how)) for i, (c, how) in enumerate(cols) if how != K]
        ins = "INSERT INTO %s VALUES (%s)" % (qid(table), ", ".join("?" * len(cols)))
        cur = src.execute(sel)
        n, t0 = 0, time.time()
        while True:
            rows = cur.fetchmany(BATCH)
            if not rows:
                break
            out = []
            for row in rows:
                vals = list(row)
                for i, fn in fns:
                    vals[i] = fn(vals[i], row)
                out.append(vals)
            dst.executemany(ins, out)
            n += len(rows)
        dst.commit()
        log("  %-14s %9d 行  %5.0f 秒  留 %d 列，不出 %d 列" % (table, n, time.time() - t0, len(cols), len(dropped)))
        return {"行": n, "公开的列": [c for c, _ in cols], "换过的列": {c: how for c, how in cols if how != K},
                "不出的列": dropped, "SPEC 里有而库里没有的列": missing}


NERR_REP = {"config": "config: x", "cert_verify": "x509", "timeout": "timeout", "refused": "refused", "eof_reset": "eof", "dns": "dns",
            "other": "other"}
DOMAIN_RE = re.compile(r"\b[A-Za-z0-9-]+\.[A-Za-z]{2,}\b")      # 与 m_posthoc.DOMAIN_RE 相同（导出时核对）
SENT_VALUES = {}                                                # 运行时从 m_integrity.SENT_HEADERS 取


# ---------------------------------------------------------------- 随库带上的中间结果（pubdb.Recorder 记下的）

# 记录文件里的表 → 公开库里的表：每列怎么处理。没列出的表不带；列出的表里没列出的列算错误（宁可停下，不悄悄带出去）
REC_SPEC = {
    # m_mitm.verify_chains：每个证书链文件一行。有效期只留长度（not_before 归零），具体日期不出
    "chains_leafinfo": [("ev", H), ("parse_ok", K), ("n_certs", K), ("leaf_sha256", LEAF), ("name_judge", K), ("name_basis", K),
                        ("san_n", K), ("self_signed", K), ("is_ca", K), ("not_before_epoch", "nb_zero"), ("not_after_epoch", "na_rel"),
                        ("chain_nb_epoch", "null"), ("chain_na_epoch", "null"), ("subject_org", "json_orgs"), ("issuer_org", "json_orgs"),
                        ("public_key", K), ("sig_alg", K), ("problem", NE)],
    # 校验结果：链顶的组织名来自公共根库，原样
    "chains_chk": [("ev", H), ("ts_epoch", K), ("ok", K), ("err_class", K), ("chain_len", K), ("root_org", K)],
    # m_literature.mani_sslstrip：每个正文证据里 https://<judge>/ 和 http://<judge>/ 各出现几次
    "body_links": [("ev", H), ("readable", K), ("n_https", K), ("n_http", K)],
    # m_posthoc.judge_info_page：整页替换的正文是不是 judge 自己的说明页
    "body_infopage": [("ev", H), ("state", K)],
    # m_posthoc.mitm_fleet：中间人 IP 落在 AWS 公布的哪个区域（不在其中的是 NULL）
    "aws": [("ip", IP), ("region", K)],
}
REC_JSON = ["chains_info", "chains_roots_note", "aws_note"]


def export_record(ex):
    rec, dst = ex.record, ex.dst
    out = {}
    dst.execute("CREATE TABLE pub_json (name TEXT, scope TEXT, value TEXT)")
    if rec is None:
        return out
    names = [r[0][4:] for r in rec.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'rec\\_%' ESCAPE '\\'")
             if r[0] not in ("rec_json", "rec_tables")]
    for name in sorted(names):
        if name not in REC_SPEC:
            raise SystemExit("记录文件里有不认识的表 rec_%s：先在 REC_SPEC 里写明每列怎么处理" % name)
        spec = REC_SPEC[name]
        cols = [r[1] for r in rec.execute("PRAGMA table_info(%s)" % qid("rec_" + name))]
        extra = [c for c in cols if c not in ("scope", "seq") and c not in {c for c, _ in spec}]
        if extra:
            raise SystemExit("rec_%s 里有 REC_SPEC 没写的列：%s" % (name, "、".join(extra)))
        use = [(c, how) for c, how in spec if c in cols]
        dst.execute("CREATE TABLE %s (scope TEXT, %s)" % (qid("pub_" + name), ", ".join(qid(c) for c, _ in use)))
        n = 0
        sel = "SELECT scope, %s FROM %s ORDER BY scope, seq" % (", ".join(qid(c) for c, _ in use), qid("rec_" + name))
        fns = [(i + 1, getattr(ex, "t_" + how)) for i, (c, how) in enumerate(use) if how != K]
        rec.row_factory = sqlite3.Row
        batch = []
        for row in rec.execute(sel):
            vals = list(row)
            for i, fn in fns:
                vals[i] = fn(vals[i], row)
            batch.append(vals)
            n += 1
        dst.executemany("INSERT INTO %s VALUES (%s)" % (qid("pub_" + name), ", ".join("?" * (len(use) + 1))), batch)
        out["pub_" + name] = {"行": n, "列": [c for c, _ in use], "换过的列": {c: how for c, how in use if how != K}}
    for name, scope, value in rec.execute("SELECT name, scope, value FROM rec_json"):
        if name not in REC_JSON:
            raise SystemExit("记录文件里有不认识的 JSON：%s" % name)
        dst.execute("INSERT INTO pub_json VALUES (?, ?, ?)", (name, scope, value))
        out["pub_json:" + name] = {"字节": len(value)}
    dst.commit()
    return out


def _t_null(self, v, row):
    return None


def _t_nb_zero(self, v, row):
    return None if v is None else 0.0


def _t_na_rel(self, v, row):
    nb = row["not_before_epoch"]
    return None if v is None else (v - nb if nb is not None else v)


def _t_json_orgs(self, v, row):
    if v is None:
        return None
    return json.dumps([self.org(o) for o in json.loads(v) or []], ensure_ascii=False)


Exporter.t_null, Exporter.t_nb_zero, Exporter.t_na_rel, Exporter.t_json_orgs = _t_null, _t_nb_zero, _t_na_rel, _t_json_orgs


# ---------------------------------------------------------------- meta、索引、检查

def export_meta(ex, extra):
    src, dst, ps = ex.src, ex.dst, ex.ps
    dst.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    have = dict(src.execute("SELECT key, value FROM meta"))
    kept, dropped = [], []
    for k, v in have.items():
        if k == "summary_json" and v is not None:
            import m_instrument
            dst.execute("INSERT INTO meta VALUES (?, ?)", (k, json.dumps(sanitize_summary_obj(json.loads(v), m_instrument.WARNING_PREFIXES),
                                                                         ensure_ascii=False)))
            kept.append(k + "（脱敏，同 summary.json）")
        elif k in META_KEEP:
            dst.execute("INSERT INTO meta VALUES (?, ?)", (k, v))
            kept.append(k)
        elif k in META_PSEUDO:
            if k in ("judge_host_sha8", "judge_ip_sha8"):
                v2 = json.dumps([ps.ident("sha8", x) for x in json.loads(v or "[]")])
            elif k == "judge_leaf_pem_sha256":
                v2 = ex.t_leaf(v, None)
            elif k == "judge_leaf_observed":
                v2 = json.dumps([dict(d, leaf=ex.t_leaf(d.get("leaf"), None)) for d in json.loads(v or "[]")], ensure_ascii=False)
            else:
                v2 = json.dumps([ex.t_leaf(x, None) if isinstance(x, str) else x for x in json.loads(v or "[]")])
            dst.execute("INSERT INTO meta VALUES (?, ?)", (k, v2))
            kept.append(k + "（假名）")
        else:
            dropped.append(k)
    unknown = [k for k in dropped if k not in META_DROP]
    for k, v in extra.items():
        dst.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (k, v))
    dst.commit()
    return {"带上的键": kept, "不出的键": dropped, "其中 SPEC 没提到的键": unknown}


def export_indexes(ex):
    """真实库上的索引原样重建（列还在的才建），再 ANALYZE：查询计划尽量与真实库一样，没写 ORDER BY 的查询行序才不变。"""
    src, dst = ex.src, ex.dst
    made, skipped = 0, []
    for name, tbl, sql in src.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL ORDER BY name"):
        cols = {r[1] for r in dst.execute("PRAGMA table_info(%s)" % qid(tbl))}
        need = [r[2] for r in src.execute("PRAGMA index_info(%s)" % qid(name))]
        where = re.search(r"\bWHERE\s+(\w+)", sql or "")
        if cols and all(c in cols for c in need) and (where is None or where.group(1) in cols):
            dst.execute(sql)
            made += 1
        else:
            skipped.append(name)
    dst.execute("ANALYZE")
    dst.commit()
    return {"重建的索引": made, "没建的索引（列不在公开库里）": skipped}


def check_injective(ex):
    """假名不能把两个不同的原值并成一个（相等关系要原样保留）。"""
    bad = []
    for kind in ("ip", "cand", "node", "hash", "leaf", "p24", "host", "nonce"):
        c = ex.cache[kind]
        if len(set(c.values())) != len(c):
            bad.append(kind)
    if bad:
        raise SystemExit("假名相撞（两个不同的原值得到同一个假名）：%s" % "、".join(bad))
    return {k: len(ex.cache[k]) for k in ("ip", "cand", "node", "hash", "leaf", "p24", "host", "subj", "issuer", "org", "nerr", "nonce")}


def check_classifiers(ex):
    """代表值在模块的判断下与原值同类：nerr.msg（m_nodes.NERR_CASE）、请求头的值（m_integrity.SENT_HEADERS）。"""
    for cls, rep in NERR_REP.items():
        if ex._nerr_class(rep) != cls:
            raise SystemExit("核对不过：nerr.msg 的代表值 %r 不属于类别 %s" % (rep, cls))
    for real, fake in ex.cache["nerr"].items():
        if ex._nerr_class(real) != ex._nerr_class(fake):
            raise SystemExit("核对不过：nerr.msg 换成代表值以后类别变了")
        if (real.lower().startswith("config: ")) != (fake.lower().startswith("config: ")):
            raise SystemExit("核对不过：nerr.msg 换成代表值以后“是不是配置被拒”变了")
    tokens = list(ex.ps.judge.values())
    for a in tokens:
        for b in tokens:
            if a != b and a in b:
                raise SystemExit("judge 地址的假名互为子串")
    return {"nerr.msg 不同原文": len(ex.cache["nerr"]), "nerr.msg 类别": sorted(set(ex.cache["nerr"].values()))}


# ---------------------------------------------------------------- 数据包里另外两个文件：summary.json、preflight.txt

SAFE_STR = re.compile(r"[A-Za-z0-9 _./:+()>,-]*")      # summary.json 里允许留下的字符串：时间、来源名、枚举、数字文本
IPV4_ANY = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]|/24)")


def sanitize_summary(path, warning_prefixes):
    """fieldtest 自带的 summary.json（文件）。见 sanitize_summary_obj。"""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    return json.dumps(sanitize_summary_obj(s, warning_prefixes), ensure_ascii=False, indent=1) + "\n"


def sanitize_summary_obj(s, warning_prefixes):
    """summary.json 的内容（数据包里的文件，和 ingest 存进 meta.summary_json 的副本）：模块只拿它的计数来交叉核对。含地址的三处去掉或合并——
    aggregator_samples[].members（抽到的条目）、findings.*.examples（例子）、nodes.errors（键是 sing-box 的错误原文，模块只用总条数）；
    warnings 是自由文本，模块只按开头归类，换成它所属的那个开头。其余只留数、布尔和形状简单的字符串，遇到别的就停下。"""
    for a in s.get("aggregator_samples") or []:
        a.pop("members", None)
    for v in (s.get("findings") or {}).values():
        if isinstance(v, dict):
            v.pop("examples", None)
    nodes = s.get("nodes")
    if isinstance(nodes, dict) and isinstance(nodes.get("errors"), dict):
        nodes["errors"] = {"（合并）": sum(int(v) for v in nodes["errors"].values())}
    if s.get("warnings") is not None:
        s["warnings"] = [next((p for p in warning_prefixes if w.startswith(p)), "其他") for w in s["warnings"]]

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                if IPV4_ANY.search(k):
                    raise SystemExit("summary.json 的键里有地址（%s 下），停下" % path)
                walk(v, path + "/" + k)
        elif isinstance(o, list):
            for v in o:
                walk(v, path + "[]")
        elif isinstance(o, str):
            if path == "/warnings[]":
                return
            if not SAFE_STR.fullmatch(o) or IPV4_ANY.search(o):
                raise SystemExit("summary.json 的 %s 里有形状不简单的字符串，停下：先决定它怎么处理" % path)
    walk(s, "")
    return s


def sanitize_preflight(path, mi):
    """测量机上的预检报告：m_instrument.preflight() 只取预检时间、仪器自检的项数、sing-box 版本和结论行。只留这几行。"""
    keep = []
    section = None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if re.match(r"^预检\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*$", line) or re.match(r"^结论：(\d+) 项失败，(\d+) 项注意", line):
                m = re.match(r"^结论：(\d+) 项失败，(\d+) 项注意", line)
                keep.append(m.group(0) if m else line)
                continue
            if line and not line[0].isspace():
                section = line.strip()
                keep.append(section if section in ("仪器自检", "sing-box") else "（其余小节）")
                continue
            if section == "仪器自检":
                m = re.match(r"^\s+(?:(\S+)\s+)?共核对 (\d+) 项，(\d+) 项不符\s*$", line)
                if m:
                    keep.append("  %s共核对 %s 项，%s 项不符" % ((m.group(1) + "  ") if m.group(1) else "", m.group(2), m.group(3)))
            elif section == "sing-box":
                m = re.search(r"sing-box version (\d+\.\d+\.\d+)", line)
                if m:
                    keep.append("  " + m.group(0))
    text = "\n".join(keep) + "\n"
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        tmp = os.path.join(d, "preflight.txt")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        a, b = mi.preflight(path, "x"), mi.preflight(tmp, "x")
    if a != b:
        raise SystemExit("核对不过：preflight.txt 只留那几行以后，m_instrument.preflight() 的结果变了")
    return text


def named_prefixes(out_dir):
    names = set()
    for p in sorted(glob.glob(os.path.join(out_dir, "*.json")) + glob.glob(os.path.join(out_dir, "*.md"))):
        with open(p, encoding="utf-8") as f:
            names |= set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}0/24", f.read()))
    return sorted(names)


# ---------------------------------------------------------------- 自检

def selftest():
    """在一个很小的合成“真实库”上导出一遍，核对假名的一致性、代表值、接缝表，再用 pub_check.scan 扫一遍。"""
    import tempfile
    import pub_check
    fails = []

    def expect(what, got, want):
        if got != want:
            fails.append("%s：得到 %r，期望 %r" % (what, got, want))

    judge, jip = "judge.real-example.org", "93.184.216.34"
    ev1, ev2, leaf = "ab" * 32, "cd" * 32, "ef" * 32
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "real.sqlite")
        con = sqlite3.connect(db)
        con.executescript("""
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
            CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
            CREATE TABLE self_leaf (leaf TEXT, source TEXT, n INTEGER, first_ts TEXT, last_ts TEXT);
            CREATE TABLE att (rid INTEGER PRIMARY KEY, ts_epoch REAL, cand TEXT, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT, cand_kind TEXT,
                              dst TEXT, nonce TEXT, tls_leaf TEXT, tls_subj TEXT, tls_issuer TEXT, ev TEXT, ip TEXT, raw TEXT, tls_detail TEXT);
            CREATE TABLE cands (rid INTEGER PRIMARY KEY, key TEXT, ip TEXT, port INTEGER, prefix24 TEXT, raw TEXT);
            CREATE TABLE evidence (hash TEXT, ext TEXT, bytes INTEGER, path TEXT);
            CREATE TABLE req (rid INTEGER PRIMARY KEY, ts_epoch REAL, remote TEXT, host TEXT, sni TEXT, target TEXT, nonce TEXT, err TEXT,
                              headers TEXT, raw TEXT);
            CREATE TABLE req_header (rid INTEGER PRIMARY KEY, req_rid INTEGER, nonce TEXT, seq INTEGER, name TEXT, value TEXT);
            CREATE TABLE nerr (rid INTEGER PRIMARY KEY, node TEXT, msg TEXT, raw TEXT);
            CREATE TABLE node (rid INTEGER PRIMARY KEY, id TEXT, host TEXT, port INTEGER);
            CREATE TABLE npre (rid INTEGER PRIMARY KEY, node TEXT, ips TEXT);
            CREATE TABLE secret_table (x TEXT);
            CREATE INDEX att_cand ON att(cand);
        """)
        con.executemany("INSERT INTO meta VALUES (?, ?)", [("ingest_version", "3"), ("data_dir", "/home/someone/data"),
                                                          ("judge_host_sha8", json.dumps(["0123abcd"]))])
        con.execute("INSERT INTO self_names VALUES (?, 'start.judge_host', 1)", (judge,))
        con.executemany("INSERT INTO self_ips VALUES (?, ?, 1)", [(jip, "start.judge_ip"), ("10.0.0.5", "nat"), ("127.0.0.1", "loop")])
        con.execute("INSERT INTO self_leaf VALUES (?, 'start', 1, NULL, NULL)", (leaf,))
        rows = [(1, 1.0, "1.2.3.4:8080", "1.2.3.4", 8080, "1.2.3.0/24", "proxy", "judge_tls", "n" * 20, leaf,
                 "CN=%s,O=Evil Org" % judge, "CN=Fake CA,O=Evil Org", ev1, "1.2.3.4", "{}", "x509: %s" % judge),
                (2, 2.0, "1.2.3.9:3128", "1.2.3.9", 3128, "1.2.3.0/24", "proxy", "judge_http", "m" * 20, None, None, None, None, jip, "{}", None),
                (3, 3.0, "control:direct", None, None, None, "control", "judge_tls", "k" * 20, None, None, None, None, "127.0.0.1", "{}", None)]
        con.executemany("INSERT INTO att VALUES (%s)" % ",".join("?" * 16), rows)
        con.executemany("INSERT INTO cands VALUES (?, ?, ?, ?, ?, '{}')", [(1, "1.2.3.4:8080", "1.2.3.4", 8080, "1.2.3.0/24"),
                                                                          (2, "1.2.3.9:3128", "1.2.3.9", 3128, "1.2.3.0/24")])
        con.executemany("INSERT INTO evidence VALUES (?, ?, 10, ?)", [(ev1, "der", "evidence/ab/%s.der" % ev1), (ev2, "body", "evidence/cd/%s.body" % ev2)])
        con.execute("INSERT INTO req VALUES (1, 1.5, '1.2.3.4', ?, ?, ?, ?, 'boom', 'h', 'r')",
                    (judge + ":443", judge, "http://%s/p/%s" % (judge, "n" * 20), "n" * 20))
        con.executemany("INSERT INTO req_header VALUES (?, 1, ?, ?, ?, ?)", [
            (1, "n" * 20, 0, "Cookie", "pc=CANARY123"), (2, "n" * 20, 1, "X-Probe-Canary", "CANARY123"),
            (3, "n" * 20, 2, "X-Forwarded-For", "%s, 1.2.3.4" % jip), (4, "n" * 20, 3, "Via", "1.1 squid.example.net"),
            (5, "n" * 20, 4, "User-Agent", SENT_VALUES.get("User-Agent") or "")])
        con.execute("INSERT INTO nerr VALUES (1, 'aaaaaaaaaaaa', 'config: bad uuid for node.example.net', '{}')")
        con.execute("INSERT INTO node VALUES (1, 'aaaaaaaaaaaa', 'node.example.net', 443)")
        con.execute("INSERT INTO npre VALUES (1, 'aaaaaaaaaaaa', ?)", (json.dumps(["5.6.7.8", "10.1.1.1"]),))
        con.commit()
        con.close()
        rec_path = os.path.join(tmp, "rec.sqlite")
        r = pubdb.Recorder(rec_path)
        r.put_rows("body_links", ["ev", "readable", "n_https", "n_http"], [(ev2, 1, 2, 0)])
        r.put_rows("aws", ["ip", "region"], [("1.2.3.4", "us-east-1"), ("1.2.3.9", None)])
        r.put_json("aws_note", {"syncToken": "1"})
        r.close()
        named = os.path.join(tmp, "named")
        os.mkdir(named)
        out = os.path.join(tmp, "pub.sqlite")
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            export(db, out, os.path.join(tmp, "key"), record=rec_path, named_from=named)
        pub = sqlite3.connect(out)
        q = lambda sql, *a: pub.execute(sql, a).fetchall()   # noqa: E731
        expect("是公开库", pubdb.is_public(pub), True)
        expect("本机路径不出", q("SELECT COUNT(*) FROM meta WHERE key = 'data_dir'"), [(0,)])
        expect("不在 SPEC 里的表不出", q("SELECT COUNT(*) FROM sqlite_master WHERE name = 'secret_table'"), [(0,)])
        expect("raw 列不出", "raw" in [c[1] for c in q("PRAGMA table_info(att)")], False)
        att = q("SELECT cand, cand_ip, prefix24, nonce, tls_subj, tls_issuer, ev, ip FROM att ORDER BY rid")
        c1, ip1, p1 = att[0][0], att[0][1], att[0][2]
        expect("假名地址在 240/4", pub_pseudo._v4(ip1) in pub_pseudo._PSEUDO4, True)
        expect("候选键 = 假名地址:原端口", c1, ip1 + ":8080")
        expect("同一个 /24 → 同一个假 /24", (att[1][2], p1 == att[1][1].rsplit(".", 1)[0] + ".0/24"), (p1, True))
        expect("cands 与 att 的假名一致", q("SELECT key, ip, prefix24 FROM cands ORDER BY rid")[0], (c1, ip1, p1))
        expect("对照组原样", att[2][0], "control:direct")
        expect("judge 的地址 → 固定假名", att[1][7] in ("240.0.0.101", "240.0.0.102"), True)
        expect("回环原样", att[2][7], "127.0.0.1")
        expect("主题：CN 是 judge 的假名", att[0][4].startswith("CN=%s,O=org-" % JUDGE_HOST), True)
        expect("签发者：只有 O 和 X", [k for k, _ in self_dn_parts(att[0][5])], ["O", "X"])
        expect("nonce 在 att 和 req 里一致", q("SELECT nonce FROM req")[0][0], att[0][3])
        expect("证据哈希与 evidence 一致", q("SELECT hash, path FROM evidence WHERE ext = 'der'")[0],
               (att[0][6], "evidence/%s/%s.der" % (att[0][6][:2], att[0][6])))
        req = q("SELECT remote, host, sni, target, err FROM req")[0]
        expect("Host 换成 judge 的假名（端口留着）", req[1:3], (JUDGE_HOST + ":443", JUDGE_HOST))
        expect("绝对 URI 仍是绝对 URI", req[3].startswith("http://%s/x/" % JUDGE_HOST), True)
        expect("错误只留有没有", req[4], "x")
        hv = dict(q("SELECT name, value FROM req_header"))
        expect("Cookie = pc= 加金丝雀的假名", hv["Cookie"], "pc=" + hv["X-Probe-Canary"])
        expect("请求头里探测器地址留下假名（与 att 里同一个）", hv["X-Forwarded-For"], att[1][7])
        expect("别的请求头清空", hv["Via"], "")
        expect("nerr.msg → 类别的代表值", q("SELECT msg FROM nerr"), [("config: x",)])
        expect("节点主机名 → 记号", q("SELECT host FROM node")[0][0].startswith("h-"), True)
        expect("npre.ips 里私网地址原样", json.loads(q("SELECT ips FROM npre")[0][0])[1], "10.1.1.1")
        expect("索引重建", q("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'att_cand'"), [(1,)])
        bl = q("SELECT ev, n_https FROM pub_body_links")
        expect("接缝表：证据哈希与 evidence 一致", bl, [(q("SELECT hash FROM evidence WHERE ext = 'body'")[0][0], 2)])
        expect("接缝表：AWS 区域跟着假名地址", dict(q("SELECT ip, region FROM pub_aws")), {ip1: "us-east-1", att[1][1]: None})
        expect("接缝 JSON", pubdb.replay_json(pub, "aws_note"), {"syncToken": "1"})
        pub.close()
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = pub_check.scan(out, db, named_from=named)
        expect("扫描没有残留", (rc, buf.getvalue().splitlines()[-1]), (0, "结论：没有发现残留"))
    for f in fails:
        print("不符：" + f, file=sys.stderr)
    print("pub_export 自检：%s" % ("通过" if not fails else "%d 项不符" % len(fails)))
    return 1 if fails else 0


def self_dn_parts(v):
    import m_mitm
    return m_mitm.dn_parts(v)


def main():
    ap = argparse.ArgumentParser(description="真实库 → 公开库（PUBLIC.md）")
    ap.add_argument("--db", help="真实的分析库（只读）")
    ap.add_argument("--out", help="公开库（不许放在仓库里）")
    ap.add_argument("--key", help="密钥文件；不存在就新建（32 字节随机数）。不进仓库，不公开")
    ap.add_argument("--record", help="模块在真实库上记下的中间结果（PHASE1B_RECORD 指向的文件）")
    ap.add_argument("--named-from", default=os.path.join(HERE, "out"), help="从这个目录的 *.json 里收集已经点了名的 /24（默认本目录的 out/）")
    ap.add_argument("--summary", help="数据包里的 summary.json；给了就把脱敏后的版本放进公开库的 pub_file 表")
    ap.add_argument("--preflight", help="数据包里的 preflight.txt；同上")
    ap.add_argument("--report", help="导出报告（JSON，只有计数和列名）写到哪里")
    ap.add_argument("--force", action="store_true", help="公开库已存在时删掉重建")
    ap.add_argument("--selftest", action="store_true", help="在合成库上导出一遍并核对")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not (args.db and args.out and args.key):
        ap.error("要给 --db、--out、--key")
    repo = os.path.abspath(os.path.join(HERE, "..", ".."))
    for p, what in ((args.out, "公开库"), (args.key, "密钥文件")):
        if os.path.abspath(p).startswith(repo + os.sep):
            raise SystemExit("%s不要放在仓库里：%s" % (what, p))
    export(args.db, args.out, args.key, record=args.record, named_from=args.named_from, summary=args.summary,
           preflight=args.preflight, report=args.report, force=args.force)
    return 0


def export(db_path, out, key_path, record=None, named_from=None, summary=None, preflight=None, report=None, force=False):
    if os.path.exists(out):
        if not force:
            raise SystemExit("公开库已存在：%s（加 --force 重建）" % out)
        os.remove(out)
    if not os.path.exists(key_path):
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
        log("新建了密钥文件（32 字节随机数）。它不进仓库，也不随公开库发布")
    with open(key_path, "rb") as f:
        key = f.read()

    import m_integrity
    import m_nodes
    import m_posthoc
    SENT_VALUES.update({k: v for k, v in m_integrity.SENT_HEADERS.items() if k in ("User-Agent", "Accept", "Accept-Language", "Accept-Encoding")})
    if m_posthoc.DOMAIN_RE.pattern != DOMAIN_RE.pattern:
        raise SystemExit("m_posthoc.DOMAIN_RE 变了，本脚本里的副本要跟着改")

    src = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(db_path), uri=True)
    src.row_factory = sqlite3.Row
    if pubdb.is_public(src):
        raise SystemExit("--db 给的已经是公开库")
    rec = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(record), uri=True) if record else None
    dst = sqlite3.connect(out)
    dst.execute("PRAGMA journal_mode = OFF")
    dst.execute("PRAGMA synchronous = OFF")
    ps = pub_pseudo.Pseudo(key)
    ex = Exporter(src, dst, ps, rec)
    ex._mem = sqlite3.connect(":memory:")
    ex._nerr_case = m_nodes.NERR_CASE

    t_all = time.time()
    log("第一遍：登记地址和 judge 的身份")
    named = named_prefixes(named_from or os.path.join(HERE, "out"))
    ex.prepare(named)
    mm = ex.mm
    ex._hosts_real, ex._ips_real = mm.judge_identity(mm.DB(os.path.abspath(db_path)))
    ex._hosts_fake = [ex.t_judge_name(h, None) for h in ex._hosts_real]
    ex._ips_fake = [ex.t_ip(i, None) for i in ex._ips_real]
    all_names = [r[0] for r in src.execute("SELECT DISTINCT name FROM self_names WHERE name IS NOT NULL AND name != ''")]
    ex._guard_real = [x.lower() for x in all_names + ex.judge_ips if x]
    ex._guard_fake = [x.lower() for x in list(ex.judge_names.values()) + [ex.t_ip(i, None) for i in ex.judge_ips] if x]

    log("第二遍：逐表导出")
    tables = [r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    rep_tables = collections.OrderedDict()
    for t in tables:
        if t in SPECIAL_TABLES:
            continue
        if t not in SPEC:
            rep_tables[t] = {"整张表不出": True}
            continue
        rep_tables[t] = ex.copy_table(t, SPEC[t])
    rep_rec = export_record(ex)
    dst.execute("CREATE TABLE pub_file (name TEXT PRIMARY KEY, content TEXT)")
    import m_instrument
    if summary:
        dst.execute("INSERT INTO pub_file VALUES ('summary.json', ?)", (sanitize_summary(summary, m_instrument.WARNING_PREFIXES),))
    if preflight:
        dst.execute("INSERT INTO pub_file VALUES ('preflight.txt', ?)", (sanitize_preflight(preflight, m_instrument),))
    dst.commit()
    rep_rec["pub_file"] = [r[0] for r in dst.execute("SELECT name FROM pub_file ORDER BY name")]
    rep_meta = export_meta(ex, {
        "public_version": PUBLIC_VERSION, "public_pseudo_v4": pub_pseudo.PSEUDO_V4, "public_pseudo_v6": pub_pseudo.PSEUDO_V6,
        "public_judge_host": JUDGE_HOST, "public_named_prefix24": str(len(ps.keep24)),
        "public_note": "这是脱敏后的公开库：地址、主机名、哈希是假名，自由文本是代表值。见 research/phase1b/PUBLIC.md"})
    log("索引和 ANALYZE")
    rep_idx = export_indexes(ex)
    rep = collections.OrderedDict([
        ("public_version", PUBLIC_VERSION), ("概况", ex.report), ("表", rep_tables), ("随库带上的中间结果", rep_rec), ("meta", rep_meta),
        ("索引", rep_idx), ("假名个数（不同原值）", check_injective(ex)), ("代表值核对", check_classifiers(ex)),
        ("其他核对", dict(ex.checks))])
    dst.execute("VACUUM")
    dst.close()
    src.close()
    if rec is not None:
        rec.close()
    text = json.dumps(rep, ensure_ascii=False, indent=1)
    if report:
        with open(report, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    log("完成：%s（%.1f MB，%.0f 秒）" % (out, os.path.getsize(out) / 1e6, time.time() - t_all))
    return rep


if __name__ == "__main__":
    raise SystemExit(main())

