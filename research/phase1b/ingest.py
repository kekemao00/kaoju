#!/usr/bin/env python3
"""把 fieldtest 的原始记录灌进一个 SQLite 库，供第一阶段 1B 的分析脚本用 SQL 聚合。

用法：
    python3 ingest.py --data <数据目录> --db <sqlite 路径> [--state <state.json.gz>]
                      [--sources <sources.json>] [--force]

数据目录可以是 `fieldtest pack` 解开后的 fieldtest/ 目录，也可以是测量机上的原始数据目录，两者布局相同。
目录里找不到 probe-*.jsonl* 而有 fieldtest/ 子目录时，自动进入子目录。

设计要点（细节见同目录的 SCHEMA.md）：
- 每种记录（JSON 里的 k）一张表，列名与 JSON 字段一致；嵌套对象拍平成前缀列（tcp_ok、tls_class、http_len 等），
  数组字段存成 JSON 文本，分析必需的数组另拆成子表（list_event、agg_member、visit_ok 等）。
- 每行保留原始 JSON 文本 raw；每张记录表都有 ts（UTC 文本，原样）和 ts_epoch（浮点秒）。
- 记录文件按小时逐个流式读取，每个文件一个事务，内存不随记录数增长；索引在全部载入之后再建。
- 同一小时同时存在 .jsonl 与 .jsonl.gz 时只读未压缩的那份（与 fieldtest 的 rec.Files 一致），
  被跳过的那份记进 files 表，并数一下它的行数以便核对。
- judge 的身份明文（主机名、公网 IP、叶子证书哈希）散布在很多列里，库里不清洗：所有表的 raw；start.raw；
  att 的 tls_subj / tls_issuer（叶子证书的 Subject/Issuer，公开证书的 CN 就是 judge 主机名）、ip（对照组回显）、
  tcp_detail / hs_detail / tls_detail / http_detail（Go 的 net 错误原文，带本机和代理的 ip:port）；req 的 host / sni /
  target / remote / headers / raw_head（base64，grep 明文查不到）；tls_fail 的 sni / remote；node 的 host / sni；
  cands.key、*.cand、npre.ips 等是候选和节点的地址。库本身不进仓库，所以这样存没有问题。
  self_ips / self_names / self_leaf 三张表把 judge 的身份各取一份供指标脚本判等。
- 指标脚本输出前按 OUTPUT_WHITELIST 取列（也写进 meta.output_whitelist），不按黑名单删词：
  白名单外的列一律不出现在 research/phase1b/out/ 里，见 SCHEMA.md“可输出列白名单”。
- 幂等：目标库已存在时拒绝覆盖；加 --force 先删再建。

只用 Python 3.10+ 标准库。
"""
import argparse
import base64
import calendar
import gzip
import hashlib
import json
import os
import re
import sqlite3
import sys
import time

INGEST_VERSION = "3"
# 3：att 加派生列 tls_detail_enum（tls_detail 移出白名单）；start.payload_sha256 移出白名单；
#    cand_src.src_name 改为先从快照数据多数票推出、再与 --sources 比对（meta.cand_src_names）
# 2：加 self_leaf 表、judge 叶子证书改从数据推导、meta 里带可输出列白名单

# ---------------------------------------------------------------- 时间

# 记录里的 ts 由 rec.TS 生成：UTC，毫秒，形如 2026-11-05T17:30:04.795Z（长度固定 24）。
# state.json.gz 里的时间由 Go 的 time.Time 直接序列化：RFC 3339，小数位 0 到 9 位、末尾零被去掉，
# 时区是服务器本地时区（真实数据是 +08:00；夹具是 Z）。两种都用下面的解析器，带偏移的换算成 UTC。
_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")
_hour_base = {}


def parse_ts(s):
    """解析 RFC 3339 时间。返回 (UTC 文本, 浮点秒, 偏移字符串)；Go 的零时间和解析不了的返回 (None, None, None)。

    UTC 文本保留原有的小数位数（Go 最多 9 位，Python 的 datetime 只有 6 位，所以不经 datetime 转换）。
    """
    if not s or s.startswith("0001-01-01"):
        return None, None, None
    if len(s) == 24 and s[-1] == "Z" and s[19] == "." and s[10] == "T":
        # 快速路径：记录里的 ts。按小时缓存 timegm 的结果，10^7 条记录只算几十次
        base = _hour_base.get(s[:13])
        if base is None:
            try:
                base = calendar.timegm((int(s[0:4]), int(s[5:7]), int(s[8:10]), int(s[11:13]), 0, 0, 0, 0, 0))
            except ValueError:
                return _parse_ts_slow(s)
            _hour_base[s[:13]] = base
        try:
            return s, base + int(s[14:16]) * 60 + int(s[17:19]) + int(s[20:23]) / 1000.0, "Z"
        except ValueError:
            return _parse_ts_slow(s)
    return _parse_ts_slow(s)


def _parse_ts_slow(s):
    m = _RFC3339.match(s.strip())
    if not m:
        return None, None, None
    y, mo, d, hh, mm, ss, frac, off = m.groups()
    try:
        secs = calendar.timegm((int(y), int(mo), int(d), int(hh), int(mm), int(ss), 0, 0, 0))
    except ValueError:
        return None, None, None
    if off != "Z":
        sign = 1 if off[0] == "+" else -1
        secs -= sign * (int(off[1:3]) * 3600 + int(off[4:6]) * 60)  # 本地时间 = UTC + 偏移，所以减掉偏移
    utc = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(secs))
    epoch = float(secs)
    if frac:
        utc += "." + frac
        epoch += int(frac) / (10 ** len(frac))
    return utc + "Z", epoch, off


# ---------------------------------------------------------------- 候选地址

_IPPORT = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$")


def split_cand(key):
    """把 "ip:port" 拆成 (ip, port, "/24 前缀")。不是这种形式（节点标识、control:*）时返回三个 None。"""
    m = _IPPORT.match(key) if key else None
    if not m:
        return None, None, None
    a, b, c, d, p = m.groups()
    return "%s.%s.%s.%s" % (a, b, c, d), int(p), "%s.%s.%s.0/24" % (a, b, c)


def cand_kind(key, proto):
    """att / visit 里 cand 字段的三种写法：代理 ip:port、节点标识（proto=node）、对照组 control:*。"""
    if key and key.startswith("control:"):
        return "control"
    if proto == "node":
        return "node"
    if split_cand(key)[0] is not None:
        return "proxy"
    return "other"


def sha8(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8] if s else None


_TLS_DETAIL_ENUM = re.compile(r"^(unknown_authority|hostname_mismatch|invalid_\d+)$")


def tls_detail_enum(tls_class, detail):
    """att.tls_detail 的可输出版本（派生列 att.tls_detail_enum）。

    wire.go TLS()：tls_class='tls_cert_invalid' 时 detail 被改写成三种枚举值之一——unknown_authority（x509.UnknownAuthorityError）、
    hostname_mismatch（x509.HostnameError）、invalid_<n>（x509.CertificateInvalidError，n 是 InvalidReason）；
    别的类别时 detail 是 short(err) 的 Go 错误原文，形如 "read tcp 本机ip:端口->代理ip:端口: i/o timeout"，
    带单个代理的 ip:port，不能出现在输出里。黑名单删词靠不住，所以入库时就把可输出的部分单独拆成一列：
      tls_cert_invalid 且 detail 是枚举值 → 原值；
      tls_cert_invalid 但 detail 不是枚举值（x509 的其他错误类型，detail 仍是错误原文）→ 'other'；
      其他类别 → NULL（失败原因已在 tls_class 里，detail 只是原文）。
    """
    if tls_class != "tls_cert_invalid":
        return None
    if isinstance(detail, str) and _TLS_DETAIL_ENUM.match(detail):
        return detail
    return "other"


def jdump(v):
    return None if v is None else json.dumps(v, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------- 表定义
#
# 每张记录表的列由 FIELDS 描述：(列名, SQLite 类型, 来源)。来源有三种：
#   "x"          顶层字段 x
#   ("tcp", "ok") 嵌套对象 tcp 里的字段 ok，拍平成列 tcp_ok
#   None          派生列，由各表的 hook 填
# 类型 JSON 表示数组或对象，存成 JSON 文本。

# wire.Step：TCP、握手、DNS 阶段共用
STEP = [("ok", "INTEGER"), ("ms", "INTEGER"), ("class", "TEXT"), ("code", "INTEGER"), ("detail", "TEXT"),
        ("banner", "TEXT"), ("sniff", "TEXT")]
# wire.TLSInfo
TLSI = [("ok", "INTEGER"), ("ms", "INTEGER"), ("class", "TEXT"), ("detail", "TEXT"), ("ver", "TEXT"),
        ("cipher", "TEXT"), ("leaf", "TEXT"), ("subj", "TEXT"), ("issuer", "TEXT"), ("self", "INTEGER"),
        ("banner", "TEXT"), ("sniff", "TEXT")]
# probe.HTTPResult = wire.Step + 正文核对的字段
HTTPR = STEP + [("len", "INTEGER"), ("sha", "TEXT"), ("pre", "INTEGER"), ("suf", "INTEGER"), ("sim", "INTEGER"),
                ("canary", "TEXT"), ("flags", "JSON"), ("added", "JSON"), ("hdr", "JSON"), ("ev", "TEXT")]
# lists.Quality
QUAL = [("lines", "INTEGER"), ("garbage", "INTEGER"), ("hostname", "INTEGER"), ("no_port", "INTEGER"),
        ("bad_range", "INTEGER"), ("duplicate", "INTEGER"), ("with_credentials", "INTEGER")]


def nested(prefix, fields):
    return [("%s_%s" % (prefix, f), t, (prefix, f)) for f, t in fields]


def top(*cols):
    return [(c, t, c) for c, t in cols]


# judge.Rec：req、noise、tls_fail、noise_dropped、req_dropped 五种记录共用同一个结构
JUDGE_REC = top(("remote", "TEXT"), ("rport", "INTEGER"), ("tls", "INTEGER"), ("tls_ver", "TEXT"), ("cipher", "TEXT"),
                ("sni", "TEXT"), ("alpn", "TEXT"), ("hello_fp", "TEXT"), ("method", "TEXT"), ("target", "TEXT"),
                ("proto", "TEXT"), ("host", "TEXT"), ("nonce", "TEXT"), ("age_s", "INTEGER"), ("kind", "TEXT"),
                ("req_canary", "TEXT"), ("headers", "JSON"), ("raw_head", "TEXT"), ("status", "INTEGER"),
                ("err", "TEXT"), ("n", "INTEGER"))

FIELDS = {
    # probe-：probe.Attempt。派生列：cand_* 是地址拆分；tls_detail_enum 是 tls_detail 里可输出的枚举部分（见 tls_detail_enum()）
    "att": top(("visit", "TEXT"), ("cand", "TEXT"), ("proto", "TEXT"), ("dst", "TEXT"), ("kind", "TEXT"),
               ("arm", "TEXT"), ("nonce", "TEXT"))
    + nested("tcp", STEP) + nested("hs", STEP) + nested("tls", TLSI) + nested("http", HTTPR)
    + top(("class", "TEXT"), ("ip", "TEXT"), ("ev", "TEXT"), ("ms", "INTEGER"))
    + [("cand_kind", "TEXT", None), ("cand_ip", "TEXT", None), ("cand_port", "INTEGER", None), ("prefix24", "TEXT", None),
       ("tls_detail_enum", "TEXT", None)],
    # probe.VisitRec
    "visit": top(("visit", "TEXT"), ("cand", "TEXT"), ("group", "INTEGER"), ("n", "INTEGER"), ("prev", "TEXT"),
                 ("state", "TEXT"), ("full", "INTEGER"), ("listed", "INTEGER"), ("labels", "JSON"), ("tried", "JSON"),
                 ("ok", "JSON"), ("auth", "INTEGER"), ("aborted", "INTEGER"), ("next_min", "REAL"), ("ms", "INTEGER"))
    + [("cand_ip", "TEXT", None), ("cand_port", "INTEGER", None), ("prefix24", "TEXT", None), ("n_ok", "INTEGER", None)],
    # probe.NPreRec
    "npre": top(("round", "INTEGER"), ("node", "TEXT")) + nested("dns", STEP) + top(("ips", "JSON"))
    + nested("tcp", STEP) + top(("class", "TEXT")) + [("n_ips", "INTEGER", None)],
    # probe.NErrRec
    "nerr": top(("round", "INTEGER"), ("node", "TEXT"), ("arm", "TEXT"), ("msg", "TEXT")),
    # probe.NRoundRec
    "nround": top(("round", "INTEGER"), ("known", "INTEGER"), ("listed", "INTEGER"), ("supported", "INTEGER"),
                  ("backoff", "INTEGER"), ("tcp_ok", "INTEGER"), ("probed", "INTEGER"), ("ok_strict", "INTEGER"),
                  ("ok_linked", "INTEGER"), ("bad_config", "INTEGER"), ("batches", "INTEGER"), ("ms", "INTEGER"),
                  ("err", "TEXT")),
    # probe.StatRec
    "stat": top(("up_min", "REAL"), ("visits", "INTEGER"), ("records", "INTEGER"), ("pool", "JSON")),
    # prober.Run 写的 start：judge 主机名和 IP 存 sha256 前 8 位（派生列，只用于判断多条 start 的值是否相同），明文在 raw 里。
    # 注意 sha256 前 8 位对 IPv4 可以穷举还原（2^32 个候选），对主机名可以查字典，所以这两列同样不可输出。
    # payload_sha256 也不可输出：h 载荷的正文是公开模板 htmlTemplate 填入 judge 主机名（payload.go Build()），
    # 拿到哈希的人把猜测的主机名填进模板算一次 sha256 就能验证猜测；核对载荷一致性只输出 COUNT(DISTINCT payload_sha256)
    "start": top(("resumed_candidates", "INTEGER"), ("load_err", "TEXT"), ("http_port", "INTEGER"),
                 ("https_port", "INTEGER"), ("probe", "JSON"), ("payload_sha256", "JSON"))
    + [("judge_host_sha8", "TEXT", None), ("judge_ip_sha8", "TEXT", None)],
    "stop": top(("visits", "INTEGER")),
    "version": top(("version", "TEXT")),
    "error": top(("what", "TEXT"), ("err", "TEXT"), ("stack", "TEXT")),
    # judge-
    "req": JUDGE_REC,
    "noise": JUDGE_REC,
    "tls_fail": JUDGE_REC,
    "noise_dropped": JUDGE_REC,
    "req_dropped": JUDGE_REC,
    # snap-：lists.SnapRec
    "snap": top(("src", "TEXT"), ("label", "TEXT"), ("status", "INTEGER"), ("err", "TEXT"), ("etag", "TEXT"),
                ("sha256", "TEXT"), ("bytes", "INTEGER"), ("n", "INTEGER")) + nested("q", QUAL)
    + top(("base", "INTEGER"), ("agg", "INTEGER"), ("add", "JSON"), ("del", "JSON"), ("ms", "INTEGER"),
          ("changed", "INTEGER")) + [("n_add", "INTEGER", None), ("n_del", "INTEGER", None)],
    # probe.AggSampleRec
    "agg_sample": top(("src", "TEXT"), ("union", "INTEGER"), ("exclusive", "INTEGER"), ("sample", "INTEGER"),
                      ("seed", "TEXT"), ("members", "JSON")),
    # probe.NSnapRec
    "nsnap": top(("src", "TEXT"), ("status", "INTEGER"), ("err", "TEXT"), ("sha256", "TEXT"), ("bytes", "INTEGER"),
                 ("lines", "INTEGER"), ("unparsed", "INTEGER"), ("n", "INTEGER"), ("base", "INTEGER"),
                 ("changed", "INTEGER"), ("add", "JSON"), ("del", "JSON"), ("ms", "INTEGER"))
    + [("n_add", "INTEGER", None), ("n_del", "INTEGER", None)],
    # probe.NodeRec（内嵌 nodes.Node 里带 json 标签的字段；凭据在 Go 侧就没有写出）
    "node": top(("src", "TEXT"), ("id", "TEXT"), ("scheme", "TEXT"), ("host", "TEXT"), ("port", "INTEGER"),
                ("method", "TEXT"), ("aid", "INTEGER"), ("flow", "TEXT"), ("net", "TEXT"), ("hdr", "TEXT"),
                ("sec", "TEXT"), ("sni", "TEXT"), ("insecure", "INTEGER"), ("plugin", "TEXT"), ("why", "TEXT")),
}

# 哪个前缀的文件里应该出现哪些 k。别的 k 进 misc 表，并在 meta 里记一笔
EXPECTED_KINDS = {
    "probe": {"att", "visit", "npre", "nerr", "nround", "stat", "start", "stop", "version", "error"},
    "judge": {"req", "noise", "tls_fail", "noise_dropped", "req_dropped"},
    "snap": {"snap", "agg_sample", "nsnap", "node"},
}

# 子表和辅助表
AUX_TABLES = {
    "att_http_flag": "rid INTEGER PRIMARY KEY, att_rid INTEGER NOT NULL, flag TEXT NOT NULL",
    "att_http_added": "rid INTEGER PRIMARY KEY, att_rid INTEGER NOT NULL, header TEXT NOT NULL",
    "visit_ok": "rid INTEGER PRIMARY KEY, visit_rid INTEGER NOT NULL, visit TEXT NOT NULL, cand TEXT NOT NULL, "
                "ts TEXT, ts_epoch REAL, proto TEXT NOT NULL",
    "visit_tried": "rid INTEGER PRIMARY KEY, visit_rid INTEGER NOT NULL, visit TEXT NOT NULL, cand TEXT NOT NULL, "
                   "seq INTEGER NOT NULL, proto TEXT NOT NULL",
    "npre_ip": "rid INTEGER PRIMARY KEY, npre_rid INTEGER NOT NULL, node TEXT NOT NULL, round INTEGER, "
               "seq INTEGER NOT NULL, ip TEXT NOT NULL",
    "stat_pool": "rid INTEGER PRIMARY KEY, stat_rid INTEGER NOT NULL, ts TEXT, ts_epoch REAL, key TEXT NOT NULL, "
                 "value INTEGER",
    "req_header": "rid INTEGER PRIMARY KEY, req_rid INTEGER NOT NULL, nonce TEXT, seq INTEGER NOT NULL, "
                  "name TEXT NOT NULL, value TEXT",
    "list_event": "rid INTEGER PRIMARY KEY, snap_rid INTEGER NOT NULL, ts TEXT NOT NULL, ts_epoch REAL NOT NULL, "
                  "src TEXT NOT NULL, label TEXT NOT NULL, cand TEXT NOT NULL, event TEXT NOT NULL, "
                  "base INTEGER NOT NULL, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT",
    "agg_member": "rid INTEGER PRIMARY KEY, agg_sample_rid INTEGER NOT NULL, ts TEXT NOT NULL, ts_epoch REAL NOT NULL, "
                  "src TEXT NOT NULL, seq INTEGER NOT NULL, cand TEXT NOT NULL, cand_ip TEXT, cand_port INTEGER, "
                  "prefix24 TEXT",
    "node_event": "rid INTEGER PRIMARY KEY, nsnap_rid INTEGER NOT NULL, ts TEXT NOT NULL, ts_epoch REAL NOT NULL, "
                  "src TEXT NOT NULL, node TEXT NOT NULL, event TEXT NOT NULL, base INTEGER NOT NULL",
    "misc": "rid INTEGER PRIMARY KEY, file_id INTEGER NOT NULL, k TEXT, ts TEXT, ts_epoch REAL, raw TEXT NOT NULL",
    "bad_line": "rid INTEGER PRIMARY KEY, file_id INTEGER NOT NULL, lineno INTEGER NOT NULL, why TEXT NOT NULL, "
                "raw TEXT NOT NULL",
    "files": "id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, prefix TEXT, hour TEXT, compressed INTEGER, "
             "bytes INTEGER, status TEXT NOT NULL, records INTEGER, bad_lines INTEGER, first_ts TEXT, last_ts TEXT, "
             "note TEXT",
    "file_kind": "file_id INTEGER NOT NULL, k TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (file_id, k)",
    "meta": "key TEXT PRIMARY KEY, value TEXT",
    "evidence": "hash TEXT NOT NULL, ext TEXT NOT NULL, bytes INTEGER NOT NULL, path TEXT NOT NULL, "
                "PRIMARY KEY (hash, ext)",
    "cands": "rid INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, ip TEXT NOT NULL, port INTEGER NOT NULL, "
             "prefix24 TEXT NOT NULL, \"group\" INTEGER NOT NULL, srcs TEXT, n_srcs INTEGER NOT NULL, "
             "listed INTEGER NOT NULL, labels INTEGER NOT NULL, label_names TEXT NOT NULL, "
             "ts TEXT, ts_epoch REAL, first_seen_raw TEXT, first_seen TEXT, first_seen_epoch REAL, "
             "delisted_at_raw TEXT, delisted_at TEXT, delisted_at_epoch REAL, next_raw TEXT, next TEXT, next_epoch REAL, "
             "visits INTEGER NOT NULL, fails INTEGER NOT NULL, state INTEGER NOT NULL, state_name TEXT NOT NULL, "
             "ok_mask INTEGER NOT NULL, ok_protos TEXT NOT NULL, ever_ok INTEGER NOT NULL, "
             "last_ok_raw TEXT, last_ok TEXT, last_ok_epoch REAL, last_full_raw TEXT, last_full TEXT, last_full_epoch REAL, "
             "last_extra_raw TEXT, last_extra TEXT, last_extra_epoch REAL, raw TEXT NOT NULL",
    "cand_src": "rid INTEGER PRIMARY KEY, key TEXT NOT NULL, src_idx INTEGER NOT NULL, src_name TEXT, "
                "labels INTEGER NOT NULL, label_names TEXT NOT NULL",
    # judge 的身份：只用于库内判等，任何输出脚本不许写出（叶子证书哈希也不行：公开证书的指纹可在 CT 日志里查到主机名）
    "self_ips": "ip TEXT NOT NULL, source TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (ip, source)",
    "self_names": "name TEXT NOT NULL, source TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (name, source)",
    "self_leaf": "leaf TEXT NOT NULL, source TEXT NOT NULL, n INTEGER NOT NULL, first_ts TEXT, last_ts TEXT, "
                 "PRIMARY KEY (leaf, source)",
}

INDEXES = [
    "CREATE INDEX att_cand_ts ON att(cand, ts_epoch)",
    "CREATE INDEX att_visit ON att(visit)",
    "CREATE INDEX att_nonce ON att(nonce) WHERE nonce IS NOT NULL",
    "CREATE INDEX att_ts ON att(ts_epoch)",
    "CREATE INDEX att_proto_dst_class ON att(proto, dst, class)",
    "CREATE INDEX att_prefix24 ON att(prefix24) WHERE prefix24 IS NOT NULL",
    "CREATE INDEX att_tls_leaf ON att(tls_leaf) WHERE tls_leaf IS NOT NULL",
    "CREATE INDEX att_flag_att ON att_http_flag(att_rid)",
    "CREATE INDEX att_added_att ON att_http_added(att_rid)",
    "CREATE INDEX visit_cand_ts ON visit(cand, ts_epoch)",
    "CREATE INDEX visit_visit ON visit(visit)",
    "CREATE INDEX visit_ts ON visit(ts_epoch)",
    "CREATE INDEX visit_prefix24 ON visit(prefix24) WHERE prefix24 IS NOT NULL",
    "CREATE INDEX visit_ok_visit ON visit_ok(visit)",
    "CREATE INDEX visit_ok_cand ON visit_ok(cand)",
    "CREATE INDEX visit_tried_visit ON visit_tried(visit)",
    "CREATE INDEX npre_node_round ON npre(node, round)",
    "CREATE INDEX npre_ts ON npre(ts_epoch)",
    "CREATE INDEX npre_ip_node ON npre_ip(node)",
    "CREATE INDEX nerr_node ON nerr(node, round)",
    "CREATE INDEX nround_round ON nround(round)",
    "CREATE INDEX stat_ts ON stat(ts_epoch)",
    "CREATE INDEX stat_pool_key ON stat_pool(key)",
    "CREATE INDEX req_nonce ON req(nonce)",
    "CREATE INDEX req_remote ON req(remote)",
    "CREATE INDEX req_ts ON req(ts_epoch)",
    "CREATE INDEX req_header_req ON req_header(req_rid)",
    "CREATE INDEX req_header_name ON req_header(name)",
    "CREATE INDEX noise_ts ON noise(ts_epoch)",
    "CREATE INDEX tls_fail_ts ON tls_fail(ts_epoch)",
    "CREATE INDEX tls_fail_remote ON tls_fail(remote)",
    "CREATE INDEX snap_src_label_ts ON snap(src, label, ts_epoch)",
    "CREATE INDEX list_event_cand ON list_event(cand, ts_epoch)",
    "CREATE INDEX list_event_src ON list_event(src, label, ts_epoch)",
    "CREATE INDEX list_event_ts ON list_event(ts_epoch)",
    "CREATE INDEX agg_member_cand ON agg_member(cand)",
    "CREATE INDEX nsnap_src_ts ON nsnap(src, ts_epoch)",
    "CREATE INDEX node_event_node ON node_event(node, ts_epoch)",
    "CREATE INDEX node_id ON node(id)",
    "CREATE INDEX cands_prefix24 ON cands(prefix24)",
    "CREATE INDEX cands_group_state ON cands(\"group\", state)",
    "CREATE INDEX cand_src_key ON cand_src(key)",
    "CREATE INDEX misc_k ON misc(k)",
]

# ---------------------------------------------------------------- 可输出列白名单
#
# 仓库是公开的。指标脚本写进 research/phase1b/out/ 的东西只能来自下面列出的列（作为 GROUP BY 的维度或被聚合的值），
# 而不是“把库里的值拿出来再删掉敏感词”——黑名单会漏（raw_head 是 base64，*_detail 是 Go 错误原文，tls_subj 是证书 CN……）。
# 原则：枚举值（class、*_class、sniff、proto、dst、state……）、计数和聚合值、毫秒数、时间（分桶后）、/24 前缀、
# 来源名、头名（不含值）可以输出；地址、主机名、哈希、自由文本、原始 JSON 一律不行。
# 不在这里的列就是不可输出。要放开某一列，先在 SCHEMA.md“可输出列白名单”里写明理由再改这里。
_TS = ["ts", "ts_epoch"]
_STEP_OUT = lambda p: ["%s_ok" % p, "%s_ms" % p, "%s_class" % p, "%s_code" % p, "%s_sniff" % p]  # 不含 detail、banner
OUTPUT_WHITELIST = {
    "att": ["proto", "dst", "kind", "arm"] + _STEP_OUT("tcp") + _STEP_OUT("hs")
    + ["tls_ok", "tls_ms", "tls_class", "tls_detail_enum", "tls_ver", "tls_cipher", "tls_self", "tls_sniff"]
    + _STEP_OUT("http") + ["http_len", "http_pre", "http_suf", "http_sim", "http_canary", "http_flags",
                           "class", "ms", "cand_kind", "cand_port", "prefix24"] + _TS,
    "att_http_flag": ["flag"],
    "att_http_added": ["header"],
    "visit": ["group", "n", "prev", "state", "full", "listed", "labels", "tried", "ok", "auth", "aborted", "next_min",
              "ms", "n_ok", "cand_port", "prefix24"] + _TS,
    "visit_ok": ["proto"] + _TS,
    "visit_tried": ["seq", "proto"],
    "npre": ["round", "node"] + _STEP_OUT("dns") + _STEP_OUT("tcp") + ["class", "n_ips"] + _TS,
    "npre_ip": ["round", "node", "seq"],
    "nerr": ["round", "node", "arm"] + _TS,
    "nround": ["round", "known", "listed", "supported", "backoff", "tcp_ok", "probed", "ok_strict", "ok_linked",
               "bad_config", "batches", "ms"] + _TS,
    "stat": ["up_min", "visits", "records", "pool"] + _TS,
    "stat_pool": ["key", "value"] + _TS,
    "start": ["resumed_candidates"] + _TS,
    "stop": ["visits"] + _TS,
    "version": ["version"] + _TS,
    "error": ["what"] + _TS,
    "req": ["tls", "tls_ver", "cipher", "alpn", "hello_fp", "method", "proto", "kind", "age_s", "req_canary",
            "status"] + _TS,
    "req_header": ["seq", "name"],
    "noise": ["tls", "tls_ver", "cipher", "alpn", "hello_fp", "method", "proto", "status"] + _TS,
    "tls_fail": ["tls", "tls_ver", "cipher", "alpn", "hello_fp"] + _TS,
    "noise_dropped": ["n"] + _TS,
    "req_dropped": ["n"] + _TS,
    "snap": ["src", "label", "status", "bytes", "n", "q_lines", "q_garbage", "q_hostname", "q_no_port", "q_bad_range",
             "q_duplicate", "q_with_credentials", "base", "agg", "ms", "changed", "n_add", "n_del"] + _TS,
    "list_event": ["src", "label", "event", "base", "cand_port", "prefix24"] + _TS,
    "agg_sample": ["src", "union", "exclusive", "sample", "seed"] + _TS,
    "agg_member": ["src", "seq", "cand_port", "prefix24"] + _TS,
    "nsnap": ["src", "status", "bytes", "lines", "unparsed", "n", "base", "changed", "ms", "n_add", "n_del"] + _TS,
    "node_event": ["src", "node", "event", "base"] + _TS,
    "node": ["src", "id", "scheme", "method", "aid", "flow", "net", "sec", "insecure", "why"] + _TS,
    "cands": ["prefix24", "port", "group", "n_srcs", "listed", "labels", "label_names", "visits", "fails", "state",
              "state_name", "ok_mask", "ok_protos", "ever_ok", "first_seen", "first_seen_epoch", "delisted_at",
              "delisted_at_epoch", "next", "next_epoch", "last_ok", "last_ok_epoch", "last_full", "last_full_epoch",
              "last_extra", "last_extra_epoch"] + _TS,
    "cand_src": ["src_idx", "src_name", "labels", "label_names"],
    "files": ["name", "prefix", "hour", "compressed", "bytes", "status", "records", "bad_lines", "first_ts", "last_ts",
              "note"],
    "file_kind": ["file_id", "k", "n"],
    "evidence": ["ext", "bytes"],
    "misc": ["k"] + _TS,
    "bad_line": ["lineno", "why"],
    # meta 按键名：路径、judge 身份的哈希都不在这里
    "meta": ["ingest_version", "ingested_at_utc", "python", "sqlite", "ingest_seconds", "files_read", "records_total",
             "records_by_kind", "first_ts", "last_ts", "duplicate_hour_files", "unknown_fields", "misplaced_kinds",
             "judge_leaf_observed_count", "judge_leaf_pem_present", "judge_leaf_pem_matches_observed",
             "judge_leaf_tls_ok_extra_count", "payload_len", "state_cands", "state_tz_offsets", "state_sampled",
             "state_mtime_utc", "sources_sha256", "sources_names", "cand_src_names", "cand_src_check", "evidence_files",
             "evidence_bytes",
             "summary_json", "output_whitelist", "output_rules"],
    "self_ips": [], "self_names": [], "self_leaf": [],
}
# 白名单之上的附加规则（机器可读的只有键名，说明给人看；check_output_columns 只管列名）
OUTPUT_RULES = {
    "att.tls_detail": "整列不输出：tls_class 不是 tls_cert_invalid 时它是 Go 错误原文，带代理的 ip:port。"
                      "用派生列 tls_detail_enum（tls_cert_invalid 时的 unknown_authority / hostname_mismatch / invalid_<n>，"
                      "其他 tls_cert_invalid 归并成 other，别的类别 NULL；wire.go TLS()）",
    "start.payload_sha256": "载荷哈希不输出：h 载荷是公开模板填入 judge 主机名后的正文（payload.go Build()），"
                            "哈希可用来验证对主机名的猜测；核对载荷一致性只输出 COUNT(DISTINCT payload_sha256)",
    "*.cand_port / cands.port": "只能单独作为维度（端口分布），不能与 prefix24 或任何别的地址信息同行出现",
    "att.tls_leaf / meta.judge_leaf_*": "叶子证书哈希不输出（公开证书的指纹可在 CT 日志查到主机名）；"
                                        "只输出“等于 judge 叶子”的计数，判等用 self_leaf 表",
    "att.ev / att.http_ev / att.http_sha": "证据哈希不输出，只输出 COUNT(DISTINCT …)",
    "start.probe": "整列不输出（exclude_file 是本机路径）；需要的数值字段用 json_extract 单独取",
    "att.dst": "obs:<名> 里的名字是配置里的观察者名，输出前核对它不是主机名",
    "时间列": "ts / *_epoch 只在分桶（小时、分钟）或做差之后输出，不输出逐行时间",
    "行": "输出的永远是聚合结果，不是行；每个数字都要带分子、分母和口径说明",
}


def check_output_columns(table, cols):
    """指标脚本写出前调用：列名全在白名单里才放行，否则抛 ValueError 并列出越界的列。"""
    allowed = OUTPUT_WHITELIST.get(table)
    if allowed is None:
        raise ValueError("表 %s 不在白名单里，没有任何列可以输出" % table)
    bad = [c for c in cols if c not in allowed]
    if bad:
        raise ValueError("表 %s 的这些列不可输出：%s" % (table, ", ".join(bad)))
    return True


# sched.go 里的常量
STATE_NAMES = ["new", "working", "open", "dead"]
LABEL_BITS = [(1, "http"), (2, "https"), (4, "connect"), (8, "socks4"), (16, "socks5")]  # lists.go labelNames
PROTO_BITS = [(1, "socks5"), (2, "socks4"), (4, "connect"), (8, "forward")]  # sched.go protoBits


def bit_names(mask, table):
    return [name for bit, name in table if mask & bit]


# ---------------------------------------------------------------- 写库

BATCH = 2000


class Sink:
    """按表攒批写入。rid 由这里分配，子表靠它关联父行，不必回查 last_insert_rowid。"""

    def __init__(self, conn):
        self.conn = conn
        self.sql = {}
        self.buf = {}
        self.next_rid = {}

    def prepare(self, table, ncols):
        self.sql[table] = "INSERT INTO \"%s\" VALUES (%s)" % (table, ",".join("?" * ncols))
        self.buf[table] = []
        self.next_rid.setdefault(table, 1)

    def rid(self, table):
        r = self.next_rid[table]
        self.next_rid[table] = r + 1
        return r

    def add(self, table, row):
        b = self.buf[table]
        b.append(row)
        if len(b) >= BATCH:
            self.conn.executemany(self.sql[table], b)
            b.clear()

    def flush(self):
        for table, b in self.buf.items():
            if b:
                self.conn.executemany(self.sql[table], b)
                b.clear()


def create_schema(conn):
    conn.execute("PRAGMA page_size = 8192")
    for k, fields in FIELDS.items():
        cols = ["rid INTEGER PRIMARY KEY", "file_id INTEGER NOT NULL", "ts TEXT", "ts_epoch REAL"]
        for name, typ, _ in fields:
            cols.append("\"%s\" %s" % (name, "TEXT" if typ == "JSON" else typ))
        cols.append("raw TEXT NOT NULL")
        conn.execute("CREATE TABLE \"%s\" (%s)" % (k, ", ".join(cols)))
    for name, ddl in AUX_TABLES.items():
        conn.execute("CREATE TABLE \"%s\" (%s)" % (name, ddl))


class Ingest:
    def __init__(self, conn, sink):
        self.conn = conn
        self.sink = sink
        self.unknown = {}  # (k, 字段) → 次数：记录里出现、FIELDS 没列的字段
        self.misplaced = {}  # (文件前缀, k) → 次数：出现在不该出现的文件里的记录
        self.judge_hosts = {}  # start 记录里的 judge_host → 次数（只进 self_names，不进 meta 明文）
        self.judge_ips = {}  # start 记录里的 judge_ip → 次数
        self.payload_len = {}  # kind → {http_len: 次数}：成功到达 judge、响应头没被动过的尝试，用来推期望正文长度
        self.hooks = {"att": self.hook_att, "visit": self.hook_visit, "npre": self.hook_npre, "stat": self.hook_stat,
                      "start": self.hook_start, "req": self.hook_req, "snap": self.hook_snap,
                      "agg_sample": self.hook_agg, "nsnap": self.hook_nsnap}
        # 预编译每张表的取值计划：(列下标, 来源)
        self.plans = {}
        self.known = {}
        self.col = {k: {name: i for i, (name, _, _) in enumerate(fields)} for k, fields in FIELDS.items()}
        for k, fields in FIELDS.items():
            plan = []
            known_top = set()
            known_nested = {}
            for i, (name, typ, src) in enumerate(fields):
                if src is None:
                    continue
                if isinstance(src, tuple):
                    plan.append((i, src[0], src[1], typ == "JSON"))
                    known_nested.setdefault(src[0], set()).add(src[1])
                    known_top.add(src[0])
                else:
                    plan.append((i, None, src, typ == "JSON"))
                    known_top.add(src)
            known_top |= {"k", "ts"}
            self.plans[k] = plan
            self.known[k] = (known_top, known_nested)
            sink.prepare(k, 4 + len(fields) + 1)
        for name, ddl in AUX_TABLES.items():
            if name in ("files", "file_kind", "meta", "evidence", "self_ips", "self_names", "self_leaf"):
                continue
            sink.prepare(name, ddl.count(",") + 1)

    def note_unknown(self, k, rec):
        known_top, known_nested = self.known[k]
        for key, v in rec.items():
            if key not in known_top:
                self.unknown[(k, key)] = self.unknown.get((k, key), 0) + 1
            elif key in known_nested and isinstance(v, dict):
                for sub in v:
                    if sub not in known_nested[key]:
                        self.unknown[(k, key + "." + sub)] = self.unknown.get((k, key + "." + sub), 0) + 1

    def record(self, k, rec, raw, file_id, ts, ts_epoch):
        """把一条记录写进它的表，返回 rid。"""
        fields = FIELDS[k]
        vals = [None] * len(fields)
        for i, obj, key, is_json in self.plans[k]:
            if obj is None:
                v = rec.get(key)
            else:
                d = rec.get(obj)
                v = d.get(key) if isinstance(d, dict) else None
            if v is not None:
                if is_json:
                    v = jdump(v)
                elif isinstance(v, bool):
                    v = int(v)
            vals[i] = v
        self.note_unknown(k, rec)
        rid = self.sink.rid(k)
        hook = self.hooks.get(k)
        if hook is not None:
            hook(rid, rec, vals, fields, ts, ts_epoch)
        self.sink.add(k, [rid, file_id, ts, ts_epoch] + vals + [raw])
        return rid

    # ---- 各表的派生列和子表。vals 的下标按 FIELDS 的顺序，self.col 把列名换成下标

    def hook_att(self, rid, rec, vals, fields, ts, ts_epoch):
        cand, proto = rec.get("cand"), rec.get("proto")
        kind = cand_kind(cand, proto)
        vals[self.col["att"]["cand_kind"]] = kind
        if kind == "proxy":
            ip, port, pfx = split_cand(cand)
            vals[self.col["att"]["cand_ip"]] = ip
            vals[self.col["att"]["cand_port"]] = port
            vals[self.col["att"]["prefix24"]] = pfx
        tls = rec.get("tls")
        if isinstance(tls, dict):
            vals[self.col["att"]["tls_detail_enum"]] = tls_detail_enum(tls.get("class"), tls.get("detail"))
        http = rec.get("http")
        if isinstance(http, dict):
            flags = http.get("flags")
            for flag in flags or ():
                self.sink.add("att_http_flag", [self.sink.rid("att_http_flag"), rid, flag])
            for h in http.get("added") or ():
                self.sink.add("att_http_added", [self.sink.rid("att_http_added"), rid, h])
            if rec.get("class") == "ok" and not flags and rec.get("dst") in ("judge_http", "judge_tls"):
                ln = http.get("len")
                if isinstance(ln, int):
                    d = self.payload_len.setdefault(rec.get("kind"), {})
                    d[ln] = d.get(ln, 0) + 1

    def hook_visit(self, rid, rec, vals, fields, ts, ts_epoch):
        cand = rec.get("cand")
        ip, port, pfx = split_cand(cand)
        vals[self.col["visit"]["cand_ip"]] = ip
        vals[self.col["visit"]["cand_port"]] = port
        vals[self.col["visit"]["prefix24"]] = pfx
        ok = rec.get("ok") or []
        vals[self.col["visit"]["n_ok"]] = len(ok)
        vid = rec.get("visit")
        for p in ok:
            self.sink.add("visit_ok", [self.sink.rid("visit_ok"), rid, vid, cand, ts, ts_epoch, p])
        for i, p in enumerate(rec.get("tried") or ()):
            self.sink.add("visit_tried", [self.sink.rid("visit_tried"), rid, vid, cand, i, p])

    def hook_npre(self, rid, rec, vals, fields, ts, ts_epoch):
        ips = rec.get("ips") or []
        vals[self.col["npre"]["n_ips"]] = len(ips)
        for i, ip in enumerate(ips):
            self.sink.add("npre_ip", [self.sink.rid("npre_ip"), rid, rec.get("node"), rec.get("round"), i, ip])

    def hook_stat(self, rid, rec, vals, fields, ts, ts_epoch):
        pool = rec.get("pool")
        if isinstance(pool, dict):
            for key, v in pool.items():
                self.sink.add("stat_pool", [self.sink.rid("stat_pool"), rid, ts, ts_epoch, key, v])

    def hook_start(self, rid, rec, vals, fields, ts, ts_epoch):
        host, ip = rec.get("judge_host"), rec.get("judge_ip")
        vals[self.col["start"]["judge_host_sha8"]] = sha8(host)
        vals[self.col["start"]["judge_ip_sha8"]] = sha8(ip)
        if host:
            self.judge_hosts[host] = self.judge_hosts.get(host, 0) + 1
        if ip:
            self.judge_ips[ip] = self.judge_ips.get(ip, 0) + 1
        self.unknown.pop(("start", "judge_host"), None)
        self.unknown.pop(("start", "judge_ip"), None)

    def hook_req(self, rid, rec, vals, fields, ts, ts_epoch):
        for i, kv in enumerate(rec.get("headers") or ()):
            if isinstance(kv, list) and len(kv) == 2:
                self.sink.add("req_header", [self.sink.rid("req_header"), rid, rec.get("nonce"), i, kv[0], kv[1]])

    def hook_snap(self, rid, rec, vals, fields, ts, ts_epoch):
        add, dele = rec.get("add") or [], rec.get("del") or []
        vals[self.col["snap"]["n_add"]] = len(add)
        vals[self.col["snap"]["n_del"]] = len(dele)
        src, label, base = rec.get("src"), rec.get("label"), int(bool(rec.get("base")))
        for event, keys in (("add", add), ("del", dele)):
            for key in keys:
                ip, port, pfx = split_cand(key)
                self.sink.add("list_event", [self.sink.rid("list_event"), rid, ts, ts_epoch, src, label, key, event,
                                             base, ip, port, pfx])

    def hook_agg(self, rid, rec, vals, fields, ts, ts_epoch):
        src = rec.get("src")
        for i, key in enumerate(rec.get("members") or ()):
            ip, port, pfx = split_cand(key)
            self.sink.add("agg_member", [self.sink.rid("agg_member"), rid, ts, ts_epoch, src, i, key, ip, port, pfx])

    def hook_nsnap(self, rid, rec, vals, fields, ts, ts_epoch):
        add, dele = rec.get("add") or [], rec.get("del") or []
        vals[self.col["nsnap"]["n_add"]] = len(add)
        vals[self.col["nsnap"]["n_del"]] = len(dele)
        src, base = rec.get("src"), int(bool(rec.get("base")))
        for event, ids in (("add", add), ("del", dele)):
            for node in ids:
                self.sink.add("node_event", [self.sink.rid("node_event"), rid, ts, ts_epoch, src, node, event, base])


# ---------------------------------------------------------------- 文件

_REC_FILE = re.compile(r"^(probe|judge|snap)-(\d{8}-\d{2})\.jsonl(\.gz)?$")
_TMP_FILE = re.compile(r"^(probe|judge|snap)-(\d{8}-\d{2})\.jsonl\.gz\.tmp$")
# 不读的文件：密钥、私钥、节点原始链接（含凭据）、旁路进程的工作目录
SKIP_SENSITIVE = {"secret", "judge-key.pem"}
SKIP_DIRS = {"local", "sidecar"}
OTHER_KNOWN = {"summary.json", "summary.txt", "preflight.txt", "judge-cert.pem", "state.json.gz", "exclude.txt",
               "fieldtest.json"}


def open_lines(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def count_lines(path):
    n = 0
    with open_lines(path) as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def plan_files(data_dir):
    """列出数据目录里的文件，决定每个怎么处理。返回 files 表的行（dict），记录文件按前缀和小时排序。"""
    rows = []
    by_hour = {}
    for name in sorted(os.listdir(data_dir)):
        p = os.path.join(data_dir, name)
        if os.path.isdir(p):
            if name in SKIP_DIRS:
                rows.append(dict(name=name + "/", prefix=None, hour=None, compressed=None, bytes=None,
                                 status="skipped_sensitive", note="不读：含凭据或与分析无关"))
            elif name == "evidence":
                pass  # 另外登记
            else:
                rows.append(dict(name=name + "/", prefix=None, hour=None, compressed=None, bytes=None,
                                 status="ignored_dir", note=None))
            continue
        size = os.path.getsize(p)
        m = _REC_FILE.match(name)
        if m:
            prefix, hour, gz = m.group(1), m.group(2), bool(m.group(3))
            row = dict(name=name, prefix=prefix, hour=hour, compressed=int(gz), bytes=size, status="read", note=None)
            by_hour.setdefault((prefix, hour), []).append(row)
            rows.append(row)
            continue
        if _TMP_FILE.match(name):
            rows.append(dict(name=name, prefix=None, hour=None, compressed=None, bytes=size, status="skipped_tmp",
                             note="压缩中途留下的临时文件，不读"))
        elif name in SKIP_SENSITIVE:
            rows.append(dict(name=name, prefix=None, hour=None, compressed=None, bytes=size, status="skipped_sensitive",
                             note="不读"))
        elif name in OTHER_KNOWN or name.startswith("fieldtest-pack-"):
            rows.append(dict(name=name, prefix=None, hour=None, compressed=None, bytes=size, status="not_ingested",
                             note=None))
        else:
            rows.append(dict(name=name, prefix=None, hour=None, compressed=None, bytes=size, status="ignored", note=None))
    # 同一小时两份：读未压缩的，跳过 .gz（与 rec.Files 一致；两者内容应相同，见 SCHEMA.md）
    for (prefix, hour), group in by_hour.items():
        if len(group) > 1:
            group.sort(key=lambda r: r["compressed"])
            for r in group[1:]:
                r["status"] = "duplicate_skipped"
                r["note"] = "同一小时另有 %s，只读那一份" % group[0]["name"]
    return rows


def ingest_file(conn, ing, path, file_id, prefix, hour):
    sink = ing.sink
    kinds = {}
    n = bad = 0
    first_ts = last_ts = None
    lineno = 0
    with open_lines(path) as f:
        for line in f:
            lineno += 1
            if not line.strip():
                continue
            try:
                raw = line.rstrip(b"\r\n").decode("utf-8")
            except UnicodeDecodeError:
                raw = line.rstrip(b"\r\n").decode("utf-8", "replace")
            try:
                rec = json.loads(raw)
                if not isinstance(rec, dict):
                    raise ValueError("不是对象")
            except ValueError as e:
                bad += 1
                sink.add("bad_line", [sink.rid("bad_line"), file_id, lineno, "JSON 解析失败: %s" % e, raw])
                continue
            k = rec.get("k")
            ts_raw = rec.get("ts")
            ts, ts_epoch, _ = parse_ts(ts_raw) if isinstance(ts_raw, str) else (None, None, None)
            if ts is not None:
                ts = ts_raw  # 记录表的 ts 列保留原文
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts
            if k in FIELDS:
                ing.record(k, rec, raw, file_id, ts, ts_epoch)
                if k not in EXPECTED_KINDS[prefix]:
                    ing.misplaced[(prefix, k)] = ing.misplaced.get((prefix, k), 0) + 1
            else:
                sink.add("misc", [sink.rid("misc"), file_id, k if isinstance(k, str) else None, ts, ts_epoch, raw])
            kinds[k] = kinds.get(k, 0) + 1
            n += 1
    sink.flush()
    conn.executemany("INSERT INTO file_kind VALUES (?,?,?)", [(file_id, str(k), v) for k, v in kinds.items()])
    conn.execute("UPDATE files SET records=?, bad_lines=?, first_ts=?, last_ts=? WHERE id=?",
                 (n, bad, first_ts, last_ts, file_id))
    return n, kinds


# ---------------------------------------------------------------- state.json.gz

def iter_state(path):
    """流式读 state.json.gz：逐个产出 cands 里的对象，最后产出 ("_rest", 其余键的字典)。

    真实数据的候选池有几十万条，整体 json.loads 要占几百 MB；这里把整个文本读进来，
    再用 raw_decode 一个对象一个对象地解析，峰值内存只有文本本身的大小。
    """
    with gzip.open(path, "rb") as f:
        text = f.read().decode("utf-8")
    dec = json.JSONDecoder()
    try:
        i = text.index('"cands"')
        i = text.index("[", i) + 1
        n = len(text)
        while True:
            while i < n and text[i] in " \t\r\n,":
                i += 1
            if text[i] == "]":
                i += 1
                break
            obj, i = dec.raw_decode(text, i)
            yield obj
        rest = text[i:].strip()
        if rest.startswith(","):
            rest = "{" + rest[1:]
        elif rest.startswith("}"):
            rest = "{}"
        yield "_rest", json.loads(rest)
    except (ValueError, IndexError):
        # 结构不是预期的样子：退回整体解析
        st = json.loads(text)
        for obj in st.get("cands") or []:
            yield obj
        yield "_rest", {k: v for k, v in st.items() if k != "cands"}


def load_state(conn, sink, path):
    """state.json.gz → cands、cand_src。cand_src.src_name 这里先留 NULL，由 resolve_src_names 在建完索引后填。"""
    offsets = {}
    n = 0
    sampled = None
    tfields = ["first_seen", "delisted_at", "next", "last_ok", "last_full", "last_extra"]
    for item in iter_state(path):
        if isinstance(item, tuple) and item[0] == "_rest":
            sampled = item[1].get("sampled")
            continue
        c = item
        key = c.get("key", "")
        ip, port, pfx = split_cand(key)
        if ip is None:
            continue  # Pool.Load 也会跳过解析不了的键
        times = {}
        for tf in tfields:
            rawv = c.get(tf)
            utc, epoch, off = parse_ts(rawv) if isinstance(rawv, str) else (None, None, None)
            times[tf] = (rawv, utc, epoch)
            if off:
                offsets[off] = offsets.get(off, 0) + 1
        srcs = c.get("srcs") or {}
        labels = int(c.get("labels") or 0)
        state = int(c.get("state") or 0)
        ok_mask = int(c.get("ok_mask") or 0)
        group = int(c.get("group") or 0)
        fs = times["first_seen"]
        row = [sink.rid("cands"), key, ip, port, pfx, group, jdump(srcs), len(srcs), int(len(srcs) > 0), labels,
               jdump(bit_names(labels, LABEL_BITS)), fs[1], fs[2]]
        for tf in tfields:
            row.extend(times[tf])
            if tf == "next":
                row.extend([int(c.get("visits") or 0), int(c.get("fails") or 0), state,
                            STATE_NAMES[state] if 0 <= state < len(STATE_NAMES) else str(state), ok_mask,
                            jdump(bit_names(ok_mask, PROTO_BITS)), int(bool(c.get("ever_ok")))])
        row.append(jdump(c))
        sink.add("cands", row)
        for idx, mask in srcs.items():
            try:
                i = int(idx)
            except ValueError:
                continue
            sink.add("cand_src", [sink.rid("cand_src"), key, i, None, int(mask), jdump(bit_names(int(mask), LABEL_BITS))])
        n += 1
    sink.flush()
    return n, offsets, sampled


# ---------------------------------------------------------------- 收尾

def pem_leaf_sha256(pem_path):
    """数据目录里 judge-cert.pem 第一张证书 DER 的 SHA-256。

    这张文件只在配置 judge.cert_file 为空时才是 judge 实际使用、探测器锁定的证书（judge.go 的 EnsureCert、LoadTrust）；
    配置了公开证书时数据目录里可能是旧的自签证书，或者根本没有这个文件（main.go pack 的 add() 对缺失文件静默跳过）。
    所以 judge 的叶子以数据本身为准（见 fill_self_identity 的 self_leaf），这个值只用来记录两者是否一致。
    文件缺失或解析不了返回 None。
    """
    try:
        with open(pem_path, "r", encoding="utf-8") as f:
            txt = f.read()
    except OSError:
        return None
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", txt, re.S)
    if not m:
        return None
    try:
        der = base64.b64decode("".join(m.group(1).split()))
    except ValueError:
        return None
    return hashlib.sha256(der).hexdigest()


def register_evidence(conn, data_dir):
    evdir = os.path.join(data_dir, "evidence")
    rows = []
    total = 0
    if os.path.isdir(evdir):
        for root, _, names in os.walk(evdir):
            for name in names:
                p = os.path.join(root, name)
                h, _, ext = name.partition(".")
                size = os.path.getsize(p)
                total += size
                rows.append((h, ext, size, os.path.relpath(p, data_dir)))
    conn.executemany("INSERT OR REPLACE INTO evidence VALUES (?,?,?,?)", rows)
    return len(rows), total


def fill_self_identity(conn, ing, pem_leaf):
    """judge 的公网 IP、主机名和叶子证书，从几个来源各取一份，带来源标签。见 SCHEMA.md“judge 的身份从哪里取”。

    对照组的 nonce 先去重再连 judge 的 req 表：同一个 nonce 被重放时 req 里有多条，不去重连接会放大。
    """
    conn.executemany("INSERT OR REPLACE INTO self_ips VALUES (?,?,?)",
                     [(ip, "start.judge_ip", n) for ip, n in ing.judge_ips.items()])
    conn.executemany("INSERT OR REPLACE INTO self_names VALUES (?,?,?)",
                     [(h, "start.judge_host", n) for h, n in ing.judge_hosts.items()])
    conn.execute("""CREATE TEMP TABLE ctl AS
        SELECT DISTINCT nonce, cand, dst FROM att
        WHERE cand_kind = 'control' AND dst IN ('judge_http', 'judge_tls') AND nonce IS NOT NULL""")
    # judge 日志里对照请求的对端地址：探测器直连 judge 时 judge 看到的地址（连回环地址时是回环地址，连公网地址时是本机的出口地址）
    conn.execute("""INSERT OR REPLACE INTO self_ips
        SELECT r.remote, 'judge_remote:' || c.cand, COUNT(*) FROM ctl c JOIN req r ON r.nonce = c.nonce
        WHERE r.remote IS NOT NULL GROUP BY 1, 2""")
    # 对照请求的响应头 X-Judge-Remote 回显的地址
    conn.execute("""INSERT OR REPLACE INTO self_ips
        SELECT a.ip, 'echo:' || a.cand, COUNT(*) FROM att a
        WHERE a.cand_kind = 'control' AND a.dst IN ('judge_http', 'judge_tls') AND a.class = 'ok' AND a.ip IS NOT NULL
        GROUP BY 1, 2""")
    # judge 收到的对照请求里的 Host（去掉端口）和 SNI
    conn.execute("""INSERT OR REPLACE INTO self_names
        SELECT CASE WHEN instr(r.host, ':') > 0 THEN substr(r.host, 1, instr(r.host, ':') - 1) ELSE r.host END,
               'judge_host_header:control', COUNT(*)
        FROM ctl c JOIN req r ON r.nonce = c.nonce WHERE r.host IS NOT NULL AND r.host != '' GROUP BY 1""")
    conn.execute("""INSERT OR REPLACE INTO self_names
        SELECT r.sni, 'judge_sni:control', COUNT(*) FROM ctl c JOIN req r ON r.nonce = c.nonce
        WHERE c.dst = 'judge_tls' AND r.sni IS NOT NULL AND r.sni != '' GROUP BY 1""")
    conn.execute("DROP TABLE ctl")
    # judge 的叶子证书，从数据本身推导（judge-cert.pem 不一定是实际用的那张，见 pem_leaf_sha256）：
    #   control_ok    对照组直连 judge_tls、全程成功的尝试看到的叶子。这是“judge 叶子”的定义；应恰好 1 个值，
    #                 多于 1 个说明中途换过证书（公开证书续期），first_ts/last_ts 给出各自的时间段
    #   tls_ok_any    所有对 judge_tls 的尝试里 TLS 校验通过（含 SPKI 锁定，wire.TLS VerifyConnection）的叶子，
    #                 经代理和节点的也算；交叉核对用，应与 control_ok 同一集合
    #   pem           judge-cert.pem 的哈希，由 main() 填
    conn.execute("""INSERT OR REPLACE INTO self_leaf
        SELECT tls_leaf, 'control_ok', COUNT(*), MIN(ts), MAX(ts) FROM att
        WHERE cand_kind = 'control' AND dst = 'judge_tls' AND class = 'ok' AND tls_leaf IS NOT NULL GROUP BY 1""")
    conn.execute("""INSERT OR REPLACE INTO self_leaf
        SELECT tls_leaf, 'tls_ok_any', COUNT(*), MIN(ts), MAX(ts) FROM att
        WHERE dst = 'judge_tls' AND tls_ok = 1 AND proto != 'tlsproxy' AND tls_leaf IS NOT NULL GROUP BY 1""")
    if pem_leaf is not None:
        conn.execute("INSERT OR REPLACE INTO self_leaf VALUES (?, 'pem', 1, NULL, NULL)", (pem_leaf,))


def judge_leaf_meta(conn, pem_leaf):
    """meta 里关于 judge 叶子证书的几个键。哈希本身的键不可输出，计数和布尔值可以。"""
    observed = [dict(leaf=r[0], n=r[1], first_ts=r[2], last_ts=r[3]) for r in conn.execute(
        "SELECT leaf, n, first_ts, last_ts FROM self_leaf WHERE source = 'control_ok' ORDER BY first_ts")]
    obs_set = {o["leaf"] for o in observed}
    extra = [dict(leaf=r[0], n=r[1], first_ts=r[2], last_ts=r[3]) for r in conn.execute(
        "SELECT leaf, n, first_ts, last_ts FROM self_leaf WHERE source = 'tls_ok_any'") if r[0] not in obs_set]
    return {
        "judge_leaf_observed": jdump(observed),  # 不可输出
        "judge_leaf_observed_count": len(observed),  # 应为 1
        "judge_leaf_pem_sha256": pem_leaf,  # 不可输出
        "judge_leaf_pem_present": int(pem_leaf is not None),
        "judge_leaf_pem_matches_observed": None if pem_leaf is None or not observed else int(pem_leaf in obs_set),
        "judge_leaf_tls_ok_extra": jdump(extra),  # 不可输出；应为空
        "judge_leaf_tls_ok_extra_count": len(extra),
    }


def payload_lengths(ing):
    """各种载荷的期望长度：成功走完全部阶段、响应头没有任何标记（没被 gzip 过）的尝试，其 http_len 就是期望值。
    对照组直连只取 h；j、b 只有经转发代理的附加测试取过。取最常见的长度，并记下有几种不同的长度以便察觉异常。"""
    out = {}
    for kind, d in ing.payload_len.items():
        ln, n = max(d.items(), key=lambda kv: kv[1])
        out[kind] = {"len": ln, "n_ok": n, "distinct_lens": len(d)}
    return out


def resolve_src_names(conn, cfg_names):
    """把 cand_src.src_idx（来源编号）换成来源名，返回写进 meta.cand_src_names 的说明（JSON 可序列化）。

    编号的含义由部署时那份 sources.json 的顺序决定：prober.go NewProber 里 snapFile.src = uint8(i)，i 是 src.Lists 的下标；
    快照记录（snap、agg_sample）的 src 字段则是同一个 l.Name。数据包里的 sources.json 未必等于仓库 HEAD 的那份
    （夹具就不是：它的来源叫 local/regular、local/aggregator），所以名字不能只按 --sources 推。做法：
      1. 从数据推：持有编号 i 的候选，其上榜事件（list_event，event='add'，含 base=1 的首次快照——重启后 srcs 正是由它重建）
         或聚合器抽样（agg_member）出现在哪个来源名下，按候选数投票；票数最高的名字就是编号 i 的来源。
         真实来源的票数等于持有者数（每个在榜候选都至少有一次该来源的 add），别的来源只有在
         “编号 i 的来源是它的子集”时才可能打平；打平或一票没有时判为未定（why 字段说明原因）。
      2. 与 --sources 比对，两条路：
         a. 逐编号核对 --sources 按下标给的名字（cfg_check）：常规列表要求“每个持有者都有这个来源的上榜事件”
            （votes[cfg] == holders）；聚合器要求“这个聚合器的抽样成员里，持有编号 i 的最多”（在全部编号里是唯一的最大值）。
            全部编号都通过，就整体采用 --sources 的名字（by='sources'，sources_trusted=1）。
            这样做是因为第 1 步的多数票对小来源不可靠：2026-11-09 的真实数据里，聚合器 dpangestuw 的抽样成员
            后来有一部分出现在常规列表 iplocate 里，iplocate 以 298 比 297 一票之差“赢”了编号 13；
            两个常规列表互为子集时还会打平（编号 0、5）。按下标核对则不受这些影响。
         b. 不能整体采用时（例如夹具的来源名与仓库的 sources.json 不同），退回旧规则：每个从数据推出的编号
            都与 --sources 一致（且至少推出一个）才用 --sources 补推不出的编号，否则推不出的留 NULL；
            不一致时以数据为准。
         两条路都把数据推出的名字与 --sources 不一致的编号列在 mismatch 里，供核查。
    每个编号的 holders（持有它的候选数）、votes（各来源名的票数）、top_share（最高票 / holders，应为 1.0）都记下来，
    供指标脚本判断名字有多可信。值里只有来源名和计数，可以输出。
    """
    conn.execute("""CREATE TEMP TABLE src_seen AS
        SELECT DISTINCT cand, src FROM list_event WHERE event = 'add'
        UNION SELECT DISTINCT cand, src FROM agg_member""")
    conn.execute("CREATE INDEX src_seen_cand ON src_seen(cand)")
    holders = {r[0]: r[1] for r in conn.execute("SELECT src_idx, COUNT(DISTINCT key) FROM cand_src GROUP BY 1")}
    votes = {}
    for idx, name, n in conn.execute("""SELECT cs.src_idx, s.src, COUNT(DISTINCT cs.key)
        FROM cand_src cs JOIN src_seen s ON s.cand = cs.key GROUP BY 1, 2"""):
        votes.setdefault(idx, {})[name] = n
    # 聚合器抽样成员持有各编号的情况：agg_name → {编号: 成员数}
    agg_hold = {}
    for name, idx, n in conn.execute("""SELECT am.src, cs.src_idx, COUNT(DISTINCT am.cand)
        FROM agg_member am JOIN cand_src cs ON cs.key = am.cand GROUP BY 1, 2"""):
        agg_hold.setdefault(name, {})[idx] = n
    conn.execute("DROP TABLE src_seen")
    by_idx = {}
    for idx in sorted(set(holders) | set(votes)):
        ranked = sorted(votes.get(idx, {}).items(), key=lambda kv: (-kv[1], kv[0]))
        data_name = why = None
        if not ranked:
            why = "no_snapshot_events"
        elif len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
            why = "tie"
        else:
            data_name = ranked[0][0]
        cfg_name = cfg_names[idx] if cfg_names and 0 <= idx < len(cfg_names) else None
        h = holders.get(idx, 0)
        if cfg_name is None:
            cfg_check = None
        elif cfg_name in agg_hold:
            held = agg_hold[cfg_name]
            best = max(held.values())
            cfg_check = {"kind": "aggregator", "members_holding": held.get(idx, 0),
                         "ok": int(held.get(idx, 0) == best and sum(1 for v in held.values() if v == best) == 1)}
        else:
            cfg_check = {"kind": "list", "cfg_votes": votes.get(idx, {}).get(cfg_name, 0),
                         "ok": int(h > 0 and votes.get(idx, {}).get(cfg_name, 0) == h)}
        by_idx[idx] = {"holders": h, "votes": dict(ranked), "data_name": data_name, "why_unresolved": why,
                       "top_share": round(ranked[0][1] / h, 4) if ranked and h else None, "cfg_name": cfg_name,
                       "agrees_with_sources": None if data_name is None or cfg_name is None else int(data_name == cfg_name),
                       "cfg_check": cfg_check}
    checked = [d for d in by_idx.values() if d["holders"] > 0]
    cfg_positional = bool(cfg_names) and bool(checked) and all(d["cfg_check"] and d["cfg_check"]["ok"] for d in checked)
    resolved = [d for d in by_idx.values() if d["data_name"] is not None]
    cfg_trusted = cfg_positional or (bool(cfg_names) and bool(resolved) and all(d["data_name"] == d["cfg_name"] for d in resolved))
    mismatch = []
    for idx, d in by_idx.items():
        if cfg_positional and d["cfg_name"] is not None:
            d["name"], d["by"] = d["cfg_name"], "sources_positional"
        elif d["data_name"] is not None:
            d["name"], d["by"] = d["data_name"], "data"
        elif cfg_trusted and d["cfg_name"] is not None:
            d["name"], d["by"] = d["cfg_name"], "sources"
        else:
            d["name"], d["by"] = None, None
        if d["agrees_with_sources"] == 0:
            mismatch.append(idx)
        conn.execute("UPDATE cand_src SET src_name = ? WHERE src_idx = ?", (d["name"], idx))
    return {"sources_trusted": int(cfg_trusted), "sources_positional": int(cfg_positional), "mismatch": mismatch, "unresolved": [i for i, d in by_idx.items() if d["name"] is None],
            "by_idx": {str(i): d for i, d in by_idx.items()}}


def cand_src_consistency(conn):
    """cand_src 的来源名（resolve_src_names 填的）用快照记录逐条核对：常规列表看 list_event 里有没有该来源的 add 事件，
    聚合器看 agg_member 里有没有该来源抽中它。matched_by_snapshot 应等于 checked；差额是“持有编号却没有该来源事件”的
    候选-来源对（快照文件缺失、或多数票选错了）。"""
    total, hit = conn.execute("""SELECT COUNT(*),
        SUM(EXISTS (SELECT 1 FROM list_event e WHERE e.cand = cs.key AND e.src = cs.src_name AND e.event = 'add')
            OR EXISTS (SELECT 1 FROM agg_member m WHERE m.cand = cs.key AND m.src = cs.src_name))
        FROM cand_src cs WHERE cs.src_name IS NOT NULL""").fetchone()
    return {"checked": total or 0, "matched_by_snapshot": hit or 0}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def main():
    ap = argparse.ArgumentParser(description="把 fieldtest 原始记录灌进 SQLite")
    ap.add_argument("--data", required=True, help="数据目录（解包后的 fieldtest/ 或原始数据目录）")
    ap.add_argument("--db", required=True, help="输出的 SQLite 文件路径（不要放进仓库）")
    ap.add_argument("--state", help="state.json.gz 路径；默认取数据目录下的同名文件，没有就跳过 cands 表")
    ap.add_argument("--sources", help="sources.json 路径，用来把 state 里的来源编号换成名字；"
                                      "默认用仓库里 fieldtest/internal/lists/sources.json")
    ap.add_argument("--force", action="store_true", help="目标库已存在时先删除再重建")
    args = ap.parse_args()

    data_dir = os.path.abspath(args.data)
    if not any(_REC_FILE.match(n) for n in os.listdir(data_dir)) and os.path.isdir(os.path.join(data_dir, "fieldtest")):
        data_dir = os.path.join(data_dir, "fieldtest")
    # 库不许落在仓库里（仓库是公开的，库里有第三方地址和 judge 的身份）；run_all.sh 也查，这里防直接运行本脚本
    repo_root = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    if os.path.commonpath([repo_root, os.path.realpath(os.path.abspath(args.db))]) == repo_root:
        log("SQLite 库不要放在仓库里：%s" % args.db)
        return 2
    if os.path.exists(args.db):
        if not args.force:
            log("目标库已存在：%s。加 --force 删除重建，或换一个路径。" % args.db)
            return 2
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                os.remove(args.db + suffix)
            except FileNotFoundError:
                pass
    state_path = args.state or os.path.join(data_dir, "state.json.gz")
    if not os.path.exists(state_path):
        if args.state:
            log("找不到 state 文件：%s" % state_path)
            return 2
        state_path = None
    sources_path = args.sources or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fieldtest",
                                                 "internal", "lists", "sources.json")
    src_names = None
    sources_sha = None
    if os.path.exists(sources_path):
        with open(sources_path, "rb") as f:
            b = f.read()
        sources_sha = hashlib.sha256(b).hexdigest()
        try:
            src_names = [l["name"] for l in json.loads(b.decode("utf-8")).get("lists", [])]
        except (ValueError, KeyError, TypeError):
            src_names = None

    t_start = time.time()
    conn = sqlite3.connect(args.db, isolation_level=None)  # 自己管事务：每个文件一个 BEGIN/COMMIT
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("PRAGMA cache_size = -262144")  # 256 MB 页缓存
    conn.execute("PRAGMA temp_store = FILE")  # 建索引和 GROUP BY 的临时空间放磁盘：一千万行的索引排序不能占内存
    conn.execute("BEGIN")
    create_schema(conn)
    conn.execute("COMMIT")
    sink = Sink(conn)
    ing = Ingest(conn, sink)

    files = plan_files(data_dir)
    conn.execute("BEGIN")
    conn.executemany("INSERT INTO files (name, prefix, hour, compressed, bytes, status, note) VALUES (?,?,?,?,?,?,?)",
                     [(r["name"], r["prefix"], r["hour"], r["compressed"], r["bytes"], r["status"], r["note"])
                      for r in files])
    conn.execute("COMMIT")
    file_ids = {r[1]: r[0] for r in conn.execute("SELECT id, name FROM files")}

    to_read = [r for r in files if r["status"] == "read"]
    to_read.sort(key=lambda r: ({"judge": 0, "snap": 1, "probe": 2}[r["prefix"]], r["hour"]))
    total_bytes = sum(r["bytes"] for r in to_read)
    done_bytes = 0
    total_records = 0
    kind_totals = {}
    for r in to_read:
        path = os.path.join(data_dir, r["name"])
        t0 = time.time()
        conn.execute("BEGIN")
        n, kinds = ingest_file(conn, ing, path, file_ids[r["name"]], r["prefix"], r["hour"])
        conn.execute("COMMIT")
        for k, v in kinds.items():
            kind_totals[k] = kind_totals.get(k, 0) + v
        total_records += n
        done_bytes += r["bytes"]
        log("%-32s %9d 条 %6.1f 秒  累计 %5.1f%% 的字节" % (r["name"], n, time.time() - t0,
                                                          100.0 * done_bytes / total_bytes if total_bytes else 100))
    # 被跳过的重复文件：数一下行数供核对
    duplicates = []
    conn.execute("BEGIN")
    for r in files:
        if r["status"] == "duplicate_skipped":
            path = os.path.join(data_dir, r["name"])
            try:
                n = count_lines(path)
                note = r["note"]
            except (OSError, EOFError) as e:
                n, note = None, "%s；读取出错: %s" % (r["note"], e)
            conn.execute("UPDATE files SET records=?, note=? WHERE name=?", (n, note, r["name"]))
            twin = conn.execute("SELECT records FROM files WHERE prefix=? AND hour=? AND status='read'",
                                (r["prefix"], r["hour"])).fetchone()
            duplicates.append({"skipped": r["name"], "lines": n, "read_twin_records": twin[0] if twin else None})
    conn.execute("COMMIT")

    # state.json.gz → cands
    state_info = {"path": None}
    if state_path:
        t0 = time.time()
        conn.execute("BEGIN")
        n, offsets, sampled = load_state(conn, sink, state_path)
        conn.execute("COMMIT")
        mt = os.path.getmtime(state_path)
        state_info = {"path": state_path, "cands": n, "tz_offsets": offsets, "sampled": sampled,
                      "mtime_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mt))}
        log("%-32s %9d 条 %6.1f 秒" % ("state.json.gz → cands", n, time.time() - t0))
    else:
        log("没有 state.json.gz，cands 表为空")

    conn.execute("BEGIN")
    n_ev, ev_bytes = register_evidence(conn, data_dir)
    conn.execute("COMMIT")

    log("建索引 ...")
    t0 = time.time()
    for ddl in INDEXES:
        conn.execute(ddl)
    log("索引完成 %.1f 秒" % (time.time() - t0))

    # cand_src 的来源名：先从快照数据推，再与 --sources 比对（见 resolve_src_names）
    src_resolution = None
    if state_path:
        conn.execute("BEGIN")
        src_resolution = resolve_src_names(conn, src_names)
        conn.execute("COMMIT")
        for idx, d in src_resolution["by_idx"].items():
            log("来源编号 %s → %s（%s；持有者 %d，最高票占 %s）%s" % (
                idx, d["name"], d["by"] or "未定：" + str(d["why_unresolved"]), d["holders"], d["top_share"],
                "" if d["agrees_with_sources"] in (None, 1) else "；数据多数票是 %r，与 --sources 的 %r 不一致" % (d["data_name"], d["cfg_name"])))
        if src_resolution.get("sources_positional"):
            log("--sources 的名字逐个编号核对通过（cfg_check），cand_src.src_name 按下标采用 --sources；多数票的不一致只作记录")
        elif src_names and not src_resolution["sources_trusted"]:
            log("注意：--sources 给的顺序与数据推出的来源名不一致，cand_src.src_name 以数据为准（meta.cand_src_names）")

    pem_leaf = pem_leaf_sha256(os.path.join(data_dir, "judge-cert.pem"))
    conn.execute("BEGIN")
    fill_self_identity(conn, ing, pem_leaf)
    conn.execute("COMMIT")

    # meta
    span = conn.execute("SELECT MIN(first_ts), MAX(last_ts) FROM files WHERE status='read'").fetchone()
    judge_host = [r[0] for r in conn.execute("SELECT name FROM self_names WHERE source='start.judge_host'")]
    judge_ip = [r[0] for r in conn.execute("SELECT ip FROM self_ips WHERE source='start.judge_ip'")]
    summary = {}
    sp = os.path.join(data_dir, "summary.json")
    if os.path.exists(sp):
        try:
            with open(sp, "r", encoding="utf-8") as f:
                sj = json.load(f)
            summary = {"generated": sj.get("generated"), "first_record": sj.get("first_record"),
                       "last_record": sj.get("last_record"), "records": sj.get("records"), "judge": sj.get("judge")}
        except (ValueError, OSError):
            summary = {"error": "summary.json 解析失败"}
    meta = {
        "ingest_version": INGEST_VERSION,
        "ingested_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "data_dir": data_dir,
        "files_read": len(to_read),
        "records_total": total_records,
        "records_by_kind": jdump(dict(sorted(kind_totals.items(), key=lambda kv: str(kv[0])))),
        "first_ts": span[0],
        "last_ts": span[1],
        "duplicate_hour_files": jdump(duplicates),
        "unknown_fields": jdump({"%s.%s" % k: v for k, v in sorted(ing.unknown.items())}),
        "misplaced_kinds": jdump({"%s:%s" % k: v for k, v in sorted(ing.misplaced.items())}),
        "judge_host_sha8": jdump([sha8(h) for h in judge_host]),
        "judge_ip_sha8": jdump([sha8(h) for h in judge_ip]),
        "payload_len": jdump(payload_lengths(ing)),
        "state_file": state_info.get("path"),
        "state_cands": state_info.get("cands"),
        "state_tz_offsets": jdump(state_info.get("tz_offsets")),
        "state_sampled": jdump(state_info.get("sampled")),
        "state_mtime_utc": state_info.get("mtime_utc"),
        "sources_file": sources_path if src_names else None,
        "sources_sha256": sources_sha if src_names else None,
        "sources_names": jdump(src_names),
        "cand_src_names": jdump(src_resolution),
        "cand_src_check": jdump(cand_src_consistency(conn)) if state_path else None,
        "evidence_files": n_ev,
        "evidence_bytes": ev_bytes,
        "summary_json": jdump(summary) if summary else None,
        "output_whitelist": jdump(OUTPUT_WHITELIST),
        "output_rules": jdump(OUTPUT_RULES),
        "ingest_seconds": round(time.time() - t_start, 1),
    }
    meta.update(judge_leaf_meta(conn, pem_leaf))
    conn.execute("BEGIN")
    conn.executemany("INSERT INTO meta VALUES (?,?)", [(k, None if v is None else str(v)) for k, v in meta.items()])
    conn.execute("COMMIT")
    conn.execute("PRAGMA optimize")
    conn.close()
    log("完成：%d 个文件，%d 条记录，%.1f 秒，库 %s" % (len(to_read), total_records, time.time() - t_start, args.db))
    if ing.unknown:
        log("注意：有 FIELDS 没列出的字段（已存进 raw，见 meta.unknown_fields）：%s"
            % ", ".join("%s.%s×%d" % (k[0], k[1], v) for k, v in sorted(ing.unknown.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
