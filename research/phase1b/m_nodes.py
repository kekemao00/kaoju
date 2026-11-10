#!/usr/bin/env python3
"""节点（第一阶段 1B，PROTOCOL“指标定义”里的“节点可用（严格）”“节点可用（照链接）”，以及“对照与自检”里的节点不变量）。

用法：
    python3 m_nodes.py --db <sqlite> --out <目录> [--markdown] [--summary <summary.json>]
    python3 m_nodes.py --selftest

只读 ingest.py 建好的库（以 mode=ro 打开，临时表都建在 TEMP 库里），结果写到 <目录>/nodes.json。
每个比例都给分子、分母和口径；百分比保留一位小数。输出前按 SCHEMA.md 的可输出列白名单检查用到的列，
写出前再对文本做一次“不许出现地址和 judge 身份”的断言（最后一道保险，不是放行手段）。
节点标识（12 位十六进制）只在库内做连接和去重，不进入输出；输出的永远是聚合值。

算什么（PROTOCOL 条目 → 本模块的键）：
- 节点可用（严格）/（照链接）→ availability：按节点去重后，曾在严格校验下走通全部阶段的节点数；只有照链接跳过校验才走通的节点数；
  “严格校验损失多少”= 只有照链接才可用的节点 / 曾经可用的节点（summary.go finish() 的 strict / as_linked_only 口径）。
- sing-box 不支持的节点 → nodes.unsupported_by_why（node 记录的 why，nodes/singbox.go Supported()）。
- 按协议、按订阅来源分组 → availability.by_scheme / by_source；节点去重照 summary.go 的 nodeSch（同一 id 只算一次）。
- 每轮的小结 → rounds.sequence（nround 记录，按时间排序，标明属于第几次启动），并用 att 按时间窗独立算一遍 probed / ok_strict / ok_linked 作核对。
- 预检各类别 → precheck（npre.class：DNS 失败、IPv6、非公网、TCP 失败、通过、取消）。
- 节点的出口地址不能是本机（不变量）→ egress.invariant：att 里 proto=node 的 ip（回显）是否等于 self_ips；
  再以 judge 日志为准（req.remote，PROTOCOL“出口地址”）做一遍，并照 summary.go nodeEgress 分“与入口相同 / 入口地址未知 / 与入口不同”。
- 订阅快照 → subscriptions（nsnap 的抓取、失败、变化次数，照 summary.go 的 nsnap 分支）。

设计要点（真实数据有一千多万条 att，但节点的只占一小部分）：
- att 只按 proto='node' 扫一遍进 TEMP 表 na（走 att(proto, dst, class) 索引），之后的聚合都打 na；judge 的 req 只取 na 里出现的 nonce。
- 其余节点表（node、npre、nround、nerr、nsnap、node_event）都小，直接 SQL 聚合。
- 临时表落在 SQLite 的临时目录（依次取环境变量 SQLITE_TMPDIR、TMPDIR，再是 /var/tmp、/tmp）。真实数据的节点尝试有百万级，
  /tmp 是小 tmpfs 时请先 export SQLITE_TMPDIR=<有几 GB 空间的磁盘目录> 再运行（PRAGMA temp_store_directory 已弃用，不用它）。
"""
import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import tempfile

PROTOCOL_VERSION = "1.2"
JUDGE_LAG_S = 10  # judge 每 2 秒落盘，summary.go 只对早于“judge 最后一条记录前 10 秒”的尝试做“judge 没收到”的核对
ROUND_MARGIN_S = 1.0  # 把 att 归到某一轮时，轮次窗口 [nround.ts, nround.ts + ms] 两端各放宽的秒数

# 本模块在 SELECT 列表或 GROUP BY 里用到、并且会进入输出（作为维度或被聚合的值）的列。
# 只在库内做连接或判等、不进入输出的列（node.id、npre.node、att.cand/nonce/ip/visit、req.nonce/remote、npre_ip.ip、
# self_ips.ip、nerr.msg）不在这里。
OUTPUT_COLUMNS = {
    "node": ["scheme", "why", "insecure", "sec", "net", "src", "ts_epoch"],
    "node_event": ["src", "event", "base", "ts_epoch"],
    "nsnap": ["src", "status", "n", "base", "changed", "n_add", "n_del", "lines", "unparsed", "ms", "ts_epoch"],
    "npre": ["round", "class", "dns_ok", "tcp_ok", "tcp_ms", "tcp_class", "n_ips", "ts_epoch"],
    "nerr": ["arm", "round", "ts_epoch"],
    "nround": ["round", "known", "listed", "supported", "backoff", "tcp_ok", "probed", "ok_strict", "ok_linked",
               "bad_config", "batches", "ms", "ts_epoch"],
    "att": ["proto", "dst", "kind", "arm", "class", "ms", "cand_kind", "ts_epoch"],
    "req": ["ts_epoch"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["visits", "ts_epoch"],
    "version": ["version", "ts_epoch"],
    "meta": ["ingest_version", "first_ts", "last_ts", "records_by_kind"],
}

DEFINITIONS = {
    "节点": "订阅里的 ss / vmess / vless / trojan 节点，以 nodes.Node.ID（去重键的 SHA-256 前 12 位，键是协议、主机、端口、凭据、传输参数）为单位。"
          "同一节点出现在多个订阅里、或探测器重启后再记一遍，都只算一次（summary.go nodeSch）。PROTOCOL“测量对象”",
    "见过的节点": "正式起点之后出现过的节点：node 记录（第一次见到时写）、订阅快照的增减（node_event）、预检（npre）或隧道探测（att）里任一处出现过的 id。"
             "协议、是否支持等属性取该 id 最早的 node 记录；只在 att/npre 里出现、没有 node 记录的归为协议“?”（summary.go finish() 同样处理）",
    "sing-box 不支持": "node 记录的 why 非空：nodes/singbox.go Supported() 判定 sing-box 1.14.4 连不了（传输方式、加密方式、缺凭据等），按 why 的值计数。"
                  "这些节点不预检、不探测，单独计数。PROTOCOL“已知局限”",
    "可探测": "why 为空的节点（nround.supported 的口径是“在榜且 why 为空”，这里不要求仍在榜）",
    "预检": "每轮先对节点地址做 DNS 和 TCP（nodes.go precheck）。类别：通过 ok；DNS 失败 dns_nxdomain / dns_timeout / dns_other；IPv6 skip_ipv6"
          "（只测 IPv4）；非公网 skip_not_public（私网或保留地址）；TCP 失败 tcp_*；取消 canceled（程序退出时还在等连接配额）。"
          "没有 tcp 对象的记录没有发起连接，所以“TCP 连得上”的分母只算 tcp_ok 非空的记录。PROTOCOL“频率与限速”节点一行",
    "探测过": "至少一次经 sing-box 旁路进程对 judge 的 TLS 端口做隧道探测（att 里 proto='node' 且 dst='judge_tls'，不含 canceled）",
    "节点可用（严格）": "不管分享链接怎么写，按完整的证书校验连接节点，然后走完全部阶段并通过核对：至少一次 arm='strict'、dst='judge_tls'、class='ok' 的尝试。"
                 "PROTOCOL“指标定义”；summary.go finish() 的 OK[scheme][strict]",
    "节点可用（照链接）": "链接要求跳过证书校验（insecure 且 sec=tls）、严格校验又连不上时，照链接要求再试一次：arm='as_linked' 的尝试。"
                  "“只有照链接才可用”= 有 as_linked 的 ok、没有 strict 的 ok（summary.go 的 as_linked_only）。只用来量化严格校验的代价，不作为可用的依据",
    "曾经可用（任一分组）": "严格可用 ∪ 只有照链接才可用",
    "严格校验损失": "只有照链接才可用的节点 / 曾经可用的节点（绝对口径，summary.go 的 as_linked_only 占全部可用）。另给相对口径：只有照链接才可用 / 严格可用"
              "（每有一个严格可用的节点，就还有多少个只因跳过校验才可用）；以及以“链接要求跳过校验的节点”为分母的一组：其中严格可用、只照链接可用、两者都不行各多少",
    "最近一次探测的结果": "每个探测过的节点，取最后一次 dst='judge_tls' 的尝试所在的那次探访（同一 visit）：严格可用 / 仅照链接可用 / 不可用。"
                 "分母是“探测过”，含已下榜但仍在 24 小时宽限期内被探测的节点；PROTOCOL 没有为节点定义时点可用率，这里只作补充",
    "结束时在榜的可探测节点（时点）": "与 PROTOCOL“时点可用率”分母“某一时刻在榜的条目”对齐的一组：分母 = 观察结束时在榜（“订阅成员”里的结束时在榜，任一订阅）且 why 为空的节点；"
                       "分子 = 其中最近一次探访严格可用 / 仅照链接可用 / 不可用 / 窗口内从未做过隧道探测。与最后一轮 nround 的 listed、supported 并列输出便于核对"
                       "（nround 在轮次开始时数，事件口径在结束时刻数，二者可以差几个）",
    "节点可用（照链接，任一轮）": "PROTOCOL“指标定义”的“节点可用（照链接）”原始计数：至少一次 arm='as_linked'、dst='judge_tls'、class='ok' 的节点，不管严格是否也通过过"
                       "（跨轮先严格通过、后来只照链接通过的节点在这里计入、在“只有照链接才可用”里不计入）",
    "可探测但从未探测过": "why 为空、窗口内却没有任何 judge_tls 隧道探测的节点，按先后顺序归一个原因：配置被 sing-box 拒绝（nerr 有 config: 记录）→ 没有预检记录（窗口内从未进入过一轮，"
                   "例如不在榜）→ 预检通过过却没有隧道探测（一直退避或批次被取消）→ 最近一次预检的类别",
    "每轮小结": "nround 记录（nodes.go Round()）：known 见过、listed 在榜、supported 在榜且能连、backoff 因连续不可用跳过、tcp_ok 预检连得上、"
            "probed 做了隧道探测、ok_strict / ok_linked、bad_config 配置被 sing-box 拒绝、batches 批数、ms 耗时。轮次编号在每次启动后从 1 重数，"
            "所以按时间排序并标出属于第几次启动（run）。att 按时间窗 [ts, ts+ms]（两端放宽 1 秒）归到各轮，独立算 probed / ok_strict / ok_linked 作核对",
    "出口地址": "以 judge 日志为准：探测请求的 nonce 在 req 里最早到达的那条的 remote（derive.go Derive）。att.ip 是 judge 在响应头里回显的对端地址，"
            "只用来互相核对。PROTOCOL“指标定义”",
    "出口不能是本机": "PROTOCOL“对照与自检”的不变量：节点探测的流量不能从本机直接出去。判据一：att 里 proto='node' 的 ip 等于本机地址；"
                "判据二：judge 看到的 remote 等于本机地址（summary.go nodeEgress 的“仪器异常”）。两者都应为 0。本机地址取 self_ips 的全部来源"
                "（start.judge_ip、judge_remote:control:*、echo:control:*）：云主机做 NAT 时 judge 看到的本机流量源地址可能不是 start.judge_ip，"
                "这是安全检查，宁可多报；只用 start.judge_ip 的一组（与 summary.go selfIPs 对齐）并列输出。另给“NAT 指标”：judge_remote:control:public "
                "的地址是否全部等于 start.judge_ip（只输出一致与否和个数，不输出地址）",
    "出口与入口": "照 summary.go nodeEgress：judge 收到的、class='ok'、dst='judge_tls' 的节点尝试里，remote 等于入口 IP 之一 → 与入口相同；"
             "没有入口 IP → 入口地址未知；否则 → 与入口不同。入口 IP 取该尝试时刻之前（ts_epoch <= att.ts_epoch）该节点最后一条解析出 IP 的预检（n_ips>0）"
             "的 npre_ip，与 summary.go 边读边更新 nodeIP 一致；另给第二组“并集口径”（该节点所有预检 IP 的并集，对 DNS 轮询 / CDN 节点更宽松）。"
             "出口是本机（全部来源）的那些先归入不变量违反，不参与分类；与 summary.json 交叉核对时只排除 start.judge_ip",
    "观察者一致": "同一次探访（visit）里，judge 看到的 remote 与两个 IP 回显服务报告的地址（att.ip，dst 为 obs:*）是否全部相同",
    "judge 没收到": "探测器认为成功（class='ok'、带 nonce、目的地 judge）、judge 的 req 里却没有这个 nonce 的节点尝试；只核对早于 judge 最后一条记录前 10 秒的尝试"
               "（judge 每 2 秒落盘）。应为 0，PROTOCOL“对照与自检”",
    "重放": "同一 nonce 被 judge 收到不止一次（req 里同 nonce 多条）。PROTOCOL“指标定义”",
    "sing-box 报的错误": "nerr 记录：sing-box 日志里与失败节点有关的最后一条错误（nodes.go batch()），msg 是日志原文（可能含节点地址），不输出；"
                   "只按 arm 和固定枚举的粗分类计数：config（配置被拒，msg 以“config: ”开头，validate()）、cert_verify（x509 / certificate）、"
                   "timeout、refused、eof_reset、dns、other",
    "订阅快照": "nsnap 记录（nodes.go snapshot()）：抓取次数；失败 = err 非空或状态码不是 200/304；变化 = changed（内容有变才解析，首次 base=1 也算变化）；"
            "未变化分两种：304（带 ETag 时服务器回 304）和 200 且内容的 SHA-256 没变（changed 为空，snapshot() 照样写记录）。"
            "抓取 = 失败 + 有变化 + 未变化（304）+ 未变化（200），在 checks 里断言。"
            "当前节点数 = 最近一次变化时的 n，n 带 omitempty，解析出 0 个节点时为空、按 0 计（summary.go 的 nsnap 分支）。"
            "真正的上榜/下榜是 base=0 的 add/del（base=1 是每次启动后的首次快照，不是新上榜）",
    "订阅成员": "节点属于哪些订阅：node_event 里 event='add' 的 (node, src) 去重，不按正式起点裁剪（成员关系是节点的属性，不是窗口的属性；"
            "否则 --formal-start 落在最后一次 base=1 快照之后时所有节点都失去归属）；只对窗口内见过的节点取。没有任何 add 事件的节点退而用 node 记录的 src"
            "（第一次见到它的订阅）。“结束时在榜”= 该订阅最后一次 base=1 快照之后、最后一个事件是 add 的节点（同样不裁窗口：这是观察结束时刻的状态）",
    "传输与安全层的归并": "node.net / node.sec 和 why 的 transport_<net>、tcp_header_<hdr>、security_<sec>、scheme_<scheme> 后缀是分享链接里的参数原文"
                   "（不可信上游的自由文本，nodes/link.go 不做枚举校验）。输出前归并到固定枚举：net ∈ {tcp, ws, grpc, http, h2, httpupgrade, xhttp, kcp, quic}，"
                   "sec ∈ {none, tls, reality, xtls}，tcp 头 ∈ {none, http, srtp, utp, wechat-video, dtls, wireguard}，协议 ∈ {ss, ssr, vmess, vless, trojan, "
                   "hysteria, hysteria2, hy2, tuic, socks, http}，其余一律归为 other，个数照常输出",
    "正式起点": "PROTOCOL“正式测量的起止”：默认取第一条 start；若之后有 resumed_candidates=0 的 start（状态被清空）或版本变了，取最后一次这样的 start。"
             "之前的数据是试运行，不并入。可用 --formal-start 覆盖",
    "观察结束时刻": "att、npre、nround、nsnap、stop 记录里最晚的时间戳（UTC）",
    "百分比": "100 × 分子 / 分母，保留一位小数；分母为 0 时为 null。每个比例都同时给出分子、分母",
}

PRECHECK_CATEGORIES = [("通过", "ok"), ("DNS 失败", "dns"), ("IPv6", "ipv6"), ("非公网", "not_public"),
                       ("TCP 失败", "tcp"), ("取消", "canceled"), ("其他", "other")]
# npre.class → 类别（nodes.go precheck()）。SQL 里用同样的规则（precheck_case）。
PRECHECK_CASE = """CASE WHEN class = 'ok' THEN 'ok'
                        WHEN class LIKE 'dns_%' THEN 'dns'
                        WHEN class = 'skip_ipv6' THEN 'ipv6'
                        WHEN class = 'skip_not_public' THEN 'not_public'
                        WHEN class LIKE 'tcp_%' THEN 'tcp'
                        WHEN class = 'canceled' THEN 'canceled'
                        ELSE 'other' END"""

# nerr.msg 的粗分类：只输出下面这些固定的字符串，不输出 msg 的任何片段
NERR_CASE = """CASE WHEN msg LIKE 'config: %' THEN 'config'
                    WHEN lower(msg) LIKE '%x509%' OR lower(msg) LIKE '%certificate%' THEN 'cert_verify'
                    WHEN lower(msg) LIKE '%timeout%' OR lower(msg) LIKE '%deadline exceeded%' THEN 'timeout'
                    WHEN lower(msg) LIKE '%refused%' THEN 'refused'
                    WHEN lower(msg) LIKE '%eof%' OR lower(msg) LIKE '%reset%' THEN 'eof_reset'
                    WHEN lower(msg) LIKE '%no such host%' OR lower(msg) LIKE '%dns%' OR lower(msg) LIKE '%lookup%' THEN 'dns'
                    ELSE 'other' END"""
NERR_CATEGORIES = ["config", "cert_verify", "timeout", "refused", "eof_reset", "dns", "other"]

# 分享链接里的自由文本参数归并到固定枚举（定义见 DEFINITIONS“传输与安全层的归并”）
KNOWN_NET = ("tcp", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "kcp", "quic")
KNOWN_SEC = ("none", "tls", "reality", "xtls")
KNOWN_HDR = ("none", "http", "srtp", "utp", "wechat-video", "dtls", "wireguard")
KNOWN_SCHEME = ("ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "socks", "http")
# why 的固定值（nodes/singbox.go Supported() 里直接 return 的字符串）
KNOWN_WHY = ("ss_method", "no_credential", "ss_plugin", "reality_no_key", "vless_encryption", "vless_flow")


def _sql_list(vals):
    return ", ".join("'%s'" % v for v in vals)


def enum_case(col, known):
    """列值在 known 里就原样保留，NULL 保留为 NULL，其余归为 other。"""
    return "CASE WHEN %s IS NULL THEN NULL WHEN %s IN (%s) THEN %s ELSE 'other' END" % (col, col, _sql_list(known), col)


def why_case(col):
    """why 归并：固定值原样；带参数原文后缀的四类按后缀枚举归并。"""
    parts = ["WHEN %s IS NULL THEN NULL" % col, "WHEN %s IN (%s) THEN %s" % (col, _sql_list(KNOWN_WHY), col)]
    for prefix, known in (("transport_", KNOWN_NET), ("tcp_header_", KNOWN_HDR), ("security_", KNOWN_SEC), ("scheme_", KNOWN_SCHEME)):
        parts.append("WHEN %s IN (%s) THEN %s" % (col, _sql_list(prefix + k for k in known), col))
        # 用 substr 比较前缀，避开 LIKE 里 _ 的通配含义
        parts.append("WHEN substr(%s, 1, %d) = '%s' THEN '%sother'" % (col, len(prefix), prefix, prefix))
    return "CASE " + " ".join(parts) + " ELSE 'other' END"


# ---------------------------------------------------------------- 小工具

def pct(num, den):
    return round(100.0 * num / den, 1) if den else None


def ratio(num, den):
    return {"num": int(num or 0), "den": int(den or 0), "pct": pct(num or 0, den or 0)}


def iso_minute(epoch):
    """时间只在分桶（到分钟）之后输出。"""
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def parse_iso(s):
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    t = dt.datetime.fromisoformat(s)
    if t.tzinfo is None:
        raise ValueError("时间必须带时区：%r" % s)
    return t.timestamp()


def fmt(v, suffix=""):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:,.1f}{suffix}"
    return f"{v:,}{suffix}"


def rfmt(r):
    """比例的 Markdown 写法：分子/分母（百分比）。"""
    return f"{fmt(r['num'])}/{fmt(r['den'])}（{fmt(r['pct'], '%')}）"


class DB:
    def __init__(self, path):
        # mode=ro：库文件只读；临时表都建在 TEMP 库里（query_only 会连 TEMP 表一起禁掉，所以不用它）
        self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        self.con.execute("PRAGMA cache_size = -262144")  # 256 MB 页缓存，内存不随记录数增长
        self.con.execute("PRAGMA temp_store = FILE")

    def q(self, sql, params=()):
        return self.con.execute(sql, params).fetchall()

    def one(self, sql, params=()):
        return self.con.execute(sql, params).fetchone()

    def scalar(self, sql, params=()):
        row = self.one(sql, params)
        return row[0] if row else None

    def x(self, sql, params=()):
        self.con.execute(sql, params)

    def counts(self, sql, params=()):
        """两列查询（键、计数）→ 有序字典，键为 NULL 时写成 "(null)"。"""
        out = {}
        for k, v in self.q(sql, params):
            out["(null)" if k is None else str(k)] = int(v or 0)
        return out

    def has_table(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) > 0

    def columns(self, table):
        return [r[1] for r in self.q('PRAGMA table_info("%s")' % table)]

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))

    def percentile(self, table, col, where, p, params=()):
        """按排序取分位数（p 在 0~1）；没有行时 None。"""
        n = self.scalar("SELECT COUNT(*) FROM %s WHERE %s IS NOT NULL AND (%s)" % (table, col, where), params)
        if not n:
            return None
        off = int(round(p * (n - 1)))
        v = self.scalar("SELECT %s FROM %s WHERE %s IS NOT NULL AND (%s) ORDER BY %s LIMIT 1 OFFSET %d" % (col, table, col, where, col, off), params)
        return v


def check_whitelist(db):
    """输出前按白名单核对本模块用到的列。优先用同目录 ingest.py 的权威常量，拿不到就读库里的 meta.output_whitelist。"""
    wl = None
    source = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import ingest  # noqa: E402
        wl = ingest.OUTPUT_WHITELIST
        source = "ingest.OUTPUT_WHITELIST"
    except Exception:
        raw = db.meta("output_whitelist")
        if raw:
            wl = json.loads(raw)
            source = "meta.output_whitelist"
    if wl is None:
        raise SystemExit("拿不到可输出列白名单（ingest.py 不可导入，库里也没有 meta.output_whitelist），拒绝输出")
    problems = []
    for table, cols in OUTPUT_COLUMNS.items():
        allowed = wl.get(table)
        if allowed is None:
            problems.append("表 %s 不在白名单里" % table)
            continue
        bad = [c for c in cols if c not in allowed]
        if bad:
            problems.append("表 %s 的列不可输出：%s" % (table, ", ".join(bad)))
    if problems:
        raise SystemExit("白名单检查不通过：" + "；".join(problems))
    return source


# ---------------------------------------------------------------- 观察窗口

def observation_window(db, formal_start_arg):
    """正式起点、结束时刻、重启与中断。PROTOCOL“正式测量的起止”。与 m_availability.observation_window 同一规则。"""
    starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0) FROM start ORDER BY ts_epoch") if db.has_table("start") else []
    stops = [r[0] for r in db.q("SELECT ts_epoch FROM stop ORDER BY ts_epoch")] if db.has_table("stop") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch") if db.has_table("version") else []

    ends = []
    for t in ("att", "npre", "nround", "nsnap", "stop"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None
    firsts = []
    for t in ("npre", "nround", "nsnap", "node"):
        if db.has_table(t):
            v = db.scalar("SELECT MIN(ts_epoch) FROM %s" % t)
            if v is not None:
                firsts.append(v)
    first_rec = min(firsts) if firsts else None

    rule = []
    if starts:
        fs = starts[0][0]
        rule.append("第一条 start")
        cleared = [s for s in starts[1:] if s[1] == 0]
        if cleared:
            fs = cleared[-1][0]
            rule.append("之后有 resumed_candidates=0 的 start（状态被清空）：取最后一次")
        if len({v for _, v in versions}) > 1:
            change = None
            for i in range(1, len(versions)):
                if versions[i][1] != versions[i - 1][1]:
                    change = versions[i][0]
            after = [s[0] for s in starts if s[0] >= change - 1]  # version 与 start 几乎同时写，留 1 秒余量
            if after and after[0] > fs:
                fs = after[0]
                rule.append("版本变过：取最后一次版本变化之后的第一条 start")
    else:
        fs = first_rec
        rule.append("没有 start 记录：取最早的节点记录")
    if formal_start_arg and formal_start_arg != "auto":
        if formal_start_arg == "first":
            fs = starts[0][0] if starts else first_rec
            rule = ["--formal-start first"]
        else:
            fs = parse_iso(formal_start_arg)
            rule = ["--formal-start 指定"]

    interruptions = []  # 只算正式起点之后的 stop → start
    for st in stops:
        nxt = [s[0] for s in starts if s[0] > st]
        if nxt and fs is not None and st >= fs:
            interruptions.append({"stop_utc": iso_minute(st), "start_utc": iso_minute(nxt[0]),
                                  "minutes": round((nxt[0] - st) / 60.0, 1)})
    # 每次启动的编号（run）：正式起点之后的 start 依次编号，轮次小结按所属的 start 标注
    runs = [s[0] for s in starts if fs is not None and s[0] >= fs - 1] if starts else []
    if fs is not None and (not runs or runs[0] > fs):
        runs = [fs] + runs
    return {
        "formal_start_utc": iso_minute(fs), "formal_start_rule": "；".join(rule),
        "end_utc": iso_minute(end), "hours": round((end - fs) / 3600.0, 2) if (fs is not None and end is not None) else None,
        "starts": [{"utc": iso_minute(s[0]), "resumed_candidates": s[1]} for s in starts],
        "stops": [iso_minute(s) for s in stops],
        "versions": sorted({v for _, v in versions}),
        "interruptions": interruptions,
        "interruption_minutes_total": round(sum(i["minutes"] for i in interruptions), 1),
        "runs_in_window": len(runs),
        "_fs": fs, "_end": end, "_runs": runs,
    }


# ---------------------------------------------------------------- 建临时表

def build_tables(db, fs, runs):
    """在 TEMP 库里建本模块用的表。见模块顶部的设计要点。

    - ips：本机地址，self_ips 的全部来源（不变量用；NAT 时 judge 看到的本机源地址可能不是 start.judge_ip，宁可多报）。
    - ips_j：只取 source='start.judge_ip'（summary.go selfIPs 只用 c.Judge.PublicIP），与 summary.json 交叉核对用。
    - nd：node 记录按 id 去重（summary.go nodeSch：同一 id 只算一次），属性取最早一条；net / sec / why 归并到固定枚举。
    - nk：正式起点之后见过的节点全集（node ∪ node_event ∪ npre ∪ att），带 nd 的属性；没有 node 记录的 scheme 为 NULL（输出时写“?”）。
    - ns：节点 ↔ 订阅（node_event 的 add 去重，不裁窗口；没有 add 事件的退而用 node.src），只对 nk 里的节点。
    - nend：观察结束时在榜的 (节点, 订阅)：该订阅最后一次 base=1 快照之后、最后一个事件是 add。
    - np：窗口内的 npre，带类别。
    - na：窗口内的节点尝试（att.proto='node'，不含 canceled），连上 judge 最早到达的同 nonce 请求（remote、copies）；na_full 不裁窗口。
    - nac：canceled 的节点 judge_tls 尝试（只有 cand 和时间），给轮次核对用。
    - nagg：每个探测过的节点的聚合（严格可用、照链接可用、最近一次结果）。
    - nrd：窗口内的 nround，带 run 编号和 att 独立算出的计数。
    """
    # ---- 探测器自己的地址
    db.x("CREATE TEMP TABLE ips (ip TEXT PRIMARY KEY)")
    db.x("CREATE TEMP TABLE ips_j (ip TEXT PRIMARY KEY)")
    for (ip,) in db.q("SELECT DISTINCT ip FROM self_ips WHERE ip IS NOT NULL AND ip != ''"):
        db.x("INSERT OR IGNORE INTO ips VALUES (?)", (ip,))
    for (ip,) in db.q("SELECT DISTINCT ip FROM self_ips WHERE source = 'start.judge_ip' AND ip IS NOT NULL AND ip != ''"):
        db.x("INSERT OR IGNORE INTO ips_j VALUES (?)", (ip,))
    self_src = "self_ips 全部来源：" + "、".join(sorted(r[0] for r in db.q("SELECT DISTINCT source FROM self_ips WHERE ip IS NOT NULL AND ip != ''")))
    if not db.scalar("SELECT COUNT(*) FROM ips_j"):
        # 没有 start.judge_ip 时，与 summary.go 对齐的那组也只能退而用全部来源
        db.x("INSERT INTO ips_j SELECT ip FROM ips")

    # ---- node 去重
    db.x("""CREATE TEMP TABLE nd AS
            SELECT f.id, f.scheme, f.why, %s AS why_c, COALESCE(f.insecure, 0) AS insecure, f.sec, %s AS sec_c, f.net, %s AS net_c,
                   f.src AS first_src, c.first_e, c.n_rows, c.n_srcs_rec
            FROM (SELECT id, scheme, why, insecure, sec, net, src,
                         ROW_NUMBER() OVER (PARTITION BY id ORDER BY ts_epoch, rid) AS rn FROM node) f
            JOIN (SELECT id, MIN(ts_epoch) AS first_e, COUNT(*) AS n_rows, COUNT(DISTINCT src) AS n_srcs_rec FROM node GROUP BY id) c ON c.id = f.id
            WHERE f.rn = 1""" % (why_case("f.why"), enum_case("f.sec", KNOWN_SEC), enum_case("f.net", KNOWN_NET)))
    db.x("CREATE INDEX temp.nd_id ON nd(id)")

    # ---- 窗口内见过的节点全集
    db.x("""CREATE TEMP TABLE nw AS
            SELECT DISTINCT id FROM (
              SELECT id FROM node WHERE ts_epoch >= :fs
              UNION SELECT node FROM node_event WHERE ts_epoch >= :fs
              UNION SELECT node FROM npre WHERE ts_epoch >= :fs
              UNION SELECT cand FROM att WHERE proto = 'node' AND ts_epoch >= :fs AND class NOT LIKE '%canceled%')""", {"fs": fs})
    # linked_arm 套 COALESCE：sec 为 NULL 时 (insecure = 1 AND sec = 'tls') 是 NULL（三值逻辑），核对里的“= 0”会漏数
    db.x("""CREATE TEMP TABLE nk AS
            SELECT w.id, d.scheme, d.why, d.why_c, COALESCE(d.insecure, 0) AS insecure, d.sec, d.sec_c, d.net, d.net_c, d.first_src,
                   (d.id IS NULL) AS no_node_rec, COALESCE(d.n_rows, 0) AS n_rows,
                   (d.why IS NULL) AS supported,
                   COALESCE(COALESCE(d.insecure, 0) = 1 AND d.sec = 'tls', 0) AS linked_arm
            FROM nw w LEFT JOIN nd d ON d.id = w.id""")
    db.x("CREATE INDEX temp.nk_id ON nk(id)")

    # ---- 节点 ↔ 订阅（成员关系是节点属性：add 事件不裁窗口，兜底分支用同一口径）
    db.x("""CREATE TEMP TABLE ns AS
            SELECT DISTINCT e.node AS id, e.src FROM node_event e JOIN nk k ON k.id = e.node WHERE e.event = 'add'
            UNION
            SELECT k.id, k.first_src FROM nk k WHERE k.first_src IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM node_event e WHERE e.node = k.id AND e.event = 'add')""")
    db.x("CREATE INDEX temp.ns_id ON ns(id)")
    db.x("CREATE INDEX temp.ns_src ON ns(src)")
    # ---- 结束时在榜（观察结束时刻的状态，不裁窗口）
    db.x("""CREATE TEMP TABLE nend AS
            SELECT node AS id, src FROM (
              SELECT e.node, e.src, e.event,
                     ROW_NUMBER() OVER (PARTITION BY e.src, e.node ORDER BY e.ts_epoch DESC, e.rid DESC) AS rn
              FROM node_event e
              LEFT JOIN (SELECT src, MAX(ts_epoch) AS lb FROM node_event WHERE base = 1 GROUP BY src) b ON b.src = e.src
              WHERE e.ts_epoch >= COALESCE(b.lb, 0))
            WHERE rn = 1 AND event = 'add'""")
    db.x("CREATE INDEX temp.nend_id ON nend(id)")

    # ---- 预检
    db.x("""CREATE TEMP TABLE np AS
            SELECT rid, ts_epoch, round, node, class, dns_ok, tcp_ok, tcp_ms, tcp_class, n_ips, %s AS cat
            FROM npre WHERE ts_epoch >= ?""" % PRECHECK_CASE, (fs,))
    db.x("CREATE INDEX temp.np_node ON np(node, ts_epoch)")
    db.x("CREATE INDEX temp.np_ts ON np(ts_epoch)")
    db.x("""CREATE TEMP TABLE np_last AS
            SELECT node, class, cat FROM (
              SELECT node, class, cat, ROW_NUMBER() OVER (PARTITION BY node ORDER BY ts_epoch DESC, rid DESC) AS rn FROM np)
            WHERE rn = 1""")
    db.x("CREATE INDEX temp.np_last_node ON np_last(node)")
    # 解析出 IP 的预检（不裁窗口：summary.go 的 nodeIP 从数据开头边读边更新），给“该尝试之前最近一次预检的入口 IP”用
    db.x("CREATE TEMP TABLE npi AS SELECT rid, node, ts_epoch FROM npre WHERE COALESCE(n_ips, 0) > 0")
    db.x("CREATE INDEX temp.npi_node_ts ON npi(node, ts_epoch, rid)")
    db.x("CREATE TEMP TABLE npip AS SELECT npre_rid, ip FROM npre_ip")
    db.x("CREATE INDEX temp.npip_rid ON npip(npre_rid, ip)")

    # ---- 节点尝试 + judge 日志
    # 不裁窗口（与 summary.json 交叉核对要用全部数据），窗口内的子集另建 na
    db.x("""CREATE TEMP TABLE na0 AS
            SELECT rid, visit, cand, arm, dst, kind, class, ms, nonce, ip, ts_epoch,
                   (ip IS NOT NULL AND ip IN (SELECT ip FROM ips)) AS echo_self,
                   (ip IS NOT NULL AND ip IN (SELECT ip FROM ips_j)) AS echo_self_j
            FROM att WHERE proto = 'node' AND class NOT LIKE '%canceled%'""")
    db.x("CREATE INDEX temp.na0_nonce ON na0(nonce)")
    db.x("""CREATE TEMP TABLE nac AS SELECT cand, ts_epoch FROM att
            WHERE proto = 'node' AND dst = 'judge_tls' AND class LIKE '%canceled%' AND ts_epoch >= ?""", (fs,))
    db.x("CREATE INDEX temp.nac_ts ON nac(ts_epoch)")
    # 同 nonce 最早到达的 req（derive.go Derive：按 TS 排序取第一条），以及份数
    db.x("""CREATE TEMP TABLE nr AS
            SELECT nonce, remote, copies FROM (
              SELECT r.nonce, r.remote, COUNT(*) OVER (PARTITION BY r.nonce) AS copies,
                     ROW_NUMBER() OVER (PARTITION BY r.nonce ORDER BY r.ts_epoch, r.rid) AS rn
              FROM req r WHERE r.nonce IN (SELECT nonce FROM na0 WHERE nonce IS NOT NULL))
            WHERE rn = 1""")
    db.x("CREATE INDEX temp.nr_nonce ON nr(nonce)")
    # remote_is_entry / has_entry：summary.go nodeEgress 的口径——该尝试之前（ts_epoch <= att）该节点最后一条带 IP 的预检
    # remote_is_entry_any / has_entry_any：并集口径（该节点全部预检 IP），作第二组
    db.x("""CREATE TEMP TABLE na_full AS
            SELECT x.*,
                   (x.pre_rid IS NOT NULL) AS has_entry,
                   (x.pre_rid IS NOT NULL AND x.remote IS NOT NULL
                    AND EXISTS (SELECT 1 FROM npip p WHERE p.npre_rid = x.pre_rid AND p.ip = x.remote)) AS remote_is_entry
            FROM (
              SELECT a.rid, a.visit, a.cand, a.arm, a.dst, a.kind, a.class, a.ms, a.nonce, a.ip, a.ts_epoch, a.echo_self, a.echo_self_j,
                     (r.nonce IS NOT NULL) AS seen, r.remote, COALESCE(r.copies, 0) AS copies,
                     (r.remote IS NOT NULL AND r.remote IN (SELECT ip FROM ips)) AS remote_self,
                     (r.remote IS NOT NULL AND r.remote IN (SELECT ip FROM ips_j)) AS remote_self_j,
                     (r.remote IS NOT NULL AND a.ip IS NOT NULL AND r.remote = a.ip) AS echo_matches,
                     EXISTS (SELECT 1 FROM npre_ip p WHERE p.node = a.cand AND p.ip = r.remote) AS remote_is_entry_any,
                     EXISTS (SELECT 1 FROM npre_ip p WHERE p.node = a.cand) AS has_entry_any,
                     CASE WHEN r.nonce IS NOT NULL THEN
                       (SELECT q.rid FROM npi q WHERE q.node = a.cand AND q.ts_epoch <= a.ts_epoch ORDER BY q.ts_epoch DESC, q.rid DESC LIMIT 1)
                     END AS pre_rid
              FROM na0 a LEFT JOIN nr r ON r.nonce = a.nonce) x""")
    db.x("DROP TABLE na0")  # 建好 na_full 立即删，临时库里最多同时两份节点尝试
    db.x("DROP TABLE nr")
    db.x("CREATE INDEX temp.na_full_cand ON na_full(cand)")
    db.x("CREATE INDEX temp.na_full_dst ON na_full(dst, arm, class)")
    db.x("CREATE TEMP TABLE na AS SELECT * FROM na_full WHERE ts_epoch >= ?", (fs,))
    db.x("CREATE INDEX temp.na_cand ON na(cand, ts_epoch)")
    db.x("CREATE INDEX temp.na_dst ON na(dst, arm, class)")
    db.x("CREATE INDEX temp.na_visit ON na(visit)")
    db.x("CREATE INDEX temp.na_ts ON na(ts_epoch)")

    # ---- 每个探测过的节点（summary.go nodeOK：只看 dst=judge_tls 的 ok）
    db.x("""CREATE TEMP TABLE nagg AS
            SELECT cand AS id,
                   COUNT(*) AS n_att, COUNT(DISTINCT visit) AS n_visits,
                   MAX(arm = 'strict' AND class = 'ok') AS ok_strict,
                   MAX(arm = 'as_linked' AND class = 'ok') AS ok_linked,
                   MAX(arm = 'as_linked') AS tried_linked,
                   MIN(ts_epoch) AS first_e, MAX(ts_epoch) AS last_e
            FROM na WHERE dst = 'judge_tls' GROUP BY cand""")
    db.x("CREATE INDEX temp.nagg_id ON nagg(id)")
    # 最近一次探访的结果：最后一个 judge_tls 尝试所在的 visit 里，有没有 ok
    db.x("""CREATE TEMP TABLE nlast AS
            SELECT l.id, MAX(a.arm = 'strict' AND a.class = 'ok') AS ok_strict, MAX(a.arm = 'as_linked' AND a.class = 'ok') AS ok_linked
            FROM (SELECT cand AS id, visit FROM (
                    SELECT cand, visit, ROW_NUMBER() OVER (PARTITION BY cand ORDER BY ts_epoch DESC, rid DESC) AS rn
                    FROM na WHERE dst = 'judge_tls') WHERE rn = 1) l
            JOIN na a ON a.visit = l.visit AND a.cand = l.id AND a.dst = 'judge_tls'
            GROUP BY l.id""")
    db.x("CREATE INDEX temp.nlast_id ON nlast(id)")

    # ---- 轮次小结 + att 独立计数
    db.x("CREATE TEMP TABLE runs (run INTEGER, start_e REAL)")
    for i, t in enumerate(runs, 1):
        db.x("INSERT INTO runs VALUES (?, ?)", (i, t))
    db.x("""CREATE TEMP TABLE nrd AS
            SELECT r.rid, r.ts_epoch, r.round, r.known, r.listed, r.supported, r.backoff, r.tcp_ok, r.probed, r.ok_strict, r.ok_linked,
                   r.bad_config, r.batches, r.ms, (r.err IS NOT NULL AND r.err != '') AS has_err,
                   COALESCE((SELECT MAX(run) FROM runs u WHERE u.start_e <= r.ts_epoch + 1), 0) AS run,
                   r.ts_epoch - :m AS w0, r.ts_epoch + COALESCE(r.ms, 0) / 1000.0 + :m AS w1
            FROM nround r WHERE r.ts_epoch >= :fs""", {"fs": fs, "m": ROUND_MARGIN_S})
    db.x("CREATE INDEX temp.nrd_ts ON nrd(ts_epoch)")
    # att_canceled：nodes.go batch() 里 rr.Probed++ 不看 class，程序退出时 e.Run 返回 canceled 的节点也计入 nround.probed；
    # 这里数窗口内只有 canceled、没有其他 judge_tls 尝试的节点，核对时 probed 对 att_probed + att_canceled
    db.x("""CREATE TEMP TABLE nrd_att AS
            SELECT d.rid,
                   (SELECT COUNT(DISTINCT a.cand) FROM na a WHERE a.dst = 'judge_tls' AND a.ts_epoch BETWEEN d.w0 AND d.w1) AS att_probed,
                   (SELECT COUNT(DISTINCT c.cand) FROM nac c WHERE c.ts_epoch BETWEEN d.w0 AND d.w1
                      AND NOT EXISTS (SELECT 1 FROM na a WHERE a.cand = c.cand AND a.dst = 'judge_tls' AND a.ts_epoch BETWEEN d.w0 AND d.w1)) AS att_canceled,
                   (SELECT COUNT(DISTINCT a.cand) FROM na a WHERE a.dst = 'judge_tls' AND a.arm = 'strict' AND a.class = 'ok'
                      AND a.ts_epoch BETWEEN d.w0 AND d.w1) AS att_ok_strict,
                   (SELECT COUNT(DISTINCT a.cand) FROM na a WHERE a.dst = 'judge_tls' AND a.arm = 'as_linked' AND a.class = 'ok'
                      AND a.ts_epoch BETWEEN d.w0 AND d.w1) AS att_ok_linked,
                   (SELECT COUNT(*) FROM np p WHERE p.ts_epoch BETWEEN d.w0 AND d.w1) AS pre_rows,
                   (SELECT COUNT(*) FROM np p WHERE p.cat = 'ok' AND p.ts_epoch BETWEEN d.w0 AND d.w1) AS pre_ok
            FROM nrd d""")
    db.x("CREATE INDEX temp.nrd_att_rid ON nrd_att(rid)")

    return {"self_ips_source": self_src, "self_ips_count": int(db.scalar("SELECT COUNT(*) FROM ips") or 0),
            "self_ips_count_judge_ip": int(db.scalar("SELECT COUNT(*) FROM ips_j") or 0)}


# ---------------------------------------------------------------- 分母与节点构成

def scheme_label(s):
    return "?" if s is None else s


def denominators(db, fs):
    n = {}
    n["node 记录行数（窗口内）"] = int(db.scalar("SELECT COUNT(*) FROM node WHERE ts_epoch >= ?", (fs,)))
    n["见过的节点（去重）"] = int(db.scalar("SELECT COUNT(*) FROM nk"))
    n["其中有 node 记录"] = int(db.scalar("SELECT COUNT(*) FROM nk WHERE no_node_rec = 0"))
    n["其中没有 node 记录（只在 npre/att/快照里出现）"] = int(db.scalar("SELECT COUNT(*) FROM nk WHERE no_node_rec = 1"))
    n["node 记录重复（同一 id 多行，重启后再记）"] = int(db.scalar("SELECT COUNT(*) FROM nk WHERE n_rows > 1"))
    n["可探测（why 为空）"] = int(db.scalar("SELECT COUNT(*) FROM nk WHERE supported = 1"))
    n["sing-box 不支持（why 非空）"] = int(db.scalar("SELECT COUNT(*) FROM nk WHERE supported = 0"))
    n["链接要求跳过证书校验（insecure 且 sec=tls，有照链接分组）"] = int(db.scalar("SELECT COUNT(*) FROM nk WHERE linked_arm = 1"))
    n["链接要求跳过证书校验（insecure，不限 sec）"] = int(db.scalar("SELECT COUNT(*) FROM nk WHERE insecure = 1"))
    n["预检过（至少一条 npre）"] = int(db.scalar("SELECT COUNT(DISTINCT node) FROM np"))
    n["预检记录（npre 行）"] = int(db.scalar("SELECT COUNT(*) FROM np"))
    n["探测过（至少一次 judge_tls 隧道探测）"] = int(db.scalar("SELECT COUNT(*) FROM nagg"))
    n["可探测但从未探测过"] = int(db.scalar("SELECT COUNT(*) FROM nk k WHERE k.supported = 1 AND NOT EXISTS (SELECT 1 FROM nagg g WHERE g.id = k.id)"))
    n["节点尝试（att proto=node，不含 canceled）"] = int(db.scalar("SELECT COUNT(*) FROM na"))
    n["其中 dst=judge_tls"] = int(db.scalar("SELECT COUNT(*) FROM na WHERE dst = 'judge_tls'"))
    n["节点探访（visit）"] = int(db.scalar("SELECT COUNT(DISTINCT visit) FROM na"))
    n["轮次（nround）"] = int(db.scalar("SELECT COUNT(*) FROM nrd"))
    n["订阅抓取（nsnap，窗口内）"] = int(db.scalar("SELECT COUNT(*) FROM nsnap WHERE ts_epoch >= ?", (fs,)) if db.has_table("nsnap") else 0)
    n["订阅来源数"] = int(db.scalar("SELECT COUNT(DISTINCT src) FROM ns"))
    n["canceled 的节点尝试（已排除）"] = int(db.scalar("SELECT COUNT(*) FROM att WHERE proto = 'node' AND class LIKE '%canceled%'"))
    return n


def composition(db):
    """节点构成：去重、协议、不支持的原因、安全层、传输。"""
    out = {}
    out["去重"] = {
        "node 记录行数": int(db.scalar("SELECT COUNT(*) FROM node")),
        "node 表去重后的 id 数（summary.go nodeSch 口径，不裁窗口）": int(db.scalar("SELECT COUNT(DISTINCT id) FROM node")),
        "窗口内见过的节点（去重）": int(db.scalar("SELECT COUNT(*) FROM nk")),
        "订阅成员对（节点 × 订阅）": int(db.scalar("SELECT COUNT(*) FROM ns")),
        "出现在多个订阅里的节点": int(db.scalar("SELECT COUNT(*) FROM (SELECT id FROM ns GROUP BY id HAVING COUNT(*) > 1)")),
        "没有任何订阅记录的节点": int(db.scalar("SELECT COUNT(*) FROM nk k WHERE NOT EXISTS (SELECT 1 FROM ns s WHERE s.id = k.id)")),
        "note": "同一节点出现在多个订阅里只算一次：id 本身就是去重键；按订阅分组时一个节点可同时计入几个订阅，总数不重复计",
    }
    out["by_scheme"] = {}
    for sch, known, sup, lk, ins in db.q("""SELECT scheme, COUNT(*), SUM(supported), SUM(linked_arm), SUM(insecure)
                                           FROM nk GROUP BY scheme ORDER BY COUNT(*) DESC, scheme"""):
        out["by_scheme"][scheme_label(sch)] = {"见过": int(known), "可探测": int(sup or 0),
                                               "链接要求跳过校验（有照链接分组）": int(lk or 0), "链接要求跳过校验（insecure）": int(ins or 0)}
    # why / sec / net 都用归并到固定枚举后的列（DEFINITIONS“传输与安全层的归并”）
    out["unsupported_by_why"] = db.counts("SELECT why_c, COUNT(*) FROM nk WHERE supported = 0 GROUP BY why_c ORDER BY COUNT(*) DESC, why_c")
    out["unsupported_by_scheme"] = {}
    for sch, why, c in db.q("SELECT scheme, why_c, COUNT(*) FROM nk WHERE supported = 0 GROUP BY scheme, why_c ORDER BY 1, 3 DESC"):
        out["unsupported_by_scheme"].setdefault(scheme_label(sch), {})[why] = int(c)
    out["by_sec"] = db.counts("SELECT COALESCE(sec_c, '(null)'), COUNT(*) FROM nk GROUP BY sec_c ORDER BY COUNT(*) DESC, sec_c")
    out["by_net"] = db.counts("SELECT COALESCE(net_c, '(null)'), COUNT(*) FROM nk GROUP BY net_c ORDER BY COUNT(*) DESC, net_c")
    out["归并为 other 的原文值个数"] = {
        "sec": int(db.scalar("SELECT COUNT(*) FROM nk WHERE sec_c = 'other'")),
        "net": int(db.scalar("SELECT COUNT(*) FROM nk WHERE net_c = 'other'")),
        "why": int(db.scalar("SELECT COUNT(*) FROM nk WHERE why_c IS NOT NULL AND why_c != why")),
        "note": "分享链接里的参数原文不在固定枚举里的节点数；只输出个数，不输出原文",
    }
    return out


# ---------------------------------------------------------------- 可用性

def availability_block(db, where="1=1", params=()):
    """一组节点（nk 的子集，由 where 限定）的可用性。where 里用别名 k 指 nk。"""
    r = db.one("""SELECT COUNT(*), SUM(k.supported), SUM(g.id IS NOT NULL),
                         SUM(COALESCE(g.ok_strict, 0)), SUM(COALESCE(g.ok_linked, 0) = 1 AND COALESCE(g.ok_strict, 0) = 0),
                         SUM(COALESCE(g.ok_strict, 0) = 1 OR COALESCE(g.ok_linked, 0) = 1),
                         SUM(g.id IS NOT NULL AND COALESCE(g.ok_strict, 0) = 0 AND COALESCE(g.ok_linked, 0) = 0),
                         SUM(COALESCE(g.tried_linked, 0)),
                         SUM(COALESCE(l.ok_strict, 0)), SUM(COALESCE(l.ok_linked, 0) = 1 AND COALESCE(l.ok_strict, 0) = 0),
                         SUM(g.id IS NOT NULL AND COALESCE(l.ok_strict, 0) = 0 AND COALESCE(l.ok_linked, 0) = 0),
                         SUM(EXISTS (SELECT 1 FROM np p WHERE p.node = k.id)),
                         SUM(EXISTS (SELECT 1 FROM np p WHERE p.node = k.id AND p.cat = 'ok')),
                         SUM(COALESCE(g.ok_linked, 0))
                  FROM nk k LEFT JOIN nagg g ON g.id = k.id LEFT JOIN nlast l ON l.id = k.id WHERE %s""" % where, params)
    known, sup, probed, strict, linked_only, any_ok, never, tried_linked, l_strict, l_linked, l_fail, pre, pre_ok, linked_any = [int(v or 0) for v in r]
    return {
        "见过": known, "可探测": sup, "预检过": pre, "预检连得上过": pre_ok, "探测过": probed,
        "节点可用（严格）": {"占见过": ratio(strict, known), "占可探测": ratio(strict, sup), "占探测过": ratio(strict, probed)},
        "节点可用（照链接，任一轮）": {"占见过": ratio(linked_any, known), "占可探测": ratio(linked_any, sup), "占探测过": ratio(linked_any, probed)},
        "只有照链接才可用": {"占见过": ratio(linked_only, known), "占可探测": ratio(linked_only, sup), "占探测过": ratio(linked_only, probed)},
        "曾经可用（任一分组）": {"占见过": ratio(any_ok, known), "占可探测": ratio(any_ok, sup), "占探测过": ratio(any_ok, probed)},
        "探测过但从未可用": ratio(never, probed),
        "试过照链接分组的节点": tried_linked,
        "严格校验损失（只有照链接才可用 / 曾经可用）": ratio(linked_only, any_ok),
        "严格校验损失（相对：只有照链接才可用 / 严格可用）": ratio(linked_only, strict),
        "最近一次探测的结果": {"严格可用": l_strict, "仅照链接可用": l_linked, "不可用": l_fail, "den_探测过": probed,
                      "严格可用占探测过": ratio(l_strict, probed)},
    }


def availability(db):
    out = {"all": availability_block(db)}
    # 链接要求跳过校验的节点：严格校验的代价落在这里
    lk = availability_block(db, "k.linked_arm = 1")
    out["linked_arm_nodes"] = {
        "note": "insecure 且 sec=tls 的节点才有照链接分组（nodes.go batch()）；严格校验的代价只可能出现在这一组",
        "见过": lk["见过"], "探测过": lk["探测过"],
        "严格可用": lk["节点可用（严格）"]["占探测过"],
        "只有照链接才可用": lk["只有照链接才可用"]["占探测过"],
        "两者都不行": lk["探测过但从未可用"],
    }
    out["by_scheme"] = {}
    for (sch,) in db.q("SELECT scheme FROM nk GROUP BY scheme ORDER BY COUNT(*) DESC, scheme"):
        out["by_scheme"][scheme_label(sch)] = availability_block(db, "k.scheme IS ?", (sch,))
    out["by_source"] = {}
    for (src,) in db.q("SELECT src FROM ns GROUP BY src ORDER BY COUNT(*) DESC, src"):
        out["by_source"][src] = availability_block(db, "EXISTS (SELECT 1 FROM ns s WHERE s.id = k.id AND s.src = ?)", (src,))
    out["by_sec"] = {}
    for (sec,) in db.q("SELECT sec_c FROM nk GROUP BY sec_c ORDER BY COUNT(*) DESC, sec_c"):
        out["by_sec"]["(null)" if sec is None else sec] = availability_block(db, "k.sec_c IS ?", (sec,))
    out["listed_at_end"] = listed_at_end(db)
    out["supported_never_probed"] = never_probed(db)
    # 隧道探测结果分布（summary.go Nodes.Classes：arm + class，只算 dst=judge_tls；这里另给全部 dst）
    cls = {}
    for arm, dst, c, n in db.q("SELECT arm, dst, class, COUNT(*) FROM na GROUP BY 1, 2, 3 ORDER BY 1, 2, 4 DESC"):
        cls.setdefault(arm or "(null)", {}).setdefault(safe_dst(dst), {})[c] = int(n)
    out["tunnel_classes"] = cls
    out["tunnel_latency_ms"] = {}
    for arm in ("strict", "as_linked"):
        w = "dst = 'judge_tls' AND class = 'ok' AND arm = '%s'" % arm
        out["tunnel_latency_ms"][arm] = {"n": int(db.scalar("SELECT COUNT(*) FROM na WHERE " + w)),
                                         "p50": db.percentile("na", "ms", w, 0.5), "p90": db.percentile("na", "ms", w, 0.9),
                                         "p99": db.percentile("na", "ms", w, 0.99)}
    # 每个节点被探测的轮数分布（n_visits）
    out["visits_per_probed_node"] = {"p50": db.percentile("nagg", "n_visits", "1=1", 0.5), "max": db.scalar("SELECT MAX(n_visits) FROM nagg"),
                                     "mean": round(db.scalar("SELECT AVG(n_visits) FROM nagg") or 0, 1)}
    return out


def listed_at_end(db):
    """与 PROTOCOL“时点可用率”分母（某一时刻在榜的条目）对齐的一组：观察结束时在榜且 why 为空的节点，取最近一次探访的结果。"""
    r = db.one("""SELECT COUNT(*), SUM(COALESCE(l.ok_strict, 0)), SUM(COALESCE(l.ok_linked, 0) = 1 AND COALESCE(l.ok_strict, 0) = 0),
                         SUM(l.id IS NOT NULL AND COALESCE(l.ok_strict, 0) = 0 AND COALESCE(l.ok_linked, 0) = 0), SUM(l.id IS NULL)
                  FROM (SELECT DISTINCT id FROM nend) e JOIN nd d ON d.id = e.id LEFT JOIN nlast l ON l.id = e.id
                  WHERE d.why IS NULL""")
    den, s_, lo, fail, never = [int(v or 0) for v in r]
    last = db.one("SELECT listed, supported FROM nrd ORDER BY ts_epoch DESC, rid DESC LIMIT 1")
    return {
        "den_结束时在榜且可探测": den,
        "最近一次探访严格可用": ratio(s_, den), "最近一次探访仅照链接可用": ratio(lo, den),
        "最近一次探访不可用": ratio(fail, den), "窗口内从未探测": ratio(never, den),
        "结束时在榜（不限是否支持）": int(db.scalar("SELECT COUNT(DISTINCT id) FROM nend") or 0),
        "最后一轮 nround": {"listed": last[0] if last else None, "supported": last[1] if last else None},
        "note": "分母照 PROTOCOL“时点可用率”取结束时刻在榜的条目（node_event 口径，任一订阅）；没有 node 记录的节点不知道 why，不计入",
    }


def never_probed(db):
    """可探测（why 为空）、窗口内却从未做过隧道探测的节点，按原因拆分（DEFINITIONS“可探测但从未探测过”）。"""
    rows = db.counts("""SELECT CASE
                WHEN EXISTS (SELECT 1 FROM nerr e WHERE e.node = k.id AND e.msg LIKE 'config: %') THEN '配置被 sing-box 拒绝'
                WHEN NOT EXISTS (SELECT 1 FROM np p WHERE p.node = k.id) THEN '没有预检记录'
                WHEN EXISTS (SELECT 1 FROM np p WHERE p.node = k.id AND p.cat = 'ok') THEN '预检通过过却没有隧道探测'
                ELSE '最近一次预检：' || COALESCE((SELECT l.cat FROM np_last l WHERE l.node = k.id), '?') END, COUNT(*)
              FROM nk k WHERE k.supported = 1 AND NOT EXISTS (SELECT 1 FROM nagg g WHERE g.id = k.id)
              GROUP BY 1 ORDER BY 2 DESC, 1""")
    zh = dict((key, z) for z, key in PRECHECK_CATEGORIES)
    out = {}
    for k, v in rows.items():
        if k.startswith("最近一次预检："):
            cat = k.split("：", 1)[1]
            k = "最近一次预检：" + zh.get(cat, cat)
        out[k] = v
    return {"total": sum(out.values()), "by_reason": out,
            "note": "节点版的“从没探访过的候选”；“没有预检记录”多半是窗口内从未在榜，或只在正式起点之前在榜"}


_OBS_NAMES = {}


def safe_dst(dst):
    """att.dst 的 obs:<名> 里是配置里的观察者名；按 OUTPUT_RULES 核对它不是主机名或地址，是就换成序号。"""
    if dst is None:
        return "(null)"
    if not dst.startswith("obs:"):
        return dst
    name = dst[4:]
    if re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
        return dst
    if name not in _OBS_NAMES:
        _OBS_NAMES[name] = "obs:观察者%d" % (len(_OBS_NAMES) + 1)
    return _OBS_NAMES[name]


# ---------------------------------------------------------------- 预检

def precheck(db):
    out = {}
    total = int(db.scalar("SELECT COUNT(*) FROM np"))
    by_rows = db.counts("SELECT cat, COUNT(*) FROM np GROUP BY cat")
    out["按预检记录"] = {"den": total, **{zh: ratio(by_rows.get(key, 0), total) for zh, key in PRECHECK_CATEGORIES}}
    out["按预检记录的具体类别"] = db.counts("SELECT class, COUNT(*) FROM np GROUP BY class ORDER BY COUNT(*) DESC")
    n_nodes = int(db.scalar("SELECT COUNT(*) FROM np_last"))
    by_last = db.counts("SELECT cat, COUNT(*) FROM np_last GROUP BY cat")
    out["按节点最近一次预检（summary.go lastPre）"] = {"den": n_nodes, **{zh: ratio(by_last.get(key, 0), n_nodes) for zh, key in PRECHECK_CATEGORIES}}
    out["按节点最近一次预检的具体类别"] = db.counts("SELECT class, COUNT(*) FROM np_last GROUP BY class ORDER BY COUNT(*) DESC")
    ever = db.one("""SELECT COUNT(*), SUM(ok), SUM(dns), SUM(tcp_tried), SUM(host_ip) FROM (
                       SELECT node, MAX(cat = 'ok') ok, MAX(cat = 'dns') dns, MAX(tcp_ok IS NOT NULL) tcp_tried, MAX(dns_ok IS NULL) host_ip
                       FROM np GROUP BY node)""")
    out["按节点（曾经）"] = {"预检过的节点": int(ever[0]), "曾经通过": ratio(ever[1], ever[0]), "曾经 DNS 失败": ratio(ever[2], ever[0]),
                      "曾发起过 TCP": int(ever[3] or 0), "主机写的是 IP（没有 DNS 步骤）": ratio(ever[4], ever[0])}
    tcp = db.one("SELECT COUNT(*), SUM(tcp_ok) FROM np WHERE tcp_ok IS NOT NULL")
    out["TCP 预检连得上（分母只算发起了连接的记录）"] = ratio(tcp[1], tcp[0])
    out["TCP 失败类别"] = db.counts("SELECT tcp_class, COUNT(*) FROM np WHERE tcp_ok = 0 GROUP BY tcp_class ORDER BY COUNT(*) DESC")
    out["TCP 预检耗时 ms（连得上的）"] = {"p50": db.percentile("np", "tcp_ms", "tcp_ok = 1", 0.5), "p90": db.percentile("np", "tcp_ms", "tcp_ok = 1", 0.9)}
    out["解析出的 IPv4 个数分布（有 DNS 步骤且成功）"] = db.counts("SELECT n_ips, COUNT(*) FROM np WHERE dns_ok = 1 GROUP BY n_ips ORDER BY n_ips")
    # 预检通过 → 隧道探测的衔接
    r = db.one("""SELECT COUNT(*), SUM(EXISTS (SELECT 1 FROM nagg g WHERE g.id = x.node)) FROM (SELECT DISTINCT node FROM np WHERE cat = 'ok') x""")
    out["预检通过过的节点里做过隧道探测的"] = ratio(r[1], r[0])
    r = db.one("SELECT COUNT(*), SUM(NOT EXISTS (SELECT 1 FROM np p WHERE p.node = g.id)) FROM nagg g")
    out["探测过却没有任何预检记录的节点（应为 0）"] = ratio(r[1], r[0])
    return out


# ---------------------------------------------------------------- 轮次

def _minutes(ms):
    return None if ms is None else round(ms / 60000.0, 1)


def rounds(db):
    seq = []
    rows = db.q("""SELECT d.run, d.round, d.ts_epoch, d.known, d.listed, d.supported, d.backoff, d.tcp_ok, d.probed, d.ok_strict, d.ok_linked,
                          d.bad_config, d.batches, d.ms, d.has_err, a.att_probed, a.att_ok_strict, a.att_ok_linked, a.pre_rows, a.pre_ok,
                          a.att_canceled
                   FROM nrd d JOIN nrd_att a ON a.rid = d.rid ORDER BY d.ts_epoch, d.rid""")
    mismatch = 0
    prev = None
    intervals = []
    for r in rows:
        (run, rnd, ts, known, listed, sup, backoff, tcp_ok, probed, oks, okl, bad, batches, ms, has_err, ap, aos, aol, pre_rows, pre_ok, ac) = r
        # nround.probed 含程序退出时 canceled 的节点（nodes.go batch() 的 rr.Probed++ 不看 class），所以对 att_probed + att_canceled
        m = (probed != ap + ac) or (oks != aos) or (okl != aol)
        mismatch += int(m)
        item = {"run": run, "round": rnd, "start_utc": iso_minute(ts), "known": known, "listed": listed, "supported": sup, "backoff": backoff,
                "tcp_ok": tcp_ok, "probed": probed, "ok_strict": oks, "ok_linked": okl, "bad_config": bad, "batches": batches,
                "minutes": round((ms or 0) / 60000.0, 1), "has_err": bool(has_err),
                "att_probed": ap, "att_canceled": ac, "att_ok_strict": aos, "att_ok_linked": aol, "npre_rows": pre_rows, "npre_ok": pre_ok, "att_mismatch": bool(m),
                "ok_strict_share_of_probed": pct(oks, probed), "ok_linked_share_of_ok": pct(okl, (oks or 0) + (okl or 0))}
        if prev is not None and prev[0] == run:
            intervals.append((ts - prev[1]) / 60.0)
        prev = (run, ts)
        seq.append(item)
    out = {"count": len(seq), "runs": int(db.scalar("SELECT COUNT(DISTINCT run) FROM nrd") or 0), "sequence": seq,
           "att_mismatch_rounds": mismatch,
           "rounds_with_err": int(db.scalar("SELECT COALESCE(SUM(has_err), 0) FROM nrd")),
           "bad_config_total": int(db.scalar("SELECT COALESCE(SUM(bad_config), 0) FROM nrd")),
           "interval_minutes": {"n": len(intervals),
                                "p50": round(sorted(intervals)[len(intervals) // 2], 1) if intervals else None,
                                "max": round(max(intervals), 1) if intervals else None,
                                "min": round(min(intervals), 1) if intervals else None,
                                "note": "同一次启动内相邻两轮起点的间隔；PROTOCOL 规定每 60 分钟一轮，启动后第一个小时会更长"},
           "round_duration_minutes": {"p50": _minutes(db.percentile("nrd", "ms", "1=1", 0.5)), "max": _minutes(db.scalar("SELECT MAX(ms) FROM nrd")),
                                      "p50_ms": db.percentile("nrd", "ms", "1=1", 0.5), "max_ms": db.scalar("SELECT MAX(ms) FROM nrd"),
                                      "note": "每轮耗时：p50 / max 是分钟（nround.ms ÷ 60000，保留一位小数，与 sequence 的 minutes 同一单位），*_ms 是原值毫秒"}}
    if seq:
        last = seq[-1]
        out["last_round"] = {k: last[k] for k in ("run", "round", "start_utc", "listed", "supported", "backoff", "tcp_ok", "probed", "ok_strict", "ok_linked")}
    # att 里出现、却不落在任何一轮窗口里的节点尝试（应为 0；非 0 说明 nround 丢了或窗口假设不成立）
    out["att_outside_any_round"] = int(db.scalar("""SELECT COUNT(*) FROM na a WHERE a.dst = 'judge_tls'
                                                    AND NOT EXISTS (SELECT 1 FROM nrd d WHERE a.ts_epoch BETWEEN d.w0 AND d.w1)"""))
    return out


# ---------------------------------------------------------------- 出口

def egress(db, win_info):
    out = {"self_ips_source": win_info["self_ips_source"], "self_ips_count": win_info["self_ips_count"],
           "self_ips_count_start_judge_ip": win_info["self_ips_count_judge_ip"]}

    def inv_block(echo_col, remote_col):
        e = db.one("SELECT COUNT(*), SUM(%s), COUNT(DISTINCT CASE WHEN %s THEN cand END) FROM na WHERE ip IS NOT NULL" % (echo_col, echo_col))
        by_dst = {}
        for dst, n, k in db.q("SELECT dst, COUNT(*), SUM(%s) FROM na WHERE ip IS NOT NULL GROUP BY dst" % echo_col):
            by_dst[safe_dst(dst)] = {"有回显": int(n), "等于本机": int(k or 0)}
        j = db.one("""SELECT COUNT(*), SUM(%s), COUNT(DISTINCT CASE WHEN %s THEN cand END)
                      FROM na WHERE seen = 1 AND class = 'ok' AND dst = 'judge_tls'""" % (remote_col, remote_col))
        j2 = db.one("SELECT COUNT(*), SUM(%s) FROM na WHERE seen = 1" % remote_col)
        return {
            "att.ip（回显）等于本机": {"num": int(e[1] or 0), "den": int(e[0] or 0), "nodes": int(e[2] or 0), "by_dst": by_dst},
            "judge 看到的 remote 等于本机（class=ok、dst=judge_tls）": {"num": int(j[1] or 0), "den": int(j[0] or 0), "nodes": int(j[2] or 0)},
            "judge 看到的 remote 等于本机（judge 收到的全部节点请求）": {"num": int(j2[1] or 0), "den": int(j2[0] or 0)},
            "_bad": int(e[1] or 0) + int(j2[1] or 0),
        }
    # 不变量：本机地址取 self_ips 全部来源（判定用）；只取 start.judge_ip 的一组与 summary.go 对齐，并列输出
    inv = inv_block("echo_self", "remote_self")
    inv_j = inv_block("echo_self_j", "remote_self_j")
    bad = inv.pop("_bad")
    inv_j.pop("_bad")
    inv["verdict"] = "通过" if not bad else "违反：节点探测的流量从本机直接出去了，数据在查明原因之前不可信（PROTOCOL“对照与自检”）"
    inv["本机地址口径"] = "self_ips 全部来源"
    inv["只用 start.judge_ip（summary.go selfIPs 口径）"] = inv_j
    out["invariant"] = inv
    # NAT 指标：judge_remote:control:public 的地址是否全部等于 start.judge_ip（不输出地址）
    pub = db.one("""SELECT COUNT(DISTINCT ip), COUNT(DISTINCT CASE WHEN ip IN (SELECT ip FROM self_ips WHERE source = 'start.judge_ip') THEN ip END)
                    FROM self_ips WHERE source = 'judge_remote:control:public' AND ip IS NOT NULL AND ip != ''""")
    has_j = int(db.scalar("SELECT COUNT(*) FROM self_ips WHERE source = 'start.judge_ip' AND ip IS NOT NULL AND ip != ''") or 0)
    n_pub, n_eq = int(pub[0] or 0), int(pub[1] or 0)
    out["nat_indicator"] = {
        "judge_remote:control:public 的不同地址数": n_pub, "其中等于 start.judge_ip 的": n_eq,
        "一致": (n_pub == n_eq) if (n_pub and has_j) else None,
        "note": "不一致说明本机访问自己的公网地址经过了 NAT，judge 看到的本机源地址不是 start.judge_ip；这时只用 start.judge_ip 判不变量会漏报，"
                "所以不变量用 self_ips 全部来源。null 表示缺少其中一种来源，无从比较（SCHEMA.md“judge 的身份从哪里取”）",
    }
    # 与入口比较（summary.go nodeEgress），出口是本机（全部来源）的先排除
    out["vs_entry"] = {}
    out["vs_entry_union"] = {"note": "第二组：入口 IP 取该节点所有预检 IP 的并集（对 DNS 轮询 / CDN 节点更宽松，“与入口相同”偏多）"}
    for key, col_same, col_has in (("vs_entry", "remote_is_entry", "has_entry"), ("vs_entry_union", "remote_is_entry_any", "has_entry_any")):
        for dst in ("judge_tls", "judge_http"):
            base = "FROM na a WHERE a.seen = 1 AND a.class = 'ok' AND a.dst = ? AND a.remote_self = 0"
            cls = "CASE WHEN a.%s THEN '与入口相同' WHEN NOT a.%s THEN '入口地址未知' ELSE '与入口不同' END" % (col_same, col_has)
            n = int(db.scalar("SELECT COUNT(*) " + base, (dst,)) or 0)
            by_att = db.counts("SELECT %s, COUNT(*) %s GROUP BY 1" % (cls, base), (dst,))
            by_node = db.counts("SELECT c, COUNT(*) FROM (SELECT DISTINCT a.cand, %s AS c %s) GROUP BY 1" % (cls, base), (dst,))
            by_arm = {}
            for arm, c, k in db.q("SELECT a.arm, %s, COUNT(*) %s GROUP BY 1, 2" % (cls, base), (dst,)):
                by_arm.setdefault(arm, {})[c] = int(k)
            out[key][dst] = {"尝试": n, "按尝试": by_att, "按节点（一个节点可属多类）": by_node, "按分组（arm）": by_arm}
    # 每个节点的出口是否稳定：judge 看到的不同 remote 个数
    st = db.counts("""SELECT k, COUNT(*) FROM (SELECT cand, COUNT(DISTINCT remote) AS k FROM na WHERE seen = 1 AND class = 'ok' GROUP BY cand) GROUP BY k ORDER BY k""")
    out["distinct_egress_per_node"] = {"按不同出口地址个数分节点": st, "note": "judge 收到的、class=ok 的节点请求里 remote 的不同值个数；1 表示出口稳定"}
    # 回显 vs 日志
    m = db.one("SELECT COUNT(*), SUM(echo_matches) FROM na WHERE seen = 1 AND ip IS NOT NULL AND dst IN ('judge_tls', 'judge_http')")
    out["echo_vs_log"] = {"回显等于 judge 日志的 remote": ratio(m[1], m[0]), "note": "att.ip 只用来与 judge 日志互相核对；不一致说明回显经过了改写或 NAT"}
    # 观察者一致性：同一 visit 里 judge 的 remote 与 obs 报告的地址
    v = db.one("""SELECT COUNT(*), SUM(consistent) FROM (
                    SELECT a.visit,
                           (COUNT(DISTINCT COALESCE(CASE WHEN a.dst LIKE 'obs:%' THEN a.ip END, CASE WHEN a.dst IN ('judge_tls','judge_http') AND a.seen THEN a.remote END)) = 1) AS consistent
                    FROM na a WHERE a.class = 'ok' AND (a.dst LIKE 'obs:%' OR (a.dst IN ('judge_tls','judge_http') AND a.seen = 1))
                    GROUP BY a.visit
                    HAVING SUM(a.dst LIKE 'obs:%' AND a.ip IS NOT NULL) > 0 AND SUM(a.dst IN ('judge_tls','judge_http') AND a.seen) > 0)""")
    out["observers_consistent"] = {"同一探访里 judge 与观察者看到的出口全部相同": ratio(v[1], v[0]),
                                   "note": "分母是既有 judge 记录、又至少有一个观察者报告地址的探访（visit）"}
    # judge 没收到 / 重放
    cutoff = db.scalar("SELECT MAX(ts_epoch) FROM req")
    if cutoff is not None:
        u = db.one("""SELECT COUNT(*), SUM(seen = 0), COUNT(DISTINCT CASE WHEN seen = 0 THEN cand END) FROM na
                      WHERE class = 'ok' AND nonce IS NOT NULL AND dst IN ('judge_tls', 'judge_http') AND ts_epoch < ?""", (cutoff - JUDGE_LAG_S,))
        out["judge_not_seen"] = {"num": int(u[1] or 0), "den": int(u[0] or 0), "nodes": int(u[2] or 0),
                                 "note": "探测器认为成功、judge 没收到；只核对早于 judge 最后一条记录前 %d 秒的尝试。应为 0" % JUDGE_LAG_S}
    else:
        out["judge_not_seen"] = {"num": None, "den": 0, "note": "库里没有 req 记录"}
    rp = db.one("SELECT COUNT(*), SUM(copies > 1), COUNT(DISTINCT CASE WHEN copies > 1 THEN cand END) FROM na WHERE seen = 1")
    out["replay"] = {"同一 nonce 被 judge 收到不止一次": ratio(rp[1], rp[0]), "nodes": int(rp[2] or 0)}
    return out


# ---------------------------------------------------------------- sing-box 报的错误

def nerr_block(db, fs):
    if not db.has_table("nerr"):
        return {"records": 0}
    total = int(db.scalar("SELECT COUNT(*) FROM nerr WHERE ts_epoch >= ?", (fs,)))
    by_arm = db.counts("SELECT arm, COUNT(*) FROM nerr WHERE ts_epoch >= ? GROUP BY arm", (fs,))
    cats = db.counts("SELECT %s AS c, COUNT(*) FROM nerr WHERE ts_epoch >= ? GROUP BY c" % NERR_CASE, (fs,))
    by_arm_cat = {}
    for arm, c, n in db.q("SELECT arm, %s AS c, COUNT(*) FROM nerr WHERE ts_epoch >= ? GROUP BY arm, c" % NERR_CASE, (fs,)):
        by_arm_cat.setdefault(arm, {})[c] = int(n)
    nodes = db.one("SELECT COUNT(DISTINCT node), COUNT(DISTINCT CASE WHEN msg LIKE 'config: %' THEN node END) FROM nerr WHERE ts_epoch >= ?", (fs,))
    return {"records": total, "by_arm": by_arm, "by_category": {c: cats.get(c, 0) for c in NERR_CATEGORIES}, "by_arm_category": by_arm_cat,
            "nodes_with_error": int(nodes[0] or 0), "nodes_with_config_rejected": int(nodes[1] or 0),
            "note": "msg 是 sing-box 日志原文，不输出；分类是按关键词归入固定枚举，other 是没匹配上的"}


# ---------------------------------------------------------------- 订阅

def subscriptions(db, fs):
    out = {"by_source": {}, "total": {}}
    if not db.has_table("nsnap"):
        return out
    rows = db.q("""SELECT src, COUNT(*) AS fetches,
                          SUM(CASE WHEN (err IS NOT NULL AND err != '') OR status NOT IN (200, 304) THEN 1 ELSE 0 END) AS failed,
                          SUM(COALESCE(changed, 0)) AS changed,
                          SUM(status = 304 AND COALESCE(err, '') = '') AS not_modified,
                          SUM(status = 200 AND COALESCE(changed, 0) = 0 AND COALESCE(err, '') = '') AS same_200,
                          SUM(COALESCE(base, 0)) AS base_snaps,
                          SUM(CASE WHEN COALESCE(base, 0) = 0 THEN COALESCE(n_add, 0) ELSE 0 END) AS adds,
                          SUM(CASE WHEN COALESCE(base, 0) = 0 THEN COALESCE(n_del, 0) ELSE 0 END) AS dels,
                          SUM(COALESCE(unparsed, 0)) AS unparsed, SUM(COALESCE(lines, 0)) AS lines,
                          MAX(ms) AS max_ms
                   FROM nsnap WHERE ts_epoch >= ? GROUP BY src ORDER BY src""", (fs,))
    for src, fetches, failed, changed, nm, same200, base_snaps, adds, dels, unparsed, lines, max_ms in rows:
        last = db.one("""SELECT status, n FROM nsnap WHERE src = ? AND ts_epoch >= ? ORDER BY ts_epoch DESC, rid DESC LIMIT 1""", (src, fs))
        # n 带 omitempty：解析出 0 个节点时为空，按 0 计（只对 changed=1 的行）
        cur = db.scalar("SELECT COALESCE(n, 0) FROM nsnap WHERE src = ? AND ts_epoch >= ? AND COALESCE(changed, 0) = 1 ORDER BY ts_epoch DESC, rid DESC LIMIT 1", (src, fs))
        failed_status = db.counts("""SELECT status, COUNT(*) FROM nsnap WHERE src = ? AND ts_epoch >= ?
                                     AND ((err IS NOT NULL AND err != '') OR status NOT IN (200, 304)) GROUP BY status""", (src, fs))
        ever = int(db.scalar("SELECT COUNT(*) FROM ns WHERE src = ?", (src,)) or 0)
        # 结束时在榜：最后一次 base 快照之后、最后一个事件是 add（TEMP 表 nend，不裁窗口）
        listed_end = int(db.scalar("SELECT COUNT(*) FROM nend WHERE src = ?", (src,)) or 0)
        out["by_source"][src] = {
            "抓取": int(fetches), "失败": ratio(failed, fetches), "失败时的状态码": failed_status, "未变化（304）": int(nm or 0),
            "未变化（200 且内容相同）": int(same200 or 0),
            "有变化（含首次）": int(changed or 0), "首次快照（base）": int(base_snaps or 0),
            "真正的上榜（base=0 的 add）": int(adds or 0), "真正的下榜（base=0 的 del）": int(dels or 0),
            "解析不了的行（累计）": int(unparsed or 0), "链接行（累计，只在有变化时数）": int(lines or 0),
            "最近一次状态码": last[0] if last else None, "当前节点数（最近一次有变化的 n）": cur,
            "曾在榜的节点（去重）": ever, "结束时在榜的节点": listed_end, "最长一次抓取 ms": max_ms,
        }
    t = db.one("""SELECT COUNT(*), SUM(CASE WHEN (err IS NOT NULL AND err != '') OR status NOT IN (200, 304) THEN 1 ELSE 0 END), SUM(COALESCE(changed, 0)),
                         SUM(status = 304 AND COALESCE(err, '') = ''), SUM(status = 200 AND COALESCE(changed, 0) = 0 AND COALESCE(err, '') = '')
                  FROM nsnap WHERE ts_epoch >= ?""", (fs,))
    out["total"] = {"抓取": int(t[0] or 0), "失败": ratio(t[1], t[0]), "有变化": int(t[2] or 0),
                    "未变化（304）": int(t[3] or 0), "未变化（200 且内容相同）": int(t[4] or 0),
                    "订阅数": len(out["by_source"]), "曾在榜的节点（全部订阅去重）": int(db.scalar("SELECT COUNT(DISTINCT id) FROM ns") or 0)}
    # 结束时在榜按订阅（不依赖窗口内有没有抓取记录：--formal-start 很晚时上面的 by_source 可能是空的）
    out["listed_at_end_by_source"] = db.counts("SELECT src, COUNT(*) FROM nend GROUP BY src ORDER BY src")
    ev = db.one("SELECT SUM(event = 'add' AND COALESCE(base, 0) = 0), SUM(event = 'del'), SUM(COALESCE(base, 0) = 1) FROM node_event WHERE ts_epoch >= ?", (fs,))
    out["node_events"] = {"真正的上榜": int(ev[0] or 0), "下榜": int(ev[1] or 0), "首次快照里的条目（不是新上榜）": int(ev[2] or 0)}
    return out


# ---------------------------------------------------------------- 内部核对

def checks(db, fs):
    out = {}
    r = db.one("SELECT COUNT(*), SUM(NOT EXISTS (SELECT 1 FROM ns s WHERE s.id = k.id)) FROM nk k")
    out["见过的节点里没有订阅归属的（应为 0）"] = ratio(r[1], r[0])
    # 订阅抓取的分解闭合：抓取 = 失败 + 有变化 + 未变化（304）+ 未变化（200 且内容相同）
    r = db.one("""SELECT COUNT(*),
                         SUM(CASE WHEN (err IS NOT NULL AND err != '') OR status NOT IN (200, 304) THEN 1 ELSE 0 END),
                         SUM(CASE WHEN NOT ((err IS NOT NULL AND err != '') OR status NOT IN (200, 304)) AND COALESCE(changed, 0) = 1 THEN 1 ELSE 0 END),
                         SUM(status = 304 AND COALESCE(err, '') = '' AND COALESCE(changed, 0) = 0),
                         SUM(status = 200 AND COALESCE(err, '') = '' AND COALESCE(changed, 0) = 0)
                  FROM nsnap WHERE ts_epoch >= ?""", (fs,))
    parts = [int(v or 0) for v in r]
    out["订阅抓取分解闭合（抓取 = 失败 + 有变化 + 未变化 304 + 未变化 200）"] = {
        "抓取": parts[0], "失败": parts[1], "有变化": parts[2], "未变化（304）": parts[3], "未变化（200 且内容相同）": parts[4],
        "闭合": parts[0] == sum(parts[1:])}
    r = db.one("SELECT COUNT(*), SUM(no_node_rec) FROM nk")
    out["见过的节点里没有 node 记录的（应为 0）"] = ratio(r[1], r[0])
    r = db.one("SELECT COUNT(*), SUM(supported = 0) FROM nagg g JOIN nk k ON k.id = g.id")
    out["探测过的节点里 why 非空的（应为 0：不支持的节点不该被探测）"] = ratio(r[1], r[0])
    r = db.one("SELECT COUNT(*), SUM(COALESCE(k.linked_arm, 0) = 0) FROM nagg g JOIN nk k ON k.id = g.id WHERE g.tried_linked = 1")
    out["试过照链接分组却不是 insecure+tls 的（应为 0）"] = ratio(r[1], r[0])
    r = db.one("""SELECT COUNT(*), SUM(ok_strict) FROM nagg g WHERE g.tried_linked = 1""")
    out["试过照链接分组的节点里严格也通过过的（同一轮先严格失败才试照链接；跨轮可能两者都有）"] = ratio(r[1], r[0])
    out["nround 与 att 独立计数不一致的轮次"] = int(db.scalar("""SELECT COUNT(*) FROM nrd d JOIN nrd_att a ON a.rid = d.rid
                                                      WHERE d.probed != a.att_probed + a.att_canceled OR d.ok_strict != a.att_ok_strict
                                                         OR d.ok_linked != a.att_ok_linked"""))
    r = db.one("SELECT SUM(ok_strict), SUM(ok_linked) FROM nrd")
    r2 = db.one("SELECT SUM(att_ok_strict), SUM(att_ok_linked) FROM nrd_att")
    out["nround 累计 ok_strict / ok_linked vs att"] = {"nround": [int(r[0] or 0), int(r[1] or 0)], "att": [int(r2[0] or 0), int(r2[1] or 0)]}
    # nround.known 最后一轮 vs 见过的节点
    last = db.one("SELECT known, listed FROM nrd ORDER BY ts_epoch DESC, rid DESC LIMIT 1")
    out["最后一轮 nround.known vs 见过的节点（去重）"] = {"nround.known": last[0] if last else None, "nk": int(db.scalar("SELECT COUNT(*) FROM nk")),
                                              "note": "重启后 known 从当次启动见过的算起，可能比全程去重数小"}
    return out


# ---------------------------------------------------------------- 与 summary.json 交叉核对

def crosscheck_summary(db, path):
    """与 fieldtest 自带汇总（summary.json）的 nodes 节交叉核对。summary.go 不区分试运行，所以这里按整个数据算（不裁正式起点）。
    只抄 summary.json 里的计数字段；errors 的键是错误文本（可能含地址），只比较总数，不抄键。"""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    nodes = s.get("nodes") or {}
    out = {"summary_generated": s.get("generated")}
    cmp = {}

    def put(key, want, got):
        cmp[key] = {"summary": want, "computed": got, "match": (want == got)}

    put("nodes.known", nodes.get("known"), int(db.scalar("SELECT COUNT(DISTINCT id) FROM node")))
    mine = db.counts("SELECT scheme, COUNT(*) FROM nd GROUP BY scheme")
    for k in sorted(nodes.get("by_scheme") or {}):
        put("nodes.by_scheme.%s" % k, nodes["by_scheme"][k], mine.get(k))
    # why 的键可能带分享链接参数原文：两边都按 why_case 归并后再比（summary.json 的键也只以归并后的形式出现在输出里）
    mine = db.counts("SELECT why_c, COUNT(*) FROM nd WHERE why IS NOT NULL GROUP BY why_c")
    theirs = {}
    for k, v in (nodes.get("unsupported") or {}).items():
        kk = db.scalar("SELECT %s" % why_case(":w"), {"w": k})
        theirs[kk] = theirs.get(kk, 0) + int(v)
    for k in sorted(theirs):
        put("nodes.unsupported.%s" % k, theirs[k], mine.get(k))
    mine = db.counts("""SELECT class, COUNT(*) FROM (
                          SELECT node, class, ROW_NUMBER() OVER (PARTITION BY node ORDER BY ts_epoch DESC, rid DESC) rn FROM npre)
                        WHERE rn = 1 GROUP BY class""")
    for k in sorted(nodes.get("precheck") or {}):
        put("nodes.precheck.%s" % k, nodes["precheck"][k], mine.get(k))
    # ok：协议 → strict / as_linked_only（summary.go finish()），协议取 node 记录，没有的是 "?"
    rows = db.q("""SELECT COALESCE(d.scheme, '?'), SUM(g.s), SUM(g.l = 1 AND g.s = 0) FROM (
                     SELECT cand, MAX(arm = 'strict' AND class = 'ok') s, MAX(arm = 'as_linked' AND class = 'ok') l
                     FROM na_full WHERE dst = 'judge_tls' GROUP BY cand HAVING s = 1 OR l = 1) g
                   LEFT JOIN nd d ON d.id = g.cand GROUP BY 1""")
    mine = {sch: {"strict": int(a or 0), "as_linked_only": int(b or 0)} for sch, a, b in rows}
    for sch in sorted(nodes.get("ok") or {}):
        for arm in sorted(nodes["ok"][sch]):
            put("nodes.ok.%s.%s" % (sch, arm), nodes["ok"][sch][arm], (mine.get(sch) or {}).get(arm, 0))
    for sch, v in mine.items():
        for arm, n in v.items():
            if n and arm not in (nodes.get("ok", {}).get(sch) or {}):
                put("nodes.ok.%s.%s" % (sch, arm), 0, n)
    mine = db.counts("SELECT arm || ' ' || class, COUNT(*) FROM na_full WHERE dst = 'judge_tls' GROUP BY 1")
    for k in sorted(nodes.get("classes") or {}):
        put("nodes.classes.%s" % k, nodes["classes"][k], mine.get(k, 0))
    mine = db.counts("""SELECT CASE WHEN remote_is_entry THEN '与入口相同' WHEN NOT has_entry THEN '入口地址未知' ELSE '与入口不同' END, COUNT(*)
                        FROM na_full WHERE seen = 1 AND class = 'ok' AND dst = 'judge_tls' AND remote_self_j = 0 GROUP BY 1""")
    for k in sorted(set(nodes.get("egress") or {}) | set(mine)):
        put("nodes.egress.%s" % k, (nodes.get("egress") or {}).get(k, 0), mine.get(k, 0))
    # rounds：summary 只留最近 6 轮，按 ts 对
    for r in nodes.get("rounds") or []:
        ts = r.get("ts")
        row = db.one("""SELECT round, known, listed, supported, backoff, tcp_ok, probed, ok_strict, ok_linked, bad_config, batches, ms
                        FROM nround WHERE ts = ?""", (ts,))
        keys = ("round", "known", "listed", "supported", "backoff", "tcp_ok", "probed", "ok_strict", "ok_linked", "bad_config", "batches", "ms")
        got = dict(zip(keys, row)) if row else {}
        want = {k: r.get(k, 0) for k in keys}
        put("nodes.rounds[%s]" % (ts[:16] if ts else "?"), want, got)
    # subscriptions
    for row in nodes.get("subscriptions") or []:
        src = row.get("src")
        r = db.one("""SELECT COUNT(*), SUM(CASE WHEN (err IS NOT NULL AND err != '') OR status NOT IN (200, 304) THEN 1 ELSE 0 END),
                             SUM(COALESCE(changed, 0)) FROM nsnap WHERE src = ?""", (src,))
        cur = db.scalar("SELECT COALESCE(n, 0) FROM nsnap WHERE src = ? AND COALESCE(changed, 0) = 1 ORDER BY ts_epoch DESC, rid DESC LIMIT 1", (src,))
        last = db.scalar("SELECT status FROM nsnap WHERE src = ? ORDER BY ts_epoch DESC, rid DESC LIMIT 1", (src,))
        got = {"fetches": int(r[0] or 0), "failed": int(r[1] or 0), "changed": int(r[2] or 0), "current": cur, "last_status": last}
        for k in ("fetches", "failed", "changed", "current", "last_status"):
            if k in row:
                put("nodes.subscriptions.%s.%s" % (src, k), row[k], got[k])
    if "errors" in nodes:
        put("nodes.errors（总条数）", sum(int(v) for v in (nodes.get("errors") or {}).values()), int(db.scalar("SELECT COUNT(*) FROM nerr")) if db.has_table("nerr") else 0)
    recs = s.get("records") or {}
    for k in ("node", "npre", "nround", "nerr", "nsnap"):
        if k in recs and db.has_table(k):
            put("records.%s" % k, recs[k], int(db.scalar("SELECT COUNT(*) FROM %s" % k)))
    out["comparisons"] = cmp
    out["matched"] = sum(1 for v in cmp.values() if v["match"])
    out["total"] = len(cmp)
    out["mismatches"] = sorted(k for k, v in cmp.items() if not v["match"])
    return out


# ---------------------------------------------------------------- 输出前的断言

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?!\d|\.\d|/24)")
HOSTPORT_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}:\d{1,5}")
NODE_ID_RE = re.compile(r'"[0-9a-f]{12}"')


def assert_clean(text, db):
    """最后一道保险：输出文本里不许有 ip:port、不带 /24 的 IPv4、judge 的主机名或 IP、节点标识。这是断言，不是放行手段。"""
    bad = []
    if HOSTPORT_RE.search(text):
        bad.append("ip:port")
    if IPV4_RE.search(text):
        bad.append("不带 /24 的 IPv4")
    if NODE_ID_RE.search(text):
        bad.append("节点标识")
    low = text.lower()
    for table, col in (("self_names", "name"), ("self_ips", "ip")):
        if db.has_table(table):
            for (v,) in db.q("SELECT DISTINCT %s FROM %s" % (col, table)):
                if v and v.lower() in low:
                    bad.append("judge 身份（%s）" % table)
                    break
    if db.has_table("node"):
        # 只查含“.”或“:”的主机名（域名、IPv4、IPv6）。不含的是单标签裸词（订阅里的垃圾链接，如 node、test），
        # 公网 DNS 解析不了、不是地址，拿它做子串或单词匹配只会撞上输出里的正常词（例如“node 记录行数”），是误报不是泄露
        for (v,) in db.q("""SELECT DISTINCT lower(host) FROM node WHERE host IS NOT NULL AND length(host) >= 4
                            AND (instr(host, '.') > 0 OR instr(host, ':') > 0)"""):
            if v in low:
                bad.append("节点主机名")
                break
    for literal in ("@",):  # judge 的名字和地址只从库里的 self_names / self_ips 取（上面已查），源码里不写
        if literal in text:
            bad.append("字面量 %s" % literal)
    if bad:
        raise SystemExit("输出含不许出现的内容：%s；已拒绝写出" % "、".join(bad))


# ---------------------------------------------------------------- Markdown

def _table(headers, rows):
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for r in rows:
        print("| " + " | ".join(str(c) for c in r) + " |")
    print()


def print_markdown(res):
    w = res["window"]
    print("### 观察窗口\n")
    print(f"- 正式起点 {w['formal_start_utc']}（{w['formal_start_rule']}），结束 {w['end_utc']}，共 {fmt(w['hours'])} 小时；"
          f"start {len(w['starts'])} 条，中断 {len(w['interruptions'])} 次合计 {fmt(w['interruption_minutes_total'])} 分钟\n")
    n = res["n"]
    print("### 分母\n")
    _table(["项", "数"], [(k, fmt(v)) for k, v in n.items()])
    c = res["nodes"]
    print("### 节点构成\n")
    _table(["协议", "见过", "可探测", "链接要求跳过校验（有照链接分组）"],
           [(k, v["见过"], v["可探测"], v["链接要求跳过校验（有照链接分组）"]) for k, v in c["by_scheme"].items()])
    print("sing-box 不支持的原因（node.why）：\n")
    _table(["why", "节点"], [(k, v) for k, v in c["unsupported_by_why"].items()] or [("（无）", 0)])
    a = res["availability"]["all"]
    print("### 可用性（全部节点）\n")
    _table(["指标", "占见过", "占可探测", "占探测过"],
           [(k, rfmt(a[k]["占见过"]), rfmt(a[k]["占可探测"]), rfmt(a[k]["占探测过"])) for k in ("节点可用（严格）", "只有照链接才可用", "曾经可用（任一分组）")])
    print(f"- 节点可用（照链接，任一轮）：占探测过 {rfmt(a['节点可用（照链接，任一轮）']['占探测过'])}")
    print(f"- 严格校验损失（只有照链接才可用 / 曾经可用）：{rfmt(a['严格校验损失（只有照链接才可用 / 曾经可用）'])}；"
          f"相对（/ 严格可用）：{rfmt(a['严格校验损失（相对：只有照链接才可用 / 严格可用）'])}")
    le = res["availability"]["listed_at_end"]
    print(f"- 结束时在榜且可探测 {le['den_结束时在榜且可探测']}：最近一次探访严格可用 {rfmt(le['最近一次探访严格可用'])}，仅照链接 {rfmt(le['最近一次探访仅照链接可用'])}，"
          f"不可用 {rfmt(le['最近一次探访不可用'])}，从未探测 {rfmt(le['窗口内从未探测'])}（最后一轮 nround listed {le['最后一轮 nround']['listed']}、supported {le['最后一轮 nround']['supported']}）")
    npb = res["availability"]["supported_never_probed"]
    print(f"- 可探测但从未探测过 {npb['total']}：{npb['by_reason']}")
    lk = res["availability"]["linked_arm_nodes"]
    print(f"- 链接要求跳过校验的节点 {lk['见过']} 个，探测过 {lk['探测过']}：严格可用 {rfmt(lk['严格可用'])}，只有照链接才可用 {rfmt(lk['只有照链接才可用'])}，两者都不行 {rfmt(lk['两者都不行'])}")
    last = a["最近一次探测的结果"]
    print(f"- 最近一次探测：严格可用 {last['严格可用']}，仅照链接可用 {last['仅照链接可用']}，不可用 {last['不可用']}（探测过 {last['den_探测过']}）\n")
    print("按协议：\n")
    _table(["协议", "见过", "可探测", "探测过", "严格可用", "只有照链接才可用", "严格校验损失"],
           [(k, v["见过"], v["可探测"], v["探测过"], rfmt(v["节点可用（严格）"]["占探测过"]), rfmt(v["只有照链接才可用"]["占探测过"]),
             rfmt(v["严格校验损失（只有照链接才可用 / 曾经可用）"])) for k, v in res["availability"]["by_scheme"].items()])
    print("按订阅来源：\n")
    _table(["订阅", "见过", "可探测", "探测过", "严格可用", "只有照链接才可用"],
           [(k, v["见过"], v["可探测"], v["探测过"], rfmt(v["节点可用（严格）"]["占探测过"]), rfmt(v["只有照链接才可用"]["占探测过"]))
            for k, v in res["availability"]["by_source"].items()])
    p = res["precheck"]
    print("### 预检\n")
    _table(["类别", "按记录", "按节点最近一次"],
           [(zh, rfmt(p["按预检记录"][zh]), rfmt(p["按节点最近一次预检（summary.go lastPre）"][zh])) for zh, _ in PRECHECK_CATEGORIES])
    print(f"- TCP 预检连得上（发起了连接的记录）：{rfmt(p['TCP 预检连得上（分母只算发起了连接的记录）'])}\n")
    r = res["rounds"]
    print(f"### 轮次（{r['count']} 轮，{r['runs']} 次启动；与 att 不一致的轮次 {r['att_mismatch_rounds']}；轮间隔中位数 {fmt(r['interval_minutes']['p50'])} 分钟，最长 {fmt(r['interval_minutes']['max'])}）\n")
    _table(["run", "轮", "起点(UTC)", "在榜", "可探测", "退避", "预检通过", "已探测", "严格可用", "仅照链接", "配置被拒", "分钟", "att 已探测/严格/照链接"],
           [(x["run"], x["round"], x["start_utc"], x["listed"], x["supported"], x["backoff"], x["tcp_ok"], x["probed"], x["ok_strict"], x["ok_linked"],
             x["bad_config"], x["minutes"], f"{x['att_probed']}/{x['att_ok_strict']}/{x['att_ok_linked']}") for x in r["sequence"]])
    e = res["egress"]
    inv = e["invariant"]
    print("### 出口\n")
    print(f"- NAT 指标（judge_remote:control:public 是否全部等于 start.judge_ip）：{e['nat_indicator']['一致']}")
    print(f"- 不变量“出口不能是本机”（本机地址取 self_ips 全部来源）：{inv['verdict']}；回显等于本机 {inv['att.ip（回显）等于本机']['num']}/{inv['att.ip（回显）等于本机']['den']}，"
          f"judge 看到的 remote 等于本机 {inv['judge 看到的 remote 等于本机（judge 收到的全部节点请求）']['num']}/{inv['judge 看到的 remote 等于本机（judge 收到的全部节点请求）']['den']}")
    ve = e["vs_entry"]["judge_tls"]
    print(f"- 出口与入口（judge_tls，按尝试）：{ve['按尝试']}；按节点：{ve['按节点（一个节点可属多类）']}")
    print(f"- 回显 vs 日志一致：{rfmt(e['echo_vs_log']['回显等于 judge 日志的 remote'])}；观察者一致：{rfmt(e['observers_consistent']['同一探访里 judge 与观察者看到的出口全部相同'])}")
    print(f"- judge 没收到：{e['judge_not_seen'].get('num')}/{e['judge_not_seen'].get('den')}；重放：{rfmt(e['replay']['同一 nonce 被 judge 收到不止一次'])}\n")
    s = res["subscriptions"]
    print("### 订阅快照\n")
    _table(["订阅", "抓取", "失败", "未变化（304）", "未变化（200）", "有变化", "真正上榜", "真正下榜", "当前节点数", "曾在榜", "结束时在榜"],
           [(k, v["抓取"], rfmt(v["失败"]), v["未变化（304）"], v["未变化（200 且内容相同）"], v["有变化（含首次）"], v["真正的上榜（base=0 的 add）"], v["真正的下榜（base=0 的 del）"],
             v["当前节点数（最近一次有变化的 n）"], v["曾在榜的节点（去重）"], v["结束时在榜的节点"]) for k, v in s["by_source"].items()])
    ne = res["nerr"]
    print(f"### sing-box 报的错误：{ne.get('records', 0)} 条，按分类 {ne.get('by_category')}\n")
    if "crosscheck" in res:
        c = res["crosscheck"]
        print(f"### 与 summary.json 交叉核对：{c['matched']}/{c['total']} 项一致" + (f"，不一致：{', '.join(c['mismatches'])}" if c["mismatches"] else ""))


# ---------------------------------------------------------------- 主流程

def run(db_path, out_dir, summary_path=None, formal_start="auto", markdown=False, write=True):
    db = DB(db_path)
    wl_source = check_whitelist(db)
    for t in ("att", "node", "npre", "nround"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表" % t)
    for t in ("node_event", "nsnap", "nerr", "npre_ip", "req", "self_ips"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表（本模块需要它做连接；入库脚本应已建好）" % t)
    win = observation_window(db, formal_start)
    fs, end, runs_ = win.pop("_fs"), win.pop("_end"), win.pop("_runs")
    if fs is None or end is None:
        raise SystemExit("库里没有任何节点记录，算不出节点指标")
    win_info = build_tables(db, fs, runs_)
    _OBS_NAMES.clear()

    res = {
        "module": "m_nodes", "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol_version": PROTOCOL_VERSION, "whitelist_source": wl_source,
        "db_meta": {k: db.meta(k) for k in ("ingest_version", "first_ts", "last_ts")},
        "definitions": DEFINITIONS, "window": win,
    }
    res["n"] = denominators(db, fs)
    res["nodes"] = composition(db)
    res["availability"] = availability(db)
    res["precheck"] = precheck(db)
    res["rounds"] = rounds(db)
    res["egress"] = egress(db, win_info)
    res["nerr"] = nerr_block(db, fs)
    res["subscriptions"] = subscriptions(db, fs)
    res["checks"] = checks(db, fs)
    if _OBS_NAMES:
        res["notes"] = ["观察者名含点号或冒号，已换成序号：%d 个" % len(_OBS_NAMES)]
    if summary_path:
        res["crosscheck"] = crosscheck_summary(db, summary_path)

    text = json.dumps(res, ensure_ascii=False, indent=1, sort_keys=False)
    assert_clean(text, db)
    if write:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "nodes.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("已写出 %s（%d 字节）" % (path, len(text.encode("utf-8"))), file=sys.stderr)
    if markdown:
        print_markdown(res)
    return res


# ---------------------------------------------------------------- 自检：合成库

def _synthetic_db(path):
    """最小合成库，只建本模块用到的列。场景写在各行注释里；预期值在 selftest() 里断言。
    地址一律用文档保留段（TEST-NET），节点主机名用 .example。"""
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE node (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, src TEXT, id TEXT, scheme TEXT, host TEXT, port INTEGER,
                       method TEXT, aid INTEGER, flow TEXT, net TEXT, hdr TEXT, sec TEXT, sni TEXT, insecure INTEGER, plugin TEXT, why TEXT, raw TEXT);
    CREATE TABLE nsnap (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, src TEXT, status INTEGER, err TEXT, sha256 TEXT, bytes INTEGER,
                        lines INTEGER, unparsed INTEGER, n INTEGER, base INTEGER, changed INTEGER, "add" TEXT, del TEXT, ms INTEGER, n_add INTEGER, n_del INTEGER, raw TEXT);
    CREATE TABLE node_event (rid INTEGER PRIMARY KEY, nsnap_rid INTEGER, ts TEXT, ts_epoch REAL, src TEXT, node TEXT, event TEXT, base INTEGER);
    CREATE TABLE npre (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, round INTEGER, node TEXT, dns_ok INTEGER, dns_ms INTEGER, dns_class TEXT,
                       ips TEXT, tcp_ok INTEGER, tcp_ms INTEGER, tcp_class TEXT, class TEXT, n_ips INTEGER, raw TEXT);
    CREATE TABLE npre_ip (rid INTEGER PRIMARY KEY, npre_rid INTEGER, node TEXT, round INTEGER, seq INTEGER, ip TEXT);
    CREATE TABLE nerr (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, round INTEGER, node TEXT, arm TEXT, msg TEXT, raw TEXT);
    CREATE TABLE nround (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, round INTEGER, known INTEGER, listed INTEGER, supported INTEGER,
                         backoff INTEGER, tcp_ok INTEGER, probed INTEGER, ok_strict INTEGER, ok_linked INTEGER, bad_config INTEGER, batches INTEGER, ms INTEGER, err TEXT, raw TEXT);
    CREATE TABLE att (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, kind TEXT, arm TEXT, nonce TEXT,
                      class TEXT, ip TEXT, ms INTEGER, cand_kind TEXT, raw TEXT);
    CREATE INDEX att_pdc ON att(proto, dst, class);
    CREATE TABLE req (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, remote TEXT, nonce TEXT, raw TEXT);
    CREATE INDEX req_nonce ON req(nonce);
    CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
    CREATE TABLE start (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER, raw TEXT);
    CREATE TABLE stop (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, visits INTEGER, raw TEXT);
    CREATE TABLE version (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, version TEXT, raw TEXT);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    """)
    T0 = dt.datetime(2026, 11, 6, 0, 0, tzinfo=dt.timezone.utc).timestamp()

    def e(minutes):
        return T0 + minutes * 60.0

    def iso(minutes):
        return dt.datetime.fromtimestamp(e(minutes), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    SELF = "203.0.113.9"
    N = {i: "a0000000000%x" % i for i in range(1, 11)}  # 12 位十六进制的节点标识
    ENTRY = {1: "198.51.100.1", 3: "198.51.100.3", 4: "198.51.100.4", 5: "198.51.100.5"}
    con.execute("INSERT INTO self_ips VALUES (?, 'start.judge_ip', 2)", (SELF,))
    con.execute("INSERT INTO self_names VALUES ('judge.example', 'start.judge_host', 2)")
    con.execute("INSERT INTO meta VALUES ('ingest_version', 'synthetic')")
    # 两次启动：T0 首次（状态空），T0+2h 停止，T0+2h05 再启动（恢复 50 个候选）
    con.execute("INSERT INTO start VALUES (1, 1, ?, ?, 0, '{}')", (iso(0), e(0)))
    con.execute("INSERT INTO version VALUES (1, 1, ?, ?, 'dev', '{}')", (iso(0), e(0)))
    con.execute("INSERT INTO stop VALUES (1, 1, ?, ?, 100, '{}')", (iso(120), e(120)))
    con.execute("INSERT INTO start VALUES (2, 2, ?, ?, 50, '{}')", (iso(125), e(125)))
    con.execute("INSERT INTO version VALUES (2, 2, ?, ?, 'dev', '{}')", (iso(125), e(125)))

    # 节点：N1 ss 严格可用；N2 vmess xhttp 不支持；N3 vless 严格可用（两个订阅都有）；N4 trojan insecure 只有照链接可用（两个订阅）；
    # N5 trojan insecure 两者都不行、后来下榜；N6 vless reality 预检 TCP 失败；N7 vmess 主机名解析失败；N8 ss 私网地址；N9 vless IPv6 / 取消；
    # N10 只在 att 里出现（没有 node 记录，协议 "?"，没有预检 → 入口地址未知）
    spec = {1: ("ss", "198.51.100.1", "aes-256-gcm", None, None, None, None), 2: ("vmess", "n2.example", None, "xhttp", "none", None, "transport_xhttp"),
            3: ("vless", "n3.example", None, "tcp", "none", None, None), 4: ("trojan", "n4.example", None, "tcp", "tls", 1, None),
            5: ("trojan", "n5.example", None, "tcp", "tls", 1, None), 6: ("vless", "n6.example", None, "tcp", "reality", None, None),
            7: ("vmess", "n7.example", None, "ws", "tls", None, None), 8: ("ss", "10.0.0.8", "chacha20-ietf-poly1305", None, None, None, None),
            9: ("vless", "n9.example", None, "grpc", "tls", None, None)}
    rid = [0]

    def node_row(t, src, i):
        rid[0] += 1
        sch, host, method, net, sec, ins, why = spec[i]
        con.execute("INSERT INTO node (rid, file_id, ts, ts_epoch, src, id, scheme, host, port, method, net, sec, insecure, why, raw) VALUES (?,1,?,?,?,?,?,?,443,?,?,?,?,?,'{}')",
                    (rid[0], iso(t), e(t), src, N[i], sch, host, method, net, sec, ins, why))
    for i in (1, 2, 3, 4, 5, 9):
        node_row(0.05, "syn/subA", i)
    for i in (6, 8):
        node_row(0.1, "syn/subB", i)
    node_row(60, "syn/subA", 7)
    for i in (1, 2, 3, 4, 7, 9):
        node_row(125.1, "syn/subA", i)
    for i in (6, 8):
        node_row(125.2, "syn/subB", i)

    # 订阅快照
    srid = [0]

    def nsnap_row(t, src, status, err=None, n=None, base=None, changed=None, add=(), dele=(), lines=None, unparsed=None):
        srid[0] += 1
        con.execute("INSERT INTO nsnap (rid, file_id, ts, ts_epoch, src, status, err, bytes, lines, unparsed, n, base, changed, ms, n_add, n_del, raw) VALUES (?,1,?,?,?,?,?,100,?,?,?,?,?,5,?,?,'{}')",
                    (srid[0], iso(t), e(t), src, status, err, lines, unparsed, n, base, changed, len(add), len(dele)))
        for i in add:
            con.execute("INSERT INTO node_event (nsnap_rid, ts, ts_epoch, src, node, event, base) VALUES (?,?,?,?,?,'add',?)", (srid[0], iso(t), e(t), src, N[i], base))
        for i in dele:
            con.execute("INSERT INTO node_event (nsnap_rid, ts, ts_epoch, src, node, event, base) VALUES (?,?,?,?,?,'del',?)", (srid[0], iso(t), e(t), src, N[i], base))
    nsnap_row(0, "syn/subA", 200, n=6, base=1, changed=1, add=(1, 2, 3, 4, 5, 9), lines=7, unparsed=1)
    nsnap_row(0.1, "syn/subB", 200, n=4, base=1, changed=1, add=(3, 4, 6, 8), lines=4)
    nsnap_row(30, "syn/subA", 304)                                   # 没变
    nsnap_row(30.1, "syn/subB", 500, err="boom")                     # 失败
    nsnap_row(60, "syn/subA", 200, n=6, changed=1, add=(7,), dele=(5,), lines=7)   # 真正的上榜 N7、下榜 N5
    nsnap_row(125.1, "syn/subA", 200, n=6, base=1, changed=1, add=(1, 2, 3, 4, 7, 9), lines=6)
    nsnap_row(125.2, "syn/subB", 200, n=4, base=1, changed=1, add=(3, 4, 6, 8), lines=4)

    # 预检
    prid = [0]

    def pre(t, rnd, i, cls, dns=None, tcp=None, tcp_ms=None, tcp_class=None, ips=()):
        prid[0] += 1
        con.execute("INSERT INTO npre (rid, file_id, ts, ts_epoch, round, node, dns_ok, dns_class, tcp_ok, tcp_ms, tcp_class, class, n_ips, raw) VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?,'{}')",
                    (prid[0], iso(t), e(t), rnd, N[i], dns, (cls if cls.startswith("dns_") else None), tcp, tcp_ms, tcp_class, cls, len(ips)))
        for k, ip in enumerate(ips):
            con.execute("INSERT INTO npre_ip (npre_rid, node, round, seq, ip) VALUES (?,?,?,?,?)", (prid[0], N[i], rnd, k, ip))
    # run1 第 1 轮
    pre(1.1, 1, 1, "ok", tcp=1, tcp_ms=20, ips=(ENTRY[1],))
    pre(1.1, 1, 3, "ok", dns=1, tcp=1, tcp_ms=30, ips=(ENTRY[3],))
    pre(1.1, 1, 4, "ok", dns=1, tcp=1, tcp_ms=40, ips=(ENTRY[4],))
    pre(1.1, 1, 5, "ok", dns=1, tcp=1, tcp_ms=50, ips=(ENTRY[5],))
    pre(1.1, 1, 6, "tcp_timeout", dns=1, tcp=0, tcp_ms=5000, tcp_class="tcp_timeout", ips=("198.51.100.6",))
    pre(1.1, 1, 8, "skip_not_public", ips=("10.0.0.8",))
    pre(1.1, 1, 9, "skip_ipv6", dns=1)
    # run1 第 2 轮（N5、N6、N8、N9 退避）
    pre(61.1, 2, 1, "ok", tcp=1, tcp_ms=22, ips=(ENTRY[1],))
    pre(61.1, 2, 3, "ok", dns=1, tcp=1, tcp_ms=33, ips=(ENTRY[3],))
    pre(61.1, 2, 4, "ok", dns=1, tcp=1, tcp_ms=44, ips=(ENTRY[4],))
    pre(61.1, 2, 7, "dns_nxdomain", dns=0)
    # run2 第 1 轮
    pre(126.1, 1, 1, "ok", tcp=1, tcp_ms=21, ips=(ENTRY[1],))
    pre(126.1, 1, 3, "ok", dns=1, tcp=1, tcp_ms=31, ips=(ENTRY[3],))
    pre(126.1, 1, 4, "ok", dns=1, tcp=1, tcp_ms=41, ips=(ENTRY[4],))
    pre(126.1, 1, 6, "tcp_refused", dns=1, tcp=0, tcp_ms=10, tcp_class="tcp_refused", ips=("198.51.100.6",))
    pre(126.1, 1, 7, "dns_timeout", dns=0)
    pre(126.1, 1, 8, "skip_not_public", ips=("10.0.0.8",))
    pre(126.1, 1, 9, "canceled", dns=1)

    # 轮次小结（probed / ok_* 与下面的 att 一致）
    def rnd(t, r, known, listed, sup, backoff, tcp_ok, probed, oks, okl, ms, bad=0, err=None):
        con.execute("INSERT INTO nround (file_id, ts, ts_epoch, round, known, listed, supported, backoff, tcp_ok, probed, ok_strict, ok_linked, bad_config, batches, ms, err, raw) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,'{}')",
                    (iso(t), e(t), r, known, listed, sup, backoff, tcp_ok, probed, oks, okl, bad, ms, err))
    rnd(1, 1, 8, 8, 7, 0, 4, 4, 2, 1, 60000)
    rnd(61, 2, 9, 8, 7, 4, 3, 4, 3, 1, 30000, bad=1)
    rnd(126, 1, 8, 8, 7, 0, 3, 3, 1, 0, 30000, err="x")

    # 节点尝试 + judge 日志
    reqs = []

    def att(t, visit, i, arm, dst, cls, nonce=None, ip=None, remote=None, copies=1, kind="h", ms=50):
        con.execute("INSERT INTO att (file_id, ts, ts_epoch, visit, cand, proto, dst, kind, arm, nonce, class, ip, ms, cand_kind, raw) VALUES (1,?,?,?,?,'node',?,?,?,?,?,?,?,'node','{}')",
                    (iso(t), e(t), visit, N[i], dst, kind, arm, nonce, cls, ip, ms))
        if remote is not None and nonce is not None:
            for c in range(copies):
                reqs.append((t + 0.001 * (c + 1), nonce, remote))
    # run1 第 1 轮（窗口 [1, 2] 分钟）
    att(1.5, "v1-1-n1", 1, "strict", "judge_tls", "ok", "n1a", ENTRY[1], ENTRY[1])             # 与入口相同
    att(1.5, "v1-1-n1", 1, "strict", "obs:kv", "ok", ip=ENTRY[1], kind=None)
    att(1.5, "v1-1-n1", 1, "strict", "obs:plain", "ok", ip=ENTRY[1], kind=None)
    att(1.5, "v1-1-n1", 1, "strict", "judge_http", "ok", "n1h", ENTRY[1], ENTRY[1])
    att(1.5, "v1-1-n3", 3, "strict", "judge_tls", "ok", "n3a", "192.0.2.33", "192.0.2.33")       # 与入口不同
    att(1.5, "v1-1-n3", 3, "strict", "obs:kv", "ok", ip="192.0.2.33", kind=None)
    att(1.5, "v1-1-n3", 3, "strict", "obs:plain", "ok", ip="192.0.2.34", kind=None)             # 观察者不一致
    att(1.5, "v1-1-n3", 3, "strict", "judge_http", "ok", "n3h", "192.0.2.33", "192.0.2.33")
    att(1.5, "v1-1-n4", 4, "strict", "judge_tls", "tls_eof")
    att(1.6, "v1-1-n4", 4, "as_linked", "judge_tls", "ok", "n4a", ENTRY[4], ENTRY[4], copies=2)  # 重放：judge 收到两份
    att(1.5, "v1-1-n5", 5, "strict", "judge_tls", "hs_refused")
    att(1.6, "v1-1-n5", 5, "as_linked", "judge_tls", "tls_eof")
    # run1 第 2 轮（窗口 [61, 61.5]）
    att(61.3, "v1-2-n1", 1, "strict", "judge_tls", "ok", "n1b", ENTRY[1], ENTRY[1])
    att(61.3, "v1-2-n3", 3, "strict", "judge_tls", "ok", "n3b", SELF, SELF)                     # 不变量违反：出口是本机（回显和日志都是）
    att(61.3, "v1-2-n4", 4, "strict", "judge_tls", "tls_eof")
    att(61.4, "v1-2-n4", 4, "as_linked", "judge_tls", "ok", "n4b", ENTRY[4], ENTRY[4])
    att(61.3, "v1-2-n10", 10, "strict", "judge_tls", "ok", "n10", "192.0.2.10", "192.0.2.10")   # 没有预检记录 → 入口地址未知
    # run2 第 1 轮（窗口 [126, 126.5]）
    att(126.3, "v2-1-n1", 1, "strict", "judge_tls", "ok", "n1c", ENTRY[1], ENTRY[1])
    att(126.3, "v2-1-n1", 1, "strict", "judge_http", "ok", "n1h2", ENTRY[1])                    # judge 没收到
    att(126.3, "v2-1-n3", 3, "strict", "judge_tls", "tls_timeout")
    att(126.3, "v2-1-n3", 3, "strict", "judge_tls", "canceled")                                 # 应被排除
    att(126.3, "v2-1-n4", 4, "strict", "judge_tls", "tls_eof")
    att(126.4, "v2-1-n4", 4, "as_linked", "judge_tls", "tls_eof")
    for k, (t, nonce, remote) in enumerate(reqs, 1):
        con.execute("INSERT INTO req (rid, file_id, ts, ts_epoch, remote, nonce, raw) VALUES (?,1,?,?,?,?,'{}')", (k, iso(t), e(t), remote, nonce))
    con.execute("INSERT INTO req (file_id, ts, ts_epoch, remote, nonce, raw) VALUES (1,?,?,?,'zz','{}')", (iso(127), e(127), "192.0.2.99"))  # judge 最后一条

    # sing-box 报的错误
    for t, r, i, arm, msg in ((1.9, 1, 4, "strict", "tls: failed to verify certificate: x509: certificate signed by unknown authority"),
                              (1.9, 1, 5, "strict", "tls: failed to verify certificate: x509: certificate signed by unknown authority"),
                              (1.9, 1, 5, "as_linked", "dial tcp 198.51.100.5:443: i/o timeout"),
                              (61.4, 2, 4, "strict", "tls: failed to verify certificate: x509: certificate signed by unknown authority"),
                              (126.4, 1, 4, "strict", "config: parse outbound[n%s]: bad option" % N[4])):
        con.execute("INSERT INTO nerr (file_id, ts, ts_epoch, round, node, arm, msg, raw) VALUES (1,?,?,?,?,?,?,'{}')", (iso(t), e(t), r, N[i], arm, msg))
    con.commit()
    con.close()


def selftest():
    tmp = tempfile.mkdtemp(prefix="m_nodes_selftest_")
    db_path = os.path.join(tmp, "synthetic.sqlite")
    _synthetic_db(db_path)
    summ = os.path.join(tmp, "summary.json")
    with open(summ, "w", encoding="utf-8") as fh:
        json.dump({"generated": "x",
                   "records": {"node": 17, "npre": 18, "nround": 3, "nerr": 5, "nsnap": 7},
                   "nodes": {"known": 9, "by_scheme": {"ss": 2, "vmess": 2, "vless": 3, "trojan": 2}, "unsupported": {"transport_xhttp": 1},
                             "precheck": {"ok": 4, "tcp_refused": 1, "dns_timeout": 1, "skip_not_public": 1, "canceled": 1},
                             "rounds": [{"ts": "2026-11-06T02:06:00.000Z", "round": 1, "known": 8, "listed": 8, "supported": 7, "backoff": 0, "tcp_ok": 3,
                                         "probed": 3, "ok_strict": 1, "ok_linked": 0, "bad_config": 0, "batches": 1, "ms": 30000}],
                             "ok": {"ss": {"strict": 1}, "vless": {"strict": 1}, "trojan": {"as_linked_only": 1}, "?": {"strict": 1}},
                             "classes": {"strict ok": 6, "strict tls_eof": 3, "strict hs_refused": 1, "strict tls_timeout": 1, "as_linked ok": 2, "as_linked tls_eof": 2},
                             "errors": {"e1": 4, "e2": 1},
                             "egress": {"与入口相同": 5, "与入口不同": 1, "入口地址未知": 1},
                             "subscriptions": [{"src": "syn/subA", "fetches": 4, "failed": 0, "changed": 3, "current": 6, "last_status": 200},
                                               {"src": "syn/subB", "fetches": 3, "failed": 1, "changed": 2, "current": 4, "last_status": 200}]}}, fh)
    res = run(db_path, os.path.join(tmp, "out"), summary_path=summ, markdown=False, write=True)
    failures = []
    n_asserts = [0]

    def expect(name, got, want):
        n_asserts[0] += 1
        if got != want:
            failures.append("%s: 得到 %r，期望 %r" % (name, got, want))

    w = res["window"]
    expect("正式起点", w["formal_start_utc"], "2026-11-06T00:00Z")
    expect("启动次数", w["runs_in_window"], 2)
    expect("中断", [i["minutes"] for i in w["interruptions"]], [5.0])
    n = res["n"]
    expect("见过的节点", n["见过的节点（去重）"], 10)
    expect("没有 node 记录", n["其中没有 node 记录（只在 npre/att/快照里出现）"], 1)
    expect("可探测", n["可探测（why 为空）"], 9)
    expect("不支持", n["sing-box 不支持（why 非空）"], 1)
    expect("照链接分组的节点", n["链接要求跳过证书校验（insecure 且 sec=tls，有照链接分组）"], 2)
    expect("探测过", n["探测过（至少一次 judge_tls 隧道探测）"], 5)
    expect("预检记录", n["预检记录（npre 行）"], 18)
    expect("canceled 已排除", n["canceled 的节点尝试（已排除）"], 1)
    c = res["nodes"]
    expect("协议", {k: v["见过"] for k, v in c["by_scheme"].items()}, {"vless": 3, "ss": 2, "vmess": 2, "trojan": 2, "?": 1})
    expect("不支持原因", c["unsupported_by_why"], {"transport_xhttp": 1})
    expect("去重 node 行", c["去重"]["node 记录行数"], 17)
    expect("去重 id", c["去重"]["node 表去重后的 id 数（summary.go nodeSch 口径，不裁窗口）"], 9)
    expect("多订阅节点", c["去重"]["出现在多个订阅里的节点"], 2)
    expect("无订阅节点", c["去重"]["没有任何订阅记录的节点"], 1)
    expect("成员对", c["去重"]["订阅成员对（节点 × 订阅）"], 11)
    a = res["availability"]["all"]
    expect("严格可用", a["节点可用（严格）"]["占探测过"], {"num": 3, "den": 5, "pct": 60.0})
    expect("严格可用占见过", a["节点可用（严格）"]["占见过"], {"num": 3, "den": 10, "pct": 30.0})
    expect("只有照链接", a["只有照链接才可用"]["占探测过"], {"num": 1, "den": 5, "pct": 20.0})
    expect("曾经可用", a["曾经可用（任一分组）"]["占探测过"]["num"], 4)
    expect("从未可用", a["探测过但从未可用"], {"num": 1, "den": 5, "pct": 20.0})
    expect("严格校验损失", a["严格校验损失（只有照链接才可用 / 曾经可用）"], {"num": 1, "den": 4, "pct": 25.0})
    expect("最近一次", (a["最近一次探测的结果"]["严格可用"], a["最近一次探测的结果"]["仅照链接可用"], a["最近一次探测的结果"]["不可用"]), (2, 0, 3))
    lk = res["availability"]["linked_arm_nodes"]
    expect("照链接组 严格", lk["严格可用"]["num"], 0)
    expect("照链接组 仅照链接", lk["只有照链接才可用"], {"num": 1, "den": 2, "pct": 50.0})
    expect("照链接组 都不行", lk["两者都不行"]["num"], 1)
    bs = res["availability"]["by_scheme"]
    expect("trojan 只有照链接", bs["trojan"]["只有照链接才可用"]["占探测过"], {"num": 1, "den": 2, "pct": 50.0})
    expect("? 严格", bs["?"]["节点可用（严格）"]["占探测过"]["num"], 1)
    src = res["availability"]["by_source"]
    expect("subA 见过/可探测/探测过", (src["syn/subA"]["见过"], src["syn/subA"]["可探测"], src["syn/subA"]["探测过"]), (7, 6, 4))
    expect("subA 严格", src["syn/subA"]["节点可用（严格）"]["占探测过"]["num"], 2)
    expect("subB", (src["syn/subB"]["见过"], src["syn/subB"]["探测过"], src["syn/subB"]["节点可用（严格）"]["占探测过"]["num"], src["syn/subB"]["只有照链接才可用"]["占探测过"]["num"]), (4, 2, 1, 1))
    expect("隧道类别", res["availability"]["tunnel_classes"]["strict"]["judge_tls"], {"ok": 6, "tls_eof": 3, "hs_refused": 1, "tls_timeout": 1})
    p = res["precheck"]
    expect("预检按记录", {k: p["按预检记录"][k]["num"] for k, _ in PRECHECK_CATEGORIES}, {"通过": 10, "DNS 失败": 2, "IPv6": 1, "非公网": 2, "TCP 失败": 2, "取消": 1, "其他": 0})
    expect("预检按节点最近一次", {k: p["按节点最近一次预检（summary.go lastPre）"][k]["num"] for k, _ in PRECHECK_CATEGORIES},
           {"通过": 4, "DNS 失败": 1, "IPv6": 0, "非公网": 1, "TCP 失败": 1, "取消": 1, "其他": 0})
    expect("TCP 预检", p["TCP 预检连得上（分母只算发起了连接的记录）"], {"num": 10, "den": 12, "pct": 83.3})
    expect("主机是 IP", p["按节点（曾经）"]["主机写的是 IP（没有 DNS 步骤）"]["num"], 2)
    expect("探测过没预检", p["探测过却没有任何预检记录的节点（应为 0）"]["num"], 1)
    r = res["rounds"]
    expect("轮次数", r["count"], 3)
    expect("轮次 run", [x["run"] for x in r["sequence"]], [1, 1, 2])
    expect("轮次 att 不一致", r["att_mismatch_rounds"], 0)
    expect("轮次 att probed", [x["att_probed"] for x in r["sequence"]], [4, 4, 3])
    expect("轮次 npre 行", [x["npre_rows"] for x in r["sequence"]], [7, 4, 7])
    expect("轮间隔", (r["interval_minutes"]["n"], r["interval_minutes"]["p50"]), (1, 60.0))
    expect("轮次出错", r["rounds_with_err"], 1)
    expect("配置被拒累计", r["bad_config_total"], 1)
    expect("窗口外 att", r["att_outside_any_round"], 0)
    eg = res["egress"]
    inv = eg["invariant"]
    expect("回显等于本机", (inv["att.ip（回显）等于本机"]["num"], inv["att.ip（回显）等于本机"]["den"]), (1, 15))  # 带回显的尝试：run1 9 + 4，run2 2
    expect("日志等于本机", inv["judge 看到的 remote 等于本机（class=ok、dst=judge_tls）"], {"num": 1, "den": 8, "nodes": 1})
    expect("不变量结论", inv["verdict"].startswith("违反"), True)
    expect("出口与入口", eg["vs_entry"]["judge_tls"]["按尝试"], {"与入口相同": 5, "与入口不同": 1, "入口地址未知": 1})
    expect("出口与入口按节点", eg["vs_entry"]["judge_tls"]["按节点（一个节点可属多类）"], {"与入口相同": 2, "与入口不同": 1, "入口地址未知": 1})
    expect("回显 vs 日志", eg["echo_vs_log"]["回显等于 judge 日志的 remote"], {"num": 10, "den": 10, "pct": 100.0})
    expect("观察者一致", eg["observers_consistent"]["同一探访里 judge 与观察者看到的出口全部相同"], {"num": 1, "den": 2, "pct": 50.0})
    expect("judge 没收到", (eg["judge_not_seen"]["num"], eg["judge_not_seen"]["den"]), (1, 11))
    expect("重放", eg["replay"]["同一 nonce 被 judge 收到不止一次"], {"num": 1, "den": 10, "pct": 10.0})
    expect("出口稳定", eg["distinct_egress_per_node"]["按不同出口地址个数分节点"], {"1": 3, "2": 1})
    ne = res["nerr"]
    expect("nerr 条数", ne["records"], 5)
    expect("nerr 分类", ne["by_category"], {"config": 1, "cert_verify": 3, "timeout": 1, "refused": 0, "eof_reset": 0, "dns": 0, "other": 0})
    expect("nerr 按 arm", ne["by_arm"], {"as_linked": 1, "strict": 4})
    s = res["subscriptions"]
    sa, sb = s["by_source"]["syn/subA"], s["by_source"]["syn/subB"]
    expect("subA 抓取", (sa["抓取"], sa["失败"]["num"], sa["未变化（304）"], sa["有变化（含首次）"], sa["首次快照（base）"]), (4, 0, 1, 3, 2))
    expect("subA 上下榜", (sa["真正的上榜（base=0 的 add）"], sa["真正的下榜（base=0 的 del）"]), (1, 1))
    expect("subA 当前/曾在榜/结束时在榜", (sa["当前节点数（最近一次有变化的 n）"], sa["曾在榜的节点（去重）"], sa["结束时在榜的节点"]), (6, 7, 6))
    expect("subA 解析不了", sa["解析不了的行（累计）"], 1)
    expect("subB 失败", (sb["抓取"], sb["失败"]["num"], sb["失败时的状态码"]), (3, 1, {"500": 1}))
    expect("subB 当前/曾在榜/结束时在榜", (sb["当前节点数（最近一次有变化的 n）"], sb["曾在榜的节点（去重）"], sb["结束时在榜的节点"]), (4, 4, 4))
    expect("订阅合计", (s["total"]["抓取"], s["total"]["失败"]["num"], s["total"]["曾在榜的节点（全部订阅去重）"]), (7, 1, 9))
    expect("节点事件", s["node_events"], {"真正的上榜": 1, "下榜": 1, "首次快照里的条目（不是新上榜）": 20})
    ck = res["checks"]
    expect("核对 照链接组", ck["试过照链接分组却不是 insecure+tls 的（应为 0）"]["num"], 0)
    expect("核对 nround vs att", ck["nround 与 att 独立计数不一致的轮次"], 0)
    cc = res["crosscheck"]
    expect("交叉核对全部一致", cc["mismatches"], [])
    expect("交叉核对项数", cc["total"] >= 30, True)
    # 输出文件存在且干净
    with open(os.path.join(tmp, "out", "nodes.json"), encoding="utf-8") as fh:
        text = fh.read()
    expect("输出里没有 ip:port", bool(HOSTPORT_RE.search(text)), False)
    expect("输出里没有 IPv4", bool(IPV4_RE.search(text)), False)
    expect("输出里没有节点标识", bool(NODE_ID_RE.search(text)), False)
    expect("输出里没有节点主机名", ".example" in text, False)
    # ---- 核对意见补上的口径（主合成库）
    expect("照链接任一轮", a["节点可用（照链接，任一轮）"]["占探测过"], {"num": 1, "den": 5, "pct": 20.0})
    expect("相对损失", a["严格校验损失（相对：只有照链接才可用 / 严格可用）"], {"num": 1, "den": 3, "pct": 33.3})
    le = res["availability"]["listed_at_end"]
    expect("结束时在榜", (le["den_结束时在榜且可探测"], le["最近一次探访严格可用"]["num"], le["最近一次探访仅照链接可用"]["num"],
                       le["最近一次探访不可用"]["num"], le["窗口内从未探测"]["num"], le["结束时在榜（不限是否支持）"]), (7, 1, 0, 2, 4, 8))
    expect("可探测但从未探测过", res["availability"]["supported_never_probed"]["by_reason"],
           {"最近一次预检：DNS 失败": 1, "最近一次预检：TCP 失败": 1, "最近一次预检：取消": 1, "最近一次预检：非公网": 1})
    expect("可探测但从未探测过（分母表）", n["可探测但从未探测过"], 4)
    expect("订阅分解闭合", ck["订阅抓取分解闭合（抓取 = 失败 + 有变化 + 未变化 304 + 未变化 200）"]["闭合"], True)
    expect("没有订阅归属", ck["见过的节点里没有订阅归属的（应为 0）"]["num"], 1)  # N10 只在 att 里出现
    expect("NAT 指标（主库没有 public 来源）", eg["nat_indicator"]["一致"], None)
    expect("出口与入口（并集口径）", eg["vs_entry_union"]["judge_tls"]["按尝试"], {"与入口相同": 5, "与入口不同": 1, "入口地址未知": 1})
    expect("轮次 att_canceled", [x["att_canceled"] for x in r["sequence"]], [0, 0, 0])
    expect("轮耗时（分钟）", r["round_duration_minutes"]["max"], 1.0)

    # ---- 边界场景：复制合成库后改几处
    import shutil
    edge = os.path.join(tmp, "edge.sqlite")
    shutil.copy(db_path, edge)
    con = sqlite3.connect(edge)
    NAT = "203.0.113.77"
    con.execute("INSERT INTO self_ips VALUES (?, 'judge_remote:control:public', 1)", (NAT,))     # NAT：judge 看到的本机源地址不是 start.judge_ip
    con.execute("UPDATE att SET ip = ? WHERE nonce = 'n10'", (NAT,))                              # N10 的流量从本机（NAT 地址）出去
    con.execute("UPDATE req SET remote = ? WHERE nonce = 'n10'", (NAT,))
    con.execute("UPDATE npre_ip SET ip = '198.51.100.101' WHERE node = ? AND round = 2", ("a00000000001",))  # N1 第 2 轮解析到别的 IP
    con.execute("UPDATE nround SET probed = 4 WHERE rid = 3")                                     # 退出时 canceled 的节点也计入 probed
    con.execute("""INSERT INTO att (file_id, ts, ts_epoch, visit, cand, proto, dst, kind, arm, class, cand_kind, raw)
                   SELECT 1, ts, ts_epoch, 'v2-1-n6', 'a00000000006', 'node', 'judge_tls', 'h', 'strict', 'canceled', 'node', '{}' FROM att WHERE visit = 'v2-1-n1' LIMIT 1""")
    con.execute("UPDATE node SET insecure = 1, sec = NULL WHERE id = 'a00000000007'")              # vmess tls 字段为空：sec NULL
    con.execute("UPDATE node SET net = 'foo<bar>', why = 'transport_foo<bar>', host = 'node' WHERE id = 'a00000000002'")  # 自由文本 + 裸词主机名
    t_last = con.execute("SELECT MAX(ts_epoch) FROM nsnap").fetchone()[0]
    con.execute("INSERT INTO nsnap (file_id, ts, ts_epoch, src, status, bytes, ms, raw) VALUES (1, 'x', ?, 'syn/subA', 200, 100, 5, '{}')", (t_last + 1,))  # 200 未变化
    con.execute("INSERT INTO nsnap (file_id, ts, ts_epoch, src, status, bytes, changed, ms, raw) VALUES (1, 'x', ?, 'syn/subB', 200, 0, 1, 5, '{}')", (t_last + 2,))  # 有变化、n 为空
    con.commit()
    con.close()
    er = run(edge, os.path.join(tmp, "out_edge"), markdown=False, write=True)
    ei = er["egress"]["invariant"]
    expect("边界 NAT：回显等于本机（全部来源）", ei["att.ip（回显）等于本机"]["num"], 2)
    expect("边界 NAT：judge remote 等于本机（全部来源）", ei["judge 看到的 remote 等于本机（judge 收到的全部节点请求）"]["num"], 2)
    expect("边界 NAT：start.judge_ip 口径只看到 1", ei["只用 start.judge_ip（summary.go selfIPs 口径）"]["att.ip（回显）等于本机"]["num"], 1)
    expect("边界 NAT 指标", er["egress"]["nat_indicator"]["一致"], False)
    expect("边界 出口与入口（精确）", er["egress"]["vs_entry"]["judge_tls"]["按尝试"], {"与入口相同": 4, "与入口不同": 2})
    expect("边界 出口与入口（并集）", er["egress"]["vs_entry_union"]["judge_tls"]["按尝试"], {"与入口相同": 5, "与入口不同": 1})
    expect("边界 canceled 计入 probed", ([x["att_canceled"] for x in er["rounds"]["sequence"]], er["rounds"]["att_mismatch_rounds"]), ([0, 0, 1], 0))
    expect("边界 sec NULL 的 insecure", (er["n"]["链接要求跳过证书校验（insecure，不限 sec）"], er["n"]["链接要求跳过证书校验（insecure 且 sec=tls，有照链接分组）"]), (3, 2))
    expect("边界 why 归并", er["nodes"]["unsupported_by_why"], {"transport_other": 1})
    expect("边界 net 归并", er["nodes"]["by_net"].get("other"), 1)
    es = er["subscriptions"]["by_source"]
    expect("边界 200 未变化", es["syn/subA"]["未变化（200 且内容相同）"], 1)
    expect("边界 当前节点数 n 为空按 0", es["syn/subB"]["当前节点数（最近一次有变化的 n）"], 0)
    expect("边界 订阅分解闭合", er["checks"]["订阅抓取分解闭合（抓取 = 失败 + 有变化 + 未变化 304 + 未变化 200）"]["闭合"], True)
    # --formal-start 落在最后一次 base=1 快照之后：成员关系不能丢
    fr = run(db_path, os.path.join(tmp, "out_fs"), formal_start="2026-11-06T02:05:30Z", markdown=False, write=True)
    expect("formal-start 后 订阅归属", (fr["checks"]["见过的节点里没有订阅归属的（应为 0）"]["num"], sorted(fr["availability"]["by_source"])),
           (0, ["syn/subA", "syn/subB"]))
    expect("formal-start 后 结束时在榜", fr["subscriptions"]["listed_at_end_by_source"], {"syn/subA": 6, "syn/subB": 4})
    if failures:
        print("自检失败：\n  " + "\n  ".join(failures), file=sys.stderr)
        print("合成库与输出留在 %s" % tmp, file=sys.stderr)
        return 1
    print("自检通过（%d 项断言）。合成库与输出在 %s" % (n_asserts[0], tmp), file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="节点（PROTOCOL“节点可用（严格）”“节点可用（照链接）”与节点不变量）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 nodes.json")
    ap.add_argument("--summary", help="fieldtest 自带的 summary.json，给了就与其 nodes 节交叉核对")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--formal-start", default="auto", help="auto（按 PROTOCOL 规则）/ first（第一条 start）/ 带时区的 ISO 时间")
    ap.add_argument("--selftest", action="store_true", help="在临时目录里建合成库并核对预期值")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    run(args.db, args.out, summary_path=args.summary, formal_start=args.formal_start, markdown=args.markdown)


if __name__ == "__main__":
    main()
