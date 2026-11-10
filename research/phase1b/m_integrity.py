#!/usr/bin/env python3
"""内容与请求完整性（第一阶段 1B，PROTOCOL“指标定义”里的“内容被改”“请求被改、匿名程度”“重放”“出口地址”四项）。

用法：
    python3 m_integrity.py --db <sqlite> --out <目录> [--markdown] [--summary <summary.json>]
    python3 m_integrity.py --selftest

只读 ingest.py 建好的库（mode=ro，临时表都建在 TEMP 库里），结果写到 <目录>/integrity.json。
每个比例都给分子、分母和口径；百分比保留一位小数。输出前按 SCHEMA.md 的可输出列白名单检查用到的列，
写出前再对文本做一次“不许出现地址和 judge 身份”的断言（最后一道保险，不是放行手段）。

口径与官方汇总程序（internal/summary/summary.go、derive.go）的对应关系写在各函数的注释里；
PROTOCOL 没说清的地方，取的解释都在 DEFINITIONS 和注释里写明。

设计要点（真实数据有一千多万条 att、几百万条 judge 记录）：
- judge 侧先按 nonce 聚合成一行（rq_n：份数、地址数、首末时间、最大 age_s），再取最早到达的那份（rq_first），
  对它的请求头按 derive.go 的 Derive 规则算出“透明/匿名/高匿”和各项“请求被改”标记（rh → rd）。这些都是 GROUP BY，
  内存由 SQLite 页缓存主导。
- 探测器侧只取到达 HTTP 阶段、带 nonce、目的地是 judge 的尝试（aj，远少于全部 att），LEFT JOIN rd 做对账。
- 内容被改只看 att 自己的字段（pc），分类照 summary.go 的 BodyChange。
- 之后所有指标都是对 aj / pc / rd 的 SQL 聚合；“去掉候选密集的 /24”只是多一个过滤条件。
- 所有与 aj 按 nonce 关联的查询都靠 aj(nonce) 索引；运行结束时用 EXPLAIN QUERY PLAN 复查执行过的每条查询，
  相关子查询里对大表的顺序扫描（O(N²)）会被记进输出的 plan_audit，自检里断言为零。
"""
import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import tempfile

MODULE = "m_integrity"
DENSE_THRESHOLD = 100   # “候选超过 100 个的 /24”（PROTOCOL 1.2 版“候选密集的地址段”）
JUDGE_LAG_S = 10        # judge 每 2 秒落盘；最后 10 秒内的成功尝试不算“judge 没收到”（summary.go judgeHorizon）
FORMAL_HOURS = 72       # PROTOCOL“正式测量的起止”：从正式起点跑满 72 小时。主口径只裁下界，超出部分在 window 里单独报告
# 相关子查询里允许顺序扫描的小表（几行到几十行）；其余表在相关子查询里出现 SCAN 就是 O(N²)，计划自检会报出来
SMALL_TABLES = {"ips", "ips_self", "basefp", "plen"}
# 节点“本机出口”判等用的探测器地址来源（SCHEMA.md“judge 的身份从哪里取”）：配置里的公网 IP，加上本机回访自己公网地址时
# judge 实际看到的源地址和回显的地址——云主机做 NAT 时后两者才是 judge 眼里的“本机”
SELF_EGRESS_SOURCES = ("start.judge_ip", "judge_remote:control:public", "echo:control:public")

# derive.go sentHeaders：探测器自己发出的请求头（值来自 wire.BuildRequest）。Cookie 与 X-Probe-Canary 的值因请求而异，单独比较。
SENT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "close",
    "Cookie": "",
    "X-Probe-Canary": "",
}
# derive.go proxyHeaders：说明“我是代理”、但不一定暴露客户端地址的头。
PROXY_HEADERS = [
    "Via", "X-Forwarded-For", "Forwarded", "X-Real-Ip", "Proxy-Connection",
    "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "Client-Ip",
    "X-Client-Ip", "Forwarded-For", "X-Proxy-Id", "X-Bluecoat-Via",
    "Surrogate-Capability", "X-Cache", "X-Squid-Error", "Cdn-Loop",
    "Proxy-Authorization", "X-Proxy-Connection", "Xroxy-Connection", "X-Originating-Ip",
    "True-Client-Ip", "Cf-Connecting-Ip", "X-Cluster-Client-Ip",
]
# 注意：wire.BuildRequest 对 HTTP 转发（请求行写绝对 URI）会自己多发一个 Proxy-Connection: close。
# 它不在 sentHeaders 里却在 proxyHeaders 里，所以代理原样透传它时 Derive 会判成“匿名”并记为“代理加的头”。
# 这里照 derive.go 的规则算（与 summary.json 可比），另外单独数出“只因 Proxy-Connection 才算匿名”的请求数。

TAMPER_NAMES = ["canary_missing", "canary_changed", "cookie_missing", "cookie_changed",
                "user_agent_missing", "user_agent_changed", "accept_missing", "accept_changed",
                "accept_language_missing", "accept_language_changed", "accept_encoding_missing", "accept_encoding_changed",
                "method_changed"]
BODY_KINDS = ["正文被截断", "正文被局部改动（注入或改写）", "正文被整页替换"]
GZ_ALL = "代理加了 gzip 的尝试（gzip_added 标记）"
GZ_SAME = "解开后正文相同（不论金丝雀；PROTOCOL“不算内容被改，单独计数”）"
GZ_CANARY = "其中正文相同、金丝雀缺失或不符（已计入“正文正确但不是这次请求的应答”）"
GZ_MIS = "解开后仍不符（已计入正文不符）"
EXPECT_ALL = "全部协议（含 CONNECT 到 80 端口、SOCKS 隧道里的明文）"
EXPECT_FWD = "只算 HTTP 转发（proto=forward，与 Tsirantonakis 等的对象可比）"
ANON_LEVELS = ["transparent", "anonymous", "elite"]
ANON_ZH = {"transparent": "透明（带出探测器地址）", "anonymous": "匿名（只暴露代理身份）", "elite": "高匿"}

# 本模块在 SELECT 列表或 GROUP BY 里用到、并且会进入输出（作为维度或被聚合的值）的列。
# 只在库内做比较或连接、不进入输出的列（att.cand/cand_ip/nonce/ip、req.remote/target、req_header.value、self_ips.ip、npre_ip.ip）不在这里。
OUTPUT_COLUMNS = {
    "att": ["proto", "dst", "kind", "arm", "class", "http_class", "http_code", "http_len", "http_pre", "http_suf", "http_sim",
            "http_canary", "tls_ok", "cand_kind", "prefix24", "ts_epoch"],
    "att_http_flag": ["flag"],
    "att_http_added": ["header"],
    "req": ["tls", "method", "kind", "age_s", "req_canary", "hello_fp", "ts_epoch"],
    "req_header": ["name"],
    "npre_ip": ["node"],
    "cands": ["prefix24"],
    "list_event": ["prefix24"],
    "agg_member": ["prefix24"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["ts_epoch"],
    "version": ["version", "ts_epoch"],
    "evidence": ["ext"],
    "meta": ["ingest_version", "first_ts", "last_ts", "state_tz_offsets", "payload_len", "judge_leaf_observed_count"],
}

DEFINITIONS = {
    "内容被改": "明文（dst=judge_http）响应状态 200 而正文 SHA-256 不符，即 att.http_class='http_body_mismatch'。分三种，算法照 summary.go BodyChange："
             "截断 = 公共前缀长度等于收到的长度且收到的比期望短；局部改动 = 相似度（HTML/JS 按期望正文的非空行有多少原样出现，二进制按公共前后缀合计占比，"
             "probe.Similarity）HTML/JS ≥ 50%、二进制 ≥ 90%；其余为整页替换。只有局部改动算篡改。PROTOCOL“指标定义·内容被改”。"
             "期望长度取 meta.payload_len（成功响应里最常见的 http_len）；omitempty 省略的 pre/sim/len 按 0 处理（与 Go 零值一致）",
    "内容被改·按请求": "分子是上面的不符尝试数；分母“明文响应 200”= 明文到 judge 的尝试里 http_code=200 的（含正确、不符、金丝雀不符）。"
                   "另给“收到任何状态码”的分母。Mani 等按请求计（10.5% 的 HTML 请求）",
    "内容被改·按代理": "分子是至少一次不符的代理数；分母“能转发的代理”= 至少一次明文响应 200 的代理（取的解释：无论正文对不对，代理把响应送回来了就算能转发）。"
                   "另给“端到端可用过（任一协议 class=ok 到 judge）”作第二分母。Tsirantonakis 等按代理计（38%）。一个代理多种改动时各类都计一次，"
                   "另按“最差”归一类：局部改动 > 整页替换 > 截断",
    "gzip 解开后相同": "代理擅自加了 gzip（att_http_flag.flag='gzip_added'，attempt.go fetchJudge 在解压、比对正文之前记下）。"
                   "按解开后的结果分三项：正文相同且金丝雀相符（class=ok）；正文相同但金丝雀缺失/不符（class=http_canary_*，PROTOCOL 只说“解开后内容相同”，"
                   "所以这一项也不算内容被改，它已计入“正文正确但不是这次请求的应答”）；解开后仍不符（http_body_mismatch，已计入不符）。"
                   "三项之和等于 gzip_added 标记的尝试数（自检）。PROTOCOL“内容被改”末句",
    "响应头被动过": "正文正确、金丝雀相符，但响应头有变：att_http_flag 的 csp_missing / csp_changed / cookie_missing / cookie_changed / gzip_added"
               "（attempt.go fetchJudge），以及 judge 没发却出现的响应头名（att_http_added，最多记 12 个）。按尝试和按代理各计；"
               "对应 summary.go 的“响应头被动过: <flag>”和“响应里多出 judge 没发的头”",
    "正文正确但不是这次请求的应答": "class 为 http_canary_missing / http_canary_bad：正文哈希对，响应头里的金丝雀却缺失或不符，说明是缓存或伪造的应答。"
                        "对应 summary.go 的“正文正确但不是这次请求的应答（缓存或重放）”",
    "请求被改": "以 judge 记下的请求头为准（req_header，取同一 nonce 最早到达的那份），照 derive.go Derive：X-Probe-Canary 缺失/不符（judge 已比对，req.req_canary）；"
             "Cookie 缺失，或 req_canary=ok 时 Cookie ≠ pc=<X-Probe-Canary>（期望值来自共享密钥，数据包里没有，所以只能在 judge 判定金丝雀正确时借用它的值比；"
             "金丝雀不正确时 Cookie 的改动无法单独判定，记为 cookie_unverifiable，不计入被改）；User-Agent / Accept / Accept-Language / Accept-Encoding 缺失或值变了；"
             "方法不是 GET。Connection 是逐跳头，去掉或改掉都不算。PROTOCOL“请求被改、匿名程度”",
    "匿名程度": "照 derive.go Derive：请求头值里出现探测器自己的地址（self_ips，来源 start.judge_ip；探测器与 judge 同机）→ 透明；"
             "否则出现 derive.go proxyHeaders 列出的代理头（Via、X-Forwarded-For 等）→ 匿名；都没有 → 高匿。"
             "主口径只算 HTTP 转发（proto=forward）且 class=ok 且 judge 收到的请求（summary.go 只对明文转发统计 Anon）；"
             "另给“全部明文（dst=judge_http，含 SOCKS/CONNECT 隧道里的明文）”和“judge 收到的全部明文请求（不限 class）”两个范围。"
             "按代理计时取该代理所有请求里最差的一级（透明 > 匿名 > 高匿）",
    "重放": "同一个 nonce 被 judge 收到不止一次（req 按 nonce 分组 COUNT>1）。探测器每次请求都生成新 nonce（attempt.go fetchJudge），所以多出来的都不是探测器发的。"
          "给出份数分布、来自几个不同地址、首末两份的间隔、最晚一份到达时 nonce 已签发多少秒（req.age_s 的最大值，即 derive.go LateS）。"
          "归到代理：按 nonce 关联 att（主口径与 summary.go 一致：class=ok 且 judge 收到的尝试）。PROTOCOL“指标定义·重放”",
    "出口地址": "judge 日志里的对端地址（req.remote，同一 nonce 取最早到达的那份），不是探测器回显的。“与入口相同”= remote 等于候选的 IP；"
             "“稳定”= 同一代理在整个观察期里 judge 看到过几个不同的出口（summary.go Egress 的 1 / 2 到 3 / 4 个以上分桶）。"
             "两个公开 IP 回显服务看到的地址（att.dst=obs:*，att.ip）与同一探访里 judge 看到的 remote 比较；另与该代理整个观察期的出口集合比较。summary.go 的 observer_vs_judge 只和记录流里这条之前攒下的出口集合比，与 summary.json 交叉核对时照它的做法算（crosscheck），两种算法的结果会差一点。"
             "响应头 X-Judge-Remote 回显的地址（att.ip）只用来与日志互相核对。PROTOCOL“指标定义·出口地址”。输出里只有相同/不同/个数，不出现地址本身",
    "节点的出口": "节点经 sing-box 到 judge 的成功尝试里，judge 看到的 remote 等于预检解析出的入口 IP 之一 → 与入口相同；没有预检 IP → 入口地址未知；"
              "否则与入口不同；等于本机地址 → 仪器异常（流量没走节点）。入口 IP 取该尝试之前最近一次解析出 IP 的预检（npre.n_ips>0，按 ts_epoch）——"
              "节点域名 72 小时里可能换地址，所以不能拿任意一轮的 IP 比。这与 summary.go 相同：它按记录流的顺序读 probe 文件，读到 npre 就更新 nodeIP，"
              "读到 att 时用的就是此前最近一次非空预检（probeLine 的 case \"npre\"、nodeEgress）。之前没有就取最早的一次（本模块取的解释，"
              "summary.go 记为入口地址未知；借用的尝试数单列）。summary.go 只统计 dst=judge_tls，这里按 dst 分列；另给 summary.go 口径和“任意一轮预检 IP”"
              "诊断口径的结果与差异数，交叉核对按 summary.go 口径。“本机地址”= self_ips 里 start.judge_ip ∪ judge_remote:control:public ∪ "
              "echo:control:public（ips_self）；summary.go 只用 start.judge_ip",
    "仪器不变量": "PROTOCOL“对照与自检·不变量”：TLS 校验通过的请求到达 judge 时必须与发出时一致、ClientHello 指纹必须与直连对照相同；"
              "探测器认为成功的请求 judge 必须收到（judge 最后一条记录前 10 秒之前的）；节点探测的出口不能是本机（ips_self，见“节点的出口”）；"
              "回显地址应等于日志。出现一次就说明仪器有错",
    "ClientHello 指纹基线": "对照组 judge_tls 成功尝试到达 judge 时的 hello_fp 集合（summary.go baseFP，应恰好 1 种）。集合为空（数据里没有对照组或对照组记录丢失）时"
                      "fp_base 取 NULL，“指纹与直连不同”输出 null 并注明无基线——照 summary.go integrity() 的 b.baseFP != \"\" 才判",
    "查询计划自检": "运行结束时对执行过的每条 SELECT 做 EXPLAIN QUERY PLAN：相关子查询（CORRELATED ... SUBQUERY）里对 SMALL_TABLES 以外的表做顺序扫描（SCAN）"
               "就是随记录数平方增长的查询，记进 plan_audit；自检里断言为零。这是保证真实数据（数百万 nonce）能跑完的手段，不改变任何数字",
    "正式起点": "PROTOCOL“正式测量的起止”：默认取第一条 start；之后有 resumed_candidates=0 的 start（状态被清空）或版本变了就取那之后的。"
             "之前的数据是试运行，不并入主口径。与 summary.json 交叉核对时按整个数据算（summary.go 不裁窗口）。可用 --formal-start 覆盖。"
             "主口径只裁下界：PROTOCOL 说“跑满 72 小时”，探测器多跑的部分照样计入，window.hours_beyond_72 和 attempts_after_72h 说明多了多少"
             "（各模块一致的选择；要统一裁上界应作为跨模块决定记进 docs/decisions）",
    "候选密集的 /24": "候选数超过阈值（默认 100）的 /24。候选全集 = 状态文件 cands ∪ 探访过的代理候选；没有 cands 表时退而用 list_event（event='add'）∪ agg_member ∪ 探访过的"
                  "（PROTOCOL 1.2 说的正是“一次也探不到”的条目，只用 att 会漏掉它们；list_event 里含被排除的条目——judge 自己的地址、私网地址、知名端口——"
                  "它们从不进候选池，所以这个退路会略高估）。各类篡改比例另给一组去掉这些 /24 里全部候选的结果；n 里逐个列出每个密集 /24 的候选数、探访过的候选数和"
                  "在本模块各分母里的份额（每个候选探访到多少次、可用多少见 availability.json 的 dense_prefixes）。PROTOCOL 1.2 版“候选密集的地址段”",
    "百分比": "100 × 分子 / 分母，保留一位小数；分母为 0 时为 null。每个比例都同时给出分子、分母",
}


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
    if not r:
        return "—"
    return f"{fmt(r['num'])}/{fmt(r['den'])}（{fmt(r['pct'], '%')}）"


def sql_in(values):
    return ",".join("'%s'" % v.replace("'", "''") for v in values)


# 比较值的请求头（rh 表的列名 → 头名）
HEADER_COLS = [("cookie", "Cookie"), ("canary_hdr", "X-Probe-Canary"), ("ua", "User-Agent"),
               ("accept", "Accept"), ("alang", "Accept-Language"), ("aenc", "Accept-Encoding")]


def last_header_cols():
    """rh 表里各比较头的取值：同名头出现多次时取最后一个，照 derive.go Derive 的 got[k] = v 逐个覆盖。
    seq 是头在 judge 记录里的位置；补成 10 位定长前缀后取 MAX 就是最后一个，再去掉前缀。
    （原来写的是 MAX(value)，同名头重复、值不同时取到的是字典序最大的那个，与 derive.go 不一致）"""
    return ",\n".join("substr(MAX(CASE WHEN h.name = '%s' THEN printf('%%010d', h.seq) || h.value END), 11) AS %s" % (name, col)
                       for col, name in HEADER_COLS)


class DB:
    def __init__(self, path):
        # mode=ro：库文件只读；临时表都建在 TEMP 库里（query_only 会连 TEMP 表一起禁掉，所以不用它）
        self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        self.con.execute("PRAGMA cache_size = -262144")  # 256 MB 页缓存，内存不随记录数增长
        self.con.execute("PRAGMA temp_store = FILE")
        self.log = []   # 执行过的 (sql, params)，给 plan_audit 复查用；条数是查询条数（几百），不随记录数增长

    def _exec(self, sql, params):
        self.log.append((sql, tuple(params)))
        return self.con.execute(sql, params)

    def q(self, sql, params=()):
        return self._exec(sql, params).fetchall()

    def one(self, sql, params=()):
        return self._exec(sql, params).fetchone()

    def scalar(self, sql, params=()):
        row = self.one(sql, params)
        return row[0] if row else None

    def x(self, sql, params=()):
        self._exec(sql, params)

    def plan_audit(self):
        """对执行过的每条 SELECT（含 CREATE TABLE ... AS SELECT 的 SELECT 部分）做 EXPLAIN QUERY PLAN，
        找相关子查询里对大表的顺序扫描。EXPLAIN QUERY PLAN 的行是 (id, parent, notused, detail)；相关子查询是 detail 以
        “CORRELATED” 开头的节点，它下面的 “SCAN <表或别名>” 表示外层每一行都要把这张表扫一遍（O(N²)），
        “SEARCH ... USING INDEX” 才是索引查找。SMALL_TABLES 里的小表例外。"""
        seen = set()
        offenders = []
        n_checked = 0
        for sql, params in self.log:
            s = sql.strip()
            m = re.match(r"CREATE\s+TEMP\s+TABLE\s+\w+\s+AS\s+(SELECT.*)$", s, re.S | re.I)
            if m:
                s = m.group(1)
            if not re.match(r"SELECT\b", s, re.I):
                continue
            key = (s, params)
            if key in seen:
                continue
            seen.add(key)
            n_checked += 1
            try:
                rows = self.con.execute("EXPLAIN QUERY PLAN " + s, params).fetchall()
            except sqlite3.Error as e:
                offenders.append({"查询": s[:200], "计划": "EXPLAIN 失败：%s" % e})
                continue
            parent = {r[0]: r[1] for r in rows}
            detail = {r[0]: r[3] for r in rows}
            for nid, d in detail.items():
                if not d.startswith("SCAN "):
                    continue
                name = d.split()[1]
                if name in SMALL_TABLES:
                    continue
                p = parent[nid]
                correlated = False
                while p in detail:
                    if detail[p].startswith("CORRELATED"):
                        correlated = True
                        break
                    p = parent[p]
                if correlated:
                    offenders.append({"查询": re.sub(r"\s+", " ", s)[:200], "计划": d})
        return {"查询数": n_checked, "相关子查询里顺序扫描大表的查询（应为空）": offenders}

    def has_table(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) > 0

    def columns(self, table):
        return [r[1] for r in self.q('PRAGMA table_info("%s")' % table)]

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))

    def counts(self, sql, params=()):
        """把“维度, 计数”两列的查询结果变成 {维度: 计数}。"""
        return {("null" if k is None else str(k)): int(v or 0) for k, v in self.q(sql, params)}


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
    """正式起点与结束时刻。规则同 m_availability.observation_window（PROTOCOL“正式测量的起止”）。"""
    starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0) FROM start ORDER BY ts_epoch") if db.has_table("start") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch") if db.has_table("version") else []
    ends = []
    for t in ("att", "req", "stop"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None
    first_att = db.scalar("SELECT MIN(ts_epoch) FROM att") if db.has_table("att") else None
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
            after = [s[0] for s in starts if s[0] >= change - 1]
            if after and after[0] > fs:
                fs = after[0]
                rule.append("版本变过：取最后一次版本变化之后的第一条 start")
    else:
        fs = first_att
        rule.append("没有 start 记录：取第一条 att")
    if formal_start_arg and formal_start_arg != "auto":
        if formal_start_arg == "first":
            fs = starts[0][0] if starts else first_att
            rule = ["--formal-start first"]
        else:
            fs = parse_iso(formal_start_arg)
            rule = ["--formal-start 指定"]
    trial = 0
    beyond = 0
    if fs is not None and db.has_table("att"):
        trial = int(db.scalar("SELECT COUNT(*) FROM att WHERE ts_epoch < ?", (fs,)) or 0)
        # PROTOCOL“跑满 72 小时”：主口径只裁下界，这里只报告超出 72 小时的部分有多少（att_ts 索引，一次范围查找）
        beyond = int(db.scalar("SELECT COUNT(*) FROM att WHERE ts_epoch >= ?", (fs + FORMAL_HOURS * 3600.0,)) or 0)
    hours = round((end - fs) / 3600.0, 2) if (fs is not None and end is not None) else None
    return {
        "formal_start_utc": iso_minute(fs), "formal_start_rule": "；".join(rule), "end_utc": iso_minute(end),
        "hours": hours,
        "formal_hours_expected": FORMAL_HOURS,
        "hours_beyond_72": (round(max(0.0, hours - FORMAL_HOURS), 2) if hours is not None else None),
        "attempts_after_72h": beyond,
        "upper_bound_note": "主口径没有裁 72 小时上界（各模块一致）；hours_beyond_72 > 0 时报告里要写明实际用了多少小时",
        "starts": len(starts), "versions": sorted({v for _, v in versions}),
        "trial_run_attempts_before_formal_start": trial,
        "_fs": fs, "_end": end,
    }


def judge_last_ts(db):
    """judge 日志最后一条记录的时刻（任何一种 judge 记录）。"""
    last = None
    for t in ("req", "noise", "tls_fail", "noise_dropped", "req_dropped"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None and (last is None or v > last):
                last = v
    return last


def judge_horizon(db):
    """judge 日志最后一条记录前 10 秒（summary.go judgeHorizon）。早于它的成功尝试必须能在 judge 日志里找到。"""
    last = judge_last_ts(db)
    return (last - JUDGE_LAG_S) if last is not None else None


def payload_lengths(db):
    """各载荷的期望长度（BodyChange 的 wantLen）。优先 meta.payload_len；缺的种类退而取 class=ok 的尝试里最常见的 http_len。"""
    out, source = {}, {}
    raw = db.meta("payload_len")
    if raw:
        try:
            for k, v in json.loads(raw).items():
                if isinstance(v, dict) and v.get("len"):
                    out[k] = int(v["len"])
                    source[k] = "meta.payload_len"
        except (ValueError, AttributeError):
            pass
    for k in ("h", "j", "b"):
        if k in out:
            continue
        row = db.one("""SELECT http_len, COUNT(*) AS n FROM att
                        WHERE class = 'ok' AND dst IN ('judge_http', 'judge_tls') AND COALESCE(kind, 'h') = ? AND http_len IS NOT NULL
                        GROUP BY http_len ORDER BY n DESC LIMIT 1""", (k,))
        if row:
            out[k] = int(row[0])
            source[k] = "att 里 class=ok 的众数"
    return out, source


# ---------------------------------------------------------------- 建临时表

def build_tables(db, fs, dense_threshold, plen):
    """在 TEMP 库里建本模块用的表。见模块顶部的设计要点。"""
    # 探测器自己的地址，两张表：
    # ips —— “请求头里带出探测器地址”（透明）的判等，照 summary.go selfIPs 只用 c.Judge.PublicIP（start.judge_ip），与 summary.json 可比；
    #        代理在公网上看到的本机源地址就是这个公网 IP。没有就退而用 self_ips 的全部行
    # ips_self —— “节点探测的出口不能是本机”的判等：start.judge_ip ∪ judge_remote:control:public ∪ echo:control:public（SELF_EGRESS_SOURCES）。
    #        本机经 NAT 回访自己的公网地址时 judge 看到的是 NAT 内侧地址而不是 start.judge_ip；sing-box 直接出去的流量走同一条路，
    #        只比 start.judge_ip 会漏判成“与入口不同”（SCHEMA.md“judge 的身份从哪里取”）。交叉核对仍用 ips（summary.go 的口径）
    db.x("CREATE TEMP TABLE ips (ip TEXT PRIMARY KEY)")
    db.x("CREATE TEMP TABLE ips_self (ip TEXT PRIMARY KEY)")
    self_src = None
    nat_same = None
    if db.has_table("self_ips"):
        rows = db.q("SELECT DISTINCT ip FROM self_ips WHERE source = 'start.judge_ip' AND ip IS NOT NULL AND ip != ''")
        self_src = "start.judge_ip"
        if not rows:
            rows = db.q("SELECT DISTINCT ip FROM self_ips WHERE ip IS NOT NULL AND ip != ''")
            self_src = "self_ips 全部来源（没有 start.judge_ip）"
        for (ip,) in rows:
            db.x("INSERT OR IGNORE INTO ips VALUES (?)", (ip,))
        db.x("INSERT OR IGNORE INTO ips_self SELECT ip FROM ips")
        db.x("INSERT OR IGNORE INTO ips_self SELECT DISTINCT ip FROM self_ips WHERE source IN (%s) AND ip IS NOT NULL AND ip != ''"
             % sql_in(SELF_EGRESS_SOURCES))
        # judge 看到的“本机回访公网地址”的源地址是否就是配置里的公网 IP；不是就说明经过了 NAT（这时 ips_self 比 ips 多出地址）
        remote_pub = [r[0] for r in db.q("SELECT DISTINCT ip FROM self_ips WHERE source = 'judge_remote:control:public' AND ip IS NOT NULL AND ip != ''")]
        if remote_pub and rows:
            nat_same = set(remote_pub) <= {r[0] for r in rows}
    n_self = db.scalar("SELECT COUNT(*) FROM ips")
    n_self_egress = db.scalar("SELECT COUNT(*) FROM ips_self")

    # 期望长度
    db.x("CREATE TEMP TABLE plen (kind TEXT PRIMARY KEY, len INTEGER)")
    for k, v in plen.items():
        db.x("INSERT INTO plen VALUES (?, ?)", (k, v))

    # 候选密集的 /24：候选全集 = 状态文件里的候选 ∪ 出现过的代理候选。没有状态文件（cands 表）时，从没探访过的候选只在快照里：
    # 退而用 list_event（event='add'）∪ agg_member ∪ 探访过的——PROTOCOL 1.2 针对的正是“72 小时里一次也探不到”的条目，只看 att 会漏掉它们
    parts = ["SELECT DISTINCT cand, prefix24 FROM att WHERE cand_kind = 'proxy'"]
    if db.has_table("cands"):
        parts.insert(0, "SELECT key AS cand, prefix24 FROM cands")
        dense_src = "状态文件 cands ∪ 探访过的代理候选（att）"
    else:
        if db.has_table("list_event"):
            parts.insert(0, "SELECT cand, prefix24 FROM list_event WHERE event = 'add' AND cand IS NOT NULL")
        if db.has_table("agg_member"):
            parts.insert(0, "SELECT cand, prefix24 FROM agg_member WHERE cand IS NOT NULL")
        dense_src = "没有 cands 表：list_event(add) ∪ agg_member ∪ 探访过的代理候选（att）；list_event 含从不进候选池的被排除条目，略高估"
    db.x("CREATE TEMP TABLE cu AS " + " UNION ".join(parts))
    db.x("CREATE INDEX temp.cu_p ON cu(prefix24)")
    db.x("CREATE TEMP TABLE dense24 AS SELECT prefix24, COUNT(*) AS n FROM cu WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING n > ?",
         (dense_threshold,))
    db.x("CREATE INDEX temp.dense24_p ON dense24(prefix24)")

    # ---- judge 侧：按 nonce 聚合
    db.x("""CREATE TEMP TABLE rq_n AS
            SELECT nonce, COUNT(*) AS copies, COUNT(DISTINCT remote) AS n_remote, MIN(ts_epoch) AS t0, MAX(ts_epoch) AS t1,
                   MAX(COALESCE(age_s, 0)) AS late, SUM(COALESCE(tls, 0)) AS tls_copies
            FROM req WHERE nonce IS NOT NULL GROUP BY nonce""")
    db.x("CREATE INDEX temp.rq_n_nonce ON rq_n(nonce)")
    # 最早到达的那份（derive.go：按 TS 稳定排序取第一份）
    db.x("""CREATE TEMP TABLE rq_first AS
            SELECT rid, nonce, remote, COALESCE(tls, 0) AS tls, method, COALESCE(req_canary, 'missing') AS req_canary, hello_fp,
                   (instr(COALESCE(target, ''), '://') > 0) AS abs_target
            FROM (SELECT rid, nonce, remote, tls, method, req_canary, hello_fp, target,
                         ROW_NUMBER() OVER (PARTITION BY nonce ORDER BY ts_epoch, rid) AS rn
                  FROM req WHERE nonce IS NOT NULL)
            WHERE rn = 1""")
    db.x("CREATE INDEX temp.rq_first_rid ON rq_first(rid)")
    db.x("CREATE INDEX temp.rq_first_nonce ON rq_first(nonce)")
    # 请求头派生：derive.go Derive 的逐头循环改写成 GROUP BY。Host 头不参与（Go 的 http.Request 把它移出 Header，judge 也没记）
    sent = sql_in(SENT_HEADERS.keys())
    proxyh = sql_in(PROXY_HEADERS)
    db.x("""CREATE TEMP TABLE rh AS
            SELECT h.req_rid,
                   SUM(h.name != 'Host' AND h.name NOT IN (%s)) AS n_added,
                   MAX(h.name IN (%s)) AS revealed,
                   MAX(h.name IN (%s) AND h.name != 'Proxy-Connection') AS revealed_other,
                   MAX(h.name != 'Host' AND EXISTS (SELECT 1 FROM ips WHERE instr(h.value, ips.ip) > 0)) AS leak,
                   %s
            FROM req_header h JOIN rq_first f ON f.rid = h.req_rid
            GROUP BY h.req_rid""" % (sent, proxyh, proxyh, last_header_cols()))
    db.x("CREATE INDEX temp.rh_rid ON rh(req_rid)")
    db.x("""CREATE TEMP TABLE rd AS
            SELECT f.nonce, f.rid AS req_rid, f.remote, f.tls AS req_tls, f.method, f.req_canary, f.hello_fp, f.abs_target,
                   n.copies, n.n_remote, n.t0, n.t1, (n.t1 - n.t0) AS span_s, n.late, n.tls_copies,
                   COALESCE(h.n_added, 0) AS n_added, COALESCE(h.revealed, 0) AS revealed,
                   COALESCE(h.revealed_other, 0) AS revealed_other, COALESCE(h.leak, 0) AS leak,
                   (f.req_canary = 'missing') AS t_canary_missing,
                   (f.req_canary = 'bad') AS t_canary_changed,
                   (h.cookie IS NULL) AS t_cookie_missing,
                   (h.cookie IS NOT NULL AND f.req_canary = 'ok' AND h.cookie != 'pc=' || COALESCE(h.canary_hdr, '')) AS t_cookie_changed,
                   (h.cookie IS NOT NULL AND f.req_canary != 'ok') AS cookie_unverifiable,
                   (h.ua IS NULL) AS t_user_agent_missing,
                   (h.ua IS NOT NULL AND h.ua != ?) AS t_user_agent_changed,
                   (h.accept IS NULL) AS t_accept_missing,
                   (h.accept IS NOT NULL AND h.accept != ?) AS t_accept_changed,
                   (h.alang IS NULL) AS t_accept_language_missing,
                   (h.alang IS NOT NULL AND h.alang != ?) AS t_accept_language_changed,
                   (h.aenc IS NULL) AS t_accept_encoding_missing,
                   (h.aenc IS NOT NULL AND h.aenc != ?) AS t_accept_encoding_changed,
                   (COALESCE(f.method, '') != 'GET') AS t_method_changed
            FROM rq_first f JOIN rq_n n ON n.nonce = f.nonce LEFT JOIN rh h ON h.req_rid = f.rid""",
         (SENT_HEADERS["User-Agent"], SENT_HEADERS["Accept"], SENT_HEADERS["Accept-Language"], SENT_HEADERS["Accept-Encoding"]))
    db.x("CREATE INDEX temp.rd_nonce ON rd(nonce)")
    tsum = " + ".join("t_%s" % t for t in TAMPER_NAMES)
    db.x("ALTER TABLE rd ADD COLUMN tamper INTEGER")
    db.x("UPDATE rd SET tamper = ((%s) > 0)" % tsum)
    db.x("ALTER TABLE rd ADD COLUMN anon TEXT")
    db.x("UPDATE rd SET anon = CASE WHEN leak THEN 'transparent' WHEN revealed THEN 'anonymous' ELSE 'elite' END")

    # 直连对照的 ClientHello 指纹基线（summary.go baseFP：对照组 judge_tls 成功尝试的 hello_fp）。
    # 基线为空（没有对照组、或对照组记录丢失）时不能把所有指纹都判成“与直连不同”：照 summary.go integrity() 的 b.baseFP != "" 才判，fp_base 取 NULL
    db.x("""CREATE TEMP TABLE basefp AS
            SELECT DISTINCT r.hello_fp FROM att a JOIN rd r ON r.nonce = a.nonce
            WHERE a.cand_kind = 'control' AND a.dst = 'judge_tls' AND a.class = 'ok' AND r.hello_fp IS NOT NULL""")
    n_basefp = int(db.scalar("SELECT COUNT(*) FROM basefp") or 0)
    fp_expr = ("CASE WHEN r.hello_fp IS NULL THEN NULL WHEN r.hello_fp IN (SELECT hello_fp FROM basefp) THEN 1 ELSE 0 END"
               if n_basefp > 0 else "NULL")

    # ---- 探测器侧：到达 HTTP 阶段、带 nonce、目的地是 judge 的尝试，与 judge 对账（seen=0 的行 r.* 全是 NULL）
    tcols = ", ".join("r.t_%s" % t for t in TAMPER_NAMES)
    db.x("""CREATE TEMP TABLE aj AS
            SELECT a.rid, a.cand, a.cand_kind, a.cand_ip, a.prefix24, a.visit, a.proto, a.dst, COALESCE(a.kind, 'h') AS kind, a.arm,
                   a.class, a.http_class, a.http_code, a.ts_epoch, (a.ts_epoch >= ?) AS in_win,
                   a.ip AS echo_ip, COALESCE(a.tls_ok, 0) AS tls_ok, a.nonce,
                   (r.nonce IS NOT NULL) AS seen, r.remote,
                   CASE WHEN r.nonce IS NULL THEN NULL WHEN r.remote = a.cand_ip THEN 1 ELSE 0 END AS egress_same,
                   r.anon, r.leak, r.revealed, r.revealed_other, r.n_added, r.tamper, r.cookie_unverifiable,
                   r.copies, r.n_remote, r.span_s, r.late, r.hello_fp, r.req_tls, r.abs_target,
                   %s AS fp_base,
                   %s
            FROM att a LEFT JOIN rd r ON r.nonce = a.nonce
            WHERE a.nonce IS NOT NULL AND a.dst IN ('judge_http', 'judge_tls') AND a.class NOT LIKE '%%canceled%%'""" % (fp_expr, tcols), (fs,))
    db.x("CREATE INDEX temp.aj_cand ON aj(cand)")
    db.x("CREATE INDEX temp.aj_visit ON aj(visit, cand)")
    db.x("CREATE INDEX temp.aj_kind ON aj(cand_kind, dst, class)")
    # judge 侧按 nonce 反查 aj（“judge 收到却没有对应 att 的 nonce”）：没有这个索引，几百万 nonce × 几百万行 aj 的相关子查询要跑数天
    db.x("CREATE INDEX temp.aj_nonce ON aj(nonce)")
    db.x("CREATE INDEX temp.aj_rid ON aj(rid)")

    # ---- 节点的入口 IP。summary.go 按记录流的顺序读 probe 文件，每读到一条 n_ips>0 的 npre 就更新 nodeIP[node]，读到节点的 att 时
    # 用的是“这条 att 之前最近一次解析出 IP 的预检”（summary.go probeLine 的 case "npre" 与 nodeEgress）；之前没有 → 入口地址未知。
    # 这里按 ts_epoch 复现同一规则（npre 的 ts 取自预检开始，同一轮的 att 都在预检结束之后，按时间与按流顺序一致）：
    #   pre_rid_prior —— 尝试之前最近一次 n_ips>0 的预检（与 summary.go 完全相同，交叉核对用它）；
    #   pre_rid       —— 主口径：pre_rid_prior，之前没有就取最早的一次（本模块取的解释，见 DEFINITIONS“节点的出口”）；
    #   *_any         —— 诊断：任意一轮预检解析出的 IP 都算（节点域名换过地址时会把“与入口不同”误判成“相同”，单列出差异）
    have_npre = db.has_table("npre") and db.has_table("npre_ip")
    if have_npre:
        db.x("CREATE TEMP TABLE npre_ok AS SELECT rid, node, ts_epoch FROM npre WHERE COALESCE(n_ips, 0) > 0 AND ts_epoch IS NOT NULL")
        db.x("CREATE INDEX temp.npre_ok_node ON npre_ok(node, ts_epoch)")
        db.x("CREATE TEMP TABLE npre_ip2 AS SELECT npre_rid, node, ip FROM npre_ip WHERE ip IS NOT NULL")
        db.x("CREATE INDEX temp.npre_ip2_rid ON npre_ip2(npre_rid, ip)")
        db.x("CREATE INDEX temp.npre_ip2_node ON npre_ip2(node, ip)")
        db.x("""CREATE TEMP TABLE nj AS
                SELECT x.rid, x.pre_rid, x.pre_rid_prior,
                       CASE WHEN x.pre_rid IS NULL THEN NULL
                            ELSE EXISTS (SELECT 1 FROM npre_ip2 i WHERE i.npre_rid = x.pre_rid AND i.ip = x.remote) END AS entry_same,
                       CASE WHEN x.pre_rid_prior IS NULL THEN 0
                            ELSE EXISTS (SELECT 1 FROM npre_ip2 i WHERE i.npre_rid = x.pre_rid_prior AND i.ip = x.remote) END AS entry_same_prior,
                       (x.pre_rid_prior IS NOT NULL) AS has_entry_prior,
                       EXISTS (SELECT 1 FROM npre_ip2 i WHERE i.node = x.cand AND i.ip = x.remote) AS entry_same_any,
                       EXISTS (SELECT 1 FROM npre_ip2 i WHERE i.node = x.cand) AS has_entry_any
                FROM (SELECT y.rid, y.cand, y.remote, y.pre_rid_prior,
                             COALESCE(y.pre_rid_prior,
                                      (SELECT p.rid FROM npre_ok p WHERE p.node = y.cand ORDER BY p.ts_epoch LIMIT 1)) AS pre_rid
                      FROM (SELECT a.rid, a.cand, a.remote,
                                   (SELECT p.rid FROM npre_ok p WHERE p.node = a.cand AND p.ts_epoch <= a.ts_epoch
                                    ORDER BY p.ts_epoch DESC LIMIT 1) AS pre_rid_prior
                            FROM aj a WHERE a.cand_kind = 'node' AND a.seen = 1) y) x""")
        npre_src = "npre 按时间（尝试之前最近一次 n_ips>0 的预检；之前没有就取最早的一次）"
    elif db.has_table("npre_ip"):
        # 只有拆开的 npre_ip、没有 npre 表（没有时间）：三种口径都退回“任意一轮”
        db.x("CREATE TEMP TABLE npre_ip2 AS SELECT npre_rid, node, ip FROM npre_ip WHERE ip IS NOT NULL")
        db.x("CREATE INDEX temp.npre_ip2_node ON npre_ip2(node, ip)")
        db.x("""CREATE TEMP TABLE nj AS
                SELECT x.rid, NULL AS pre_rid, NULL AS pre_rid_prior,
                       x.same_any AS entry_same, x.same_any AS entry_same_prior, x.has_any AS has_entry_prior,
                       x.same_any AS entry_same_any, x.has_any AS has_entry_any
                FROM (SELECT a.rid,
                             EXISTS (SELECT 1 FROM npre_ip2 i WHERE i.node = a.cand AND i.ip = a.remote) AS same_any,
                             EXISTS (SELECT 1 FROM npre_ip2 i WHERE i.node = a.cand) AS has_any
                      FROM aj a WHERE a.cand_kind = 'node' AND a.seen = 1) x""")
        npre_src = "只有 npre_ip（没有 npre 表）：任意一轮"
    else:
        db.x("CREATE TEMP TABLE nj AS SELECT a.rid, NULL AS pre_rid, NULL AS pre_rid_prior, NULL AS entry_same, "
             "0 AS entry_same_prior, 0 AS has_entry_prior, 0 AS entry_same_any, 0 AS has_entry_any "
             "FROM aj a WHERE a.cand_kind = 'node' AND a.seen = 1")
        npre_src = "无预检记录"
    db.x("CREATE INDEX temp.nj_rid ON nj(rid)")
    # 预检解析出的 IP 集合在观察期内变过的节点：某一轮有、另一轮没有的 IP 存在
    n_entry_changed = 0
    if have_npre:
        n_entry_changed = int(db.scalar("""SELECT COUNT(DISTINCT p.node) FROM npre_ok p JOIN npre_ip2 i ON i.npre_rid = p.rid
            WHERE EXISTS (SELECT 1 FROM npre_ok p2 WHERE p2.node = p.node AND p2.rid != p.rid
                          AND NOT EXISTS (SELECT 1 FROM npre_ip2 i2 WHERE i2.npre_rid = p2.rid AND i2.ip = i.ip))""") or 0)

    # ---- 内容：到达 HTTP 阶段并收到状态码的尝试（代理和节点），带 BodyChange 分类
    db.x("""CREATE TEMP TABLE pc AS
            SELECT a.rid, a.cand, a.cand_kind, a.prefix24, a.proto, a.dst, COALESCE(a.kind, 'h') AS kind, a.class, a.http_class,
                   a.http_code, (a.ts_epoch >= ?) AS in_win,
                   COALESCE(a.http_len, 0) AS len, COALESCE(a.http_pre, 0) AS pre, COALESCE(a.http_suf, 0) AS suf,
                   COALESCE(a.http_sim, 0) AS sim, p.len AS want_len,
                   CASE WHEN a.http_class = 'http_body_mismatch' THEN
                        CASE WHEN COALESCE(a.http_pre, 0) = COALESCE(a.http_len, 0) AND COALESCE(a.http_len, 0) < COALESCE(p.len, 0)
                                  THEN '正文被截断'
                             WHEN (COALESCE(a.kind, 'h') = 'b' AND COALESCE(a.http_sim, 0) >= 90)
                                  OR (COALESCE(a.kind, 'h') != 'b' AND COALESCE(a.http_sim, 0) >= 50)
                                  THEN '正文被局部改动（注入或改写）'
                             ELSE '正文被整页替换' END
                   END AS body_change,
                   EXISTS (SELECT 1 FROM att_http_flag f WHERE f.att_rid = a.rid AND f.flag = 'gzip_added') AS gz,
                   (a.http_ev IS NOT NULL) AS has_ev,
                   CASE WHEN a.http_class = 'http_body_mismatch' THEN a.http_ev END AS ev
            FROM att a LEFT JOIN plen p ON p.kind = COALESCE(a.kind, 'h')
            WHERE a.cand_kind IN ('proxy', 'node') AND a.dst IN ('judge_http', 'judge_tls')
              AND a.http_code IS NOT NULL AND a.class NOT LIKE '%canceled%'""", (fs,))
    db.x("CREATE INDEX temp.pc_cand ON pc(cand)")
    db.x("CREATE INDEX temp.pc_k ON pc(cand_kind, dst, http_class)")

    # ---- 小表各扫一遍 att 就够：回显服务的尝试（ob）、响应头标记（fl）、多出的响应头（ad）。之后的查询都打这些小表，不再扫 att
    db.x("""CREATE TEMP TABLE ob AS
            SELECT a.rid, a.cand, a.cand_kind, a.prefix24, a.visit, a.dst, a.class, a.ip, (a.ts_epoch >= ?) AS in_win
            FROM att a WHERE a.dst LIKE 'obs:%' AND a.class NOT LIKE '%canceled%'""", (fs,))
    db.x("CREATE INDEX temp.ob_visit ON ob(visit, cand)")
    db.x("""CREATE TEMP TABLE fl AS
            SELECT f.att_rid, f.flag, a.cand, a.cand_kind, a.prefix24, a.dst, a.class, (a.ts_epoch >= ?) AS in_win
            FROM att_http_flag f JOIN att a ON a.rid = f.att_rid WHERE a.class NOT LIKE '%canceled%'""", (fs,))
    db.x("""CREATE TEMP TABLE ad AS
            SELECT x.att_rid, x.header, a.cand, a.cand_kind, a.prefix24, a.dst, a.class, (a.ts_epoch >= ?) AS in_win
            FROM att_http_added x JOIN att a ON a.rid = x.att_rid WHERE a.class NOT LIKE '%canceled%'""", (fs,))
    return {"self_ips_source": self_src, "self_ips_count": int(n_self or 0),
            "self_egress_ips_count": int(n_self_egress or 0), "nat_same": nat_same,
            "dense_prefixes": int(db.scalar("SELECT COUNT(*) FROM dense24") or 0),
            "dense_candidates": int(db.scalar("SELECT COALESCE(SUM(n), 0) FROM dense24") or 0),
            "dense_source": dense_src,
            "basefp_count": n_basefp,
            "npre_source": npre_src, "nodes_entry_changed": n_entry_changed}


def nd(alias, exclude_dense):
    """“去掉密集 /24”的过滤条件；NOT EXISTS 对 prefix24 为 NULL 的节点行也成立（节点不属于任何 /24）。"""
    return (" AND NOT EXISTS (SELECT 1 FROM dense24 d WHERE d.prefix24 = %s.prefix24)" % alias) if exclude_dense else ""


# ---------------------------------------------------------------- 分母

def denominators(db, win_info):
    out = {}
    out["到达 HTTP 阶段并带 nonce、目的地 judge 的尝试（aj，正式起点之后）"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE in_win = 1"))
    out["其中 judge 收到"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE in_win = 1 AND seen = 1"))
    out["其中代理（cand_kind=proxy）"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE in_win = 1 AND cand_kind = 'proxy'"))
    out["其中节点"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE in_win = 1 AND cand_kind = 'node'"))
    out["其中对照组"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE in_win = 1 AND cand_kind = 'control'"))
    out["收到状态码的明文尝试（代理，dst=judge_http）"] = int(db.scalar(
        "SELECT COUNT(*) FROM pc WHERE in_win = 1 AND cand_kind = 'proxy' AND dst = 'judge_http'"))
    out["明文响应 200 的尝试（代理）"] = int(db.scalar(
        "SELECT COUNT(*) FROM pc WHERE in_win = 1 AND cand_kind = 'proxy' AND dst = 'judge_http' AND http_code = 200"))
    out["能转发的代理（至少一次明文响应 200）"] = int(db.scalar(
        "SELECT COUNT(DISTINCT cand) FROM pc WHERE in_win = 1 AND cand_kind = 'proxy' AND dst = 'judge_http' AND http_code = 200"))
    out["端到端可用过的代理（任一协议 class=ok 到 judge）"] = int(db.scalar(
        "SELECT COUNT(DISTINCT cand) FROM aj WHERE in_win = 1 AND cand_kind = 'proxy' AND class = 'ok'"))
    out["judge 收到过请求的代理"] = int(db.scalar(
        "SELECT COUNT(DISTINCT cand) FROM aj WHERE in_win = 1 AND cand_kind = 'proxy' AND seen = 1"))
    out["judge 收到的请求（req 记录）"] = int(db.scalar("SELECT COUNT(*) FROM req"))
    out["judge 收到的不同 nonce"] = int(db.scalar("SELECT COUNT(*) FROM rq_n"))
    out["judge 收到、却没有对应 att 记录的 nonce"] = int(db.scalar(
        "SELECT COUNT(*) FROM rq_n n LEFT JOIN aj a ON a.nonce = n.nonce WHERE a.nonce IS NULL"))
    out["judge 限速丢弃的 req 条数（req_dropped.n 之和）"] = int(db.scalar("SELECT COALESCE(SUM(n), 0) FROM req_dropped") or 0) \
        if db.has_table("req_dropped") else 0
    out["探测器自己的地址个数（self_ips，透明判定用）"] = win_info["self_ips_count"]
    out["self_ips 来源"] = win_info["self_ips_source"]
    out["本机出口判定用的地址个数（start.judge_ip ∪ judge_remote:control:public ∪ echo:control:public）"] = win_info["self_egress_ips_count"]
    out["judge_remote:control:public 等于 start.judge_ip（否则本机访问公网地址经过了 NAT；null=缺其一）"] = win_info["nat_same"]
    out["候选密集的 /24 个数"] = win_info["dense_prefixes"]
    out["候选密集的 /24 里的候选数"] = win_info["dense_candidates"]
    out["候选密集的 /24 的候选来源"] = win_info["dense_source"]
    out["候选密集的 /24（逐个）"] = dense_prefix_table(db)
    out["直连对照的 ClientHello 指纹种数（应为 1）"] = win_info["basefp_count"]
    out["节点入口 IP 的来源"] = win_info["npre_source"]
    out["预检解析出的 IP 在观察期内变过的节点"] = win_info["nodes_entry_changed"]
    return out


def dense_prefix_table(db):
    """PROTOCOL 1.2“列出被去掉的 /24 各有多少候选、探访到多少”。每个密集 /24 一行：候选数（cu）、探访过的候选数（att 里出现过）、
    在本模块各分母里的份额。pc/aj 各扫一遍按 prefix24 分组，不做相关子查询。每个候选探访到多少次、可用多少见 availability.json 的 dense_prefixes。"""
    rows = {p: {"prefix24": p, "候选": int(n)} for p, n in db.q("SELECT prefix24, n FROM dense24 ORDER BY n DESC, prefix24")}
    if not rows:
        return []
    for p, v in db.q("""SELECT a.prefix24, COUNT(DISTINCT a.cand) FROM att a JOIN dense24 d ON d.prefix24 = a.prefix24
                        WHERE a.cand_kind = 'proxy' AND a.class NOT LIKE '%canceled%' GROUP BY 1"""):
        rows[p]["探访过的候选（att 里出现过）"] = int(v or 0)
    for p, n200, c200, nmis, cmis in db.q("""SELECT p.prefix24, SUM(p.http_code = 200), COUNT(DISTINCT CASE WHEN p.http_code = 200 THEN p.cand END),
                                                 SUM(p.http_class = 'http_body_mismatch'), COUNT(DISTINCT CASE WHEN p.http_class = 'http_body_mismatch' THEN p.cand END)
                                          FROM pc p JOIN dense24 d ON d.prefix24 = p.prefix24
                                          WHERE p.in_win = 1 AND p.cand_kind = 'proxy' AND p.dst = 'judge_http' GROUP BY 1"""):
        rows[p].update({"明文响应 200 的尝试": int(n200 or 0), "能转发的代理（至少一次明文响应 200）": int(c200 or 0),
                        "正文不符的尝试": int(nmis or 0), "正文不符的代理": int(cmis or 0)})
    for p, nok, cok, nseen in db.q("""SELECT a.prefix24, SUM(a.class = 'ok'), COUNT(DISTINCT CASE WHEN a.class = 'ok' THEN a.cand END), SUM(a.seen)
                                     FROM aj a JOIN dense24 d ON d.prefix24 = a.prefix24
                                     WHERE a.in_win = 1 AND a.cand_kind = 'proxy' GROUP BY 1"""):
        rows[p].update({"class=ok 到 judge 的尝试": int(nok or 0), "端到端可用过的代理": int(cok or 0), "judge 收到的请求": int(nseen or 0)})
    keys = ["探访过的候选（att 里出现过）", "明文响应 200 的尝试", "能转发的代理（至少一次明文响应 200）", "正文不符的尝试", "正文不符的代理",
            "class=ok 到 judge 的尝试", "端到端可用过的代理", "judge 收到的请求"]
    for v in rows.values():
        for k in keys:
            v.setdefault(k, 0)
    return list(rows.values())


# ---------------------------------------------------------------- 内容被改

def content_modification(db, exclude_dense, plen, plen_src):
    """PROTOCOL“内容被改”。分类照 summary.go BodyChange（已在 pc.body_change 里算好）。主口径：代理、明文（dst=judge_http）、正式起点之后。"""
    f = nd("p", exclude_dense)
    base = "FROM pc p WHERE p.in_win = 1 AND p.cand_kind = 'proxy' AND p.dst = 'judge_http'" + f
    n_any = db.scalar("SELECT COUNT(*) " + base)
    n_200 = db.scalar("SELECT COUNT(*) " + base + " AND p.http_code = 200")
    n_mis = db.scalar("SELECT COUNT(*) " + base + " AND p.http_class = 'http_body_mismatch'")
    by_kind = db.counts("SELECT p.body_change, COUNT(*) " + base + " AND p.http_class = 'http_body_mismatch' GROUP BY 1")
    per_req = {
        "明文响应 200": int(n_200), "收到任何状态码": int(n_any),
        "正文不符（全部）": ratio(n_mis, n_200),
        "正文不符占收到状态码的": ratio(n_mis, n_any),
    }
    for k in BODY_KINDS:
        per_req[k] = ratio(by_kind.get(k, 0), n_200)
    per_req["按载荷种类"] = {}
    for kind, zh in (("h", "HTML"), ("j", "JavaScript"), ("b", "二进制")):
        d200 = db.scalar("SELECT COUNT(*) " + base + " AND p.http_code = 200 AND p.kind = ?", (kind,))
        bk = db.counts("SELECT p.body_change, COUNT(*) " + base + " AND p.http_class = 'http_body_mismatch' AND p.kind = ? GROUP BY 1", (kind,))
        per_req["按载荷种类"][zh] = {"明文响应 200": int(d200), "正文不符": ratio(sum(bk.values()), d200),
                                **{k: ratio(bk.get(k, 0), d200) for k in BODY_KINDS},
                                "期望长度": plen.get(kind), "期望长度来源": plen_src.get(kind)}
    per_req["按协议"] = {}
    for (proto,) in db.q("SELECT DISTINCT p.proto " + base + " ORDER BY 1"):
        d200 = db.scalar("SELECT COUNT(*) " + base + " AND p.http_code = 200 AND p.proto = ?", (proto,))
        bk = db.counts("SELECT p.body_change, COUNT(*) " + base + " AND p.http_class = 'http_body_mismatch' AND p.proto = ? GROUP BY 1", (proto,))
        per_req["按协议"][proto] = {"明文响应 200": int(d200), "正文不符": ratio(sum(bk.values()), d200),
                                 **{k: ratio(bk.get(k, 0), d200) for k in BODY_KINDS}}
    # gzip：attempt.go fetchJudge 在解压、比对正文之前记 gzip_added，所以它可与 ok / http_canary_* / http_body_mismatch 任一同时出现。
    # PROTOCOL 只说“解开后内容相同的不算内容被改，单独计数”，不论金丝雀；按解开后的结果分三项，三项之和应等于标记数。
    # class=ok 的 att 里 http_class 是 NULL（wire.Step 成功时省略 class），所以“正文相同”不能写成 http_class != 'http_body_mismatch'
    g = db.one("SELECT COUNT(*), COUNT(DISTINCT p.cand), "
               "SUM(p.class = 'ok'), COUNT(DISTINCT CASE WHEN p.class = 'ok' THEN p.cand END), "
               "SUM(p.http_class LIKE 'http_canary_%'), COUNT(DISTINCT CASE WHEN p.http_class LIKE 'http_canary_%' THEN p.cand END), "
               "SUM(p.http_class = 'http_body_mismatch'), COUNT(DISTINCT CASE WHEN p.http_class = 'http_body_mismatch' THEN p.cand END), "
               "COUNT(DISTINCT CASE WHEN p.class = 'ok' OR p.http_class LIKE 'http_canary_%' THEN p.cand END) "
               + base + " AND p.gz = 1")
    g = [int(v or 0) for v in g]
    # 金丝雀：正文对但不是这次请求的应答
    can = db.counts("SELECT p.http_class, COUNT(*) " + base + " AND p.http_class LIKE 'http_canary_%' GROUP BY 1")
    can_c = db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_class LIKE 'http_canary_%'")
    # 证据留存：不符的尝试里 http_ev 非空且证据库里有这个文件
    ev = None
    if db.has_table("evidence"):
        # pc.ev 是不符尝试的 http_ev（只在库内比较，不输出）；按 evidence 的主键 (hash, ext) 直接查找，不依赖规划器选的连接顺序
        # （有 ANALYZE 统计时，原先“evidence JOIN att”的写法会被规划成每行把 evidence 扫一遍）
        ev = db.one("SELECT COUNT(*), SUM(p.has_ev), SUM(p.ev IS NOT NULL AND EXISTS (SELECT 1 FROM evidence e "
                    "WHERE e.hash = p.ev AND e.ext = 'body')) " + base + " AND p.http_class = 'http_body_mismatch'")

    # 按代理
    d1 = db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_code = 200")
    d2 = db.scalar("SELECT COUNT(DISTINCT a.cand) FROM aj a WHERE a.in_win = 1 AND a.cand_kind = 'proxy' AND a.class = 'ok'" + nd("a", exclude_dense))
    c_mis = db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_class = 'http_body_mismatch'")
    c_kind = db.counts("SELECT p.body_change, COUNT(DISTINCT p.cand) " + base + " AND p.http_class = 'http_body_mismatch' GROUP BY 1")
    worst = db.counts("""SELECT worst, COUNT(*) FROM (
                SELECT p.cand, CASE WHEN MAX(p.body_change = '正文被局部改动（注入或改写）') THEN '正文被局部改动（注入或改写）'
                                    WHEN MAX(p.body_change = '正文被整页替换') THEN '正文被整页替换'
                                    ELSE '正文被截断' END AS worst
                """ + base + " AND p.http_class = 'http_body_mismatch' GROUP BY p.cand) GROUP BY 1")
    # 不符的代理里，有多少同时也有过正确的响应（间歇性改动）
    inter = db.scalar("""SELECT COUNT(*) FROM (SELECT p.cand """ + base + """ GROUP BY p.cand
                         HAVING MAX(p.http_class = 'http_body_mismatch') = 1 AND MAX(p.class = 'ok') = 1)""")
    per_cand = {
        "能转发的代理（至少一次明文响应 200）": int(d1),
        "端到端可用过的代理（任一协议 class=ok 到 judge）": int(d2),
        "正文不符的代理（占能转发的）": ratio(c_mis, d1),
        "正文不符的代理（占端到端可用过的）": ratio(c_mis, d2),
        "各类（一个代理可属多类）": {k: ratio(c_kind.get(k, 0), d1) for k in BODY_KINDS},
        "按最差一类归一": {k: ratio(worst.get(k, 0), d1) for k in BODY_KINDS},
        "不符的代理里也有过正确响应的（间歇性）": ratio(inter, c_mis),
    }
    out = {
        "按请求": per_req, "按代理": per_cand,
        "gzip": {GZ_ALL: {"尝试": g[0], "代理": g[1]},
                 GZ_SAME: {"尝试": g[2] + g[4], "代理": g[8]},
                 "其中正文相同、金丝雀也相符（class=ok）": {"尝试": g[2], "代理": g[3]},
                 GZ_CANARY: {"尝试": g[4], "代理": g[5]},
                 GZ_MIS: {"尝试": g[6], "代理": g[7]},
                 "三项之和等于标记数（自检）": (g[2] + g[4] + g[6]) == g[0]},
        "正文正确但不是这次请求的应答（缓存或伪造）": {"尝试（按类别）": can, "尝试合计": sum(can.values()), "代理": int(can_c or 0),
                                     "占明文响应 200": ratio(sum(can.values()), n_200)},
    }
    if ev:
        out["证据留存"] = {"不符的尝试": int(ev[0] or 0), "记了证据哈希": int(ev[1] or 0), "证据文件在库里": int(ev[2] or 0)}
    return out


# ---------------------------------------------------------------- 响应头被动过

HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
HEADER_MIN_PROXIES = 3


def name_table(rows, unit, min_proxies=None):
    """头名由代理决定，不可信：只点名形状正常（字母开头、只含字母数字和连字符、不超过 64 个字符）且出现在至少
    HEADER_MIN_PROXIES 个代理上的头；其余合并成一行“其他”，只给种数和合计。rows = [(头名, 次数, 代理数)]。"""
    k = HEADER_MIN_PROXIES if min_proxies is None else min_proxies
    out, other = {}, {"种数": 0, unit: 0, "代理（按头名分别计，可重复）": 0}
    for name, n, proxies in rows:
        if name and HEADER_NAME_RE.match(name) and proxies >= k:
            out[name] = {unit: n, "代理": proxies}
        else:
            other["种数"] += 1
            other[unit] += n
            other["代理（按头名分别计，可重复）"] += proxies
    if other["种数"]:
        out["其他（形状不规则或少于 %d 个代理的头名）" % k] = other
    return out


def response_headers(db, exclude_dense):
    """attempt.go fetchJudge 的 flags / added；对应 summary.go “响应头被动过: <flag>”“响应里多出 judge 没发的头”。
    范围：代理、目的地 judge、正式起点之后。flags 里 gzip_added 可与正文不符同时出现，其余只在 class=ok 时有。
    分母取 aj（class=ok 到 judge 的尝试必然带 nonce，所以 aj 里的 class=ok 行就是全部成功尝试）。"""
    f = nd("a", exclude_dense)
    base = "FROM aj a WHERE a.in_win = 1 AND a.cand_kind = 'proxy' AND a.class = 'ok'" + f
    d_ok = db.scalar("SELECT COUNT(*) " + base)
    d_ok_c = db.scalar("SELECT COUNT(DISTINCT a.cand) " + base)
    fb = "FROM fl a WHERE a.in_win = 1 AND a.cand_kind = 'proxy' AND a.dst IN ('judge_http', 'judge_tls')" + f
    flags = {}
    for (flag,) in db.q("SELECT DISTINCT flag FROM fl ORDER BY 1"):
        r = db.one("SELECT COUNT(*), COUNT(DISTINCT a.cand), SUM(a.class = 'ok'), SUM(a.dst = 'judge_tls') " + fb + " AND a.flag = ?", (flag,))
        flags[flag] = {"尝试": int(r[0] or 0), "其中 class=ok": int(r[2] or 0), "其中经 TLS 隧道（应为 0）": int(r[3] or 0),
                       "代理": int(r[1] or 0), "代理占端到端可用过的": ratio(r[1], d_ok_c)}
    any_flag = db.one("SELECT COUNT(DISTINCT a.att_rid), COUNT(DISTINCT a.cand) " + fb + " AND a.class = 'ok' AND a.dst = 'judge_http' AND a.flag != 'gzip_added'")
    ab = "FROM ad a WHERE a.in_win = 1 AND a.cand_kind = 'proxy' AND a.dst IN ('judge_http', 'judge_tls') AND a.class = 'ok'" + f
    rows = []
    for (hdr,) in db.q("SELECT DISTINCT header FROM ad ORDER BY 1"):
        r = db.one("SELECT COUNT(*), COUNT(DISTINCT a.cand) " + ab + " AND a.header = ?", (hdr,))
        rows.append((hdr, int(r[0] or 0), int(r[1] or 0)))
    added = name_table(rows, "尝试")
    any_added = db.one("SELECT COUNT(DISTINCT a.att_rid), COUNT(DISTINCT a.cand) " + ab)
    return {
        "分母": {"class=ok 的尝试（代理，目的地 judge）": int(d_ok), "端到端可用过的代理": int(d_ok_c)},
        "标记（按标记）": flags,
        "明文成功响应里 CSP/Cookie 被动过（不含 gzip_added）": {"尝试": int(any_flag[0] or 0), "代理": ratio(any_flag[1], d_ok_c)},
        "多出 judge 没发的头（按头名）": added,
        "多出 judge 没发的头（任一）": {"尝试": ratio(any_added[0], d_ok), "代理": ratio(any_added[1], d_ok_c)},
    }


# ---------------------------------------------------------------- 请求被改与匿名程度

ANON_SCOPES = [
    ("forward_ok", "HTTP 转发、class=ok、judge 收到（summary.go Anon 的口径）",
     "a.cand_kind = 'proxy' AND a.proto = 'forward' AND a.class = 'ok' AND a.seen = 1"),
    ("plain_ok", "全部明文（dst=judge_http，含 SOCKS/CONNECT 里的明文）、class=ok、judge 收到",
     "a.cand_kind = 'proxy' AND a.dst = 'judge_http' AND a.class = 'ok' AND a.seen = 1"),
    ("plain_seen", "judge 收到的全部明文请求（不限 class：含正文不符、金丝雀不符等）",
     "a.cand_kind = 'proxy' AND a.dst = 'judge_http' AND a.seen = 1"),
    ("node_plain_ok", "节点、明文、class=ok、judge 收到",
     "a.cand_kind = 'node' AND a.dst = 'judge_http' AND a.class = 'ok' AND a.seen = 1"),
]


def anonymity(db, exclude_dense):
    """derive.go Derive 的 Anonymity；按请求和按代理（取最差）。"""
    out = {}
    for key, desc, cond in ANON_SCOPES:
        base = "FROM aj a WHERE a.in_win = 1 AND " + cond + nd("a", exclude_dense)
        n = db.scalar("SELECT COUNT(*) " + base)
        by = db.counts("SELECT a.anon, COUNT(*) " + base + " GROUP BY 1")
        pc_only = db.scalar("SELECT COUNT(*) " + base + " AND a.anon = 'anonymous' AND a.revealed_other = 0")
        worst = db.counts("""SELECT w, COUNT(*) FROM (
                    SELECT a.cand, CASE WHEN MAX(a.anon = 'transparent') THEN 'transparent'
                                        WHEN MAX(a.anon = 'anonymous') THEN 'anonymous' ELSE 'elite' END AS w
                    """ + base + " GROUP BY a.cand) GROUP BY 1")
        nc = sum(worst.values())
        mixed = db.scalar("SELECT COUNT(*) FROM (SELECT a.cand " + base + " GROUP BY a.cand HAVING COUNT(DISTINCT a.anon) > 1)")
        out[key] = {
            "口径": desc,
            "按请求": {"请求": int(n), **{ANON_ZH[k]: ratio(by.get(k, 0), n) for k in ANON_LEVELS},
                     "其中只因 Proxy-Connection 被判匿名（探测器自己对转发代理发的头被透传）": int(pc_only or 0)},
            "按代理（取最差）": {"代理": int(nc), **{ANON_ZH[k]: ratio(worst.get(k, 0), nc) for k in ANON_LEVELS},
                          "不同请求等级不一致的代理": int(mixed or 0)},
        }
    return out


def request_tamper(db, exclude_dense):
    """derive.go Derive 的 Tamper / LeakIP / AddedReq；对应 summary.go “请求头被改动”“请求头里带出了探测器的地址”。"""
    out = {}
    for key, desc, cond in ANON_SCOPES[:3]:
        base = "FROM aj a WHERE a.in_win = 1 AND " + cond + nd("a", exclude_dense)
        n = db.scalar("SELECT COUNT(*) " + base)
        nc = db.scalar("SELECT COUNT(DISTINCT a.cand) " + base)
        r = db.one("SELECT SUM(a.tamper), COUNT(DISTINCT CASE WHEN a.tamper THEN a.cand END), SUM(a.leak), "
                   "COUNT(DISTINCT CASE WHEN a.leak THEN a.cand END), SUM(a.n_added > 0), COUNT(DISTINCT CASE WHEN a.n_added > 0 THEN a.cand END), "
                   "SUM(a.cookie_unverifiable), SUM(a.abs_target), COUNT(DISTINCT CASE WHEN a.abs_target THEN a.cand END) " + base)
        kinds = {}
        for t in TAMPER_NAMES:
            k = db.one("SELECT SUM(a.t_%s), COUNT(DISTINCT CASE WHEN a.t_%s THEN a.cand END) " % (t, t) + base)
            if k[0]:
                kinds[t] = {"请求": int(k[0]), "代理": int(k[1])}
        # 代理加进请求的头：按头名（req_header.name 可输出；值不输出）
        added = name_table([(nm, int(c or 0), int(p or 0)) for nm, c, p in db.q(
            """SELECT h.name, COUNT(*), COUNT(DISTINCT a.cand) FROM aj a JOIN req_header h ON h.req_rid = (SELECT req_rid FROM rd WHERE rd.nonce = a.nonce)
               WHERE a.in_win = 1 AND """ + cond + nd("a", exclude_dense) + """
                 AND h.name != 'Host' AND h.name NOT IN (%s) GROUP BY 1 ORDER BY 2 DESC""" % sql_in(SENT_HEADERS.keys()))], "请求")
        out[key] = {
            "口径": desc, "请求": int(n), "代理": int(nc),
            "请求被改（任一项）": {"请求": ratio(r[0], n), "代理": ratio(r[1], nc)},
            "各项（一个请求可有多项）": kinds,
            "Cookie 无法判定（金丝雀已不对）": int(r[6] or 0),
            "请求头里带出探测器地址": {"请求": ratio(r[2], n), "代理": ratio(r[3], nc)},
            "代理加了请求头": {"请求": ratio(r[4], n), "代理": ratio(r[5], nc), "按头名": added},
            "到达 judge 时请求行仍是绝对 URI": {"请求": ratio(r[7], n), "代理": ratio(r[8], nc)},
        }
    return out


# ---------------------------------------------------------------- 重放

def bucket_counts(db, expr, base, edges, labels):
    """按 expr 的值分桶计数；edges 是右开区间的上界（最后一桶无上界）。"""
    cases = []
    lo = None
    for i, e in enumerate(edges):
        cond = ("%s < %r" % (expr, e)) if lo is None else ("%s >= %r AND %s < %r" % (expr, lo, expr, e))
        cases.append("WHEN %s THEN '%s'" % (cond, labels[i]))
        lo = e
    cases.append("ELSE '%s'" % labels[-1])
    return db.counts("SELECT CASE %s END AS b, COUNT(*) %s GROUP BY 1" % (" ".join(cases), base))


def replay(db, exclude_dense):
    """PROTOCOL“重放”。judge 侧按 nonce；归到代理按 nonce 关联 att。"""
    out = {}
    # judge 侧全部（不限窗口、不限是否有 att）：所有 nonce
    n_nonce = db.scalar("SELECT COUNT(*) FROM rq_n")
    n_rep = db.scalar("SELECT COUNT(*) FROM rq_n WHERE copies > 1")
    out["judge 侧（全部 nonce）"] = {
        "不同 nonce": int(n_nonce), "被收到不止一次的 nonce": ratio(n_rep, n_nonce),
        "多收到的份数合计": int(db.scalar("SELECT COALESCE(SUM(copies - 1), 0) FROM rq_n WHERE copies > 1")),
        "份数分布": bucket_counts(db, "copies", "FROM rq_n WHERE copies > 1", [3, 4, 10], ["2", "3", "4 到 9", "10 以上"]),
        "来自几个不同地址": bucket_counts(db, "n_remote", "FROM rq_n WHERE copies > 1", [2, 3], ["1", "2", "3 以上"]),
        "首末两份的间隔（秒）": bucket_counts(db, "(t1 - t0)", "FROM rq_n WHERE copies > 1", [1, 10, 60, 600, 3600],
                                     ["<1", "1 到 10", "10 到 60", "60 到 600", "600 到 3600", "3600 以上"]),
        "最晚一份到达时 nonce 已签发（秒，req.age_s 最大值）": bucket_counts(db, "late", "FROM rq_n WHERE copies > 1", [1, 10, 60, 600, 3600],
                                                              ["<1", "1 到 10", "10 到 60", "60 到 600", "600 到 3600", "3600 以上"]),
        "重放的份里经 TLS 端口到达的": int(db.scalar("SELECT COALESCE(SUM(tls_copies), 0) FROM rq_n WHERE copies > 1") or 0),
        "没有对应 att 的被重放 nonce": int(db.scalar(
            "SELECT COUNT(*) FROM rq_n n LEFT JOIN aj a ON a.nonce = n.nonce WHERE n.copies > 1 AND a.nonce IS NULL")),
    }
    # 归到代理（主口径 summary.go：class=ok、judge 收到、正式起点之后）
    base = "FROM aj a WHERE a.in_win = 1 AND a.cand_kind = 'proxy' AND a.seen = 1" + nd("a", exclude_dense)
    n_seen = db.scalar("SELECT COUNT(*) " + base)
    n_seen_c = db.scalar("SELECT COUNT(DISTINCT a.cand) " + base)
    ok = " AND a.class = 'ok'"
    n_ok = db.scalar("SELECT COUNT(*) " + base + ok)
    n_ok_c = db.scalar("SELECT COUNT(DISTINCT a.cand) " + base + ok)
    r = db.one("SELECT SUM(a.copies > 1), COUNT(DISTINCT CASE WHEN a.copies > 1 THEN a.cand END), SUM(a.copies > 1 AND a.n_remote > 1), "
               "COUNT(DISTINCT CASE WHEN a.copies > 1 AND a.n_remote > 1 THEN a.cand END) " + base + ok)
    r2 = db.one("SELECT SUM(a.copies > 1), COUNT(DISTINCT CASE WHEN a.copies > 1 THEN a.cand END) " + base)
    by_proto = {}
    for proto, n, rep, c, repc in db.q("SELECT a.proto, COUNT(*), SUM(a.copies > 1), COUNT(DISTINCT a.cand), "
                                       "COUNT(DISTINCT CASE WHEN a.copies > 1 THEN a.cand END) " + base + ok + " GROUP BY 1 ORDER BY 1"):
        by_proto[proto] = {"请求": ratio(rep, n), "代理": ratio(repc, c)}
    by_dst = {}
    for dst, n, rep in db.q("SELECT a.dst, COUNT(*), SUM(a.copies > 1) " + base + ok + " GROUP BY 1 ORDER BY 1"):
        by_dst[dst] = ratio(rep, n)
    out["归到代理（class=ok 且 judge 收到）"] = {
        "请求": int(n_ok), "代理": int(n_ok_c),
        "被重放的请求": ratio(r[0], n_ok), "有请求被重放的代理": ratio(r[1], n_ok_c),
        "重放来自别的地址": {"请求": ratio(r[2], n_ok), "代理": ratio(r[3], n_ok_c)},
        "按协议": by_proto, "按目的地（经 TLS 隧道的重放应为 0）": by_dst,
        "首末两份的间隔（秒）": bucket_counts(db, "a.span_s", base + ok + " AND a.copies > 1", [1, 10, 60, 600, 3600],
                                     ["<1", "1 到 10", "10 到 60", "60 到 600", "600 到 3600", "3600 以上"]),
        "最晚一份到达时 nonce 已签发（秒）": bucket_counts(db, "a.late", base + ok + " AND a.copies > 1", [1, 10, 60, 600, 3600],
                                              ["<1", "1 到 10", "10 到 60", "60 到 600", "600 到 3600", "3600 以上"]),
    }
    out["归到代理（judge 收到，不限 class）"] = {"请求": int(n_seen), "代理": int(n_seen_c),
                                      "被重放的请求": ratio(r2[0], n_seen), "有请求被重放的代理": ratio(r2[1], n_seen_c)}
    nodes = db.one("SELECT COUNT(*), SUM(a.copies > 1), COUNT(DISTINCT a.cand), COUNT(DISTINCT CASE WHEN a.copies > 1 THEN a.cand END) "
                   "FROM aj a WHERE a.in_win = 1 AND a.cand_kind = 'node' AND a.seen = 1 AND a.class = 'ok'")
    out["节点（class=ok 且 judge 收到）"] = {"请求": ratio(nodes[1], nodes[0]), "节点": ratio(nodes[3], nodes[2])}
    return out


# ---------------------------------------------------------------- 出口地址

def observer_names(dsts):
    """obs:<名> 里的名字是配置里的观察者名；带点或冒号的可能是主机名，输出前换成按字典序的编号（白名单规则 att.dst）。"""
    out = {}
    for i, dst in enumerate(sorted(dsts)):
        name = dst[4:] if dst.startswith("obs:") else dst
        out[dst] = ("obs_%d" % (i + 1)) if ("." in name or ":" in name or not name) else name
    return out


def egress(db, exclude_dense):
    """PROTOCOL“出口地址”。主口径：代理、class=ok、judge 收到、正式起点之后（summary.go 的 c.egress 只在这种尝试上累积）。"""
    base = "FROM aj a WHERE a.in_win = 1 AND a.cand_kind = 'proxy' AND a.seen = 1" + nd("a", exclude_dense)
    ok = " AND a.class = 'ok'"
    n_ok = db.scalar("SELECT COUNT(*) " + base + ok)
    same = db.scalar("SELECT SUM(a.egress_same) " + base + ok)
    n_seen = db.scalar("SELECT COUNT(*) " + base)
    same_seen = db.scalar("SELECT SUM(a.egress_same) " + base)
    by_proto = {}
    for proto, n, s, c, cs in db.q("SELECT a.proto, COUNT(*), SUM(a.egress_same), COUNT(DISTINCT a.cand), "
                                   "COUNT(DISTINCT CASE WHEN a.egress_same = 0 THEN a.cand END) " + base + ok + " GROUP BY 1 ORDER BY 1"):
        by_proto[proto] = {"与入口相同（请求）": ratio(s, n), "出现过不同出口的代理": ratio(cs, c)}
    # 按代理：相同/不同/混合；不同出口个数
    per = db.counts("""SELECT CASE WHEN mn = 1 THEN '全部相同' WHEN mx = 0 THEN '全部不同' ELSE '有时相同有时不同' END, COUNT(*) FROM (
                       SELECT a.cand, MIN(a.egress_same) mn, MAX(a.egress_same) mx """ + base + ok + " GROUP BY a.cand) GROUP BY 1")
    n_c = sum(per.values())
    distinct = db.counts("""SELECT CASE WHEN k = 1 THEN '1 个出口地址' WHEN k <= 3 THEN '2 到 3 个出口地址' ELSE '4 个以上出口地址' END, COUNT(*)
                            FROM (SELECT a.cand, COUNT(DISTINCT a.remote) k """ + base + ok + " GROUP BY a.cand) GROUP BY 1")
    multi = db.counts("""SELECT CASE WHEN k = 1 THEN '1 个出口地址' WHEN k <= 3 THEN '2 到 3 个出口地址' ELSE '4 个以上出口地址' END, COUNT(*)
                         FROM (SELECT a.cand, COUNT(DISTINCT a.remote) k """ + base + ok + " GROUP BY a.cand HAVING COUNT(*) >= 3) GROUP BY 1")
    n_multi = sum(multi.values())
    # 出口在候选的 /24 里但不是候选 IP（同一机器的另一个地址）：去掉最后一段数字后前缀相同（rtrim 去掉末尾的数字，留下 "a.b.c."）
    same24 = db.scalar("SELECT SUM(a.egress_same = 0 AND rtrim(a.remote, '0123456789') = rtrim(a.cand_ip, '0123456789')) " + base + ok)
    # 回显与日志
    echo = db.one("SELECT COUNT(*), SUM(a.echo_ip != a.remote) " + base + " AND a.echo_ip IS NOT NULL")
    # 两个回显服务 vs 同一探访里 judge 看到的 remote
    obs_base = "FROM ob o WHERE o.in_win = 1 AND o.cand_kind = 'proxy' AND o.class = 'ok' AND o.ip IS NOT NULL" + nd("o", exclude_dense)
    obs = {}
    dsts = [d for (d,) in db.q("SELECT DISTINCT o.dst " + obs_base + " ORDER BY 1")]
    names = observer_names(dsts)
    for dst in dsts:
        r = db.one("""SELECT COUNT(*),
                             SUM(EXISTS (SELECT 1 FROM aj j WHERE j.visit = o.visit AND j.cand = o.cand AND j.seen = 1 AND j.class = 'ok')),
                             SUM(EXISTS (SELECT 1 FROM aj j WHERE j.visit = o.visit AND j.cand = o.cand AND j.seen = 1 AND j.class = 'ok' AND j.remote = o.ip)),
                             SUM(EXISTS (SELECT 1 FROM aj j WHERE j.cand = o.cand AND j.seen = 1 AND j.class = 'ok')),
                             SUM(EXISTS (SELECT 1 FROM aj j WHERE j.cand = o.cand AND j.seen = 1 AND j.class = 'ok' AND j.remote = o.ip)),
                             COUNT(DISTINCT o.cand),
                             COUNT(DISTINCT CASE WHEN EXISTS (SELECT 1 FROM aj j WHERE j.visit = o.visit AND j.cand = o.cand AND j.seen = 1 AND j.class = 'ok')
                                                  AND NOT EXISTS (SELECT 1 FROM aj j WHERE j.visit = o.visit AND j.cand = o.cand AND j.seen = 1 AND j.class = 'ok' AND j.remote = o.ip)
                                                 THEN o.cand END)
                      """ + obs_base + " AND o.dst = ?", (dst,))
        obs[names[dst]] = {
            "成功取回地址的尝试": int(r[0]),
            "同一探访里 judge 也收到过请求": int(r[1] or 0),
            "与同一探访里 judge 看到的出口相同": ratio(r[2], r[1]),
            "与同一探访里 judge 看到的不同": ratio((r[1] or 0) - (r[2] or 0), r[1]),
            "与该代理整个观察期的出口集合比": {"same_ip": int(r[4] or 0), "different_ip": int((r[3] or 0) - (r[4] or 0))},
            "代理": int(r[5]), "出现过不一致的代理": int(r[6] or 0),
        }
    # 两个回显服务之间
    pair = db.one("""SELECT COUNT(*), SUM(k.ip = p.ip) FROM ob k JOIN ob p ON p.visit = k.visit AND p.cand = k.cand AND p.dst > k.dst
                     AND p.class = 'ok' AND p.ip IS NOT NULL
                     WHERE k.in_win = 1 AND k.cand_kind = 'proxy' AND k.class = 'ok' AND k.ip IS NOT NULL""" + nd("k", exclude_dense))
    return {
        "按请求（class=ok 且 judge 收到）": {"请求": int(n_ok), "出口与入口相同": ratio(same, n_ok), "出口与入口不同": ratio((n_ok or 0) - (same or 0), n_ok),
                                   "不同但在入口的同一 /24 里": ratio(same24, (n_ok or 0) - (same or 0)), "按协议": by_proto},
        "按请求（judge 收到，不限 class）": {"请求": int(n_seen), "出口与入口相同": ratio(same_seen, n_seen)},
        "按代理": {"代理": int(n_c), **{k: ratio(per.get(k, 0), n_c) for k in ("全部相同", "全部不同", "有时相同有时不同")}},
        "稳定性（每个代理不同出口地址的个数）": {"代理": int(n_c), **{k: ratio(distinct.get(k, 0), n_c) for k in ("1 个出口地址", "2 到 3 个出口地址", "4 个以上出口地址")},
                                 "只看至少 3 次成功请求的代理": {"代理": int(n_multi), **{k: ratio(multi.get(k, 0), n_multi)
                                                                                for k in ("1 个出口地址", "2 到 3 个出口地址", "4 个以上出口地址")}}},
        "响应头回显的地址 vs judge 日志": {"有回显的请求": int(echo[0] or 0), "不一致（应为 0）": int(echo[1] or 0)},
        "两个回显服务 vs judge": obs,
        "两个回显服务之间（同一探访都成功时）": {"探访": int(pair[0] or 0), "一致": ratio(pair[1], pair[0])},
    }


# 主口径：入口 IP 按时间取最近一次预检（nj.entry_same，build_tables），“本机”用 ips_self（start.judge_ip ∪ NAT 内侧地址）
NODE_CLS = """CASE WHEN a.remote IN (SELECT ip FROM ips_self) THEN '仪器异常：出口是本机'
                 WHEN nj.entry_same = 1 THEN '与入口相同'
                 WHEN nj.entry_same IS NULL OR COALESCE(nj.has_entry_any, 0) = 0 THEN '入口地址未知'
                 ELSE '与入口不同' END"""
# summary.go nodeEgress 的口径：尝试之前最近一次解析出 IP 的预检（之前没有 → 入口地址未知），“本机”只按 c.Judge.PublicIP（start.judge_ip）。
# 与主口径只差两处：本机地址不含 NAT 内侧地址；之前没有预检时不借用之后的。交叉核对用它
NODE_CLS_SUMMARY = """CASE WHEN a.remote IN (SELECT ip FROM ips) THEN '仪器异常：出口是本机'
                         WHEN nj.entry_same_prior = 1 THEN '与入口相同'
                         WHEN COALESCE(nj.has_entry_prior, 0) = 0 THEN '入口地址未知'
                         ELSE '与入口不同' END"""
# 诊断：任意一轮预检解析出的 IP 都算（本机地址同主口径）。与主口径的差异 = 节点域名在观察期内换过地址的影响
NODE_CLS_ANY = """CASE WHEN a.remote IN (SELECT ip FROM ips_self) THEN '仪器异常：出口是本机'
                     WHEN nj.entry_same_any = 1 THEN '与入口相同'
                     WHEN COALESCE(nj.has_entry_any, 0) = 0 THEN '入口地址未知'
                     ELSE '与入口不同' END"""


def nodes_egress(db, info):
    """DEFINITIONS“节点的出口”。主口径按时间取最近预检、本机用 ips_self；另给 summary.go nodeEgress 口径（只差本机地址和“之前没有预检”两处）
    和“任意一轮预检 IP”诊断口径的结果，以及各自与主口径不一致的尝试数。"""
    out = {"入口 IP 的来源": info["npre_source"], "预检解析出的 IP 在观察期内变过的节点": info["nodes_entry_changed"]}
    for dst in ("judge_tls", "judge_http"):
        base = ("FROM aj a LEFT JOIN nj ON nj.rid = a.rid "
                "WHERE a.in_win = 1 AND a.cand_kind = 'node' AND a.seen = 1 AND a.class = 'ok' AND a.dst = ?")
        by_att = db.counts("SELECT %s, COUNT(*) %s GROUP BY 1" % (NODE_CLS, base), (dst,))
        by_node = db.counts("SELECT c, COUNT(*) FROM (SELECT DISTINCT a.cand, %s AS c %s) GROUP BY 1" % (NODE_CLS, base), (dst,))
        by_arm = {}
        for arm, in db.q("SELECT DISTINCT a.arm " + base + " ORDER BY 1", (dst,)):
            by_arm[arm or "null"] = db.counts("SELECT %s, COUNT(*) %s AND a.arm IS ? GROUP BY 1" % (NODE_CLS, base), (dst, arm))
        by_att_sum = db.counts("SELECT %s, COUNT(*) %s GROUP BY 1" % (NODE_CLS_SUMMARY, base), (dst,))
        differ = db.scalar("SELECT COUNT(*) %s AND (%s) != (%s)" % (base, NODE_CLS, NODE_CLS_SUMMARY), (dst,))
        by_att_any = db.counts("SELECT %s, COUNT(*) %s GROUP BY 1" % (NODE_CLS_ANY, base), (dst,))
        differ_any = db.scalar("SELECT COUNT(*) %s AND (%s) != (%s)" % (base, NODE_CLS, NODE_CLS_ANY), (dst,))
        borrowed = db.scalar("SELECT COUNT(*) %s AND nj.pre_rid IS NOT NULL AND nj.pre_rid_prior IS NULL" % base, (dst,))
        n = sum(by_att.values())
        out[dst] = {"尝试": int(n), "按尝试": by_att, "按节点（一个节点可属多类）": by_node, "按分组（arm）": by_arm,
                    "节点": int(db.scalar("SELECT COUNT(DISTINCT a.cand) " + base, (dst,)) or 0),
                    "不同出口个数的分布（按节点）": db.counts("""SELECT CASE WHEN k = 1 THEN '1 个' WHEN k <= 3 THEN '2 到 3 个' ELSE '4 个以上' END, COUNT(*)
                                                    FROM (SELECT a.cand, COUNT(DISTINCT a.remote) k """ + base + " GROUP BY a.cand) GROUP BY 1", (dst,)),
                    "入口取自尝试之后的预检（之前没有解析出 IP 的预检）的尝试": int(borrowed or 0),
                    "summary.go 口径（之前最近一次预检，没有就算入口地址未知；本机只按 start.judge_ip）按尝试": by_att_sum,
                    "与 summary.go 口径判定不一致的尝试": int(differ or 0),
                    "诊断：任意一轮预检 IP 都算的口径 按尝试": by_att_any,
                    "与任意一轮口径判定不一致的尝试（节点域名换过地址的影响）": int(differ_any or 0)}
    return out


# ---------------------------------------------------------------- 仪器不变量

def checks(db, horizon, info, judge_last, probe_last):
    out = {}
    hz = horizon if horizon is not None else -1
    r = db.one("SELECT COUNT(*), COUNT(DISTINCT a.cand) FROM aj a WHERE a.in_win = 1 AND a.class = 'ok' AND a.seen = 0 AND a.ts_epoch < ?", (hz,))
    out["探测器认为成功，但 judge 没收到请求（judge 最后记录前 10 秒之前）"] = {"尝试": int(r[0]), "候选": int(r[1])}
    # judge 进程比探测器先停时，horizon 之后的全部成功尝试都落进这一项，所以标签不能写成“最后 10 秒内”
    out["judge 最后一条记录前 10 秒之后的成功但未收到（含 judge 停止后的时段；不作数，只列出）"] = int(db.scalar(
        "SELECT COUNT(*) FROM aj a WHERE a.in_win = 1 AND a.class = 'ok' AND a.seen = 0 AND a.ts_epoch >= ?", (hz,)))
    out["探测器最后一条 att 晚于 judge 最后一条记录（分钟；明显大于 0 说明 judge 先停了）"] = (
        round((probe_last - judge_last) / 60.0, 1) + 0.0 if (probe_last is not None and judge_last is not None) else None)  # + 0.0 把 -0.0 变成 0.0
    r = db.one("""SELECT COUNT(*), SUM(a.tamper), SUM(a.n_added > 0), SUM(a.fp_base = 0), SUM(a.tamper OR a.n_added > 0 OR a.fp_base = 0),
                         COUNT(DISTINCT CASE WHEN a.tamper OR a.n_added > 0 OR a.fp_base = 0 THEN a.cand END)
                  FROM aj a WHERE a.in_win = 1 AND a.class = 'ok' AND a.seen = 1 AND a.tls_ok = 1 AND a.dst = 'judge_tls'""")
    nb = info["basefp_count"]
    out["TLS 校验通过的请求到达 judge 时与发出时不同（仪器异常，应为 0）"] = {
        "TLS 内成功请求": int(r[0]), "请求头被改": int(r[1] or 0), "多了请求头": int(r[2] or 0),
        "ClientHello 指纹与直连不同": (int(r[3] or 0) if nb > 0 else None),
        "指纹基线": ("对照组 judge_tls 成功尝试到达 judge 时的指纹，%d 种" % nb) if nb > 0
                else "无基线（数据里没有对照组 judge_tls 成功尝试），指纹一项无法判定，不计入“任一”",
        "任一": int(r[4] or 0), "候选": int(r[5] or 0)}
    out["TLS 内的请求 judge 看到的指纹种数"] = int(db.scalar(
        "SELECT COUNT(DISTINCT a.hello_fp) FROM aj a WHERE a.in_win = 1 AND a.seen = 1 AND a.dst = 'judge_tls' AND a.hello_fp IS NOT NULL") or 0)
    # 经 TLS 隧道的正文不符：代理改不了 TLS 里的内容，但能提前断开连接。收到的正文是期望正文的前缀（BodyChange 判“截断”）
    # 是代理断连，不是仪器问题；只有截断以外的不符才是仪器异常
    r = db.one("""SELECT COUNT(*), SUM(p.body_change = ?), COUNT(DISTINCT p.cand)
                  FROM pc p WHERE p.in_win = 1 AND p.dst = 'judge_tls' AND p.http_class = 'http_body_mismatch'""", (BODY_KINDS[0],))
    out["经 TLS 隧道却正文不符"] = {"尝试": int(r[0] or 0), "其中正文被截断（代理提前断开，不是篡改）": int(r[1] or 0),
                              "截断以外的不符（仪器异常，应为 0）": int(r[0] or 0) - int(r[1] or 0), "候选": int(r[2] or 0)}
    out["经 TLS 隧道到达 judge 的请求却在明文端口（req.tls=0）（应为 0）"] = int(db.scalar(
        "SELECT COUNT(*) FROM aj a WHERE a.in_win = 1 AND a.seen = 1 AND a.dst = 'judge_tls' AND a.req_tls = 0") or 0)
    # 明文请求却经 TLS 端口到达：代理自己把 http:// 换成了 https:// 去取（升级到 HTTPS）。这是代理的行为，不是仪器问题，只计数
    r = db.one("SELECT COUNT(*), COUNT(DISTINCT a.cand) FROM aj a WHERE a.in_win = 1 AND a.seen = 1 AND a.dst = 'judge_http' AND a.req_tls = 1")
    out["明文请求却经 TLS 端口到达 judge（代理自行改用 HTTPS 去取）"] = {"尝试": int(r[0] or 0), "候选": int(r[1] or 0)}
    r = db.one("SELECT COUNT(*), COUNT(DISTINCT a.cand), SUM(a.remote IN (SELECT ip FROM ips)) FROM aj a "
               "WHERE a.in_win = 1 AND a.cand_kind = 'node' AND a.seen = 1 AND a.class = 'ok' AND a.remote IN (SELECT ip FROM ips_self)")
    out["节点探测的流量从本机直接出去（仪器异常，应为 0）"] = {
        "尝试": int(r[0]), "节点": int(r[1]), "其中只按 start.judge_ip 就能判出的（summary.go 口径）": int(r[2] or 0),
        "本机地址的口径": "start.judge_ip ∪ judge_remote:control:public ∪ echo:control:public（%d 个地址）" % info["self_egress_ips_count"]}
    r = db.one("SELECT COUNT(*), COUNT(DISTINCT a.cand) FROM aj a WHERE a.in_win = 1 AND a.seen = 1 AND a.echo_ip IS NOT NULL AND a.echo_ip != a.remote")
    out["响应头回显的地址与 judge 日志不一致（应为 0）"] = {"尝试": int(r[0]), "候选": int(r[1])}
    r = db.one("SELECT COUNT(*), SUM(a.seen), SUM(a.tamper), SUM(a.leak), SUM(a.copies > 1) FROM aj a WHERE a.in_win = 1 AND a.cand_kind = 'control' AND a.class = 'ok'")
    out["对照组（直连）"] = {"成功请求": int(r[0]), "judge 收到": int(r[1] or 0), "请求被改（应为 0）": int(r[2] or 0),
                     "带出探测器地址（直连本来就是本机地址，这里只记数）": int(r[3] or 0), "被重放（应为 0）": int(r[4] or 0)}
    out["judge 的叶子证书种数（meta.judge_leaf_observed_count，应为 1）"] = db.meta("judge_leaf_observed_count")
    return out


# ---------------------------------------------------------------- 与 PROTOCOL 预期范围对照

EXPECT_RANGES = {
    "明文正文不符的代理占能转发的代理": ("5% 到 40%（Mani 等按请求 10.5%，Tsirantonakis 等按代理 38%）", 5.0, 40.0),
    "其中属于局部改动的": ("0.5% 到 10%（Mani 等恶意 2.2%，Tsirantonakis 等 5.15%）", 0.5, 10.0),
    "请求头带出客户端地址的代理占能转发的代理": ("30% 到 80%（Mani 等 66%）", 30.0, 80.0),
}


def protocol_expectations(db):
    """PROTOCOL“与文献对账”里本模块能回答的三条预期范围。落在范围之外时按 PROTOCOL 先检查探测器，再谈结论。
    分母“能转发的代理”给两组：EXPECT_ALL 照 PROTOCOL 的定义不限协议，CONNECT 连 80 端口（附加测试 connect_to_port_80）和 SOCKS 隧道里的明文也算；
    EXPECT_FWD 只算 HTTP 转发（proto=forward）——Tsirantonakis 等的对象是 HTTP 代理，隧道代理对 CONNECT/SOCKS 里的字节流不透明、不会改隧道内容，
    把它们计入分母会系统性压低比例，所以与文献比的是这一组。“请求头带出客户端地址的代理”的分母同样取“能转发的代理”，
    分子是 judge 收到过的明文请求（不限 class）里带出探测器地址的代理。EXPECT_ALL 的正文不符与 content.all.按代理 是同一查询。"""
    out = {k: {"预期范围": v[0]} for k, v in EXPECT_RANGES.items()}
    for gname, extra in ((EXPECT_ALL, ""), (EXPECT_FWD, " AND p.proto = 'forward'")):
        base = "FROM pc p WHERE p.in_win = 1 AND p.cand_kind = 'proxy' AND p.dst = 'judge_http'" + extra
        d1 = db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_code = 200")
        c_mis = db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_class = 'http_body_mismatch'")
        c_part = db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.body_change = ?", (BODY_KINDS[1],))
        leak_c = db.scalar("SELECT COUNT(DISTINCT p.cand) FROM aj p WHERE p.in_win = 1 AND p.cand_kind = 'proxy' AND p.dst = 'judge_http' "
                           "AND p.seen = 1 AND p.leak = 1" + extra)
        vals = {"明文正文不符的代理占能转发的代理": ratio(c_mis, d1), "其中属于局部改动的": ratio(c_part, d1),
                "请求头带出客户端地址的代理占能转发的代理": ratio(leak_c, d1)}
        for k, r in vals.items():
            lo, hi = EXPECT_RANGES[k][1], EXPECT_RANGES[k][2]
            out[k][gname] = {"能转发的代理": int(d1 or 0), "结果": r, "在预期范围内": None if r["pct"] is None else (lo <= r["pct"] <= hi)}
    out["与文献可比的一组"] = EXPECT_FWD
    return out


# ---------------------------------------------------------------- 与 summary.json 交叉核对

def crosscheck_summary(db, path):
    """与 fieldtest 自带汇总交叉核对。summary.go 不裁正式起点、findings 把节点也算进候选数，这里照它的口径按整个数据算。
    只读 summary.json 的计数字段；examples 等含地址的字段一概不读。"""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    cmp = {}

    def put(key, want, got):
        cmp[key] = {"summary": want, "computed": got, "match": (want == got)}

    anon = s.get("anonymity") or {}
    mine = db.counts("SELECT anon, COUNT(*) FROM aj WHERE cand_kind = 'proxy' AND proto = 'forward' AND class = 'ok' AND seen = 1 GROUP BY 1")
    for k in ANON_LEVELS:
        if k in anon or k in mine:
            put("anonymity.%s" % k, anon.get(k, 0), mine.get(k, 0))
    eg = s.get("egress") or {}
    mine = db.counts("""SELECT CASE WHEN k = 1 THEN '1 个出口地址' WHEN k <= 3 THEN '2 到 3 个出口地址' ELSE '4 个以上出口地址' END, COUNT(*)
                        FROM (SELECT cand, COUNT(DISTINCT remote) k FROM aj WHERE cand_kind = 'proxy' AND class = 'ok' AND seen = 1 GROUP BY cand) GROUP BY 1""")
    for k in ("1 个出口地址", "2 到 3 个出口地址", "4 个以上出口地址"):
        if k in eg or k in mine:
            put("egress.%s" % k, eg.get(k, 0), mine.get(k, 0))
    ex = s.get("extras") or {}
    ovj = ex.get("observer_vs_judge") or {}
    # summary.go 边读记录边累积每个代理的出口集合（class=ok、目的地 judge、judge 收到），回显服务的尝试只和读到它之前攒下的集合比，
    # 集合还空就不计。记录流的顺序就是 att.rid 的顺序（ingest 按文件名排序逐行编号，与 rec.Files 的顺序相同），所以只取 j.rid < o.rid
    r = db.one("""SELECT SUM(EXISTS (SELECT 1 FROM aj j WHERE j.cand = o.cand AND j.seen = 1 AND j.class = 'ok' AND j.rid < o.rid AND j.remote = o.ip)),
                         SUM(EXISTS (SELECT 1 FROM aj j WHERE j.cand = o.cand AND j.seen = 1 AND j.class = 'ok' AND j.rid < o.rid)
                             AND NOT EXISTS (SELECT 1 FROM aj j WHERE j.cand = o.cand AND j.seen = 1 AND j.class = 'ok' AND j.rid < o.rid AND j.remote = o.ip))
                  FROM ob o WHERE o.cand_kind = 'proxy' AND o.class = 'ok'""")
    for k, v in (("same_ip", r[0]), ("different_ip", r[1])):
        if k in ovj or v:
            put("extras.observer_vs_judge.%s" % k, ovj.get(k, 0), int(v or 0))
    for name, m in ex.items():
        if name.startswith("observer "):
            got = db.counts("SELECT class, COUNT(*) FROM ob WHERE cand_kind = 'proxy' AND dst = ? GROUP BY 1", ("obs:" + name[9:],))
            for cls in m:
                put("extras.%s.%s" % (name, cls), m[cls], got.get(cls, 0))
    for name, cond in (("plain_http_inside_socks", "proto IN ('socks5', 'socks4') AND dst = 'judge_http'"),
                       ("connect_to_port_80", "proto = 'connect' AND dst = 'judge_http'")):
        if name in ex:
            got = db.counts("SELECT class, COUNT(*) FROM att WHERE cand_kind = 'proxy' AND %s AND class NOT LIKE '%%canceled%%' GROUP BY 1" % cond)
            for cls in ex[name]:
                put("extras.%s.%s" % (name, cls), ex[name][cls], got.get(cls, 0))

    # findings：尝试数 / 候选数（含节点；summary.go 的 who 对节点是 "node <id>"，这里 cand 就是节点 id，互不冲突）
    fd = s.get("findings") or {}
    who = "cand_kind IN ('proxy', 'node')"
    F = {}
    F["出口地址与列表里的地址不同"] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE cand_kind = 'proxy' AND class = 'ok' AND seen = 1 AND egress_same = 0")
    F["同一请求被 judge 收到多次（重放）"] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND class = 'ok' AND seen = 1 AND copies > 1" % who)
    F["重放来自别的地址"] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND class = 'ok' AND seen = 1 AND copies > 1 AND n_remote > 1" % who)
    F["请求头被改动"] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND class = 'ok' AND seen = 1 AND tamper = 1" % who)
    F["请求头里带出了探测器的地址"] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND class = 'ok' AND seen = 1 AND leak = 1" % who)
    F["响应头里回显的地址与 judge 日志不一致"] = db.one(
        "SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND class = 'ok' AND seen = 1 AND echo_ip IS NOT NULL AND echo_ip != remote" % who)
    hz = judge_horizon(db)
    F["探测器认为成功，但 judge 没收到请求"] = db.one(
        "SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND class = 'ok' AND seen = 0 AND ts_epoch < ?" % who, (hz if hz is not None else -1,))
    F["仪器异常：TLS 内的请求到达 judge 时与发出时不同"] = db.one(
        "SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND class = 'ok' AND seen = 1 AND tls_ok = 1 AND (tamper = 1 OR n_added > 0 OR fp_base = 0)" % who)
    F["仪器异常：节点探测的流量从本机直接出去了"] = db.one(
        "SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE cand_kind = 'node' AND dst = 'judge_tls' AND class = 'ok' AND seen = 1 AND remote IN (SELECT ip FROM ips)")
    F["正文正确但不是这次请求的应答（缓存或重放）"] = db.one(
        "SELECT COUNT(*), COUNT(DISTINCT cand) FROM pc WHERE %s AND http_class LIKE 'http_canary_%%'" % who)
    F["响应里多出 judge 没发的头"] = db.one(
        "SELECT COUNT(DISTINCT att_rid), COUNT(DISTINCT cand) FROM ad WHERE %s AND class = 'ok' AND dst IN ('judge_http', 'judge_tls')" % who)
    for k in BODY_KINDS:
        F[k] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM pc WHERE %s AND body_change = ?" % who, (k,))
    for (flag,) in db.q("SELECT DISTINCT flag FROM fl"):
        F["响应头被动过: " + flag] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM fl WHERE %s AND flag = ?" % who, (flag,))
    names = set(F) | {k for k in fd if k in F or k.startswith("响应头被动过") or k.startswith("正文被")}
    for name in sorted(names):
        want = fd.get(name)
        got = F.get(name)
        if want is None and got is not None and (got[0] or 0) == 0:
            continue  # 两边都没有
        put("findings.%s.attempts" % name, want.get("attempts", 0) if want else 0, int(got[0] or 0) if got else None)
        put("findings.%s.candidates" % name, want.get("candidates", 0) if want else 0, int(got[1] or 0) if got else None)
    # summary 有、这里没算的 findings（比如中间人，属于别的模块）只列名字
    extra = sorted(k for k in fd if k not in names)
    # 节点出口：summary.go nodeEgress（尝试之前最近一次解析出 IP 的预检，本机只按 start.judge_ip，只统计 judge_tls），不裁窗口
    ne = (s.get("nodes") or {}).get("egress") or {}
    mine = db.counts("""SELECT %s, COUNT(*) FROM aj a LEFT JOIN nj ON nj.rid = a.rid
                        WHERE a.cand_kind = 'node' AND a.dst = 'judge_tls' AND a.class = 'ok' AND a.seen = 1 GROUP BY 1""" % NODE_CLS_SUMMARY)
    for k in ("与入口相同", "与入口不同", "入口地址未知"):
        if k in ne or k in mine:
            put("nodes.egress.%s" % k, ne.get(k, 0), mine.get(k, 0))
    jd = s.get("judge") or {}
    if "req" in jd:
        put("judge.req（judge 每 2 秒落盘，summary 可能少几条）", jd["req"], int(db.scalar("SELECT COUNT(*) FROM req")))
    return {"summary_generated": s.get("generated"), "comparisons": cmp,
            "matched": sum(1 for v in cmp.values() if v["match"]), "total": len(cmp),
            "mismatches": sorted(k for k, v in cmp.items() if not v["match"]),
            "summary_findings_not_covered_here": extra}


# ---------------------------------------------------------------- 输出前的断言

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?!\d|\.\d|/24)")
HOSTPORT_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}:\d{1,5}")
HEX12_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{12,}(?![0-9a-fA-F])")


def assert_clean(text, db):
    """最后一道保险：输出文本里不许有 ip:port、不带 /24 的 IPv4、judge 的主机名或 IP、长十六进制串（nonce、哈希、节点 id）。"""
    bad = []
    if HOSTPORT_RE.search(text):
        bad.append("ip:port")
    if IPV4_RE.search(text):
        bad.append("不带 /24 的 IPv4")
    if HEX12_RE.search(text):
        bad.append("长十六进制串（哈希/nonce/节点 id）")
    for table, col in (("self_names", "name"), ("self_ips", "ip")):
        if db.has_table(table):
            for (v,) in db.q("SELECT DISTINCT %s FROM %s" % (col, table)):
                if v and v.lower() in text.lower():
                    bad.append("judge 身份（%s）" % table)
                    break
    for literal in ("@",):  # judge 的名字和地址只从库里的 self_names / self_ips 取（上面已查），源码里不写
        if literal in text:
            bad.append("字面量 %s" % literal)
    if bad:
        raise SystemExit("输出含不许出现的内容：%s；已拒绝写出" % "、".join(bad))


# ---------------------------------------------------------------- Markdown

def print_markdown(res):
    w = res["window"]
    print("### 观察窗口与分母\n")
    print(f"- 正式起点 {w['formal_start_utc']}（{w['formal_start_rule']}），结束 {w['end_utc']}，共 {fmt(w['hours'])} 小时；"
          f"正式起点之前的试运行尝试 {fmt(w['trial_run_attempts_before_formal_start'])} 条"
          + (f"。**超出 72 小时 {fmt(w['hours_beyond_72'])} 小时**（{fmt(w['attempts_after_72h'])} 条尝试），主口径没有裁上界，报告里要写明实际时长"
             if (w.get("hours_beyond_72") or 0) > 0 else ""))
    n = res["n"]
    print(f"- 到达 HTTP 阶段并带 nonce 的 judge 尝试 {fmt(n['到达 HTTP 阶段并带 nonce、目的地 judge 的尝试（aj，正式起点之后）'])}，judge 收到 {fmt(n['其中 judge 收到'])}；"
          f"明文响应 200 的尝试 {fmt(n['明文响应 200 的尝试（代理）'])}；能转发的代理 {fmt(n['能转发的代理（至少一次明文响应 200）'])}，"
          f"端到端可用过的代理 {fmt(n['端到端可用过的代理（任一协议 class=ok 到 judge）'])}；judge 收到 {fmt(n['judge 收到的请求（req 记录）'])} 条 req、"
          f"{fmt(n['judge 收到的不同 nonce'])} 个 nonce；密集 /24 {fmt(n['候选密集的 /24 个数'])} 个")

    print("\n### 内容被改（明文、代理）\n")
    print("| 口径 | 分母 | 正文不符 | 截断 | 局部改动（篡改） | 整页替换 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        c = res["content"][key]
        r = c["按请求"]
        print(f"| {label}·按请求 | 明文响应 200：{fmt(r['明文响应 200'])} | {rfmt(r['正文不符（全部）'])} | {rfmt(r['正文被截断'])} | "
              f"{rfmt(r['正文被局部改动（注入或改写）'])} | {rfmt(r['正文被整页替换'])} |")
        p = c["按代理"]
        k = p["各类（一个代理可属多类）"]
        print(f"| {label}·按代理 | 能转发的代理：{fmt(p['能转发的代理（至少一次明文响应 200）'])} | {rfmt(p['正文不符的代理（占能转发的）'])} | "
              f"{rfmt(k['正文被截断'])} | {rfmt(k['正文被局部改动（注入或改写）'])} | {rfmt(k['正文被整页替换'])} |")
    c = res["content"]["all"]
    print("\n| 载荷 | 明文响应 200 | 正文不符 | 局部改动 | 期望长度 |")
    print("| --- | --- | --- | --- | --- |")
    for kind, v in c["按请求"]["按载荷种类"].items():
        print(f"| {kind} | {fmt(v['明文响应 200'])} | {rfmt(v['正文不符'])} | {rfmt(v['正文被局部改动（注入或改写）'])} | {fmt(v['期望长度'])} |")
    g = c["gzip"]
    print(f"\n- gzip：代理加了 gzip {fmt(g[GZ_ALL]['尝试'])} 次 / {fmt(g[GZ_ALL]['代理'])} 个代理；解开后正文相同 {fmt(g[GZ_SAME]['尝试'])} 次 / "
          f"{fmt(g[GZ_SAME]['代理'])} 个代理（其中金丝雀缺失或不符 {fmt(g[GZ_CANARY]['尝试'])} 次）；解开后仍不符 {fmt(g[GZ_MIS]['尝试'])} 次")
    cc = c["正文正确但不是这次请求的应答（缓存或伪造）"]
    print(f"- 正文正确但金丝雀不符（缓存或伪造）：{rfmt(cc['占明文响应 200'])}，{fmt(cc['代理'])} 个代理")

    rh = res["response_headers"]["all"]
    print("\n### 响应头被动过（代理，class=ok）\n")
    print("| 标记 | 尝试 | 代理 | 代理占端到端可用过的 |")
    print("| --- | --- | --- | --- |")
    for flag, v in rh["标记（按标记）"].items():
        print(f"| {flag} | {fmt(v['尝试'])} | {fmt(v['代理'])} | {rfmt(v['代理占端到端可用过的'])} |")
    print(f"\n- 多出 judge 没发的头：{rfmt(rh['多出 judge 没发的头（任一）']['代理'])} 个代理；按头名："
          + "、".join(f"{h} {fmt(v.get('代理', v.get('代理（按头名分别计，可重复）')))}" for h, v in rh["多出 judge 没发的头（按头名）"].items()))

    print("\n### 匿名程度（derive.go 规则）\n")
    print("| 口径 | 范围 | 请求/代理 | 透明 | 匿名 | 高匿 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        for scope in ("forward_ok", "plain_ok"):
            a = res["anonymity"][key][scope]
            r, p = a["按请求"], a["按代理（取最差）"]
            print(f"| {label} | {scope} | 请求 {fmt(r['请求'])} | {rfmt(r[ANON_ZH['transparent']])} | {rfmt(r[ANON_ZH['anonymous']])} | {rfmt(r[ANON_ZH['elite']])} |")
            print(f"| {label} | {scope} | 代理 {fmt(p['代理'])} | {rfmt(p[ANON_ZH['transparent']])} | {rfmt(p[ANON_ZH['anonymous']])} | {rfmt(p[ANON_ZH['elite']])} |")
    t = res["request_tamper"]["all"]["plain_ok"]
    print(f"\n- 请求被改（全部明文、class=ok）：请求 {rfmt(t['请求被改（任一项）']['请求'])}，代理 {rfmt(t['请求被改（任一项）']['代理'])}；各项："
          + ("、".join(f"{k} {fmt(v['请求'])}/{fmt(v['代理'])}" for k, v in t["各项（一个请求可有多项）"].items()) or "无"))
    print(f"- 带出探测器地址：请求 {rfmt(t['请求头里带出探测器地址']['请求'])}，代理 {rfmt(t['请求头里带出探测器地址']['代理'])}；"
          f"代理加了请求头：代理 {rfmt(t['代理加了请求头']['代理'])}，按头名 "
          + ("、".join(f"{k} {fmt(v['请求'])}" for k, v in t["代理加了请求头"]["按头名"].items()) or "无"))

    rp = res["replay"]["all"]
    j = rp["judge 侧（全部 nonce）"]
    print("\n### 重放\n")
    print(f"- judge 侧：{fmt(j['不同 nonce'])} 个 nonce 里 {rfmt(j['被收到不止一次的 nonce'])} 被收到不止一次；份数分布 {j['份数分布']}；"
          f"来自几个地址 {j['来自几个不同地址']}；首末间隔（秒）{j['首末两份的间隔（秒）']}；最晚一份的 nonce 年龄（秒）{j['最晚一份到达时 nonce 已签发（秒，req.age_s 最大值）']}")
    p = rp["归到代理（class=ok 且 judge 收到）"]
    print(f"- 归到代理：请求 {rfmt(p['被重放的请求'])}，代理 {rfmt(p['有请求被重放的代理'])}；来自别的地址：代理 {rfmt(p['重放来自别的地址']['代理'])}")

    eg = res["egress"]["all"]
    print("\n### 出口地址（代理，class=ok 且 judge 收到）\n")
    r = eg["按请求（class=ok 且 judge 收到）"]
    print(f"- 按请求：与入口相同 {rfmt(r['出口与入口相同'])}，不同 {rfmt(r['出口与入口不同'])}（其中在入口的同一 /24 里 {rfmt(r['不同但在入口的同一 /24 里'])}）")
    print("- 按协议：" + "、".join(f"{k} 相同 {rfmt(v['与入口相同（请求）'])}" for k, v in r["按协议"].items()))
    p = eg["按代理"]
    print(f"- 按代理：{fmt(p['代理'])} 个；全部相同 {rfmt(p['全部相同'])}，全部不同 {rfmt(p['全部不同'])}，有时相同有时不同 {rfmt(p['有时相同有时不同'])}")
    s = eg["稳定性（每个代理不同出口地址的个数）"]
    print(f"- 稳定性：1 个 {rfmt(s['1 个出口地址'])}，2 到 3 个 {rfmt(s['2 到 3 个出口地址'])}，4 个以上 {rfmt(s['4 个以上出口地址'])}")
    for name, o in eg["两个回显服务 vs judge"].items():
        print(f"- 回显服务 {name}：与同一探访里 judge 看到的相同 {rfmt(o['与同一探访里 judge 看到的出口相同'])}，不同 {rfmt(o['与同一探访里 judge 看到的不同'])}")
    pr = eg["两个回显服务之间（同一探访都成功时）"]
    print(f"- 两个回显服务之间一致：{rfmt(pr['一致'])}；回显头 vs 日志不一致 {fmt(eg['响应头回显的地址 vs judge 日志']['不一致（应为 0）'])}")
    ne = res["nodes_egress"].get("judge_tls", {})
    print(f"- 节点（judge_tls）：{ne.get('按尝试')}")

    print("\n### 与 PROTOCOL 预期范围对照\n")
    print("| 指标 | 全部协议 | 在范围内 | 只算 HTTP 转发（与文献可比） | 在范围内 | 预期范围 |")
    print("| --- | --- | --- | --- | --- | --- |")
    yn = lambda b: "是" if b else ("—" if b is None else "否")  # noqa: E731
    for k, v in res["protocol_expectations"].items():
        if not isinstance(v, dict):
            continue
        a, f = v[EXPECT_ALL], v[EXPECT_FWD]
        print(f"| {k} | {rfmt(a['结果'])} | {yn(a['在预期范围内'])} | {rfmt(f['结果'])} | {yn(f['在预期范围内'])} | {v['预期范围']} |")
    ck = res["checks"]
    print("\n### 仪器不变量\n")
    for k, v in ck.items():
        print(f"- {k}：{v}")
    if "crosscheck" in res:
        x = res["crosscheck"]
        print(f"\n### 与 summary.json 交叉核对：{x['matched']}/{x['total']} 项一致"
              + (f"；不一致：{', '.join(x['mismatches'])}" if x["mismatches"] else ""))
    pa = res["plan_audit"]
    print(f"\n- 查询计划自检：{fmt(pa['查询数'])} 条查询，相关子查询里顺序扫描大表的 {fmt(len(pa['相关子查询里顺序扫描大表的查询（应为空）']))} 条")


# ---------------------------------------------------------------- 主流程

def run(db_path, out_dir, summary_path=None, dense_threshold=DENSE_THRESHOLD, formal_start="auto", markdown=False, write=True):
    db = DB(db_path)
    wl_source = check_whitelist(db)
    for t in ("att", "req", "req_header", "att_http_flag", "att_http_added"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表" % t)
    win = observation_window(db, formal_start)
    fs, end = win.pop("_fs"), win.pop("_end")
    if fs is None:
        raise SystemExit("库里没有任何尝试记录")
    plen, plen_src = payload_lengths(db)
    info = build_tables(db, fs, dense_threshold, plen)
    horizon = judge_horizon(db)
    judge_last = judge_last_ts(db)
    probe_last = db.scalar("SELECT MAX(ts_epoch) FROM att")

    res = {
        "module": MODULE, "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol_version": "1.2", "whitelist_source": wl_source, "dense_threshold": dense_threshold,
        "db_meta": {k: db.meta(k) for k in ("ingest_version", "first_ts", "last_ts", "state_tz_offsets")},
        "definitions": DEFINITIONS, "window": win,
        "payload_expected_len": {"len": plen, "source": plen_src},
    }
    res["n"] = denominators(db, info)
    res["content"] = {"all": content_modification(db, False, plen, plen_src), "excluding_dense": content_modification(db, True, plen, plen_src)}
    res["response_headers"] = {"all": response_headers(db, False), "excluding_dense": response_headers(db, True)}
    res["anonymity"] = {"all": anonymity(db, False), "excluding_dense": anonymity(db, True)}
    res["request_tamper"] = {"all": request_tamper(db, False), "excluding_dense": request_tamper(db, True)}
    res["replay"] = {"all": replay(db, False), "excluding_dense": replay(db, True)}
    res["egress"] = {"all": egress(db, False), "excluding_dense": egress(db, True)}
    res["nodes_egress"] = nodes_egress(db, info)
    res["checks"] = checks(db, horizon, info, judge_last, probe_last)
    res["protocol_expectations"] = protocol_expectations(db)
    if summary_path:
        res["crosscheck"] = crosscheck_summary(db, summary_path)
    # 查询计划自检放在最后，连交叉核对的查询一起复查
    res["plan_audit"] = db.plan_audit()
    if res["plan_audit"]["相关子查询里顺序扫描大表的查询（应为空）"]:
        print("警告：%d 条查询在相关子查询里顺序扫描大表（真实数据上会随记录数平方增长），见输出的 plan_audit"
              % len(res["plan_audit"]["相关子查询里顺序扫描大表的查询（应为空）"]), file=sys.stderr)

    text = json.dumps(res, ensure_ascii=False, indent=1, sort_keys=False)
    try:
        assert_clean(text, db)
    finally:
        db.con.close()   # 释放只读连接上的共享锁（同一进程里随后要写这个库的调用方，比如自检和复现脚本）
    if write:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "integrity.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("已写出 %s（%d 字节）" % (path, len(text.encode("utf-8"))), file=sys.stderr)
    if markdown:
        print_markdown(res)
    return res


# ---------------------------------------------------------------- 自检：合成库

def _synthetic_db(path, with_control=True, nat=False):
    """最小合成库，覆盖主要分支。地址用 TEST-NET（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）。
    索引照 ingest.py 建（计划自检要在和真实库一样的索引上做）。with_control=False：没有对照组（指纹基线为空）；
    nat=True：judge 看到的本机回访公网地址的源地址是 NAT 内侧地址，节点 4 的出口是它。"""
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE att (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, kind TEXT, arm TEXT,
        nonce TEXT, tls_ok INTEGER, class TEXT, http_class TEXT, http_code INTEGER, http_len INTEGER, http_pre INTEGER, http_suf INTEGER,
        http_sim INTEGER, http_canary TEXT, http_ev TEXT, ip TEXT, cand_kind TEXT, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
    CREATE INDEX att_nonce ON att(nonce); CREATE INDEX att_cand_ts ON att(cand, ts_epoch); CREATE INDEX att_ts ON att(ts_epoch);
    CREATE INDEX att_prefix24 ON att(prefix24); CREATE INDEX att_visit ON att(visit);
    CREATE TABLE att_http_flag (rid INTEGER PRIMARY KEY, att_rid INTEGER, flag TEXT);
    CREATE INDEX att_flag_att ON att_http_flag(att_rid);
    CREATE TABLE att_http_added (rid INTEGER PRIMARY KEY, att_rid INTEGER, header TEXT);
    CREATE INDEX att_added_att ON att_http_added(att_rid);
    CREATE TABLE req (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, remote TEXT, rport INTEGER, tls INTEGER, hello_fp TEXT, method TEXT,
        target TEXT, nonce TEXT, age_s INTEGER, kind TEXT, req_canary TEXT, status INTEGER);
    CREATE INDEX req_nonce ON req(nonce); CREATE INDEX req_ts ON req(ts_epoch); CREATE INDEX req_remote ON req(remote);
    CREATE TABLE req_header (rid INTEGER PRIMARY KEY, req_rid INTEGER, nonce TEXT, seq INTEGER, name TEXT, value TEXT);
    CREATE INDEX req_header_req ON req_header(req_rid); CREATE INDEX req_header_name ON req_header(name);
    CREATE TABLE self_ips (ip TEXT NOT NULL, source TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (ip, source));
    CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE cands (rid INTEGER PRIMARY KEY, key TEXT, ip TEXT, port INTEGER, prefix24 TEXT);
    CREATE TABLE npre (rid INTEGER PRIMARY KEY, ts_epoch REAL, round INTEGER, node TEXT, n_ips INTEGER);
    CREATE INDEX npre_node_round ON npre(node, round); CREATE INDEX npre_ts ON npre(ts_epoch);
    CREATE TABLE npre_ip (rid INTEGER PRIMARY KEY, npre_rid INTEGER, node TEXT, round INTEGER, seq INTEGER, ip TEXT);
    CREATE INDEX npre_ip_node ON npre_ip(node);
    CREATE TABLE start (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER);
    CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL);
    CREATE TABLE version (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, version TEXT);
    CREATE TABLE evidence (hash TEXT, ext TEXT, bytes INTEGER, path TEXT, PRIMARY KEY (hash, ext));
    """)
    T0 = parse_iso("2026-11-06T00:00:00Z")
    SELF = "192.0.2.250"
    NATIP = "192.0.2.77"
    con.execute("INSERT INTO self_ips VALUES (?, 'start.judge_ip', 1)", (SELF,))
    con.execute("INSERT INTO self_ips VALUES (?, 'judge_remote:control:public', 1)", (NATIP if nat else SELF,))
    con.execute("INSERT INTO self_ips VALUES (?, 'echo:control:public', 1)", (SELF,))
    con.execute("INSERT INTO self_ips VALUES ('127.0.0.1', 'judge_remote:control:loopback', 1)")
    con.execute("INSERT INTO self_names VALUES ('judge.example', 'start.judge_host', 1)")
    con.execute("INSERT INTO meta VALUES ('payload_len', ?)", (json.dumps({"h": {"len": 2704}, "j": {"len": 1306}, "b": {"len": 32768}}),))
    con.execute("INSERT INTO meta VALUES ('judge_leaf_observed_count', '1')")
    con.execute("INSERT INTO start VALUES (1, NULL, ?, 0)", (T0,))
    con.execute("INSERT INTO version VALUES (1, NULL, ?, 'test')", (T0,))
    con.execute("INSERT INTO stop VALUES (1, NULL, ?)", (T0 + 7200,))
    con.execute("INSERT INTO evidence VALUES ('e1', 'body', 10, 'x')")

    PN, PD = "198.51.100.0/24", "203.0.113.0/24"
    A, B, C, E, F = "198.51.100.1:8080", "198.51.100.2:3128", "198.51.100.3:8080", "198.51.100.4:1080", "198.51.100.5:8080"
    D1 = "203.0.113.1:8080"
    for k in (A, B, C, E, F):
        ip, port = k.split(":")
        con.execute("INSERT INTO cands (key, ip, port, prefix24) VALUES (?, ?, ?, ?)", (k, ip, int(port), PN))
    for i in range(1, 102):  # 密集 /24：101 个候选
        con.execute("INSERT INTO cands (key, ip, port, prefix24) VALUES (?, ?, ?, ?)", ("203.0.113.%d:8080" % i, "203.0.113.%d" % i, 8080, PD))

    rid = [0]

    def att(t, visit, cand, proto, dst, cls, kind="h", nonce=None, http_code=None, http_class=None, ln=None, pre=None, suf=None, sim=None,
            canary=None, ev=None, ip=None, tls_ok=None, arm=None, flags=(), added=()):
        rid[0] += 1
        if cand.startswith("control:"):
            ck, cip, p24 = "control", None, None
        elif ":" in cand:
            ck, cip, p24 = "proxy", cand.split(":")[0], ".".join(cand.split(":")[0].split(".")[:3]) + ".0/24"
        else:
            ck, cip, p24 = "node", None, None
        # 真实库里 class=ok 的 att 的 http_class 是 NULL（wire.Step 成功时省略 class），合成库照此
        hc = http_class or (cls if (http_code and cls != "ok") else None)
        con.execute("INSERT INTO att VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid[0], None, t, visit, cand, proto, dst, kind, arm, nonce, tls_ok, cls, hc,
                     http_code, ln, pre, suf, sim, canary, ev, ip, ck, cip, None, p24))
        for f in flags:
            con.execute("INSERT INTO att_http_flag (att_rid, flag) VALUES (?, ?)", (rid[0], f))
        for h in added:
            con.execute("INSERT INTO att_http_added (att_rid, header) VALUES (?, ?)", (rid[0], h))
        return rid[0]

    rrid = [0]
    STD = [("Accept", SENT_HEADERS["Accept"]), ("Accept-Encoding", "identity"), ("Accept-Language", "en-US,en;q=0.9"),
           ("Connection", "close"), ("User-Agent", SENT_HEADERS["User-Agent"])]

    def req(t, nonce, remote, canary="ok", tls=0, fp=None, method="GET", age=0, extra=(), ua=None, cookie=True, canary_hdr=True, target="/p/h/x", tail=()):
        rrid[0] += 1
        con.execute("INSERT INTO req VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rrid[0], None, t, remote, 12345, tls or None, fp, method, target, nonce, age or None, "h", canary, 200))
        hdrs = [(k, v) for k, v in STD]
        if ua is not None:
            hdrs = [(k, (ua if k == "User-Agent" else v)) for k, v in hdrs]
        if cookie:
            hdrs.append(("Cookie", "pc=deadbeefcafe0001"))
        if canary_hdr:
            hdrs.append(("X-Probe-Canary", "deadbeefcafe0001"))
        hdrs += list(extra)
        # tail 不参与排序、排在最后：用来造同名头重复、后一个值字典序更小的情况
        for i, (k, v) in enumerate(sorted(hdrs) + list(tail)):
            con.execute("INSERT INTO req_header (req_rid, nonce, seq, name, value) VALUES (?, ?, ?, ?, ?)", (rrid[0], nonce, i, k, v))

    t = T0 + 60
    # 对照组：指纹基线（with_control=False 时没有，基线为空）
    if with_control:
        att(t, "vc1", "control:loopback", "direct", "judge_tls", "ok", nonce="c1", http_code=200, canary="ok", tls_ok=1, ip=SELF)
        req(t, "c1", SELF, tls=1, fp="basefp")
        att(t, "vc1", "control:loopback", "direct", "judge_http", "ok", nonce="c2", http_code=200, canary="ok", ip=SELF)
        req(t, "c2", SELF)
        att(t, "vc2", "control:public", "direct", "judge_tls", "ok", nonce="c3", http_code=200, canary="ok", tls_ok=1, ip=SELF)
        req(t, "c3", SELF, tls=1, fp="basefp")
    # 试运行（正式起点之前）：A 一次成功
    att(T0 - 3600, "vt", A, "forward", "judge_http", "ok", nonce="t1", http_code=200, canary="ok", ip="198.51.100.1")
    req(T0 - 3600, "t1", "198.51.100.1")
    # A：各类正文改动
    t = T0 + 120
    att(t, "va", A, "forward", "judge_http", "ok", nonce="n1", http_code=200, canary="ok", ip="198.51.100.1")
    # Accept 头出现两次，后一个是 */*：derive.go 取最后一个 → accept_changed；按字典序取最大会取到原值、漏判
    req(t, "n1", "198.51.100.1", tail=[("Accept", "*/*")])
    att(t, "va", A, "forward", "judge_http", "http_body_mismatch", nonce="n2", http_code=200, ln=2700, pre=2000, suf=10, sim=95, ev="e1")
    req(t, "n2", "198.51.100.1")
    att(t, "va", A, "forward", "judge_http", "http_body_mismatch", kind="j", nonce="n3", http_code=200, ln=500, pre=500, sim=30, ev="e2")
    req(t, "n3", "198.51.100.1")
    att(t, "va", A, "forward", "judge_http", "http_body_mismatch", kind="b", nonce="n4", http_code=200, ln=113, sim=0, ev="e3")
    req(t, "n4", "198.51.100.1")
    att(t, "va", A, "forward", "judge_http", "ok", nonce="n5", http_code=200, canary="ok", ip="198.51.100.1", flags=["gzip_added"], added=["Content-Encoding"])
    req(t, "n5", "198.51.100.1")
    att(t, "va", A, "forward", "judge_http", "http_body_mismatch", nonce="n6", http_code=200, ln=2704, pre=100, sim=10, flags=["gzip_added"])
    req(t, "n6", "198.51.100.1")
    # B：透明、改了 UA、重放、出口不同、两个出口；回显服务一同一异
    t = T0 + 180
    xff = [("X-Forwarded-For", SELF), ("Via", "1.1 proxy")]
    att(t, "vb1", B, "forward", "judge_http", "ok", nonce="m1", http_code=200, canary="ok", ip="198.51.100.22")
    req(t, "m1", "198.51.100.22", extra=xff, ua="curl/8.0")
    req(t + 30, "m1", "198.51.100.22", extra=xff, ua="curl/8.0", age=30)
    req(t + 60, "m1", "198.51.100.23", extra=xff, ua="curl/8.0", age=60)
    att(t, "vb1", B, "connect", "obs:kv", "ok", kind=None, http_code=200, ip="198.51.100.22")
    att(t, "vb1", B, "connect", "obs:plain", "ok", kind=None, http_code=200, ip="198.51.100.99")
    # 回显服务排在同一探访的 judge 之前：整个观察期的出口集合里有 .24（相同），记录流到这里只攒了 .22（summary.go 记为不同）
    att(t + 600, "vb2", B, "connect", "obs:kv", "ok", kind=None, http_code=200, ip="198.51.100.24")
    att(t + 600, "vb2", B, "forward", "judge_http", "ok", nonce="m2", http_code=200, canary="ok", ip="198.51.100.24")
    req(t + 600, "m2", "198.51.100.24", extra=xff, ua="curl/8.0")
    # C：匿名（只有 Via）、金丝雀与 Cookie 缺失、响应头 CSP/Cookie 被删、多了 Via/X-Cache；一次金丝雀不符
    t = T0 + 240
    att(t, "vc", C, "forward", "judge_http", "ok", nonce="k1", http_code=200, canary="ok", ip="198.51.100.3",
        flags=["csp_missing", "cookie_missing"], added=["Via", "X-Cache"])
    req(t, "k1", "198.51.100.3", canary="missing", extra=[("Via", "1.1 cache")], cookie=False, canary_hdr=False)
    att(t, "vc", C, "forward", "judge_http", "http_canary_bad", nonce="k2", http_code=200, ln=2704, canary="bad")
    req(t, "k2", "198.51.100.3")
    # 加了 gzip、解开后正文相同、但金丝雀不符：PROTOCOL 口径下属于“解开后内容相同”，不算内容被改
    att(t, "vc", C, "forward", "judge_http", "http_canary_bad", nonce="k3", http_code=200, ln=2704, canary="bad", flags=["gzip_added"])
    req(t, "k3", "198.51.100.3")
    # E：SOCKS5，TLS 隧道；一次指纹异常；一次 judge 没收到；一次回显与日志不一致
    t = T0 + 300
    att(t, "ve", E, "socks5", "judge_tls", "ok", nonce="s1", http_code=200, canary="ok", tls_ok=1, ip="198.51.100.4")
    req(t, "s1", "198.51.100.4", tls=1, fp="basefp")
    att(t, "ve", E, "socks5", "judge_tls", "ok", nonce="s2", http_code=200, canary="ok", tls_ok=1, ip="198.51.100.4")
    req(t, "s2", "198.51.100.4", tls=1, fp="otherfp")
    att(t, "ve", E, "socks5", "judge_http", "ok", nonce="s3", http_code=200, canary="ok", ip="198.51.100.4")
    req(t, "s3", "198.51.100.4")
    att(t, "ve", E, "socks5", "judge_tls", "ok", nonce="s4", http_code=200, canary="ok", tls_ok=1, ip="198.51.100.4")  # judge 没收到
    att(t, "ve", E, "socks5", "judge_tls", "ok", nonce="s5", http_code=200, canary="ok", tls_ok=1, ip="198.51.100.4")
    req(t, "s5", "198.51.100.44", tls=1, fp="basefp")  # 回显说 .4，日志说 .44
    # F：只收到 403，没到 judge
    att(T0 + 360, "vf", F, "forward", "judge_http", "http_status", nonce="f1", http_code=403)
    # D1：密集 /24 里的代理，一次局部改动、一次正确
    t = T0 + 420
    att(t, "vd", D1, "forward", "judge_http", "http_body_mismatch", nonce="d1", http_code=200, ln=2704, pre=2600, sim=97)
    req(t, "d1", "203.0.113.1")
    att(t, "vd", D1, "forward", "judge_http", "ok", nonce="d2", http_code=200, canary="ok", ip="203.0.113.1")
    req(t, "d2", "203.0.113.1")
    # 节点。预检按轮次记进 npre/npre_ip。节点 2 的域名在第 2 轮换了地址（.72 → .82），尝试在第 2 轮之后：
    # 按时间取最近预检 → 与入口不同；summary.go 的任意一轮口径 → 与入口相同（两种口径不一致 1 次）。
    # 节点 3 预检没解析出 IP → 入口地址未知。节点 4 的出口是本机（nat=True 时是 NAT 内侧地址，只有 ips_self 才能判出）。
    # 节点 5 唯一一次预检在尝试之后：主口径借用它 → 与入口相同；summary.go 口径 → 入口地址未知
    prid = [0]

    def npre(tt, node, rnd, ips):
        prid[0] += 1
        con.execute("INSERT INTO npre (rid, ts_epoch, round, node, n_ips) VALUES (?, ?, ?, ?, ?)", (prid[0], tt, rnd, node, len(ips)))
        for i, ip in enumerate(ips):
            con.execute("INSERT INTO npre_ip (npre_rid, node, round, seq, ip) VALUES (?, ?, ?, ?, ?)", (prid[0], node, rnd, i, ip))
    npre(T0 + 400, "aaaaaaaaaaa1", 1, ["198.51.100.71"])
    npre(T0 + 400, "aaaaaaaaaaa2", 1, ["198.51.100.72"])
    npre(T0 + 470, "aaaaaaaaaaa2", 2, ["198.51.100.82"])
    npre(T0 + 400, "aaaaaaaaaaa3", 1, [])
    npre(T0 + 400, "aaaaaaaaaaa4", 1, ["198.51.100.84"])
    npre(T0 + 500, "aaaaaaaaaaa5", 1, ["198.51.100.85"])
    t = T0 + 480
    for nid, remote in (("aaaaaaaaaaa1", "198.51.100.71"), ("aaaaaaaaaaa2", "198.51.100.72"),
                        ("aaaaaaaaaaa3", "198.51.100.73"), ("aaaaaaaaaaa4", NATIP if nat else SELF),
                        ("aaaaaaaaaaa5", "198.51.100.85")):
        att(t, "vn" + nid[-1], nid, "node", "judge_tls", "ok", nonce="x" + nid[-1], http_code=200, canary="ok", tls_ok=1, arm="strict", ip=remote)
        req(t, "x" + nid[-1], remote, tls=1, fp="basefp")
    att(t, "vn1", "aaaaaaaaaaa1", "node", "obs:kv", "ok", kind=None, http_code=200, ip="198.51.100.71", arm="strict")
    # judge 最后一条记录放在最后，保证 horizon 在上面所有尝试之后
    req(T0 + 7000, "zz", "198.51.100.1")
    con.commit()
    con.close()


def selftest():
    tmp = tempfile.mkdtemp(prefix="m_integrity_selftest_")
    db_path = os.path.join(tmp, "synthetic.sqlite")
    _synthetic_db(db_path)
    failures = []
    # 头名门槛与形状：少于门槛、形状不规则（含点号的数字片段）的合并进“其他”
    nt = name_table([("Via", 5, 3), ("X-Rare", 2, 1), ("X-Foo-192.0.2.1", 4, 9)], "尝试", min_proxies=3)
    if set(nt) != {"Via", "其他（形状不规则或少于 3 个代理的头名）"} or nt["其他（形状不规则或少于 3 个代理的头名）"]["种数"] != 2:
        failures.append("name_table 门槛/形状：%r" % nt)
    global HEADER_MIN_PROXIES
    HEADER_MIN_PROXIES = 1   # 合成库代理少：自检里关掉“至少 3 个代理”的门槛，核对的是计数本身（门槛已在上面单独核对）
    fake_summary = os.path.join(tmp, "summary.json")
    with open(fake_summary, "w", encoding="utf-8") as f:
        json.dump({"extras": {"observer_vs_judge": {"same_ip": 1, "different_ip": 2}}}, f)
    res = run(db_path, os.path.join(tmp, "out"), summary_path=fake_summary, markdown=False, write=True)
    n_asserts = [0]

    def expect(name, got, want):
        n_asserts[0] += 1
        if got != want:
            failures.append("%s: 得到 %r，期望 %r" % (name, got, want))

    expect("计划自检：相关子查询里没有对大表的顺序扫描", res["plan_audit"]["相关子查询里顺序扫描大表的查询（应为空）"], [])
    expect("正式起点", res["window"]["formal_start_utc"], "2026-11-06T00:00Z")
    expect("试运行尝试", res["window"]["trial_run_attempts_before_formal_start"], 1)
    expect("超出 72 小时", res["window"]["hours_beyond_72"], 0.0)
    expect("72 小时后的尝试", res["window"]["attempts_after_72h"], 0)
    n = res["n"]
    expect("密集 /24", n["候选密集的 /24 个数"], 1)
    expect("密集 /24 逐个", n["候选密集的 /24（逐个）"],
           [{"prefix24": "203.0.113.0/24", "候选": 101, "探访过的候选（att 里出现过）": 1, "明文响应 200 的尝试": 2, "能转发的代理（至少一次明文响应 200）": 1,
             "正文不符的尝试": 1, "正文不符的代理": 1, "class=ok 到 judge 的尝试": 1, "端到端可用过的代理": 1, "judge 收到的请求": 2}])
    expect("NAT：judge 看到的本机地址等于配置", n["judge_remote:control:public 等于 start.judge_ip（否则本机访问公网地址经过了 NAT；null=缺其一）"], True)
    expect("本机出口判定地址数", n["本机出口判定用的地址个数（start.judge_ip ∪ judge_remote:control:public ∪ echo:control:public）"], 1)
    expect("预检 IP 变过的节点", n["预检解析出的 IP 在观察期内变过的节点"], 1)
    expect("能转发的代理", n["能转发的代理（至少一次明文响应 200）"], 5)
    expect("端到端可用过的代理", n["端到端可用过的代理（任一协议 class=ok 到 judge）"], 5)
    expect("没有 att 的 nonce", n["judge 收到、却没有对应 att 记录的 nonce"], 1)   # zz
    c = res["content"]["all"]
    r = c["按请求"]
    expect("明文响应 200", r["明文响应 200"], 14)
    expect("收到状态码", r["收到任何状态码"], 15)
    expect("正文不符", r["正文不符（全部）"], {"num": 5, "den": 14, "pct": 35.7})
    expect("局部改动", r["正文被局部改动（注入或改写）"]["num"], 2)
    expect("截断", r["正文被截断"]["num"], 1)
    expect("整页替换", r["正文被整页替换"]["num"], 2)
    expect("HTML 不符", r["按载荷种类"]["HTML"]["正文不符"]["num"], 3)
    expect("JS 截断", r["按载荷种类"]["JavaScript"]["正文被截断"]["num"], 1)
    p = c["按代理"]
    expect("不符的代理", p["正文不符的代理（占能转发的）"], {"num": 2, "den": 5, "pct": 40.0})
    expect("局部改动的代理", p["各类（一个代理可属多类）"]["正文被局部改动（注入或改写）"]["num"], 2)
    expect("最差归一", p["按最差一类归一"]["正文被局部改动（注入或改写）"]["num"], 2)
    expect("间歇性", p["不符的代理里也有过正确响应的（间歇性）"], {"num": 2, "den": 2, "pct": 100.0})
    expect("gzip 标记", c["gzip"][GZ_ALL], {"尝试": 3, "代理": 2})
    expect("gzip 解开后相同（不论金丝雀）", c["gzip"][GZ_SAME], {"尝试": 2, "代理": 2})
    expect("gzip 相同且金丝雀对", c["gzip"]["其中正文相同、金丝雀也相符（class=ok）"], {"尝试": 1, "代理": 1})
    expect("gzip 相同但金丝雀不符", c["gzip"][GZ_CANARY], {"尝试": 1, "代理": 1})
    expect("gzip 仍不符", c["gzip"][GZ_MIS], {"尝试": 1, "代理": 1})
    expect("gzip 三项之和", c["gzip"]["三项之和等于标记数（自检）"], True)
    expect("金丝雀不符", c["正文正确但不是这次请求的应答（缓存或伪造）"]["尝试合计"], 2)
    expect("证据留存", c["证据留存"], {"不符的尝试": 5, "记了证据哈希": 3, "证据文件在库里": 1})
    ce = res["content"]["excluding_dense"]
    expect("去密集 明文 200", ce["按请求"]["明文响应 200"], 12)
    expect("去密集 不符", ce["按请求"]["正文不符（全部）"]["num"], 4)
    expect("去密集 代理", ce["按代理"]["正文不符的代理（占能转发的）"], {"num": 1, "den": 4, "pct": 25.0})
    rh = res["response_headers"]["all"]
    expect("gzip_added 标记", rh["标记（按标记）"]["gzip_added"]["尝试"], 3)
    expect("gzip_added ok", rh["标记（按标记）"]["gzip_added"]["其中 class=ok"], 1)
    expect("csp_missing", rh["标记（按标记）"]["csp_missing"]["代理"], 1)
    expect("多出的头 Via", rh["多出 judge 没发的头（按头名）"]["Via"], {"尝试": 1, "代理": 1})
    expect("多出的头任一", rh["多出 judge 没发的头（任一）"]["代理"]["num"], 2)
    a = res["anonymity"]["all"]["forward_ok"]
    expect("匿名 forward 请求", a["按请求"]["请求"], 6)
    expect("透明请求", a["按请求"][ANON_ZH["transparent"]]["num"], 2)
    expect("匿名请求", a["按请求"][ANON_ZH["anonymous"]]["num"], 1)
    expect("高匿请求", a["按请求"][ANON_ZH["elite"]]["num"], 3)
    expect("按代理 透明", a["按代理（取最差）"][ANON_ZH["transparent"]], {"num": 1, "den": 4, "pct": 25.0})
    expect("按代理 高匿", a["按代理（取最差）"][ANON_ZH["elite"]]["num"], 2)
    a2 = res["anonymity"]["all"]["plain_ok"]
    expect("全部明文 请求", a2["按请求"]["请求"], 7)
    expect("全部明文 代理", a2["按代理（取最差）"]["代理"], 5)
    a3 = res["anonymity"]["excluding_dense"]["forward_ok"]
    expect("去密集 forward 请求", a3["按请求"]["请求"], 5)
    t = res["request_tamper"]["all"]["plain_ok"]
    expect("请求被改 请求", t["请求被改（任一项）"]["请求"]["num"], 4)
    expect("请求被改 代理", t["请求被改（任一项）"]["代理"]["num"], 3)
    expect("UA 改动", t["各项（一个请求可有多项）"]["user_agent_changed"], {"请求": 2, "代理": 1})
    expect("Accept 重复取最后一个", t["各项（一个请求可有多项）"].get("accept_changed"), {"请求": 1, "代理": 1})
    expect("金丝雀缺失", t["各项（一个请求可有多项）"]["canary_missing"]["请求"], 1)
    expect("Cookie 缺失", t["各项（一个请求可有多项）"]["cookie_missing"]["请求"], 1)
    expect("带出地址", t["请求头里带出探测器地址"]["代理"]["num"], 1)
    expect("加了头 按名", {k: v["请求"] for k, v in t["代理加了请求头"]["按头名"].items()}, {"Via": 3, "X-Forwarded-For": 2})
    rp = res["replay"]["all"]
    expect("重放 nonce", rp["judge 侧（全部 nonce）"]["被收到不止一次的 nonce"]["num"], 1)
    expect("重放 份数分布", rp["judge 侧（全部 nonce）"]["份数分布"], {"3": 1})
    expect("重放 地址数", rp["judge 侧（全部 nonce）"]["来自几个不同地址"], {"2": 1})
    expect("重放 间隔", rp["judge 侧（全部 nonce）"]["首末两份的间隔（秒）"], {"60 到 600": 1})
    expect("重放 年龄", rp["judge 侧（全部 nonce）"]["最晚一份到达时 nonce 已签发（秒，req.age_s 最大值）"], {"60 到 600": 1})
    pr = rp["归到代理（class=ok 且 judge 收到）"]
    expect("重放 代理", pr["有请求被重放的代理"], {"num": 1, "den": 5, "pct": 20.0})
    expect("重放 别的地址", pr["重放来自别的地址"]["请求"]["num"], 1)
    eg = res["egress"]["all"]
    expect("出口 请求相同", eg["按请求（class=ok 且 judge 收到）"]["出口与入口相同"], {"num": 7, "den": 10, "pct": 70.0})
    expect("出口 按代理", {k: eg["按代理"][k]["num"] for k in ("全部相同", "全部不同", "有时相同有时不同")}, {"全部相同": 3, "全部不同": 1, "有时相同有时不同": 1})
    expect("出口 稳定性", {k: eg["稳定性（每个代理不同出口地址的个数）"][k]["num"] for k in ("1 个出口地址", "2 到 3 个出口地址", "4 个以上出口地址")},
           {"1 个出口地址": 3, "2 到 3 个出口地址": 2, "4 个以上出口地址": 0})
    expect("回显 vs 日志", eg["响应头回显的地址 vs judge 日志"]["不一致（应为 0）"], 1)
    expect("回显服务 kv 相同", eg["两个回显服务 vs judge"]["kv"]["与同一探访里 judge 看到的出口相同"]["num"], 2)
    expect("回显服务 kv 整个观察期", eg["两个回显服务 vs judge"]["kv"]["与该代理整个观察期的出口集合比"], {"same_ip": 2, "different_ip": 0})
    cc = res["crosscheck"]["comparisons"]
    expect("交叉核对 observer_vs_judge 按记录流顺序", {k: cc["extras.observer_vs_judge." + k]["computed"] for k in ("same_ip", "different_ip")},
           {"same_ip": 1, "different_ip": 2})
    expect("回显服务 plain 不同", eg["两个回显服务 vs judge"]["plain"]["与同一探访里 judge 看到的不同"]["num"], 1)
    expect("回显服务之间", eg["两个回显服务之间（同一探访都成功时）"], {"探访": 1, "一致": {"num": 0, "den": 1, "pct": 0.0}})
    ne = res["nodes_egress"]["judge_tls"]
    NE_SUM = "summary.go 口径（之前最近一次预检，没有就算入口地址未知；本机只按 start.judge_ip）按尝试"
    NE_ANY = "诊断：任意一轮预检 IP 都算的口径 按尝试"
    expect("节点出口（按时间取最近预检）", ne["按尝试"], {"与入口相同": 2, "与入口不同": 1, "入口地址未知": 1, "仪器异常：出口是本机": 1})
    expect("节点出口（summary.go 口径）", ne[NE_SUM], {"与入口相同": 1, "与入口不同": 1, "入口地址未知": 2, "仪器异常：出口是本机": 1})
    expect("节点出口与 summary.go 口径不一致（节点 5 借用之后的预检）", ne["与 summary.go 口径判定不一致的尝试"], 1)
    expect("节点出口借用之后预检的尝试", ne["入口取自尝试之后的预检（之前没有解析出 IP 的预检）的尝试"], 1)
    expect("节点出口（任意一轮）", ne[NE_ANY], {"与入口相同": 3, "入口地址未知": 1, "仪器异常：出口是本机": 1})
    expect("节点出口与任意一轮不一致（节点 2 换了地址）", ne["与任意一轮口径判定不一致的尝试（节点域名换过地址的影响）"], 1)
    ck = res["checks"]
    expect("judge 没收到", ck["探测器认为成功，但 judge 没收到请求（judge 最后记录前 10 秒之前）"], {"尝试": 1, "候选": 1})
    expect("judge 先停", ck["探测器最后一条 att 晚于 judge 最后一条记录（分钟；明显大于 0 说明 judge 先停了）"], -103.7)  # 最后一条 att 是 B 的第二次探访 T0+780，judge 最后记录 T0+7000
    expect("TLS 内不同", ck["TLS 校验通过的请求到达 judge 时与发出时不同（仪器异常，应为 0）"]["ClientHello 指纹与直连不同"], 1)
    expect("TLS 内成功请求", ck["TLS 校验通过的请求到达 judge 时与发出时不同（仪器异常，应为 0）"]["TLS 内成功请求"], 10)  # E 3 次 + 节点 5 次 + 对照组 2 次
    expect("节点本机出口", ck["节点探测的流量从本机直接出去（仪器异常，应为 0）"]["节点"], 1)
    expect("对照 judge 收到", ck["对照组（直连）"]["judge 收到"], 3)
    pe = res["protocol_expectations"]
    expect("预期范围 全部协议 不符", pe["明文正文不符的代理占能转发的代理"][EXPECT_ALL]["结果"], {"num": 2, "den": 5, "pct": 40.0})
    expect("预期范围 全部协议 与 content 一致", pe["明文正文不符的代理占能转发的代理"][EXPECT_ALL]["结果"], p["正文不符的代理（占能转发的）"])
    expect("预期范围 只算转发 不符", pe["明文正文不符的代理占能转发的代理"][EXPECT_FWD]["结果"], {"num": 2, "den": 4, "pct": 50.0})
    expect("预期范围 只算转发 带出地址", pe["请求头带出客户端地址的代理占能转发的代理"][EXPECT_FWD]["结果"], {"num": 1, "den": 4, "pct": 25.0})
    expect("预期范围 全部协议 带出地址", pe["请求头带出客户端地址的代理占能转发的代理"][EXPECT_ALL]["结果"], {"num": 1, "den": 5, "pct": 20.0})
    text = json.dumps(res, ensure_ascii=False)
    expect("输出里没有 ip:port", bool(HOSTPORT_RE.search(text)), False)
    expect("输出里没有裸 IPv4", bool(IPV4_RE.search(text)), False)
    expect("输出里没有探测器地址", "192.0.2.250" in text, False)
    expect("输出里没有节点 id", "aaaaaaaaaaa1" in text, False)

    # 变体一：没有对照组 → 指纹基线为空，“指纹与直连不同”必须是 null 而不是把全部 TLS 内请求判成异常
    db2 = os.path.join(tmp, "nocontrol.sqlite")
    _synthetic_db(db2, with_control=False)
    r2 = run(db2, os.path.join(tmp, "out_nocontrol"), markdown=False, write=True)
    tls2 = r2["checks"]["TLS 校验通过的请求到达 judge 时与发出时不同（仪器异常，应为 0）"]
    expect("无对照组：基线种数", r2["n"]["直连对照的 ClientHello 指纹种数（应为 1）"], 0)
    expect("无对照组：TLS 内成功请求", tls2["TLS 内成功请求"], 8)
    expect("无对照组：指纹一项为 null", tls2["ClientHello 指纹与直连不同"], None)
    expect("无对照组：任一为 0", tls2["任一"], 0)
    expect("无对照组：计划自检", r2["plan_audit"]["相关子查询里顺序扫描大表的查询（应为空）"], [])

    # 变体二：本机经 NAT 回访公网地址，judge 看到的是 NAT 内侧地址；节点 4 的流量从本机直接出去时 judge 看到的也是它
    db3 = os.path.join(tmp, "nat.sqlite")
    _synthetic_db(db3, nat=True)
    r3 = run(db3, os.path.join(tmp, "out_nat"), markdown=False, write=True)
    expect("NAT：judge 看到的本机地址不等于配置", r3["n"]["judge_remote:control:public 等于 start.judge_ip（否则本机访问公网地址经过了 NAT；null=缺其一）"], False)
    expect("NAT：本机出口判定地址数", r3["n"]["本机出口判定用的地址个数（start.judge_ip ∪ judge_remote:control:public ∪ echo:control:public）"], 2)
    expect("NAT：节点本机出口仍判出", r3["checks"]["节点探测的流量从本机直接出去（仪器异常，应为 0）"]["尝试"], 1)
    expect("NAT：只按 start.judge_ip 判不出", r3["checks"]["节点探测的流量从本机直接出去（仪器异常，应为 0）"]["其中只按 start.judge_ip 就能判出的（summary.go 口径）"], 0)
    ne3 = r3["nodes_egress"]["judge_tls"]
    expect("NAT：节点出口按尝试", ne3["按尝试"], {"与入口相同": 2, "与入口不同": 1, "入口地址未知": 1, "仪器异常：出口是本机": 1})
    expect("NAT：summary.go 口径把本机出口漏判成与入口不同", ne3[NE_SUM], {"与入口相同": 1, "与入口不同": 2, "入口地址未知": 2})
    expect("NAT：与 summary.go 口径不一致（节点 4、节点 5）", ne3["与 summary.go 口径判定不一致的尝试"], 2)
    expect("NAT：与任意一轮口径不一致（只有节点 2）", ne3["与任意一轮口径判定不一致的尝试（节点域名换过地址的影响）"], 1)
    expect("NAT：输出里没有 NAT 地址", "192.0.2.77" in json.dumps(r3, ensure_ascii=False), False)

    # 变体三：库里有 ANALYZE 统计（ingest 末尾的 PRAGMA optimize 可能会做）。规划器会按表的大小换连接顺序，
    # 计划自检要在有统计时同样为零，结果要与没有统计时完全相同
    db4 = os.path.join(tmp, "analyzed.sqlite")
    _synthetic_db(db4)
    con = sqlite3.connect(db4)
    con.execute("ANALYZE")
    con.commit()
    con.close()
    r4 = run(db4, os.path.join(tmp, "out_analyzed"), summary_path=fake_summary, markdown=False, write=True)
    expect("有统计：计划自检", r4["plan_audit"]["相关子查询里顺序扫描大表的查询（应为空）"], [])
    strip = lambda d: {k: v for k, v in d.items() if k not in ("generated_utc", "plan_audit")}  # noqa: E731
    expect("有统计：结果与没有统计时相同", json.dumps(strip(r4), ensure_ascii=False, sort_keys=True) == json.dumps(strip(res), ensure_ascii=False, sort_keys=True), True)
    if failures:
        print("自检失败 %d/%d 项：" % (len(failures), n_asserts[0]), file=sys.stderr)
        for x in failures:
            print("  - " + x, file=sys.stderr)
        return 1
    print("自检通过：%d 项断言，合成库 %s" % (n_asserts[0], db_path), file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="内容与请求完整性（PROTOCOL“内容被改”“请求被改、匿名程度”“重放”“出口地址”）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 integrity.json")
    ap.add_argument("--summary", help="fieldtest 自带的 summary.json，给了就交叉核对")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--dense-threshold", type=int, default=DENSE_THRESHOLD, help="“候选密集的 /24”的阈值，默认 100")
    ap.add_argument("--formal-start", default="auto", help="auto（按 PROTOCOL 规则）/ first（第一条 start）/ 带时区的 ISO 时间")
    ap.add_argument("--selftest", action="store_true", help="在临时目录里建合成库并核对预期值")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    run(args.db, args.out, summary_path=args.summary, dense_threshold=args.dense_threshold, formal_start=args.formal_start, markdown=args.markdown)


if __name__ == "__main__":
    main()
