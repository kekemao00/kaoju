#!/usr/bin/env python3
"""标签准确率（第一阶段 1B，PROTOCOL“指标定义”表的“标签准确率”行）：
列表给的协议标签里，实测可用的比例；标签与实测的对照表；标签为 https 的条目的两项附加测试。

用法：
    python3 m_labels.py --db <sqlite> --out <目录> [--markdown] [--summary <summary.json>]
                        [--formal-start auto|first|<带时区的 ISO 时间>] [--dense-threshold 100]
    python3 m_labels.py --selftest

只读 ingest.py 建好的库（mode=ro，中间表都建在 TEMP 库里），结果写到 <目录>/labels.json；
加 --markdown 时把主要表格以 Markdown 打印到标准输出。每个比例都给分子、分母和口径，百分比保留一位小数。
输出前按 SCHEMA.md 的可输出列白名单核对本模块用到的列，写出前再对文本做一次“不许出现地址和 judge 身份”的断言
（最后一道保险，不是放行手段）。

口径（PROTOCOL 第 1.2 版；PROTOCOL 没说清的地方，取的解释写在 DEFINITIONS 和各函数注释里）：

- 标签：visit.labels 是该候选到探访时为止出现过的全部标签（sched.go Cand.Labels 按位累加，lists.go LabelNames 解码），
  本模块取最后一次非 aborted 探访的 labels，与 summary.go probeLine() 的做法相同；
  按来源看时用 snap 事件（list_event）里该来源的文件标签——同一个条目在不同来源可能有不同标签。
- 实测：以 visit 的 ok 数组（通过端到端校验的协议，prober.go Visit() 的 okMask）为准，取两种口径：
  “曾经通过”（正式起点后任一非 aborted 探访的 ok 含该协议）和“最近一次通过”（最后一次非 aborted 探访的 ok 含该协议）。
  注意 okMask 只由主循环（for _, proto := range order）累加，附加测试里通过的尝试不进去，所以它比 PROTOCOL“可用”行的原句
  （“一次探访里至少有一次尝试走完全部阶段并通过核对”）窄；每个标签下另给一列“曾经通过·按 att class='ok'”（summary.go attempt()
  的 everOK 口径：任一到 judge 的尝试 class='ok'），两种分子并排出现，差多少一眼能看到。
- 标签声称的协议：PROTOCOL 没写标签到协议的映射，这里给两种解释并都报告：
  严格——http→forward（HTTP 转发）、https→connect（HTTP CONNECT 隧道）、connect→connect、socks4→socks4、socks5→socks5；
  宽松——prober.go labelProtos() 为该标签首先尝试的协议集合：http→{forward, connect}、https/connect→{connect, forward}、
  socks4→{socks4}、socks5→{socks5}。严格版是“标签说的那个协议”，宽松版是“标签说的那一族”。
- 分母：探访过（正式起点后至少一次非 aborted 探访）的带该标签的候选；另给以“曾经可用（任一协议）”为分母的条件版本，
  把“代理死了”和“标签错了”分开。从没探访过的候选不进任何分母，单独按标签和 /24 报告（PROTOCOL“候选密集的地址段”）。
- 去掉“候选超过 100 个的 /24”的一组结果照 PROTOCOL 1.2 版另给。

设计要点（真实数据有一千多万条 att）：visit 按正式窗口过滤成 TEMP 表后用窗口函数取最后一次探访、用 visit_ok 聚合“曾经通过”；
“连得上过”从 visit.state 推（working/open ⇔ 这次探访 tcpOK，见 build_cand_table 的注释），不扫 att；
att 只按 (proto, dst, class) 索引做三类聚合（class='ok' 到 judge、tlsproxy、CONNECT 连 80 端口），只有交叉核对 summary.json 时
为了对齐 summary.go 的“任何 att 的 TCP 通过”才对 att 全表按候选分组一次。全部是 SQL 聚合，中间结果都是“每候选一行”的量级，
内存由 SQLite 页缓存主导。
只用 Python 3.10+ 标准库。
"""
import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import tempfile

MODULE = "m_labels"
OUTPUT_NAME = "labels.json"
PROTOCOL_VERSION = "1.2"
DENSE_THRESHOLD = 100   # PROTOCOL 1.2“候选密集的地址段”：候选超过 100 个的 /24
TOP_PREFIXES = 30       # 从没探访过的候选按 /24 汇总时列出的前几个

# 标签（lists.go labelNames 的顺序和位）
LABELS = ["http", "https", "connect", "socks4", "socks5"]
LABEL_BIT = {"http": 1, "https": 2, "connect": 4, "socks4": 8, "socks5": 16}
# 实测协议：visit.ok 的顺序是 sched.go protoBits（socks5、socks4、connect、forward）；
# 对照表里组合的写法照 summary.go finish()：socks5、connect、forward、socks4，用 + 连接，空为“无”
PROTOS = ["socks5", "socks4", "connect", "forward"]
OK_ORDER = ["socks5", "connect", "forward", "socks4"]
NONE_COMBO = "无"
NO_LABEL = "(无标签)"
# 标签声称的协议：严格 = 标签名对应的单一协议（本模块的解释）；宽松 = prober.go labelProtos() 首先尝试的集合
STRICT = {"http": ["forward"], "https": ["connect"], "connect": ["connect"], "socks4": ["socks4"], "socks5": ["socks5"]}
LENIENT = {"http": ["forward", "connect"], "https": ["connect", "forward"], "connect": ["connect", "forward"],
           "socks4": ["socks4"], "socks5": ["socks5"]}
# cl 表里的列名缩写
PCOL = {"socks5": "s5", "socks4": "s4", "connect": "c", "forward": "f"}
# 没有状态文件时“候选密集的 /24”的退路要近似 sched.go Pool.ineligible() 的排除规则：
# 非公网地址段照 lists.go 的 reserved；不探测的端口照 cfg.go DefaultConfig 的 Probe.SkipPorts（真实配置若改过这两处会有偏差，
# basis 字段里写明）。judge 自己的地址从库里的 self_ips 表取，不写进这里。
RESERVED_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
               "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
               "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]
CFG_DEFAULT_SKIP_PORTS = {21, 22, 23, 25, 53, 110, 111, 135, 137, 138, 139, 143, 161, 389, 445, 465, 587,
                          993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017}

# 本模块在 SELECT 列表或 GROUP BY 里用到、并且会进入输出（作为维度或被聚合的值）的列。
# 连接用的键（visit.cand、visit.visit、visit_ok.visit_rid、att.cand、att.visit、list_event.cand、agg_member.cand、cands.key、cand_src.key）
# 只在库内做 JOIN，不进入输出，所以不在这里；没有状态文件时 _fallback_pool() 读 visit.cand_ip、list_event.cand_ip / cand_port
# 只为按 ineligible 规则筛选，筛完只留下 cand 与 prefix24，也不进入输出。
OUTPUT_COLUMNS = {
    "visit": ["group", "labels", "ok", "full", "aborted", "state", "n_ok", "prefix24", "ts_epoch"],
    "visit_ok": ["proto"],
    "att": ["proto", "dst", "class", "tcp_ok", "hs_ok", "hs_class", "hs_code", "tls_ok", "tls_class", "tls_detail_enum",
            "tls_self", "tls_sniff", "cand_kind", "ts_epoch"],
    "list_event": ["src", "label", "event", "prefix24"],
    "agg_member": ["src"],
    "cands": ["prefix24", "group", "visits", "label_names", "ok_protos", "ever_ok"],
    "cand_src": ["src_name", "label_names"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["ts_epoch"],
    "version": ["version", "ts_epoch"],
    "meta": ["ingest_version", "first_ts", "last_ts", "state_cands", "state_tz_offsets"],
}

DEFINITIONS = {
    "标签": "列表给条目贴的协议标签：http / https / connect / socks4 / socks5（lists.go labelNames）。一个条目可以有多个标签。"
          "探访记录 visit.labels 是该条目到探访时为止出现过的全部标签（sched.go Cand.Labels 按位累加），本模块取最后一次非 aborted 探访的 labels"
          "（summary.go probeLine() 同样取最后一次探访）；按来源看时用 snap 事件（list_event，event='add'）里该来源的文件标签。"
          "聚合器不逐条记快照（PROTOCOL“记录”），聚合器抽样条目的标签取 visit.labels。PROTOCOL“指标定义”表“标签准确率”行",
    "标签声称的协议（严格）": "标签名对应的单一协议：http→forward（HTTP 转发）、https→connect（HTTP CONNECT 隧道）、connect→connect、"
                    "socks4→socks4、socks5→socks5。PROTOCOL 没有写标签到协议的映射，这是本模块取的解释：这些列表里 https 标签的通行含义是"
                    "“能代理 HTTPS”，而代理 HTTPS 靠 CONNECT；http 标签的通行含义是明文转发",
    "标签声称的协议（宽松）": "探测器为该标签首先尝试的协议集合（prober.go labelProtos()）：http→{forward, connect}、https→{connect, forward}、"
                    "connect→{connect, forward}、socks4→{socks4}、socks5→{socks5}。即“标签说的那一族”里任一协议通过就算",
    "实测可用（曾经通过）": "正式起点后任一非 aborted 探访的 ok 数组（prober.go Visit() 的 okMask，子表 visit_ok）含该协议。"
                   "okMask 只由主循环（for _, proto := range order，每协议一次 h 载荷的尝试）累加；附加测试（Visit() 的 extraDue 段）里"
                   "通过的尝试不进 okMask——具体是 h 载荷 http_body_mismatch（fwdAnswers 为真）而 j/b 载荷 class='ok' 的转发，"
                   "按 PROTOCOL“可用”行的原句（“一次探访里至少有一次尝试走完全部阶段并通过核对”）算可用，按 visit.ok 不算。"
                   "所以这一列比 PROTOCOL 原句窄，是模块任务书指定的口径（“以 visit 的 ok 为准”）；PROTOCOL 原句的口径见下一条，两列并排给出",
    "实测可用（曾经通过·按 att class='ok'）": "正式起点后任一到 judge 的尝试（att，dst ∈ {judge_tls, judge_http}，proto 是四种代理协议之一）"
                                    "class='ok'。这是 summary.go attempt() 的 everOK 口径，也最接近 PROTOCOL“可用”行的原句。"
                                    "与 visit.ok 的差只来自两处：附加测试里 j/b 载荷通过而 h 载荷不符的转发（见上一条）；"
                                    "aborted 探访里的尝试（summary.go attempt() 不看 aborted，照它不过滤）。"
                                    "SOCKS 隧道里走明文和 CONNECT 连 80 端口两项虽然也到 judge，但只对 okMask 已含该协议的候选做，不会多出协议",
    "连得上过": "正式起点后任一非 aborted 探访的 state ∈ {working, open}。prober.go Visit() 写回状态时 okMask≠0→working、tcpOK→open、"
            "否则→dead，所以这等价于“这次探访里至少一次尝试的 TCP 阶段通过”（PROTOCOL“连得上”行，按探访取并）。"
            "summary.go attempt() 的 c.tcp 和 m_availability 用 att.tcp_ok，两者只差 aborted 探访里的尝试和跨正式起点那次探访的尝试；"
            "交叉核对 summary.json 时按 att 口径重算",
    "实测可用（最近一次通过）": "最后一次非 aborted 探访的 ok 数组含该协议。平时的探访只试上一次通过的协议（prober.go Visit()：order = ProtoNames(OKMask)），"
                     "完整识别每 24 小时一次，所以这是“当前仍可用”的保守估计",
    "标签准确率": "探访过的带该标签的候选里，标签声称的协议实测可用的比例（分子分母都按候选计；一个候选有几个标签就进几个标签的分母）。"
             "分子按三种实测口径各给一次：曾经通过（visit.ok）、曾经通过·按 att class='ok'、最近一次通过（visit.ok）。"
             "另给以“曾经可用（任一协议）”（各自口径）或“最近一次探访可用”为分母的条件版本，用来把“代理死了”和“标签错了”分开。"
             "PROTOCOL“指标定义”表“标签准确率”行",
    "对照表": "标签组合 → 实测通过校验的协议组合 → 候选数，曾经通过（visit.ok）、曾经通过（att class='ok'）、最近一次通过各一张。"
           "标签组合按 http、https、connect、socks4、socks5 的顺序用 + 连接；"
           "实测组合照 summary.go finish() 按 socks5、connect、forward、socks4 的顺序用 + 连接，空为“无”。"
           "本模块对全部探访过的候选都列（含聚合器抽样、含连不上的）；summary.json 的 labels 只含常规列表且连得上过的候选、实测取 att 的 class='ok'，"
           "交叉核对时按它的口径重算。PROTOCOL“指标定义”表“标签准确率”行",
    "按来源": "来源 × 该来源给的标签 × 候选。常规来源的标签来自 list_event（event='add'，含首次快照）；聚合器来源的成员来自 agg_member、标签取 visit.labels。"
           "同一候选出现在几个来源就在几个来源里各算一次",
    "https 标签的端口是否说 TLS": "完整识别时对标签含 https 或 connect 的候选做的 tlsproxy 尝试（attempt.go run()：对代理端口按 IP 校验证书、只握手不发数据；"
                        "prober.go Visit()：was.Labels&(LHTTPS|LConnect)!=0 且 full 且 tcpOK 时做）。"
                        "端口说 TLS = tls_ok=1 或 tls_class ∈ {tls_cert_invalid, tls_pin_mismatch, tls_alert}（对方按 TLS 应答，哪怕证书不对）；"
                        "不说 TLS = tls_class='tls_not_tls'（wire.go TLS()：RecordHeaderError）；其余（超时、断开、TCP 失败）无结论。"
                        "一个候选有多次尝试时：任一次说 TLS 即“说 TLS”，否则任一次不说即“不说 TLS”，否则无结论。PROTOCOL“一次探访”末段",
    "CONNECT 连 80 端口": "完整识别时 CONNECT 通过校验的候选再让 CONNECT 连 judge 的 80 端口（att proto='connect'、dst='judge_http'；prober.go Visit()）。"
                      "允许 = 握手通过（hs_ok=1，不管后面明文 HTTP 的结果）；拒绝 = hs_class='hs_refused'（带 CONNECT 应答的状态码 hs_code）；"
                      "要求认证 = hs_class='hs_auth'；其余无结论。一个候选多次尝试时按 允许 > 拒绝 > 要求认证 > 无结论 取。PROTOCOL“一次探访”末段",
    "探访过": "正式起点之后至少有一次 aborted≠1 的 visit 记录。aborted=1 的探访结果不作数（prober.go Visit()），summary.go 也跳过",
    "从没探访过": "状态文件 cands 里有、正式起点后却没有任何非 aborted 探访的候选。不进任何比例的分母，单独按标签和 /24 报告。"
             "其中 cands.visits>0 的那些（sched.go Cand.Visits，Visit() 里 ctx.Err() 的检查在 c.Visits++ 之前，所以 aborted 探访不计入；"
             "跨重启保留、不区分正式起点前后）是正式起点之前探访过的——含随状态文件从上一次运行带过来的——或探访记录缺失的候选。"
             "PROTOCOL“候选密集的地址段”",
    "候选密集的 /24": "状态文件里候选数超过阈值（默认 100）的 /24。没有状态文件时的退路：visit 里出现过的候选 ∪ list_event 里出现过、"
                  "且按 sched.go Pool.ineligible() 的近似（lists.go reserved 的非公网段、cfg.go 默认的 skip_ports、库里 self_ips 的 judge 地址）"
                  "没被排除的候选；list_event 含永远不进候选池的条目，剔除后仍可能偏多（真实配置的 skip_ports/exclude_file 若与默认值不同）。"
                  "每个比例另给一组去掉这些 /24 里全部候选后的结果，并列出每个被去掉的 /24 的候选数、正式窗口内探访到的候选数（按 cl）、"
                  "状态文件里 visits>0 的候选数（含试运行、不含下榜后被丢弃的：sched.go Pool.Done 在 next 为零时 delete）。PROTOCOL 1.2 版“候选密集的地址段”",
    "正式起点": "PROTOCOL“正式测量的起止”：默认取第一条 start；若之后有 resumed_candidates=0 的 start（状态被清空）或版本变了，取最后一次这样的 start。"
             "之前的数据是试运行，不并入。可用 --formal-start 覆盖。交叉核对 summary.json 时不裁（summary.go 不区分试运行）",
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
    return f"{fmt(r['num'])}/{fmt(r['den'])}（{fmt(r['pct'], '%')}）"


def label_combo_name(mask):
    """标签位 → “http+socks5”这样的组合名（lists.go labelNames 的顺序）。"""
    names = [name for name in LABELS if mask & LABEL_BIT[name]]
    return "+".join(names) if names else NO_LABEL


def labels_json_to_list(text):
    """visit.labels / cands.label_names 是 JSON 数组文本；缺省（NULL）就是空。"""
    if not text:
        return []
    try:
        v = json.loads(text)
    except ValueError:
        return []
    return [x for x in v if isinstance(x, str)]


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

    def has_table(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) > 0

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))


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
    """正式起点与结束时刻。规则与 m_availability.observation_window 相同（PROTOCOL“正式测量的起止”）。"""
    starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0) FROM start ORDER BY ts_epoch") if db.has_table("start") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch") if db.has_table("version") else []
    ends = []
    for t in ("visit", "att", "stop"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None
    first_visit = db.scalar("SELECT MIN(ts_epoch) FROM visit")
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
        fs = first_visit
        rule.append("没有 start 记录：取第一条 visit")
    if formal_start_arg and formal_start_arg != "auto":
        if formal_start_arg == "first":
            fs = starts[0][0] if starts else first_visit
            rule = ["--formal-start first"]
        else:
            fs = parse_iso(formal_start_arg)
            rule = ["--formal-start 指定"]
    if fs is None:
        fs = 0.0
        rule.append("库里没有 visit，起点取 0")
    return {
        "formal_start_utc": iso_minute(fs), "formal_start_rule": "；".join(rule), "end_utc": iso_minute(end),
        "hours": round((end - fs) / 3600.0, 2) if end is not None else None,
        "starts": [{"utc": iso_minute(s[0]), "resumed_candidates": s[1]} for s in starts],
        "versions": sorted({v for _, v in versions}),
        "trial_run_visits_before_formal_start": int(db.scalar("SELECT COUNT(*) FROM visit WHERE ts_epoch < ?", (fs,)) or 0),
        "_fs": fs, "_end": end,
    }


# ---------------------------------------------------------------- 中间表

def _fallback_pool(db):
    """没有状态文件时近似候选池：TEMP 表 dcand(cand, prefix24)。

    visit 里出现过的候选一定进过候选池；list_event 里的条目则要先过 sched.go Pool.ineligible() 的筛子（判定在 Upsert 时、进池之前），
    这里近似它：非 IPv4、judge 自己的地址（库里 self_ips 表）、非公网段（lists.go reserved，照搬到 RESERVED_V4）、
    不探测的端口（cfg.go 默认 Probe.SkipPorts，照搬到 CFG_DEFAULT_SKIP_PORTS）。真实配置的 allow_local / skip_ports / exclude_file
    若与默认值不同会有偏差：allow_local 从数据推（visit 里探访过非公网地址就不按公网段排除），其余两项推不出来，basis 里写明。
    list_event.cand_ip / cand_port 只在这里做筛选，不进输出。返回剔除的条目数（按候选）。
    """
    import ipaddress
    reserved = [ipaddress.ip_network(s) for s in RESERVED_V4]
    self_ips = set()
    if db.has_table("self_ips"):
        self_ips = {v for (v,) in db.q("SELECT DISTINCT ip FROM self_ips") if v}

    def public(ip):
        return not any(ip in n for n in reserved)

    allow_local = False
    cur = db.con.execute("SELECT DISTINCT cand_ip FROM visit WHERE cand_ip IS NOT NULL")
    while not allow_local:
        rows = cur.fetchmany(5000)
        if not rows:
            break
        for (ip,) in rows:
            try:
                if not public(ipaddress.ip_address(ip)):
                    allow_local = True
                    break
            except ValueError:
                continue
    db.x("DROP TABLE IF EXISTS dcand")
    db.x("CREATE TEMP TABLE dcand (cand TEXT PRIMARY KEY, prefix24 TEXT)")
    db.x("INSERT OR IGNORE INTO dcand SELECT cand, prefix24 FROM visit WHERE prefix24 IS NOT NULL")
    dropped = {"not_ipv4": 0, "self": 0, "not_public": 0, "skip_port": 0}
    if db.has_table("list_event"):
        cur = db.con.execute("""SELECT DISTINCT cand, cand_ip, cand_port, prefix24 FROM list_event
                                WHERE prefix24 IS NOT NULL AND cand NOT IN (SELECT cand FROM dcand)""")
        while True:
            rows = cur.fetchmany(5000)
            if not rows:
                break
            keep = []
            for cand, ip, port, prefix24 in rows:
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    a = None
                if a is None or a.version != 4:
                    dropped["not_ipv4"] += 1
                elif ip in self_ips:
                    dropped["self"] += 1
                elif not allow_local and not public(a):
                    dropped["not_public"] += 1
                elif port in CFG_DEFAULT_SKIP_PORTS:
                    dropped["skip_port"] += 1
                else:
                    keep.append((cand, prefix24))
            db.con.executemany("INSERT OR IGNORE INTO dcand VALUES (?, ?)", keep)
    return dropped, allow_local


def build_dense(db, threshold):
    """TEMP 表 dense(prefix24, cands, visited_state)：候选超过阈值的 /24。
    有状态文件按“状态文件 ∪ 尝试记录里的代理候选”数（与 m_availability、m_integrity、report_tables 的点名规则同一口径，决策 D14；
    visited_state = 有尝试记录的候选数，含试运行）；没有就按 _fallback_pool() 近似的候选池。
    “正式窗口内探访到多少”要等 cl 建好后由 dense_visited() 补上（PROTOCOL 1.2“列出被去掉的 /24 各有多少候选、探访到多少”）。"""
    db.x("DROP TABLE IF EXISTS dense")
    out = {"threshold": threshold}
    if db.has_table("cands"):
        att_part = (" UNION ALL SELECT DISTINCT cand, prefix24, 1 FROM att WHERE cand_kind = 'proxy' AND prefix24 IS NOT NULL"
                    if db.has_table("att") else "")
        db.x("""CREATE TEMP TABLE dense AS
                SELECT prefix24, COUNT(*) AS cands, SUM(in_att) AS visited_state FROM (
                  SELECT cand, MAX(prefix24) AS prefix24, MAX(in_att) AS in_att FROM (
                    SELECT key AS cand, prefix24, 0 AS in_att FROM cands WHERE prefix24 IS NOT NULL%s)
                  GROUP BY cand)
                GROUP BY prefix24 HAVING COUNT(*) > ?""" % att_part, (threshold,))
        out["basis"] = "状态文件 cands ∪ 尝试记录里的代理候选（att，含试运行）：下榜超过 24 小时的候选会从状态文件里丢掉，只数状态文件会漏掉它们"
    else:
        dropped, allow_local = _fallback_pool(db)
        db.x("""CREATE TEMP TABLE dense AS
                SELECT prefix24, COUNT(*) AS cands, NULL AS visited_state FROM dcand GROUP BY prefix24 HAVING COUNT(*) > ?""", (threshold,))
        out["basis"] = ("visit 里出现过的候选 ∪ list_event 里按 sched.go Pool.ineligible() 的近似没被排除的候选（没有状态文件）。"
                        "仍可能偏多：真实配置的 skip_ports / exclude_file 若与 cfg.go 默认值不同，这里剔不掉")
        out["fallback"] = {"allow_local（从 visit 推出）": allow_local, "list_event 里被剔除的候选（按 ineligible 的原因）": dropped}
    rows = db.q("SELECT prefix24, cands, visited_state FROM dense ORDER BY cands DESC")
    out["count"] = len(rows)
    out["prefixes"] = [{"prefix24": p, "候选": int(c),
                        "有尝试记录（含试运行）": (int(v) if v is not None else None)} for p, c, v in rows]
    return out


def dense_visited(db, dense_info):
    """给每个密集 /24 补上“正式窗口内探访到的候选数”（按 cl：正式起点后至少一次非 aborted 探访）。"""
    got = {p: int(n) for p, n in db.q("SELECT prefix24, COUNT(*) FROM cl WHERE dense = 1 GROUP BY prefix24")}
    for row in dense_info["prefixes"]:
        row["正式窗口内探访到（按 cl）"] = got.get(row["prefix24"], 0)
    return dense_info


def build_cand_table(db, since, name="cl", att_tcp="atcp", att_ok="aok", tcp_source="visit"):
    """每个探访过的候选一行的 TEMP 表 <name>：标签位与组合、曾经/最近一次通过的协议位与组合、按 att class='ok' 的协议位与组合、
    分组、/24、是否密集、连得上过。

    - 探访过 = since 之后至少一次非 aborted 探访；标签、分组取最后一次探访（summary.go probeLine()）。
    - 曾经通过（e_*）= visit_ok 里该候选的协议集合（只看 since 之后的非 aborted 探访）。
    - 按 att class='ok'（a_*）= since 之后任一到 judge 的尝试 class='ok' 的协议集合（summary.go attempt() 的 everOK；照它不过滤 aborted）。
      按 att(proto, dst, class) 索引取，只碰 class='ok' 的行。
    - 连得上过（tcp）：tcp_source='visit' 时取 vv 里 state ∈ (working, open)——prober.go Visit() 写回状态：okMask≠0→working、tcpOK→open、
      否则 dead，所以这等价于“这次探访里有尝试的 TCP 通过”，按探访取并，不用扫 att；tcp_source='att' 时照 summary.go attempt() 的 c.tcp
      对 att 全表按候选分组（任何目的地、含 aborted 探访里的尝试），只给交叉核对用。两者只差 aborted 探访和跨正式起点那次探访里的尝试。
    - 标签/协议的布尔列由 JSON 数组文本的 LIKE 判断：'"http"' 带引号，不会误配 '"https"'。
    """
    db.x("DROP TABLE IF EXISTS vv")
    db.x("""CREATE TEMP TABLE vv AS
            SELECT rid, cand, COALESCE("group", 0) AS grp, labels, ok, prefix24, COALESCE("full", 0) AS f, ts_epoch,
                   CASE WHEN state IN ('working', 'open') THEN 1 ELSE 0 END AS tcp
            FROM visit WHERE COALESCE(aborted, 0) = 0 AND ts_epoch >= ?""", (since,))
    db.x("CREATE INDEX vv_rid ON vv(rid)")
    db.x("CREATE INDEX vv_cand ON vv(cand, ts_epoch)")
    db.x("DROP TABLE IF EXISTS lastv")
    db.x("""CREATE TEMP TABLE lastv AS
            SELECT cand, grp, labels, ok, prefix24 FROM
              (SELECT cand, grp, labels, ok, prefix24, ROW_NUMBER() OVER (PARTITION BY cand ORDER BY ts_epoch DESC, rid DESC) AS rn FROM vv)
            WHERE rn = 1""")
    db.x("DROP TABLE IF EXISTS ev")
    db.x("""CREATE TEMP TABLE ev AS
            SELECT v.cand,
                   MAX(o.proto = 'socks5') AS s5, MAX(o.proto = 'socks4') AS s4,
                   MAX(o.proto = 'connect') AS c, MAX(o.proto = 'forward') AS f
            FROM visit_ok o JOIN vv v ON v.rid = o.visit_rid GROUP BY v.cand""")
    db.x("DROP TABLE IF EXISTS vagg")
    db.x("""CREATE TEMP TABLE vagg AS
            SELECT cand, COUNT(*) AS n, SUM(f) AS nf, COUNT(DISTINCT COALESCE(labels, '')) AS nl, MAX(tcp) AS tcp FROM vv GROUP BY cand""")
    # 每候选是否连得上过
    db.x("DROP TABLE IF EXISTS %s" % att_tcp)
    if tcp_source == "att":
        # summary.go attempt()：a.TCP.OK，任何目的地、任何探访（含 aborted）都算。att 全表按 (cand, ts_epoch) 索引分组，是本模块最慢的一步，
        # 只在交叉核对 summary.json 时走
        db.x("""CREATE TEMP TABLE %s AS
                SELECT cand, MAX(COALESCE(tcp_ok, 0)) AS tcp FROM att
                WHERE cand_kind = 'proxy' AND class NOT LIKE '%%canceled%%' AND ts_epoch >= ? GROUP BY cand""" % att_tcp, (since,))
    else:
        db.x("CREATE TEMP TABLE %s AS SELECT cand, tcp FROM vagg" % att_tcp)
    # 每候选按 att class='ok' 通过过的协议（summary.go attempt()：a.Class == "ok" && judgeDst）。按 att(proto, dst, class) 索引只碰 ok 行
    db.x("DROP TABLE IF EXISTS %s" % att_ok)
    db.x("""CREATE TEMP TABLE %s AS
            SELECT cand, MAX(proto = 'socks5') AS s5, MAX(proto = 'socks4') AS s4, MAX(proto = 'connect') AS c, MAX(proto = 'forward') AS f
            FROM att WHERE class = 'ok' AND dst IN ('judge_tls', 'judge_http') AND proto IN ('socks5', 'socks4', 'connect', 'forward')
              AND cand_kind = 'proxy' AND ts_epoch >= ? GROUP BY cand""" % att_ok, (since,))
    db.x("CREATE UNIQUE INDEX %s_cand ON %s(cand)" % (att_ok, att_ok))

    def lab(name):
        return "CASE WHEN l.labels LIKE '%%\"%s\"%%' THEN 1 ELSE 0 END" % name

    def okl(proto):
        return "CASE WHEN l.ok LIKE '%%\"%s\"%%' THEN 1 ELSE 0 END" % proto

    combo_labels = " || ".join("CASE WHEN l_%s = 1 THEN '+%s' ELSE '' END" % (n, n) for n in LABELS)
    combo_ev = " || ".join("CASE WHEN e_%s = 1 THEN '+%s' ELSE '' END" % (PCOL[p], p) for p in OK_ORDER)
    combo_la = " || ".join("CASE WHEN la_%s = 1 THEN '+%s' ELSE '' END" % (PCOL[p], p) for p in OK_ORDER)
    combo_a = " || ".join("CASE WHEN a_%s = 1 THEN '+%s' ELSE '' END" % (PCOL[p], p) for p in OK_ORDER)
    db.x("DROP TABLE IF EXISTS %s" % name)
    db.x("""CREATE TEMP TABLE %(name)s AS
            SELECT *,
                   CASE WHEN label_mask = 0 THEN '%(nolabel)s' ELSE LTRIM(%(cl)s, '+') END AS label_combo,
                   CASE WHEN e_any = 0 THEN '%(none)s' ELSE LTRIM(%(ce)s, '+') END AS e_combo,
                   CASE WHEN la_any = 0 THEN '%(none)s' ELSE LTRIM(%(cla)s, '+') END AS la_combo,
                   CASE WHEN a_any = 0 THEN '%(none)s' ELSE LTRIM(%(ca)s, '+') END AS a_combo
            FROM (
              SELECT l.cand, l.grp, l.prefix24, (d.prefix24 IS NOT NULL) AS dense, l.labels,
                     %(lh)s AS l_http, %(lhs)s AS l_https, %(lc)s AS l_connect, %(l4)s AS l_socks4, %(l5)s AS l_socks5,
                     %(lh)s * 1 + %(lhs)s * 2 + %(lc)s * 4 + %(l4)s * 8 + %(l5)s * 16 AS label_mask,
                     COALESCE(e.s5, 0) AS e_s5, COALESCE(e.s4, 0) AS e_s4, COALESCE(e.c, 0) AS e_c, COALESCE(e.f, 0) AS e_f,
                     CASE WHEN COALESCE(e.s5, 0) + COALESCE(e.s4, 0) + COALESCE(e.c, 0) + COALESCE(e.f, 0) > 0 THEN 1 ELSE 0 END AS e_any,
                     %(o5)s AS la_s5, %(o4)s AS la_s4, %(oc)s AS la_c, %(of)s AS la_f,
                     CASE WHEN l.ok IS NOT NULL AND l.ok != '[]' THEN 1 ELSE 0 END AS la_any,
                     COALESCE(k.s5, 0) AS a_s5, COALESCE(k.s4, 0) AS a_s4, COALESCE(k.c, 0) AS a_c, COALESCE(k.f, 0) AS a_f,
                     CASE WHEN COALESCE(k.s5, 0) + COALESCE(k.s4, 0) + COALESCE(k.c, 0) + COALESCE(k.f, 0) > 0 THEN 1 ELSE 0 END AS a_any,
                     a.n AS n_visits, a.nf AS n_full, CASE WHEN a.nl > 1 THEN 1 ELSE 0 END AS labels_changed,
                     COALESCE(t.tcp, 0) AS tcp
              FROM lastv l JOIN vagg a ON a.cand = l.cand
              LEFT JOIN ev e ON e.cand = l.cand
              LEFT JOIN %(aok)s k ON k.cand = l.cand
              LEFT JOIN dense d ON d.prefix24 = l.prefix24
              LEFT JOIN %(tcp)s t ON t.cand = l.cand)""" % {
        "name": name, "nolabel": NO_LABEL, "none": NONE_COMBO, "cl": combo_labels, "ce": combo_ev, "cla": combo_la, "ca": combo_a,
        "lh": lab("http"), "lhs": lab("https"), "lc": lab("connect"), "l4": lab("socks4"), "l5": lab("socks5"),
        "o5": okl("socks5"), "o4": okl("socks4"), "oc": okl("connect"), "of": okl("forward"), "tcp": att_tcp, "aok": att_ok})
    db.x("CREATE UNIQUE INDEX %s_cand ON %s(cand)" % (name, name))
    return int(db.scalar("SELECT COUNT(*) FROM %s" % name))


def build_source_table(db):
    """TEMP 表 sl(src, label, cand, agg)：来源 × 该来源给的标签 × 候选。常规来源来自 list_event 的 add 事件（含首次快照）；
    聚合器来源来自 agg_member，标签取候选最后一次探访的 labels（聚合器不逐条记快照）。"""
    db.x("DROP TABLE IF EXISTS sl")
    db.x("CREATE TEMP TABLE sl (src TEXT, label TEXT, cand TEXT, agg INTEGER)")
    n_reg = n_agg = 0
    if db.has_table("list_event"):
        db.x("""INSERT INTO sl SELECT DISTINCT src, label, cand, 0 FROM list_event
                WHERE event = 'add' AND label IS NOT NULL AND cand IS NOT NULL""")
        n_reg = int(db.scalar("SELECT COUNT(*) FROM sl WHERE agg = 0"))
    if db.has_table("agg_member"):
        rows = db.q("""SELECT DISTINCT m.src, m.cand, c.labels FROM agg_member m JOIN cl c ON c.cand = m.cand""")
        ins = []
        for src, cand, labels in rows:
            for lab in labels_json_to_list(labels):
                if lab in LABEL_BIT:
                    ins.append((src, lab, cand, 1))
        db.con.executemany("INSERT INTO sl VALUES (?, ?, ?, ?)", ins)
        n_agg = len(ins)
    db.x("CREATE INDEX sl_cand ON sl(cand)")
    db.x("CREATE INDEX sl_src ON sl(src, label)")
    # 每（来源, 候选）一行：该来源给的标签位
    db.x("DROP TABLE IF EXISTS slm")
    db.x("""CREATE TEMP TABLE slm AS
            SELECT src, cand, MAX(agg) AS agg,
                   SUM(DISTINCT CASE label WHEN 'http' THEN 1 WHEN 'https' THEN 2 WHEN 'connect' THEN 4
                                           WHEN 'socks4' THEN 8 WHEN 'socks5' THEN 16 ELSE 0 END) AS mask
            FROM sl GROUP BY src, cand""")
    db.x("CREATE INDEX slm_cand ON slm(cand)")
    return {"常规来源的（来源, 标签, 候选）行": n_reg, "聚合器来源的（来源, 标签, 候选）行": n_agg}


# ---------------------------------------------------------------- 指标

def dense_where(alias, exclude_dense):
    return " AND %s.dense = 0" % alias if exclude_dense else ""


# 对照表的三种实测口径：cl 里的组合列。顺序也是 matrix_by_source 读列的顺序
MATRIX_MODES = (("曾经通过", "e_combo"), ("曾经通过（att class='ok'）", "a_combo"), ("最近一次通过", "la_combo"))


def match_expr(prefix, protos):
    """协议集合里任一通过：prefix 是 e_（曾经）或 la_（最近一次）。"""
    return "CASE WHEN " + " OR ".join("c.%s%s = 1" % (prefix, PCOL[p]) for p in protos) + " THEN 1 ELSE 0 END"


ACC_KEYS = ("den", "e_any", "la_any", "a_any", "es", "el", "ls", "ll", "as_", "al")
ATT_OK_KEY = "曾经通过·按 att class='ok'（summary.go everOK 口径）"


def acc_sums(prefix_lab):
    """accuracy 的 SELECT 列表：分母与三种口径的严格/宽松分子。prefix_lab 给出“标签 → 协议集合”的表达式生成器。"""
    return ", ".join(["COUNT(*)", "SUM(c.e_any)", "SUM(c.la_any)", "SUM(c.a_any)",
                      "SUM(%s)" % prefix_lab("e_", STRICT), "SUM(%s)" % prefix_lab("e_", LENIENT),
                      "SUM(%s)" % prefix_lab("la_", STRICT), "SUM(%s)" % prefix_lab("la_", LENIENT),
                      "SUM(%s)" % prefix_lab("a_", STRICT), "SUM(%s)" % prefix_lab("a_", LENIENT)])


def acc_entry(v):
    """一行准确率：v 是 ACC_KEYS 顺序的计数。visit.ok 的两种口径与 att class='ok' 口径并排，分子分母都给。"""
    return {
        "探访过": v["den"], "曾经可用（任一协议）": v["e_any"], "最近一次探访可用": v["la_any"], "曾经可用（任一协议，att class='ok' 口径）": v["a_any"],
        "曾经通过": {"严格": {"占探访过": ratio(v["es"], v["den"]), "占曾经可用": ratio(v["es"], v["e_any"])},
                 "宽松": {"占探访过": ratio(v["el"], v["den"]), "占曾经可用": ratio(v["el"], v["e_any"])}},
        ATT_OK_KEY: {"严格": {"占探访过": ratio(v["as_"], v["den"]), "占曾经可用（att 口径）": ratio(v["as_"], v["a_any"])},
                     "宽松": {"占探访过": ratio(v["al"], v["den"]), "占曾经可用（att 口径）": ratio(v["al"], v["a_any"])},
                     "与 visit.ok 口径的分子之差（严格）": v["as_"] - v["es"]},
        "最近一次通过": {"严格": {"占探访过": ratio(v["ls"], v["den"]), "占最近一次可用": ratio(v["ls"], v["la_any"])},
                   "宽松": {"占探访过": ratio(v["ll"], v["den"]), "占最近一次可用": ratio(v["ll"], v["la_any"])}},
    }


def accuracy_rows(db, where, params):
    """按标签算准确率。where 是对 cl 别名 c 的附加条件。"""
    out = {}
    tot = {k: 0 for k in ACC_KEYS}
    for lab in LABELS:
        r = db.one("SELECT %s FROM cl c WHERE c.l_%s = 1 %s" % (acc_sums(lambda p, t: match_expr(p, t[lab])), lab, where), params)
        v = {k: int(x or 0) for k, x in zip(ACC_KEYS, r)}
        for k in ACC_KEYS:
            tot[k] += v[k]
        out[lab] = acc_entry(v)
    out["合计（候选-标签对）"] = acc_entry(tot)
    out["合计（候选-标签对）"]["note"] = "一个候选有几个标签就计几次，所以合计的分母可能大于探访过的候选数"
    return out


def accuracy(db, exclude_dense):
    base = dense_where("c", exclude_dense)
    return {
        "total": accuracy_rows(db, base, ()),
        "regular": accuracy_rows(db, base + " AND c.grp = 0", ()),
        "aggregator_sample": accuracy_rows(db, base + " AND c.grp = 1", ()),
    }


def accuracy_by_source(db, exclude_dense):
    """来源 × 该来源给的标签。分子的协议集合由该来源的标签决定（CASE）。"""
    def case(prefix, table):
        return "CASE s.label " + " ".join("WHEN '%s' THEN (%s)" % (lab, match_expr(prefix, table[lab])) for lab in LABELS) + " ELSE 0 END"

    rows = db.q("""SELECT s.src, s.label, MAX(s.agg), %s
                   FROM sl s JOIN cl c ON c.cand = s.cand WHERE 1 = 1 %s
                   GROUP BY s.src, s.label ORDER BY s.src, s.label""" % (acc_sums(case), dense_where("c", exclude_dense)))
    out = {}
    for row in rows:
        src, lab, agg = row[:3]
        v = {k: int(x or 0) for k, x in zip(ACC_KEYS, row[3:])}
        out.setdefault(src, {"aggregator": bool(agg), "labels": {}})["labels"][lab] = acc_entry(v)
    return out


def matrix(db, exclude_dense):
    """标签组合 → 实测组合 → 候选数，曾经通过（visit.ok）、曾经通过（att class='ok'）、最近一次通过各一张；
    另给只看常规列表的一张（接近 summary.json 的口径）。"""
    out = {}
    for mode, col in MATRIX_MODES:
        for scope, extra in (("全部探访过的候选", ""), ("只看常规列表（group=0）", " AND c.grp = 0")):
            rows = db.q("""SELECT c.label_combo, c.%s, COUNT(*) FROM cl c WHERE 1 = 1 %s %s
                           GROUP BY 1, 2 ORDER BY 1, 3 DESC""" % (col, dense_where("c", exclude_dense), extra))
            tab = {}
            for lc, oc, n in rows:
                t = tab.setdefault(lc, {"候选": 0, "实测组合": {}})
                t["候选"] += int(n)
                t["实测组合"][oc] = int(n)
            out.setdefault(mode, {})[scope] = tab
    return out


def matrix_by_source(db, exclude_dense):
    """来源 → 该来源给的标签组合 → 实测组合（三种口径各一个字典）→ 候选数。"""
    rows = db.q("""SELECT s.src, s.mask, c.e_combo, c.a_combo, c.la_combo, COUNT(*) FROM slm s JOIN cl c ON c.cand = s.cand
                   WHERE 1 = 1 %s GROUP BY 1, 2, 3, 4, 5""" % dense_where("c", exclude_dense))
    out = {}
    for src, mask, ec, ac, lc, n in rows:
        name = label_combo_name(int(mask or 0))
        t = out.setdefault(src, {}).setdefault(name, {"候选": 0, **{mode: {} for mode, _ in MATRIX_MODES}})
        t["候选"] += int(n)
        for (mode, _), combo in zip(MATRIX_MODES, (ec, ac, lc)):
            t[mode][combo] = t[mode].get(combo, 0) + int(n)
    return out


def counts(db, have_cands, top_prefixes):
    """各分母：候选、探访过、从没探访过（按标签、按 /24、按来源）。"""
    n = {"探访过": int(db.scalar("SELECT COUNT(*) FROM cl")),
         "探访过且连得上过": int(db.scalar("SELECT COUNT(*) FROM cl WHERE tcp = 1") or 0),
         "探访过且曾经可用": int(db.scalar("SELECT COUNT(*) FROM cl WHERE e_any = 1") or 0),
         "探访过且最近一次可用": int(db.scalar("SELECT COUNT(*) FROM cl WHERE la_any = 1") or 0),
         "分组（最后一次探访的 group）": {"regular": int(db.scalar("SELECT COUNT(*) FROM cl WHERE grp = 0") or 0),
                             "aggregator_sample": int(db.scalar("SELECT COUNT(*) FROM cl WHERE grp = 1") or 0)},
         "标签数分布（探访过的候选）": {str(k): int(v) for k, v in db.q(
             "SELECT l_http + l_https + l_connect + l_socks4 + l_socks5 AS k, COUNT(*) FROM cl GROUP BY k ORDER BY k")},
         "按标签（探访过的候选；多标签的候选在每个标签里各计一次）": {
             lab: int(db.scalar("SELECT COUNT(*) FROM cl WHERE l_%s = 1" % lab) or 0) for lab in LABELS},
         "按标签组合（探访过的候选）": {k: int(v) for k, v in db.q("SELECT label_combo, COUNT(*) FROM cl GROUP BY 1 ORDER BY 2 DESC")},
         "密集 /24 里的探访过候选": int(db.scalar("SELECT COUNT(*) FROM cl WHERE dense = 1") or 0)}
    if have_cands:
        n["候选池（状态文件 cands）"] = int(db.scalar("SELECT COUNT(*) FROM cands"))
        n["有探访记录但不在状态文件里（下榜后被丢弃）"] = int(db.scalar(
            "SELECT COUNT(*) FROM cl WHERE NOT EXISTS (SELECT 1 FROM cands k WHERE k.key = cl.cand)") or 0)
        # 逐行流式读（候选密集的 /24 里从没探访过的候选可能有上万个），只累加计数
        cur = db.con.execute("""SELECT k.label_names, k.prefix24, k.visits FROM cands k
                                WHERE NOT EXISTS (SELECT 1 FROM cl WHERE cl.cand = k.key)""")
        by_label = {lab: 0 for lab in LABELS}
        by_combo, by_prefix = {}, {}
        trial_only = 0
        total_never = 0
        for label_names, prefix24, visits in cur:
            total_never += 1
            labs = [x for x in labels_json_to_list(label_names) if x in LABEL_BIT]
            for lab in labs:
                by_label[lab] += 1
            mask = sum(LABEL_BIT[x] for x in labs)
            name = label_combo_name(mask)
            by_combo[name] = by_combo.get(name, 0) + 1
            by_prefix[prefix24] = by_prefix.get(prefix24, 0) + 1
            if (visits or 0) > 0:
                trial_only += 1
        top = sorted(by_prefix.items(), key=lambda kv: (-kv[1], kv[0] or ""))[:top_prefixes]
        # cands.visits 是 Pool 的累计计数（sched.go Cand.Visits）：Visit() 里 ctx.Err() 的检查在 c.Visits++ 之前，aborted 探访不计入；
        # 跨重启保留、不区分正式起点前后。所以 visits>0 却不在 cl 的候选 = 正式起点之前探访过（含随状态文件从上一次运行带过来的），
        # 或探访记录缺失（日志文件没收全）
        n["从没探访过"] = {
            "总数": total_never, "其中状态文件 visits>0（正式起点之前探访过，或探访记录缺失）": trial_only,
            "按标签": by_label, "按标签组合": dict(sorted(by_combo.items(), key=lambda kv: -kv[1])),
            "按 /24（前 %d 个）" % top_prefixes: [{"prefix24": p, "候选": c} for p, c in top],
            "不同 /24 的个数": len(by_prefix),
        }
        if db.has_table("cand_src"):
            rows = db.q("""SELECT cs.src_name, cs.label_names, COUNT(*) FROM cands k JOIN cand_src cs ON cs.key = k.key
                           WHERE NOT EXISTS (SELECT 1 FROM cl WHERE cl.cand = k.key) GROUP BY 1, 2""")
            src_tab = {}
            for src, label_names, c in rows:
                for lab in labels_json_to_list(label_names):
                    if lab in LABEL_BIT:
                        src_tab.setdefault(src or "(未定)", {})[lab] = src_tab.setdefault(src or "(未定)", {}).get(lab, 0) + int(c)
            n["从没探访过"]["按来源（状态文件结束时仍列着它的来源 × 标签）"] = src_tab
    else:
        n["候选池（状态文件 cands）"] = None
        n["从没探访过"] = {"总数": None, "note": "没有状态文件（cands 表），算不出从没探访过的候选"}
    return n


# ---------------------------------------------------------------- https 标签的附加测试

TLS_SPEAKS = "(COALESCE(tls_ok, 0) = 1 OR tls_class IN ('tls_cert_invalid', 'tls_pin_mismatch', 'tls_alert'))"


def explain_outside(db, proto, dst, cand_sql, since):
    """把“做过某项测试、却不在 cl 的口径里”的尝试按所属探访分解：prober.go Visit() 先做完全部尝试（含附加测试、CONNECT 连 80、tlsproxy）
    再检查 ctx.Err()，程序退出时这次探访写成 aborted=1，att 都在而 visit 不作数；visit.ts 是探访开始时刻 t0，att.ts 是各次尝试的时刻，
    跨正式起点的那次探访被 vv 裁掉而它的 att 落在窗口内。这两种都是仪器的正常行为；“其他”才是异常。
    cand_sql 是给出候选集合的子查询（只含 cand 一列）。按 att(visit) 与 visit(visit) 索引连接，行数只有异常候选的尝试数。"""
    rows = db.q("""SELECT CASE WHEN v.rid IS NULL THEN '探访记录缺失'
                               WHEN COALESCE(v.aborted, 0) = 1 THEN 'aborted 探访（程序退出时被打断）'
                               WHEN v.ts_epoch < ? THEN '探访开始于正式起点之前（跨正式起点）'
                               ELSE '其他（未解释，需查）' END AS why, COUNT(*), COUNT(DISTINCT a.cand)
                   FROM att a LEFT JOIN visit v ON v.visit = a.visit
                   WHERE a.proto = ? AND a.dst = ? AND a.cand_kind = 'proxy' AND a.class NOT LIKE '%%canceled%%' AND a.ts_epoch >= ?
                     AND a.cand IN (%s) GROUP BY 1""" % cand_sql, (since, proto, dst, since))
    return {why: {"尝试": int(n), "候选": int(k)} for why, n, k in rows}


def https_block(db, since):
    """tlsproxy（代理端口本身说不说 TLS）与 CONNECT 连 80 端口（端口策略）。按尝试和按候选各报一次，并与标签、实测对照。"""
    out = {}
    base = "cand_kind = 'proxy' AND class NOT LIKE '%canceled%' AND ts_epoch >= ?"
    # ---- tlsproxy
    rows = db.q("""SELECT class, tls_class, tls_detail_enum, COALESCE(tls_self, 0), tls_sniff, COUNT(*), COUNT(DISTINCT cand)
                   FROM att WHERE proto = 'tlsproxy' AND %s GROUP BY 1, 2, 3, 4, 5 ORDER BY 6 DESC""" % base, (since,))
    per_att = [{"class": c, "tls_class": tc, "tls_detail_enum": de, "tls_self": int(sf), "tls_sniff": sn, "尝试": int(n), "候选": int(k)}
               for c, tc, de, sf, sn, n, k in rows]
    db.x("DROP TABLE IF EXISTS tp")
    db.x("""CREATE TEMP TABLE tp AS
            SELECT cand, COUNT(*) AS n,
                   MAX(CASE WHEN %s THEN 1 ELSE 0 END) AS speaks,
                   MAX(CASE WHEN tls_class = 'tls_not_tls' THEN 1 ELSE 0 END) AS not_tls,
                   MAX(COALESCE(tls_ok, 0)) AS valid_cert,
                   MAX(CASE WHEN tls_class = 'tls_cert_invalid' AND COALESCE(tls_self, 0) = 1 THEN 1 ELSE 0 END) AS self_signed
            FROM att WHERE proto = 'tlsproxy' AND %s GROUP BY cand""" % (TLS_SPEAKS, base), (since,))
    db.x("CREATE UNIQUE INDEX tp_cand ON tp(cand)")
    verdict = """CASE WHEN t.cand IS NULL THEN '没做 tlsproxy 尝试' WHEN t.speaks = 1 THEN '端口说 TLS'
                      WHEN t.not_tls = 1 THEN '端口不说 TLS' ELSE '无结论（超时/断开/连不上）' END"""

    def tls_table(where):
        rows = db.q("""SELECT %s AS v, c.e_c, c.e_f, c.la_c, COUNT(*) FROM cl c LEFT JOIN tp t ON t.cand = c.cand
                       WHERE %s GROUP BY 1, 2, 3, 4""" % (verdict, where))
        tab = {}
        for v, ec, ef, lc, n in rows:
            t = tab.setdefault(v, {"候选": 0, "其中 CONNECT 曾通过": 0, "其中 CONNECT 最近一次通过": 0, "其中转发曾通过": 0,
                                   "其中 CONNECT 和转发都没通过": 0})
            t["候选"] += int(n)
            if ec:
                t["其中 CONNECT 曾通过"] += int(n)
            if lc:
                t["其中 CONNECT 最近一次通过"] += int(n)
            if ef:
                t["其中转发曾通过"] += int(n)
            if not ec and not ef:
                t["其中 CONNECT 和转发都没通过"] += int(n)
        den = sum(t["候选"] for t in tab.values())
        tested = den - tab.get("没做 tlsproxy 尝试", {}).get("候选", 0)
        return {"候选": den, "做过 tlsproxy 尝试的候选": tested,
                "端口说 TLS 的比例（占做过尝试的）": ratio(tab.get("端口说 TLS", {}).get("候选", 0), tested),
                "端口不说 TLS 的比例（占做过尝试的）": ratio(tab.get("端口不说 TLS", {}).get("候选", 0), tested),
                "按结论": tab}

    tls_by_combo = {}
    for (lc,) in db.q("SELECT DISTINCT c.label_combo FROM cl c JOIN tp t ON t.cand = c.cand ORDER BY 1"):
        tls_by_combo[lc] = tls_table("c.label_combo = '%s'" % lc.replace("'", "''"))
    extra = db.one("""SELECT COUNT(*), SUM(c.cand IS NOT NULL AND c.l_https = 0 AND c.l_connect = 0), SUM(c.cand IS NULL)
                      FROM tp t LEFT JOIN cl c ON c.cand = t.cand""")
    # prober.go Visit() 只对 was.Labels 含 https/connect 的候选做 tlsproxy；Cand.Labels 只增不减（sched.go Delist 只改 Srcs，不清 Labels），
    # 所以探访过的候选最后一次的 labels ⊇ 做 tlsproxy 时的 labels，“在 cl 里却两种标签都没有”只可能来自跨正式起点、且中间状态被清空的探访，
    # 正常应为 0。做过尝试却不在 cl 里的候选来自 aborted 探访或跨正式起点的探访（见 explain_outside），不是异常
    out["tlsproxy"] = {
        "按尝试": per_att,
        "按候选（标签含 https）": tls_table("c.l_https = 1"),
        "按候选（标签含 connect、不含 https）": tls_table("c.l_connect = 1 AND c.l_https = 0"),
        "按候选（按标签组合）": tls_by_combo,
        "证书统计（做过尝试的候选）": {
            "做过尝试的候选": int(extra[0] or 0),
            "证书按 IP 校验通过": int(db.scalar("SELECT SUM(valid_cert) FROM tp") or 0),
            "证书校验不过且自签": int(db.scalar("SELECT SUM(self_signed) FROM tp") or 0),
            "探访过、标签却既不含 https 也不含 connect（Cand.Labels 只增不减，正常应为 0）": int(extra[1] or 0),
            "做过尝试但不在探访过的候选里（只有 aborted 或跨正式起点的探访）": int(extra[2] or 0),
            "不在探访过的候选里的尝试按所属探访分解": explain_outside(
                db, "tlsproxy", "self", "SELECT t.cand FROM tp t LEFT JOIN cl c ON c.cand = t.cand WHERE c.cand IS NULL", since),
        },
    }
    # ---- CONNECT 连 80 端口
    rows = db.q("""SELECT class, hs_class, hs_code, COUNT(*), COUNT(DISTINCT cand) FROM att
                   WHERE proto = 'connect' AND dst = 'judge_http' AND %s GROUP BY 1, 2, 3 ORDER BY 4 DESC""" % base, (since,))
    per_att = [{"class": c, "hs_class": hc, "hs_code": code, "尝试": int(n), "候选": int(k)} for c, hc, code, n, k in rows]
    db.x("DROP TABLE IF EXISTS c80")
    db.x("""CREATE TEMP TABLE c80 AS
            SELECT cand, COUNT(*) AS n, MAX(COALESCE(hs_ok, 0)) AS allowed,
                   MAX(CASE WHEN hs_class = 'hs_refused' THEN 1 ELSE 0 END) AS refused,
                   MAX(CASE WHEN hs_class = 'hs_auth' THEN 1 ELSE 0 END) AS auth,
                   MAX(CASE WHEN class = 'ok' THEN 1 ELSE 0 END) AS e2e_ok
            FROM att WHERE proto = 'connect' AND dst = 'judge_http' AND %s GROUP BY cand""" % base, (since,))
    db.x("CREATE UNIQUE INDEX c80_cand ON c80(cand)")
    refused_codes = {str(code): int(n) for code, n in db.q(
        """SELECT hs_code, COUNT(DISTINCT cand) FROM att WHERE proto = 'connect' AND dst = 'judge_http' AND hs_class = 'hs_refused'
           AND %s GROUP BY 1 ORDER BY 2 DESC""" % base, (since,))}
    verdict80 = """CASE WHEN t.cand IS NULL THEN '没做 80 端口测试' WHEN t.allowed = 1 THEN '允许连 80 端口'
                        WHEN t.refused = 1 THEN '拒绝（协议层）' WHEN t.auth = 1 THEN '要求认证' ELSE '无结论（超时/断开）' END"""

    def c80_table(where):
        rows = db.q("""SELECT %s AS v, COUNT(*), SUM(COALESCE(t.e2e_ok, 0)) FROM cl c LEFT JOIN c80 t ON t.cand = c.cand
                       WHERE %s GROUP BY 1""" % (verdict80, where))
        tab = {v: {"候选": int(n), "其中明文 HTTP 也通过核对（class='ok'）": int(e or 0)} for v, n, e in rows}
        den = sum(t["候选"] for t in tab.values())
        tested = den - tab.get("没做 80 端口测试", {}).get("候选", 0)
        return {"候选": den, "做过 80 端口测试的候选": tested,
                "允许的比例（占做过测试的）": ratio(tab.get("允许连 80 端口", {}).get("候选", 0), tested),
                "拒绝的比例（占做过测试的）": ratio(tab.get("拒绝（协议层）", {}).get("候选", 0), tested),
                "按结论": tab}

    out["connect_to_port_80"] = {
        "按尝试": per_att,
        "拒绝时 CONNECT 应答的状态码（候选数）": refused_codes,
        "按候选（CONNECT 曾通过的候选，即有资格做这项测试的）": c80_table("c.e_c = 1"),
        "按候选（CONNECT 曾通过且标签含 https）": c80_table("c.e_c = 1 AND c.l_https = 1"),
        "按候选（CONNECT 曾通过且标签不含 https）": c80_table("c.e_c = 1 AND c.l_https = 0"),
        # prober.go Visit()：CONNECT 连 80 只在 okMask&PConnect≠0 时做，所以这次探访若作数，visit.ok 必含 connect；
        # 不含的只能是 aborted 探访（att 都在、visit 不作数）或跨正式起点的探访（visit 在窗口外、att 在窗口内），分解见下
        "做过测试但 visit.ok 里没有 CONNECT 的候选（来自 aborted 探访或跨正式起点的探访）": int(db.scalar(
            "SELECT COUNT(*) FROM c80 t LEFT JOIN cl c ON c.cand = t.cand WHERE COALESCE(c.e_c, 0) = 0") or 0),
        "这些候选的 80 端口测试按所属探访分解": explain_outside(
            db, "connect", "judge_http", "SELECT t.cand FROM c80 t LEFT JOIN cl c ON c.cand = t.cand WHERE COALESCE(c.e_c, 0) = 0", since),
    }
    return out


# ---------------------------------------------------------------- 内部一致性

def checks(db, have_cands, since):
    out = {}
    out["标签在观察期内变过的候选（探访记录里 labels 不止一种）"] = int(db.scalar("SELECT SUM(labels_changed) FROM cl") or 0)
    # list_event 的标签并集 vs 最后一次探访的 labels（只看常规来源有事件的候选）
    r = db.one("""SELECT COUNT(*), SUM((x.m | c.label_mask) != c.label_mask), SUM((x.m | c.label_mask) != x.m)
                  FROM (SELECT cand, SUM(DISTINCT CASE label WHEN 'http' THEN 1 WHEN 'https' THEN 2 WHEN 'connect' THEN 4
                                                             WHEN 'socks4' THEN 8 WHEN 'socks5' THEN 16 ELSE 0 END) AS m
                        FROM sl WHERE agg = 0 GROUP BY cand) x JOIN cl c ON c.cand = x.cand""")
    out["快照事件的标签并集 vs 最后一次探访的 labels（有快照事件的候选）"] = {
        "候选": int(r[0] or 0), "快照里有、探访记录里没有的标签（最后一次探访之后才上榜的文件）": int(r[1] or 0),
        "探访记录里有、快照里没有的标签（只可能来自聚合器）": int(r[2] or 0)}
    r = db.one("""SELECT COUNT(*), SUM(COALESCE(c.n_ok, 0) != cnt) FROM
                  (SELECT v.rid, v.n_ok, COUNT(o.rid) AS cnt FROM visit v LEFT JOIN visit_ok o ON o.visit = v.visit GROUP BY v.rid) c""")
    out["visit.n_ok vs visit_ok 子表条数不一致的探访"] = {"num": int(r[1] or 0), "den": int(r[0] or 0)}
    # visit 口径的“曾经通过”（e_*）vs att 口径（a_*：class='ok' 且目的地是 judge，build_cand_table 里已并进 cl），按（候选, 协议）对
    r = db.one("""SELECT COUNT(*),
                         SUM(c.e_s5 != c.a_s5) + SUM(c.e_s4 != c.a_s4) + SUM(c.e_c != c.a_c) + SUM(c.e_f != c.a_f),
                         SUM(c.e_f = 0 AND c.a_f = 1),
                         SUM(c.e_s5 = 0 AND c.a_s5 = 1) + SUM(c.e_s4 = 0 AND c.a_s4 = 1) + SUM(c.e_c = 0 AND c.a_c = 1),
                         SUM(c.e_s5 = 1 AND c.a_s5 = 0) + SUM(c.e_s4 = 1 AND c.a_s4 = 0) + SUM(c.e_c = 1 AND c.a_c = 0) + SUM(c.e_f = 1 AND c.a_f = 0)
                  FROM cl c""")
    out["visit.ok 的“曾经通过” vs att class='ok'（到 judge）不一致的（候选, 协议）对"] = {
        "num": int(r[1] or 0), "den": int(r[0] or 0) * 4,
        "其中 forward 只在 att 里 ok（附加测试的 j/b 载荷通过而 h 载荷不符，summary.go 会把它算成 forward 可用）": int(r[2] or 0),
        "其中隧道协议只在 att 里 ok（只能来自 aborted 探访里的尝试）": int(r[3] or 0),
        "其中只在 visit.ok 里 ok（不该出现：ok 的尝试一定有 att 记录）": int(r[4] or 0),
        "note": "visit.ok 只含主循环的尝试（prober.go Visit()），att 还含附加测试、端口策略测试和 aborted 探访里的尝试；差异应只来自这些"}
    if have_cands:
        # 状态文件的 label_names / ok_protos 是 ingest 写的 JSON 文本，visit 的是 Go 写的，空格可能不同：解析后按集合比，不比文本
        den = lab_diff = ok_diff = 0
        cur = db.con.execute("""SELECT k.label_names, c.labels, k.ok_protos, c.la_s5, c.la_s4, c.la_c, c.la_f
                                FROM cl c JOIN cands k ON k.key = c.cand""")
        while True:
            rows = cur.fetchmany(5000)
            if not rows:
                break
            for label_names, labels, ok_protos, s5, s4, c, f in rows:
                den += 1
                if set(labels_json_to_list(label_names)) != set(labels_json_to_list(labels)):
                    lab_diff += 1
                mine = {p for p, flag in zip(("socks5", "socks4", "connect", "forward"), (s5, s4, c, f)) if flag}
                if set(labels_json_to_list(ok_protos)) != mine:
                    ok_diff += 1
        out["cands.label_names（状态文件）vs 最后一次探访的 labels 不一致的候选"] = {
            "num": lab_diff, "den": den, "note": "最后一次探访之后又上榜了新文件会造成差异"}
        out["cands.ok_protos（状态文件）vs 最后一次探访的 ok 不一致的候选"] = {
            "num": ok_diff, "den": den, "note": "状态文件是结束时刻的快照；aborted 探访或正式起点的裁剪会造成差异"}
        r = db.one("SELECT COUNT(*), SUM(COALESCE(k.ever_ok, 0) != c.e_any) FROM cl c JOIN cands k ON k.key = c.cand")
        out["cands.ever_ok vs visit 口径曾经可用 不一致的候选"] = {"num": int(r[1] or 0), "den": int(r[0] or 0)}
    return out


# ---------------------------------------------------------------- 与 summary.json 交叉核对

def crosscheck_summary(db, path):
    """照 summary.go 的口径重算并逐格比较：
    - labels：finish()——候选取最后一次非 aborted 探访的 group 与 labels（整个数据，不裁正式起点）、group=0、连得上过（任何 att 的 TCP 通过）；
      实测取 attempt() 的 everOK：class='ok' 且目的地是 judge（judge_tls 或 judge_http）的 att 的 proto，按 socks5、connect、forward、socks4 拼接，空为“无”。
    - extras.connect_to_port_80：proto=connect、dst=judge_http 的尝试按 class 计数。
    - extras.https_label_port_speaks_tls：tlsproxy 尝试按 class 计数，tls_cert_invalid 时附 detail（只能复现枚举值；'other' 的原文复现不了）。
    只读 summary.json 里的计数字段；examples 等含地址的字段一概不读。"""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    out = {"summary_generated": s.get("generated")}
    cmp = {}

    def put(key, want, got):
        cmp[key] = {"summary": want, "computed": got, "match": (want == got)}

    # 整个数据（since=0）、连得上过按 att 全表（summary.go attempt() 的 c.tcp：任何目的地、含 aborted 探访里的尝试），
    # 与主表按 visit.state 的口径只差 aborted 探访里的尝试。这是本模块唯一一次对 att 全表按候选分组
    build_cand_table(db, 0.0, name="clx", att_tcp="atcpx", att_ok="aokx", tcp_source="att")
    rows = db.q("""SELECT c.labels, c.a_s5, c.a_c, c.a_f, c.a_s4, COUNT(*)
                   FROM clx c WHERE c.grp = 0 AND c.tcp = 1 GROUP BY 1, 2, 3, 4, 5""")
    mine = {}
    for labels, s5, c, f, s4, n in rows:
        key = "+".join(labels_json_to_list(labels))
        oks = [p for p, flag in zip(OK_ORDER, (s5, c, f, s4)) if flag]
        val = "+".join(oks) if oks else NONE_COMBO
        mine.setdefault(key, {})[val] = mine.setdefault(key, {}).get(val, 0) + int(n)
    want = s.get("labels") or {}
    for key in sorted(set(want) | set(mine)):
        for val in sorted(set(want.get(key, {})) | set(mine.get(key, {}))):
            put("labels.%s.%s" % (key, val), want.get(key, {}).get(val), mine.get(key, {}).get(val))
    extras = s.get("extras") or {}
    base = "cand_kind = 'proxy' AND class NOT LIKE '%canceled%'"
    got = {c: int(n) for c, n in db.q("SELECT class, COUNT(*) FROM att WHERE proto = 'connect' AND dst = 'judge_http' AND %s GROUP BY 1" % base)}
    want80 = extras.get("connect_to_port_80") or {}
    for k in sorted(set(want80) | set(got)):
        put("extras.connect_to_port_80.%s" % k, want80.get(k), got.get(k))
    got = {}
    for cls, de, n in db.q("SELECT class, tls_detail_enum, COUNT(*) FROM att WHERE proto = 'tlsproxy' AND %s GROUP BY 1, 2" % base):
        k = cls
        if cls == "tls_cert_invalid" and de:
            k = "%s (%s)" % (cls, de if de != "other" else "其他：原文复现不了")
        got[k] = got.get(k, 0) + int(n)
    wantt = extras.get("https_label_port_speaks_tls") or {}
    for k in sorted(set(wantt) | set(got)):
        put("extras.https_label_port_speaks_tls.%s" % k, wantt.get(k), got.get(k))
    out["comparisons"] = cmp
    out["matched"] = sum(1 for v in cmp.values() if v["match"])
    out["total"] = len(cmp)
    out["mismatches"] = sorted(k for k, v in cmp.items() if not v["match"])
    out["note"] = "labels 按 summary.go finish() 的口径重算（整个数据、常规列表、连得上过、att 的 class='ok'），与本模块主表（正式窗口、全部探访过、visit.ok）口径不同"
    return out


# ---------------------------------------------------------------- 输出前的断言

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?!\d|\.\d|/24)")
HOSTPORT_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}:\d{1,5}")


def assert_clean(text, db):
    """最后一道保险：输出文本里不许有 ip:port、不带 /24 的 IPv4、judge 的主机名或 IP、邮箱（@）。这是断言，不是放行手段。
    judge 的身份只从库里的 self_names / self_ips 表取（ingest 从 start 记录和 judge 记录推出），模块里不写它的字面量；
    夹具 judge 的主机名和回环地址也在这两张表里（ingest 从 start 记录读出），裸 IPv4 另有 IPV4_RE 兜着。"""
    bad = []
    if HOSTPORT_RE.search(text):
        bad.append("ip:port")
    if IPV4_RE.search(text):
        bad.append("不带 /24 的 IPv4")
    for table, col in (("self_names", "name"), ("self_ips", "ip")):
        if db.has_table(table):
            for (v,) in db.q("SELECT DISTINCT %s FROM %s" % (col, table)):
                if v and v.lower() in text.lower():
                    bad.append("judge 身份（%s）" % table)
                    break
    if "@" in text:
        bad.append("字面量 @")
    if bad:
        raise SystemExit("输出含不许出现的内容：%s；已拒绝写出" % "、".join(bad))


# ---------------------------------------------------------------- Markdown

def acc_cell(row, mode, kind, key):
    return rfmt(row[mode][kind][key])


def print_accuracy_table(title, rows):
    print(f"\n{title}\n")
    print("| 标签 | 探访过 | 曾经可用 | 曾经通过·严格 | 曾经通过·宽松 | 曾经通过·严格·按 att class='ok' | 曾经通过·严格（占曾经可用） | "
          "最近一次·严格 | 最近一次·宽松 | 最近一次·严格（占最近一次可用） |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for lab in LABELS + ["合计（候选-标签对）"]:
        r = rows[lab]
        if lab != "合计（候选-标签对）" and r["探访过"] == 0:
            continue
        print(f"| {lab} | {fmt(r['探访过'])} | {fmt(r['曾经可用（任一协议）'])} | {acc_cell(r, '曾经通过', '严格', '占探访过')} | "
              f"{acc_cell(r, '曾经通过', '宽松', '占探访过')} | {acc_cell(r, ATT_OK_KEY, '严格', '占探访过')} | "
              f"{acc_cell(r, '曾经通过', '严格', '占曾经可用')} | "
              f"{acc_cell(r, '最近一次通过', '严格', '占探访过')} | {acc_cell(r, '最近一次通过', '宽松', '占探访过')} | "
              f"{acc_cell(r, '最近一次通过', '严格', '占最近一次可用')} |")


def print_markdown(res):
    w = res["window"]
    n = res["n"]
    print("### 标签准确率（PROTOCOL“指标定义”）\n")
    print(f"- 正式起点 {w['formal_start_utc']}（{w['formal_start_rule']}），结束 {w['end_utc']}，共 {fmt(w['hours'])} 小时；"
          f"正式起点之前的试运行探访 {fmt(w['trial_run_visits_before_formal_start'])} 次")
    nv = n.get("从没探访过") or {}
    print(f"- 探访过的候选 {fmt(n['探访过'])}（常规 {fmt(n['分组（最后一次探访的 group）']['regular'])}，"
          f"聚合器抽样 {fmt(n['分组（最后一次探访的 group）']['aggregator_sample'])}；连得上过 {fmt(n['探访过且连得上过'])}，"
          f"曾经可用 {fmt(n['探访过且曾经可用'])}），从没探访过 {fmt(nv.get('总数'))}，"
          f"密集 /24 {fmt(res['dense_prefixes']['count'])} 个（含探访过的候选 {fmt(n['密集 /24 里的探访过候选'])}）")
    print("- 标签声称的协议：严格 = " + "、".join(f"{k}→{'/'.join(v)}" for k, v in STRICT.items())
          + "；宽松（labelProtos）= " + "、".join(f"{k}→{'/'.join(v)}" for k, v in LENIENT.items()))
    print("- 实测口径：“曾经通过”“最近一次通过”按 visit.ok（只含主循环的尝试）；“按 att class='ok'”是 summary.go everOK 口径，"
          "多出附加测试里 j/b 载荷通过而 h 载荷不符的转发（最接近 PROTOCOL“可用”行的原句）")
    print_accuracy_table("#### 按标签（全部探访过的候选）", res["accuracy"]["all"]["total"])
    if res["dense_prefixes"]["count"]:
        print_accuracy_table("#### 按标签（去掉候选超过 %d 个的 /24）" % res["dense_prefixes"]["threshold"], res["accuracy"]["excluding_dense"]["total"])
        print("\n| 被去掉的 /24 | 候选 | 正式窗口内探访到（按 cl） | 有尝试记录（含试运行） |")
        print("| --- | --- | --- | --- |")
        for p in res["dense_prefixes"]["prefixes"]:
            print(f"| {p['prefix24']} | {fmt(p['候选'])} | {fmt(p['正式窗口内探访到（按 cl）'])} | "
                  f"{fmt(p['有尝试记录（含试运行）'])} |")
    for mode, _ in MATRIX_MODES:
        tab = res["matrix"]["all"][mode]["全部探访过的候选"]
        print(f"\n#### 对照表：标签组合 → 实测通过的协议组合（{mode}，全部探访过的候选）\n")
        print("| 标签组合 | 候选 | 实测组合（个数） |")
        print("| --- | --- | --- |")
        for lc in sorted(tab, key=lambda k: -tab[k]["候选"]):
            cells = "，".join(f"{oc} {fmt(c)}" for oc, c in sorted(tab[lc]["实测组合"].items(), key=lambda kv: -kv[1]))
            print(f"| {lc} | {fmt(tab[lc]['候选'])} | {cells} |")
    bs = res["accuracy_by_source"]["all"]
    if bs:
        print("\n#### 按来源（该来源自己给的标签）\n")
        print("| 来源 | 标签 | 探访过 | 曾经可用 | 曾经通过·严格 | 曾经通过·宽松 | 最近一次·严格 | 最近一次·宽松 |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for src in sorted(bs):
            for lab in LABELS:
                r = bs[src]["labels"].get(lab)
                if not r:
                    continue
                print(f"| {src}{'（聚合器）' if bs[src]['aggregator'] else ''} | {lab} | {fmt(r['探访过'])} | {fmt(r['曾经可用（任一协议）'])} | "
                      f"{acc_cell(r, '曾经通过', '严格', '占探访过')} | {acc_cell(r, '曾经通过', '宽松', '占探访过')} | "
                      f"{acc_cell(r, '最近一次通过', '严格', '占探访过')} | {acc_cell(r, '最近一次通过', '宽松', '占探访过')} |")
    h = res["https_label"]
    t = h["tlsproxy"]["按候选（标签含 https）"]
    print(f"\n#### 标签含 https 的候选：代理端口本身说不说 TLS（tlsproxy）\n")
    print(f"- 候选 {fmt(t['候选'])}，做过 tlsproxy 尝试 {fmt(t['做过 tlsproxy 尝试的候选'])}；"
          f"端口说 TLS {rfmt(t['端口说 TLS 的比例（占做过尝试的）'])}，不说 TLS {rfmt(t['端口不说 TLS 的比例（占做过尝试的）'])}")
    print("\n| 结论 | 候选 | 其中 CONNECT 曾通过 | 其中转发曾通过 | 其中两者都没通过 |")
    print("| --- | --- | --- | --- | --- |")
    for v, r in sorted(t["按结论"].items(), key=lambda kv: -kv[1]["候选"]):
        print(f"| {v} | {fmt(r['候选'])} | {fmt(r['其中 CONNECT 曾通过'])} | {fmt(r['其中转发曾通过'])} | {fmt(r['其中 CONNECT 和转发都没通过'])} |")
    c = h["connect_to_port_80"]
    print(f"\n#### CONNECT 连 80 端口（端口策略）\n")
    for key in ("按候选（CONNECT 曾通过的候选，即有资格做这项测试的）", "按候选（CONNECT 曾通过且标签含 https）"):
        r = c[key]
        print(f"- {key}：候选 {fmt(r['候选'])}，做过测试 {fmt(r['做过 80 端口测试的候选'])}；允许 {rfmt(r['允许的比例（占做过测试的）'])}，"
              f"拒绝 {rfmt(r['拒绝的比例（占做过测试的）'])}；按结论 "
              + "，".join(f"{v} {fmt(x['候选'])}" for v, x in sorted(r["按结论"].items(), key=lambda kv: -kv[1]["候选"])))
    if c["拒绝时 CONNECT 应答的状态码（候选数）"]:
        print("- 拒绝时的应答状态码（候选数）：" + "，".join(f"{k} {fmt(v)}" for k, v in c["拒绝时 CONNECT 应答的状态码（候选数）"].items()))
    if "crosscheck" in res:
        cc = res["crosscheck"]
        print(f"\n### 与 summary.json 交叉核对：{cc['matched']}/{cc['total']} 项一致"
              + (f"，不一致：{', '.join(cc['mismatches'])}" if cc["mismatches"] else ""))


# ---------------------------------------------------------------- 主流程

def run(db_path, out_dir, summary_path=None, formal_start="auto", dense_threshold=DENSE_THRESHOLD,
        top_prefixes=TOP_PREFIXES, markdown=False, write=True):
    db = DB(db_path)
    wl_source = check_whitelist(db)
    for t in ("visit", "visit_ok", "att"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表" % t)
    have_cands = db.has_table("cands")
    win = observation_window(db, formal_start)
    fs, _end = win.pop("_fs"), win.pop("_end")
    res = {
        "module": MODULE, "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol_version": PROTOCOL_VERSION, "whitelist_source": wl_source,
        "db_meta": {k: db.meta(k) for k in ("ingest_version", "first_ts", "last_ts", "state_cands", "state_tz_offsets")},
        "definitions": DEFINITIONS,
        "label_protocol_map": {"严格": STRICT, "宽松（prober.go labelProtos）": LENIENT},
        "window": win,
    }
    res["dense_prefixes"] = build_dense(db, dense_threshold)
    n_visited = build_cand_table(db, fs)
    if n_visited == 0:
        print("正式起点之后没有任何非 aborted 的探访，各表为空", file=sys.stderr)
    dense_visited(db, res["dense_prefixes"])
    res["source_table"] = build_source_table(db)
    res["n"] = counts(db, have_cands, top_prefixes)
    res["accuracy"] = {"all": accuracy(db, False), "excluding_dense": accuracy(db, True)}
    res["accuracy_by_source"] = {"all": accuracy_by_source(db, False), "excluding_dense": accuracy_by_source(db, True)}
    res["matrix"] = {"all": matrix(db, False), "excluding_dense": matrix(db, True)}
    res["matrix_by_source"] = {"all": matrix_by_source(db, False), "excluding_dense": matrix_by_source(db, True)}
    res["https_label"] = https_block(db, fs)
    res["checks"] = checks(db, have_cands, fs)
    if summary_path:
        res["crosscheck"] = crosscheck_summary(db, summary_path)

    text = json.dumps(res, ensure_ascii=False, indent=1, sort_keys=False)
    assert_clean(text, db)
    if write:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, OUTPUT_NAME)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("已写出 %s（%d 字节）" % (path, len(text.encode("utf-8"))), file=sys.stderr)
    if markdown:
        print_markdown(res)
    return res


# ---------------------------------------------------------------- 自检：合成库

def _synthetic_db(path):
    """最小合成库，只建本模块用到的列。场景见各条注释；预期值在 selftest() 里断言。地址只用文档保留段（TEST-NET）。"""
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE visit (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, "group" INTEGER, n INTEGER,
        prev TEXT, state TEXT, "full" INTEGER, listed INTEGER, labels TEXT, tried TEXT, ok TEXT, auth INTEGER, aborted INTEGER,
        next_min REAL, ms INTEGER, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT, n_ok INTEGER);
    CREATE TABLE visit_ok (rid INTEGER PRIMARY KEY, visit_rid INTEGER, visit TEXT, cand TEXT, ts TEXT, ts_epoch REAL, proto TEXT);
    CREATE TABLE att (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, kind TEXT, class TEXT,
        tcp_ok INTEGER, hs_ok INTEGER, hs_class TEXT, hs_code INTEGER, tls_ok INTEGER, tls_class TEXT, tls_detail_enum TEXT,
        tls_self INTEGER, tls_sniff TEXT, cand_kind TEXT, prefix24 TEXT);
    CREATE INDEX att_visit ON att(visit);
    CREATE INDEX visit_visit ON visit(visit);
    CREATE TABLE cands (rid INTEGER PRIMARY KEY, key TEXT UNIQUE, ip TEXT, port INTEGER, prefix24 TEXT, "group" INTEGER, n_srcs INTEGER,
        listed INTEGER, labels INTEGER, label_names TEXT, visits INTEGER, state INTEGER, state_name TEXT, ok_mask INTEGER, ok_protos TEXT, ever_ok INTEGER);
    CREATE TABLE cand_src (rid INTEGER PRIMARY KEY, key TEXT, src_idx INTEGER, src_name TEXT, labels INTEGER, label_names TEXT);
    CREATE TABLE list_event (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, src TEXT, label TEXT, cand TEXT, event TEXT, base INTEGER,
        cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
    CREATE TABLE agg_member (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, src TEXT, seq INTEGER, cand TEXT, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
    CREATE TABLE start (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER);
    CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visits INTEGER);
    CREATE TABLE version (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, version TEXT);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
    """)
    E = parse_iso("2026-11-06T00:00:00Z")  # 正式起点
    H = 3600.0
    P_N = "198.51.100.0/24"   # 普通 /24（TEST-NET-2，只在合成库里）
    P_D = "203.0.113.0/24"    # 密集 /24（TEST-NET-3）
    P_A = "192.0.2.0/24"      # 聚合器条目（TEST-NET-1）
    SRC_A, SRC_B, SRC_Z = "synthetic/listA", "synthetic/listB", "synthetic/aggZ"

    def key(prefix, i, port=8080):
        return "%s.%d:%d" % (prefix.rsplit(".", 1)[0], i, port)

    X = {i: key(P_N, i) for i in range(1, 13)}
    D = {i: key(P_D, i % 250 + 1, 10000 + i) for i in range(1, 102)}
    M = {1: key(P_A, 1), 2: key(P_A, 2)}
    con.execute("INSERT INTO start (ts, ts_epoch, resumed_candidates) VALUES (?, ?, 0)", (iso_minute(E - 2 * H), E - 2 * H))
    con.execute("INSERT INTO stop (ts, ts_epoch, visits) VALUES (?, ?, 1)", (iso_minute(E - 0.5 * H), E - 0.5 * H))
    con.execute("INSERT INTO start (ts, ts_epoch, resumed_candidates) VALUES (?, ?, 0)", (iso_minute(E), E))  # 状态被清空：正式起点
    con.execute("INSERT INTO version (ts, ts_epoch, version) VALUES (?, ?, 'test')", (iso_minute(E), E))
    con.execute("INSERT INTO meta VALUES ('ingest_version', 'selftest')")
    con.execute("INSERT INTO self_names VALUES ('judge.invalid', 'start.judge_host', 1)")
    con.execute("INSERT INTO self_ips VALUES ('192.0.2.250', 'start.judge_ip', 1)")

    # ---- 列表快照事件：来源 × 标签 × 候选
    ev = []
    for i in (1, 6, 7, 8, 9):
        ev.append((SRC_A, "http", X[i]))
    ev += [(SRC_A, "https", X[2]), (SRC_B, "http", X[2]),          # X2：A 标 https，B 标 http → 累计 http+https
           (SRC_A, "https", X[3]), (SRC_A, "https", X[11]), (SRC_A, "https", X[12]),
           (SRC_A, "socks5", X[4]), (SRC_A, "socks5", X[5]), (SRC_A, "socks5", X[6]),  # X6：A 同时标 http 和 socks5
           (SRC_B, "connect", X[10])]
    ev += [(SRC_A, "http", D[i]) for i in range(1, 102)]
    for src, lab, cand in ev:
        ip, port = cand.rsplit(":", 1)
        con.execute("INSERT INTO list_event (ts, ts_epoch, src, label, cand, event, base, cand_ip, cand_port, prefix24) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (iso_minute(E), E, src, lab, cand, "add", 1, ip, int(port), ip.rsplit(".", 1)[0] + ".0/24"))
    for i, cand in M.items():
        ip, port = cand.rsplit(":", 1)
        con.execute("INSERT INTO agg_member (ts, ts_epoch, src, seq, cand, cand_ip, cand_port, prefix24) VALUES (?,?,?,?,?,?,?,?)",
                    (iso_minute(E), E, SRC_Z, i, cand, ip, int(port), P_A))

    # ---- 探访：(时刻, 候选, group, labels, ok, full, aborted, state)
    # state 照 prober.go Visit() 写回的规则：有协议通过→working、只连得上→open、连不上→dead；aborted 的探访 state = prev（这里都是 new）
    visits = []

    def v(t, cand, labels, ok, full=1, grp=None, aborted=None, tcp=True):
        state = "new" if aborted else ("working" if ok else ("open" if tcp else "dead"))
        visits.append((t, cand, grp, labels, ok, full, aborted, state))

    v(E - 1 * H, X[9], ["http"], ["forward"])                              # X9：只在试运行里探访过（正式起点前），不作数
    v(E + 0.2 * H, X[1], ["http"], ["connect", "forward"])                  # X1：曾经 connect+forward
    v(E + 6.5 * H, X[1], ["http"], ["connect"], full=0)                     #     最近一次只剩 connect → http 严格最近一次 ✗
    v(E + 0.2 * H, X[2], ["http", "https"], ["connect", "forward"])         # X2：http+https，两者都对
    v(E + 0.3 * H, X[3], ["https"], ["forward"])                            # X3：标 https 只通转发 → 严格 ✗ 宽松 ✓
    v(E + 0.3 * H, X[4], ["socks5"], ["socks4"])                            # X4：标 socks5 实为 socks4
    v(E + 0.4 * H, X[5], ["socks5"], [])                                    # X5：开着但没协议通过
    v(E + 6.4 * H, X[5], ["socks5"], [], full=0)
    v(E + 0.5 * H, X[6], ["http"], ["socks5"])                              # X6：先只有 http 标签
    v(E + 6.6 * H, X[6], ["http", "socks5"], ["socks5"], full=0)            #     后来 socks5 文件也列了它：标签变过
    v(E + 1.0 * H, X[8], ["http"], ["connect"], aborted=1)                  # X8：只有 aborted 探访 → 不算探访过（它的 att 都在，含 80 端口测试）
    v(E + 1.0 * H, X[10], ["connect"], ["connect"])                         # X10：标 connect
    v(E + 1.1 * H, X[11], ["https"], [], tcp=False)                         # X11：连不上（dead），没有 tlsproxy
    v(E + 1.2 * H, X[12], ["https"], ["connect"])                           # X12：端口本身说 TLS
    for i in (1, 2):
        v(E + 0.5 * H, D[i], ["http"], ["forward"])                         # 密集 /24 里探访过且可用的
    v(E + 0.5 * H, D[3], ["http"], [])                                      # 密集 /24 里探访过但 visit.ok 为空：h 载荷被改、j/b 载荷通过
    v(E + 1.0 * H, M[1], ["http"], ["forward"], grp=1)                      # 聚合器抽样
    v(E + 1.0 * H, M[2], ["socks5"], [], grp=1)
    vid_of = {}
    for i, (t, cand, grp, labels, ok, full, aborted, state) in enumerate(visits):
        ip, port = cand.rsplit(":", 1)
        vid = "v%d" % i
        vid_of[(cand, t)] = vid
        cur = con.execute("INSERT INTO visit (ts, ts_epoch, visit, cand, \"group\", n, prev, state, \"full\", listed, labels, ok, aborted, "
                          "cand_ip, cand_port, prefix24, n_ok) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (iso_minute(t), t, vid, cand, grp, 1, "new", state, full or None, 1,
                           json.dumps(labels), json.dumps(ok) if ok else None, aborted, ip, int(port), ip.rsplit(".", 1)[0] + ".0/24", len(ok)))
        for p in ok:
            con.execute("INSERT INTO visit_ok (visit_rid, visit, cand, ts, ts_epoch, proto) VALUES (?,?,?,?,?,?)",
                        (cur.lastrowid, vid, cand, iso_minute(t), t, p))

    # ---- att：TCP、主循环的 ok（与 visit.ok 一致）、附加测试的 j/b 载荷、tlsproxy、CONNECT 连 80。att.visit 指回同一时刻该候选的探访
    atts = []

    def a(t, cand, proto, dst, cls, tcp=1, hs_ok=None, hs_class=None, hs_code=None, tls_ok=None, tls_class=None, de=None, tls_self=None, sniff=None,
          kind="h"):
        atts.append((t, cand, proto, dst, kind, cls, tcp, hs_ok, hs_class, hs_code, tls_ok, tls_class, de, tls_self, sniff))

    a(E - 1 * H, X[9], "forward", "judge_http", "ok")                       # 试运行
    a(E + 0.2 * H, X[1], "connect", "judge_tls", "ok", hs_ok=1, hs_code=200)
    a(E + 0.2 * H, X[1], "forward", "judge_http", "ok")
    a(E + 0.2 * H, X[1], "connect", "judge_http", "ok", hs_ok=1, hs_code=200)   # 80 端口：允许
    a(E + 0.2 * H, X[2], "connect", "judge_tls", "ok", hs_ok=1, hs_code=200)
    a(E + 0.2 * H, X[2], "forward", "judge_http", "ok")
    a(E + 0.2 * H, X[2], "connect", "judge_http", "http_body_mismatch", hs_ok=1, hs_code=200)  # 80 端口：握手通过、明文被改
    a(E + 0.2 * H, X[2], "tlsproxy", "self", "tls_not_tls", tls_ok=0, tls_class="tls_not_tls", sniff="http")
    a(E + 0.3 * H, X[3], "forward", "judge_http", "ok")
    a(E + 0.3 * H, X[3], "connect", "judge_tls", "hs_refused", hs_ok=0, hs_class="hs_refused", hs_code=403)
    a(E + 0.3 * H, X[3], "tlsproxy", "self", "tls_cert_invalid", tls_ok=0, tls_class="tls_cert_invalid", de="hostname_mismatch", tls_self=1)
    a(E + 0.3 * H, X[4], "socks4", "judge_tls", "ok", hs_ok=1)
    a(E + 0.4 * H, X[5], "socks5", "judge_tls", "hs_timeout", hs_ok=0, hs_class="hs_timeout")
    a(E + 0.5 * H, X[6], "socks5", "judge_tls", "ok", hs_ok=1)
    a(E + 1.0 * H, X[8], "connect", "judge_tls", "ok", hs_ok=1, hs_code=200)      # X8：主循环 CONNECT 通过……
    a(E + 1.0 * H, X[8], "connect", "judge_http", "ok", hs_ok=1, hs_code=200)     #     80 端口测试也做了……
    a(E + 1.0 * H, X[8], "forward", "judge_http", "canceled", tcp=None)           #     然后程序退出：这次探访 aborted，att 都留着
    a(E + 1.0 * H, X[10], "connect", "judge_tls", "ok", hs_ok=1, hs_code=200)
    a(E + 1.0 * H, X[10], "connect", "judge_http", "hs_refused", hs_ok=0, hs_class="hs_refused", hs_code=403)  # 80 端口：拒绝
    a(E + 1.0 * H, X[10], "tlsproxy", "self", "tls_timeout", tls_ok=0, tls_class="tls_timeout")            # 无结论
    a(E + 1.1 * H, X[11], "connect", "judge_tls", "tcp_timeout", tcp=0)
    a(E + 1.2 * H, X[12], "connect", "judge_tls", "ok", hs_ok=1, hs_code=200)
    a(E + 1.2 * H, X[12], "connect", "judge_http", "hs_timeout", hs_ok=0, hs_class="hs_timeout")           # 80 端口：无结论
    a(E + 1.2 * H, X[12], "tlsproxy", "self", "ok", tls_ok=1)                                               # 端口说 TLS，证书按 IP 校验还通过了
    a(E + 1.2 * H, X[12], "tlsproxy", "self", "tls_alert", tls_ok=0, tls_class="tls_alert")                # 第二次：alert，仍算说 TLS
    for i in (1, 2):
        a(E + 0.5 * H, D[i], "forward", "judge_http", "ok")
    a(E + 0.5 * H, D[3], "forward", "judge_http", "http_body_mismatch")            # D3：h 载荷被改 → 不进 okMask，但 fwdAnswers 为真……
    a(E + 0.5 * H, D[3], "forward", "judge_http", "ok", kind="j")                  #     附加测试的 j/b 载荷原样通过：按 att class='ok' 口径
    a(E + 0.5 * H, D[3], "forward", "judge_http", "ok", kind="b")                  #     forward 可用，按 visit.ok 不可用
    a(E + 1.0 * H, M[1], "forward", "judge_http", "ok")
    a(E + 1.0 * H, M[2], "socks5", "judge_tls", "hs_eof", hs_ok=0, hs_class="hs_eof")
    for t, cand, proto, dst, kind, cls, tcp, hs_ok, hs_class, hs_code, tls_ok, tls_class, de, tls_self, sniff in atts:
        ip, _ = cand.rsplit(":", 1)
        con.execute("INSERT INTO att (ts, ts_epoch, visit, cand, proto, dst, kind, class, tcp_ok, hs_ok, hs_class, hs_code, tls_ok, tls_class, "
                    "tls_detail_enum, tls_self, tls_sniff, cand_kind, prefix24) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (iso_minute(t), t, vid_of.get((cand, t), "x"), cand, proto, dst, kind, cls, tcp, hs_ok, hs_class, hs_code, tls_ok, tls_class,
                     de, tls_self, sniff, "proxy", ip.rsplit(".", 1)[0] + ".0/24"))

    # ---- 状态文件：全部候选（含从没探访过的 X7 与 D4..D101），标签取累计
    labels_of = {X[1]: ["http"], X[2]: ["http", "https"], X[3]: ["https"], X[4]: ["socks5"], X[5]: ["socks5"], X[6]: ["http", "socks5"],
                 X[7]: ["http"], X[8]: ["http"], X[9]: ["http"], X[10]: ["connect"], X[11]: ["https"], X[12]: ["https"],
                 M[1]: ["http"], M[2]: ["socks5"]}
    for i in range(1, 102):
        labels_of[D[i]] = ["http"]
    visited = {cand for (_, cand, _, _, _, _, ab, _) in visits if not ab}
    for cand, labs in labels_of.items():
        ip, port = cand.rsplit(":", 1)
        mask = sum(LABEL_BIT[x] for x in labs)
        nvis = 1 if cand in visited else 0
        if cand == X[9]:
            nvis = 1   # 试运行里探访过
        con.execute("INSERT INTO cands (key, ip, port, prefix24, \"group\", n_srcs, listed, labels, label_names, visits, state, state_name, ok_mask, ok_protos, ever_ok) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (cand, ip, int(port), ip.rsplit(".", 1)[0] + ".0/24", 1 if cand in M.values() else 0, 1, 1, mask, json.dumps(labs), nvis,
                     0, "new", 0, None, 0))
        srcs = sorted({src for src, _, c in ev if c == cand} | ({SRC_Z} if cand in M.values() else set()))
        for src in srcs:
            sl = sorted({lab for s, lab, c in ev if c == cand and s == src}, key=LABELS.index) or labs
            con.execute("INSERT INTO cand_src (key, src_idx, src_name, labels, label_names) VALUES (?,?,?,?,?)",
                        (cand, 0, src, sum(LABEL_BIT[x] for x in sl), json.dumps(sl)))
    con.commit()
    con.close()


def selftest():
    tmp = tempfile.mkdtemp(prefix="m_labels_selftest_")
    db_path = os.path.join(tmp, "synthetic.sqlite")
    _synthetic_db(db_path)
    res = run(db_path, os.path.join(tmp, "out"), markdown=False, write=True)
    failures = []
    n_asserts = [0]

    def expect(name, got, want):
        n_asserts[0] += 1
        if got != want:
            failures.append("%s: 得到 %r，期望 %r" % (name, got, want))

    w = res["window"]
    expect("正式起点", w["formal_start_utc"], "2026-11-06T00:00Z")
    expect("试运行探访", w["trial_run_visits_before_formal_start"], 1)
    n = res["n"]
    expect("探访过", n["探访过"], 14)             # X1-6, X10-12（9）+ D1-3（3）+ M1, M2（2）；X8 只有 aborted；X9 只在试运行
    expect("连得上过", n["探访过且连得上过"], 13)  # X11 连不上
    expect("曾经可用", n["探访过且曾经可用"], 10)  # X5、X11、D3、M2 没有协议通过
    expect("分组", n["分组（最后一次探访的 group）"], {"regular": 12, "aggregator_sample": 2})
    expect("按标签 http", n["按标签（探访过的候选；多标签的候选在每个标签里各计一次）"]["http"], 7)   # X1 X2 X6 D1 D2 D3 M1
    expect("按标签 https", n["按标签（探访过的候选；多标签的候选在每个标签里各计一次）"]["https"], 4)  # X2 X3 X11 X12
    expect("按标签 socks5", n["按标签（探访过的候选；多标签的候选在每个标签里各计一次）"]["socks5"], 4)  # X4 X5 X6 M2
    expect("按标签组合", n["按标签组合（探访过的候选）"]["http+https"], 1)
    expect("标签数分布", n["标签数分布（探访过的候选）"], {"1": 12, "2": 2})
    nv = n["从没探访过"]
    expect("从没探访过 总数", nv["总数"], 101)       # X7、X8（aborted 不算探访）、X9（试运行）+ D4..D101（98）
    expect("从没探访过 试运行", nv["其中状态文件 visits>0（正式起点之前探访过，或探访记录缺失）"], 1)
    expect("从没探访过 按标签", nv["按标签"]["http"], 101)
    expect("从没探访过 /24", nv["按 /24（前 30 个）"][0], {"prefix24": "203.0.113.0/24", "候选": 98})
    expect("从没探访过 按来源", nv["按来源（状态文件结束时仍列着它的来源 × 标签）"]["synthetic/listA"]["http"], 101)
    d = res["dense_prefixes"]
    expect("密集 /24", (d["count"], d["basis"], d["prefixes"][0]),
           (1, "状态文件 cands ∪ 尝试记录里的代理候选（att，含试运行）：下榜超过 24 小时的候选会从状态文件里丢掉，只数状态文件会漏掉它们",
            {"prefix24": "203.0.113.0/24", "候选": 101, "有尝试记录（含试运行）": 3,
                                 "正式窗口内探访到（按 cl）": 3}))
    acc = res["accuracy"]["all"]["total"]
    expect("http 曾经严格", acc["http"]["曾经通过"]["严格"]["占探访过"], {"num": 5, "den": 7, "pct": 71.4})    # X1 X2 D1 D2 M1
    expect("http 曾经宽松", acc["http"]["曾经通过"]["宽松"]["占探访过"], {"num": 5, "den": 7, "pct": 71.4})
    expect("http 曾经严格 占曾经可用", acc["http"]["曾经通过"]["严格"]["占曾经可用"], {"num": 5, "den": 6, "pct": 83.3})  # X6 只通 socks5
    # att class='ok' 口径多出 D3（j/b 载荷通过）：分子 6；分母“曾经可用（att 口径）”也多出 D3 → 7
    expect("http att 严格", acc["http"][ATT_OK_KEY]["严格"]["占探访过"], {"num": 6, "den": 7, "pct": 85.7})
    expect("http att 严格 占曾经可用", acc["http"][ATT_OK_KEY]["严格"]["占曾经可用（att 口径）"], {"num": 6, "den": 7, "pct": 85.7})
    expect("http att 与 visit 之差", acc["http"][ATT_OK_KEY]["与 visit.ok 口径的分子之差（严格）"], 1)
    expect("http 曾经可用 att 口径", acc["http"]["曾经可用（任一协议，att class='ok' 口径）"], 7)
    expect("https att 严格（与 visit 相同）", acc["https"][ATT_OK_KEY]["严格"]["占探访过"], {"num": 2, "den": 4, "pct": 50.0})
    expect("合计 att 严格", acc["合计（候选-标签对）"][ATT_OK_KEY]["严格"]["占探访过"]["num"], 10)
    expect("http 最近严格", acc["http"]["最近一次通过"]["严格"]["占探访过"], {"num": 4, "den": 7, "pct": 57.1})  # X1 最近只剩 connect
    expect("http 最近宽松", acc["http"]["最近一次通过"]["宽松"]["占探访过"], {"num": 5, "den": 7, "pct": 71.4})
    expect("https 曾经严格", acc["https"]["曾经通过"]["严格"]["占探访过"], {"num": 2, "den": 4, "pct": 50.0})   # X2 X12
    expect("https 曾经宽松", acc["https"]["曾经通过"]["宽松"]["占探访过"], {"num": 3, "den": 4, "pct": 75.0})   # + X3
    expect("https 曾经严格 占曾经可用", acc["https"]["曾经通过"]["严格"]["占曾经可用"], {"num": 2, "den": 3, "pct": 66.7})
    expect("socks5 曾经严格", acc["socks5"]["曾经通过"]["严格"]["占探访过"], {"num": 1, "den": 4, "pct": 25.0})  # X6
    expect("connect 曾经严格", acc["connect"]["曾经通过"]["严格"]["占探访过"], {"num": 1, "den": 1, "pct": 100.0})
    expect("socks4 分母 0", acc["socks4"]["曾经通过"]["严格"]["占探访过"], {"num": 0, "den": 0, "pct": None})
    expect("合计 分母", acc["合计（候选-标签对）"]["探访过"], 16)      # 14 个候选，X2 与 X6 各有两个标签
    expect("合计 曾经严格", acc["合计（候选-标签对）"]["曾经通过"]["严格"]["占探访过"]["num"], 9)
    expect("regular http 分母", res["accuracy"]["all"]["regular"]["http"]["探访过"], 6)
    expect("agg http", res["accuracy"]["all"]["aggregator_sample"]["http"]["曾经通过"]["严格"]["占探访过"], {"num": 1, "den": 1, "pct": 100.0})
    ex = res["accuracy"]["excluding_dense"]["total"]
    expect("去密集 http 曾经严格", ex["http"]["曾经通过"]["严格"]["占探访过"], {"num": 3, "den": 4, "pct": 75.0})
    expect("去密集 http 最近严格", ex["http"]["最近一次通过"]["严格"]["占探访过"], {"num": 2, "den": 4, "pct": 50.0})
    bs = res["accuracy_by_source"]["all"]
    expect("来源 A http", bs["synthetic/listA"]["labels"]["http"]["曾经通过"]["严格"]["占探访过"], {"num": 3, "den": 5, "pct": 60.0})  # X1 X6 D1 D2 D3
    expect("来源 A http att", bs["synthetic/listA"]["labels"]["http"][ATT_OK_KEY]["严格"]["占探访过"], {"num": 4, "den": 5, "pct": 80.0})  # + D3
    expect("来源 A https", bs["synthetic/listA"]["labels"]["https"]["曾经通过"]["严格"]["占探访过"], {"num": 2, "den": 4, "pct": 50.0})
    expect("来源 A socks5", bs["synthetic/listA"]["labels"]["socks5"]["曾经通过"]["严格"]["占探访过"], {"num": 1, "den": 3, "pct": 33.3})
    expect("来源 B http（X2 被 B 标 http）", bs["synthetic/listB"]["labels"]["http"]["曾经通过"]["严格"]["占探访过"], {"num": 1, "den": 1, "pct": 100.0})
    expect("来源 B connect", bs["synthetic/listB"]["labels"]["connect"]["曾经通过"]["严格"]["占探访过"], {"num": 1, "den": 1, "pct": 100.0})
    expect("聚合器 Z", (bs["synthetic/aggZ"]["aggregator"], bs["synthetic/aggZ"]["labels"]["socks5"]["探访过"]), (True, 1))
    expect("去密集 来源 A http", res["accuracy_by_source"]["excluding_dense"]["synthetic/listA"]["labels"]["http"]["探访过"], 2)
    m = res["matrix"]["all"]["曾经通过"]["全部探访过的候选"]
    expect("对照 http", m["http"], {"候选": 5, "实测组合": {"connect+forward": 1, "forward": 3, "无": 1}})
    expect("对照 http+https", m["http+https"], {"候选": 1, "实测组合": {"connect+forward": 1}})
    expect("对照 https", m["https"], {"候选": 3, "实测组合": {"forward": 1, "无": 1, "connect": 1}})
    expect("对照 socks5", m["socks5"], {"候选": 3, "实测组合": {"socks4": 1, "无": 2}})
    expect("对照 http+socks5", m["http+socks5"], {"候选": 1, "实测组合": {"socks5": 1}})
    ml = res["matrix"]["all"]["最近一次通过"]["全部探访过的候选"]
    expect("对照 最近一次 http", ml["http"]["实测组合"], {"connect": 1, "forward": 3, "无": 1})
    ma = res["matrix"]["all"]["曾经通过（att class='ok'）"]["全部探访过的候选"]
    expect("对照 att http（D3 从“无”变成 forward）", ma["http"], {"候选": 5, "实测组合": {"connect+forward": 1, "forward": 4}})
    mr = res["matrix"]["all"]["曾经通过"]["只看常规列表（group=0）"]
    expect("对照 常规 http", mr["http"]["候选"], 4)
    expect("对照 去密集 http", res["matrix"]["excluding_dense"]["曾经通过"]["全部探访过的候选"]["http"]["候选"], 2)
    ms = res["matrix_by_source"]["all"]
    expect("来源对照 A http+socks5", ms["synthetic/listA"]["http+socks5"],
           {"候选": 1, "曾经通过": {"socks5": 1}, "曾经通过（att class='ok'）": {"socks5": 1}, "最近一次通过": {"socks5": 1}})
    expect("来源对照 A https（X2 在 A 里只是 https）", ms["synthetic/listA"]["https"]["候选"], 4)
    expect("来源对照 B http", ms["synthetic/listB"]["http"]["曾经通过"], {"connect+forward": 1})
    h = res["https_label"]
    t = h["tlsproxy"]["按候选（标签含 https）"]
    expect("tlsproxy https 候选", (t["候选"], t["做过 tlsproxy 尝试的候选"]), (4, 3))
    expect("tlsproxy 说 TLS", t["端口说 TLS 的比例（占做过尝试的）"], {"num": 2, "den": 3, "pct": 66.7})    # X3（cert_invalid）X12（ok + alert）
    expect("tlsproxy 不说 TLS", t["端口不说 TLS 的比例（占做过尝试的）"], {"num": 1, "den": 3, "pct": 33.3})  # X2
    expect("tlsproxy 不说 TLS 却 CONNECT 通过", t["按结论"]["端口不说 TLS"]["其中 CONNECT 曾通过"], 1)
    expect("tlsproxy 没做", t["按结论"]["没做 tlsproxy 尝试"]["候选"], 1)                                  # X11
    expect("tlsproxy connect 标签", h["tlsproxy"]["按候选（标签含 connect、不含 https）"]["按结论"]["无结论（超时/断开/连不上）"]["候选"], 1)
    expect("tlsproxy 证书", h["tlsproxy"]["证书统计（做过尝试的候选）"],
           {"做过尝试的候选": 4, "证书按 IP 校验通过": 1, "证书校验不过且自签": 1,
            "探访过、标签却既不含 https 也不含 connect（Cand.Labels 只增不减，正常应为 0）": 0,
            "做过尝试但不在探访过的候选里（只有 aborted 或跨正式起点的探访）": 0,
            "不在探访过的候选里的尝试按所属探访分解": {}})
    expect("tlsproxy 按尝试", sorted((r["class"], r["尝试"]) for r in h["tlsproxy"]["按尝试"]),
           [("ok", 1), ("tls_alert", 1), ("tls_cert_invalid", 1), ("tls_not_tls", 1), ("tls_timeout", 1)])
    c = h["connect_to_port_80"]["按候选（CONNECT 曾通过的候选，即有资格做这项测试的）"]
    expect("80 端口 候选", (c["候选"], c["做过 80 端口测试的候选"]), (4, 4))                               # X1 X2 X10 X12
    expect("80 端口 允许", c["允许的比例（占做过测试的）"], {"num": 2, "den": 4, "pct": 50.0})
    expect("80 端口 拒绝", c["拒绝的比例（占做过测试的）"], {"num": 1, "den": 4, "pct": 25.0})
    expect("80 端口 允许且明文通过", c["按结论"]["允许连 80 端口"]["其中明文 HTTP 也通过核对（class='ok'）"], 1)  # X2 的明文被改
    expect("80 端口 拒绝码", h["connect_to_port_80"]["拒绝时 CONNECT 应答的状态码（候选数）"], {"403": 1})
    expect("80 端口 https", h["connect_to_port_80"]["按候选（CONNECT 曾通过且标签含 https）"]["按结论"]["无结论（超时/断开）"]["候选"], 1)
    # X8 的 80 端口测试做了，但那次探访 aborted：不在 visit.ok 口径里，分解应全部落在“aborted 探访”
    expect("80 端口 不在 visit.ok 里", h["connect_to_port_80"]["做过测试但 visit.ok 里没有 CONNECT 的候选（来自 aborted 探访或跨正式起点的探访）"], 1)
    expect("80 端口 分解", h["connect_to_port_80"]["这些候选的 80 端口测试按所属探访分解"], {"aborted 探访（程序退出时被打断）": {"尝试": 1, "候选": 1}})
    ck = res["checks"]
    expect("标签变过", ck["标签在观察期内变过的候选（探访记录里 labels 不止一种）"], 1)
    expect("快照 vs 探访 标签", ck["快照事件的标签并集 vs 最后一次探访的 labels（有快照事件的候选）"],
           {"候选": 12, "快照里有、探访记录里没有的标签（最后一次探访之后才上榜的文件）": 0, "探访记录里有、快照里没有的标签（只可能来自聚合器）": 0})
    expect("n_ok vs visit_ok", ck["visit.n_ok vs visit_ok 子表条数不一致的探访"]["num"], 0)
    va = ck["visit.ok 的“曾经通过” vs att class='ok'（到 judge）不一致的（候选, 协议）对"]
    expect("visit vs att 曾经通过", (va["num"], va["den"]), (1, 14 * 4))                                        # 只有 D3 的 forward
    expect("visit vs att 其中 forward 只在 att", va["其中 forward 只在 att 里 ok（附加测试的 j/b 载荷通过而 h 载荷不符，summary.go 会把它算成 forward 可用）"], 1)
    expect("visit vs att 其中只在 visit", va["其中只在 visit.ok 里 ok（不该出现：ok 的尝试一定有 att 记录）"], 0)
    expect("cands.label_names vs visit", ck["cands.label_names（状态文件）vs 最后一次探访的 labels 不一致的候选"]["num"], 0)
    # 输出文件存在且干净
    with open(os.path.join(tmp, "out", OUTPUT_NAME), encoding="utf-8") as fh:
        text = fh.read()
    expect("输出里没有 ip:port", bool(HOSTPORT_RE.search(text)), False)
    expect("输出里没有 judge 主机名", "judge.invalid" in text, False)
    # 交叉核对的代码路径：按 summary.go 的口径，整个数据（含试运行的 X9）、常规列表、连得上过（任何 att 的 TCP 通过）、att 的 class='ok'
    # （D3 按它算 forward 可用）；X8 只有 aborted 探访，probeLine() 跳过它，但 attempt() 仍把它的 80 端口测试计进 extras
    summ = os.path.join(tmp, "summary.json")
    with open(summ, "w", encoding="utf-8") as fh:
        json.dump({"generated": "x",
                   "labels": {"http": {"connect+forward": 1, "forward": 4, "socks5": 99},   # socks5: 99 是故意写错的
                              "http+https": {"connect+forward": 1}, "https": {"forward": 1, "connect": 1},
                              "socks5": {"socks4": 1, "无": 1}, "http+socks5": {"socks5": 1}, "connect": {"connect": 1}},
                   "extras": {"connect_to_port_80": {"ok": 2, "http_body_mismatch": 1, "hs_refused": 1, "hs_timeout": 1},
                              "https_label_port_speaks_tls": {"ok": 1, "tls_alert": 1, "tls_cert_invalid (hostname_mismatch)": 1,
                                                              "tls_not_tls": 1, "tls_timeout": 1}}}, fh)
    res2 = run(db_path, os.path.join(tmp, "out"), summary_path=summ, write=False)
    cc = res2["crosscheck"]
    # summary.go 的口径：含试运行的 X9（forward）、不含聚合器的 M1、不含连不上的 X11 → http→forward = D1 + D2 + D3（att 口径）+ X9 = 4
    expect("交叉核对 http forward", cc["comparisons"]["labels.http.forward"], {"summary": 4, "computed": 4, "match": True})
    expect("交叉核对 http 无（D3 按 att 口径不再是“无”）", cc["comparisons"].get("labels.http.无"), None)
    expect("交叉核对 故意写错的格", cc["comparisons"]["labels.http.socks5"], {"summary": 99, "computed": None, "match": False})
    expect("交叉核对 https 无（X11 连不上，不进 summary 的表）", cc["comparisons"].get("labels.https.无"), None)
    expect("交叉核对 不一致项", cc["mismatches"], ["labels.http.socks5"])
    expect("交叉核对 总数与一致数", (cc["total"], cc["matched"]), (19, 18))
    expect("交叉核对 80 端口 ok 含 aborted 探访的尝试", cc["comparisons"]["extras.connect_to_port_80.ok"], {"summary": 2, "computed": 2, "match": True})
    expect("交叉核对 80 端口", cc["comparisons"]["extras.connect_to_port_80.http_body_mismatch"]["match"], True)
    expect("交叉核对 tlsproxy 细分", cc["comparisons"]["extras.https_label_port_speaks_tls.tls_cert_invalid (hostname_mismatch)"]["match"], True)
    if failures:
        print("自检失败：\n  " + "\n  ".join(failures), file=sys.stderr)
        print("合成库与输出留在 %s" % tmp, file=sys.stderr)
        return 1
    print("自检通过（%d 项断言）。合成库与输出在 %s" % (n_asserts[0], tmp), file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="标签准确率（PROTOCOL“指标定义”表“标签准确率”行）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 %s" % OUTPUT_NAME)
    ap.add_argument("--summary", help="fieldtest 自带的 summary.json，给了就交叉核对 labels 与 extras 两节")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--formal-start", default="auto", help="auto（按 PROTOCOL 规则）/ first（第一条 start）/ 带时区的 ISO 时间")
    ap.add_argument("--dense-threshold", type=int, default=DENSE_THRESHOLD, help="“候选密集的 /24”的阈值，默认 100")
    ap.add_argument("--top-prefixes", type=int, default=TOP_PREFIXES, help="从没探访过的候选按 /24 列出前几个")
    ap.add_argument("--selftest", action="store_true", help="在临时目录里建合成库并核对预期值")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    run(args.db, args.out, summary_path=args.summary, formal_start=args.formal_start, dense_threshold=args.dense_threshold,
        top_prefixes=args.top_prefixes, markdown=args.markdown)


if __name__ == "__main__":
    main()
