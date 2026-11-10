#!/usr/bin/env python3
"""可用率（第一阶段 1B，PROTOCOL“指标定义”一节）：连得上、有协议回应、可用、时点可用率、累计可用率。

用法：
    python3 m_availability.py --db <sqlite> --out <目录> [--markdown] [--summary <summary.json>]
    python3 m_availability.py --selftest

只读 ingest.py 建好的库（以 mode=ro 打开，临时表都建在 TEMP 库里），结果写到 <目录>/availability.json。
每个比例都给分子、分母和口径；百分比保留一位小数。输出前按 SCHEMA.md 的可输出列白名单检查用到的列，
写出前再对文本做一次“不许出现地址和 judge 身份”的断言（这是最后一道保险，不是放行手段）。

口径与官方汇总程序（internal/summary/summary.go）的对应关系写在各函数的注释里；
PROTOCOL 没说清的地方，取的解释都在 DEFINITIONS 和注释里写明。

设计要点（真实数据有一千多万条 att）：
- att 只扫一遍：按候选 GROUP BY 得到“连得上 / 有协议回应 / 走通过 / 要求认证”四个布尔值，
  正式起点之后的一组给指标用，整个数据的一组给 summary.json 交叉核对用（函数 build_candidate_table；
  GROUP BY +cand 迫使顺序扫描 + 临时 B 树分组，避免按 att_cand_ts 索引顺序逐行回表——带 raw JSON 的大表上那是随机读）。
- 时点指标只用 visit 表（每次探访一行）和 list_event（上下榜事件），每个时点各做一次窗口查询；内存由 SQLite 页缓存主导。
- 从没探访过的候选不进任何比例的分母（PROTOCOL“候选密集的地址段”），单独报告并按 /24 汇总。
- “可用过”有两个口径：visit.state='working' 只看主流程四种协议的 HTML 尝试（prober.go Visit 的 okMask）；
  att 的 class='ok' 且目的地是 judge 还包括附加测试（转发 j/b 载荷、SOCKS 隧道里的明文）。summary.go Funnel.Working /
  SourceRow.Working 用的是 att 口径（attempt() 的 everOK），PROTOCOL“可用”的字面也不区分主流程与附加测试，
  所以累计可用率取 att 口径，visit 口径降为核对项；时点可用率（最近一次探访可用）照 summary.go WorkingNow 用 visit.state。
"""
import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import tempfile

STEP_HOURS = 6          # 时点序列的间隔（任务要求：每 6 小时一个时点）
DENSE_THRESHOLD = 100   # “候选超过 100 个的 /24”（PROTOCOL 1.2 版“候选密集的地址段”）
TOP_PREFIXES = 30       # 从没探访过的候选按 /24 汇总时列出的前几个
LATE_CLEAR_HOURS = 1.0  # resumed_candidates=0 的 start 距第一条 start 超过这个小时数，就在 warnings 里要求显式确认

# 本模块在 SELECT 列表或 GROUP BY 里用到、并且会进入输出（作为维度或被聚合的值）的列。
# 连接用的键（visit.cand、cands.key、list_event.cand、agg_member.cand）只在库内做 JOIN，不进入输出，所以不在这里。
# start.load_err 只作“是否非空”的布尔判断，原文（可能含服务器上的文件路径）不进输出，所以也不在这里。
OUTPUT_COLUMNS = {
    "visit": ["group", "state", "listed", "auth", "aborted", "n_ok", "prefix24", "ts_epoch"],
    "att": ["proto", "dst", "class", "tcp_ok", "hs_ok", "hs_code", "http_code", "cand_kind", "ts_epoch"],
    "cands": ["prefix24", "group", "listed", "visits", "state_name", "ever_ok"],
    "cand_src": ["src_name"],
    "list_event": ["src", "label", "event", "base", "prefix24", "ts_epoch"],
    "agg_member": ["src", "prefix24", "ts_epoch"],
    "agg_sample": ["src", "union", "exclusive", "sample", "ts_epoch"],
    "snap": ["src", "label", "base", "agg", "ts_epoch"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["visits", "ts_epoch"],
    "stat": ["ts_epoch"],
    "version": ["version", "ts_epoch"],
    "stat_pool": ["key", "value", "ts_epoch"],
    "meta": ["ingest_version", "first_ts", "last_ts", "state_cands", "state_tz_offsets", "records_by_kind"],
}

DEFINITIONS = {
    "连得上": "探访过的候选里，至少一次尝试的 TCP 阶段通过（att.tcp_ok）的比例。PROTOCOL“指标定义”；对应 summary.go Funnel.TCP",
    "有协议回应": "探访过的候选里，至少一次尝试得到协议层面的回答（握手通过、握手应答码非零——含拒绝和要求认证——或收到 HTTP 状态码）"
                "的比例。PROTOCOL“指标定义”（Mani 等的 responsive）；判据照 summary.go attempt()：hs.OK || hs.Code != 0 || http.Code != 0",
    "可用（一次探访）": "PROTOCOL“指标定义”：一次探访里至少有一次尝试走完全部阶段并通过核对。有两个口径：visit.state='working' 只看主流程"
                   "四种协议的 HTML 尝试（prober.go Visit 的 okMask，等价于 visit.ok 非空）；att 口径（class='ok' 且 dst∈{judge_tls,judge_http}）"
                   "还包括附加测试（转发 j/b 载荷、SOCKS 隧道里的明文），主流程 HTML 被改（http_body_mismatch）但 j/b 载荷通过的代理只在 att 口径下算可用。"
                   "累计可用率取 att 口径（summary.go Funnel.Working），时点可用率取 visit 口径（summary.go WorkingNow），两者的差单独列为核对项",
    "时点可用率": "某一时刻在榜的条目里，最近一次探访（该时刻之前最后一次非 aborted 的探访，以探访开始时刻 visit.ts 为准，跨该时刻的探访算作已知）"
               "visit.state='working' 的比例。分母只含该时刻之前至少探访过一次的在榜条目；在榜但尚未探访的单独计数，"
               "分成“在候选池里排队”和“不进候选池（私网、judge 自身、知名端口、退出名单；sched.go ineligible）”两类。"
               "“某一时刻”取观察结束时刻，另给从正式起点起每 6 小时一个时点的序列。PROTOCOL“指标定义”；结束时刻的分子对应 summary.go Funnel.WorkingNow / SourceRow.WorkingNow",
    "在榜（常规列表）": "由 snap- 记录重建：每个列表文件（来源 × 标签）按时间处理上下榜事件，base=1 的首次快照把该文件的集合重置为它的 add 列表"
                   "（与 summary.go snapLine 相同），某条目在时刻 T 在榜 = 至少一个文件里它在 T 之前的最后一个事件是 add 且不早于该文件 T 之前最后一次 base 快照。"
                   "结束时刻另与状态文件 cands.listed 交叉核对",
    "在榜（聚合器抽样）": "聚合器不逐条记快照（PROTOCOL“记录”），所以聚合器条目的“在榜”只在结束时刻由状态文件 cands.listed 给出；"
                    "时点序列里聚合器一行的分母是“抽样时刻 ≤ T 且已探访过”的抽样条目，不区分是否仍在榜，并标明这一点。"
                    "抽样是从合并集合里随机取的（prober.go snapAggregators），抽中的私网地址、知名端口、judge 自身会被 Pool.Upsert 跳过，"
                    "根本不进候选池，所以“从没探访过”拆成“从没探访过（在候选池里）”和“不进候选池”两列，与常规列表一致",
    "聚合器抽样范围": "只用正式起点之前最后一次候选池为空的 start（resumed_candidates=0）之后的 agg_member / agg_sample 记录。抽样标记随状态文件保存，"
                 "只是重启不重抽（sched.go MarkSampled / Pool.Load）；状态被清空或读不出来后会重抽，清空之前的抽样属于试运行",
    "聚合器独有": "抽样条目里在正式起点之后从未出现在任何常规列表快照里的（list_event 里没有它）。抽样本身只取抽样时刻不在常规列表里的条目（PROTOCOL“测量对象”），"
               "之后出现在常规列表里的候选在状态文件里 group 会改成 0；两者交叉核对",
    "累计可用率": "探访过的条目里至少可用过一次的比例，“可用过”取 att 口径：至少一条 class='ok' 且 dst∈{judge_tls,judge_http} 的尝试（正式起点之后、"
               "不含 canceled）。PROTOCOL“指标定义”；对应 summary.go Funnel.Working / SourceRow.Working（attempt() 的 everOK）。"
               "visit 口径（至少一次探访 state='working'）另给出作核对，两者不一致的候选数一并列出",
    "曾经在榜": "正式起点之后任何一次 add 事件（含 base=1 的首次快照）里出现过的条目；试运行期间的快照不算",
    "要求认证": "至少一次探访 visit.auth=1（握手类别 hs_auth，或 CONNECT/转发收到 407）的候选数。PROTOCOL“一次尝试”（遇到要求认证只记录不尝试凭据）；对应 summary.go Funnel.Auth",
    "探访过": "正式起点之后至少有一次 aborted≠1 的 visit 记录。aborted=1 的探访结果不作数（prober.go Visit），summary.go 也跳过",
    "候选": "候选池里的条目：状态文件 cands 的全部行，加上有 visit 记录却不在状态文件里的条目（下榜超过 24 小时后被丢弃的，Pool.Done）。"
          "分组（常规列表 / 聚合器抽样）取最后一次探访记录的 group（summary.go 的做法），没探访过的取 cands.group",
    "从没探访过": "候选池里正式起点之后没有任何非 aborted 探访记录的候选。不进任何比例的分母，单独报告条数并按 /24 汇总；"
              "其中状态文件 visits>0 的是只在试运行期间探访过的，另计条数。PROTOCOL“候选密集的地址段”",
    "候选密集的 /24": "候选数超过阈值（默认 100）的 /24。每个比例另给一组去掉这些 /24 里全部候选后的结果，并列出每个被去掉的 /24 有多少候选、探访到多少、可用多少。"
                  "PROTOCOL 1.2 版“候选密集的地址段”",
    "正式起点": "PROTOCOL“正式测量的起止”：默认取第一条 start；若之后有 resumed_candidates=0 且 load_err 为空的 start（状态被清空）或版本变了，"
             "取最后一次这样的 start，之前的数据是试运行，不并入。load_err 非空的 start（状态文件读不出来，prober.go Run 的 Pool.Load 出错）"
             "是崩溃后重启，不是清空状态，不改变正式起点，只记 warning。正式起点被挪动时 warnings 里写明丢弃多少探访；可用 --formal-start 覆盖",
    "首轮快照完成时刻": "正式起点之后每个常规列表文件（来源 × 标签）第一次 base 快照时刻的最大值（snap 表，没有就用 list_event）。"
                   "在此之前重建的“在榜”集合不完整，所以时点序列从正式起点 + 一个间隔开始，不给 0 小时的点；每个时点标明是否晚于这一时刻",
    "观察结束时刻": "visit、att、stop 记录里最晚的时间戳（UTC）",
    "中断时段": "正式起点之后每条 start 之前的空档（PROTOCOL“正式测量的起止”）。上一条 start 与它之间有 stop 记录的是正常停止（kind=stop，从最后那条 stop 算起；"
             "stop 在全部探访结束后才写，prober.go Run）；没有 stop 的是崩溃重启（kind=crash，从这段时间里最后一条 visit/att/stat 记录算起，"
             "一条记录都没有就从上一条 start 算起）。只在窗口信息里列出，不改变指标口径",
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


class DB:
    def __init__(self, path):
        # mode=ro：库文件只读；临时表都建在 TEMP 库里（query_only 会连 TEMP 表一起禁掉，所以不用它）
        self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        self.con.execute("PRAGMA cache_size = -262144")  # 256 MB 页缓存，内存不随记录数增长
        self.con.execute("PRAGMA temp_store = FILE")

    def q(self, sql, params=()):
        return self.con.execute(sql, params).fetchall()

    def one(self, sql, params=()):
        row = self.con.execute(sql, params).fetchone()
        return row

    def scalar(self, sql, params=()):
        row = self.one(sql, params)
        return row[0] if row else None

    def x(self, sql, params=()):
        self.con.execute(sql, params)

    def has_table(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) > 0

    def columns(self, table):
        return [r[1] for r in self.q('PRAGMA table_info("%s")' % table)]

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))


def check_whitelist(db):
    """输出前按白名单核对本模块用到的列。优先用同目录 ingest.py 的权威常量，拿不到就读库里的 meta.output_whitelist。"""
    wl = None
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

def last_activity_between(db, lo, hi):
    """(lo, hi) 开区间里最后一条 visit / att / stat 记录的时刻；没有就返回 None。三张表都有 ts_epoch 索引。"""
    best = None
    for t in ("visit", "att", "stat"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s WHERE ts_epoch > ? AND ts_epoch < ?" % t, (lo, hi))
            if v is not None and (best is None or v > best):
                best = v
    return best


def first_snapshot_round(db, fs):
    """正式起点之后每个常规列表文件第一次 base 快照时刻的最大值（DEFINITIONS“首轮快照完成时刻”）。
    返回 (时刻, 有过 base 快照的文件数, 依据的表)。snap 表里 base 只在成功（200）且非聚合器的首次快照上为 1（lists.go SnapRec）。"""
    if db.has_table("snap") and {"src", "label", "base"} <= set(db.columns("snap")):
        agg_f = " AND COALESCE(agg, 0) = 0" if "agg" in db.columns("snap") else ""
        rows = db.q("SELECT src, label, MIN(ts_epoch) FROM snap WHERE base = 1%s AND ts_epoch >= ? GROUP BY src, label" % agg_f, (fs,))
        source = "snap"
    elif db.has_table("list_event"):
        rows = db.q("SELECT src, label, MIN(ts_epoch) FROM list_event WHERE base = 1 AND ts_epoch >= ? GROUP BY src, label", (fs,))
        source = "list_event"
    else:
        return None, 0, None
    return (max(r[2] for r in rows) if rows else None), len(rows), source


def observation_window(db, formal_start_arg):
    """正式起点、结束时刻、重启与中断。PROTOCOL“正式测量的起止”。"""
    warnings = []
    start_cols = db.columns("start") if db.has_table("start") else []
    if start_cols:
        load_err_sel = "COALESCE(load_err, '')" if "load_err" in start_cols else "''"
        starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0), %s FROM start ORDER BY ts_epoch" % load_err_sel)
        if "load_err" not in start_cols:
            warnings.append("start 表没有 load_err 列，无法区分“清空状态”与“状态文件读不出来”，resumed_candidates=0 一律按清空处理")
    else:
        starts = []
    stops = [r[0] for r in db.q("SELECT ts_epoch FROM stop ORDER BY ts_epoch")] if db.has_table("stop") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch") if db.has_table("version") else []

    ends = []
    for t in ("visit", "att", "stop"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None

    first_visit = db.scalar("SELECT MIN(ts_epoch) FROM visit") if db.has_table("visit") else None
    rule = []
    if starts:
        fs = starts[0][0]
        rule.append("第一条 start")
        # load_err 非空：状态文件读不出来（崩溃后损坏等），resumed_candidates 也是 0，但这不是 PROTOCOL 说的“清空了状态”
        for s in starts[1:]:
            if s[2] != "":
                warnings.append("%s 的 start 带 load_err（状态文件读不出来，resumed_candidates=%d）：按崩溃后重启处理，不当作清空状态，不改变正式起点；"
                                "但候选池和聚合器抽样标记随状态一起丢了，之后的 agg_sample 是重新抽的，聚合器一节会把两批抽样并在一起"
                                % (iso_minute(s[0]), s[1]))
        cleared = [s for s in starts[1:] if s[1] == 0 and s[2] == ""]
        if cleared:
            fs = cleared[-1][0]
            rule.append("之后有 resumed_candidates=0 且 load_err 为空的 start（状态被清空）：取最后一次")
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
    explicit = bool(formal_start_arg and formal_start_arg != "auto")
    if explicit:
        if formal_start_arg == "first":
            fs = starts[0][0] if starts else first_visit
            rule = ["--formal-start first"]
        else:
            fs = parse_iso(formal_start_arg)
            rule = ["--formal-start 指定"]
    trial_visits = int(db.scalar("SELECT COUNT(*) FROM visit WHERE ts_epoch < ?", (fs,)) or 0) \
        if (db.has_table("visit") and fs is not None) else 0
    if starts and fs is not None and fs > starts[0][0]:
        gap_h = (fs - starts[0][0]) / 3600.0
        msg = ("正式起点不是第一条 start：从 %s 挪到 %s（晚 %.1f 小时），之前的 %d 次探访按试运行丢弃，不进任何指标"
               % (iso_minute(starts[0][0]), iso_minute(fs), gap_h, trial_visits))
        if not explicit:
            msg += "。这是自动规则（%s）的结果" % "；".join(rule)
            if gap_h > LATE_CLEAR_HOURS:
                msg += ("；该 start 距第一条 start 超过 %g 小时（已过 PROTOCOL“正式测量的起止”的 30 分钟检查），"
                        "请确认状态确实是有意清空的，否则用 --formal-start first 或 --formal-start <带时区的 ISO 时间> 覆盖" % LATE_CLEAR_HOURS)
        warnings.append(msg)

    # 中断：正式起点之后的每条 start 之前的空档。上一条 start 与它之间有 stop 的是正常停止，否则是崩溃重启（没有 stop 记录）。
    interruptions = []
    for i in range(1, len(starts)):
        s, prev = starts[i][0], starts[i - 1][0]
        if fs is None or s <= fs:
            continue  # 试运行与正式起点之间的空档不算中断
        between = [st for st in stops if prev < st < s]
        if between:
            begin, kind, note = between[-1], "stop", "stop 记录到下一条 start"
        else:
            begin = last_activity_between(db, prev, s)
            kind = "crash"
            if begin is None:
                begin, note = prev, "没有 stop 记录，这段时间也没有任何 visit/att/stat 记录：从上一条 start 算起"
            else:
                note = "没有 stop 记录：从崩溃前最后一条 visit/att/stat 记录算起"
        interruptions.append({"kind": kind, "from_utc": iso_minute(begin), "start_utc": iso_minute(s),
                              "minutes": round((s - begin) / 60.0, 1), "load_err_present": starts[i][2] != "", "note": note})
    n_crash = sum(1 for x in interruptions if x["kind"] == "crash")
    if n_crash:
        warnings.append("有 %d 次没有 stop 记录的重启（崩溃），PROTOCOL 要求报告里写明中断时段" % n_crash)

    first_round, n_files, round_src = first_snapshot_round(db, fs) if fs is not None else (None, 0, None)
    # 聚合器抽样的时间下界：正式起点之前最后一次候选池为空的 start（resumed_candidates=0：首次启动、清空或状态文件读不出来，
    # 这几种情况 Pool.Load 都没有恢复 sampled 标记，抽样会重做；只是重启不重抽，sched.go MarkSampled）。DEFINITIONS“聚合器抽样范围”
    agg_cutoff = fs
    if starts and fs is not None:
        empty = [s[0] for s in starts if s[0] <= fs and s[1] == 0]
        if empty:
            agg_cutoff = empty[-1]
    return {
        "formal_start_utc": iso_minute(fs), "formal_start_rule": "；".join(rule),
        "end_utc": iso_minute(end), "hours": round((end - fs) / 3600.0, 2) if (fs is not None and end is not None) else None,
        "first_snapshot_round_complete_utc": iso_minute(first_round),
        "first_snapshot_round": {"regular_list_files_with_base_snapshot": n_files, "source_table": round_src,
                                 "minutes_after_formal_start": round((first_round - fs) / 60.0, 1) if (first_round is not None and fs is not None) else None},
        "aggregator_sample_cutoff_utc": iso_minute(agg_cutoff),
        "starts": [{"utc": iso_minute(s[0]), "resumed_candidates": s[1], "load_err_present": s[2] != ""} for s in starts],
        "stops": [iso_minute(s) for s in stops],
        "versions": sorted({v for _, v in versions}),
        "interruptions": interruptions,
        "interruption_minutes_total": round(sum(i["minutes"] for i in interruptions), 1),
        "interruptions_by_kind": {"stop": len(interruptions) - n_crash, "crash": n_crash},
        "trial_run_visits_before_formal_start": trial_visits,
        "warnings": warnings,
        "_fs": fs, "_end": end, "_first_round": first_round, "_agg_cutoff": agg_cutoff,
    }


# ---------------------------------------------------------------- 候选表

def build_candidate_table(db, fs, dense_threshold, agg_cutoff):
    """在 TEMP 库里建候选表 cand_u：每个候选一行，带状态文件的字段、visit 聚合、att 聚合、是否属于密集 /24。

    - vf：正式起点之后、aborted≠1 的探访（summary.go probeLine 跳过 Aborted）。
    - vc / vl：每个候选的探访次数、是否 state='working' 过、是否要求过认证；最后一次探访的状态和分组（summary.go candAgg.lastState / group）。
    - ac：att 按候选聚合（summary.go attempt()：tcp、responsive、everOK、auth），只算代理候选（cand_kind='proxy'），跳过 canceled。
      每个布尔值算两份：*_all 是整个数据的（给 crosscheck_summary 用，summary.go 不区分试运行），不带后缀的是正式起点之后的。
    - cu：候选全集 = cands ∪ 探访过的候选。
    - am：正式起点所在那次运行之后的聚合器抽样条目（DEFINITIONS“聚合器抽样范围”）。
    - le_cands：正式起点之后出现在任何常规列表快照里的条目（“聚合器独有”的判据）。
    - pfx_n：每个 /24 的候选数（给“从没探访过”按 /24 汇总用，免得相关子查询对 cand_u 反复全表扫描）。
    """
    db.x("""CREATE TEMP TABLE vf AS
            SELECT rid, cand, prefix24, ts_epoch, COALESCE("group", 0) AS grp, state,
                   COALESCE(listed, 0) AS listed, COALESCE(auth, 0) AS auth, COALESCE(n_ok, 0) AS n_ok
            FROM visit WHERE COALESCE(aborted, 0) = 0 AND ts_epoch >= ?""", (fs,))
    db.x("CREATE INDEX temp.vf_cand ON vf(cand, ts_epoch)")
    db.x("CREATE INDEX temp.vf_ts ON vf(ts_epoch)")
    db.x("""CREATE TEMP TABLE vc AS
            SELECT cand, COUNT(*) AS n, MIN(ts_epoch) AS first_e, MAX(ts_epoch) AS last_e,
                   MAX(state = 'working') AS ever_ok, MAX(n_ok > 0) AS ever_nok, MAX(auth) AS auth
            FROM vf GROUP BY cand""")
    db.x("CREATE INDEX temp.vc_cand ON vc(cand)")
    db.x("""CREATE TEMP TABLE vl AS
            SELECT cand, prefix24, state, grp, listed FROM (
              SELECT cand, prefix24, state, grp, listed,
                     ROW_NUMBER() OVER (PARTITION BY cand ORDER BY ts_epoch DESC, rid DESC) AS rn FROM vf)
            WHERE rn = 1""")
    db.x("CREATE INDEX temp.vl_cand ON vl(cand)")

    # att 只扫这一遍。hs_code / http_code 为 0 时 JSON 里省略、库里是 NULL，所以 IS NOT NULL 就是 Go 侧的 Code != 0。
    # GROUP BY +cand：“+”让 SQLite 不用 att_cand_ts 索引（按索引顺序逐行回表是随机读），改为顺序扫描 + 临时 B 树分组。
    att_has_kind = "cand_kind" in db.columns("att")
    kind_filter = "cand_kind = 'proxy'" if att_has_kind else "cand LIKE '%:%' AND cand NOT LIKE 'control:%'"
    exprs = {
        "tcp": "COALESCE(tcp_ok, 0)",
        "resp": "CASE WHEN COALESCE(hs_ok, 0) = 1 OR hs_code IS NOT NULL OR http_code IS NOT NULL THEN 1 ELSE 0 END",
        "ok": "CASE WHEN class = 'ok' AND dst IN ('judge_tls', 'judge_http') THEN 1 ELSE 0 END",
        "auth": "CASE WHEN class = 'hs_auth' OR http_code = 407 THEN 1 ELSE 0 END",
    }
    cols = []
    for name, e in exprs.items():
        cols.append("MAX(%s) AS %s_all" % (e, name))
        cols.append("MAX(CASE WHEN ts_epoch >= ? THEN %s ELSE 0 END) AS %s" % (e, name))
    db.x("""CREATE TEMP TABLE ac AS
            SELECT cand, %s
            FROM att WHERE %s AND class NOT LIKE '%%canceled%%' GROUP BY +cand""" % (", ".join(cols), kind_filter),
         tuple([fs] * len(exprs)))
    db.x("CREATE INDEX temp.ac_cand ON ac(cand)")

    have_cands = db.has_table("cands")
    if have_cands:
        db.x("""CREATE TEMP TABLE cu AS
                SELECT c.key AS key, c.prefix24 AS prefix24, c."group" AS c_grp, 1 AS in_state, c.listed AS listed_end,
                       c.state_name AS state_end, c.visits AS c_visits, c.ever_ok AS c_ever_ok
                FROM cands c
                UNION ALL
                SELECT v.cand, v.prefix24, v.grp, 0, 0, NULL, NULL, NULL
                FROM vl v WHERE NOT EXISTS (SELECT 1 FROM cands c WHERE c.key = v.cand)""")
    else:
        db.x("""CREATE TEMP TABLE cu AS
                SELECT v.cand AS key, v.prefix24 AS prefix24, v.grp AS c_grp, 0 AS in_state, NULL AS listed_end,
                       NULL AS state_end, NULL AS c_visits, NULL AS c_ever_ok FROM vl v""")
    db.x("CREATE INDEX temp.cu_key ON cu(key)")
    # 密集 /24 与其他模块同一个口径（决策 D14）：候选 = 状态文件 cands ∪ 尝试记录里的代理候选（含试运行、含 aborted 探访的尝试）。
    # 下榜超过 24 小时的候选会从状态文件里丢掉，只数 cu（状态文件 ∪ 正式起点后的探访）会漏掉只在试运行里出现、或探访都被中止的候选
    if have_cands and "prefix24" in db.columns("att"):
        db.x("""CREATE TEMP TABLE dense24 AS
                SELECT prefix24, COUNT(*) AS n FROM (SELECT key AS cand, prefix24 FROM cands
                                                     UNION SELECT DISTINCT cand, prefix24 FROM att WHERE %s)
                WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING n > ?""" % kind_filter, (dense_threshold,))
    else:
        db.x("CREATE TEMP TABLE dense24 AS SELECT prefix24, COUNT(*) AS n FROM cu WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING n > ?",
             (dense_threshold,))
    db.x("CREATE INDEX temp.dense24_p ON dense24(prefix24)")
    db.x("""CREATE TEMP TABLE cand_u AS
            SELECT cu.key, cu.prefix24, cu.in_state, cu.listed_end, cu.state_end, cu.c_visits, cu.c_ever_ok, cu.c_grp,
                   COALESCE(vl.grp, cu.c_grp, 0) AS grp,
                   COALESCE(vc.n, 0) AS v_n, vc.first_e, vc.last_e, vl.state AS v_last_state, vl.listed AS v_last_listed,
                   COALESCE(vc.ever_ok, 0) AS v_ever_ok, COALESCE(vc.ever_nok, 0) AS v_ever_nok, COALESCE(vc.auth, 0) AS v_auth,
                   COALESCE(ac.tcp, 0) AS a_tcp, COALESCE(ac.resp, 0) AS a_resp, COALESCE(ac.ok, 0) AS a_ok, COALESCE(ac.auth, 0) AS a_auth,
                   (cu.prefix24 IN (SELECT prefix24 FROM dense24)) AS dense
            FROM cu LEFT JOIN vc ON vc.cand = cu.key LEFT JOIN vl ON vl.cand = cu.key LEFT JOIN ac ON ac.cand = cu.key""")
    db.x("CREATE INDEX temp.cand_u_key ON cand_u(key)")
    db.x("CREATE INDEX temp.cand_u_grp ON cand_u(grp, dense)")
    db.x("CREATE INDEX temp.cand_u_pfx ON cand_u(prefix24)")
    db.x("CREATE TEMP TABLE pfx_n AS SELECT prefix24, COUNT(*) AS n FROM cand_u GROUP BY prefix24")
    db.x("CREATE INDEX temp.pfx_n_pfx ON pfx_n(prefix24)")
    # 正式起点之后出现在任何常规列表快照里的条目（“聚合器独有”的判据），只算一次
    if db.has_table("list_event"):
        db.x("CREATE TEMP TABLE le_cands AS SELECT DISTINCT cand FROM list_event WHERE ts_epoch >= ?", (fs,))
    else:
        db.x("CREATE TEMP TABLE le_cands (cand TEXT)")
    db.x("CREATE INDEX temp.le_cands_cand ON le_cands(cand)")
    # 聚合器抽样条目：只取正式起点所在那次运行之后的
    if db.has_table("agg_member"):
        db.x("CREATE TEMP TABLE am AS SELECT cand, src, prefix24, ts_epoch FROM agg_member WHERE ts_epoch >= ?", (agg_cutoff,))
    else:
        db.x("CREATE TEMP TABLE am (cand TEXT, src TEXT, prefix24 TEXT, ts_epoch REAL)")
    db.x("CREATE INDEX temp.am_cand ON am(cand)")
    db.x("CREATE INDEX temp.am_src ON am(src)")
    return have_cands


def dense_filter(alias, exclude_dense):
    """给查询加“去掉密集 /24”的条件；alias 是带 prefix24 列的表别名。"""
    return (" AND %s.prefix24 NOT IN (SELECT prefix24 FROM dense24)" % alias) if exclude_dense else ""


# ---------------------------------------------------------------- 整个窗口的指标

def group_name(g):
    return "aggregator_sample" if g == 1 else "regular"


def funnel(db, exclude_dense):
    """漏斗（summary.go finish() 的 Funnel）：探访过 → 连得上 → 有协议回应 → 可用过（att 口径）→ 现在可用；要求认证另计。分母都是探访过的候选。"""
    out = {}
    rows = db.q("""SELECT grp, COUNT(*) AS seen, SUM(a_tcp) AS tcp, SUM(a_resp) AS resp, SUM(a_ok) AS working,
                          SUM(v_last_state = 'working') AS now, SUM(v_auth) AS auth, SUM(v_ever_ok) AS visit_ok,
                          SUM(v_ever_ok != a_ok) AS ok_mismatch, SUM(a_ok = 1 AND v_ever_ok = 0) AS att_only,
                          SUM(v_auth != a_auth) AS auth_mismatch
                   FROM cand_u c WHERE v_n > 0%s GROUP BY grp""" % dense_filter("c", exclude_dense))
    for g, seen, tcp, resp, working, now, auth, visit_ok, okm, att_only, authm in rows:
        out[group_name(g)] = {
            "seen": int(seen),
            "连得上": ratio(tcp, seen), "有协议回应": ratio(resp, seen),
            "累计可用率": ratio(working, seen), "最近一次探访可用": ratio(now, seen),
            "要求认证": ratio(auth, seen),
            "核对": {"visit 口径的可用过（state='working'）": int(visit_ok or 0), "两种可用口径不一致的候选": int(okm or 0),
                     "其中只有 att 口径可用（主流程 HTML 没通过、附加测试通过）": int(att_only or 0),
                     "visit.auth 与 att 认证判定不一致的候选": int(authm or 0)},
        }
    for name in ("regular", "aggregator_sample"):
        out.setdefault(name, {"seen": 0, "连得上": ratio(0, 0), "有协议回应": ratio(0, 0), "累计可用率": ratio(0, 0),
                              "最近一次探访可用": ratio(0, 0), "要求认证": ratio(0, 0),
                              "核对": {"visit 口径的可用过（state='working'）": 0, "两种可用口径不一致的候选": 0,
                                       "其中只有 att 口径可用（主流程 HTML 没通过、附加测试通过）": 0,
                                       "visit.auth 与 att 认证判定不一致的候选": 0}})
    tot = db.one("""SELECT COUNT(*), SUM(a_tcp), SUM(a_resp), SUM(a_ok), SUM(v_last_state='working'), SUM(v_auth), SUM(v_ever_ok)
                    FROM cand_u c WHERE v_n > 0%s""" % dense_filter("c", exclude_dense))
    out["total"] = {"seen": int(tot[0]), "连得上": ratio(tot[1], tot[0]), "有协议回应": ratio(tot[2], tot[0]),
                    "累计可用率": ratio(tot[3], tot[0]), "最近一次探访可用": ratio(tot[4], tot[0]), "要求认证": ratio(tot[5], tot[0]),
                    "核对": {"visit 口径的可用过（state='working'）": int(tot[6] or 0)}}
    return out


def counts(db, have_cands):
    """各分母：候选、探访过、从没探访过、在榜、下榜后被丢弃。"""
    r = db.one("""SELECT COUNT(*), SUM(in_state), SUM(in_state = 0), SUM(v_n > 0), SUM(v_n = 0),
                         SUM(COALESCE(listed_end, 0)), SUM(dense), SUM(grp = 1), SUM(grp = 0),
                         SUM(v_n > 0 AND grp = 0), SUM(v_n > 0 AND grp = 1), SUM(v_n), SUM(COALESCE(c_visits, 0)),
                         SUM(COALESCE(listed_end, 0) AND grp = 0), SUM(COALESCE(listed_end, 0) AND grp = 1)
                  FROM cand_u""")
    out = {
        "候选": int(r[0]), "其中在状态文件里": int(r[1] or 0) if have_cands else None,
        "其中有探访记录但不在状态文件里（下榜后被丢弃）": int(r[2] or 0) if have_cands else None,
        "探访过": int(r[3] or 0), "从没探访过": int(r[4] or 0) if have_cands else None,
        "结束时在榜（cands.listed）": {"合计": int(r[5] or 0), "regular": int(r[13] or 0), "aggregator_sample": int(r[14] or 0),
                                "note": "状态文件的 listed 标志，含聚合器抽样；按最后一次探访的 group 分组。常规列表由 snap- 重建的在榜数见 point_end"}
        if have_cands else None,
        "属于密集 /24 的候选": int(r[6] or 0),
        "分组": {"regular": int(r[8] or 0), "aggregator_sample": int(r[7] or 0)},
        "探访过（分组）": {"regular": int(r[9] or 0), "aggregator_sample": int(r[10] or 0)},
        "非 aborted 探访次数（正式起点之后）": int(r[11] or 0),
        "状态文件记的探访次数之和（含试运行）": int(r[12] or 0) if have_cands else None,
    }
    if db.has_table("stat_pool"):
        last = db.scalar("SELECT MAX(ts_epoch) FROM stat_pool")
        if last is not None:
            out["最后一条 stat 的 pool"] = {k: int(v) for k, v in db.q(
                "SELECT key, value FROM stat_pool WHERE ts_epoch = ? ORDER BY key", (last,))}
    if have_cands:
        out["状态文件各状态候选数"] = {k: int(v) for k, v in db.q(
            "SELECT state_end, COUNT(*) FROM cand_u WHERE in_state = 1 GROUP BY state_end ORDER BY state_end")}
    return out


def never_visited(db, have_cands, top):
    """从没探访过的候选：条数、分组、在榜、按 /24 汇总（前 top 个 + 其余合计）。"""
    if not have_cands:
        return {"note": "库里没有 cands 表（入库时没给 state.json.gz），从没探访过的候选无法识别", "total": None}
    r = db.one("""SELECT COUNT(*), SUM(grp = 0), SUM(grp = 1), SUM(COALESCE(listed_end, 0)), SUM(dense), COUNT(DISTINCT prefix24),
                         SUM(COALESCE(c_visits, 0) > 0)
                  FROM cand_u WHERE v_n = 0""")
    rows = db.q("""SELECT c.prefix24, COUNT(*) AS never, p.n AS cands,
                          SUM(COALESCE(c.listed_end, 0)) AS listed, MAX(c.dense) AS dense
                   FROM cand_u c JOIN pfx_n p ON p.prefix24 = c.prefix24
                   WHERE c.v_n = 0 GROUP BY c.prefix24 ORDER BY never DESC, c.prefix24 LIMIT ?""", (top,))
    listed_top = [{"prefix24": p, "从没探访过": int(n), "该 /24 的候选": int(cands), "其中结束时在榜": int(listed or 0),
                   "属于密集 /24": bool(dense)} for p, n, cands, listed, dense in rows]
    rest = int(r[0] or 0) - sum(x["从没探访过"] for x in listed_top)
    return {"total": int(r[0] or 0), "分组": {"regular": int(r[1] or 0), "aggregator_sample": int(r[2] or 0)},
            "其中结束时在榜": int(r[3] or 0), "其中属于密集 /24": int(r[4] or 0), "涉及的 /24 个数": int(r[5] or 0),
            "其中只在试运行期间探访过（cands.visits>0）": int(r[6] or 0),
            "按 /24（前 %d 个）" % top: listed_top, "其余 /24 合计": rest}


def dense_prefixes(db, threshold):
    rows = db.q("""SELECT c.prefix24, COUNT(*) AS cands, SUM(v_n > 0) AS visited, SUM(v_n = 0) AS never,
                          SUM(a_ok) AS ever_ok, SUM(v_last_state = 'working') AS now, SUM(COALESCE(listed_end, 0)) AS listed,
                          SUM(grp = 1) AS agg, (SELECT d.n FROM dense24 d WHERE d.prefix24 = c.prefix24) AS n_rule
                   FROM cand_u c WHERE dense = 1 GROUP BY c.prefix24 ORDER BY cands DESC, c.prefix24""")
    out = [{"prefix24": p, "候选": int(c), "判定用的候选（状态文件 ∪ 尝试记录）": int(nr or 0), "探访过": int(v or 0), "从没探访过": int(nv or 0),
            "可用过": int(e or 0), "最近一次探访可用": int(n or 0), "结束时在榜": int(l or 0), "其中聚合器抽样": int(a or 0)}
           for p, c, v, nv, e, n, l, a, nr in rows]
    return {"threshold": threshold, "口径": "候选数 > 阈值的 /24。判定用的候选 = 状态文件 cands ∪ 尝试记录里的代理候选（各模块同一口径，决策 D14）；"
                                           "“候选”一列是本模块分母用的 cand_u（状态文件 ∪ 正式起点后探访过的）；“可用过”是 att 口径（同累计可用率）",
            "prefixes": out, "count": len(out),
            "candidates_total": sum(x["候选"] for x in out), "visited_total": sum(x["探访过"] for x in out),
            "ever_ok_total": sum(x["可用过"] for x in out)}


def auth_block(db, exclude_dense):
    r = db.one("""SELECT SUM(v_auth), SUM(v_auth AND grp = 0), SUM(v_auth AND grp = 1), SUM(v_auth AND COALESCE(listed_end, 0) = 1),
                         SUM(v_auth AND a_ok), SUM(a_auth), COUNT(*)
                  FROM cand_u c WHERE v_n > 0%s""" % dense_filter("c", exclude_dense))
    return {"要求认证的候选": int(r[0] or 0), "分组": {"regular": int(r[1] or 0), "aggregator_sample": int(r[2] or 0)},
            "其中结束时在榜": int(r[3] or 0), "其中也曾可用（另一种协议通过，att 口径）": int(r[4] or 0),
            "att 口径（hs_auth 或 407）": int(r[5] or 0), "占探访过的候选": ratio(r[0] or 0, r[6] or 0)}


# ---------------------------------------------------------------- 时点

def make_listed_at(db, T, name):
    """重建时刻 T 常规列表的在榜集合（cand, src, prefix24）。口径见 DEFINITIONS[“在榜（常规列表）”]，与 summary.go snapLine 一致。"""
    db.x('DROP TABLE IF EXISTS "%s"' % name)
    if not db.has_table("list_event"):
        db.x('CREATE TEMP TABLE "%s" (cand TEXT, src TEXT, prefix24 TEXT)' % name)
        db.x('CREATE INDEX temp."%s_cand" ON "%s"(cand)' % (name, name))
        return
    db.x("""CREATE TEMP TABLE "%s" AS
            WITH lb AS (SELECT src, label, MAX(ts_epoch) AS bts FROM list_event WHERE base = 1 AND ts_epoch <= ? GROUP BY src, label),
                 le AS (SELECT cand, src, label, event, ts_epoch, prefix24,
                               ROW_NUMBER() OVER (PARTITION BY cand, src, label ORDER BY ts_epoch DESC, rid DESC) AS rn
                        FROM list_event WHERE ts_epoch <= ?)
            SELECT DISTINCT le.cand AS cand, le.src AS src, le.prefix24 AS prefix24
            FROM le JOIN lb ON lb.src = le.src AND lb.label = le.label
            WHERE le.rn = 1 AND le.event = 'add' AND le.ts_epoch >= lb.bts""" % name, (T, T))
    db.x('CREATE INDEX temp."%s_cand" ON "%s"(cand)' % (name, name))
    db.x('CREATE INDEX temp."%s_src" ON "%s"(src)' % (name, name))


def make_last_at(db, T, name):
    """时刻 T 之前每个候选最后一次（非 aborted）探访的状态。按探访开始时刻 visit.ts 取（DEFINITIONS“时点可用率”）。"""
    db.x('DROP TABLE IF EXISTS "%s"' % name)
    db.x("""CREATE TEMP TABLE "%s" AS
            SELECT cand, state, grp FROM (
              SELECT cand, state, grp, ROW_NUMBER() OVER (PARTITION BY cand ORDER BY ts_epoch DESC, rid DESC) AS rn
              FROM vf WHERE ts_epoch <= ?) WHERE rn = 1""" % name, (T,))
    db.x('CREATE INDEX temp."%s_cand" ON "%s"(cand)' % (name, name))


def point_regular(db, exclude_dense, by_source):
    """时刻 T 常规列表的时点可用率（用已建好的 lst / lastv 两张临时表）。"""
    df = dense_filter("l", exclude_dense)
    base = """FROM lst l LEFT JOIN lastv v ON v.cand = l.cand LEFT JOIN cand_u u ON u.key = l.cand WHERE 1%s""" % df
    sel = """COUNT(DISTINCT l.cand) AS listed,
             COUNT(DISTINCT CASE WHEN v.cand IS NOT NULL THEN l.cand END) AS den,
             COUNT(DISTINCT CASE WHEN v.state = 'working' THEN l.cand END) AS num,
             COUNT(DISTINCT CASE WHEN v.cand IS NULL AND u.key IS NOT NULL THEN l.cand END) AS queued,
             COUNT(DISTINCT CASE WHEN v.cand IS NULL AND u.key IS NULL THEN l.cand END) AS excluded"""
    r = db.one("SELECT " + sel + " " + base)
    out = {"在榜": int(r[0]), "在榜但尚未探访（候选池里排队）": int(r[3]), "在榜但不进候选池（不探测的地址）": int(r[4]),
           "时点可用率": ratio(r[2], r[1])}
    if by_source:
        rows = db.q("SELECT l.src, " + sel + " " + base + " GROUP BY l.src ORDER BY l.src")
        out["by_source"] = {src: {"在榜": int(a), "在榜但尚未探访（候选池里排队）": int(q), "在榜但不进候选池（不探测的地址）": int(e),
                                  "时点可用率": ratio(n, d)} for src, a, d, n, q, e in rows}
    return out


def point_aggregator(db, T, exclude_dense):
    """时刻 T 聚合器抽样的时点可用率：分母是抽样时刻 ≤ T 且已探访过的抽样条目（不区分是否仍在榜）。
    “尚未探访”只算进了候选池的抽样条目；被 Pool.Upsert 跳过（不进候选池）的另计。"""
    if not db.has_table("agg_member"):
        return {"note": "库里没有 agg_member 表"}
    df = dense_filter("m", exclude_dense)
    sel = """COUNT(DISTINCT m.cand) AS members,
             COUNT(DISTINCT CASE WHEN v.cand IS NOT NULL THEN m.cand END) AS den,
             COUNT(DISTINCT CASE WHEN v.state = 'working' THEN m.cand END) AS num,
             COUNT(DISTINCT CASE WHEN v.cand IS NULL AND u.key IS NOT NULL THEN m.cand END) AS queued,
             COUNT(DISTINCT CASE WHEN u.key IS NULL THEN m.cand END) AS excluded,
             COUNT(DISTINCT CASE WHEN x.cand IS NULL THEN m.cand END) AS excl_members,
             COUNT(DISTINCT CASE WHEN x.cand IS NULL AND v.cand IS NOT NULL THEN m.cand END) AS excl_den,
             COUNT(DISTINCT CASE WHEN x.cand IS NULL AND v.state = 'working' THEN m.cand END) AS excl_num"""
    base = """FROM am m LEFT JOIN lastv v ON v.cand = m.cand LEFT JOIN cand_u u ON u.key = m.cand
              LEFT JOIN le_cands x ON x.cand = m.cand
              WHERE m.ts_epoch <= ?%s""" % df

    def block(row, label):
        members, den, num, queued, excluded, em, ed, en = row
        return {label: int(members), "尚未探访（在候选池里）": int(queued), "不进候选池": int(excluded),
                "时点可用率": ratio(num, den), "独有条目": int(em), "独有条目的时点可用率": ratio(en, ed)}

    out = {"by_aggregator": {}}
    for row in db.q("SELECT m.src, " + sel + " " + base + " GROUP BY m.src ORDER BY m.src", (T,)):
        out["by_aggregator"][row[0]] = block(row[1:], "抽样条目")
    out["all_samples"] = block(db.one("SELECT " + sel + " " + base, (T,)), "抽样条目（去重）")
    return out


def point_at(db, T, with_sources):
    make_listed_at(db, T, "lst")
    make_last_at(db, T, "lastv")
    out = {}
    for key, ex in (("all", False), ("excluding_dense", True)):
        out[key] = {"regular": point_regular(db, ex, with_sources), "aggregator_sample": point_aggregator(db, T, ex)}
    return out


def point_series(db, fs, end, step_hours, with_sources, first_round=None):
    """从正式起点 + 一个间隔起每隔 step_hours 一个时点，最后一个点是结束时刻。
    不给 0 小时的点：那时列表快照还没抓完，重建的“在榜”只含 ts ≤ 正式起点的那几个文件（DEFINITIONS“首轮快照完成时刻”）。"""
    pts = []
    if fs is None or end is None:
        return pts
    k = 1
    while True:
        T = fs + k * step_hours * 3600.0
        if T >= end:
            break
        pts.append((T, False))
        k += 1
    pts.append((end, True))
    series = []
    for T, is_end in pts:
        entry = {"t_utc": iso_minute(T), "hours_since_start": round((T - fs) / 3600.0, 2), "is_end": is_end,
                 "snapshots_complete": (T >= first_round) if first_round is not None else None}
        entry.update(point_at(db, T, with_sources))
        series.append(entry)
    return series


# ---------------------------------------------------------------- 来源

def sources(db, exclude_dense, fs):
    """每个常规来源：结束时在榜（summary.go SourceRow 口径）与曾经在榜（累计）两组。要求 lst 是结束时刻的在榜表。
    累计可用率取 att 口径（a_ok；summary.go SourceRow.Working 也是 everOK）。"""
    if not db.has_table("list_event"):
        return {}
    df_l = dense_filter("l", exclude_dense)
    out = {}
    rows = db.q("""SELECT l.src, COUNT(DISTINCT l.cand), COUNT(DISTINCT CASE WHEN u.v_n > 0 THEN l.cand END),
                          COUNT(DISTINCT CASE WHEN u.v_last_state = 'working' THEN l.cand END),
                          COUNT(DISTINCT CASE WHEN u.a_ok = 1 THEN l.cand END),
                          COUNT(DISTINCT CASE WHEN u.key IS NULL THEN l.cand END),
                          COUNT(DISTINCT CASE WHEN u.key IS NOT NULL AND u.v_n = 0 THEN l.cand END),
                          COUNT(DISTINCT CASE WHEN u.v_auth = 1 THEN l.cand END)
                   FROM lst l LEFT JOIN cand_u u ON u.key = l.cand WHERE 1%s GROUP BY l.src ORDER BY l.src""" % df_l)
    for src, listed, visited, now, ever, excluded, queued, auth in rows:
        out[src] = {"结束时在榜": int(listed), "其中不进候选池": int(excluded), "其中尚未探访": int(queued),
                    "时点可用率（结束时刻）": ratio(now, visited), "累计可用率（结束时在榜）": ratio(ever, visited),
                    "要求认证": int(auth)}
    # 曾经在榜：正式起点之后任何一次 add 事件（含 base=1 的首次快照）
    rows = db.q("""SELECT e.src, COUNT(DISTINCT e.cand), COUNT(DISTINCT CASE WHEN u.v_n > 0 THEN e.cand END),
                          COUNT(DISTINCT CASE WHEN u.a_ok = 1 THEN e.cand END),
                          COUNT(DISTINCT CASE WHEN u.key IS NULL THEN e.cand END)
                   FROM list_event e LEFT JOIN cand_u u ON u.key = e.cand
                   WHERE e.event = 'add' AND e.ts_epoch >= ?%s GROUP BY e.src ORDER BY e.src""" % dense_filter("e", exclude_dense), (fs,))
    for src, ever_listed, visited, ever_ok, excluded in rows:
        out.setdefault(src, {})
        out[src].update({"曾经在榜": int(ever_listed), "曾经在榜且不进候选池": int(excluded),
                         "累计可用率（曾经在榜）": ratio(ever_ok, visited)})
    return out


def aggregators(db, exclude_dense, agg_cutoff):
    """每个聚合器：抽样规模（agg_sample）、独有条目、结束时的时点与累计可用率。要求 lastv 是结束时刻的表。
    “从没探访过”拆成在候选池里的和不进候选池的两列（DEFINITIONS“在榜（聚合器抽样）”）。累计可用率取 att 口径。"""
    if not db.has_table("agg_member"):
        return {}
    out = {}
    if db.has_table("agg_sample"):
        for src, union, excl, sample in db.q('SELECT src, "union", exclusive, sample FROM agg_sample WHERE ts_epoch >= ? ORDER BY ts_epoch',
                                             (agg_cutoff,)):
            out.setdefault(src, {})["抽样记录"] = {"合并后条目": int(union or 0), "不在任何常规列表里的": int(excl or 0), "抽中": int(sample or 0)}
    df = dense_filter("m", exclude_dense)
    rows = db.q("""SELECT m.src, COUNT(DISTINCT m.cand),
                          COUNT(DISTINCT CASE WHEN u.v_n > 0 THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN u.v_last_state = 'working' THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN u.a_ok = 1 THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN u.key IS NOT NULL AND u.v_n = 0 THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN u.key IS NULL THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN COALESCE(u.listed_end, 0) = 1 THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN x.cand IS NULL THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN x.cand IS NULL AND u.v_n > 0 THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN x.cand IS NULL AND u.v_last_state = 'working' THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN x.cand IS NULL AND u.a_ok = 1 THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN u.in_state = 1 AND u.c_grp = 1 THEN m.cand END),
                          COUNT(DISTINCT CASE WHEN u.v_auth = 1 THEN m.cand END)
                   FROM am m LEFT JOIN cand_u u ON u.key = m.cand
                        LEFT JOIN le_cands x ON x.cand = m.cand
                   WHERE 1%s GROUP BY m.src ORDER BY m.src""" % df)
    for (src, members, visited, now, ever, never, excluded, listed_end, excl, excl_vis, excl_now, excl_ever, grp1, auth) in rows:
        out.setdefault(src, {}).update({
            "抽样条目": int(members), "从没探访过（在候选池里）": int(never), "不进候选池": int(excluded),
            "结束时仍在榜（cands.listed）": int(listed_end),
            "时点可用率（结束时刻）": ratio(now, visited), "累计可用率": ratio(ever, visited), "要求认证": int(auth),
            "独有条目": int(excl), "独有条目的时点可用率（结束时刻）": ratio(excl_now, excl_vis), "独有条目的累计可用率": ratio(excl_ever, excl_vis),
            "核对：状态文件里 group=1 的抽样条目": int(grp1)})
    r = db.one("""SELECT COUNT(DISTINCT m.cand),
                         COUNT(DISTINCT CASE WHEN x.cand IS NULL THEN m.cand END),
                         COUNT(DISTINCT CASE WHEN x.cand IS NULL AND u.v_n > 0 THEN m.cand END),
                         COUNT(DISTINCT CASE WHEN x.cand IS NULL AND u.v_last_state = 'working' THEN m.cand END),
                         COUNT(DISTINCT CASE WHEN x.cand IS NULL AND u.a_ok = 1 THEN m.cand END),
                         COUNT(DISTINCT CASE WHEN x.cand IS NOT NULL THEN m.cand END),
                         COUNT(DISTINCT CASE WHEN u.key IS NOT NULL AND u.v_n = 0 THEN m.cand END),
                         COUNT(DISTINCT CASE WHEN u.key IS NULL THEN m.cand END)
                  FROM am m LEFT JOIN cand_u u ON u.key = m.cand
                       LEFT JOIN le_cands x ON x.cand = m.cand WHERE 1%s""" % df)
    out["_all_aggregators"] = {"抽样条目（去重）": int(r[0]), "从没探访过（在候选池里）": int(r[6]), "不进候选池": int(r[7]),
                               "独有条目": int(r[1]), "后来也出现在常规列表里": int(r[5]),
                               "独有条目的时点可用率（结束时刻）": ratio(r[3], r[2]), "独有条目的累计可用率": ratio(r[4], r[2])}
    return out


# ---------------------------------------------------------------- 核对

def checks(db, have_cands, end_point):
    """内部一致性：list_event 重建的结束时在榜 vs cands.listed；最后一次探访状态 vs cands.state_name；visit 与 att 的可用判定。"""
    out = {}
    if have_cands and db.has_table("list_event"):
        r = db.one("""SELECT COUNT(*),
                             SUM(COALESCE(u.listed_end, 0) = 1),
                             SUM(u.key IS NULL)
                      FROM lst l LEFT JOIN cand_u u ON u.key = l.cand""")
        r2 = db.scalar("""SELECT COUNT(*) FROM cand_u u WHERE COALESCE(u.listed_end, 0) = 1 AND u.grp = 0
                          AND NOT EXISTS (SELECT 1 FROM lst l WHERE l.cand = u.key)""")
        blk = {"重建的常规在榜条目": int(r[0]), "其中 cands.listed=1": int(r[1] or 0), "其中不在候选池": int(r[2] or 0),
               "cands.listed=1 且 group=0 却不在重建集合里": int(r2 or 0)}
        # 归因：group 只降不升（sched.go Upsert 只把 1 改成 0），先在常规列表上过榜、之后只剩聚合器还列着的候选仍是 group=0、listed=1，
        # 但常规列表重建里已经没有它。按状态文件里结束时的来源（cand_src.src_name）分三类；聚合器来源名取 agg_sample.src。
        if r2 and db.has_table("cand_src") and db.has_table("agg_sample"):
            r3 = db.one("""WITH miss AS (SELECT u.key FROM cand_u u WHERE COALESCE(u.listed_end, 0) = 1 AND u.grp = 0
                                         AND NOT EXISTS (SELECT 1 FROM lst l WHERE l.cand = u.key)),
                                aggs AS (SELECT DISTINCT src FROM agg_sample),
                                per AS (SELECT m.key, COUNT(s.key) AS n_src,
                                               SUM(s.src_name IS NOT NULL AND s.src_name NOT IN (SELECT src FROM aggs)) AS n_reg
                                        FROM miss m LEFT JOIN cand_src s ON s.key = m.key GROUP BY m.key)
                           SELECT SUM(n_src > 0 AND n_reg = 0), SUM(n_reg > 0), SUM(n_src = 0) FROM per""")
            blk["其中结束时只有聚合器在列（group 只降不升，sched.go Upsert）"] = int(r3[0] or 0)
            blk["其中结束时仍有常规来源（应为 0：重建漏了）"] = int(r3[1] or 0)
            blk["其中状态文件里没有来源"] = int(r3[2] or 0)
        out["结束时在榜：list_event 重建 vs cands.listed"] = blk
        r = db.one("""SELECT SUM(v_n > 0 AND v_last_state IS NOT state_end), SUM(v_n > 0)
                      FROM cand_u WHERE in_state = 1""")
        out["最后一次探访状态 vs cands.state_name 不一致的候选"] = {"num": int(r[0] or 0), "den": int(r[1] or 0),
                                                        "note": "试运行或 aborted 探访会造成差异；不为 0 不一定是错"}
        # cands.ever_ok 由 okMask != 0 置位（prober.go Visit），是 visit 口径，所以和 v_ever_ok 比
        r = db.one("SELECT SUM(v_ever_ok != COALESCE(c_ever_ok, 0)), COUNT(*) FROM cand_u WHERE in_state = 1")
        out["visit 口径可用过 vs cands.ever_ok 不一致的候选"] = {"num": int(r[0] or 0), "den": int(r[1]),
                                                     "note": "cands.ever_ok 由主流程 okMask 置位，与 visit.state='working' 同口径；试运行探访会造成差异"}
    r = db.one("SELECT SUM(v_ever_ok != a_ok), SUM(v_ever_ok != v_ever_nok), COUNT(*), SUM(a_ok = 1 AND v_ever_ok = 0), SUM(a_ok = 0 AND v_ever_ok = 1) FROM cand_u WHERE v_n > 0")
    out["累计可用率的两种口径：att class='ok'（到 judge）vs visit.state='working' 不一致的候选"] = {
        "num": int(r[0] or 0), "den": int(r[2] or 0),
        "只有 att 口径可用（主流程 HTML 没通过、附加测试通过）": int(r[3] or 0),
        "只有 visit 口径可用（不应出现：state='working' 必有一条 ok 的 att）": int(r[4] or 0)}
    out["visit.state='working' vs visit.ok 非空 不一致的候选"] = {"num": int(r[1] or 0), "den": int(r[2] or 0)}
    if end_point is not None and have_cands:
        now_state = db.scalar("SELECT COUNT(*) FROM cand_u WHERE in_state = 1 AND state_end = 'working' AND COALESCE(listed_end, 0) = 1 AND grp = 0")
        out["结束时刻常规时点可用率分子 vs cands（state_name='working' 且 listed 且 group=0）"] = {
            "重建口径": end_point["all"]["regular"]["时点可用率"]["num"], "cands 口径": int(now_state or 0)}
    return out


def crosscheck_summary(db, path, have_cands):
    """与 fieldtest 自带汇总（summary.json）交叉核对。summary.go 不区分试运行，所以这里按整个数据算（不裁正式起点），
    att 侧复用 build_candidate_table 建好的 ac 表的 *_all 列（不再扫第二遍 att）；working 用 att 口径（summary.go everOK）。
    只抄 summary.json 里的计数字段；members、examples 等含地址的字段一概不读。"""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    out = {"summary_generated": s.get("generated")}
    cmp = {}

    def put(key, want, got):
        cmp[key] = {"summary": want, "computed": got, "match": (want == got)}

    # pool：summary 抄的是最后一条 stat 的 pool
    pool = s.get("pool") or {}
    if db.has_table("stat_pool"):
        last = db.scalar("SELECT MAX(ts_epoch) FROM stat_pool")
        mine = {k: int(v) for k, v in db.q("SELECT key, value FROM stat_pool WHERE ts_epoch = ?", (last,))} if last else {}
        for k in sorted(pool):
            put("pool.%s (stat_pool)" % k, pool[k], mine.get(k))
    if have_cands:
        c = db.one("""SELECT COUNT(*), SUM(listed), SUM("group" = 1), SUM(state_name = 'working'), SUM(state_name = 'open'),
                             SUM(state_name = 'dead'), SUM(state_name = 'new') FROM cands""")
        for k, v in (("total", c[0]), ("listed", c[1]), ("aggregator_sample", c[2]), ("working", c[3]), ("open", c[4]), ("dead", c[5])):
            if k in pool:
                put("pool.%s (cands)" % k, pool[k], int(v or 0))
    # funnel：整个数据、非 aborted、分组取最后一次探访的 group；tcp / responsive / working / auth 取 att 的 *_all 列
    fun = s.get("funnel") or {}
    db.x("DROP TABLE IF EXISTS xf")
    db.x("""CREATE TEMP TABLE xf AS
            WITH v AS (SELECT rid, cand, COALESCE("group", 0) AS grp, state, COALESCE(auth, 0) AS auth, ts_epoch FROM visit WHERE COALESCE(aborted, 0) = 0),
                 agg AS (SELECT cand, MAX(state = 'working') AS ever_visit, MAX(auth) AS auth FROM v GROUP BY cand),
                 last AS (SELECT cand, grp, state FROM (SELECT cand, grp, state, ROW_NUMBER() OVER (PARTITION BY cand ORDER BY ts_epoch DESC, rid DESC) rn FROM v) WHERE rn = 1)
            SELECT last.cand, last.grp, last.state, agg.ever_visit, agg.auth,
                   COALESCE(a.tcp_all, 0) tcp, COALESCE(a.resp_all, 0) resp, COALESCE(a.ok_all, 0) ever
            FROM last JOIN agg ON agg.cand = last.cand LEFT JOIN ac a ON a.cand = last.cand""")
    db.x("CREATE INDEX temp.xf_cand ON xf(cand)")
    for g, name in ((0, "regular"), (1, "aggregator_sample")):
        r = db.one("SELECT COUNT(*), SUM(tcp), SUM(resp), SUM(ever), SUM(state = 'working'), SUM(auth) FROM xf WHERE grp = ?", (g,))
        want = fun.get(name) or {}
        for k, v in zip(("seen", "tcp", "responsive", "working", "working_now", "auth"), r):
            if k in want:
                put("funnel.%s.%s" % (name, k), want[k], int(v or 0))
    # by_source：结束时在榜（重建）× 探访过 / 现在可用 / 曾经可用（att 口径）
    end = db.scalar("SELECT MAX(ts_epoch) FROM list_event") if db.has_table("list_event") else None
    if end is not None:
        make_listed_at(db, max(end, db.scalar("SELECT MAX(ts_epoch) FROM visit") or end), "xl")
        rows = {src: (a, b, c, d) for src, a, b, c, d in db.q("""
            SELECT l.src, COUNT(DISTINCT l.cand), COUNT(DISTINCT CASE WHEN x.cand IS NOT NULL THEN l.cand END),
                   COUNT(DISTINCT CASE WHEN x.state = 'working' THEN l.cand END), COUNT(DISTINCT CASE WHEN x.ever = 1 THEN l.cand END)
            FROM xl l LEFT JOIN xf x ON x.cand = l.cand GROUP BY l.src""")}
        for row in s.get("by_source") or []:
            src = row.get("src")
            got = rows.get(src, (None, None, None, None))
            for k, v in zip(("listed", "visited", "working_now", "working"), got):
                if k in row:
                    put("by_source.%s.%s" % (src, k), row[k], v)
    # 聚合器抽样记录
    if db.has_table("agg_sample"):
        mine = {src: (u, e, n) for src, u, e, n in db.q('SELECT src, "union", exclusive, sample FROM agg_sample')}
        for a in s.get("aggregator_samples") or []:
            src = a.get("src")
            got = mine.get(src, (None, None, None))
            for k, v in zip(("union", "exclusive", "sample"), got):
                if k in a:
                    put("aggregator_samples.%s.%s" % (src, k), a[k], v)
    # 记录条数
    recs = s.get("records") or {}
    for k in ("visit", "att"):
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


def assert_clean(text, db):
    """最后一道保险：输出文本里不许有 ip:port、不带 /24 的 IPv4、judge 的主机名或 IP、分享链接/凭据形态（@）。
    judge 的身份只从库里的 self_names / self_ips 表取（ingest 从 start.judge_host / judge_ip 和 judge 记录填出），
    脚本里不写任何主机名或 IP 字面量；两张表缺失或为空就拒绝输出，免得检查静默通过。这是断言，不是放行手段。"""
    bad = []
    if HOSTPORT_RE.search(text):
        bad.append("ip:port")
    m = IPV4_RE.search(text)
    if m:
        bad.append("不带 /24 的 IPv4")
    for table, col in (("self_names", "name"), ("self_ips", "ip")):
        if not db.has_table(table):
            raise SystemExit("库里没有 %s 表，无法核对输出里有没有 judge 的身份；拒绝输出" % table)
        vals = [v for (v,) in db.q("SELECT DISTINCT %s FROM %s" % (col, table)) if v]
        if not vals:
            raise SystemExit("%s 表是空的（ingest 应从 start.judge_host / judge_ip 填出至少一条），无法核对；拒绝输出" % table)
        low = text.lower()
        if any(v.lower() in low for v in vals):
            bad.append("judge 身份（%s）" % table)
    if "@" in text:
        bad.append("字面量 @（分享链接或凭据形态）")
    if bad:
        raise SystemExit("输出含不许出现的内容：%s；已拒绝写出" % "、".join(bad))


# ---------------------------------------------------------------- Markdown

def print_markdown(res):
    w = res["window"]
    print("### 观察窗口\n")
    ib = w["interruptions_by_kind"]
    print(f"- 正式起点 {w['formal_start_utc']}（{w['formal_start_rule']}），结束 {w['end_utc']}，共 {fmt(w['hours'])} 小时；"
          f"start {len(w['starts'])} 条，中断 {len(w['interruptions'])} 次（正常停止 {ib['stop']}，崩溃 {ib['crash']}）合计 {fmt(w['interruption_minutes_total'])} 分钟；"
          f"首轮快照完成于 {w['first_snapshot_round_complete_utc']}；正式起点之前的试运行探访 {fmt(w['trial_run_visits_before_formal_start'])} 次")
    for msg in w["warnings"]:
        print(f"- 注意：{msg}")
    n = res["n"]
    le = n["结束时在榜（cands.listed）"] or {}
    print(f"- 候选 {fmt(n['候选'])}（常规 {fmt(n['分组']['regular'])}，聚合器抽样 {fmt(n['分组']['aggregator_sample'])}），"
          f"探访过 {fmt(n['探访过'])}，从没探访过 {fmt(n['从没探访过'])}，"
          f"结束时 cands.listed=1 的 {fmt(le.get('合计'))}（常规 {fmt(le.get('regular'))}，含聚合器抽样 {fmt(le.get('aggregator_sample'))}），"
          f"下榜后被丢弃 {fmt(n['其中有探访记录但不在状态文件里（下榜后被丢弃）'])}")

    print("\n### 漏斗（分母：探访过的候选；累计可用率为 att 口径）\n")
    print("| 口径 | 分组 | 探访过 | 连得上 | 有协议回应 | 累计可用率 | 最近一次探访可用 | 要求认证 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        for g in ("regular", "aggregator_sample", "total"):
            f = res["funnel"][key][g]
            print(f"| {label} | {g} | {fmt(f['seen'])} | {rfmt(f['连得上'])} | {rfmt(f['有协议回应'])} | {rfmt(f['累计可用率'])} | "
                  f"{rfmt(f['最近一次探访可用'])} | {rfmt(f['要求认证'])} |")
    fr = res["funnel"]["all"]["regular"]["核对"]
    vk = "visit 口径的可用过（state='working'）"
    print(f"\n常规列表里 visit 口径（state='working'）可用过 {fmt(fr[vk])} 个，"
          f"两种口径不一致 {fmt(fr['两种可用口径不一致的候选'])} 个（其中只在附加测试里通过的 "
          f"{fmt(fr['其中只有 att 口径可用（主流程 HTML 没通过、附加测试通过）'])} 个）")

    print("\n### 时点可用率（观察结束时刻；分母：在榜且探访过）\n")
    print("| 口径 | 分组 | 在榜 | 排队未探访 | 不进候选池 | 时点可用率 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        r = res["point_end"][key]["regular"]
        print(f"| {label} | 常规列表合计 | {fmt(r['在榜'])} | {fmt(r['在榜但尚未探访（候选池里排队）'])} | "
              f"{fmt(r['在榜但不进候选池（不探测的地址）'])} | {rfmt(r['时点可用率'])} |")
        a = res["point_end"][key]["aggregator_sample"].get("all_samples")
        if a:
            print(f"| {label} | 聚合器抽样合计（抽样条目，不看在榜） | {fmt(a['抽样条目（去重）'])} | {fmt(a['尚未探访（在候选池里）'])} | "
                  f"{fmt(a['不进候选池'])} | {rfmt(a['时点可用率'])} |")
            print(f"| {label} | 聚合器独有条目 | {fmt(a['独有条目'])} | — | — | {rfmt(a['独有条目的时点可用率'])} |")

    print("\n### 每个来源（结束时刻；全部候选 / 去掉密集 /24）\n")
    print("| 来源 | 结束时在榜 | 不进候选池 | 尚未探访 | 时点可用率 | 累计可用率（结束时在榜） | 曾经在榜 | 累计可用率（曾经在榜） | 去掉密集 /24：时点 | 去掉密集 /24：累计（曾经在榜） |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for src in sorted(res["by_source"]["all"]):
        s = res["by_source"]["all"][src]
        e = res["by_source"]["excluding_dense"].get(src, {})
        print(f"| {src} | {fmt(s.get('结束时在榜'))} | {fmt(s.get('其中不进候选池'))} | {fmt(s.get('其中尚未探访'))} | "
              f"{rfmt(s['时点可用率（结束时刻）']) if '时点可用率（结束时刻）' in s else '—'} | "
              f"{rfmt(s['累计可用率（结束时在榜）']) if '累计可用率（结束时在榜）' in s else '—'} | {fmt(s.get('曾经在榜'))} | "
              f"{rfmt(s['累计可用率（曾经在榜）']) if '累计可用率（曾经在榜）' in s else '—'} | "
              f"{rfmt(e['时点可用率（结束时刻）']) if '时点可用率（结束时刻）' in e else '—'} | "
              f"{rfmt(e['累计可用率（曾经在榜）']) if '累计可用率（曾经在榜）' in e else '—'} |")

    print("\n### 聚合器抽样（结束时刻）\n")
    print("| 聚合器 | 抽中 | 从没探访过（在候选池里） | 不进候选池 | 结束时仍在榜 | 时点可用率 | 累计可用率 | 独有条目 | 独有：时点 | 独有：累计 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for src, a in sorted(res["aggregators"]["all"].items()):
        if src.startswith("_") or "抽样条目" not in a:
            continue
        print(f"| {src} | {fmt(a['抽样条目'])} | {fmt(a['从没探访过（在候选池里）'])} | {fmt(a['不进候选池'])} | {fmt(a['结束时仍在榜（cands.listed）'])} | "
              f"{rfmt(a['时点可用率（结束时刻）'])} | {rfmt(a['累计可用率'])} | {fmt(a['独有条目'])} | "
              f"{rfmt(a['独有条目的时点可用率（结束时刻）'])} | {rfmt(a['独有条目的累计可用率'])} |")
    allagg = res["aggregators"]["all"].get("_all_aggregators")
    if allagg:
        print(f"\n全部聚合器：抽样条目（去重）{fmt(allagg['抽样条目（去重）'])}，从没探访过（在候选池里）{fmt(allagg['从没探访过（在候选池里）'])}，"
              f"不进候选池 {fmt(allagg['不进候选池'])}，独有 {fmt(allagg['独有条目'])}，"
              f"后来也出现在常规列表里 {fmt(allagg['后来也出现在常规列表里'])}；独有条目时点可用率 {rfmt(allagg['独有条目的时点可用率（结束时刻）'])}，"
              f"累计 {rfmt(allagg['独有条目的累计可用率'])}")

    d = res["dense_prefixes"]
    print(f"\n### 候选密集的 /24（候选 > {d['threshold']}）：{d['count']} 个，共 {fmt(d['candidates_total'])} 个候选\n")
    if d["prefixes"]:
        print("| /24 | 候选 | 探访过 | 从没探访过 | 可用过（att 口径） | 最近一次探访可用 | 结束时在榜 |")
        print("| --- | --- | --- | --- | --- | --- | --- |")
        for p in d["prefixes"]:
            print(f"| {p['prefix24']} | {fmt(p['候选'])} | {fmt(p['探访过'])} | {fmt(p['从没探访过'])} | {fmt(p['可用过'])} | "
                  f"{fmt(p['最近一次探访可用'])} | {fmt(p['结束时在榜'])} |")
    else:
        print("（没有）")

    nv = res["never_visited"]
    print(f"\n### 从没探访过的候选：{fmt(nv.get('total'))}" +
          (f"（其中只在试运行期间探访过 {fmt(nv['其中只在试运行期间探访过（cands.visits>0）'])}）" if nv.get("total") else "") + "\n")
    if nv.get("total"):
        key = [k for k in nv if k.startswith("按 /24")][0]
        print("| /24 | 从没探访过 | 该 /24 的候选 | 其中结束时在榜 | 密集 /24 |")
        print("| --- | --- | --- | --- | --- |")
        for p in nv[key]:
            print(f"| {p['prefix24']} | {fmt(p['从没探访过'])} | {fmt(p['该 /24 的候选'])} | {fmt(p['其中结束时在榜'])} | {'是' if p['属于密集 /24'] else '否'} |")
        if nv["其余 /24 合计"]:
            print(f"| 其余 | {fmt(nv['其余 /24 合计'])} | | | |")

    print("\n### 时点序列（常规列表合计；每 %g 小时，从正式起点 + 一个间隔开始）\n" % res["step_hours"])
    print("| 时刻（UTC） | 小时 | 快照已齐 | 在榜 | 排队未探访 | 时点可用率（全部） | 时点可用率（去掉密集 /24） | 聚合器抽样时点可用率 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for p in res["point_series"]:
        r = p["all"]["regular"]
        e = p["excluding_dense"]["regular"]
        a = p["all"]["aggregator_sample"].get("all_samples", {})
        sc = {True: "是", False: "否", None: "—"}[p["snapshots_complete"]]
        print(f"| {p['t_utc']}{'（结束）' if p['is_end'] else ''} | {p['hours_since_start']} | {sc} | {fmt(r['在榜'])} | "
              f"{fmt(r['在榜但尚未探访（候选池里排队）'])} | {rfmt(r['时点可用率'])} | {rfmt(e['时点可用率'])} | "
              f"{rfmt(a['时点可用率']) if a else '—'} |")

    if res.get("crosscheck"):
        c = res["crosscheck"]
        print(f"\n### 与 summary.json 交叉核对：{c['matched']}/{c['total']} 项一致" + (f"，不一致：{', '.join(c['mismatches'])}" if c["mismatches"] else ""))


# ---------------------------------------------------------------- 主流程

def run(db_path, out_dir, summary_path=None, step_hours=STEP_HOURS, dense_threshold=DENSE_THRESHOLD,
        formal_start="auto", top_prefixes=TOP_PREFIXES, markdown=False, write=True):
    db = DB(db_path)
    wl_source = check_whitelist(db)
    for t in ("visit", "att"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表" % t)
    win = observation_window(db, formal_start)
    fs, end = win.pop("_fs"), win.pop("_end")
    first_round, agg_cutoff = win.pop("_first_round"), win.pop("_agg_cutoff")
    if fs is None or end is None:
        raise SystemExit("库里没有任何探访记录，算不出可用率")
    for msg in win["warnings"]:
        print("注意：" + msg, file=sys.stderr)
    have_cands = build_candidate_table(db, fs, dense_threshold, agg_cutoff)

    res = {
        "module": "m_availability", "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol_version": "1.2", "step_hours": step_hours, "whitelist_source": wl_source,
        "db_meta": {k: db.meta(k) for k in ("ingest_version", "first_ts", "last_ts", "state_cands", "state_tz_offsets")},
        "definitions": DEFINITIONS, "window": win,
    }
    res["n"] = counts(db, have_cands)
    res["dense_prefixes"] = dense_prefixes(db, dense_threshold)
    res["never_visited"] = never_visited(db, have_cands, top_prefixes)
    res["funnel"] = {"all": funnel(db, False), "excluding_dense": funnel(db, True)}
    res["auth"] = {"all": auth_block(db, False), "excluding_dense": auth_block(db, True)}
    # 时点序列（最后一个点就是结束时刻；它留下的 lst / lastv 两张表给来源和聚合器用）
    res["point_series"] = point_series(db, fs, end, step_hours, with_sources=True, first_round=first_round)
    res["point_end"] = {k: res["point_series"][-1][k] for k in ("all", "excluding_dense")}
    make_listed_at(db, end, "lst")   # 下面的来源、聚合器、核对都用结束时刻的在榜表和最后一次探访表
    make_last_at(db, end, "lastv")
    res["cumulative"] = {k: {g: res["funnel"][k][g]["累计可用率"] for g in ("regular", "aggregator_sample", "total")}
                         for k in ("all", "excluding_dense")}
    res["by_source"] = {"all": sources(db, False, fs), "excluding_dense": sources(db, True, fs)}
    res["aggregators"] = {"all": aggregators(db, False, agg_cutoff), "excluding_dense": aggregators(db, True, agg_cutoff)}
    res["checks"] = checks(db, have_cands, res["point_end"])
    if summary_path:
        res["crosscheck"] = crosscheck_summary(db, summary_path, have_cands)

    text = json.dumps(res, ensure_ascii=False, indent=1, sort_keys=False)
    assert_clean(text, db)
    if write:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "availability.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("已写出 %s（%d 字节）" % (path, len(text.encode("utf-8"))), file=sys.stderr)
    if markdown:
        print_markdown(res)
    return res


# ---------------------------------------------------------------- 自检：合成库

def _synthetic_db(path):
    """最小合成库，只建本模块用到的列。场景见各条注释；预期值在 selftest() 里断言。"""
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE visit (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, "group" INTEGER, n INTEGER,
        prev TEXT, state TEXT, "full" INTEGER, listed INTEGER, labels TEXT, tried TEXT, ok TEXT, auth INTEGER, aborted INTEGER,
        next_min REAL, ms INTEGER, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT, n_ok INTEGER);
    CREATE INDEX visit_ts ON visit(ts_epoch);
    CREATE TABLE att (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, class TEXT,
        tcp_ok INTEGER, hs_ok INTEGER, hs_code INTEGER, http_code INTEGER, cand_kind TEXT, prefix24 TEXT);
    CREATE INDEX att_ts ON att(ts_epoch);
    CREATE TABLE cands (rid INTEGER PRIMARY KEY, key TEXT UNIQUE, ip TEXT, port INTEGER, prefix24 TEXT, "group" INTEGER, n_srcs INTEGER,
        listed INTEGER, visits INTEGER, state INTEGER, state_name TEXT, ever_ok INTEGER);
    CREATE TABLE list_event (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, src TEXT, label TEXT, cand TEXT, event TEXT, base INTEGER,
        cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
    CREATE TABLE agg_member (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, src TEXT, seq INTEGER, cand TEXT, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
    CREATE TABLE agg_sample (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, src TEXT, "union" INTEGER, exclusive INTEGER, sample INTEGER, seed TEXT);
    CREATE TABLE start (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER, load_err TEXT);
    CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visits INTEGER);
    CREATE TABLE version (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, version TEXT);
    CREATE TABLE stat (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, up_min REAL, visits INTEGER);
    CREATE TABLE stat_pool (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, key TEXT, value INTEGER);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
    """)
    E = parse_iso("2026-11-06T00:00:00Z")  # 正式起点
    H = 3600.0
    P_N = "198.51.100.0/24"   # 普通 /24（TEST-NET-2，只在合成库里）
    P_D = "203.0.113.0/24"    # 密集 /24（TEST-NET-3）
    P_A = "192.0.2.0/24"      # 聚合器条目（TEST-NET-1）

    def key(prefix, i, port=8080):
        return "%s.%d:%d" % (prefix.rsplit(".", 1)[0], i, port)

    X = {i: key(P_N, i) for i in range(1, 10)}
    D = {i: key(P_D, i % 250 + 1, 10000 + i) for i in range(1, 121)}
    M = {i: key(P_A, i) for i in range(1, 6)}

    cands = []  # (key, prefix24, group, listed, visits, state_name, ever_ok)
    cands += [(X[1], P_N, 0, 1, 3, "working", 1), (X[2], P_N, 0, 1, 3, "open", 0), (X[3], P_N, 0, 1, 2, "dead", 0),
              (X[4], P_N, 0, 1, 3, "dead", 1), (X[5], P_N, 0, 0, 2, "working", 1), (X[6], P_N, 0, 1, 0, "new", 0),
              (X[8], P_N, 0, 0, 1, "open", 0), (X[9], P_N, 0, 1, 0, "new", 0)]
    for i in range(1, 121):
        if i <= 5:
            cands.append((D[i], P_D, 0, 1, 2, "working", 1))
        elif i == 6:
            cands.append((D[i], P_D, 0, 1, 1, "dead", 0))
        else:
            cands.append((D[i], P_D, 0, 1, 0, "new", 0))
    # M5 是抽中但被 Pool.Upsert 跳过的条目（知名端口），不在 cands 里
    cands += [(M[1], P_A, 1, 1, 2, "working", 1), (M[2], P_A, 1, 1, 1, "dead", 0), (M[3], P_A, 1, 1, 0, "new", 0),
              (M[4], P_A, 0, 1, 2, "working", 1)]
    for k, p, g, l, v, st, e in cands:
        ip, port = k.rsplit(":", 1)
        con.execute("INSERT INTO cands (key, ip, port, prefix24, \"group\", n_srcs, listed, visits, state, state_name, ever_ok) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)", (k, ip, int(port), p, g, l, l, v, 0, st, e))

    visits = []  # (epoch, cand, group, state, listed, auth, aborted, prefix24)

    def v(t, cand, grp, state, listed=1, auth=0, aborted=None, prefix=P_N):
        visits.append((t, cand, grp, state, listed, auth, aborted, prefix))

    v(E - 1 * H, X[1], None, "dead")            # 试运行：正式起点之前，不作数
    v(E + 0.2 * H, X[1], None, "working"); v(E + 6.5 * H, X[1], None, "working"); v(E + 12.9 * H, X[1], None, "working")
    v(E + 0.2 * H, X[2], None, "open"); v(E + 6.2 * H, X[2], None, "open"); v(E + 12.5 * H, X[2], None, "open")
    v(E + 0.3 * H, X[3], None, "dead"); v(E + 12.0 * H, X[3], None, "dead")
    v(E + 0.5 * H, X[4], None, "working"); v(E + 7.0 * H, X[4], None, "dead"); v(E + 12.0 * H, X[4], None, "dead")
    v(E + 0.4 * H, X[5], None, "working"); v(E + 6.0 * H, X[5], None, "working", listed=0)   # 3 小时时下榜
    v(E + 1.0 * H, X[8], None, "open", auth=1)                                              # 要求认证；重启后不在榜
    v(E + 1.0 * H, X[9], None, "working", aborted=1)                                        # aborted：不作数
    for i in range(1, 6):
        v(E + 0.5 * H, D[i], None, "working", prefix=P_D); v(E + 12.0 * H, D[i], None, "working", prefix=P_D)
    v(E + 0.5 * H, D[6], None, "dead", prefix=P_D)
    v(E + 1.0 * H, M[1], 1, "working", prefix=P_A); v(E + 12.0 * H, M[1], 1, "working", prefix=P_A)
    v(E + 1.0 * H, M[2], 1, "dead", prefix=P_A)
    v(E + 1.0 * H, M[4], None, "working", prefix=P_A); v(E + 12.0 * H, M[4], None, "working", prefix=P_A)
    for i, (t, cand, grp, state, listed, auth, aborted, prefix) in enumerate(visits):
        ip, port = cand.rsplit(":", 1)
        n_ok = 1 if state == "working" else 0
        con.execute("INSERT INTO visit (ts, ts_epoch, visit, cand, \"group\", n, prev, state, listed, auth, aborted, cand_ip, cand_port, prefix24, n_ok) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (iso_minute(t), t, "v%d" % i, cand, grp, 1, "new", state, listed, auth or None, aborted, ip, int(port), prefix, n_ok))

    # att：X2 的主流程 HTML 被改（http_body_mismatch，visit.state 仍是 open），但附加测试的 j 载荷通过——只有 att 口径算它可用过；
    # X3 连不上，X8 要求认证
    atts = []

    def a(t, cand, proto, dst, cls, tcp, hs_ok=None, hs_code=None, http_code=None, prefix=P_N):
        atts.append((t, cand, proto, dst, cls, tcp, hs_ok, hs_code, http_code, prefix))

    a(E - 1 * H, X[1], "connect", "judge_tls", "tcp_refused", 0)          # 试运行：不作数
    a(E + 0.2 * H, X[1], "connect", "judge_tls", "ok", 1, 1, 200, 200)
    a(E + 0.2 * H, X[2], "connect", "judge_tls", "hs_refused", 1, 0, 403)
    a(E + 0.2 * H, X[2], "forward", "judge_http", "http_body_mismatch", 1, None, None, 200)
    a(E + 0.2 * H, X[2], "forward", "judge_http", "ok", 1, None, None, 200)   # 附加测试 j 载荷
    a(E + 0.3 * H, X[3], "forward", "judge_http", "tcp_refused", 0)
    a(E + 0.5 * H, X[4], "socks5", "judge_tls", "ok", 1, 1, None, 200)
    a(E + 0.4 * H, X[5], "forward", "judge_http", "ok", 1, None, None, 200)
    a(E + 1.0 * H, X[8], "connect", "judge_tls", "hs_auth", 1, 0, 407)
    a(E + 1.0 * H, X[9], "connect", "judge_tls", "canceled", None)
    for i in range(1, 6):
        a(E + 0.5 * H, D[i], "connect", "judge_tls", "ok", 1, 1, 200, 200, prefix=P_D)
    a(E + 0.5 * H, D[6], "connect", "judge_tls", "tcp_timeout", 0, prefix=P_D)
    a(E + 1.0 * H, M[1], "socks5", "judge_tls", "ok", 1, 1, None, 200, prefix=P_A)
    a(E + 1.0 * H, M[2], "socks5", "judge_tls", "tcp_refused", 0, prefix=P_A)
    a(E + 1.0 * H, M[4], "connect", "judge_tls", "ok", 1, 1, 200, 200, prefix=P_A)
    a(E + 0.5 * H, "control:public", "direct", "judge_tls", "ok", 1, None, None, 200, prefix=None)
    for t, cand, proto, dst, cls, tcp, hs_ok, hs_code, http_code, prefix in atts:
        kind = "control" if cand.startswith("control:") else "proxy"
        con.execute("INSERT INTO att (ts, ts_epoch, visit, cand, proto, dst, class, tcp_ok, hs_ok, hs_code, http_code, cand_kind, prefix24) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (iso_minute(t), t, "x", cand, proto, dst, cls, tcp, hs_ok, hs_code, http_code, kind, prefix))

    # 列表事件：synthetic/listA 的 http 文件。试运行时（E-2h）有一次只含 X7 的 base 快照（不该算进“曾经在榜”）；
    # base1 在 E；3 小时时删 X5；8.5 小时重启后 base2 不含 X5、X8。X7 只在列表里（不进候选池）。
    SRC = "synthetic/listA"
    X7 = key(P_N, 7, 22)
    base1 = [X[i] for i in range(1, 10) if i != 7] + [X7] + list(D.values()) + [M[4]]
    base2 = [c for c in base1 if c not in (X[5], X[8])]
    events = [(E - 2 * H, X7, "add", 1)] + [(E, c, "add", 1) for c in base1] + [(E + 3 * H, X[5], "del", 0)] + [(E + 8.5 * H, c, "add", 1) for c in base2]
    for t, c, ev, base in events:
        ip, port = c.rsplit(":", 1)
        pfx = P_D if ip.startswith("203.") else (P_A if ip.startswith("192.") else P_N)
        con.execute("INSERT INTO list_event (ts, ts_epoch, src, label, cand, event, base, cand_ip, cand_port, prefix24) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (iso_minute(t), t, SRC, "http", c, ev, base, ip, int(port), pfx))
    # 聚合器抽样：M1..M5，其中 M4 也在常规列表里（不是独有），M5 没进候选池
    AGG = "synthetic/aggZ"
    con.execute("INSERT INTO agg_sample (ts, ts_epoch, src, \"union\", exclusive, sample, seed) VALUES (?,?,?,?,?,?,?)",
                (iso_minute(E + 0.1 * H), E + 0.1 * H, AGG, 1000, 500, 5, "00"))
    for i in range(1, 6):
        ip, port = M[i].rsplit(":", 1)
        con.execute("INSERT INTO agg_member (ts, ts_epoch, src, seq, cand, cand_ip, cand_port, prefix24) VALUES (?,?,?,?,?,?,?,?)",
                    (iso_minute(E + 0.1 * H), E + 0.1 * H, AGG, i, M[i], ip, int(port), P_A))
    # 运行事件：试运行 start（E-2h, resumed=0），stop（E-0.5h），正式 start（E, resumed=0）；
    # E+7.5h 崩溃重启（没有 stop；崩溃前最后一条记录是 X4 的 7.0h 探访）；stop（E+8h）/ start（E+8.5h）正常重启；
    # E+11h 又一次崩溃重启，状态文件损坏（resumed=0 但 load_err 非空）：不是清空状态，正式起点不动；结束 stop（E+13h）
    for t, r, err in ((E - 2 * H, 0, ""), (E, 0, ""), (E + 7.5 * H, 132, ""), (E + 8.5 * H, 132, ""), (E + 11 * H, 0, "gzip: invalid header")):
        con.execute("INSERT INTO start (ts, ts_epoch, resumed_candidates, load_err) VALUES (?,?,?,?)", (iso_minute(t), t, r, err))
        con.execute("INSERT INTO version (ts, ts_epoch, version) VALUES (?,?,?)", (iso_minute(t), t, "0.1.1-test"))
    for t in (E - 0.5 * H, E + 8 * H, E + 13 * H):
        con.execute("INSERT INTO stop (ts, ts_epoch, visits) VALUES (?,?,?)", (iso_minute(t), t, 0))
    con.execute("INSERT INTO stat (ts, ts_epoch, up_min, visits) VALUES (?,?,?,?)", (iso_minute(E + 9 * H), E + 9 * H, 30, 0))  # 8.5h 那次运行的 stat
    for k, val in (("total", 132), ("listed", 128 + 3), ("working", 13), ("open", 2), ("dead", 4), ("new", 114), ("aggregator_sample", 3), ("dropped", 0)):
        con.execute("INSERT INTO stat_pool (ts, ts_epoch, key, value) VALUES (?,?,?,?)", (iso_minute(E + 13 * H), E + 13 * H, k, val))
    con.execute("INSERT INTO meta VALUES ('first_ts', ?)", (iso_minute(E - 2 * H),))
    con.execute("INSERT INTO meta VALUES ('last_ts', ?)", (iso_minute(E + 13 * H),))
    con.execute("INSERT INTO meta VALUES ('state_cands', '132')")
    con.execute("INSERT INTO self_ips VALUES ('198.18.0.1', 'start.judge_ip', 1)")
    con.execute("INSERT INTO self_names VALUES ('judge.invalid', 'start.judge_host', 1)")
    con.commit()
    con.close()


def selftest():
    tmp = tempfile.mkdtemp(prefix="m_availability_selftest_")
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
    expect("正式起点（load_err 非空的 resumed=0 不改变它）", w["formal_start_utc"], "2026-11-06T00:00Z")
    expect("结束", w["end_utc"], "2026-11-06T13:00Z")
    expect("start 条数", len(w["starts"]), 5)
    expect("load_err 标记", [s["load_err_present"] for s in w["starts"]], [False, False, False, False, True])
    expect("中断次数（试运行与正式起点之间的空档不算）", len(w["interruptions"]), 3)
    expect("中断种类", [i["kind"] for i in w["interruptions"]], ["crash", "stop", "crash"])
    expect("崩溃 1 从最后一条记录算起", (w["interruptions"][0]["from_utc"], w["interruptions"][0]["minutes"]), ("2026-11-06T07:00Z", 30.0))
    expect("正常停止从 stop 算起", (w["interruptions"][1]["from_utc"], w["interruptions"][1]["minutes"]), ("2026-11-06T08:00Z", 30.0))
    expect("崩溃 2 从 stat 记录算起", (w["interruptions"][2]["from_utc"], w["interruptions"][2]["minutes"]), ("2026-11-06T09:00Z", 120.0))
    expect("中断分类计数", w["interruptions_by_kind"], {"stop": 1, "crash": 2})
    expect("warnings 条数（load_err、正式起点被挪动、崩溃）", len(w["warnings"]), 3)
    expect("warning：load_err", any("load_err" in m for m in w["warnings"]), True)
    expect("warning：正式起点挪动且超过 1 小时要求确认", any("试运行丢弃" in m and "--formal-start first" in m for m in w["warnings"]), True)
    expect("warning：崩溃次数", any("2 次没有 stop 记录" in m for m in w["warnings"]), True)
    expect("首轮快照完成时刻", w["first_snapshot_round_complete_utc"], "2026-11-06T00:00Z")
    expect("试运行探访", w["trial_run_visits_before_formal_start"], 1)
    n = res["n"]
    expect("候选", n["候选"], 132)                  # X1..X6, X8, X9（8）+ D1..D120 + M1..M4
    expect("探访过", n["探访过"], 15)                # X1..X5, X8（6）+ D1..D6（6）+ M1, M2, M4（3）；X9 只有 aborted 的探访
    expect("从没探访过", n["从没探访过"], 132 - 15)
    expect("结束时在榜 分组", (n["结束时在榜（cands.listed）"]["合计"], n["结束时在榜（cands.listed）"]["regular"],
                        n["结束时在榜（cands.listed）"]["aggregator_sample"]), (130, 127, 3))
    d = res["dense_prefixes"]
    expect("密集 /24 个数", d["count"], 1)
    expect("密集 /24 候选", d["prefixes"][0]["候选"], 120)
    expect("密集 /24 判定用的候选（状态文件 ∪ 尝试记录）", d["prefixes"][0]["判定用的候选（状态文件 ∪ 尝试记录）"], 120)
    expect("密集 /24 探访过", d["prefixes"][0]["探访过"], 6)
    expect("密集 /24 可用过", d["prefixes"][0]["可用过"], 5)
    f = res["funnel"]["all"]["regular"]
    expect("漏斗 regular seen", f["seen"], 13)
    expect("漏斗 regular 连得上", f["连得上"]["num"], 11)    # X3 与 D6 连不上
    expect("漏斗 regular 有协议回应", f["有协议回应"]["num"], 11)
    expect("漏斗 regular 累计可用（att 口径，含 X2）", f["累计可用率"]["num"], 10)
    expect("漏斗 regular visit 口径可用过", f["核对"]["visit 口径的可用过（state='working'）"], 9)
    expect("漏斗 regular 两种口径不一致", f["核对"]["两种可用口径不一致的候选"], 1)
    expect("漏斗 regular 只有 att 口径可用", f["核对"]["其中只有 att 口径可用（主流程 HTML 没通过、附加测试通过）"], 1)
    expect("漏斗 regular 现在可用", f["最近一次探访可用"]["num"], 8)
    expect("漏斗 regular 要求认证", f["要求认证"]["num"], 1)
    fa = res["funnel"]["all"]["aggregator_sample"]
    expect("漏斗 agg seen", fa["seen"], 2)
    expect("漏斗 agg 累计可用", fa["累计可用率"]["num"], 1)
    fe = res["funnel"]["excluding_dense"]["regular"]
    expect("漏斗 去密集 regular seen", fe["seen"], 7)
    expect("漏斗 去密集 regular 累计可用", fe["累计可用率"], {"num": 5, "den": 7, "pct": 71.4})
    pe = res["point_end"]["all"]["regular"]
    expect("结束时点 在榜", pe["在榜"], 128)
    expect("结束时点 不进候选池", pe["在榜但不进候选池（不探测的地址）"], 1)
    expect("结束时点 排队", pe["在榜但尚未探访（候选池里排队）"], 116)
    expect("结束时点 可用率", pe["时点可用率"], {"num": 7, "den": 11, "pct": 63.6})
    pex = res["point_end"]["excluding_dense"]["regular"]
    expect("结束时点 去密集 可用率", pex["时点可用率"], {"num": 2, "den": 5, "pct": 40.0})
    expect("结束时点 来源", pe["by_source"]["synthetic/listA"]["时点可用率"]["num"], 7)
    pa = res["point_end"]["all"]["aggregator_sample"]
    expect("结束时点 聚合器", pa["by_aggregator"]["synthetic/aggZ"]["时点可用率"], {"num": 2, "den": 3, "pct": 66.7})
    expect("结束时点 聚合器独有", pa["by_aggregator"]["synthetic/aggZ"]["独有条目的时点可用率"], {"num": 1, "den": 2, "pct": 50.0})
    expect("结束时点 聚合器 尚未探访 / 不进候选池", (pa["all_samples"]["尚未探访（在候选池里）"], pa["all_samples"]["不进候选池"]), (1, 1))
    series = res["point_series"]
    expect("序列点数（没有 0 小时的点）", [p["hours_since_start"] for p in series], [6.0, 12.0, 13.0])
    expect("序列各点快照已齐", [p["snapshots_complete"] for p in series], [True, True, True])
    p6 = series[0]["all"]["regular"]
    expect("6 小时 在榜", p6["在榜"], 129)
    expect("6 小时 可用率", p6["时点可用率"], {"num": 8, "den": 12, "pct": 66.7})
    s = res["by_source"]["all"]["synthetic/listA"]
    expect("来源 曾经在榜（试运行的快照不算）", s["曾经在榜"], 130)
    expect("来源 累计（曾经在榜，att 口径）", s["累计可用率（曾经在榜）"], {"num": 10, "den": 13, "pct": 76.9})
    expect("来源 累计（结束时在榜，att 口径）", s["累计可用率（结束时在榜）"], {"num": 9, "den": 11, "pct": 81.8})
    ag = res["aggregators"]["all"]
    expect("聚合器 抽样条目", ag["synthetic/aggZ"]["抽样条目"], 5)
    expect("聚合器 独有", ag["synthetic/aggZ"]["独有条目"], 4)
    expect("聚合器 从没探访过（在候选池里）", ag["synthetic/aggZ"]["从没探访过（在候选池里）"], 1)
    expect("聚合器 不进候选池", ag["synthetic/aggZ"]["不进候选池"], 1)
    expect("聚合器 状态文件 group=1", ag["synthetic/aggZ"]["核对：状态文件里 group=1 的抽样条目"], 3)
    expect("全部聚合器 后来也在常规列表", ag["_all_aggregators"]["后来也出现在常规列表里"], 1)
    expect("要求认证", res["auth"]["all"]["要求认证的候选"], 1)
    ck = res["checks"]
    ck_ok = ck["累计可用率的两种口径：att class='ok'（到 judge）vs visit.state='working' 不一致的候选"]
    expect("核对 两种口径不一致", (ck_ok["num"], ck_ok["只有 att 口径可用（主流程 HTML 没通过、附加测试通过）"],
                           ck_ok["只有 visit 口径可用（不应出现：state='working' 必有一条 ok 的 att）"]), (1, 1, 0))
    expect("核对 重建在榜 vs cands.listed", ck["结束时在榜：list_event 重建 vs cands.listed"]["其中 cands.listed=1"], 127)
    nv = res["never_visited"]
    expect("从没探访过 密集", nv["其中属于密集 /24"], 114)
    expect("从没探访过 只在试运行期间探访过", nv["其中只在试运行期间探访过（cands.visits>0）"], 0)
    # 输出文件存在且干净
    with open(os.path.join(tmp, "out", "availability.json"), encoding="utf-8") as fh:
        text = fh.read()
    expect("输出里没有 ip:port", bool(HOSTPORT_RE.search(text)), False)
    expect("输出里没有 judge 主机名", "judge.invalid" in text, False)
    expect("输出里没有 load_err 原文", "gzip" in text, False)
    # 用 --summary 路径跑一遍交叉核对的代码（summary.go 的 working 是 att 口径：含 X2）
    summ = os.path.join(tmp, "summary.json")
    with open(summ, "w", encoding="utf-8") as fh:
        json.dump({"generated": "x", "pool": {"total": 132, "listed": 131}, "funnel": {"regular": {"seen": 14, "working": 10, "tcp": 11}},
                   "by_source": [{"src": "synthetic/listA", "listed": 128, "visited": 11, "working_now": 7, "working": 9}],
                   "aggregator_samples": [{"src": "synthetic/aggZ", "union": 1000, "exclusive": 500, "sample": 5}],
                   "records": {"visit": 31, "att": 22}}, fh)
    res2 = run(db_path, os.path.join(tmp, "out"), summary_path=summ, write=False)
    cc = res2["crosscheck"]["comparisons"]
    expect("交叉核对 pool.total", cc["pool.total (cands)"]["match"], True)
    expect("交叉核对 funnel.seen（整个数据含试运行，X1 的试运行探访不改变 seen；X9 aborted 不算）", cc["funnel.regular.seen"]["computed"], 13)
    expect("交叉核对 funnel.working（att 口径）", cc["funnel.regular.working"]["match"], True)
    expect("交叉核对 funnel.tcp（整个数据：X1 试运行的 tcp_refused 不影响）", cc["funnel.regular.tcp"]["match"], True)
    expect("交叉核对 by_source.listed", cc["by_source.synthetic/listA.listed"]["match"], True)
    expect("交叉核对 by_source.working_now", cc["by_source.synthetic/listA.working_now"]["match"], True)
    expect("交叉核对 by_source.working（att 口径）", cc["by_source.synthetic/listA.working"]["match"], True)
    expect("交叉核对 agg union", cc["aggregator_samples.synthetic/aggZ.union"]["match"], True)
    # --formal-start 覆盖：挪到 E+8.5h 的 start，要有“丢弃探访”的 warning
    res3 = run(db_path, os.path.join(tmp, "out"), formal_start="2026-11-06T08:30:00Z", write=False)
    expect("显式正式起点", res3["window"]["formal_start_utc"], "2026-11-06T08:30Z")
    expect("显式正式起点的 warning 提到丢弃", any("试运行丢弃" in m for m in res3["window"]["warnings"]), True)
    expect("显式正式起点之后的中断只剩 1 次崩溃", [i["kind"] for i in res3["window"]["interruptions"]], ["crash"])
    if failures:
        print("自检失败：\n  " + "\n  ".join(failures), file=sys.stderr)
        print("合成库与输出留在 %s" % tmp, file=sys.stderr)
        return 1
    print("自检通过（%d 项断言）。合成库与输出在 %s" % (n_asserts[0], tmp), file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="可用率（PROTOCOL“指标定义”）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 availability.json")
    ap.add_argument("--summary", help="fieldtest 自带的 summary.json，给了就交叉核对")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--step-hours", type=float, default=STEP_HOURS, help="时点序列的间隔（小时），默认 6")
    ap.add_argument("--dense-threshold", type=int, default=DENSE_THRESHOLD, help="“候选密集的 /24”的阈值，默认 100")
    ap.add_argument("--formal-start", default="auto", help="auto（按 PROTOCOL 规则）/ first（第一条 start）/ 带时区的 ISO 时间")
    ap.add_argument("--top-prefixes", type=int, default=TOP_PREFIXES, help="从没探访过的候选按 /24 列出前几个")
    ap.add_argument("--selftest", action="store_true", help="在临时目录里建合成库并核对预期值")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    run(args.db, args.out, summary_path=args.summary, step_hours=args.step_hours, dense_threshold=args.dense_threshold,
        formal_start=args.formal_start, top_prefixes=args.top_prefixes, markdown=args.markdown)


if __name__ == "__main__":
    main()
