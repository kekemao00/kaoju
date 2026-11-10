#!/usr/bin/env python3
"""寿命：公开代理“能用多久”（PROTOCOL“指标定义”表的“寿命”一行）。

用法：
    python3 m_lifetime.py --db <sqlite> --out <目录> [--markdown] [--since <时间>] [--until <时间>]
                          [--gap-min 10] [--dense-threshold 100] [--no-curve]
    python3 m_lifetime.py --selftest [保留合成库的路径]

输出 <目录>/lifetime.json；加 --markdown 时把主要表格以 Markdown 打印到标准输出。
--since/--until 是 RFC 3339（Z 或带偏移，带偏移的换算成 UTC），正式测量要从状态清空那一刻重算时用 --since。
库由 ingest.py 建好（表结构见 SCHEMA.md），本脚本只读它，不改它；中间结果放在 SQLite 的 TEMP 表里，
visit 按候选顺序流式扫一遍（INDEXED BY visit_cand_ts，查询计划是 SCAN visit USING INDEX visit_cand_ts：按索引顺序回表取列，没有外排序），
内存不随记录数增长（合成 916 万条探访：峰值 167 MB、19 秒，那是改成 INDEXED BY 之前量的）。
没有 state.json.gz 时库里没有 cands 表（ingest.py 不建它），本脚本也能跑：候选池相关的数字退回到
list_event ∪ agg_member ∪ 探访过的候选，并在 basis 里注明。

口径（照 PROTOCOL 第 1.2 版；定义不清的地方取的解释写在各处注释里）：

- 一次探访“可用”= 至少一种协议通过端到端校验，即 visit.n_ok > 0（visit.OK 数组非空，prober.go Visit()
  里 okMask != 0 ⇔ 状态 working）。aborted=1 的探访不作数（prober.go：程序退出时被打断，state 等于 prev）。
- 寿命从第一次可用的探访时刻 t0 起，到“其后连续两次探访都不可用”里第一次不可用的探访时刻为止（事件）。
  单次不可用、紧接着又可用的，不算死亡（下面叫“闪断”，单独计数）。
- 右删失：到观察结束仍没有确认死亡的，在**最后一次可用的探访时刻**删失（那是我们最后一次确知它活着的时刻；
  下榜 24 小时后不再探访的条目、以及最后只观察到一次不可用的条目都这样处理）。
- 左截断：PROTOCOL 的“第一次可用”是我们第一次**观察到**可用，不是代理真正开始可用的时刻，定义本身是观察性的；
  第一次探访就可用的条目（含观察开始时就在榜的）量到的其实是剩余寿命。主结果仍按 PROTOCOL 原文算，但给两个计数：
  n.candidates_ok_at_first_visit（第一次探访就可用）和 n.left_truncated_candidates（用 --since 时，since 之前就有过
  可用探访的候选），后者不为零时另给一组剔除它们的 KM（first_life_km_excluding_left_truncated）并在 warnings 里提示。
- 探访之间的间隔用记录里实际的 ts，不用设定值：可用的 20 分钟复测，连不上的退避（sched.go 的调度），
  启动后约一小时有积压（PROTOCOL“已知局限”）。实际间隔的分布一并输出，作为“分辨率 20 分钟”这句话的证据。
- 两类时段里观察到的“不可用”不算作死亡的证据（从序列里剔除，可用的探访照常算）：
  1. 回环对照失败的时段（PROTOCOL“对照与自检”：对照 control:loopback 失败说明故障在我们自己这边）：
     回环对照有两路（prober.go controlLoop：dst=judge_http 和 judge_tls，每分钟各一次，相隔约 1 毫秒），**按路分别算**：
     从失败那次之前最近一次同一路成功、到之后最近一次同一路成功之间（没有就各取 60 秒），再把两路的时段合并。
     两路混在一起算会让窗口几乎只向失败之前延伸（另一路 1 毫秒后的成功会把右端掐掉），所以不那样算。
  2. 探测器停过的时段：stop 到下一次 start 之间（clean 重启）；没有 stop 的崩溃取 start 之前最后一条心跳到 start；
     以及任何“心跳”（visit、stat、start、stop、对照 att）连续缺席超过 --gap-min 分钟的时段。
     停机时段里本来不会有探访，后一条主要防 stat 中断而探访仍在的异常情况。
     任务原文里的“stat 记录的间断”另算一组只看 stat 的间断（window.stat_only_gaps），只作诊断、不并入停机：
     stat 由 housekeeping 协程每 5 分钟写一条，它断了而探访还在继续时，探访结果本身没有问题。
     另外单独数出“死亡的确认跨过了停机时段”的条目（最后一次可用在停机前、首次不可用在停机后），
     这些条目的寿命被高估了停机那么长。
     重启清单里的间隔是真实的 stop→start 间隔，不受 --since 裁剪；并入“不算死亡”的时段才按观察窗口裁剪。
- 分辨率：寿命的精度受复测间隔限制，可用条目名义上 20 分钟复测一次；真实死亡时刻落在
  最后一次可用与第一次不可用之间，这里按 PROTOCOL 取后者。短于复测间隔的中断看不到。
- Kaplan–Meier：标准乘积极限估计，同一时刻既有事件又有删失时删失仍在风险集里；方差用 Greenwood 公式，
  95% 置信区间用 log(-log) 变换；分位数 t_q = 首个 S(t) ≤ 1-q 的事件时刻；分位数的 95% 区间按 Brookmeyer–Crowley：
  下限 = 置信带下界 lo(t) 首次 ≤ 1-q 的事件时刻，上限 = 上界 hi(t) 首次 ≤ 1-q 的事件时刻（与 R survival 的
  quantile.survfit 一致；lo ≤ S ≤ hi，所以下界先穿过）。S(t) 只在最长随访时间之内有定义：超过它、而最后一次观察
  没有把 S 降到 0（最后是删失）的时点报 null 并注明；没有个体的组所有估计都是 null，不报 100%。
- 分组：常规列表（候选在任何一次探访里 group=0，与 sched.go Upsert 里“聚合器抽样条目后来出现在常规列表就改成 0”一致）、
  聚合器抽样（始终 group=1）、各来源（候选出现在 list_event 的 add 事件或 agg_member 里的来源；一个候选可属多个来源）。
  另按 PROTOCOL“候选密集的地址段”给一组去掉“候选超过 100 个的 /24”的常规列表结果——该节没有把寿命列进去，
  这是本脚本多给的一组，报告里要标明。
- “死而复生”：确认死亡之后又出现可用探访的次数；比例的分母是至少确认死亡过一次的候选。

输出里不出现任何地址、主机名、哈希：维度只用白名单列（ingest.check_output_columns），写出前再扫一遍。
只用 Python 3.10+ 标准库。
"""
import argparse
import bisect
import collections
import itertools
import json
import math
import os
import re
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ingest  # noqa: E402  check_output_columns、parse_ts

MODULE = "m_lifetime"
OUTPUT_NAME = "lifetime.json"
RESOLUTION_MIN = 20          # PROTOCOL：可用条目每 20 分钟复测，寿命的分辨率
HORIZONS_H = (1, 6, 24, 48)  # 任务要求：在这些时点仍存活的比例
QUANTILES = (0.25, 0.5, 0.75, 0.9)
DENSE_PREFIX_THRESHOLD = 100  # PROTOCOL 1.2“候选密集的地址段”：候选超过 100 个的 /24
NEVER_VISITED_PREFIX_MIN = 10  # 从没探访过的条目按 /24 汇总时，只点名至少有这么多条的 /24（更小的 /24 接近单个地址，只给合计）
GAP_MIN_DEFAULT = 10          # 心跳缺席超过 10 分钟视为停机（stat 每 5 分钟一条，对照每分钟一次）
LOOPBACK_PERIOD_S = 60        # 回环对照每分钟一次（prober.go controlLoop）
CURVE_MAX_H = 72
Z95 = 1.959963984540054

DEFINITIONS = {
    "可用": "一次探访里至少一种协议通过端到端校验（visit.n_ok > 0；aborted=1 的探访不作数）。PROTOCOL“指标定义”。",
    "寿命": "从第一次可用的探访时刻起，到其后连续两次探访都不可用里第一次不可用的探访时刻为止；单次不可用后又可用的不算死亡。"
          "PROTOCOL“指标定义”表“寿命”行。",
    "右删失": "观察结束前没有确认死亡的，在最后一次可用的探访时刻删失（含下榜 24 小时后不再探访的、以及最后只见到一次不可用的）。"
            "PROTOCOL“指标定义”表“寿命”行。",
    "不算死亡的时段": "回环对照失败的时段（judge_http、judge_tls 两路分别取失败前后最近一次同一路成功之间，再合并）和探测器停过的时段"
                 "（stop 到 start、或心跳缺席超过 gap_min 分钟）里观察到的不可用，不作为死亡证据，从序列里剔除。"
                 "PROTOCOL“对照与自检”、“正式测量的起止”。",
    "左截断": "“第一次可用”是第一次观察到可用；第一次探访就可用的候选量到的是剩余寿命（candidates_ok_at_first_visit），"
            "用 --since 时 since 之前就可用过的候选也算在内（left_truncated_candidates，另给剔除它们的一组 KM）。主结果按 PROTOCOL 原文。",
    "只看 stat 的间断": "stat 记录相邻两条相隔超过 gap_min 分钟；只作仪器诊断，不并入停机（探访还在继续时探访结果本身没有问题）。",
    "从没探访过的条目": "PROTOCOL 1.2“候选密集的地址段”：不进任何比例的分母，单独报告条数并按 /24 汇总。"
                  "有状态文件时按 cands.visits=0 算，没有时用 list_event ∪ agg_member 减去 visit 里出现过的候选。",
    "分辨率": "死亡时刻只知道落在最后一次可用与第一次不可用之间，取后者；可用条目名义上每 20 分钟复测，实际间隔见 retest_interval。"
            "PROTOCOL“频率与限速”、“已知局限”。",
    "Kaplan–Meier": "乘积极限估计 S(t)=∏(1-d_i/n_i)，Greenwood 方差，log(-log) 变换的 95% 置信区间；"
                   "分位数 t_q 是首个 S(t)≤1-q 的事件时刻；分位数的 95% 区间 = [下界 lo(t) 首次≤1-q 的时刻, 上界 hi(t) 首次≤1-q 的时刻]"
                   "（Brookmeyer–Crowley，与 R survival quantile.survfit 一致）。",
    "在 t 小时仍存活的比例": "S(t)，右连续；同时给 t 之前的事件数、删失数和 t 时刻之后的风险集大小。"
                      "t 超过最长随访时间且最后一次观察没把 S 降到 0 时没有定义，报 null；没有个体时报 null。",
    "常规列表 / 聚合器抽样": "候选在任何一次探访里 group=0 的算常规列表，始终 group=1 的算聚合器抽样（sched.go Upsert 的归并规则）。"
                        "PROTOCOL“测量对象”。",
    "各来源": "候选出现在 list_event 的 add 事件（含 base=1 快照）或 agg_member 里的来源，即“曾被该来源列出过”；一个候选可同时属于"
            "多个来源，各来源的子集互相不排斥。这与 summary.json by_source 的口径（数据结束时仍在榜的集合）不同，"
            "后者另算在 summary_style_current_set 里作对照。",
    "去掉候选密集的 /24": "PROTOCOL 1.2“候选密集的地址段”：去掉候选超过 100 个的 /24 之后的常规列表结果。"
                      "该节未把寿命列入，这一组是本脚本额外给出的，报告里要标明。",
    "死而复生": "确认死亡之后又出现可用探访的次数；比例的分母是至少确认死亡过一次的候选。",
    "闪断": "可用之后单次不可用、紧接着的下一次探访又可用；不算死亡，单独计数。",
    "复测间隔": "同一候选相邻两次（未被打断的）探访之间的实际时间差，按上一次探访的结果分：可用之后、首次不可用之后。"
            "1 秒桶（取整秒）直方图的分位数，报分钟保留两位，误差小于 1 秒。",
    "观察窗口": "从第一条 start（或 --since）到最后一条 visit/stop（或 --until）。PROTOCOL“正式测量的起止”。",
}


# ---------------------------------------------------------------- 小工具

def ts_text(epoch):
    """浮点秒 → 2026-11-05T17:30:04.795Z（与记录里的 ts 同格式）。"""
    if epoch is None:
        return None
    ms = int(round(epoch * 1000))
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms // 1000)) + ".%03dZ" % (ms % 1000)


def pct(num, den):
    return None if not den else round(100.0 * num / den, 1)


def hours(sec):
    return None if sec is None else round(sec / 3600.0, 2)


def parse_cli_time(s):
    """--since/--until：RFC 3339（Z 或带偏移，带偏移的换算成 UTC）。"""
    utc, epoch, _ = ingest.parse_ts(s)
    if epoch is None:
        raise SystemExit("时间格式不对：%r（要 RFC 3339，如 2026-11-06T08:06:00Z 或 2026-11-06T16:06:00+08:00）" % s)
    return epoch


def merge_windows(ws):
    """合并重叠的 [a, b] 区间，返回按 a 排序的列表。"""
    out = []
    for a, b in sorted(ws):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


class Windows:
    """一组互不重叠、已排序的时段，支持“某个区间是否与任一时段相交”。"""

    def __init__(self, ws):
        self.ws = merge_windows(ws)
        self.starts = [a for a, _ in self.ws]

    def overlaps(self, x0, x1):
        i = bisect.bisect_right(self.starts, x1) - 1
        return i >= 0 and self.ws[i][1] >= x0

    def total_seconds(self):
        return sum(b - a for a, b in self.ws)

    def __len__(self):
        return len(self.ws)


def hist_quantiles(hist, qs):
    """hist: {桶值: 计数}；返回 {q: 桶值}（桶值是该桶的代表值）。"""
    total = sum(hist.values())
    if not total:
        return {str(q): None for q in qs}, 0
    out = {}
    acc = 0
    items = sorted(hist.items())
    qi = 0
    qs = sorted(qs)
    for v, c in items:
        acc += c
        while qi < len(qs) and acc >= qs[qi] * total:
            out[str(qs[qi])] = v
            qi += 1
        if qi >= len(qs):
            break
    return out, total


# ---------------------------------------------------------------- 观察窗口、停机、对照

def run_events(conn, since, until):
    """start/stop 事件（整个库的，供报告重启；窗口由 since/until 决定）。"""
    ev = []
    for k, col in (("start", "resumed_candidates"), ("stop", "visits")):
        for ts, ep, v in conn.execute("SELECT ts, ts_epoch, %s FROM %s ORDER BY ts_epoch" % (col, k)):
            ev.append((ep, k, v))
    ev.sort()
    return ev


CONTROL_CANDS = "('control:loopback', 'control:public', 'control:observer')"  # prober.go controlLoop 的三个对照 cand


def table_exists(conn, name):
    """库里有没有这张表。没有 state.json.gz 时 ingest.py 不建 cands/cand_src（m_availability、m_integrity 同样写法）。"""
    return conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()[0] > 0


def last_heartbeat_before(conn, t):
    """t 之前最后一条探测器侧记录的时刻（stop、stat、visit、对照 att）。查的是整个库，不受观察窗口限制。
    对照 att 按 cand 取（EXPLAIN：SEARCH att USING COVERING INDEX att_cand_ts）；按 proto='direct' 取会走 att_ts 再逐行回表。"""
    best = None
    for sql in ("SELECT MAX(ts_epoch) FROM stop WHERE ts_epoch < ?",
                "SELECT MAX(ts_epoch) FROM stat WHERE ts_epoch < ?",
                "SELECT MAX(ts_epoch) FROM visit WHERE ts_epoch < ?",
                "SELECT MAX(ts_epoch) FROM att WHERE cand IN " + CONTROL_CANDS + " AND ts_epoch < ?"):
        v = conn.execute(sql, (t,)).fetchone()[0]
        if v is not None and (best is None or v > best):
            best = v
    return best


def heartbeat_minutes(conn, since, until):
    """探测器“活着”的分钟桶：visit、stat、start、stop、对照 att。
    对照 att 按 cand IN (...) 取，EXPLAIN 是 SEARCH att USING COVERING INDEX att_cand_ts（三个 cand 各一段范围）；
    之前按 proto='direct' 取时计划是 SEARCH att USING INDEX att_ts + 逐行回表，一千多万条 att 等于整表回表一遍。"""
    mins = set()
    for sql in ("SELECT DISTINCT CAST(ts_epoch / 60 AS INTEGER) FROM visit WHERE ts_epoch BETWEEN ? AND ?",
                "SELECT DISTINCT CAST(ts_epoch / 60 AS INTEGER) FROM stat WHERE ts_epoch BETWEEN ? AND ?",
                "SELECT DISTINCT CAST(ts_epoch / 60 AS INTEGER) FROM start WHERE ts_epoch BETWEEN ? AND ?",
                "SELECT DISTINCT CAST(ts_epoch / 60 AS INTEGER) FROM stop WHERE ts_epoch BETWEEN ? AND ?",
                "SELECT DISTINCT CAST(ts_epoch / 60 AS INTEGER) FROM att WHERE cand IN " + CONTROL_CANDS + " AND ts_epoch BETWEEN ? AND ?"):
        mins.update(m for (m,) in conn.execute(sql, (since, until)))
    return sorted(mins)


def downtime_windows(conn, events, since, until, gap_min):
    """停机时段：(1) clean 重启：上一条 stop → start；(2) 没有 stop 的崩溃：start 之前最后一条心跳 → start；
    (3) 心跳分钟桶连续缺席超过 gap_min 分钟。返回 (Windows, 重启清单, 心跳间断清单, 只看 stat 的间断清单)。

    重启清单给真实的间隔（不按 --since 裁剪）；并入 Windows 的时段按 [since, until] 裁剪，只影响“不算死亡”的判定。
    last_heartbeat_before() 查整个库，所以 --since 恰好落在某条 start 上时，不会把上一段正常运行算成停机。
    起点在 since 之前的 start 不列入重启清单（那属于试运行，PROTOCOL“正式测量的起止”），但 window.starts 里仍全部列出。"""
    ws = []
    restarts = []
    starts = [e for e in events if e[1] == "start"]
    for i, (ep, _, resumed) in enumerate(starts):
        if i == 0 or ep < since or ep > until:
            continue
        # 上一条 start 与这次 start 之间有没有 stop：有就是 clean 重启，窗口从 stop 起；没有就是崩溃，从最后一条心跳起
        stops_between = [e for e in events if e[1] == "stop" and starts[i - 1][0] < e[0] < ep]
        clean = bool(stops_between)
        if clean:
            a = stops_between[-1][0]
        else:
            a = last_heartbeat_before(conn, ep)
            if a is None or a < starts[i - 1][0]:
                a = starts[i - 1][0]
        lo, hi = max(a, since), min(ep, until)
        if lo < hi:
            ws.append((lo, hi))
        restarts.append({"stop_utc": ts_text(a), "start_utc": ts_text(ep), "gap_s": round(ep - a, 3),
                         "clean_stop": clean, "resumed_candidates": resumed,
                         "state_cleared": bool(resumed == 0),
                         # --since 正好指在这条 start 上：窗口从这里开始，停机在窗口之外
                         "at_since": bool(ep <= since)})
    gaps = []
    mins = heartbeat_minutes(conn, since, until)
    for m0, m1 in zip(mins, mins[1:]):
        if m1 - m0 > gap_min:
            a, b = (m0 + 1) * 60.0, m1 * 60.0
            ws.append((a, b))
            gaps.append({"from_utc": ts_text(a), "to_utc": ts_text(b), "gap_s": round(b - a, 3)})
    # 只看 stat 的间断：诊断用，不并入停机（stat 每 5 分钟一条，72 小时不到一千条，读进内存没问题）
    stat_gaps = []
    stat_ts = [t for (t,) in conn.execute("SELECT ts_epoch FROM stat WHERE ts_epoch BETWEEN ? AND ? ORDER BY ts_epoch", (since, until))]
    start_ts = [e[0] for e in starts]
    for t0, t1 in zip(stat_ts, stat_ts[1:]):
        if t1 - t0 > gap_min * 60:
            j = bisect.bisect_right(start_ts, t0)
            stat_gaps.append({"from_utc": ts_text(t0), "to_utc": ts_text(t1), "gap_s": round(t1 - t0, 3),
                              "across_restart": bool(j < len(start_ts) and start_ts[j] <= t1)})
    return Windows(ws), restarts, gaps, stat_gaps


def loopback_windows(conn, since, until):
    """回环对照失败的时段。对照 att：cand='control:loopback'，proto='direct'，dst 是 judge_http 或 judge_tls
    （prober.go controlLoop：每分钟两路各一次，相隔约 1 毫秒）；canceled 的跳过（SCHEMA“坑”4）。
    两路分别算：失败那次之前最近一次同一路成功、到之后最近一次同一路成功之间（没有就各取 60 秒），再合并两路的时段。
    混在一起算，另一路 1 毫秒后的成功会把窗口的右端掐掉，失败之后到下一次同路成功之间的代理失败就会被算成死亡证据。
    每分钟两条、72 小时不到一万条，读进内存没问题。返回 (Windows, 总次数, 失败次数, 按 dst 的明细)。"""
    rows = conn.execute(
        "SELECT ts_epoch, COALESCE(ms, 0), class, COALESCE(dst, '') FROM att WHERE cand = 'control:loopback' AND proto = 'direct' "
        "AND class NOT LIKE '%canceled%' AND ts_epoch BETWEEN ? AND ? ORDER BY ts_epoch", (since, until)).fetchall()
    by_dst = collections.defaultdict(list)
    for ep, ms, cls, dst in rows:
        by_dst[dst].append((ep, ms, cls))
    ws = []
    n_fail = 0
    detail = collections.OrderedDict()
    for dst in sorted(by_dst):
        rs = by_dst[dst]
        oks = [ep for ep, _, cls in rs if cls == "ok"]
        d_ws = []
        for ep, ms, cls in rs:
            if cls == "ok":
                continue
            i = bisect.bisect_left(oks, ep)
            prev_ok = oks[i - 1] if i > 0 else ep - LOOPBACK_PERIOD_S
            next_ok = oks[i] if i < len(oks) else ep + ms / 1000.0 + LOOPBACK_PERIOD_S
            d_ws.append((prev_ok, next_ok))
        n_fail += len(d_ws)
        ws.extend(d_ws)
        detail[dst or "(无 dst)"] = {"attempts": len(rs), "failed": len(d_ws),
                                    "failure_windows_total_s": round(Windows(d_ws).total_seconds(), 3)}
    return Windows(ws), len(rows), n_fail, detail


# ---------------------------------------------------------------- 逐候选扫描

# 先删再建：同一个连接上可以多次 build()（自检里用不同的 --since 跑几遍）
TEMP_SCHEMA = """
DROP TABLE IF EXISTS lt_cand; DROP TABLE IF EXISTS lt_life; DROP TABLE IF EXISTS lt_resurrect;
DROP TABLE IF EXISTS lt_src; DROP TABLE IF EXISTS lt_dense; DROP TABLE IF EXISTS lt_lefttrunc; DROP TABLE IF EXISTS lt_src_cur;
CREATE TEMP TABLE lt_cand (cand TEXT PRIMARY KEY, grp INTEGER, prefix24 TEXT, n_visits INTEGER, ever_ok INTEGER,
    first_ok REAL, last_ok REAL, last_visit REAL, n_deaths INTEGER, n_resurrect INTEGER, n_blips INTEGER,
    n_fail_skipped_loopback INTEGER, n_fail_skipped_down INTEGER, pending_at_end INTEGER,
    first_visit REAL, ok_at_first_visit INTEGER);
CREATE TEMP TABLE lt_life (cand TEXT, grp INTEGER, prefix24 TEXT, life_no INTEGER, t0 REAL, t_end REAL, dur_s REAL,
    event INTEGER, last_ok REAL, n_visits INTEGER, straddles_down INTEGER);
CREATE TEMP TABLE lt_resurrect (cand TEXT, grp INTEGER, gap_s REAL);
CREATE TEMP TABLE lt_src (cand TEXT, src TEXT, kind TEXT);
CREATE TEMP TABLE lt_dense (prefix24 TEXT PRIMARY KEY, cands INTEGER, visited INTEGER, subjects INTEGER);
CREATE TEMP TABLE lt_lefttrunc (cand TEXT PRIMARY KEY);
CREATE TEMP TABLE lt_src_cur (src TEXT, cand TEXT);
"""


def scan_candidates(conn, bad_lo, bad_down, since, until, stats):
    """把 visit 按候选流式扫一遍，逐候选套用寿命定义，结果写进 TEMP 表。内存只保留一个候选的探访。

    stats：累计的计数和直方图（dict，原地更新）。
    """
    conn.executescript(TEMP_SCHEMA)
    cur = conn.cursor()
    cur.arraysize = 5000
    # 强制走 visit_cand_ts 索引顺序扫描（EXPLAIN：SCAN visit USING INDEX visit_cand_ts，按索引顺序回表取列，没有外排序；
    # 不加 INDEXED BY 时优化器会先按 visit_ts 取时间范围再整体 ORDER BY，多一次全量外排序）。
    # aborted 的探访不作数（prober.go：state 等于 prev）
    cur.execute(
        'SELECT cand, ts_epoch, COALESCE(ms, 0), COALESCE(n_ok, 0) > 0, COALESCE("group", 0), prefix24, state, aborted '
        "FROM visit INDEXED BY visit_cand_ts WHERE ts_epoch BETWEEN ? AND ? ORDER BY cand, ts_epoch", (since, until))
    cand_rows, life_rows, res_rows = [], [], []
    hist = stats["hist"]

    def flush():
        if cand_rows:
            conn.executemany("INSERT INTO lt_cand VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", cand_rows)
            cand_rows.clear()
        if life_rows:
            conn.executemany("INSERT INTO lt_life VALUES (?,?,?,?,?,?,?,?,?,?,?)", life_rows)
            life_rows.clear()
        if res_rows:
            conn.executemany("INSERT INTO lt_resurrect VALUES (?,?,?)", res_rows)
            res_rows.clear()

    for cand, rows in itertools.groupby(cur, key=lambda r: r[0]):
        grp = 1
        prefix24 = None
        n_visits = 0
        first_ok = last_ok = last_visit = first_visit = None
        ok_at_first_visit = 0
        alive = False
        life_start = None
        life_visits = 0
        pending = None            # 单次不可用的时刻（等第二次确认）
        prev_ts = None
        prev_ok = None
        deaths = []
        n_resurrect = n_blips = 0
        skipped_lo = skipped_down = 0
        lives = []
        for _, ts, ms, ok, g, pfx, state, aborted in rows:
            stats["visits_total"] += 1
            if aborted:
                stats["visits_aborted"] += 1
                continue
            n_visits += 1
            if first_visit is None:
                first_visit, ok_at_first_visit = ts, (1 if ok else 0)
            if g == 0:
                grp = 0
            if pfx:
                prefix24 = pfx
            if (state == "working") != bool(ok):
                stats["visits_ok_state_mismatch"] += 1
            # 复测间隔直方图（1 秒桶，取整秒；键数上限是最长间隔的秒数，不随记录数增长），按上一次探访的结果分。
            # 之前用半分钟桶并取桶下沿，分位数系统性偏低最多 0.5 分钟，与 sched.go 的 ±10% 核对不上。
            if prev_ts is not None:
                key = ("ok" if prev_ok else ("pending" if pending is not None and not prev_ok else None), "agg" if g else "reg")
                if key[0] is not None:
                    hist[key][int(ts - prev_ts)] += 1
            if ok:
                if first_ok is None:
                    first_ok = ts
                if not alive:
                    if deaths:
                        n_resurrect += 1
                        res_rows.append((cand, grp, ts - deaths[-1]))
                    alive, life_start, life_visits = True, ts, 0
                elif pending is not None:
                    n_blips += 1
                pending = None
                last_ok = ts
                life_visits += 1
            elif alive:
                # 不可用。先看它是否落在“不算死亡”的时段里：探访区间 [ts, ts+ms] 与时段相交就剔除
                t1 = ts + ms / 1000.0
                if bad_lo.overlaps(ts, t1):
                    skipped_lo += 1
                elif bad_down.overlaps(ts, t1):
                    skipped_down += 1
                else:
                    life_visits += 1
                    if pending is None:
                        pending = ts
                    else:
                        # 连续两次不可用：死亡时刻是第一次不可用的时刻
                        straddles = 1 if bad_down.overlaps(last_ok, pending) else 0
                        lives.append((life_start, pending, 1, last_ok, life_visits, straddles))
                        deaths.append(pending)
                        alive, pending = False, None
            prev_ts, prev_ok = ts, ok
            last_visit = ts
        if alive:
            # 观察结束仍未确认死亡：在最后一次可用的时刻右删失
            lives.append((life_start, last_ok, 0, last_ok, life_visits, 0))
        for i, (t0, t_end, event, lok, nv, straddles) in enumerate(lives, 1):
            life_rows.append((cand, grp, prefix24, i, t0, t_end, t_end - t0, event, lok, nv, straddles))
        cand_rows.append((cand, grp, prefix24, n_visits, 1 if first_ok is not None else 0, first_ok, last_ok, last_visit,
                          len(deaths), n_resurrect, n_blips, skipped_lo, skipped_down,
                          1 if (alive and pending is not None) else 0, first_visit, ok_at_first_visit))
        if len(cand_rows) >= 2000:
            flush()
    flush()
    conn.execute("CREATE INDEX lt_life_grp ON lt_life(grp, life_no, dur_s)")
    conn.execute("CREATE INDEX lt_life_cand ON lt_life(cand)")
    conn.execute("CREATE INDEX lt_src_cand ON lt_src(cand)")


def load_sources(conn):
    """候选 → 来源。来源名是权威的快照来源名（SCHEMA“坑”18）。

    lt_src：“曾被该来源列出过”——list_event 的 add 事件（含 base=1 快照）∪ agg_member；一个候选可属多个来源。
    lt_src_cur：summary.go finish() 里 by_source 的口径——数据结束时该来源各标签“当前在榜”集合的并集：
    base=1 的快照把该 (来源, 标签) 的集合清空重建（summary.go：set == nil || r.Base），之后按 add/del 回放，
    同一候选取 rid 最大的那个事件（ingest 按文件顺序发 rid，同一快照内 add 在 del 之前）。只用来和 summary.json 并排对照。"""
    conn.execute("INSERT INTO lt_src SELECT DISTINCT cand, src, 'regular' FROM list_event WHERE event = 'add'")
    conn.execute("INSERT INTO lt_src SELECT DISTINCT cand, src, 'aggregator_sample' FROM agg_member")
    conn.execute("""
        INSERT INTO lt_src_cur
        WITH lb AS (SELECT src, label, MAX(ts_epoch) AS tb FROM list_event WHERE base = 1 GROUP BY src, label),
             ev AS (SELECT e.rid, e.src, e.label, e.cand, e.event FROM list_event e
                    LEFT JOIN lb ON lb.src = e.src AND lb.label = e.label
                    WHERE lb.tb IS NULL OR e.ts_epoch >= lb.tb),
             last AS (SELECT src, label, cand, MAX(rid) AS rid FROM ev GROUP BY src, label, cand)
        SELECT DISTINCT e.src, e.cand FROM ev e JOIN last l ON l.rid = e.rid WHERE e.event = 'add'""")


def load_dense_prefixes(conn, threshold):
    """候选超过 threshold 个的 /24。候选数按状态文件 cands ∪ att 里的代理候选数（决策 D14）；库里没有 cands 表（没送 state.json.gz 时 ingest.py 不建它）
    或表为空时，退回到 list_event ∪ agg_member ∪ 窗口内探访过的候选（lt_cand）的并集，并在 basis 里注明。
    返回 (basis, 有没有可用的 cands 表)。"""
    has_cands = table_exists(conn, "cands") and conn.execute("SELECT COUNT(*) FROM cands").fetchone()[0] > 0
    if has_cands:
        # 状态文件 ∪ 尝试记录里的代理候选（与 m_availability、m_integrity、report_tables 的点名规则同一口径，决策 D14）
        att_cols = {r[1] for r in conn.execute("PRAGMA table_info(att)")} if table_exists(conn, "att") else set()
        att_part = (" UNION SELECT DISTINCT cand, prefix24 FROM att WHERE cand_kind = 'proxy'"
                    if {"cand", "prefix24", "cand_kind"} <= att_cols else "")
        src = ("SELECT prefix24, COUNT(*) FROM (SELECT key AS cand, prefix24 FROM cands%s) "
               "WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING COUNT(*) > ?" % att_part)
        basis = "状态文件 cands ∪ 尝试记录里的代理候选（att，含试运行）：下榜超过 24 小时的候选会从状态文件里丢掉，只数状态文件会漏掉它们"
    else:
        src = ("SELECT prefix24, COUNT(DISTINCT cand) FROM (SELECT cand, prefix24 FROM list_event "
               "UNION SELECT cand, prefix24 FROM agg_member UNION SELECT cand, prefix24 FROM lt_cand) "
               "WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING COUNT(DISTINCT cand) > ?")
        basis = "list_event ∪ agg_member ∪ 窗口内探访过的候选（没有状态文件：库里没有 cands 表或表为空）"
    rows = conn.execute(src, (threshold,)).fetchall()
    for pfx, n in rows:
        visited = conn.execute("SELECT COUNT(*) FROM lt_cand WHERE prefix24 = ?", (pfx,)).fetchone()[0]
        subjects = conn.execute("SELECT COUNT(*) FROM lt_cand WHERE prefix24 = ? AND ever_ok = 1", (pfx,)).fetchone()[0]
        conn.execute("INSERT INTO lt_dense VALUES (?,?,?,?)", (pfx, n, visited, subjects))
    return basis, has_cands


def pool_counts(conn, has_cands):
    """候选池总数与“从没探访过的条目”（PROTOCOL 1.2“候选密集的地址段”：不进任何比例的分母，单独报告条数并按 /24 汇总）。
    有 cands 时以状态文件的 visits 字段为准（整个运行期间一次都没探访过）；
    没有时用 list_event ∪ agg_member 出现过的候选减去整个库的 visit 里出现过的候选（DISTINCT cand 走 visit_cand_ts 覆盖索引，
    内存按候选数而不是记录数算）。"""
    if has_cands:
        total = conn.execute("SELECT COUNT(*) FROM cands").fetchone()[0]
        never_sql = "SELECT prefix24 FROM cands WHERE COALESCE(visits, 0) = 0"
        basis = "cands.visits = 0（state.json.gz）"
    else:
        pool = ("SELECT cand, MAX(prefix24) AS prefix24 FROM (SELECT cand, prefix24 FROM list_event "
                "UNION ALL SELECT cand, prefix24 FROM agg_member) GROUP BY cand")
        never_sql = "SELECT prefix24 FROM (" + pool + ") WHERE cand NOT IN (SELECT DISTINCT cand FROM visit)"
        total = conn.execute("SELECT COUNT(*) FROM (" + pool + ")").fetchone()[0]
        basis = "list_event ∪ agg_member 里出现过、但整个库的 visit 里没出现过的候选（没有状态文件）"
    never = conn.execute("SELECT COUNT(*) FROM (" + never_sql + ")").fetchone()[0]
    # 按 /24 汇总：只点名至少 NEVER_VISITED_PREFIX_MIN 条的 /24（前 10 个），其余只给合计，免得一个 /24 一条等于指出单个地址
    by_pfx = conn.execute("SELECT prefix24, COUNT(*) AS n FROM (" + never_sql + ") WHERE prefix24 IS NOT NULL "
                          "GROUP BY prefix24 HAVING n >= ? ORDER BY n DESC, prefix24 LIMIT 10", (NEVER_VISITED_PREFIX_MIN,)).fetchall()
    rest_pfx, rest_n = conn.execute("SELECT COUNT(*), COALESCE(SUM(n), 0) FROM (SELECT prefix24, COUNT(*) AS n FROM (" + never_sql + ") "
                                    "GROUP BY prefix24 HAVING n < ?)", (NEVER_VISITED_PREFIX_MIN,)).fetchone()
    return {"candidates_in_pool": total, "candidates_never_visited": never, "never_visited_pct_of_pool": pct(never, total),
            "never_visited_by_prefix24": [{"prefix24": p, "n": n} for p, n in by_pfx],
            "never_visited_other_prefixes": {"prefixes": rest_pfx, "n": rest_n,
                                             "note": "不到 %d 条的 /24 只给合计" % NEVER_VISITED_PREFIX_MIN},
            "basis": basis}


def load_left_truncated(conn, since):
    """--since 之前就有过可用探访（非 aborted、n_ok>0）、而且窗口内也曾可用的候选：它们在窗口里的“第一次可用”其实是剩余寿命的起点。
    逐候选用 visit_cand_ts 索引探一次，不扫 since 之前的全部探访。没有 --since 时为 0。"""
    if since is None:
        return 0
    conn.execute("INSERT INTO lt_lefttrunc SELECT c.cand FROM lt_cand c WHERE c.ever_ok = 1 AND EXISTS "
                 "(SELECT 1 FROM visit v WHERE v.cand = c.cand AND v.ts_epoch < ? AND COALESCE(v.n_ok, 0) > 0 "
                 "AND COALESCE(v.aborted, 0) = 0)", (since,))
    return conn.execute("SELECT COUNT(*) FROM lt_lefttrunc").fetchone()[0]


# ---------------------------------------------------------------- Kaplan–Meier

def kaplan_meier(rows, n_subjects, points_s, quantiles=QUANTILES, with_curve=True):
    """rows：按 dur_s 升序的 (dur_s, 事件数, 该时刻的总数) ；points_s：要报告 S(t) 的时刻（升序，秒）。

    同一时刻既有事件又有删失：删失仍在风险集里（标准约定）。返回的字典里百分比保留一位小数，并带分子分母。
    S(t) 只在 t ≤ 最长随访时间上有定义：超过它、而最后一次观察没有把 S 降到 0（最后是删失）的时点，survival_pct 给 null
    并注明“超过最长随访时间”；没有个体时一切估计都是 null，不报 100%。
    分位数的 95% 区间按 Brookmeyer–Crowley：{t : lo(t) ≤ 1-q ≤ hi(t)}，下限 = 下界 lo(t) 首次 ≤ 1-q 的事件时刻，
    上限 = 上界 hi(t) 首次 ≤ 1-q 的事件时刻（lo ≤ S ≤ hi，下界先穿过；与 R survival 的 quantile.survfit 一致）。
    S 降到 0 之后 log(-log) 区间没有定义，那之后的分位数区间端点保持 null（R 也给 NA）。
    """
    S, var_sum = 1.0, 0.0
    processed = 0
    events = censored = 0
    pts = sorted(set(points_s))
    pi = 0
    at_points = {}
    q_time = {q: None for q in quantiles}
    q_lo = {q: None for q in quantiles}   # 置信带下界 lo 首次 ≤ 1-q 的时刻 → 分位数区间的下限
    q_hi = {q: None for q in quantiles}   # 置信带上界 hi 首次 ≤ 1-q 的时刻 → 分位数区间的上限
    max_dur = None                        # 最长随访时间（最后一行的 dur）；没有个体时是 None

    def ci(S, var_sum):
        # S 在 0 或 1 上、或方差无穷时 log(-log) 区间没有定义，给 null（与 R survival 的 NA 一致）
        if S <= 0.0 or S >= 1.0 or var_sum <= 0.0 or var_sum == float("inf"):
            return None, None
        se_theta = math.sqrt(var_sum) / abs(math.log(S))
        lo = S ** math.exp(Z95 * se_theta)
        hi = S ** math.exp(-Z95 * se_theta)
        return lo, hi

    def record(p, beyond=False):
        if n_subjects == 0:
            at_points[p] = {"survival_pct": None, "ci95_pct": [None, None], "events_by_then": 0, "censored_by_then": 0,
                            "at_risk_after": 0, "note": "没有个体"}
            return
        if beyond and S > 0.0:
            # 最后一次观察是删失（或同一时刻有事件但 S 还没到 0）：KM 在那之后没有定义
            at_points[p] = {"survival_pct": None, "ci95_pct": [None, None], "events_by_then": events, "censored_by_then": censored,
                            "at_risk_after": 0, "note": "超过最长随访时间（%s 小时），Kaplan–Meier 在最后一次观察之后没有定义" % hours(max_dur)}
            return
        lo, hi = ci(S, var_sum)
        at_points[p] = {"survival_pct": round(100 * S, 1),
                        "ci95_pct": [None if lo is None else round(100 * lo, 1), None if hi is None else round(100 * hi, 1)],
                        "events_by_then": events, "censored_by_then": censored,
                        "at_risk_after": n_subjects - processed}

    for dur, d, total in rows:
        while pi < len(pts) and pts[pi] < dur:
            record(pts[pi])      # 后面还有观察，p 在随访期内
            pi += 1
        at_risk = n_subjects - processed
        if d and at_risk > 0:
            S *= 1.0 - d / at_risk
            if at_risk - d > 0:
                var_sum += d / (at_risk * (at_risk - d))
            else:
                var_sum = float("inf")
        events += d
        censored += total - d
        processed += total
        max_dur = dur
        lo, hi = ci(S, var_sum)
        for q in quantiles:
            if q_time[q] is None and S <= 1.0 - q + 1e-12 and d:
                q_time[q] = dur
            # 下界 lo 先穿过 1-q（区间下限），上界 hi 后穿过（区间上限）
            if q_lo[q] is None and lo is not None and lo <= 1.0 - q + 1e-12:
                q_lo[q] = dur
            if q_hi[q] is None and hi is not None and hi <= 1.0 - q + 1e-12:
                q_hi[q] = dur
    while pi < len(pts):
        # 循环结束后剩下的时点都 ≥ 最长随访时间；正好等于它的仍有定义（右连续），超过的看 S 有没有降到 0
        record(pts[pi], beyond=(max_dur is None or pts[pi] > max_dur))
        pi += 1
    none = n_subjects == 0
    out = {"n_subjects": n_subjects, "events": events, "censored": censored,
           "max_followup_h": hours(max_dur),
           "median_h": hours(q_time[0.5]) if 0.5 in q_time else None,
           "median_ci95_h": [hours(q_lo.get(0.5)), hours(q_hi.get(0.5))],
           "median_note": ("没有个体" if none else
                           None if q_time.get(0.5) is not None else
                           "观察期内生存函数没有降到 0.5，中位寿命超过最长随访时间（%s 小时）" % hours(max_dur)),
           "quantiles_h": {("p%d" % round(q * 100)): hours(q_time[q]) for q in quantiles},
           "quantiles_ci95_h": {("p%d" % round(q * 100)): [hours(q_lo[q]), hours(q_hi[q])] for q in quantiles},
           "final_survival_pct": None if none else round(100 * S, 1),
           "final_survival_note": None if none else "最后一次观察（%s 小时）时的 S(t)；%s" % (
               hours(max_dur), "之后 S(t) 没有定义" if S > 0.0 else "此后恒为 0")}
    return out, at_points


def km_for(conn, where, params, with_curve=True, horizons_h=HORIZONS_H, life_no=1):
    """对 lt_life 的一个子集做 KM。life_no=1 只看每个候选的第一段寿命；None 把每段寿命当一个个体（“全部寿命段”）。"""
    cond = where + (" AND life_no = 1" if life_no == 1 else "")
    n = conn.execute("SELECT COUNT(*) FROM lt_life WHERE " + cond, params).fetchone()[0]
    rows = conn.execute("SELECT dur_s, SUM(event), COUNT(*) FROM lt_life WHERE " + cond + " GROUP BY dur_s ORDER BY dur_s", params)
    horizons = [h * 3600.0 for h in horizons_h]
    grid = [i * RESOLUTION_MIN * 60.0 for i in range(0, CURVE_MAX_H * 60 // RESOLUTION_MIN + 1)] if with_curve else []
    km, at = kaplan_meier(rows, n, horizons + grid)
    km["survival_at"] = {"%dh" % h: at[h * 3600.0] for h in horizons_h}
    if with_curve:
        # 曲线点 [小时, S(t)%, 之后的风险集]，只到最长随访时间；之后 S(t) 没有定义，不输出
        km["curve_step_%dmin" % RESOLUTION_MIN] = [[round(t / 3600.0, 2), at[t]["survival_pct"], at[t]["at_risk_after"]]
                                                 for t in grid if at[t]["survival_pct"] is not None]
        km["curve_note"] = "每 %d 分钟一个点，只到最长随访时间（%s 小时）" % (RESOLUTION_MIN, km["max_followup_h"])
    return km


def resurrection_for(conn, where, params):
    """死而复生的分布：确认死亡过的候选里，复活 0/1/2/3+ 次的各多少；死亡到复活的间隔分位数。"""
    dist = collections.OrderedDict((k, 0) for k in ("0", "1", "2", "3+"))
    for n_res, c in conn.execute("SELECT n_resurrect, COUNT(*) FROM lt_cand WHERE n_deaths >= 1 AND " + where + " GROUP BY 1", params):
        dist[str(n_res) if n_res < 3 else "3+"] += c
    died = sum(dist.values())
    revived = died - dist["0"]
    row = conn.execute("SELECT COUNT(*), SUM(n_blips), SUM(n_blips > 0), SUM(ever_ok), SUM(n_fail_skipped_loopback), "
                       "SUM(n_fail_skipped_down), SUM(pending_at_end) FROM lt_cand WHERE " + where, params).fetchone()
    n_cand, blips, cands_with_blip, ever_ok, sk_lo, sk_down, pending_end = [v or 0 for v in row]
    # 复活间隔的分位数用 SQL 排序取位置，不把全部间隔读进内存。
    # where 只对 lt_cand 用（grp、prefix24 两张表都有，放进子查询避免歧义，也不改写 where 里可能有的子查询）
    in_cands = " r.cand IN (SELECT cand FROM lt_cand WHERE " + where + ")"
    n_gaps = conn.execute("SELECT COUNT(*) FROM lt_resurrect r WHERE" + in_cands, params).fetchone()[0]
    gap_q = {}
    for q in (0.5, 0.9):
        if n_gaps:
            off = min(n_gaps - 1, int(math.floor(q * (n_gaps - 1))))
            v = conn.execute("SELECT r.gap_s FROM lt_resurrect r WHERE" + in_cands + " ORDER BY r.gap_s LIMIT 1 OFFSET ?",
                             params + (off,)).fetchone()[0]
            gap_q["p%d" % round(q * 100)] = hours(v)
        else:
            gap_q["p%d" % round(q * 100)] = None
    second_life = conn.execute("SELECT COUNT(*), SUM(event) FROM lt_life WHERE life_no >= 2 AND " + where, params).fetchone()
    return {"candidates_ever_ok": ever_ok, "candidates_with_confirmed_death": died,
            "candidates_revived": revived, "revived_pct_of_died": pct(revived, died),
            "resurrections_distribution": dict(dist),
            "death_to_revival_gap_h": dict(gap_q, n=n_gaps),
            "later_lives": {"n": second_life[0] or 0, "events": second_life[1] or 0},
            "blips": {"total": blips, "candidates_with_blip": cands_with_blip, "candidates_with_blip_pct_of_ever_ok": pct(cands_with_blip, ever_ok)},
            "failures_disregarded": {"loopback_failure_window": sk_lo, "downtime_window": sk_down},
            "censored_with_single_unconfirmed_failure": pending_end}


# ---------------------------------------------------------------- 组装报告

def group_block(conn, where, params, label, with_curve=True):
    n_cand, n_ever = conn.execute("SELECT COUNT(*), SUM(ever_ok) FROM lt_cand WHERE " + where, params).fetchone()
    n_ever = n_ever or 0
    ok_first = conn.execute("SELECT COUNT(*) FROM lt_cand WHERE ok_at_first_visit = 1 AND " + where, params).fetchone()[0]
    left_trunc = conn.execute("SELECT COUNT(*) FROM lt_cand WHERE cand IN (SELECT cand FROM lt_lefttrunc) AND " + where, params).fetchone()[0]
    blk = {"label": label,
           "n": {"candidates_visited": n_cand, "candidates_ever_ok": n_ever, "candidates_never_ok": n_cand - n_ever,
                 "ever_ok_pct_of_visited": pct(n_ever, n_cand),
                 "candidates_ok_at_first_visit": ok_first, "ok_at_first_visit_pct_of_ever_ok": pct(ok_first, n_ever),
                 "left_truncated_candidates": left_trunc},
           "first_life_km": km_for(conn, where, params, with_curve=with_curve, life_no=1),
           "all_lives_km": km_for(conn, where, params, with_curve=False, life_no=None),
           "resurrection": resurrection_for(conn, where, params)}
    if left_trunc:
        # 另给一组：剔除 --since 之前就可用过的候选（它们的第一段寿命是剩余寿命）
        blk["first_life_km_excluding_left_truncated"] = km_for(
            conn, where + " AND cand NOT IN (SELECT cand FROM lt_lefttrunc)", params, with_curve=False, life_no=1)
        blk["first_life_km_excluding_left_truncated"]["note"] = "剔除了 %d 个 --since 之前就有过可用探访的候选" % left_trunc
    straddle = conn.execute("SELECT SUM(straddles_down), SUM(event) FROM lt_life WHERE life_no = 1 AND " + where, params).fetchone()
    blk["first_life_km"]["deaths_confirmed_across_downtime"] = straddle[0] or 0
    # 提前删失：最后一次探访比观察结束早 2 小时以上的删失个体（多半是下榜 24 小时后不再探访的）
    blk["first_life_km"]["censored_more_than_2h_before_end"] = conn.execute(
        "SELECT COUNT(*) FROM (SELECT cand FROM lt_life WHERE life_no = 1 AND event = 0 AND " + where + ") l "
        "JOIN lt_cand c ON c.cand = l.cand WHERE c.last_visit < ?", params + (OBS["end"] - 7200,)).fetchone()[0]
    return blk


OBS = {"start": None, "end": None}


def build(conn, since, until, gap_min, dense_threshold, want_curve=True):
    stats = {"visits_total": 0, "visits_aborted": 0, "visits_ok_state_mismatch": 0,
             "hist": collections.defaultdict(lambda: collections.Counter())}
    events = run_events(conn, since, until)
    first_start = next((e[0] for e in events if e[1] == "start"), None)
    min_visit, max_visit = conn.execute("SELECT MIN(ts_epoch), MAX(ts_epoch) FROM visit").fetchone()
    last_stop = max((e[0] for e in events if e[1] == "stop"), default=None)
    obs_start = since if since is not None else (first_start if first_start is not None else min_visit)
    obs_end = until if until is not None else max(x for x in (max_visit, last_stop) if x is not None)
    if obs_start is None or obs_end is None:
        raise SystemExit("库里没有 visit 记录，算不了寿命")
    OBS["start"], OBS["end"] = obs_start, obs_end

    bad_down, restarts, gaps, stat_gaps = downtime_windows(conn, events, obs_start, obs_end, gap_min)
    bad_lo, lo_total, lo_fail, lo_detail = loopback_windows(conn, obs_start, obs_end)
    pub_total, pub_fail = conn.execute(
        "SELECT COUNT(*), SUM(class != 'ok') FROM att WHERE proto = 'direct' AND cand = 'control:public' "
        "AND class NOT LIKE '%canceled%' AND ts_epoch BETWEEN ? AND ?", (obs_start, obs_end)).fetchone()

    scan_candidates(conn, bad_lo, bad_down, obs_start, obs_end, stats)
    load_sources(conn)
    dense_basis, has_cands = load_dense_prefixes(conn, dense_threshold)
    n_left_trunc = load_left_truncated(conn, since)
    pool = pool_counts(conn, has_cands)
    # “可用”取 visit.n_ok>0（prober.go okMask：主循环四种协议；与探测器状态机和 summary.go 一致）。PROTOCOL 原文是
    # “至少有一次尝试走完全部阶段并通过核对”，附加尝试（prober.go：SOCKS 隧道里走明文、forward 的 j/b 内容）可能 class=ok
    # 而 okMask=0；这里数出两种口径不一致的探访数作提示，不改口径。走 att_visit 索引逐探访查。
    stats["visits_ok_by_att_but_n_ok_zero"] = conn.execute(
        "SELECT COUNT(*) FROM visit v WHERE v.ts_epoch BETWEEN ? AND ? AND COALESCE(v.n_ok, 0) = 0 AND COALESCE(v.aborted, 0) = 0 "
        "AND EXISTS (SELECT 1 FROM att a WHERE a.visit = v.visit AND a.class = 'ok' AND a.dst IN ('judge_http', 'judge_tls'))",
        (obs_start, obs_end)).fetchone()[0]

    # 维度列全在白名单里（SCHEMA“可输出列白名单”）；候选地址、visit 号只在 TEMP 表和子查询里当连接键，不输出
    ingest.check_output_columns("visit", ["group", "prefix24", "n_ok", "aborted", "state", "ms", "ts_epoch"])
    ingest.check_output_columns("att", ["proto", "dst", "class", "ms", "ts_epoch"])
    ingest.check_output_columns("list_event", ["src", "label", "event", "base", "prefix24", "ts_epoch"])
    ingest.check_output_columns("agg_member", ["src", "prefix24"])
    ingest.check_output_columns("cands", ["prefix24", "visits"])
    ingest.check_output_columns("start", ["resumed_candidates", "ts_epoch"])
    ingest.check_output_columns("stop", ["ts_epoch"])
    ingest.check_output_columns("stat", ["ts_epoch"])

    report = collections.OrderedDict()
    report["module"] = MODULE
    report["generated_utc"] = ts_text(time.time())
    report["protocol_version"] = "1.2"
    report["definitions"] = DEFINITIONS
    meta = dict(conn.execute("SELECT key, value FROM meta WHERE key IN ('ingest_version','first_ts','last_ts','records_by_kind')"))
    report["db"] = {"ingest_version": meta.get("ingest_version"), "first_ts": meta.get("first_ts"), "last_ts": meta.get("last_ts"),
                    "records_visit": json.loads(meta["records_by_kind"]).get("visit") if meta.get("records_by_kind") else None}
    report["parameters"] = {"resolution_min": RESOLUTION_MIN, "horizons_h": list(HORIZONS_H),
                            "quantiles": list(QUANTILES), "gap_min": gap_min, "loopback_period_s": LOOPBACK_PERIOD_S,
                            "dense_prefix_threshold": dense_threshold, "since": ts_text(since), "until": ts_text(until),
                            "censoring": "最后一次可用的探访时刻", "death_time": "连续两次不可用里第一次的探访时刻"}
    starts_all = [e for e in events if e[1] == "start"]
    report["window"] = {
        "obs_start_utc": ts_text(obs_start), "obs_end_utc": ts_text(obs_end), "hours": hours(obs_end - obs_start),
        # 首条 start 的 resumed_candidates 必然是 0（没有可恢复的状态），state_cleared 对它没有意义，给 null
        "starts": [{"utc": ts_text(e[0]), "resumed_candidates": e[2], "state_cleared": (None if i == 0 else e[2] == 0),
                    "in_window": bool(obs_start <= e[0] <= obs_end)} for i, e in enumerate(starts_all)],
        "stops": [{"utc": ts_text(e[0]), "visits": e[2]} for e in events if e[1] == "stop"],
        "restarts": restarts,
        "heartbeat_gaps_over_gap_min": gaps,
        "stat_only_gaps": {"gaps": stat_gaps, "n": len(stat_gaps),
                           "note": "只看 stat 记录的间断（超过 gap_min 分钟），诊断用，不并入停机；across_restart 表示间断里有一次 start"},
        "downtime": {"windows": len(bad_down), "total_s": round(bad_down.total_seconds(), 3),
                     "total_h": hours(bad_down.total_seconds()),
                     "note": "并入“不算死亡”的停机时段（按观察窗口裁剪后）：clean 重启的 stop→start、崩溃的最后心跳→start、心跳缺席超过 gap_min 分钟"},
        "loopback_control": {"attempts": lo_total, "failed": lo_fail, "failed_pct": pct(lo_fail, lo_total),
                             "failure_windows": len(bad_lo), "failure_windows_total_s": round(bad_lo.total_seconds(), 3),
                             "by_dst": lo_detail,
                             "note": "两路（judge_http、judge_tls）分别取失败前后最近一次同一路成功之间，再合并；attempts 是两路合计"},
        "public_control_informational": {"attempts": pub_total or 0, "failed": pub_fail or 0,
                                         "note": "公网地址对照失败不算入“不算死亡的时段”（PROTOCOL 只说回环），只作参考"},
        "warnings": [],
    }
    # --since 已经指到那条状态清空的 start 上（at_since）时不再提示
    if any(r["state_cleared"] and not r["at_since"] for r in restarts):
        report["window"]["warnings"].append("观察窗口内有 resumed_candidates=0 的非首条 start：状态被清空，PROTOCOL 规定从那一刻重新算 72 小时；"
                                            "请用 --since 指定正式起点后重跑")
    if stats["visits_ok_state_mismatch"]:
        report["window"]["warnings"].append("有 %d 条 visit 的 n_ok>0 与 state='working' 不一致，请核对 ingest" % stats["visits_ok_state_mismatch"])
    if n_left_trunc:
        report["window"]["warnings"].append("有 %d 个候选在 --since 之前就有过可用探访：它们的第一段寿命是剩余寿命（左截断），"
                                            "各组另给了剔除它们的 first_life_km_excluding_left_truncated" % n_left_trunc)
    if stats["visits_ok_by_att_but_n_ok_zero"]:
        report["window"]["warnings"].append("有 %d 条探访 n_ok=0 但同一 visit 里有 class=ok 的 judge 尝试（附加尝试）：按 PROTOCOL 原文算可用、"
                                            "按本脚本的 n_ok 口径不算，见 n.visits_ok_by_att_but_n_ok_zero" % stats["visits_ok_by_att_but_n_ok_zero"])

    n_cand_total, n_ever_total = conn.execute("SELECT COUNT(*), SUM(ever_ok) FROM lt_cand").fetchone()
    report["n"] = {"visits_in_window": stats["visits_total"], "visits_aborted_excluded": stats["visits_aborted"],
                   "visits_used": stats["visits_total"] - stats["visits_aborted"],
                   "visits_ok_state_mismatch": stats["visits_ok_state_mismatch"],
                   "visits_ok_by_att_but_n_ok_zero": stats["visits_ok_by_att_but_n_ok_zero"],
                   "candidates_visited": n_cand_total, "candidates_ever_ok": n_ever_total or 0,
                   "candidates_ok_at_first_visit": conn.execute("SELECT COUNT(*) FROM lt_cand WHERE ok_at_first_visit = 1").fetchone()[0],
                   "left_truncated_candidates": n_left_trunc,
                   "candidates_by_group": {g: c for g, c in conn.execute("SELECT CASE grp WHEN 0 THEN 'regular' ELSE 'aggregator_sample' END, COUNT(*) FROM lt_cand GROUP BY grp")},
                   "lives_total": conn.execute("SELECT COUNT(*) FROM lt_life").fetchone()[0],
                   "sources": conn.execute("SELECT COUNT(DISTINCT src) FROM lt_src").fetchone()[0],
                   "dense_prefixes": conn.execute("SELECT COUNT(*) FROM lt_dense").fetchone()[0],
                   "pool": pool,
                   "notes": {"candidates_ok_at_first_visit": "窗口内第一次（未被打断的）探访就可用的候选：寿命起点可能早于观察，量到的是剩余寿命",
                             "left_truncated_candidates": "--since 之前就有过可用探访、窗口内也曾可用的候选（没有 --since 时为 0）",
                             "visits_ok_by_att_but_n_ok_zero": "n_ok=0 但同一 visit 里有 class=ok、dst 为 judge_http/judge_tls 的尝试的探访数",
                             "pool": "候选池与从没探访过的条目，PROTOCOL 1.2“候选密集的地址段”；不进任何比例的分母"}}

    groups = collections.OrderedDict()
    groups["regular"] = group_block(conn, "grp = 0", (), "常规列表", want_curve)
    groups["regular_excluding_dense_prefixes"] = group_block(
        conn, "grp = 0 AND (prefix24 IS NULL OR prefix24 NOT IN (SELECT prefix24 FROM lt_dense WHERE prefix24 IS NOT NULL))", (),
        "常规列表，去掉候选超过 %d 个的 /24（本脚本额外给出，PROTOCOL 1.2 该节未列寿命）" % dense_threshold, want_curve)
    groups["aggregator_sample"] = group_block(conn, "grp = 1", (), "聚合器抽样", want_curve)
    report["groups"] = groups

    report["dense_prefixes_excluded"] = {
        "basis": dense_basis, "threshold": dense_threshold,
        "prefixes": [{"prefix24": p, "cands": c, "visited": v, "ever_ok": s} for p, c, v, s in
                     conn.execute("SELECT prefix24, cands, visited, subjects FROM lt_dense ORDER BY cands DESC")]}

    # 各来源：候选可属多个来源；只看第一段寿命，不画曲线
    by_src = collections.OrderedDict()
    src_rows = conn.execute(
        "SELECT s.src, MIN(s.kind), COUNT(DISTINCT c.cand), SUM(c.ever_ok) FROM lt_src s JOIN lt_cand c ON c.cand = s.cand "
        "GROUP BY s.src ORDER BY COUNT(DISTINCT c.cand) DESC").fetchall()
    for src, kind, n_vis, n_ok in src_rows:
        n = conn.execute("SELECT COUNT(*) FROM lt_life l WHERE l.life_no = 1 AND EXISTS (SELECT 1 FROM lt_src s WHERE s.cand = l.cand AND s.src = ?)",
                         (src,)).fetchone()[0]
        rows = conn.execute("SELECT l.dur_s, SUM(l.event), COUNT(*) FROM lt_life l WHERE l.life_no = 1 AND EXISTS "
                            "(SELECT 1 FROM lt_src s WHERE s.cand = l.cand AND s.src = ?) GROUP BY l.dur_s ORDER BY l.dur_s", (src,))
        km, at = kaplan_meier(rows, n, [h * 3600.0 for h in HORIZONS_H])
        km["survival_at"] = {"%dh" % h: at[h * 3600.0] for h in HORIZONS_H}
        died = conn.execute("SELECT COUNT(*), SUM(n_resurrect > 0) FROM lt_cand c WHERE c.n_deaths >= 1 AND EXISTS "
                            "(SELECT 1 FROM lt_src s WHERE s.cand = c.cand AND s.src = ?)", (src,)).fetchone()
        cur_listed = conn.execute("SELECT COUNT(DISTINCT cand) FROM lt_src_cur WHERE src = ?", (src,)).fetchone()[0]
        cur_vis, cur_ok = conn.execute("SELECT COUNT(*), COALESCE(SUM(ever_ok), 0) FROM lt_cand WHERE cand IN "
                                       "(SELECT cand FROM lt_src_cur WHERE src = ?)", (src,)).fetchone()
        by_src[src] = {"kind": kind,
                       "label": "曾被该来源列出过的候选（list_event 的 add 事件，含 base=1 快照；聚合器取 agg_member），"
                                "与 summary.json by_source 的并集口径不同",
                       "n": {"candidates_visited": n_vis, "candidates_ever_ok": n_ok or 0,
                             "ever_ok_pct_of_visited": pct(n_ok or 0, n_vis)},
                       "summary_style_current_set": None if kind == "aggregator_sample" else {
                           "listed": cur_listed, "visited": cur_vis, "ever_ok": cur_ok,
                           "note": "summary.json by_source 的口径（summary.go finish()）：数据结束时该来源各标签“当前在榜”集合的并集；"
                                   "探访过/曾可用按本脚本的观察窗口算，summary 按整个运行算"},
                       "first_life_km": km,
                       "resurrection": {"candidates_with_confirmed_death": died[0] or 0, "candidates_revived": died[1] or 0,
                                        "revived_pct_of_died": pct(died[1] or 0, died[0] or 0)}}
    report["by_source"] = by_src

    # 复测间隔（分辨率的证据）：1 秒桶直方图的分位数，报分钟保留两位（桶的下沿，误差 < 1 秒）。
    # 名义值从 start 记录的探测器配置里取（start.probe 整列不可输出，SCHEMA 允许用 json_extract 单取数值字段；
    # 多条 start 配置不同时取第一条并记下）。PROTOCOL“频率与限速”：可用 20、聚合器 60、曾可用后连不上从 5 起加倍。
    cfg_rows = conn.execute("SELECT json_extract(raw, '$.probe.alive_interval_min'), json_extract(raw, '$.probe.aggregator_min'), "
                            "json_extract(raw, '$.probe.just_died_base_min') FROM start ORDER BY ts_epoch").fetchall()
    nominal = {"alive_interval_min": cfg_rows[0][0] if cfg_rows else None, "aggregator_min": cfg_rows[0][1] if cfg_rows else None,
               "just_died_base_min": cfg_rows[0][2] if cfg_rows else None,
               "distinct_configs_across_starts": len(set(cfg_rows))}
    ri = collections.OrderedDict()
    ri["nominal_from_start_record"] = nominal
    for (after, g), label, nom in ((("ok", "reg"), "常规列表：可用之后", nominal["alive_interval_min"]),
                                   (("pending", "reg"), "常规列表：首次不可用之后", nominal["just_died_base_min"]),
                                   (("ok", "agg"), "聚合器抽样：可用之后", nominal["aggregator_min"]),
                                   (("pending", "agg"), "聚合器抽样：首次不可用之后", nominal["just_died_base_min"])):
        h = stats["hist"].get((after, g), {})
        qs, total = hist_quantiles(h, (0.1, 0.5, 0.9))
        ri[after + "_" + g] = {"label": label, "n_intervals": total,
                               "quantiles_min": {("p%d" % round(float(k) * 100)): (None if v is None else round(v / 60.0, 2)) for k, v in qs.items()},
                               "bucket": "1 秒（取整秒，报桶的下沿）",
                               "nominal_min": nom,
                               "nominal_note": "sched.go：实际间隔在配置值的 ±10% 内浮动；曾可用后连不上的每次失败加倍；启动后约一小时有积压"}
    report["retest_interval"] = ri
    return report


# ---------------------------------------------------------------- Markdown

def fmt(v, suffix=""):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:,.1f}{suffix}" if suffix == "%" else f"{v:,.2f}{suffix}"
    return f"{v:,}{suffix}"


def km_row(name, blk):
    km = blk["first_life_km"]
    # 中位数：没有个体 → “—”；有个体但 S 没降到 0.5 → “—（未达到）”
    cells = [name, fmt(blk["n"]["candidates_visited"]), fmt(km["n_subjects"]), fmt(km["events"]), fmt(km["censored"]),
             fmt(km["median_h"]) + ("" if km["median_h"] is not None or not km["n_subjects"] else "（未达到）")]
    for h in HORIZONS_H:
        s = km["survival_at"]["%dh" % h]
        lo, hi = s["ci95_pct"]
        cells.append(f"{fmt(s['survival_pct'], '%')}（{fmt(lo, '%')}–{fmt(hi, '%')}）" if lo is not None else fmt(s["survival_pct"], "%"))
    return "| " + " | ".join(cells) + " |"


def markdown(rep):
    out = []
    w = rep["window"]
    out.append("### 寿命（Kaplan–Meier，第一段寿命；分辨率 %d 分钟）\n" % RESOLUTION_MIN)
    out.append("观察窗口 %s 到 %s（%s 小时）；重启 %d 次，停机合计 %s 小时；回环对照 %s 次失败 %s 次。" % (
        w["obs_start_utc"], w["obs_end_utc"], fmt(w["hours"]), len(w["restarts"]), fmt(w["downtime"]["total_h"]),
        fmt(w["loopback_control"]["attempts"]), fmt(w["loopback_control"]["failed"])))
    p = rep["n"]["pool"]
    out.append("候选池 %s 条，从没探访过 %s 条（%s；不进任何比例的分母）；窗口内探访过 %s 个候选，第一次探访就可用的 %s 个。"
               "“—”表示没有定义（没有个体，或超过最长随访时间）。" % (
                   fmt(p["candidates_in_pool"]), fmt(p["candidates_never_visited"]), p["basis"],
                   fmt(rep["n"]["candidates_visited"]), fmt(rep["n"]["candidates_ok_at_first_visit"])))
    out.append("")
    hdr = "| 分组 | 探访过的候选 | 曾可用（个体） | 死亡 | 删失 | 中位寿命（小时） | " + " | ".join("%d 小时仍存活" % h for h in HORIZONS_H) + " |"
    out.append(hdr)
    out.append("| " + " | ".join(["---"] * (6 + len(HORIZONS_H))) + " |")
    for key, name in (("regular", "常规列表"), ("regular_excluding_dense_prefixes", "常规列表（去掉密集 /24）"), ("aggregator_sample", "聚合器抽样")):
        out.append(km_row(name, rep["groups"][key]))
    out.append("")
    out.append("### 各来源（候选可属多个来源）\n")
    out.append(hdr.replace("分组", "来源"))
    out.append("| " + " | ".join(["---"] * (6 + len(HORIZONS_H))) + " |")
    for src, blk in rep["by_source"].items():
        out.append(km_row(src, blk))
    out.append("")
    out.append("### 死而复生\n")
    out.append("| 分组 | 曾可用 | 确认死亡过 | 又恢复过 | 占死亡过的 | 恢复 1 次 | 2 次 | 3 次以上 | 死亡到恢复中位（小时） | 闪断（不算死亡） |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, name in (("regular", "常规列表"), ("aggregator_sample", "聚合器抽样")):
        r = rep["groups"][key]["resurrection"]
        d = r["resurrections_distribution"]
        out.append(f"| {name} | {fmt(r['candidates_ever_ok'])} | {fmt(r['candidates_with_confirmed_death'])} | {fmt(r['candidates_revived'])} | "
                   f"{fmt(r['revived_pct_of_died'], '%')} | {fmt(d['1'])} | {fmt(d['2'])} | {fmt(d['3+'])} | "
                   f"{fmt(r['death_to_revival_gap_h']['p50'])} | {fmt(r['blips']['total'])} |")
    out.append("")
    out.append("### 复测间隔（实际值，分钟）\n")
    out.append("| 情形 | 间隔数 | p10 | p50 | p90 | 名义值 |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for k, r in rep["retest_interval"].items():
        if k == "nominal_from_start_record":
            continue
        q = r["quantiles_min"]
        out.append(f"| {r['label']} | {fmt(r['n_intervals'])} | {fmt(q.get('p10'))} | {fmt(q.get('p50'))} | {fmt(q.get('p90'))} | {r['nominal_min']} |")
    if rep["dense_prefixes_excluded"]["prefixes"]:
        out.append("")
        out.append("### 被去掉的候选密集 /24\n")
        out.append("| /24 | 候选 | 探访过 | 曾可用 |")
        out.append("| --- | --- | --- | --- |")
        for p in rep["dense_prefixes_excluded"]["prefixes"]:
            out.append(f"| {p['prefix24']} | {fmt(p['cands'])} | {fmt(p['visited'])} | {fmt(p['ever_ok'])} |")
    if w["warnings"]:
        out.append("")
        out.append("警告：" + "；".join(w["warnings"]))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- 输出前的自检

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d{1,5})?(?!\d|\.\d)")


def assert_no_identifiers(text, conn):
    """写出前扫一遍：不许有 ip（/24 前缀 a.b.c.0/24 除外）、judge 的主机名和地址、候选地址。
    这是最后一道保险，不是放行依据：放行靠白名单取列。"""
    bad = []
    for m in _IPV4.finditer(text):
        tail = text[m.end():m.end() + 3]
        if not (m.group(4) == "0" and tail == "/24" and ":" not in m.group(0)):
            bad.append(m.group(0))
    for tbl, col in (("self_names", "name"), ("self_ips", "ip")):
        try:
            for (v,) in conn.execute("SELECT DISTINCT %s FROM %s" % (col, tbl)):
                if v and v in text:
                    bad.append("<%s>" % tbl)
        except sqlite3.Error:
            pass
    if bad:
        raise SystemExit("输出里出现了不该出现的标识，拒绝写出：%s" % ", ".join(sorted(set(bad))[:5]))


# ---------------------------------------------------------------- 合成库自检

SELFTEST_SCHEMA = """
CREATE TABLE visit (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, "group" INTEGER,
    n INTEGER, prev TEXT, state TEXT, full INTEGER, listed INTEGER, labels TEXT, tried TEXT, ok TEXT, auth INTEGER, aborted INTEGER,
    next_min REAL, ms INTEGER, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT, n_ok INTEGER, raw TEXT);
CREATE INDEX visit_cand_ts ON visit(cand, ts_epoch);
CREATE TABLE att (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, class TEXT, ms INTEGER, cand_kind TEXT);
CREATE TABLE start (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER,
    raw TEXT DEFAULT '{"probe":{"alive_interval_min":20,"aggregator_min":60,"just_died_base_min":5}}');
CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visits INTEGER);
CREATE TABLE stat (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, up_min REAL);
CREATE TABLE list_event (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, cand TEXT, src TEXT, label TEXT, event TEXT, base INTEGER, prefix24 TEXT);
CREATE TABLE agg_member (rid INTEGER PRIMARY KEY, cand TEXT, src TEXT, prefix24 TEXT);
CREATE TABLE cands (key TEXT PRIMARY KEY, prefix24 TEXT, "group" INTEGER, visits INTEGER);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
"""


def selftest(keep=None):
    """最小合成库：覆盖死亡、闪断、删失、回环失败剔除、停机、复活、聚合器组、密集 /24、aborted、来源归属。
    通过时打印 selftest ok；任何一项不符就抛 AssertionError。"""
    T0 = 1_800_000_000.0
    H = 3600.0
    fd, path = tempfile.mkstemp(prefix="m_lifetime_selftest_", suffix=".sqlite")
    os.close(fd)
    os.unlink(path)
    conn = sqlite3.connect(path)
    conn.executescript(SELFTEST_SCHEMA)
    # 合成地址全部取自 RFC 5737 的文档保留段（TEST-NET-1/2/3），不是真实代理；用格式化拼出来，脚本常量里不出现 ip:port 字面量
    tn1, tn2, tn3 = "192.0.2.%d", "198.51.100.%d", "203.0.113.%d"
    conn.execute("INSERT INTO self_names VALUES ('judge.example.test', 'start.judge_host', 1)")
    conn.execute("INSERT INTO self_ips VALUES (?, 'start.judge_ip', 1)", (tn3 % 9,))
    conn.execute("INSERT INTO start (rid, ts, ts_epoch, resumed_candidates) VALUES (1, ?, ?, 0)", (ts_text(T0), T0))
    # 停机：T0+10h 停，T0+13h 再起（clean 重启）
    conn.execute("INSERT INTO stop VALUES (1, ?, ?, 100)", (ts_text(T0 + 10 * H), T0 + 10 * H))
    conn.execute("INSERT INTO start (rid, ts, ts_epoch, resumed_candidates) VALUES (2, ?, ?, 50)", (ts_text(T0 + 13 * H), T0 + 13 * H))
    conn.execute("INSERT INTO stop VALUES (2, ?, ?, 200)", (ts_text(T0 + 30 * H), T0 + 30 * H))
    for i in range(0, int(30 * H), 300):
        t = T0 + i
        if 10 * H < i < 13 * H:
            continue
        conn.execute("INSERT INTO stat (ts, ts_epoch, up_min) VALUES (?, ?, ?)", (ts_text(t), t, i / 60))
    # 回环对照：每分钟两路（judge_http、judge_tls 相隔 1 毫秒），T0+5h 整那一次 judge_http 失败、judge_tls 成功
    # → 按路算窗口 = [T0+5h-60, T0+5h+60]（同路前后成功）；混在一起算会得到 [T0+5h-60, T0+5h+0.001]
    for i in range(0, int(30 * H), 60):
        t = T0 + i
        if 10 * H < i < 13 * H:
            continue
        cls = "tcp_refused" if i == int(5 * H) else "ok"
        conn.execute("INSERT INTO att (ts, ts_epoch, visit, cand, proto, dst, class, ms, cand_kind) VALUES (?,?,?,?,?,?,?,?,?)",
                     (ts_text(t), t, "c%d" % i, "control:loopback", "direct", "judge_http", cls, 5, "control"))
        conn.execute("INSERT INTO att (ts, ts_epoch, visit, cand, proto, dst, class, ms, cand_kind) VALUES (?,?,?,?,?,?,?,?,?)",
                     (ts_text(t + 0.001), t + 0.001, "c%d" % i, "control:loopback", "direct", "judge_tls", "ok", 5, "control"))
        conn.execute("INSERT INTO att (ts, ts_epoch, visit, cand, proto, dst, class, ms, cand_kind) VALUES (?,?,?,?,?,?,?,?,?)",
                     (ts_text(t), t, "c%d" % i, "control:public", "direct", "judge_http", "ok", 5, "control"))

    rid = [0]

    def visit(cand, t, ok, group=None, aborted=None, ms=1000, pfx="192.0.2.0/24"):
        rid[0] += 1
        conn.execute("INSERT INTO visit (rid, file_id, ts, ts_epoch, visit, cand, \"group\", n, prev, state, listed, ok, aborted, ms, prefix24, n_ok, raw) "
                     "VALUES (?,1,?,?,?,?,?,?,?,?,1,?,?,?,?,?,'{}')",
                     (rid[0], ts_text(t), t, "v%d" % rid[0], cand, group, rid[0], "new", "working" if ok else "dead",
                      '["socks5"]' if ok else None, aborted, ms, pfx, 1 if ok else None))

    m = 60.0
    # A：ok, ok, fail, fail → 死亡在第 3 次（t=40m），寿命 40 分钟
    A = tn1 % 1 + ":1080"
    for t, ok in ((0, 1), (20 * m, 1), (40 * m, 0), (45 * m, 0)):
        visit(A, T0 + t, ok)
    # B：ok, fail, ok, ok → 闪断一次，删失在最后一次 ok（t=60m）
    B = tn1 % 2 + ":1080"
    for t, ok in ((0, 1), (20 * m, 0), (25 * m, 1), (60 * m, 1)):
        visit(B, T0 + t, ok)
    # C：从未可用
    C = tn1 % 3 + ":1080"
    for t in (0, 30 * m, 90 * m):
        visit(C, T0 + t, 0)
    # D：ok(4h50m), fail 落在回环失败窗口里(5h)，fail(5h05m), fail(5h10m) → 第一次 fail 剔除，死亡在 5h05m，寿命 15 分钟
    D = tn1 % 4 + ":1080"
    for t, ok in ((4 * H + 50 * m, 1), (5 * H, 0), (5 * H + 5 * m, 0), (5 * H + 10 * m, 0)):
        visit(D, T0 + t, ok)
    # E：ok, fail, fail(死亡 20m), ok(复活 2h), ok, fail, fail(第二次死亡) → 复活 1 次；第一段寿命 20 分钟
    E = tn1 % 5 + ":1080"
    for t, ok in ((0, 1), (20 * m, 0), (25 * m, 0), (2 * H, 1), (2 * H + 20 * m, 1), (2 * H + 40 * m, 0), (2 * H + 45 * m, 0)):
        visit(E, T0 + t, ok)
    # F：聚合器抽样，ok, ok → 删失，寿命 ≥ 60 分钟
    F = tn2 % 1 + ":8080"
    for t, ok in ((0, 1), (60 * m, 1)):
        visit(F, T0 + t, ok, group=1, pfx="198.51.100.0/24")
    # G：ok 在停机前（9h50m），重启后 fail(13h02m), fail(13h07m) → 死亡 13h02m，跨停机
    G = tn1 % 6 + ":1080"
    for t, ok in ((9 * H + 30 * m, 1), (9 * H + 50 * m, 1), (13 * H + 2 * m, 0), (13 * H + 7 * m, 0)):
        visit(G, T0 + t, ok)
    # H：ok, aborted 的 fail（不作数）, ok → 没有闪断，删失
    Hc = tn1 % 7 + ":1080"
    visit(Hc, T0 + 0, 1)
    visit(Hc, T0 + 20 * m, 0, aborted=1)
    visit(Hc, T0 + 40 * m, 1)
    # 密集 /24：203.0.113.0/24 有 8 个候选（阈值设 7；192.0.2.0/24 只有 7 个，不算密集），其中一个 ok 后死亡
    for i in range(11, 19):
        k = tn3 % i + ":3128"
        conn.execute("INSERT INTO cands VALUES (?, '203.0.113.0/24', 0, 1)", (k,))
        if i == 11:
            for t, ok in ((0, 1), (20 * m, 0), (25 * m, 0)):
                visit(k, T0 + t, ok, pfx="203.0.113.0/24")
        else:
            visit(k, T0 + 0, 0, pfx="203.0.113.0/24")
    for k in (A, B, C, D, E, G, Hc):
        conn.execute("INSERT INTO cands VALUES (?, '192.0.2.0/24', 0, 1)", (k,))
    conn.execute("INSERT INTO cands VALUES (?, '198.51.100.0/24', 1, 1)", (F,))
    # 一个从没探访过的候选（只在状态文件里，visits=0）
    conn.execute("INSERT INTO cands VALUES (?, '198.51.100.0/24', 0, 0)", (tn2 % 2 + ":8080",))
    # 来源：s1 的 base 快照列了 A、B、C，后一次快照 del 了 C（summary 口径“当前在榜”= A、B；本脚本口径“曾列出”= A、B、C）；
    # s2 列了 E、G；聚合器 agg1 抽了 F
    for k in (A, B, C):
        conn.execute("INSERT INTO list_event (ts, ts_epoch, cand, src, label, event, base, prefix24) VALUES (?, ?, ?, 's1', 'socks5', 'add', 1, '192.0.2.0/24')",
                     (ts_text(T0), T0, k))
    conn.execute("INSERT INTO list_event (ts, ts_epoch, cand, src, label, event, base, prefix24) VALUES (?, ?, ?, 's1', 'socks5', 'del', 0, '192.0.2.0/24')",
                 (ts_text(T0 + H), T0 + H, C))
    for k in (E, G):
        conn.execute("INSERT INTO list_event (ts, ts_epoch, cand, src, label, event, base, prefix24) VALUES (?, ?, ?, 's2', 'http', 'add', 0, '192.0.2.0/24')",
                     (ts_text(T0), T0, k))
    conn.execute("INSERT INTO agg_member (cand, src, prefix24) VALUES (?, 'agg1', '198.51.100.0/24')", (F,))
    conn.execute("INSERT INTO meta VALUES ('ingest_version', 'selftest')")
    conn.execute("INSERT INTO meta VALUES ('records_by_kind', '{\"visit\": %d}')" % rid[0])
    conn.commit()
    conn.close()

    ro = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    rep = build(ro, None, None, GAP_MIN_DEFAULT, 7, want_curve=True)

    # —— 核对 ——
    lives = {c: r for c, *r in ro.execute("SELECT cand, t0, t_end, dur_s, event, straddles_down FROM lt_life WHERE life_no = 1")}
    assert lives[A][2] == 40 * m and lives[A][3] == 1, lives[A]
    assert lives[B][2] == 60 * m and lives[B][3] == 0, lives[B]
    assert C not in lives
    assert lives[D][2] == 15 * m and lives[D][3] == 1, lives[D]
    assert lives[E][2] == 20 * m and lives[E][3] == 1, lives[E]
    assert lives[F][2] == 60 * m and lives[F][3] == 0, lives[F]
    assert lives[G][3] == 1 and lives[G][4] == 1 and abs(lives[G][2] - (3 * H + 32 * m)) < 1e-6, lives[G]
    assert lives[Hc][2] == 40 * m and lives[Hc][3] == 0, lives[Hc]
    cand = {c: r for c, *r in ro.execute("SELECT cand, n_deaths, n_resurrect, n_blips, n_fail_skipped_loopback, n_fail_skipped_down FROM lt_cand")}
    assert cand[E][:3] == [2, 1, 0], cand[E]
    assert cand[B][:3] == [0, 0, 1], cand[B]
    assert cand[D][3] == 1, cand[D]
    assert cand[Hc][2] == 0, cand[Hc]
    assert ro.execute("SELECT COUNT(*) FROM lt_life WHERE cand = ?", (E,)).fetchone()[0] == 2
    w = rep["window"]
    assert len(w["restarts"]) == 1 and w["restarts"][0]["clean_stop"] and abs(w["restarts"][0]["gap_s"] - 3 * H) < 1e-6, w["restarts"]
    assert w["restarts"][0]["stop_utc"] == ts_text(T0 + 10 * H) and not w["restarts"][0]["at_since"], w["restarts"]
    assert w["starts"][0]["state_cleared"] is None and w["starts"][1]["state_cleared"] is False and not w["warnings"], w
    # 回环：两路分别算，失败的是 judge_http 那一路，窗口 120 秒（同路前后成功之间），judge_tls 的 1 毫秒后成功不掐窗口
    lc = w["loopback_control"]
    assert lc["failed"] == 1 and lc["failure_windows"] == 1 and abs(lc["failure_windows_total_s"] - 120) < 1e-6, lc
    assert lc["by_dst"]["judge_http"]["failed"] == 1 and lc["by_dst"]["judge_tls"]["failed"] == 0, lc["by_dst"]
    # 只看 stat 的间断：10h→13h 那一段，跨了一次 start；不并入停机（停机时段由 stop→start 给出）
    assert w["stat_only_gaps"]["n"] == 1 and w["stat_only_gaps"]["gaps"][0]["across_restart"], w["stat_only_gaps"]
    # 候选池：16 个探访过的 + 1 个从没探访过的
    assert rep["n"]["pool"]["candidates_in_pool"] == 17 and rep["n"]["pool"]["candidates_never_visited"] == 1, rep["n"]["pool"]
    assert rep["n"]["pool"]["never_visited_by_prefix24"] == [] and rep["n"]["pool"]["never_visited_other_prefixes"]["n"] == 1, rep["n"]["pool"]
    assert rep["n"]["left_truncated_candidates"] == 0
    reg = rep["groups"]["regular"]
    km = reg["first_life_km"]
    # 常规组第一段寿命的个体：A(40m 死) B(60m 删) D(15m 死) E(20m 死) G(3h32m 死，跨停机) H(40m 删) 密集 11(20m 死) → 7 个，5 死 2 删
    assert km["n_subjects"] == 7 and km["events"] == 5 and km["censored"] == 2, km
    # 手算 KM：t=15m: 7→6/7；t=20m: 2 死 /6 → ×4/6；t=40m: 1 死 /4（A 死、H 删失同在 40m，删失仍在风险集）→ ×3/4；
    # t=60m B 删；t=3h32m G 死 /1 → 0
    s20 = 6 / 7 * 4 / 6
    assert abs(km["survival_at"]["1h"]["survival_pct"] - round(100 * s20 * 3 / 4, 1)) < 1e-9, km["survival_at"]["1h"]
    assert km["survival_at"]["6h"]["survival_pct"] == 0.0
    # S(20m)=0.571 还在 0.5 之上，S(40m)=0.571×3/4=0.429 才首次 ≤ 0.5 → 中位数 40 分钟
    assert km["median_h"] == round(40 * m / 3600, 2), km["median_h"]
    assert km["quantiles_h"]["p25"] == round(20 * m / 3600, 2), km["quantiles_h"]
    assert km["deaths_confirmed_across_downtime"] == 1
    assert km["survival_at"]["1h"]["at_risk_after"] == 1 and km["survival_at"]["1h"]["events_by_then"] == 4 and km["survival_at"]["1h"]["censored_by_then"] == 2
    res = reg["resurrection"]
    assert res["candidates_with_confirmed_death"] == 5 and res["candidates_revived"] == 1 and res["revived_pct_of_died"] == 20.0, res
    assert res["blips"]["total"] == 1 and res["failures_disregarded"]["loopback_failure_window"] == 1
    assert res["later_lives"] == {"n": 1, "events": 1}
    ex = rep["groups"]["regular_excluding_dense_prefixes"]["first_life_km"]
    assert ex["n_subjects"] == 6 and ex["events"] == 4, ex
    assert rep["dense_prefixes_excluded"]["prefixes"] == [{"prefix24": "203.0.113.0/24", "cands": 8, "visited": 8, "ever_ok": 1}]
    agg = rep["groups"]["aggregator_sample"]["first_life_km"]
    assert agg["n_subjects"] == 1 and agg["censored"] == 1 and agg["median_h"] is None and agg["median_note"]
    # 聚合器组只有 F，在 60 分钟删失：S(1h)=100% 有定义（正好等于最长随访），6h 起超过最长随访时间 → null
    assert agg["survival_at"]["1h"]["survival_pct"] == 100.0 and agg["survival_at"]["6h"]["survival_pct"] is None
    assert "超过最长随访时间" in agg["survival_at"]["6h"]["note"] and agg["final_survival_pct"] == 100.0
    assert set(rep["by_source"]) == {"s1", "s2", "agg1"}
    assert rep["by_source"]["s1"]["first_life_km"]["n_subjects"] == 2 and rep["by_source"]["s2"]["first_life_km"]["events"] == 2
    assert rep["by_source"]["agg1"]["kind"] == "aggregator_sample" and rep["by_source"]["agg1"]["summary_style_current_set"] is None
    # s1：曾列出 A、B、C（3 个），summary 口径“当前在榜” A、B（C 被 del）→ listed 2、visited 2、ever_ok 2
    assert rep["by_source"]["s1"]["n"]["candidates_visited"] == 3
    assert rep["by_source"]["s1"]["summary_style_current_set"] == dict(listed=2, visited=2, ever_ok=2, note=rep["by_source"]["s1"]["summary_style_current_set"]["note"])
    assert rep["n"]["visits_aborted_excluded"] == 1 and rep["n"]["visits_ok_by_att_but_n_ok_zero"] == 0
    # 第一次探访就可用：A B E F H 密集11 → 6；D（第一次 4h50m 可用）也是，G（第一次 9h30 可用）也是 → 8；C 和其余密集的不是
    assert rep["n"]["candidates_ok_at_first_visit"] == 8, rep["n"]["candidates_ok_at_first_visit"]
    # 复测间隔用 1 秒桶：常规组“可用之后”的间隔 A:20m B:20m,35m E:20m,20m,20m G:20m,3h12m H:40m D:10m F(agg):60m 密集11:20m …
    # p50 应是 20.00 分钟整（不再是半分钟桶的 19.5/20.0 之争）
    assert rep["retest_interval"]["ok_reg"]["quantiles_min"]["p50"] == 20.0, rep["retest_interval"]["ok_reg"]
    assert rep["retest_interval"]["ok_agg"]["quantiles_min"]["p50"] == 60.0, rep["retest_interval"]["ok_agg"]
    # 手算 KM 的独立核对：时间 1,2,2,3+,4 → S(1)=.8 S(2)=.4 S(3)=.4 S(4)=0，中位数 2
    km2, at = kaplan_meier([(1, 1, 1), (2, 2, 2), (3, 0, 1), (4, 1, 1)], 5, [1, 2.5, 3, 4])
    assert at[1]["survival_pct"] == 80.0 and at[2.5]["survival_pct"] == 40.0 and at[3]["survival_pct"] == 40.0 and at[4]["survival_pct"] == 0.0
    assert km2["median_h"] == hours(2) and km2["quantiles_h"]["p25"] == hours(2) and km2["quantiles_h"]["p75"] == hours(4)
    # 分位数区间的方向：20 个个体分别在 1..20 小时死亡 → 中位数 10 小时，Brookmeyer–Crowley 95% 区间 [5, 15]
    # （下界带在 5 小时首次 ≤ 0.5，上界带在 15 小时；之前上下限写反成 [15, 5]）
    km3, at3 = kaplan_meier([(h * 3600.0, 1, 1) for h in range(1, 21)], 20, [3600.0 * 10, 3600.0 * 25])
    assert km3["median_h"] == 10.0 and km3["median_ci95_h"] == [5.0, 15.0], (km3["median_h"], km3["median_ci95_h"])
    assert km3["quantiles_ci95_h"]["p25"][0] < km3["quantiles_h"]["p25"] < km3["quantiles_ci95_h"]["p25"][1], km3["quantiles_ci95_h"]
    assert at3[3600.0 * 25]["survival_pct"] == 0.0        # 全部死亡后 S 恒为 0，超过最长随访也有定义
    # 没有个体 / 超过最长随访时间（最后是删失）：不再报 100%
    km0, at0 = kaplan_meier([], 0, [3600.0])
    assert at0[3600.0]["survival_pct"] is None and km0["final_survival_pct"] is None and km0["median_note"] == "没有个体"
    kmc, atc = kaplan_meier([(100.0, 0, 3)], 3, [50.0, 100.0, 3600.0])
    assert atc[50.0]["survival_pct"] == 100.0 and atc[100.0]["survival_pct"] == 100.0 and atc[3600.0]["survival_pct"] is None, atc
    text = json.dumps(rep, ensure_ascii=False)
    assert_no_identifiers(text, ro)
    assert tn1 % 1 not in text and "judge.example" not in text
    md = markdown(rep)
    assert "常规列表" in md and "203.0.113.0/24" in md and tn3 % 11 not in md
    # 聚合器组 6 小时那格在 Markdown 里是“—”，不是 100.0%
    agg_row = [ln for ln in md.splitlines() if ln.startswith("| 聚合器抽样 |")][0]
    assert agg_row.split(" | ")[7].strip() == "—", agg_row
    # 泄露检测本身要能抓到：塞一个 ip:port 进去必须报错
    try:
        assert_no_identifiers(text + " " + A, ro)
    except SystemExit:
        pass
    else:
        raise AssertionError("assert_no_identifiers 没有抓到 ip:port")

    # —— --since 落在第二条 start 上：重启的间隔仍是真实的 3 小时，但停机在窗口之外；没有“状态清空”的警告 ——
    rep2 = build(ro, T0 + 13 * H, None, GAP_MIN_DEFAULT, 7, want_curve=False)
    w2 = rep2["window"]
    assert len(w2["restarts"]) == 1 and w2["restarts"][0]["at_since"] and abs(w2["restarts"][0]["gap_s"] - 3 * H) < 1e-6, w2["restarts"]
    assert w2["downtime"]["total_s"] == 0 and not w2["warnings"], (w2["downtime"], w2["warnings"])
    assert_no_identifiers(json.dumps(rep2, ensure_ascii=False), ro)

    # —— --since = T0+1h：B（0 可用）、E（0 可用）、F（0 可用）在 since 之前就可用过 → 左截断 3 个（常规 2、聚合器 1）；
    # 常规组窗口内曾可用 B、D、E、G → 4 个个体，剔除左截断后剩 D、G（都死亡）——
    rep3 = build(ro, T0 + H, None, GAP_MIN_DEFAULT, 7, want_curve=False)
    assert rep3["n"]["left_truncated_candidates"] == 3, rep3["n"]
    r3 = rep3["groups"]["regular"]
    assert r3["n"]["left_truncated_candidates"] == 2 and r3["first_life_km"]["n_subjects"] == 4, r3["n"]
    assert r3["first_life_km_excluding_left_truncated"]["n_subjects"] == 2 and r3["first_life_km_excluding_left_truncated"]["events"] == 2
    assert rep3["groups"]["aggregator_sample"]["n"]["left_truncated_candidates"] == 1
    assert any("左截断" in x for x in rep3["window"]["warnings"]), rep3["window"]["warnings"]
    ro.close()

    # —— 没有 cands 表（没送 state.json.gz 时 ingest.py 不建它）：退回并集口径，寿命结果不变 ——
    rw = sqlite3.connect(path)
    rw.execute("DROP TABLE cands")
    rw.commit()
    rep4 = build(rw, None, None, GAP_MIN_DEFAULT, 7, want_curve=False)
    assert "没有状态文件" in rep4["dense_prefixes_excluded"]["basis"] and "没有状态文件" in rep4["n"]["pool"]["basis"], rep4["dense_prefixes_excluded"]
    assert rep4["dense_prefixes_excluded"]["prefixes"] == rep["dense_prefixes_excluded"]["prefixes"]
    assert rep4["groups"]["regular"]["first_life_km"]["median_h"] == km["median_h"]
    # 并集口径的候选池：list_event ∪ agg_member = A B C E G F = 6，都探访过
    assert rep4["n"]["pool"] == dict(rep4["n"]["pool"], candidates_in_pool=6, candidates_never_visited=0)
    rw.close()
    if keep:
        os.replace(path, keep)
        print("合成库保留在", keep)
    else:
        os.unlink(path)
    print("selftest ok：%d 条探访、%d 个候选、常规组 %d 个个体（%d 死 %d 删失）、中位寿命 %s 小时、复活 %d 个" % (
        rep["n"]["visits_in_window"], rep["n"]["candidates_visited"], km["n_subjects"], km["events"], km["censored"],
        km["median_h"], res["candidates_revived"]))


# ---------------------------------------------------------------- 入口

def main():
    ap = argparse.ArgumentParser(description="寿命：Kaplan–Meier 生存分析（PROTOCOL“指标定义”表“寿命”行）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 lifetime.json")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--since", help="观察窗口起点（RFC 3339；默认第一条 start）。正式测量从状态清空那一刻重算时用它")
    ap.add_argument("--until", help="观察窗口终点（RFC 3339；默认最后一条 visit/stop）")
    ap.add_argument("--gap-min", type=float, default=GAP_MIN_DEFAULT, help="心跳缺席超过多少分钟算停机（默认 %d）" % GAP_MIN_DEFAULT)
    ap.add_argument("--dense-threshold", type=int, default=DENSE_PREFIX_THRESHOLD,
                    help="“候选密集的 /24”的阈值（默认 %d，PROTOCOL 1.2）" % DENSE_PREFIX_THRESHOLD)
    ap.add_argument("--no-curve", action="store_true", help="不输出逐 20 分钟的生存曲线点（缩小 JSON）")
    ap.add_argument("--selftest", nargs="?", const=True, default=False, metavar="保留路径",
                    help="在合成库上自检；给路径则把合成库保留在该处")
    args = ap.parse_args()
    if args.selftest:
        selftest(None if args.selftest is True else args.selftest)
        return
    if not args.db or not args.out:
        ap.error("--db 和 --out 必填（或用 --selftest）")
    since = parse_cli_time(args.since) if args.since else None
    until = parse_cli_time(args.until) if args.until else None
    conn = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(args.db), uri=True)
    conn.execute("PRAGMA cache_size = -131072")   # 128 MB 页缓存；TEMP 表落在 SQLite 的临时存储里，不随记录数占内存
    conn.execute("PRAGMA temp_store = FILE")
    t0 = time.time()
    rep = build(conn, since, until, args.gap_min, args.dense_threshold, want_curve=not args.no_curve)
    rep["seconds"] = round(time.time() - t0, 1)
    text = json.dumps(rep, ensure_ascii=False, indent=1)
    assert_no_identifiers(text, conn)
    md = markdown(rep)
    assert_no_identifiers(md, conn)
    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, OUTPUT_NAME)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    if args.markdown:
        sys.stdout.write(md)
    reg = rep["groups"]["regular"]["first_life_km"]
    sys.stderr.write("写出 %s：常规列表 %d 个个体（%d 死亡、%d 删失），中位寿命 %s 小时，用时 %.1f 秒\n" % (
        out_path, reg["n_subjects"], reg["events"], reg["censored"], reg["median_h"], rep["seconds"]))


if __name__ == "__main__":
    main()
