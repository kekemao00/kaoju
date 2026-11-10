#!/usr/bin/env python3
"""列表时效（第一阶段 1B，PROTOCOL“指标定义”表的“上榜新鲜度”“下榜滞后”两行，以及“要回答的问题”里
“列表更新得是否及时：上榜时还活着吗，死了多久才下榜，下榜的是不是其实还活着”）。

用法：
    python3 m_freshness.py --db <sqlite> --out <目录> [--markdown] [--since <时间>] [--until <时间>]
                           [--fresh-window-min 10] [--dense-threshold 100] [--no-series]
    python3 m_freshness.py --selftest [保留合成库的路径]

输出 <目录>/freshness.json；加 --markdown 时把主要表格以 Markdown 打印到标准输出。
库由 ingest.py 建好（表结构见 SCHEMA.md），本脚本以只读方式打开，不改它；中间结果都放在 SQLite 的 TEMP 库里。

算法（真实数据有一千多万条 att，本模块根本不碰 att；list_event 和 visit 的规模由列表的变动和探访次数决定）：
1. 把 list_event 按 (cand, ts_epoch) 的索引顺序流式扫一遍，逐个候选重放“哪些列表文件此刻列着它”，
   得到候选层面的上榜事件、下榜事件和来源层面的下榜事件，写进 TEMP 表。内存只保留一个候选的事件。
2. 指标全部用 SQL 在 TEMP 表与 visit 之间聚合（索引 visit(cand, ts_epoch)）。

口径（照 PROTOCOL 第 1.2 版；定义不清的地方取的解释写在 DEFINITIONS 和各处注释里）：

- 列表文件 = 来源 × 标签（lists.go 的 File），快照记录 snap 按文件写；base=1 是该文件在本进程里的第一次快照，
  add 列出全部条目（lists.go Snapshot()）。探测器每次启动都重来一遍首次快照，所以 base=1 的 add 不是新上榜。
- 候选“在榜” = 至少一个文件列着它（sched.go Cand.Listed()：len(Srcs) > 0）。文件集合按 summary.go snapLine 的办法重放：
  base 快照把该文件的集合重置为它的 add 列表，之后按 add/del 增减。
  由此推论：某文件 base 快照里没有的候选，如果之前在该文件里，就在那一刻被“无声地”移出（重启前后的差异不记 del 事件）；
  本模块把这种移出记为 silent=1 的下榜，时刻取 base 快照的时刻（Pool.Load 把它们记成重启时刻，相差几秒，见 checks）。
- 新上榜 = 候选在窗口内第一次出现在任何文件里，且那次是 base=0 的 add（kind='new'）。
  第一次出现是 base=1 的 add 的：首次启动那一轮叫 initial（观察起点时已在榜），重启那一轮叫 restart_base
  （停机期间上的榜，上榜时刻不知道）——都不算新上榜，只报条数。上榜前已在候选池里的（聚合器抽样条目后来出现在常规列表、
  上榜前已有探访记录、状态文件的 first_seen 早于上榜时刻）归 pool_already，也不算。下榜后又上榜的（kind='relist'）单独报告，
  不并入主指标。
- 可探测的新上榜 = kind='new' 且不是 pool_already、也不是按 sched.go ineligible() 永远不进候选池的条目（PROTOCOL“不探测的地址”）。
  “新上榜”的 total、“10 分钟内完成第一次探访”的分母、按来源与按小时的新上榜数都只数它；pool_already 与不进候选池的条目在旁边单列。
- 第一次探访 = 上榜时刻之后第一条非 aborted 的 visit；“完成”取 visit.ts + visit.ms（探访结束时刻）。
  上榜新鲜度只算完成时刻在上榜后 10 分钟内的条目（PROTOCOL 1.2“候选密集的地址段”），分子是那次探访可用（visit.n_ok > 0）。
  PROTOCOL 没写“约 10 分钟内”以开始还是完成为准，主口径取完成，另给按开始时刻算的一组看敏感性。
  其余条目（延迟超过 10 分钟、或窗口内没探访到）单独报告条数和延迟分布，按是否属于候选超过 100 个的 /24 分开。
  没探访到的再分：候选池里排队没探到（在状态文件里）、不进候选池（私网/保留地址、judge 自身、知名端口；规则照 sched.go ineligible()
  和 lists.go IsPublicV4；退出名单看不到）、原因不明。
- 下榜 = 候选从所有文件里消失（候选层面；对应 Pool.Delist 里 len(Srcs)==0 → DelistedAt）；
  来源层面的下榜 = 候选从某来源的全部文件里消失（候选可能仍在别的来源）。“按来源”的指标用后者。
  例外（聚合器）：抽样条目被 snapAggregators 以聚合器为来源 Upsert，这个来源不写 list_event；它后来进了常规列表（Group 改成 0，
  聚合器从此不再碰它）、常规列表再把它删掉时，prober 里 Srcs 仍含聚合器 → 仍在榜，直到下一次重启 Pool.Load 清空 Srcs。
  本模块把这种“从全部常规文件消失、但聚合器仍可能列着”的事件标 agg_held=1，候选层面的指标默认排除并单独计数。
- 换榜/抖动：下榜后很快（≤ 一轮快照，默认 10 分钟，--flap-min）又上榜的，不是列表“更新”，是换文件、两个来源几秒内一删一加、
  或一次坏抓取（status=200 的错误页解析出 0 条 → Del=全部，下一轮 Add=全部；lists.go Snapshot 对任何 200 正文都解析）。
  这类事件标 flap=1：候选层面与来源层面的“还活着”三组比例、滞后分布默认排除它们，另给含/不含两组。
  文件层面还检测抖动快照对：某次快照 n_del ≥ 上一次 n 的一半、下一次有变化的非 base 快照 n_add ≈ n_del（相差 ≤ 10%），
  两次快照的事件标 file_flap=1 并在 snapshots.files 里报出。
- 下榜滞后 = 下榜时刻 − 下榜前最后一次可用探访的时刻。下榜时按最后一次探访的结果分四类：没探访过、从未可用、仍可用、已死
  （曾可用，最后一次探访不可用）。“死了多久才下榜”看“已死”一类的滞后分布；“仍可用”一类的滞后只是距上次复测的时间。
- 下榜后 24 小时内仍可用 = 下榜后 24 小时内（探测器对下榜条目继续探测 24 小时，cfg DelistedGraceHours）至少一次探访可用。
  分母只含下榜时刻 + 24 小时不晚于观察结束、且这 24 小时里至少探访过一次的下榜事件；不足 24 小时的单独计数。
  “下榜后第一次探访”限于下榜后 24 小时内、且在再上榜之前的探访。
- 各来源每次快照的增减序列直接来自 snap 表（n_add、n_del、n、status、changed、base）。来源层面的“一轮”= 同一来源内按时间相邻、
  没有文件重复、相邻间隔 ≤ 5 分钟的一串快照（一轮内各文件顺序抓取，可能跨分钟；重启后的 base 轮与前一轮可能只隔几十秒）。
- 观察窗口：起点默认第一条 start；之后若有 resumed_candidates=0 的 start（状态被清空）或版本变了，取最后一次这样的 start
  （PROTOCOL“正式测量的起止”）；--since/--until 覆盖。起点之前的事件不发事件；上榜时刻早于起点的条目不算新上榜。
  --since 落在运行中间（不在某条 start 的 ±5 秒内）时，先从各文件在起点之前最近一次 base 快照起静默重放到起点（重启时刻清空，
  照 Pool.Load），把起点时在榜的候选记成 implicit_initial；落在 start 上时起点的在榜状态为空（Pool.Load 清空了 Srcs），不用预热。

输出里不出现任何地址、主机名、哈希：维度只用白名单列（ingest.OUTPUT_WHITELIST / meta.output_whitelist），写出前再扫一遍。
只用 Python 3.10+ 标准库。
"""
import argparse
import bisect
import collections
import datetime as dt
import itertools
import json
import os
import re
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import ingest  # noqa: E402  OUTPUT_WHITELIST、parse_ts
except Exception:  # 库里的 meta.output_whitelist 是后备
    ingest = None

MODULE = "m_freshness"
OUTPUT_NAME = "freshness.json"
PROTOCOL_VERSION = "1.2"
FRESH_WINDOW_MIN = 10        # PROTOCOL：上榜后约 10 分钟内的第一次探访
DELIST_FOLLOWUP_H = 24       # PROTOCOL“频率与限速”：下榜的条目继续探测 24 小时；“下榜后 24 小时内仍可用”
DENSE_THRESHOLD = 100        # PROTOCOL 1.2“候选密集的地址段”：候选超过 100 个的 /24
SNAPSHOT_MIN_NOMINAL = 10    # PROTOCOL“组成”：每 10 分钟抓一次各列表
FLAP_MIN = 10                # 下榜后 ≤ 一轮快照（10 分钟）又上榜 → 换榜/抖动，不算下榜（--flap-min 可改）
FLAP_ADD_TOL = 0.10          # 文件层面抖动：下一次有变化的非 base 快照 n_add 与本次 n_del 相差 ≤ 10% 算“≈”
ROUND_GAP_MIN = 5            # 同一来源内相邻快照间隔 ≤ 5 分钟且文件不重复 → 同一轮（SnapshotMin 的一半）
MATCH_TOL_S = 1.0            # 与状态文件比对时允许的时间差（同一个 now 写两处，应完全相等）
RESTART_TOL_S = 5.0          # cands.delisted_at 落在某次 start 前后 5 秒内 → Pool.Load 的重启痕迹；--since 落在 start ±5 秒内算“在 start 上”
QUANTILES = (0.10, 0.25, 0.50, 0.75, 0.90)
DELAY_BUCKETS_MIN = [(0, 10), (10, 30), (30, 60), (60, 180), (180, 360), (360, 720), (720, 1440), (1440, None)]
LAG_BUCKETS_MIN = [(0, 20), (20, 60), (60, 120), (120, 360), (360, 720), (720, 1440), (1440, 2880), (2880, None)]
# lists.go reserved：不探测的保留地址段（sched.go ineligible() 的 not_public）
RESERVED_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
               "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
               "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]

# 本模块会进入输出（作维度或被聚合）的列。只在库内做 JOIN 的键（list_event.cand、visit.cand、cands.key、agg_member.cand）
# 和只用于分类、不进输出的列（list_event.cand_ip、cand_port；start.raw 里的 skip_ports；snap.err 只在谓词里）不在这里。
OUTPUT_COLUMNS = {
    "list_event": ["src", "label", "event", "base", "prefix24", "ts_epoch"],
    "snap": ["src", "label", "status", "n", "base", "agg", "changed", "n_add", "n_del", "ms", "ts_epoch"],
    "visit": ["state", "n_ok", "aborted", "listed", "group", "ms", "prefix24", "ts_epoch"],
    "cands": ["prefix24", "group", "listed", "visits", "first_seen_epoch", "delisted_at_epoch", "state_name", "ever_ok"],
    "agg_member": ["src", "ts_epoch"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["ts_epoch"],
    "version": ["version", "ts_epoch"],
    "stat_pool": ["key", "value", "ts_epoch"],
    "meta": ["ingest_version", "first_ts", "last_ts", "state_cands", "state_tz_offsets"],
}

DEFINITIONS = {
    "列表文件": "来源 × 标签（lists.go File）。snap 记录按文件写，base=1 是该文件在本进程里的第一次快照、add 为全部条目；"
             "探测器每次启动都重来一遍首次快照。PROTOCOL“组成”“记录”。",
    "在榜": "至少一个列表文件此刻列着该候选（sched.go Cand.Listed()）。文件集合按 summary.go snapLine 重放：base 快照重置集合，之后按 add/del 增减。",
    "新上榜（kind=new）": "候选在观察窗口内第一次出现在任何文件里，且那次是 base=0 的 add；上榜时刻取那条 snap 的 ts。"
                     "首次启动的 base 快照（initial）、重启的 base 快照（restart_base）、上榜前已在候选池（pool_already：上榜前有探访、"
                     "聚合器抽样在先、或状态文件 first_seen 早于上榜时刻 1 秒以上）、下榜后再上榜（relist）都不算，只报条数。"
                     "PROTOCOL“指标定义”表“上榜新鲜度”行；本模块对“新”的解释。",
    "可探测的新上榜": "kind='new' 且分类不是 pool_already、也不是 never_visited_ineligible（sched.go ineligible() 永远不进候选池的条目，"
                "PROTOCOL“不探测的地址”）。“新上榜”的 total、“10 分钟内完成第一次探访”的分母、按来源与按小时的新上榜数都只数它。",
    "第一次探访": "上榜时刻之后该候选第一条非 aborted 的 visit（不限于该次上榜结束之前：上榜几分钟就下榜、下榜后才被探访的也算）；"
             "完成时刻 = visit.ts + visit.ms。延迟 = 完成时刻 − 上榜时刻；另给按开始时刻（visit.ts）算的延迟。",
    "上榜新鲜度": "可探测的新上榜里第一次探访在上榜后 10 分钟内完成的条目中，那次探访可用（visit.n_ok > 0，等价于 state='working'）的比例。"
              "PROTOCOL“指标定义”表“上榜新鲜度”行；只算 10 分钟内完成的，见 1.2 版“候选密集的地址段”。PROTOCOL 没写以开始还是完成为准，"
              "主口径取完成，另给按开始时刻算的一组。",
    "第一次探访延迟超过 10 分钟 / 没探访到": "可探测的新上榜里不满足 10 分钟条件的条目：分别报条数和延迟分布，按是否属于候选超过 100 个的 /24 分开。"
                              "没探访到的再分：候选池里排队没探到（在状态文件 cands 里）、原因不明。不进候选池的（sched.go ineligible()："
                              "私网/保留地址、judge 自身、知名端口；退出名单看不到）不算新上榜，按原因在旁边单列。PROTOCOL 1.2“候选密集的地址段”。",
    "下榜（候选层面）": "候选从所有列表文件里消失的时刻（Pool.Delist：len(Srcs)==0 → DelistedAt）。某文件 base 快照里没有它、而它之前在该文件里的，"
                 "记为无声下榜（silent=1），时刻取 base 快照时刻。聚合器仍可能列着的（agg_held=1，见下）默认排除。",
    "agg_held（聚合器仍可能列着）": "候选是聚合器抽样条目（agg_member，抽样时刻 ≤ 事件时刻），且自它第一次出现在常规文件起到事件时刻之间没有重启。"
                          "snapAggregators 以聚合器为来源 Upsert 抽样条目但不写 list_event；它进了常规列表后 Group 改成 0、聚合器不再碰它，"
                          "Srcs 里的聚合器来源一直留到下一次 Pool.Load（重启）才清空。所以常规列表删掉它时 prober 里它仍在榜，下榜时刻不可知。"
                          "候选层面的指标默认排除这类事件并单独计数；来源层面不受影响。",
    "flap（换榜/抖动）": "下榜后 ≤ flap_min（默认 10 分钟，一轮快照）又上榜的下榜事件（relist_gap_s ≤ flap_min×60），或属于文件层面抖动快照对的事件"
                   "（file_flap=1：某次快照 n_del ≥ 上一次 n 的一半，且下一次有变化的非 base 快照 n_add 与 n_del 相差 ≤ 10%；"
                   "典型原因是 status=200 的错误页被 lists.go Snapshot 解析成 0 条）。这不是列表更新，默认排除，另给含抖动的一组。",
    "下榜（来源层面）": "候选从某来源的全部文件里消失；候选可能仍在别的来源（still_listed_elsewhere，只看常规文件）。“按来源”的指标用它。",
    "下榜时的状态": "按下榜前最后一次探访分四类：没探访过（never_visited_before）、从未可用（never_ok_before）、仍可用（ok_at_delist）、"
               "已死（died_before_delist：曾可用、最后一次探访不可用）。",
    "下榜滞后": "下榜时刻 − 下榜前最后一次可用探访的 visit.ts。主分布看“已死”一类（这才是“死了多久才下榜”）；“仍可用”一类的滞后只是距上次复测的时间，"
             "另列。PROTOCOL“指标定义”表“下榜滞后”行。",
    "在榜时长": "下榜时刻 − 这次在榜期间的上榜时刻（fr_listing.t_add；implicit_initial / initial 的上榜时刻是观察起点，所以是下界）。",
    "下榜后第一次探访可用": "下榜后 24 小时内、且在再上榜之前（若有）的第一条探访可用的比例；分母是有这样一条探访的下榜事件。",
    "下榜后 24 小时内仍可用": "下榜后 24 小时内至少一次探访可用的下榜事件比例。分母：下榜时刻 + 24 小时 ≤ 观察结束、且这 24 小时内至少探访过一次的下榜事件；"
                      "不足 24 小时（followup_incomplete）和 24 小时内没探访（not_probed_after）的单独计数。PROTOCOL“指标定义”表“下榜滞后”行、"
                      "“频率与限速”（下榜的条目继续探测 24 小时）。",
    "下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）": "分析时补的变体（不是 PROTOCOL 事先写下的口径）：分子分母都只留 24 小时内没再上榜"
                                                 "（relisted_within=0）的事件，这样 24 小时里的探访都在下榜期间。",
    "下榜的是不是其实还活着": "三个角度：下榜时最后一次探访仍可用的比例；下榜后第一次探访可用的比例；下榜后 24 小时内仍可用的比例。"
                    "默认不含 flap 与 agg_held 的事件，旁边给含它们的一组。PROTOCOL“要回答的问题”。",
    "快照增减序列": "snap 表每条记录的 n_add / n_del / n / status / changed / base，按文件（来源 × 标签）排列；base=1 的 add 数单列，不算增量。"
               "来源层面的“一轮”：同一来源内按时间相邻、文件不重复、相邻间隔 ≤ 5 分钟的一串快照，时间取第一条快照。PROTOCOL“组成”（每 10 分钟抓一次）。",
    "候选密集的 /24": "候选数超过阈值（默认 100）的 /24；候选 = 状态文件 cands 的全部行（没有状态文件时用 list_event ∪ agg_member ∪ visit 的候选并集）。"
                  "“探访到”= 窗口内有非 aborted 探访的候选数。PROTOCOL 1.2“候选密集的地址段”。",
    "观察窗口": "起点默认第一条 start；之后若有 resumed_candidates=0 的 start（状态被清空）或版本变了，取最后一次这样的 start。"
             "终点取 visit / snap / stop 里最晚的时刻。起点之前的事件不发事件。--since 落在运行中间时从各文件起点前最近一次 base 快照起"
             "静默重放（重启时刻清空，照 Pool.Load），起点时在榜的记成 implicit_initial。PROTOCOL“正式测量的起止”。",
    "起点后第一小时": "PROTOCOL“已知局限”：启动后约一小时候选池从空开始排队，间隔偏长。新鲜度另按“起点后 1 小时内上榜 / 1 小时后上榜”分两组。",
    "分位数": "nearest-rank：p_q = 升序排第 ceil(q·n) 位的值（n=2 时 p50 取较小的那个）；mean 是算术平均。",
    "百分比": "100 × 分子 / 分母，保留一位小数；分母为 0 时为 null。每个比例都同时给出分子（num）和分母（den）。",
}


# ---------------------------------------------------------------- 小工具

def pct(num, den):
    return None if not den else round(100.0 * num / den, 1)


def ratio(num, den):
    return {"num": int(num or 0), "den": int(den or 0), "pct": pct(int(num or 0), int(den or 0))}


def iso_minute(epoch):
    if epoch is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime(epoch))


def iso_hour(epoch):
    if epoch is None:
        return None
    return time.strftime("%Y-%m-%dT%H:00Z", time.gmtime(epoch))


def iso_second(epoch):
    if epoch is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def ts_text(epoch):
    """浮点秒 → 记录里 ts 的格式（只给合成库用）。"""
    ms = int(round(epoch * 1000))
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms // 1000)) + ".%03dZ" % (ms % 1000)


def parse_cli_time(s):
    """--since/--until：RFC 3339（Z 或带偏移，带偏移的换算成 UTC）。"""
    if ingest is not None:
        _, epoch, _ = ingest.parse_ts(s)
    else:
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            epoch = d.timestamp() if d.tzinfo else None
        except ValueError:
            epoch = None
    if epoch is None:
        raise SystemExit("时间格式不对：%r（要 RFC 3339，如 2026-11-06T08:06:00Z 或 2026-11-06T16:06:00+08:00）" % s)
    return epoch


def minutes(sec):
    return None if sec is None else round(sec / 60.0, 1)


def hours(sec):
    return None if sec is None else round(sec / 3600.0, 2)


def _ip_int(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


_RESERVED = []
for _cidr in RESERVED_V4:
    _net, _bits = _cidr.split("/")
    _mask = (0xFFFFFFFF << (32 - int(_bits))) & 0xFFFFFFFF
    _RESERVED.append((_ip_int(_net) & _mask, _mask))


def _cidrs(cidrs):
    out = []
    for cidr in cidrs:
        net, bits = cidr.split("/")
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
        out.append((_ip_int(net) & mask, mask))
    return out


def is_public_v4(ip, public_extra=()):
    """lists.go IsPublicV4：不在保留段里的 IPv4。public_extra 是例外地址段（已按 _cidrs 解析），落在里面的当作公网：
    只给合成库用——合成库的地址取自 RFC 5737 文档段，不能让它们全部落进 not_public。"""
    try:
        v = _ip_int(ip)
    except (ValueError, AttributeError):
        return False
    if any((v & m) == n for n, m in public_extra):
        return True
    return not any((v & m) == n for n, m in _RESERVED)


# sched.go ineligible() 需要的规则。self_ips：judge 的公网 IP（不输出）；skip_ports：start.raw 的 probe.skip_ports（不输出）；
# enforce_public：cfg.AllowLocal 的反面（False 对应 allowLo，自检夹具允许回环地址）；public_extra：见 is_public_v4。
PoolRules = collections.namedtuple("PoolRules", "self_ips skip_ports enforce_public public_extra")


def ineligible(ip, port, rules):
    """sched.go ineligible()：self / not_public / skip_port，按这个顺序；excluded（退出名单）数据里看不到。"""
    if ip is None:
        return "unparsable"
    if ip in rules.self_ips:
        return "self"
    if rules.enforce_public and not is_public_v4(ip, rules.public_extra):
        return "not_public"
    if port in rules.skip_ports:
        return "skip_port"
    return None


class DB:
    def __init__(self, path):
        # mode=ro：库文件只读；临时表都建在 TEMP 库里（query_only 会连 TEMP 表一起禁掉，所以不用它）
        self.con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(path), uri=True)
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
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','view') AND name=?", (name,)) > 0

    def columns(self, table):
        return [r[1] for r in self.q('PRAGMA table_info("%s")' % table)]

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))


def check_whitelist(db):
    """输出前按白名单核对本模块用到的列。优先用同目录 ingest.py 的权威常量，拿不到就读库里的 meta.output_whitelist。"""
    wl, source = None, None
    if ingest is not None:
        wl, source = ingest.OUTPUT_WHITELIST, "ingest.OUTPUT_WHITELIST"
    else:
        raw = db.meta("output_whitelist")
        if raw:
            wl, source = json.loads(raw), "meta.output_whitelist"
    if wl is None:
        raise SystemExit("拿不到可输出列白名单（ingest.py 不可导入，库里也没有 meta.output_whitelist），拒绝输出")
    problems = []
    for table, cols in OUTPUT_COLUMNS.items():
        if ingest is not None:
            try:
                ingest.check_output_columns(table, cols)  # 权威检查（SCHEMA.md“可输出列白名单”）
            except ValueError as e:
                problems.append(str(e))
            continue
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

def observation_window(db, since, until):
    """正式起点、终点、重启。PROTOCOL“正式测量的起止”；规则与 m_availability.observation_window 相同。"""
    starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0) FROM start ORDER BY ts_epoch") if db.has_table("start") else []
    stops = [r[0] for r in db.q("SELECT ts_epoch FROM stop ORDER BY ts_epoch")] if db.has_table("stop") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch") if db.has_table("version") else []
    first_snap = db.scalar("SELECT MIN(ts_epoch) FROM snap")
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
        fs = first_snap
        rule.append("没有 start 记录：取第一条 snap")
    # --since 落在某条 start 的 ±RESTART_TOL_S 秒内算“在 start 上”：那一刻 Pool.Load 刚清空 Srcs，起点的在榜状态为空，不用预热。
    # 落在运行中间时要预热：从各常规文件在起点之前最近一次 base 快照起静默重放到起点，否则起点时已在榜的候选会被错记成
    # restart_base / 漏掉起点前上榜、起点后无声移出的候选（核对者意见）。
    since_on_start = None
    pre = None
    if since is not None:
        fs, rule = since, ["--since 指定"]
        since_on_start = any(abs(since - s[0]) <= RESTART_TOL_S for s in starts)
        if not since_on_start:
            last_bases = [r[0] for r in db.q("SELECT MAX(ts_epoch) FROM snap WHERE COALESCE(agg, 0) = 0 AND COALESCE(base, 0) = 1 "
                                             "AND ts_epoch <= ? GROUP BY src, label", (fs,))]
            pre = min(last_bases) if last_bases else fs
            rule.append("起点在运行中间：从各文件起点前最近一次 base 快照起静默预热，起点时在榜的记为 implicit_initial")
        else:
            rule.append("起点落在某条 start 上：起点的在榜状态为空（Pool.Load），不预热")
    ends = []
    for t in ("visit", "snap", "stop"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None
    if until is not None:
        end = until
    if fs is None or end is None:
        raise SystemExit("库里没有 snap/visit 记录，算不了列表时效")
    if pre is None:
        pre = fs
    # 窗口内的重启（起点之后的 start）：它们之后的 base 快照不是新上榜
    restarts = []
    for i, (ep, resumed) in enumerate(starts):
        if ep <= fs or ep > end:
            continue
        prev_stop = max((s for s in stops if s < ep), default=None)
        restarts.append({"start_utc": iso_minute(ep), "stop_before_utc": iso_minute(prev_stop),
                         "gap_min": minutes(ep - prev_stop) if prev_stop is not None else None,
                         "resumed_candidates": resumed, "state_cleared": resumed == 0, "_t": ep})
    return {
        "obs_start_utc": iso_minute(fs), "obs_end_utc": iso_minute(end), "hours": hours(end - fs),
        "rule": "；".join(rule),
        "since_on_start": since_on_start,
        "warm_up_from_utc": iso_minute(pre) if pre < fs else None,
        "starts": [{"utc": iso_minute(s[0]), "resumed_candidates": s[1]} for s in starts],
        "stops": [iso_minute(s) for s in stops],
        "versions": sorted({v for _, v in versions}),
        "restarts_in_window": restarts,
        "events_before_start_ignored": int(db.scalar("SELECT COUNT(*) FROM list_event WHERE ts_epoch < ?", (pre,)) or 0),
        "events_in_warm_up": int(db.scalar("SELECT COUNT(*) FROM list_event WHERE ts_epoch >= ? AND ts_epoch < ?", (pre, fs)) or 0),
        "_fs": fs, "_end": end, "_pre": pre, "_restart_times": [r["_t"] for r in restarts],
    }


# ---------------------------------------------------------------- 逐候选重放列表事件

TEMP_SCHEMA = """
CREATE TEMP TABLE fr_cand (cand TEXT PRIMARY KEY, prefix24 TEXT, inelig TEXT, n_listings INTEGER, n_delists INTEGER,
    first_kind TEXT, listed_end INTEGER, anomalies INTEGER);
CREATE TEMP TABLE fr_listing (lid INTEGER PRIMARY KEY, cand TEXT, prefix24 TEXT, t_add REAL, kind TEXT, listing_no INTEGER,
    t_end REAL, n_srcs INTEGER, relist_gap_s REAL, file_flap INTEGER);
CREATE TEMP TABLE fr_listing_src (lid INTEGER, src TEXT);
CREATE TEMP TABLE fr_delist (did INTEGER PRIMARY KEY, cand TEXT, prefix24 TEXT, t_delist REAL, silent INTEGER, delist_no INTEGER,
    t_relist REAL, t_listed REAL, file_flap INTEGER, agg_sampled INTEGER, agg_held INTEGER);
CREATE TEMP TABLE fr_delist_src (did INTEGER, src TEXT);
CREATE TEMP TABLE fr_src_delist (sid INTEGER PRIMARY KEY, cand TEXT, prefix24 TEXT, src TEXT, t_delist REAL, silent INTEGER,
    t_relist REAL, still_listed_elsewhere INTEGER, file_flap INTEGER, agg_held INTEGER);
CREATE TEMP TABLE fr_src_listing (cand TEXT, src TEXT, t_add REAL, kind TEXT);
"""
# fr_listing.relist_gap_s：kind 为 relist / relist_base 时，距上一次候选层面下榜的秒数（上一次下榜在窗口外时为 NULL）。
# fr_delist.t_listed：这次在榜期间的上榜时刻（fr_listing.t_add）。file_flap / agg_sampled / agg_held 见 DEFINITIONS。


class Replay:
    """把 list_event 按候选重放成上榜/下榜事件。

    base_times：{(src, label): 按时间排序的 base 快照时刻}。候选在某文件里、而该文件之后的 base 快照没有它 → 无声移出。
    restart_times：窗口内的 start 时刻；base 快照发生在第一次重启之后的叫 restart_base，否则 initial。
    starts_all：全部 start 时刻。预热期间（pre ≤ t < fs）遇到 start 把在榜文件集合清空（Pool.Load）；判断 agg_held 时也用它。
    agg_sample：{cand: 抽样时刻}（agg_member）。flap_pairs：load_flap_pairs 的结果，文件层面的抖动快照对。
    pre：预热起点（--since 落在运行中间时 < fs，否则 = fs）。pre ≤ t < fs 的事件只更新文件集合，不发事件。
    """

    BATCH = 2000

    def __init__(self, db, fs, end, base_times, restart_times, starts_all, rules, agg_sample=None, flap_pairs=None, pre=None):
        self.db, self.fs, self.end = db, fs, end
        self.pre = fs if pre is None else pre
        self.base_times = base_times
        self.first_restart = min(restart_times) if restart_times else None
        self.starts_all = sorted(starts_all)
        self.rules = rules
        self.agg_sample = agg_sample or {}
        self.flap_del, self.flap_add = (flap_pairs or ({}, set(), set()))[1:]
        self.rows = collections.defaultdict(list)
        self.lid = self.did = self.sid = 0
        self.stats = collections.Counter()

    def flush(self, force=False):
        sqls = {
            "fr_cand": "INSERT INTO fr_cand VALUES (?,?,?,?,?,?,?,?)",
            "fr_listing": "INSERT INTO fr_listing VALUES (?,?,?,?,?,?,?,?,?,?)",
            "fr_listing_src": "INSERT INTO fr_listing_src VALUES (?,?)",
            "fr_delist": "INSERT INTO fr_delist VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            "fr_delist_src": "INSERT INTO fr_delist_src VALUES (?,?)",
            "fr_src_delist": "INSERT INTO fr_src_delist VALUES (?,?,?,?,?,?,?,?,?,?)",
            "fr_src_listing": "INSERT INTO fr_src_listing VALUES (?,?,?,?)",
        }
        for t, rows in self.rows.items():
            if rows and (force or len(rows) >= self.BATCH):
                self.db.con.executemany(sqls[t], rows)
                rows.clear()

    def run(self):
        self.db.con.executescript(TEMP_SCHEMA)
        cur = self.db.con.execute(
            "SELECT cand, prefix24, cand_ip, cand_port, ts_epoch, src, label, event, COALESCE(base, 0) "
            "FROM list_event WHERE ts_epoch BETWEEN ? AND ? ORDER BY cand, ts_epoch", (self.pre, self.end))
        for cand, group in itertools.groupby(cur, key=lambda r: r[0]):
            rows = list(group)
            self.one_cand(cand, rows[0][1], rows[0][2], rows[0][3], [(r[4], r[5], r[6], r[7], r[8]) for r in rows])
            self.flush()
        self.flush(force=True)
        for t in ("fr_listing", "fr_delist", "fr_src_delist", "fr_src_listing"):
            self.db.x("CREATE INDEX temp.%s_cand ON %s(cand)" % (t, t))
        self.db.x("CREATE INDEX temp.fr_listing_src_lid ON fr_listing_src(lid)")
        self.db.x("CREATE INDEX temp.fr_delist_src_did ON fr_delist_src(did)")
        self.db.x("CREATE INDEX temp.fr_listing_kind ON fr_listing(kind)")
        return self.stats

    def one_cand(self, cand, prefix24, ip, port, events):
        """events：按时间排序的 (t, src, label, event, base)。同一时刻先加后减，免得“换文件”被记成一次零时长的下榜。

        一个候选的全部结果先攒在局部变量里（下榜行要等到再上榜时才知道 t_relist），候选处理完再一起交给 self.rows。
        """
        st = self.stats
        fs = self.fs
        in_files = set()
        src_n = collections.Counter()
        listed = False
        listing_no = delist_no = anomalies = 0
        first_kind = None
        open_listing = None     # [lid, t_add, kind, listing_no, srcs, relist_gap_s, file_flap]
        open_delist = None      # did，等着被再上榜填 t_relist
        open_src_delist = {}    # src → sid
        src_listed_since = {}
        last_t = self.pre
        ever_added = False      # 窗口内或预热期间有过 add（预热期间上过榜、起点前下榜、起点后再出现的记为 relist）
        first_reg_add = None    # 第一次出现在常规文件的时刻（含预热；再早的看不到，agg_held 的判断以此为准，见 DEFINITIONS）
        quiet = self.pre < fs   # 预热模式：只更新文件集合，不发事件
        t_sample = self.agg_sample.get(cand)
        L_listing, L_listing_src, L_src_listing = [], [], []
        L_delist, L_delist_src, L_src_delist = {}, [], {}   # did → 行（list）；sid → 行（list）

        def agg_held_at(t):
            """聚合器是否仍可能列着它（DEFINITIONS“agg_held”）。抽样在事件之前、且第一次进常规文件之后到 t 之间没有重启（Pool.Load 会清空
            Srcs，而 Group 已是 0、聚合器不再 Upsert）。预热前就进了常规文件的，first_reg_add 取已知的最早时刻（偏晚 → 偏向判为 held，保守）。"""
            if t_sample is None or t_sample > t:
                return 0, 0
            since = first_reg_add if first_reg_add is not None else t
            i = bisect.bisect_right(self.starts_all, since)
            held = not (i < len(self.starts_all) and self.starts_all[i] <= t)
            return 1, 1 if held else 0

        def emit_listing(t, kind, srcs, file_flap=0):
            nonlocal listing_no, open_listing, first_kind, open_delist
            listing_no += 1
            self.lid += 1
            gap = None
            if open_delist is not None:
                L_delist[open_delist][6] = t   # t_relist
                gap = t - L_delist[open_delist][3]
                open_delist = None
            open_listing = [self.lid, t, kind, listing_no, set(srcs), gap, file_flap]
            if first_kind is None:
                first_kind = kind
            st["listing_" + kind] += 1

        def close_listing(t):
            nonlocal open_listing
            lid, t_add, kind, no, srcs, gap, file_flap = open_listing
            L_listing.append((lid, cand, prefix24, t_add, kind, no, t, len(srcs), gap, file_flap))
            for s in srcs:
                L_listing_src.append((lid, s))
            open_listing = None

        def add(t, src, label, base, group_srcs):
            nonlocal listed, ever_added, first_reg_add
            f = (src, label)
            if f in in_files:
                return  # base 快照里再次列出仍在榜的候选：延续，不是事件
            in_files.add(f)
            src_n[src] += 1
            if first_reg_add is None:
                first_reg_add = t
            if quiet:
                src_listed_since[src] = t
                ever_added = True
                return
            if src_n[src] == 1:
                src_listed_since[src] = t
                sid = open_src_delist.pop(src, None)
                if sid is not None:
                    L_src_delist[sid][6] = t   # t_relist
                L_src_listing.append((cand, src, t, "base" if base else ("relist" if sid is not None else "new")))
            if not listed:
                listed = True
                if base:
                    if ever_added or listing_no > 0:
                        kind = "relist_base"
                    elif self.first_restart is not None and t >= self.first_restart:
                        kind = "restart_base"
                    else:
                        kind = "initial"
                else:
                    kind = "relist" if (ever_added or listing_no > 0) else "new"
                emit_listing(t, kind, group_srcs, 1 if (not base and (f, t) in self.flap_add) else 0)
            ever_added = True

        def remove(t, src, label, silent, group_srcs):
            nonlocal listed, delist_no, anomalies, open_delist
            f = (src, label)
            if f not in in_files:
                if not quiet:
                    anomalies += 1
                    st["anomaly_del_not_listed"] += 1
                return
            in_files.discard(f)
            src_n[src] -= 1
            if src_n[src] == 0:
                del src_n[src]
            if quiet:
                return
            file_flap = 1 if (not silent and (f, t) in self.flap_del) else 0
            agg_sampled, agg_held = agg_held_at(t)
            if src not in src_n:
                self.sid += 1
                L_src_delist[self.sid] = [self.sid, cand, prefix24, src, t, 1 if silent else 0, None, 1 if in_files else 0, file_flap, agg_held]
                open_src_delist[src] = self.sid
                st["src_delist"] += 1
                if silent:
                    st["src_delist_silent"] += 1
            if not in_files and listed:
                listed = False
                delist_no += 1
                self.did += 1
                t_listed = open_listing[1]
                close_listing(t)
                L_delist[self.did] = [self.did, cand, prefix24, t, 1 if silent else 0, delist_no, None, t_listed, file_flap, agg_sampled, agg_held]
                for s in group_srcs:
                    L_delist_src.append((self.did, s))
                open_delist = self.did
                st["delist"] += 1
                if silent:
                    st["delist_silent"] += 1
                if file_flap:
                    st["delist_file_flap"] += 1
                if agg_held:
                    st["delist_agg_held"] += 1

        def silent_drops(lo, hi, include_hi=False, exclude=()):
            """候选所在的文件在 (lo, hi)（include_hi 时为 (lo, hi]）内有 base 快照、而快照里没有它 → 无声移出，按时间顺序处理。
            exclude 是在 hi 时刻有 add 事件的文件：那次 base 快照列着它，不是移出。"""
            drops = []
            for f in list(in_files):
                if f in exclude:
                    continue
                bt = self.base_times.get(f)
                if not bt:
                    continue
                i = bisect.bisect_right(bt, lo)
                if i < len(bt) and (bt[i] < hi or (include_hi and bt[i] == hi)):
                    drops.append((bt[i], f))
            for b, (src, label) in sorted(drops):
                remove(b, src, label, True, [src])

        def warm_up_restarts(lo, hi):
            """预热期间 (lo, hi] 内的 start：Pool.Load 清空 Srcs，之后由各文件的 base 快照重建。"""
            i = bisect.bisect_right(self.starts_all, lo)
            while i < len(self.starts_all) and self.starts_all[i] <= hi:
                in_files.clear()
                src_n.clear()
                i += 1

        def leave_warm_up():
            """到达观察起点：预热期间的无声移出和重启先结清，起点时还在榜的记一条 implicit_initial（上榜时刻取起点）。"""
            nonlocal quiet, listed, last_t
            silent_drops(last_t, fs)
            warm_up_restarts(last_t, fs)   # 起点 ±5 秒内有 start 的情形由 observation_window 判为“在 start 上”，根本不进预热
            quiet = False
            last_t = fs
            if in_files:
                listed = True
                srcs = sorted(src_n)
                for s in srcs:
                    src_listed_since[s] = fs
                    L_src_listing.append((cand, s, fs, "implicit_initial"))
                emit_listing(fs, "implicit_initial", srcs)

        i = 0
        n = len(events)
        while i < n:
            t = events[i][0]
            if quiet and t >= fs:
                leave_warm_up()
            if quiet:
                warm_up_restarts(last_t, t)
            silent_drops(last_t, t)  # 严格早于 t 的 base 快照
            j = i
            adds, dels = [], []
            while j < n and events[j][0] == t:
                _, src, label, ev, base = events[j]
                (adds if ev == "add" else dels).append((src, label, base))
                j += 1
            add_srcs = sorted({s for s, _, _ in adds})
            del_srcs = sorted({s for s, _, _ in dels})
            for src, label, base in adds:
                add(t, src, label, base, add_srcs)
            # 恰在 t 时刻、别的文件的 base 快照里消失：放在同一时刻的 add 之后，免得“换文件”被记成一次零时长的下榜
            silent_drops(last_t, t, include_hi=True, exclude={(s, l) for s, l, _ in adds})
            for src, label, _ in dels:
                remove(t, src, label, False, del_srcs)
            last_t = t
            i = j
        if quiet:
            leave_warm_up()
        silent_drops(last_t, self.end, include_hi=True)
        if open_listing is not None:
            close_listing(None)
        self.rows["fr_listing"].extend(L_listing)
        self.rows["fr_listing_src"].extend(L_listing_src)
        self.rows["fr_src_listing"].extend(L_src_listing)
        self.rows["fr_delist"].extend(tuple(r) for r in L_delist.values())
        self.rows["fr_delist_src"].extend(L_delist_src)
        self.rows["fr_src_delist"].extend(tuple(r) for r in L_src_delist.values())
        inel = ineligible(ip, port, self.rules)
        self.rows["fr_cand"].append((cand, prefix24, inel, listing_no, delist_no, first_kind, 1 if listed else 0, anomalies))
        st["cands"] += 1
        if inel:
            st["inelig_" + inel] += 1


def load_base_times(db, fs, end):
    """{(src, label): [base 快照时刻…]}，只看常规列表文件（agg=0）。"""
    out = collections.defaultdict(list)
    for src, label, t in db.q("SELECT src, label, ts_epoch FROM snap WHERE COALESCE(agg, 0) = 0 AND COALESCE(base, 0) = 1 "
                              "AND ts_epoch BETWEEN ? AND ? ORDER BY ts_epoch", (fs, end)):
        out[(src, label)].append(t)
    return out


def load_pool_rules(db, enforce_public=None, public_extra=()):
    """sched.go ineligible() 需要的规则（PoolRules）：judge 的公网 IP（self_ips，不输出）、不探测的端口（start.raw 的 probe.skip_ports，不输出）、
    not_public 规则是否生效。enforce_public=None 时从数据推断；显式给 True/False 时照用（合成库用）。"""
    self_ips = set()
    if db.has_table("self_ips"):
        self_ips = {r[0] for r in db.q("SELECT ip FROM self_ips WHERE source = 'start.judge_ip'")}
    skip_ports = set()
    if db.has_table("start") and "raw" in db.columns("start"):
        for (raw,) in db.q("SELECT raw FROM start"):
            try:
                skip_ports.update(int(p) for p in (json.loads(raw).get("probe") or {}).get("skip_ports") or [])
            except (ValueError, TypeError, AttributeError):
                pass
    if enforce_public is None:
        # cfg.AllowLocal 是 json:"-"，记录里没有；候选池里有保留段的地址（/24 前缀的网络地址不是公网）就说明 not_public 没有生效。
        # 保留段都不小于 /24，所以一个 /24 要么整个在保留段里要么整个不在。
        src = "cands" if db.has_table("cands") else "visit"
        enforce_public = True
        for (pfx,) in db.q("SELECT DISTINCT prefix24 FROM %s WHERE prefix24 IS NOT NULL" % src):
            if not is_public_v4(pfx.split("/")[0], public_extra):
                enforce_public = False
                break
    return PoolRules(self_ips, skip_ports, enforce_public, tuple(public_extra))


def load_agg_sample(db):
    """{cand: 抽样时刻}（agg_member；同一条目被几个聚合器抽到时取最早）。抽样条目数不超过聚合器数 × AggregatorSample，放得进内存。"""
    if not db.has_table("agg_member"):
        return {}
    return {c: t for c, t in db.q("SELECT cand, MIN(ts_epoch) FROM agg_member GROUP BY cand")}


def load_flap_pairs(db, lo, hi, tol=FLAP_ADD_TOL):
    """文件层面的抖动快照对（DEFINITIONS“flap”）。按文件扫常规快照：某次有变化的非 base 快照 n_del ≥ 上一次 n 的一半（且 > 0），
    下一次有变化的非 base 快照 n_add 与它的 n_del 相差 ≤ tol × n_del → 这两次快照是一对抖动。
    返回 ({(src, label): [(t_del, t_add, n_del, n_add), …]}, {(文件, t_del)}, {(文件, t_add)})。快照表很小，整张扫没问题。"""
    pairs, del_set, add_set = collections.defaultdict(list), set(), set()
    rows = db.q("""SELECT src, label, ts_epoch, COALESCE(base, 0), n, COALESCE(n_add, 0), COALESCE(n_del, 0)
                   FROM snap WHERE COALESCE(agg, 0) = 0 AND COALESCE(changed, 0) = 1 AND ts_epoch BETWEEN ? AND ? ORDER BY src, label, ts_epoch""", (lo, hi))
    for f, group in itertools.groupby(rows, key=lambda r: (r[0], r[1])):
        seq = list(group)
        for i, (_, _, t, base, n, na, nd) in enumerate(seq):
            if i == 0 or base:
                continue
            prev_n = seq[i - 1][4]
            if not prev_n or nd <= 0 or nd * 2 < prev_n:
                continue
            nxt = next((r for r in seq[i + 1:] if not r[3]), None)
            if nxt is None or abs(nxt[5] - nd) > tol * nd:
                continue
            pairs[f].append((t, nxt[2], nd, nxt[5]))
            del_set.add((f, t))
            add_set.add((f, nxt[2]))
    return dict(pairs), del_set, add_set


# ---------------------------------------------------------------- 探访与候选的辅助表

def build_visit_table(db, fs, end):
    """fr_visit：窗口内非 aborted 的探访（prober.go：Aborted 的结果不作数；summary.go 也跳过）。t1 是探访结束时刻。"""
    db.x("""CREATE TEMP TABLE fr_visit AS
            SELECT rid, cand, prefix24, ts_epoch AS t0, ts_epoch + COALESCE(ms, 0) / 1000.0 AS t1,
                   (COALESCE(n_ok, 0) > 0) AS ok, state, COALESCE(listed, 0) AS listed, COALESCE("group", 0) AS grp
            FROM visit WHERE COALESCE(aborted, 0) = 0 AND ts_epoch BETWEEN ? AND ?""", (fs, end))
    db.x("CREATE INDEX temp.fr_visit_cand ON fr_visit(cand, t0)")
    db.x("CREATE INDEX temp.fr_visit_rid ON fr_visit(rid)")
    n_all, n_ab = db.one("SELECT COUNT(*), SUM(COALESCE(aborted, 0) = 1) FROM visit WHERE ts_epoch BETWEEN ? AND ?", (fs, end))
    mism = db.scalar("SELECT COUNT(*) FROM fr_visit WHERE ok != (state = 'working')")
    return {"visits_in_window": int(n_all or 0), "visits_aborted_excluded": int(n_ab or 0),
            "visits_used": int(db.scalar("SELECT COUNT(*) FROM fr_visit")), "visits_ok_state_mismatch": int(mism or 0)}


def build_cand_tables(db, dense_threshold):
    """fr_cands（状态文件里的候选，可能为空）、dense24（候选密集的 /24）、fr_agg（聚合器抽样条目及抽样时刻）。"""
    have_cands = db.has_table("cands")
    if have_cands:
        db.x("CREATE TEMP TABLE fr_cands AS SELECT key, prefix24, listed, delisted_at_epoch, first_seen_epoch, visits, "
             '"group" AS grp FROM cands')
        basis = "状态文件 cands ∪ 尝试记录里的代理候选（att，含试运行）：下榜超过 24 小时的候选会从状态文件里丢掉，只数状态文件会漏掉它们"
        # 状态文件 ∪ 尝试记录里的代理候选（与 m_availability、m_integrity、report_tables 的点名规则同一口径，决策 D14）
        att_part = " UNION SELECT DISTINCT cand, prefix24 FROM att WHERE cand_kind = 'proxy'" if db.has_table("att") else ""
        db.x("CREATE TEMP TABLE dense24 AS SELECT prefix24, COUNT(*) AS n FROM (SELECT key AS cand, prefix24 FROM fr_cands%s) "
             "WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING n > ?" % att_part, (dense_threshold,))
    else:
        db.x("CREATE TEMP TABLE fr_cands (key TEXT, prefix24 TEXT, listed INTEGER, delisted_at_epoch REAL, first_seen_epoch REAL, "
             "visits INTEGER, grp INTEGER)")
        basis = "list_event ∪ agg_member ∪ visit 的候选并集（没有状态文件）"
        agg_part = " UNION SELECT DISTINCT cand, prefix24 FROM agg_member" if db.has_table("agg_member") else ""
        db.x("""CREATE TEMP TABLE dense24 AS SELECT prefix24, COUNT(*) AS n FROM (
                  SELECT DISTINCT cand, prefix24 FROM list_event %s UNION SELECT DISTINCT cand, prefix24 FROM visit)
                GROUP BY prefix24 HAVING n > ?""" % agg_part, (dense_threshold,))
    db.x("CREATE INDEX temp.fr_cands_key ON fr_cands(key)")
    db.x("CREATE INDEX temp.dense24_p ON dense24(prefix24)")
    if db.has_table("agg_member"):
        db.x("CREATE TEMP TABLE fr_agg AS SELECT cand, MIN(ts_epoch) AS t_sample FROM agg_member GROUP BY cand")
    else:
        db.x("CREATE TEMP TABLE fr_agg (cand TEXT, t_sample REAL)")
    db.x("CREATE INDEX temp.fr_agg_cand ON fr_agg(cand)")
    return have_cands, basis


def dense_prefix_list(db):
    """PROTOCOL 1.2“候选密集的地址段”：列出被去掉的 /24 各有多少候选、探访到多少。“探访到”= 窗口内有非 aborted 探访的候选数。"""
    rows = db.q("""SELECT d.prefix24, d.n,
                          (SELECT COUNT(DISTINCT v.cand) FROM fr_visit v WHERE v.prefix24 = d.prefix24) AS visited,
                          (SELECT COUNT(*) FROM fr_cand c WHERE c.prefix24 = d.prefix24) AS with_events,
                          (SELECT COUNT(*) FROM fr_new x WHERE x.prefix24 = d.prefix24 AND x.probeable = 1) AS new_listings,
                          (SELECT COUNT(*) FROM fr_delist x WHERE x.prefix24 = d.prefix24) AS delists
                   FROM dense24 d ORDER BY d.n DESC, d.prefix24""")
    return [{"prefix24": p, "候选": int(n), "探访到": int(v), "有列表事件的候选": int(e), "可探测的新上榜": int(nl), "候选层面下榜": int(dl)}
            for p, n, v, e, nl, dl in rows]


# ---------------------------------------------------------------- 分布

def quantiles_sql(db, sql, params=(), qs=QUANTILES, scale=60.0):
    """对 `sql`（返回一列数值）算分位数、均值、最大值；用窗口函数在库里排序，不把全部值读进 Python。单位除以 scale（默认换成分钟）。"""
    n = db.scalar("SELECT COUNT(*) FROM (%s)" % sql, params)
    out = {"n": int(n or 0)}
    if not n:
        out.update({"p%d" % int(q * 100): None for q in qs})
        out.update({"mean": None, "max": None})
        return out
    ranked = "SELECT v, ROW_NUMBER() OVER (ORDER BY v) AS rn FROM (%s)" % sql
    for q in qs:
        k = max(1, int(-(-q * n // 1)))  # ceil(q·n)
        v = db.scalar("SELECT v FROM (%s) WHERE rn = ?" % ranked, tuple(params) + (k,))
        out["p%d" % int(q * 100)] = round(v / scale, 1) if v is not None else None
    mean, mx = db.one("SELECT AVG(v), MAX(v) FROM (%s)" % sql, params)
    out["mean"] = round(mean / scale, 1) if mean is not None else None
    out["max"] = round(mx / scale, 1) if mx is not None else None
    return out


def histogram_sql(db, sql, params, buckets_min):
    """`sql` 返回一列秒数；按分钟桶计数。"""
    out = []
    for lo, hi in buckets_min:
        cond = "v >= ?" + (" AND v < ?" if hi is not None else "")
        p = tuple(params) + ((lo * 60.0, hi * 60.0) if hi is not None else (lo * 60.0,))
        n = db.scalar("SELECT COUNT(*) FROM (%s) WHERE %s" % (sql, cond), p)
        out.append({"bucket_min": "[%d, %s)" % (lo, hi if hi is not None else "∞"), "n": int(n or 0)})
    return out


def distribution(db, sql, params, buckets_min, unit="分钟"):
    return {"unit": unit, "quantiles": quantiles_sql(db, sql, params), "histogram": histogram_sql(db, sql, params, buckets_min)}


# ---------------------------------------------------------------- 上榜新鲜度

def build_new_listing_table(db, fs, end, fresh_s, have_cands):
    """fr_new：每条 new / relist 上榜事件一行，带第一次探访、延迟、分类。"""
    db.x("""CREATE TEMP TABLE fr_new0 AS
            SELECT l.lid, l.cand, l.prefix24, l.t_add, l.kind, l.listing_no, l.t_end, l.n_srcs, l.relist_gap_s, l.file_flap,
                   (l.prefix24 IN (SELECT prefix24 FROM dense24)) AS dense,
                   c.inelig, (SELECT 1 FROM fr_cands k WHERE k.key = l.cand) AS in_cands,
                   (SELECT COUNT(*) FROM fr_visit v WHERE v.cand = l.cand AND v.t0 < l.t_add) AS visits_before,
                   (SELECT v.rid FROM fr_visit v WHERE v.cand = l.cand AND v.t0 >= l.t_add ORDER BY v.t0 LIMIT 1) AS v_rid,
                   (SELECT 1 FROM fr_agg a WHERE a.cand = l.cand AND a.t_sample <= l.t_add) AS in_agg,
                   (SELECT 1 FROM fr_cands k WHERE k.key = l.cand AND k.first_seen_epoch < l.t_add - ?) AS first_seen_earlier
            FROM fr_listing l JOIN fr_cand c ON c.cand = l.cand
            WHERE l.kind IN ('new', 'relist')""", (MATCH_TOL_S,))
    # 分类：pool_already（上榜前已在候选池：上榜前有探访 / 聚合器抽样在先 / 状态文件 first_seen 早于上榜时刻；Upsert 用与 snap 相同的 now 写
    # FirstSeen，所以真正的新候选两者相等）> 没探访到（按状态文件 / sched.go 规则再分）> fresh（10 分钟内完成）> late。
    # probeable（可探测的新上榜）：kind='new' 且不是 pool_already / never_visited_ineligible —— “新上榜”各处分母都用它。
    # cls_start：同样的分类但“10 分钟内”以探访开始时刻算（PROTOCOL 没写以开始还是完成为准，两者都报）。
    db.x("""CREATE TEMP TABLE fr_new AS
            SELECT n.*, v.t1 - n.t_add AS delay_s, v.t0 - n.t_add AS delay_start_s, v.ok AS first_ok, v.state AS first_state,
                   CASE WHEN n.kind = 'new' AND (n.visits_before > 0 OR n.in_agg = 1 OR n.first_seen_earlier = 1) THEN 'pool_already'
                        WHEN v.rid IS NULL THEN
                             CASE WHEN n.in_cands = 1 THEN 'never_visited_in_pool'
                                  WHEN n.inelig IS NOT NULL THEN 'never_visited_ineligible'
                                  WHEN ? = 1 THEN 'never_visited_unknown'
                                  ELSE 'never_visited' END
                        WHEN v.t1 - n.t_add <= ? THEN 'fresh'
                        ELSE 'late' END AS cls,
                   CASE WHEN n.kind = 'new' AND (n.visits_before > 0 OR n.in_agg = 1 OR n.first_seen_earlier = 1) THEN 'pool_already'
                        WHEN v.rid IS NULL THEN 'never_visited'
                        WHEN v.t0 - n.t_add <= ? THEN 'fresh'
                        ELSE 'late' END AS cls_start,
                   NULL AS pool_already_why,
                   (? - n.t_add < ?) AS too_recent,
                   (n.t_add - ? < 3600.0) AS first_hour
            FROM fr_new0 n LEFT JOIN fr_visit v ON v.rid = n.v_rid""", (1 if have_cands else 0, fresh_s, fresh_s, end, fresh_s, fs))
    db.x("""ALTER TABLE fr_new ADD COLUMN probeable INTEGER""")
    db.x("""UPDATE fr_new SET probeable = (kind = 'new' AND cls NOT IN ('pool_already', 'never_visited_ineligible'))""")
    # pool_already 的原因（互不排斥，按优先级取一个）：visits_before > agg_sampled > first_seen_earlier
    db.x("""UPDATE fr_new SET pool_already_why = CASE WHEN visits_before > 0 THEN 'visited_before' WHEN in_agg = 1 THEN 'aggregator_sample'
                                                  ELSE 'first_seen_earlier' END WHERE cls = 'pool_already'""")
    db.x("CREATE INDEX temp.fr_new_kind ON fr_new(kind, cls)")
    db.x("CREATE INDEX temp.fr_new_lid ON fr_new(lid)")


def freshness_block(db, where, params, note=None):
    """一组上榜事件的新鲜度：10 分钟内完成第一次探访的里可用的比例，以及第一次探访的状态分布。"""
    n, ok, w, o, d = db.one("""SELECT COUNT(*), SUM(first_ok), SUM(first_state = 'working'), SUM(first_state = 'open'),
                                     SUM(first_state = 'dead') FROM fr_new WHERE cls = 'fresh' AND %s""" % where, params)
    ns, oks = db.one("SELECT COUNT(*), SUM(first_ok) FROM fr_new WHERE cls_start = 'fresh' AND %s" % where, params)
    blk = {"上榜新鲜度": ratio(ok, n),
           "第一次探访的状态": {"working": int(w or 0), "open": int(o or 0), "dead": int(d or 0)},
           "第一次探访延迟（10 分钟内的）": quantiles_sql(db, "SELECT delay_s AS v FROM fr_new WHERE cls = 'fresh' AND %s" % where, params),
           "按开始时刻算的上榜新鲜度（敏感性）": ratio(oks, ns)}
    if note:
        blk["note"] = note
    return blk


def late_block(db, where, params):
    """可探测的新上榜里延迟超过 10 分钟或没探访到的条目：条数、延迟分布，按是否密集 /24 分开。
    不进候选池的（never_visited_ineligible）不算新上榜（PROTOCOL“不探测的地址”），在旁边按原因单列，不进“没探访到”的 total。
    /24 只按密集 / 非密集分，不逐个列出非密集 /24（公开仓库里只允许出现候选密集的 /24 前缀）。"""
    out = {}
    for name, dense in (("dense_prefix", 1), ("other_prefix", 0)):
        w = where + " AND dense = ?"
        p = tuple(params) + (dense,)
        row = db.one("""SELECT SUM(cls = 'late'), SUM(cls LIKE 'never_visited%%' AND cls != 'never_visited_ineligible'),
                               SUM(cls = 'never_visited_in_pool'), SUM(cls = 'never_visited_unknown'),
                               SUM(cls = 'never_visited'), SUM(cls LIKE 'never_visited%%' AND cls != 'never_visited_ineligible' AND too_recent = 1)
                        FROM fr_new WHERE %s""" % w, p)
        late, never, inpool, unk, nov, recent = (int(x or 0) for x in row)
        # 不进候选池的按 probeable=0 被 where 排除了，这里按 kind='new' 单独数（它们不是“可探测的新上榜”，只在旁边报）
        inel_by = {r: int(n) for r, n in db.q("SELECT inelig, COUNT(*) FROM fr_new WHERE kind = 'new' AND cls = 'never_visited_ineligible' AND dense = ? GROUP BY 1", (dense,))}
        inel = sum(inel_by.values())
        out[name] = {
            "延迟超过 10 分钟": late,
            "延迟分布（超过 10 分钟的）": distribution(db, "SELECT delay_s AS v FROM fr_new WHERE cls = 'late' AND %s" % w, p, DELAY_BUCKETS_MIN),
            "窗口内没探访到（可探测的）": {"total": never, "候选池里排队没探到": inpool,
                               "原因不明（不在状态文件、规则也不排除）": unk, "没有状态文件、无法区分": nov,
                               "其中上榜到观察结束不足 10 分钟": recent},
            "不进候选池（不算新上榜）": {"total": inel, "按原因": inel_by},
            "延迟分布（全部探访到的，含 10 分钟内）": distribution(db, "SELECT delay_s AS v FROM fr_new WHERE cls IN ('fresh', 'late') AND %s" % w, p, DELAY_BUCKETS_MIN),
            "开始时刻延迟分布（全部探访到的）": distribution(db, "SELECT delay_start_s AS v FROM fr_new WHERE cls IN ('fresh', 'late') AND %s" % w, p, DELAY_BUCKETS_MIN),
        }
    return out


def listing_section(db, fs, end, fresh_min, have_cands, flap_s):
    kinds = {k: int(n) for k, n in db.q("SELECT kind, COUNT(*) FROM fr_listing GROUP BY kind")}
    cls_new = {k: int(n) for k, n in db.q("SELECT cls, COUNT(*) FROM fr_new WHERE kind = 'new' GROUP BY cls")}
    cls_re = {k: int(n) for k, n in db.q("SELECT cls, COUNT(*) FROM fr_new WHERE kind = 'relist' GROUP BY cls")}
    n_kind_new = sum(cls_new.values())
    n_new = int(db.scalar("SELECT COUNT(*) FROM fr_new WHERE probeable = 1") or 0)
    n_fresh = int(db.scalar("SELECT COUNT(*) FROM fr_new WHERE probeable = 1 AND cls = 'fresh'") or 0)
    n_fresh_start = int(db.scalar("SELECT COUNT(*) FROM fr_new WHERE probeable = 1 AND cls_start = 'fresh'") or 0)
    pa_why = {k: int(n) for k, n in db.q("SELECT pool_already_why, COUNT(*) FROM fr_new WHERE kind = 'new' AND cls = 'pool_already' GROUP BY 1")}
    inel_why = {k: int(n) for k, n in db.q("SELECT inelig, COUNT(*) FROM fr_new WHERE kind = 'new' AND cls = 'never_visited_ineligible' GROUP BY 1")}
    inel_dense = {k: int(n) for k, n in db.q("SELECT CASE WHEN dense = 1 THEN 'dense_prefix' ELSE 'other_prefix' END, COUNT(*) FROM fr_new "
                                             "WHERE kind = 'new' AND cls = 'never_visited_ineligible' GROUP BY 1")}
    re_flap = int(db.scalar("SELECT COUNT(*) FROM fr_new WHERE kind = 'relist' AND (file_flap = 1 OR relist_gap_s <= ?)", (flap_s,)) or 0)
    sec = {
        "note": "新上榜 = 窗口内第一次出现且是 base=0 的 add。首次快照（initial）、重启首次快照（restart_base）、上榜前已在候选池（pool_already）、"
                "再上榜（relist）不算，只报条数。“新上榜”的 total 与各比例的分母是“可探测的新上榜”（kind=new 去掉 pool_already 与不进候选池的），"
                "pool_already 与不进候选池的在“不算新上榜的 new 事件”里单列。第一次探访“完成”= visit.ts + visit.ms。",
        "fresh_window_min": fresh_min,
        "上榜事件按种类": kinds,
        "新上榜按分类（kind=new 全部）": cls_new,
        "不算新上榜的 new 事件": {
            "kind=new 事件总数": n_kind_new,
            "pool_already": {"total": cls_new.get("pool_already", 0), "按原因": pa_why,
                             "note": "visited_before：上榜前窗口内已有探访；aggregator_sample：聚合器抽样在先；first_seen_earlier：状态文件 first_seen 早于上榜时刻"},
            "不进候选池（sched.go ineligible）": {"total": cls_new.get("never_visited_ineligible", 0), "按原因": inel_why, "按是否密集 /24": inel_dense,
                                          "note": "PROTOCOL“不探测的地址”：私网/保留地址、judge 自身、知名端口；退出名单看不到。按 /24 只分密集 / 非密集"},
        },
        "新上榜": {
            "total": n_new,
            "note": "可探测的新上榜（见 definitions）",
            "10 分钟内完成第一次探访": ratio(n_fresh, n_new),
            "10 分钟内开始第一次探访（敏感性）": ratio(n_fresh_start, n_new),
            "all": freshness_block(db, "probeable = 1", ()),
            "excluding_dense": freshness_block(db, "probeable = 1 AND dense = 0", (), note="去掉候选超过阈值的 /24"),
            "dense_only": freshness_block(db, "probeable = 1 AND dense = 1", ()),
            "first_hour_after_start": freshness_block(db, "probeable = 1 AND first_hour = 1", (), note="起点后 1 小时内上榜的（PROTOCOL“已知局限”：积压期）"),
            "after_first_hour": freshness_block(db, "probeable = 1 AND first_hour = 0", ()),
            "其余条目（延迟超过 10 分钟或没探访到）": late_block(db, "probeable = 1", ()),
        },
        "再上榜（relist，下榜后又出现）": {
            "total": sum(cls_re.values()), "按分类": cls_re, "其中换榜/抖动（距下榜 ≤ flap_min 或文件层面抖动）": re_flap,
            "note": "下榜后 24 小时内探测器仍在探它，所以“再上榜后第一次探访”不是由上榜触发的；只作参考",
            "freshness": freshness_block(db, "kind = 'relist'", ()),
            "距上一次下榜（分钟）": quantiles_sql(db, "SELECT relist_gap_s AS v FROM fr_new WHERE kind = 'relist' AND relist_gap_s IS NOT NULL", ()),
        },
        "by_source": {},
    }
    for (src,) in db.q("SELECT DISTINCT src FROM fr_listing_src ORDER BY src"):
        where = "probeable = 1 AND lid IN (SELECT lid FROM fr_listing_src s WHERE s.src = ?)"
        tot = db.scalar("SELECT COUNT(*) FROM fr_new WHERE %s" % where, (src,))
        fresh = db.scalar("SELECT COUNT(*) FROM fr_new WHERE cls = 'fresh' AND %s" % where, (src,))
        late = db.scalar("SELECT COUNT(*) FROM fr_new WHERE cls = 'late' AND %s" % where, (src,))
        never = db.scalar("SELECT COUNT(*) FROM fr_new WHERE cls LIKE 'never_visited%%' AND %s" % where, (src,))
        not_counted = db.scalar("SELECT COUNT(*) FROM fr_new WHERE kind = 'new' AND probeable = 0 AND lid IN (SELECT lid FROM fr_listing_src s WHERE s.src = ?)", (src,))
        blk = freshness_block(db, where, (src,))
        blk.update({"可探测的新上榜（该来源参与的）": int(tot or 0), "10 分钟内完成第一次探访": ratio(fresh, tot), "延迟超过 10 分钟": int(late or 0),
                    "没探访到": int(never or 0), "不算新上榜的 new 事件（pool_already / 不进候选池）": int(not_counted or 0),
                    "来源层面 base 上榜（首次 / 重启 / 再上榜的 base 快照）": int(db.scalar("SELECT COUNT(*) FROM fr_src_listing WHERE src = ? AND kind = 'base'", (src,)) or 0)})
        sec["by_source"][src] = blk
    sec["by_source_note"] = "同一时刻把候选加进来的每个来源各记一次，所以各来源之和可以大于“新上榜”总数"
    return sec


# ---------------------------------------------------------------- 下榜

def build_delist_tables(db, end, followup_s, flap_s):
    """fr_del（候选层面）和 fr_sdel（来源层面）：每个下榜事件带下榜前后的探访情况。
    flap = 文件层面抖动（file_flap）或再上榜距下榜 ≤ flap_s（relist_flap）；agg_held 见 DEFINITIONS（来源层面也带，只作参考）。
    first_after_ok 限于下榜后 24 小时内、且在再上榜之前的探访（核对者意见）。"""
    common = """
        (SELECT MAX(v.t0) FROM fr_visit v WHERE v.cand = d.cand AND v.t0 <= d.t_delist AND v.ok = 1) AS last_ok_before,
        (SELECT COUNT(*) FROM fr_visit v WHERE v.cand = d.cand AND v.t0 <= d.t_delist) AS visits_before,
        (SELECT v.ok FROM fr_visit v WHERE v.cand = d.cand AND v.t0 <= d.t_delist ORDER BY v.t0 DESC LIMIT 1) AS last_visit_ok,
        (SELECT COUNT(*) FROM fr_visit v WHERE v.cand = d.cand AND v.t0 > d.t_delist AND v.t0 <= d.t_delist + {fu}) AS visits_after,
        (SELECT MAX(v.ok) FROM fr_visit v WHERE v.cand = d.cand AND v.t0 > d.t_delist AND v.t0 <= d.t_delist + {fu}) AS ok_after,
        (SELECT v.ok FROM fr_visit v WHERE v.cand = d.cand AND v.t0 > d.t_delist AND v.t0 <= d.t_delist + {fu}
            AND (d.t_relist IS NULL OR v.t0 < d.t_relist) ORDER BY v.t0 LIMIT 1) AS first_after_ok,
        (SELECT MIN(v.t0) FROM fr_visit v WHERE v.cand = d.cand AND v.t0 > d.t_delist AND v.ok = 1) AS first_ok_after_t,
        (SELECT MAX(v.t0) FROM fr_visit v WHERE v.cand = d.cand AND v.t0 > d.t_delist AND v.t0 <= d.t_delist + {fu} AND v.ok = 1) AS last_ok_after_t,
        (d.t_delist + {fu} <= {end}) AS full_followup,
        (d.t_relist IS NOT NULL AND d.t_relist <= d.t_delist + {fu}) AS relisted_within,
        d.t_relist - d.t_delist AS relist_gap_s,
        (d.t_relist IS NOT NULL AND d.t_relist - d.t_delist <= {flap}) AS relist_flap,
        (COALESCE(d.file_flap, 0) = 1 OR (d.t_relist IS NOT NULL AND d.t_relist - d.t_delist <= {flap})) AS flap,
        (d.prefix24 IN (SELECT prefix24 FROM dense24)) AS dense
    """.format(fu=repr(float(followup_s)), end=repr(float(end)), flap=repr(float(flap_s)))
    cat = """CASE WHEN visits_before = 0 THEN 'never_visited_before'
                  WHEN last_ok_before IS NULL THEN 'never_ok_before'
                  WHEN last_visit_ok = 1 THEN 'ok_at_delist'
                  ELSE 'died_before_delist' END AS cat,
             t_delist - last_ok_before AS lag_s"""
    db.x("CREATE TEMP TABLE fr_del0 AS SELECT d.*, d.t_delist - d.t_listed AS listed_dur_s, %s FROM fr_delist d" % common)
    db.x("CREATE TEMP TABLE fr_del AS SELECT *, %s FROM fr_del0" % cat)
    db.x("CREATE INDEX temp.fr_del_cat ON fr_del(cat)")
    db.x("CREATE TEMP TABLE fr_sdel0 AS SELECT d.*, NULL AS listed_dur_s, %s FROM fr_src_delist d" % common)
    db.x("CREATE TEMP TABLE fr_sdel AS SELECT *, %s FROM fr_sdel0" % cat)
    db.x("CREATE INDEX temp.fr_sdel_src ON fr_sdel(src, cat)")


def delist_block(db, table, where, params):
    """一组下榜事件的全部指标。table 是 fr_del 或 fr_sdel。"""
    n = db.scalar("SELECT COUNT(*) FROM %s WHERE %s" % (table, where), params)
    cats = {k: int(c) for k, c in db.q("SELECT cat, COUNT(*) FROM %s WHERE %s GROUP BY cat" % (table, where), params)}
    silent = db.scalar("SELECT SUM(silent) FROM %s WHERE %s" % (table, where), params)
    visited_before = int(n or 0) - cats.get("never_visited_before", 0)
    lag_died = "SELECT lag_s AS v FROM %s WHERE cat = 'died_before_delist' AND %s" % (table, where)
    lag_ok = "SELECT lag_s AS v FROM %s WHERE cat = 'ok_at_delist' AND %s" % (table, where)
    lag_all = "SELECT lag_s AS v FROM %s WHERE lag_s IS NOT NULL AND %s" % (table, where)
    fu_den, fu_num, fu_inc, fu_np, fu_rel, fn_den, fn_num = db.one(
        """SELECT SUM(full_followup = 1 AND visits_after > 0), SUM(full_followup = 1 AND visits_after > 0 AND ok_after = 1),
                  SUM(full_followup = 0), SUM(full_followup = 1 AND visits_after = 0), SUM(relisted_within = 1),
                  SUM(full_followup = 1 AND visits_after > 0 AND relisted_within = 0),
                  SUM(full_followup = 1 AND visits_after > 0 AND relisted_within = 0 AND ok_after = 1)
           FROM %s WHERE %s""" % (table, where), params)
    fa_den, fa_num = db.one("SELECT SUM(first_after_ok IS NOT NULL), SUM(first_after_ok = 1) FROM %s WHERE %s" % (table, where), params)
    n_flap, n_file_flap, n_relist_flap, n_agg = db.one(
        "SELECT SUM(flap), SUM(COALESCE(file_flap, 0)), SUM(relist_flap), SUM(COALESCE(agg_held, 0)) FROM %s WHERE %s" % (table, where), params)
    # 下榜后 24 小时内仍可用的：最后一次可用距下榜多久（它至少活到那时）
    alive_dur = ("SELECT last_ok_after_t - t_delist AS v FROM %s WHERE full_followup = 1 AND ok_after = 1 AND %s" % (table, where))
    out = {
        "下榜事件": int(n or 0), "其中无声下榜（重启后的首次快照里消失）": int(silent or 0),
        "其中换榜/抖动（flap）": {"total": int(n_flap or 0), "文件层面抖动": int(n_file_flap or 0), "再上榜距下榜 ≤ flap_min": int(n_relist_flap or 0)},
        "其中聚合器仍可能列着（agg_held）": int(n_agg or 0),
        "下榜时的状态": cats,
        "下榜时仍可用（最后一次探访可用）": ratio(cats.get("ok_at_delist", 0), visited_before),
        "下榜时已死（曾可用、最后一次探访不可用）": ratio(cats.get("died_before_delist", 0), visited_before),
        "下榜时从未可用": ratio(cats.get("never_ok_before", 0), visited_before),
        "下榜滞后（已死的：最后一次可用到下榜）": distribution(db, lag_died, params, LAG_BUCKETS_MIN),
        "下榜滞后（仍可用的：距上次复测）": distribution(db, lag_ok, params, LAG_BUCKETS_MIN),
        "下榜滞后（曾可用的全部）": distribution(db, lag_all, params, LAG_BUCKETS_MIN),
        "下榜后第一次探访可用": ratio(fa_num, fa_den),
        "下榜后 24 小时内仍可用": ratio(fu_num, fu_den),
        # 上面一项的 24 小时里含又上榜之后的时段（那时它可用不说明“下榜的其实还活着”）。只看 24 小时内没再上榜的事件，
        # 这时 24 小时里的每次探访都在下榜期间（分析时补的变体，不是 PROTOCOL 事先写下的口径）
        "下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）": ratio(fn_num, fn_den),
        "下榜后 24 小时的观察": {"不足 24 小时（不进分母）": int(fu_inc or 0), "24 小时内没探访（不进分母）": int(fu_np or 0),
                          "24 小时内又上榜": int(fu_rel or 0)},
        "下榜后仍可用的最后一次可用距下榜": distribution(db, alive_dur, params, LAG_BUCKETS_MIN),
    }
    if table == "fr_del":
        out["在榜时长（下榜时刻 − 这次上榜时刻；initial 的是下界）"] = distribution(
            db, "SELECT listed_dur_s AS v FROM fr_del WHERE listed_dur_s IS NOT NULL AND %s" % where, params, LAG_BUCKETS_MIN)
    return out


def delist_section(db, have_cands, flap_min):
    excl = "flap = 0 AND COALESCE(agg_held, 0) = 0"
    sec = {
        "note": "候选层面 = 从所有列表文件消失；来源层面 = 从某来源的全部文件消失（候选可能仍在别的来源）。"
                "“仍可用”的分母是下榜前探访过的事件；“24 小时内仍可用”的分母见 definitions。"
                "默认组（all / excluding_dense / first_delist_only / by_source）不含换榜/抖动（flap）；候选层面还不含聚合器仍可能列着的（agg_held）；"
                "including_* 是不排除的一组，flaps_only / agg_held_only 是被排除的那些。",
        "flap_min": flap_min,
        "candidate_level": {
            "all": delist_block(db, "fr_del", excl, ()),
            "excluding_dense": delist_block(db, "fr_del", excl + " AND dense = 0", ()),
            "first_delist_only": delist_block(db, "fr_del", excl + " AND delist_no = 1", ()),
            "including_flaps_and_agg_held": delist_block(db, "fr_del", "1 = 1", ()),
            "flaps_only": delist_block(db, "fr_del", "flap = 1", ()),
            "agg_held_only": delist_block(db, "fr_del", "COALESCE(agg_held, 0) = 1", ()),
        },
        "source_level": {"all": delist_block(db, "fr_sdel", "flap = 0", ()),
                         "including_flaps": delist_block(db, "fr_sdel", "1 = 1", ()),
                         "flaps_only": delist_block(db, "fr_sdel", "flap = 1", ()),
                         "still_listed_elsewhere": int(db.scalar("SELECT COUNT(*) FROM fr_sdel WHERE still_listed_elsewhere = 1") or 0),
                         "agg_held（只作参考，来源层面不排除）": int(db.scalar("SELECT COUNT(*) FROM fr_sdel WHERE COALESCE(agg_held, 0) = 1") or 0),
                         "by_source": {}},
    }
    for (src,) in db.q("SELECT DISTINCT src FROM fr_sdel ORDER BY src"):
        sec["source_level"]["by_source"][src] = delist_block(db, "fr_sdel", "flap = 0 AND src = ?", (src,))
    # 聚合器抽样条目：快照只记数量，它们的下榜由 snapAggregators 直接调 Pool.Delist（prober.go），list_event 里没有事件，
    # 只能看状态文件结束时刻的 listed / delisted_at / state，报条数，不进上面的比例。
    # 抽样条目 = agg_member 的成员（sched.go Upsert 把后来进了常规列表的 Group 改成 0，所以不能用 cands.group=1 数）；按 group 现值分两列。
    if have_cands and db.has_table("agg_member"):
        row = db.one("""SELECT COUNT(*), SUM(COALESCE(listed, 0) = 1), SUM(COALESCE(listed, 0) = 0 AND delisted_at_epoch IS NOT NULL),
                               SUM(COALESCE(listed, 0) = 0 AND delisted_at_epoch IS NOT NULL AND state_name = 'working'),
                               SUM(COALESCE(listed, 0) = 0 AND delisted_at_epoch IS NOT NULL AND COALESCE(ever_ok, 0) = 1),
                               SUM(COALESCE(visits, 0) = 0)
                        FROM cands WHERE key IN (SELECT cand FROM agg_member) AND "group" = 1""")
        tot, listed, delisted, del_working, del_ever_ok, never = (int(x or 0) for x in row)
        members = int(db.scalar("SELECT COUNT(*) FROM (SELECT DISTINCT cand FROM agg_member)") or 0)
        in_state = int(db.scalar("SELECT COUNT(*) FROM cands WHERE key IN (SELECT cand FROM agg_member)") or 0)
        moved = int(db.scalar('SELECT COUNT(*) FROM cands WHERE key IN (SELECT cand FROM agg_member) AND "group" = 0') or 0)
        sec["aggregator_sample_state_file"] = {
            "note": "聚合器抽样条目（agg_member 成员）的下榜没有 list_event 事件（快照只记数量），这里只给状态文件结束时刻的计数，不进上面的比例。"
                    "“仍只在聚合器”= group 现值 1；“后来进了常规列表”= group 现值 0（它们的常规列表事件在上面的表里，见 agg_held）。"
                    "“下榜且最后一次探访可用”= state_name='working'。",
            "抽样条目（agg_member 成员）": members, "其中在状态文件里": in_state, "后来进了常规列表（group=0）": moved,
            "仍只在聚合器（group=1）": {"抽样条目": tot, "结束时仍在榜": listed, "结束时已下榜": delisted,
                               "已下榜且最后一次探访可用": ratio(del_working, delisted), "已下榜且曾可用": ratio(del_ever_ok, delisted), "从未探访": never}}
    # agg_held 的交叉核对：每个候选最后一次候选层面下榜若是 agg_held 且之后没再上榜，状态文件应仍说在榜（聚合器来源还在 Srcs 里），
    # 或 delisted_at 落在某次 start 上（Pool.Load 清空了聚合器的来源）。
    if have_cands:
        rows = db.q("""SELECT COALESCE(k.listed, 0), k.delisted_at_epoch
                       FROM fr_del d JOIN fr_cands k ON k.key = d.cand
                       WHERE d.agg_held = 1 AND d.t_relist IS NULL
                         AND d.t_delist = (SELECT MAX(t_delist) FROM fr_delist x WHERE x.cand = d.cand)""")
        starts = [r[0] for r in db.q("SELECT ts_epoch FROM start")] if db.has_table("start") else []
        n_listed = sum(1 for l, _ in rows if l == 1)
        n_restart = sum(1 for l, da in rows if l == 0 and da is not None and any(abs(da - s) <= RESTART_TOL_S for s in starts))
        sec["agg_held_vs_state_file"] = {
            "note": "agg_held 且之后没再上榜的最后一次下榜：状态文件说仍在榜（聚合器来源仍在 Srcs）或 delisted_at 在某次 start 上（Pool.Load 清空）都与推断一致。",
            "compared": len(rows), "state_file_listed": n_listed, "state_file_delisted_at_restart": n_restart,
            "inconsistent": len(rows) - n_listed - n_restart}
    # 下榜是不是其实还活着：三个角度放在一起（默认组），旁边给不排除的一组
    a = sec["candidate_level"]["all"]
    b_all = sec["candidate_level"]["including_flaps_and_agg_held"]
    sec["still_alive_summary"] = {
        "note": "默认不含 flap 与 agg_held 的事件；“含 flap 与 agg_held”是不排除的一组。",
        "下榜时最后一次探访仍可用": a["下榜时仍可用（最后一次探访可用）"],
        "下榜后第一次探访可用": a["下榜后第一次探访可用"],
        "下榜后 24 小时内仍可用": a["下榜后 24 小时内仍可用"],
        "下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）": a["下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）"],
        "含 flap 与 agg_held": {
            "下榜时最后一次探访仍可用": b_all["下榜时仍可用（最后一次探访可用）"],
            "下榜后第一次探访可用": b_all["下榜后第一次探访可用"],
            "下榜后 24 小时内仍可用": b_all["下榜后 24 小时内仍可用"]},
        "按来源（来源层面，不含 flap，下榜后 24 小时内仍可用）": {s: b["下榜后 24 小时内仍可用"] for s, b in sec["source_level"]["by_source"].items()},
    }
    return sec


# ---------------------------------------------------------------- 快照序列

def snapshot_section(db, fs, end, with_series, flap_pairs):
    files = {}
    rows = db.q("""SELECT src, label, COALESCE(agg, 0), ts_epoch, status, COALESCE(changed, 0), COALESCE(base, 0), n,
                          COALESCE(n_add, 0), COALESCE(n_del, 0), ms, (err IS NOT NULL) AS has_err
                   FROM snap WHERE ts_epoch BETWEEN ? AND ? ORDER BY src, label, ts_epoch""", (fs, end))
    for src, label, agg, t, status, changed, base, n, na, nd, ms, has_err in rows:
        f = files.setdefault((src, label), {"src": src, "label": label, "aggregator": bool(agg), "fetches": 0, "ok_fetches": 0,
                                           "failed_fetches": 0, "changed": 0, "base_snapshots": 0, "base_entries": 0,
                                           "adds": 0, "dels": 0, "entries_first": None, "entries_last": None,
                                           "entries_min": None, "entries_max": None, "_prev_t": None, "_gaps": [], "rows": [],
                                           "flap_pairs": [[iso_second(a), iso_second(b), int(nd_), int(na_)]
                                                          for a, b, nd_, na_ in flap_pairs.get((src, label), []) if fs <= a <= end]})
        f["fetches"] += 1
        failed = has_err or status not in (200, 304)  # summary.go snapLine：err 或非 200/304 算失败
        if failed:
            f["failed_fetches"] += 1
        else:
            f["ok_fetches"] += 1
        if changed:
            f["changed"] += 1
            if n is not None:
                f["entries_last"] = n
                if f["entries_first"] is None:
                    f["entries_first"] = n
                f["entries_min"] = n if f["entries_min"] is None else min(f["entries_min"], n)
                f["entries_max"] = n if f["entries_max"] is None else max(f["entries_max"], n)
        if base:
            f["base_snapshots"] += 1
            f["base_entries"] += na
        else:
            f["adds"] += na
            f["dels"] += nd
        if f["_prev_t"] is not None:
            f["_gaps"].append(t - f["_prev_t"])
        f["_prev_t"] = t
        if with_series:
            f["rows"].append([iso_minute(t), status, int(changed), int(base), n, int(na), int(nd)])
    # 每个来源每轮快照：同一来源的几个文件在一轮里顺序抓取（可能跨分钟；lists.go Get 超时 90 秒且失败重试一次）。
    # 归并规则：同一来源内按 ts 排序，文件（标签）在本轮里已出现过、或距上一条快照超过 ROUND_GAP_MIN 分钟就开新轮
    # （按分钟归并会把重启后几十秒内的 base 轮和前一轮合成一轮、把跨分钟的一轮拆成两行——核对者意见）。
    # 条目数是各文件最近一次有变化时的 n 之和；轮的时间取第一条快照（到秒）。
    src_rounds = collections.OrderedDict()
    if with_series:
        cur_n = {}
        cur_round = {}   # src → [起点 t, 上一条 t, 本轮已见标签]
        for src, label, t, status, changed, base, n, na, nd, has_err in db.q(
                """SELECT src, label, ts_epoch, status, COALESCE(changed, 0), COALESCE(base, 0), n, COALESCE(n_add, 0), COALESCE(n_del, 0),
                          (err IS NOT NULL) FROM snap WHERE COALESCE(agg, 0) = 0 AND ts_epoch BETWEEN ? AND ? ORDER BY src, ts_epoch""", (fs, end)):
            if changed and n is not None:
                cur_n[(src, label)] = n
            cr = cur_round.get(src)
            if cr is None or label in cr[2] or t - cr[1] > ROUND_GAP_MIN * 60.0:
                cr = cur_round[src] = [t, t, set()]
            cr[1] = t
            cr[2].add(label)
            key = (src, iso_second(cr[0]))
            r = src_rounds.setdefault(key, {"files": 0, "failed": 0, "changed": 0, "base_files": 0, "add": 0, "del": 0, "base_entries": 0})
            r["files"] += 1
            r["failed"] += 1 if (has_err or status not in (200, 304)) else 0
            r["changed"] += 1 if changed else 0
            if base:
                r["base_files"] += 1
                r["base_entries"] += na
            else:
                r["add"] += na
                r["del"] += nd
            r["entries"] = sum(v for (s, _), v in cur_n.items() if s == src)
    hours_total = (end - fs) / 3600.0 if end > fs else None
    out_files, by_source = [], {}
    for key in sorted(files):
        f = files[key]
        gaps = sorted(f.pop("_gaps"))
        f.pop("_prev_t")
        f["snapshot_interval_min"] = {"n": len(gaps), "p50": minutes(gaps[len(gaps) // 2]) if gaps else None,
                                      "max": minutes(gaps[-1]) if gaps else None, "nominal": SNAPSHOT_MIN_NOMINAL}
        f["churn_per_hour"] = round((f["adds"] + f["dels"]) / hours_total, 2) if hours_total else None
        if not with_series:
            f.pop("rows")
        s = by_source.setdefault(f["src"], {"aggregator": f["aggregator"], "files": 0, "fetches": 0, "failed_fetches": 0, "changed": 0,
                                           "base_snapshots": 0, "adds": 0, "dels": 0, "entries_last_sum": 0, "churn_per_hour": 0.0})
        s["files"] += 1
        for k in ("fetches", "failed_fetches", "changed", "base_snapshots", "adds", "dels"):
            s[k] += f[k]
        s["entries_last_sum"] += f["entries_last"] or 0
        s["churn_per_hour"] = round(s["churn_per_hour"] + (f["churn_per_hour"] or 0), 2)
        out_files.append(f)
    if with_series:
        for (src, minute), r in src_rounds.items():
            s = by_source.get(src)
            if s is not None:
                s.setdefault("rows", []).append([minute, r["files"], r["failed"], r["changed"], r["base_files"], r["entries"],
                                                 r["add"], r["del"], r["base_entries"]])
    # 候选层面的每小时序列：可探测的新上榜数及其 fresh / late / never_visited 分布（头一小时是积压期，PROTOCOL“已知局限”）、
    # 不算新上榜的 new 事件数、再上榜数、下榜数（候选层面，另列 flap 与 agg_held）
    empty = {"new_listings": 0, "new_fresh": 0, "new_late": 0, "new_never_visited": 0, "new_not_counted": 0, "relistings": 0,
             "delists": 0, "delists_silent": 0, "delists_flap": 0, "delists_agg_held": 0}
    hourly = collections.OrderedDict()
    for h, n, fr, la, nv in db.q("""SELECT CAST((t_add - ?) / 3600 AS INTEGER), COUNT(*), SUM(cls = 'fresh'), SUM(cls = 'late'),
                                           SUM(cls LIKE 'never_visited%') FROM fr_new WHERE probeable = 1 GROUP BY 1""", (fs,)):
        d = hourly.setdefault(int(h), dict(empty))
        d["new_listings"], d["new_fresh"], d["new_late"], d["new_never_visited"] = int(n), int(fr or 0), int(la or 0), int(nv or 0)
    for h, n in db.q("SELECT CAST((t_add - ?) / 3600 AS INTEGER), COUNT(*) FROM fr_new WHERE kind = 'new' AND probeable = 0 GROUP BY 1", (fs,)):
        hourly.setdefault(int(h), dict(empty))["new_not_counted"] = int(n)
    for h, n in db.q("SELECT CAST((t_add - ?) / 3600 AS INTEGER), COUNT(*) FROM fr_listing WHERE kind = 'relist' GROUP BY 1", (fs,)):
        hourly.setdefault(int(h), dict(empty))["relistings"] = int(n)
    for h, n, s, fl, ag in db.q("""SELECT CAST((t_delist - ?) / 3600 AS INTEGER), COUNT(*), SUM(silent), SUM(flap), SUM(COALESCE(agg_held, 0))
                                   FROM fr_del GROUP BY 1""", (fs,)):
        d = hourly.setdefault(int(h), dict(empty))
        d["delists"], d["delists_silent"], d["delists_flap"], d["delists_agg_held"] = int(n), int(s or 0), int(fl or 0), int(ag or 0)
    hourly_rows = [{"hour_index": h, "hour_utc": iso_hour(fs + h * 3600), **hourly[h]} for h in sorted(hourly)]
    # 核对：snap 的 n_add/n_del 之和应等于 list_event 的事件数
    sa, sd = db.one("SELECT SUM(COALESCE(n_add, 0)), SUM(COALESCE(n_del, 0)) FROM snap WHERE COALESCE(agg, 0) = 0 AND ts_epoch BETWEEN ? AND ?", (fs, end))
    la, ld = db.one("SELECT SUM(event = 'add'), SUM(event = 'del') FROM list_event WHERE ts_epoch BETWEEN ? AND ?", (fs, end))
    return {
        "note": "来自 snap 表，按文件（来源 × 标签）；base=1 的 add 数单列为 base_entries，不算增量。逐文件序列的时间取到分钟；"
                "来源层面每轮的时间取该轮第一条快照（到秒），一轮 = 同一来源内文件不重复、相邻间隔 ≤ %d 分钟的一串快照。"
                "失败 = err 非空或状态码不是 200/304（summary.go snapLine）。flap_pairs = 文件层面的抖动快照对"
                "[t_del, t_add, n_del, n_add]（见 definitions“flap”）。" % ROUND_GAP_MIN,
        "series_columns": ["ts_utc_minute", "status", "changed", "base", "entries", "add", "del"] if with_series else None,
        "files": out_files,
        "by_source_series_columns": ["round_start_utc", "files_fetched", "failed", "changed", "base_files", "entries_sum", "add", "del",
                                     "base_entries"] if with_series else None,
        "by_source": by_source,
        "hourly_candidate_events": hourly_rows,
        "check_snap_vs_list_event": {"snap_n_add_sum": int(sa or 0), "list_event_add": int(la or 0),
                                     "snap_n_del_sum": int(sd or 0), "list_event_del": int(ld or 0),
                                     "equal": (int(sa or 0), int(sd or 0)) == (int(la or 0), int(ld or 0))},
    }


# ---------------------------------------------------------------- 与状态文件、探访记录的交叉核对

def checks_section(db, fs, end, have_cands, restart_times, starts_all, rules):
    out = {}
    # 1. visit.listed 与重放结果
    db.x("""CREATE TEMP TABLE fr_lcheck AS
            SELECT v.listed AS flag,
                   EXISTS (SELECT 1 FROM fr_listing l WHERE l.cand = v.cand AND l.t_add <= v.t0 AND (l.t_end IS NULL OR v.t0 < l.t_end)) AS recon
            FROM fr_visit v
            WHERE v.cand IN (SELECT cand FROM fr_cand) AND v.cand NOT IN (SELECT cand FROM fr_agg)""")
    n, agree, flag1_recon0, flag0_recon1 = db.one(
        "SELECT COUNT(*), SUM(flag = recon), SUM(flag = 1 AND recon = 0), SUM(flag = 0 AND recon = 1) FROM fr_lcheck")
    out["visit_listed_vs_replay"] = {
        "note": "有列表事件、且不是聚合器抽样的候选的探访：visit.listed 应等于重放出的在榜状态。重启后 Pool.Load 先清空来源、首次快照才重建，"
                "所以重启到首次快照之间的探访会出现 listed=0 而重放为在榜；下榜当刻的探访可能两边差一条。",
        "visits_checked": int(n or 0), "agree": ratio(agree, n),
        "visit_says_listed_replay_says_not": int(flag1_recon0 or 0), "visit_says_not_replay_says_listed": int(flag0_recon1 or 0)}
    # 2. 状态文件
    if have_cands:
        n_both = db.scalar("SELECT COUNT(*) FROM fr_cand c JOIN fr_cands k ON k.key = c.cand")
        n_listed_agree = db.scalar("SELECT COUNT(*) FROM fr_cand c JOIN fr_cands k ON k.key = c.cand WHERE COALESCE(k.listed, 0) = c.listed_end")
        # delisted_at 与最后一次候选层面下榜
        db.x("CREATE TEMP TABLE fr_starts (t REAL)")
        db.con.executemany("INSERT INTO fr_starts VALUES (?)", [(s,) for s in starts_all])
        # restart_artifact：Pool.Load 重启时先把在榜候选记成下榜，首次快照没把它加回来 → delisted_at 是重启时刻（本模块记在 base 快照时刻，silent=1）
        # agg_held_cleared：最后一次下榜是 agg_held（聚合器仍列着，prober 里没下榜），之后的重启 Pool.Load 清空 Srcs → delisted_at 是重启时刻
        cmp_, match, restart_art, agg_clr, no_mine = db.one("""
            SELECT COUNT(*), SUM(mine IS NOT NULL AND ABS(da - mine) <= ?),
                   SUM(mine IS NOT NULL AND ABS(da - mine) > ? AND silent = 1 AND COALESCE(agg_held, 0) = 0
                       AND EXISTS (SELECT 1 FROM fr_starts s WHERE ABS(da - s.t) <= ?)),
                   SUM(mine IS NOT NULL AND ABS(da - mine) > ? AND COALESCE(agg_held, 0) = 1
                       AND EXISTS (SELECT 1 FROM fr_starts s WHERE ABS(da - s.t) <= ?)),
                   SUM(mine IS NULL)
            FROM (SELECT k.delisted_at_epoch AS da,
                         (SELECT d.t_delist FROM fr_delist d WHERE d.cand = c.cand ORDER BY d.t_delist DESC LIMIT 1) AS mine,
                         (SELECT d.silent FROM fr_delist d WHERE d.cand = c.cand ORDER BY d.t_delist DESC LIMIT 1) AS silent,
                         (SELECT d.agg_held FROM fr_delist d WHERE d.cand = c.cand ORDER BY d.t_delist DESC LIMIT 1) AS agg_held
                  FROM fr_cand c JOIN fr_cands k ON k.key = c.cand
                  WHERE k.delisted_at_epoch IS NOT NULL AND COALESCE(k.listed, 0) = 0)""",
            (MATCH_TOL_S, MATCH_TOL_S, RESTART_TOL_S, MATCH_TOL_S, RESTART_TOL_S))
        cmp_, match, restart_art, agg_clr, no_mine = (int(x or 0) for x in (cmp_, match, restart_art, agg_clr, no_mine))
        mismatch = cmp_ - match - restart_art - agg_clr - no_mine
        fs_cmp, fs_match, fs_before = db.one("""
            SELECT COUNT(*), SUM(a IS NOT NULL AND b IS NOT NULL AND ABS(a - b) <= ?),
                   SUM(a IS NOT NULL AND b IS NOT NULL AND a < b - ?)
            FROM (SELECT k.first_seen_epoch AS a, (SELECT MIN(l.t_add) FROM fr_listing l WHERE l.cand = c.cand) AS b
                  FROM fr_cand c JOIN fr_cands k ON k.key = c.cand WHERE c.cand NOT IN (SELECT cand FROM fr_agg))""",
            (MATCH_TOL_S, MATCH_TOL_S))
        fs_cmp, fs_match, fs_before = (int(x or 0) for x in (fs_cmp, fs_match, fs_before))
        out["state_file"] = {
            "note": "状态文件是结束时刻的快照。first_seen 应等于第一次 add 的 snap.ts（Upsert 用同一个 now）；"
                    "delisted_at 应等于候选层面最后一次下榜的时刻；first_seen 早于窗口内第一次上榜的是起点之前就在候选池里的（试运行或状态未清空）。",
            "cands_with_list_events_in_state_file": int(n_both or 0),
            "listed_flag_agree": ratio(n_listed_agree, n_both),
            "delisted_at": {"compared": cmp_, "match_within_1s": match, "restart_artifact_pool_load": restart_art,
                            "agg_held_cleared_at_restart": agg_clr, "no_replayed_delist": no_mine, "mismatch": mismatch},
            "first_seen_vs_first_add": {"compared": fs_cmp, "match_within_1s": fs_match, "first_seen_earlier_than_window_first_add": fs_before,
                                        "other": fs_cmp - fs_match - fs_before},
            "state_cands_total": int(db.scalar("SELECT COUNT(*) FROM fr_cands") or 0),
            "list_event_cands_not_in_state_file": int(db.scalar("SELECT COUNT(*) FROM fr_cand c WHERE NOT EXISTS (SELECT 1 FROM fr_cands k WHERE k.key = c.cand)") or 0),
        }
    else:
        out["state_file"] = {"note": "库里没有 cands 表（入库时没给 state.json.gz），跳过与状态文件的比对"}
    # 3. stat_pool 的 skipped_* 与本模块按 sched.go 规则算出的“不进候选池”
    if db.has_table("stat_pool"):
        last_t = db.scalar("SELECT MAX(ts_epoch) FROM stat_pool WHERE ts_epoch <= ?", (end,))
        skipped = {k[len("skipped_"):]: int(v) for k, v in db.q("SELECT key, value FROM stat_pool WHERE ts_epoch = ? AND key LIKE 'skipped_%'", (last_t,))} if last_t else {}
        # 取 stat_pool 最后一条记录之前最近的 start（stat 每隔一段才写一次，最后一条可能写在之后的 start 之前——核对者意见）
        ref_t = last_t if last_t is not None else end
        last_start = max([s for s in starts_all if s <= ref_t] or [fs])
        mine = collections.Counter({r: int(n) for r, n in db.q("""SELECT c.inelig, COUNT(*) FROM list_event e JOIN fr_cand c ON c.cand = e.cand
                                              WHERE e.event = 'add' AND e.ts_epoch >= ? AND e.ts_epoch <= ? AND c.inelig IS NOT NULL GROUP BY 1""", (last_start, ref_t))})
        # 聚合器第一次抽样时对 members 直接 Pool.Upsert（prober.go snapAggregators），抽中的不进候选池的条目也让 Skipped[why]++；
        # 这些条目没有 list_event，按 agg_member 的 cand_ip / cand_port 用同一规则算
        agg_mine = collections.Counter()
        if db.has_table("agg_member"):
            cols = db.columns("agg_member")
            sel = "cand_ip, cand_port" if "cand_ip" in cols and "cand_port" in cols else "NULL, NULL"
            for ip, port, cand in db.q("SELECT %s, cand FROM agg_member WHERE ts_epoch >= ? AND ts_epoch <= ?" % sel, (last_start, ref_t)):
                if ip is None and cand and ":" in cand:   # 老的合成库没有拆好的列，从 cand 拆
                    ip, port = cand.rsplit(":", 1)
                    port = int(port) if port.isdigit() else None
                why = ineligible(ip, port, rules)
                if why:
                    agg_mine[why] += 1
        total = mine + agg_mine
        out["skipped_vs_stat_pool"] = {
            "note": "Pool.Skipped 按 Upsert 调用计数（每个文件的每次 add 各算一次），每次启动归零；这里数 stat_pool 最后一条记录之前最近一次 start 之后、"
                    "不进候选池的候选的 add 事件数，加上同一时段聚合器抽样里不进候选池的成员数。excluded（退出名单）本模块算不出。",
            "stat_pool_last": skipped, "replayed_add_events_by_reason": dict(mine), "aggregator_members_by_reason": dict(agg_mine),
            "mine_total_by_reason": dict(total),
            "agree": all(skipped.get(k, 0) == v for k, v in total.items()) and all(k == "excluded" or total.get(k, 0) == v for k, v in skipped.items()),
        }
    out["replay_anomalies"] = {"del_events_for_unlisted_file": int(db.scalar("SELECT SUM(anomalies) FROM fr_cand") or 0),
                               "note": "del 事件对应的文件当时并没有列着该候选；应为 0"}
    return out


# ---------------------------------------------------------------- 组装

def counts_section(db, fs, end, replay_stats, visit_stats, have_cands):
    n = {
        "有列表事件的候选": int(replay_stats.get("cands", 0)),
        "上榜事件（候选层面，按种类）": {k[len("listing_"):]: int(v) for k, v in replay_stats.items() if k.startswith("listing_")},
        "下榜事件（候选层面）": int(replay_stats.get("delist", 0)),
        "其中无声下榜": int(replay_stats.get("delist_silent", 0)),
        "其中换榜/抖动（flap）": int(db.scalar("SELECT COUNT(*) FROM fr_del WHERE flap = 1") or 0),
        "其中聚合器仍可能列着（agg_held）": int(replay_stats.get("delist_agg_held", 0)),
        "下榜事件（候选层面，不含 flap 与 agg_held）": int(db.scalar("SELECT COUNT(*) FROM fr_del WHERE flap = 0 AND COALESCE(agg_held, 0) = 0") or 0),
        "下榜事件（来源层面）": int(replay_stats.get("src_delist", 0)),
        "不进候选池的候选（按 sched.go 规则）": {k[len("inelig_"):]: int(v) for k, v in replay_stats.items() if k.startswith("inelig_")},
        "kind=new 的上榜事件（含不算新上榜的）": int(db.scalar("SELECT COUNT(*) FROM fr_listing WHERE kind = 'new'") or 0),
        "新上榜事件（可探测的）": int(db.scalar("SELECT COUNT(*) FROM fr_new WHERE probeable = 1") or 0),
        "新上榜且 10 分钟内完成第一次探访": int(db.scalar("SELECT COUNT(*) FROM fr_new WHERE probeable = 1 AND cls = 'fresh'") or 0),
        "下榜事件里下榜前探访过的（不含 flap 与 agg_held）": int(db.scalar("SELECT COUNT(*) FROM fr_del WHERE cat != 'never_visited_before' AND flap = 0 AND COALESCE(agg_held, 0) = 0") or 0),
        "下榜事件里 24 小时观察完整且期间探访过的（不含 flap 与 agg_held）": int(db.scalar("SELECT COUNT(*) FROM fr_del WHERE full_followup = 1 AND visits_after > 0 AND flap = 0 AND COALESCE(agg_held, 0) = 0") or 0),
        "来源数（窗口内有列表事件）": int(db.scalar("SELECT COUNT(DISTINCT src) FROM list_event WHERE ts_epoch BETWEEN ? AND ?", (fs, end)) or 0),
        "列表文件数": int(db.scalar("SELECT COUNT(*) FROM (SELECT DISTINCT src, label FROM snap WHERE COALESCE(agg, 0) = 0)") or 0),
        "快照记录数": int(db.scalar("SELECT COUNT(*) FROM snap") or 0),
        "状态文件里的候选": int(db.scalar("SELECT COUNT(*) FROM fr_cands") or 0) if have_cands else None,
        "候选密集的 /24 个数": int(db.scalar("SELECT COUNT(*) FROM dense24") or 0),
    }
    n.update(visit_stats)
    return n


def build(db, since, until, fresh_min, dense_threshold, with_series, flap_min=FLAP_MIN, enforce_public=None, public_extra=()):
    """enforce_public：None 从数据推断（正常运行）；合成库显式传 True/False。public_extra：当作公网的地址段（CIDR 字符串），只给合成库用。"""
    wl_source = check_whitelist(db)
    for t in ("snap", "list_event", "visit"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表" % t)
    # 同一连接上再次 build（自检里换窗口重算）：先清掉上次的 TEMP 表
    for (name,) in db.q("SELECT name FROM temp.sqlite_master WHERE type = 'table'"):
        db.x('DROP TABLE IF EXISTS temp."%s"' % name)
    win = observation_window(db, since, until)
    fs, end, pre, restart_times = win.pop("_fs"), win.pop("_end"), win.pop("_pre"), win.pop("_restart_times")
    for r in win["restarts_in_window"]:
        r.pop("_t", None)
    starts_all = [s[0] for s in db.q("SELECT ts_epoch FROM start")] if db.has_table("start") else []
    have_cands, dense_basis = build_cand_tables(db, dense_threshold)
    visit_stats = build_visit_table(db, fs, end)
    rules = load_pool_rules(db, enforce_public, _cidrs(public_extra))
    base_times = load_base_times(db, pre, end)
    flap_pairs = load_flap_pairs(db, pre, end)
    agg_sample = load_agg_sample(db)
    replay_stats = Replay(db, fs, end, base_times, restart_times, starts_all, rules, agg_sample, flap_pairs, pre).run()
    build_new_listing_table(db, fs, end, fresh_min * 60.0, have_cands)
    build_delist_tables(db, end, DELIST_FOLLOWUP_H * 3600.0, flap_min * 60.0)

    rep = collections.OrderedDict()
    rep["module"] = MODULE
    rep["generated_utc"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rep["protocol_version"] = PROTOCOL_VERSION
    rep["whitelist_source"] = wl_source
    rep["parameters"] = {"fresh_window_min": fresh_min, "delist_followup_h": DELIST_FOLLOWUP_H, "dense_threshold": dense_threshold,
                         "dense_basis": dense_basis, "snapshot_min_nominal": SNAPSHOT_MIN_NOMINAL,
                         "flap_min": flap_min, "flap_add_tol": FLAP_ADD_TOL, "round_gap_min": ROUND_GAP_MIN,
                         "skip_ports_from_start_config": sorted(rules.skip_ports),
                         "not_public_rule_enforced": rules.enforce_public,
                         "not_public_rule_source": "显式参数" if enforce_public is not None else "从数据推断",
                         "not_public_rule_note": "cfg.AllowLocal 不写进记录；候选池里出现保留段地址（自检夹具）就判定该规则没有生效"}
    rep["db_meta"] = {k: db.meta(k) for k in ("ingest_version", "first_ts", "last_ts", "state_cands", "state_tz_offsets")}
    rep["definitions"] = DEFINITIONS
    rep["window"] = win
    rep["n"] = counts_section(db, fs, end, replay_stats, visit_stats, have_cands)
    rep["dense_prefixes"] = {"threshold": dense_threshold, "basis": dense_basis, "prefixes": dense_prefix_list(db)}
    rep["listing_freshness"] = listing_section(db, fs, end, fresh_min, have_cands, flap_min * 60.0)
    rep["delisting"] = delist_section(db, have_cands, flap_min)
    rep["snapshots"] = snapshot_section(db, fs, end, with_series, flap_pairs[0])
    rep["checks"] = checks_section(db, fs, end, have_cands, restart_times, starts_all, rules)
    return rep


# ---------------------------------------------------------------- Markdown

def fmt(v, suffix=""):
    if v is None:
        return "—"
    if isinstance(v, str):
        return v
    if isinstance(v, float):
        return f"{v:,.1f}{suffix}"
    return f"{v:,}{suffix}"


def rfmt(r):
    if not r or r.get("pct") is None:
        return "—（%s/%s）" % (fmt(r.get("num") if r else None), fmt(r.get("den") if r else None))
    return "%s%%（%s/%s）" % (fmt(r["pct"]), fmt(r["num"]), fmt(r["den"]))


def qfmt(q):
    return " / ".join(fmt(q.get(k)) for k in ("p10", "p50", "p90")) + "（n=%s）" % fmt(q.get("n"))


def markdown(rep):
    out = []
    w = rep["window"]
    out.append("### 列表时效（PROTOCOL“上榜新鲜度”“下榜滞后”）\n")
    out.append("观察窗口 %s 到 %s（%s 小时）；窗口内重启 %d 次。" % (w["obs_start_utc"], w["obs_end_utc"], fmt(w["hours"]), len(w["restarts_in_window"])))
    out.append("")
    lf = rep["listing_freshness"]
    out.append("#### 上榜事件按种类\n")
    out.append("| 种类 | 条数 | 说明 |")
    out.append("| --- | --- | --- |")
    desc = {"initial": "首次快照就在榜（观察起点时已上榜）", "restart_base": "重启后的首次快照才出现（停机期间上榜，时刻不明）",
            "new": "base=0 的 add（含不算新上榜的 pool_already / 不进候选池）", "relist": "下榜后再上榜", "relist_base": "重启后的首次快照里再出现",
            "implicit_initial": "窗口起点时已在榜（--since 落在运行中间，预热重放得出）"}
    for k, v in sorted(lf["上榜事件按种类"].items()):
        out.append("| %s | %s | %s |" % (k, fmt(v), desc.get(k, "")))
    out.append("")
    nc = lf["不算新上榜的 new 事件"]
    out.append("kind=new 共 %s 条，其中 pool_already %s 条（%s）、不进候选池 %s 条（%s）不算新上榜；可探测的新上榜 %s 条。" % (
        fmt(nc["kind=new 事件总数"]), fmt(nc["pool_already"]["total"]), json.dumps(nc["pool_already"]["按原因"], ensure_ascii=False),
        fmt(nc["不进候选池（sched.go ineligible）"]["total"]), json.dumps(nc["不进候选池（sched.go ineligible）"]["按原因"], ensure_ascii=False),
        fmt(lf["新上榜"]["total"])))
    out.append("")
    nl = lf["新上榜"]
    out.append("#### 上榜新鲜度（可探测的新上榜且 10 分钟内完成第一次探访）\n")
    out.append("| 分组 | 新上榜 | 10 分钟内完成第一次探访 | 其中第一次探访可用 | 第一次探访 working/open/dead | 按开始时刻算的新鲜度 |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for key, name in (("all", "全部"), ("excluding_dense", "去掉密集 /24"), ("dense_only", "只看密集 /24"),
                      ("first_hour_after_start", "起点后 1 小时内上榜"), ("after_first_hour", "起点 1 小时后上榜")):
        b = nl[key]
        st = b["第一次探访的状态"]
        tot = nl["total"] if key == "all" else "—"
        fr = rfmt(nl["10 分钟内完成第一次探访"]) if key == "all" else fmt(b["上榜新鲜度"]["den"])
        out.append("| %s | %s | %s | %s | %s / %s / %s | %s |" % (name, fmt(tot), fr, rfmt(b["上榜新鲜度"]), st["working"], st["open"], st["dead"],
                                                            rfmt(b["按开始时刻算的上榜新鲜度（敏感性）"])))
    out.append("")
    out.append("#### 其余新上榜条目（延迟超过 10 分钟或没探访到）\n")
    out.append("| /24 类别 | 延迟超过 10 分钟 | 延迟 p10/p50/p90（分钟） | 没探访到 | 排队没探到 | 原因不明 | 不进候选池（不算新上榜） |")
    out.append("| --- | --- | --- | --- | --- | --- | --- |")
    for key, name in (("dense_prefix", "候选超过阈值的 /24"), ("other_prefix", "其他 /24")):
        b = nl["其余条目（延迟超过 10 分钟或没探访到）"][key]
        nv = b["窗口内没探访到（可探测的）"]
        out.append("| %s | %s | %s | %s | %s | %s | %s |" % (name, fmt(b["延迟超过 10 分钟"]), qfmt(b["延迟分布（超过 10 分钟的）"]["quantiles"]),
                                                     fmt(nv["total"]), fmt(nv["候选池里排队没探到"]),
                                                     fmt(nv["原因不明（不在状态文件、规则也不排除）"] + nv["没有状态文件、无法区分"]),
                                                     fmt(b["不进候选池（不算新上榜）"]["total"])))
    out.append("")
    if lf["by_source"]:
        out.append("#### 上榜新鲜度按来源（同一时刻加入的每个来源各记一次）\n")
        out.append("| 来源 | 可探测的新上榜 | 10 分钟内完成第一次探访 | 第一次探访可用 | 延迟超过 10 分钟 | 没探访到 | 不算新上榜的 new |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        for src, b in lf["by_source"].items():
            out.append("| %s | %s | %s | %s | %s | %s | %s |" % (src, fmt(b["可探测的新上榜（该来源参与的）"]), rfmt(b["10 分钟内完成第一次探访"]), rfmt(b["上榜新鲜度"]),
                                                        fmt(b["延迟超过 10 分钟"]), fmt(b["没探访到"]), fmt(b["不算新上榜的 new 事件（pool_already / 不进候选池）"])))
        out.append("")
    dl = rep["delisting"]
    out.append("#### 下榜（候选层面：从所有列表消失；默认不含换榜/抖动与聚合器仍可能列着的事件）\n")
    out.append("| 分组 | 下榜事件 | 无声下榜 | flap | agg_held | 下榜前探访过 | 下榜时仍可用 | 下榜时已死 | 从未可用 | 已死的滞后 p10/p50/p90（分钟） | 下榜后第一次探访可用 | 下榜后 24 小时内仍可用 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, name in (("all", "全部（默认）"), ("excluding_dense", "去掉密集 /24"), ("first_delist_only", "每个候选只算第一次下榜"),
                      ("including_flaps_and_agg_held", "含 flap 与 agg_held"), ("flaps_only", "只看 flap"), ("agg_held_only", "只看 agg_held")):
        b = dl["candidate_level"][key]
        out.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            name, fmt(b["下榜事件"]), fmt(b["其中无声下榜（重启后的首次快照里消失）"]), fmt(b["其中换榜/抖动（flap）"]["total"]), fmt(b["其中聚合器仍可能列着（agg_held）"]),
            fmt(b["下榜时仍可用（最后一次探访可用）"]["den"]),
            rfmt(b["下榜时仍可用（最后一次探访可用）"]), rfmt(b["下榜时已死（曾可用、最后一次探访不可用）"]), rfmt(b["下榜时从未可用"]),
            qfmt(b["下榜滞后（已死的：最后一次可用到下榜）"]["quantiles"]), rfmt(b["下榜后第一次探访可用"]), rfmt(b["下榜后 24 小时内仍可用"])))
    a = dl["candidate_level"]["all"]["下榜后 24 小时的观察"]
    out.append("")
    out.append("只算 24 小时内没再上榜的下榜事件（默认组）：24 小时内仍可用 %s。" % rfmt(dl["candidate_level"]["all"]["下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）"]))
    out.append("默认组里 24 小时观察不足的下榜事件 %s 条、24 小时内没探访的 %s 条不进分母；24 小时内又上榜的 %s 条（flap_min=%s 分钟）。" % (
        fmt(a["不足 24 小时（不进分母）"]), fmt(a["24 小时内没探访（不进分母）"]), fmt(a["24 小时内又上榜"]), fmt(dl["flap_min"])))
    out.append("")
    if dl["source_level"]["by_source"]:
        out.append("#### 下榜按来源（来源层面：从该来源的全部文件消失）\n")
        out.append("| 来源 | 下榜事件 | 下榜时仍可用 | 下榜时已死 | 已死的滞后 p50（分钟） | 下榜后 24 小时内仍可用 |")
        out.append("| --- | --- | --- | --- | --- | --- |")
        for src, b in dl["source_level"]["by_source"].items():
            out.append("| %s | %s | %s | %s | %s | %s |" % (src, fmt(b["下榜事件"]), rfmt(b["下榜时仍可用（最后一次探访可用）"]),
                                                   rfmt(b["下榜时已死（曾可用、最后一次探访不可用）"]),
                                                   fmt(b["下榜滞后（已死的：最后一次可用到下榜）"]["quantiles"]["p50"]), rfmt(b["下榜后 24 小时内仍可用"])))
        out.append("")
    sn = rep["snapshots"]
    out.append("#### 快照（按来源汇总）\n")
    out.append("| 来源 | 聚合器 | 文件 | 抓取 | 失败 | 有变化 | 首次快照 | 增 | 减 | 最后一次条目数 | 增减/小时 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for src, s in sn["by_source"].items():
        out.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            src, "是" if s["aggregator"] else "", fmt(s["files"]), fmt(s["fetches"]), fmt(s["failed_fetches"]), fmt(s["changed"]),
            fmt(s["base_snapshots"]), fmt(s["adds"]), fmt(s["dels"]), fmt(s["entries_last_sum"]), fmt(s["churn_per_hour"])))
    out.append("")
    if rep["dense_prefixes"]["prefixes"]:
        out.append("#### 候选密集的 /24（候选超过 %d 个；“去掉密集 /24”的组去掉的就是它们）\n" % rep["dense_prefixes"]["threshold"])
        out.append("| /24 | 候选 | 探访到 | 有列表事件的候选 | 可探测的新上榜 | 候选层面下榜 |")
        out.append("| --- | --- | --- | --- | --- | --- |")
        for p in rep["dense_prefixes"]["prefixes"]:
            out.append("| %s | %s | %s | %s | %s | %s |" % (p["prefix24"], fmt(p["候选"]), fmt(p["探访到"]), fmt(p["有列表事件的候选"]),
                                                   fmt(p["可探测的新上榜"]), fmt(p["候选层面下榜"])))
        out.append("")
    ck = rep["checks"]
    out.append("#### 核对\n")
    lv = ck["visit_listed_vs_replay"]
    out.append("- visit.listed 与重放一致：%s（visit 说在榜、重放说不在 %s；反之 %s）" % (rfmt(lv["agree"]), fmt(lv["visit_says_listed_replay_says_not"]), fmt(lv["visit_says_not_replay_says_listed"])))
    sf = ck["state_file"]
    if "delisted_at" in sf:
        d = sf["delisted_at"]
        out.append("- 状态文件 listed 一致：%s；delisted_at 比对 %s 条：1 秒内相符 %s、重启痕迹 %s、聚合器仍列着且重启清空 %s、无重放下榜 %s、不符 %s" % (
            rfmt(sf["listed_flag_agree"]), fmt(d["compared"]), fmt(d["match_within_1s"]), fmt(d["restart_artifact_pool_load"]),
            fmt(d["agg_held_cleared_at_restart"]), fmt(d["no_replayed_delist"]), fmt(d["mismatch"])))
    else:
        out.append("- " + sf["note"])
    c = sn["check_snap_vs_list_event"]
    out.append("- snap 的 n_add/n_del 之和 = list_event 事件数：%s（%s/%s 增，%s/%s 减）" % ("是" if c["equal"] else "否", fmt(c["snap_n_add_sum"]), fmt(c["list_event_add"]), fmt(c["snap_n_del_sum"]), fmt(c["list_event_del"])))
    if "skipped_vs_stat_pool" in ck:
        s = ck["skipped_vs_stat_pool"]
        out.append("- 不进候选池的 add 事件数与 stat_pool 的 skipped_* 一致：%s（stat %s；重放 %s）" % ("是" if s["agree"] else "否", json.dumps(s["stat_pool_last"], ensure_ascii=False), json.dumps(s["replayed_add_events_by_reason"], ensure_ascii=False)))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- 输出前的自检

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d{1,5})?(?!\d|\.\d)")


def assert_no_identifiers(text, db):
    """写出前扫一遍：不许有 ip（/24 前缀 a.b.c.0/24 除外）、ip:port、judge 的主机名和地址、@。
    这是最后一道保险，不是放行依据：放行靠白名单取列。"""
    bad = []
    for m in _IPV4.finditer(text):
        tail = text[m.end():m.end() + 3]
        if not (m.group(4) == "0" and tail == "/24" and ":" not in m.group(0)):
            bad.append(m.group(0))
    for tbl, col in (("self_names", "name"), ("self_ips", "ip")):
        if db.has_table(tbl):
            for (v,) in db.q("SELECT DISTINCT %s FROM %s" % (col, tbl)):
                if v and v.lower() in text.lower():
                    bad.append("<%s>" % tbl)
    # judge 的主机名 / IP 只从库里的 self_names / self_ips 取（上面），不在脚本里写成常量（仓库公开；夹具的也一样）；
    # 回环地址等 IP 字面量由 _IPV4 正则兜底。只剩 "@"（凭据 / 邮箱）需要字面量检查。
    if "@" in text:
        bad.append("字面量 @")
    if bad:
        raise SystemExit("输出里出现了不该出现的标识，拒绝写出：%s" % ", ".join(sorted(set(bad))[:5]))


# ---------------------------------------------------------------- 合成库自检

SELFTEST_SCHEMA = """
CREATE TABLE snap (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, src TEXT, label TEXT, status INTEGER, err TEXT, n INTEGER,
    base INTEGER, agg INTEGER, changed INTEGER, n_add INTEGER, n_del INTEGER, ms INTEGER);
CREATE TABLE list_event (rid INTEGER PRIMARY KEY, snap_rid INTEGER, ts TEXT, ts_epoch REAL, src TEXT, label TEXT, cand TEXT, event TEXT,
    base INTEGER, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
CREATE INDEX list_event_cand_ts ON list_event(cand, ts_epoch);
CREATE TABLE visit (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, "group" INTEGER, n INTEGER, prev TEXT, state TEXT,
    listed INTEGER, aborted INTEGER, next_min REAL, ms INTEGER, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT, n_ok INTEGER);
CREATE INDEX visit_cand_ts ON visit(cand, ts_epoch);
CREATE TABLE cands (key TEXT PRIMARY KEY, prefix24 TEXT, "group" INTEGER, listed INTEGER, visits INTEGER, first_seen_epoch REAL,
    delisted_at_epoch REAL, state_name TEXT, ever_ok INTEGER);
CREATE TABLE agg_member (rid INTEGER PRIMARY KEY, ts_epoch REAL, src TEXT, cand TEXT, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
CREATE TABLE start (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER,
    raw TEXT DEFAULT '{"probe":{"skip_ports":[22,25]}}');
CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visits INTEGER);
CREATE TABLE version (rid INTEGER PRIMARY KEY, ts_epoch REAL, version TEXT);
CREATE TABLE stat_pool (rid INTEGER PRIMARY KEY, ts_epoch REAL, key TEXT, value INTEGER);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
"""


class Synth:
    """往合成库里写记录的小帮手：snap 带事件、探访。"""

    def __init__(self, conn):
        self.conn = conn
        self.snap_rid = 0

    def snap(self, t, src, label, status=200, changed=0, base=0, n=None, add=(), dele=(), err=None):
        self.snap_rid += 1
        self.conn.execute("INSERT INTO snap VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (self.snap_rid, ts_text(t), t, src, label, status, err, n, base or None, None, changed or None,
                           len(add), len(dele), 5))
        for ev, keys in (("add", add), ("del", dele)):
            for k in keys:
                ip, port = k.rsplit(":", 1)
                pfx = ".".join(ip.split(".")[:3]) + ".0/24"
                self.conn.execute("INSERT INTO list_event (snap_rid, ts, ts_epoch, src, label, cand, event, base, cand_ip, cand_port, prefix24) "
                                  "VALUES (?,?,?,?,?,?,?,?,?,?,?)", (self.snap_rid, ts_text(t), t, src, label, k, ev, base or None, ip, int(port), pfx))

    def visit(self, t, cand, ok, listed=1, ms=3000, aborted=None, grp=None):
        ip, port = cand.rsplit(":", 1)
        pfx = ".".join(ip.split(".")[:3]) + ".0/24"
        self.conn.execute("INSERT INTO visit (ts, ts_epoch, visit, cand, \"group\", n, prev, state, listed, aborted, next_min, ms, cand_ip, cand_port, prefix24, n_ok) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (ts_text(t), t, "v", cand, grp, 1, "new", "working" if ok else "dead", listed, aborted, 20, ms, ip, int(port), pfx,
                           1 if ok else None))


def selftest(keep=None):
    """最小合成库，覆盖：initial / restart_base / new / relist / pool_already（三种原因）/ 不进候选池；10 分钟内可用与不可用、延迟超时
    （密集与非密集）、没探访到（排队、私网、知名端口）；候选层面与来源层面下榜、四种下榜时状态、滞后、24 小时内仍可用、观察不足 24 小时、
    无声下榜（重启首次快照里消失）、Pool.Load 的重启痕迹、聚合器仍列着的常规列表删除（agg_held）、坏抓取造成的换榜/抖动（flap）、
    listed 标志核对、快照序列、--since 落在运行中间的预热。通过时打印 selftest ok。

    地址只用 RFC 5737 文档段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）：公开仓库里不放可路由的 ip:port。这些段在 lists.go 里是保留段，
    所以 build 显式传 enforce_public=True 并把三个段列为 public_extra，10.0.0.5 仍是 not_public 用例。"""
    T0 = 1_800_000_000.0
    H, M = 3600.0, 60.0
    DOC_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    fd, path = tempfile.mkstemp(prefix="m_freshness_selftest_", suffix=".sqlite")
    os.close(fd)
    os.unlink(path)
    conn = sqlite3.connect(path)
    conn.executescript(SELFTEST_SCHEMA)
    conn.execute("INSERT INTO self_names VALUES ('judge.example.test', 'start.judge_host', 1)")
    conn.execute("INSERT INTO self_ips VALUES ('198.51.100.9', 'start.judge_ip', 1)")
    conn.execute("INSERT INTO meta VALUES ('state_tz_offsets', '{\"+08:00\": 1}')")
    s = Synth(conn)
    END = T0 + 40 * H
    conn.execute("INSERT INTO start (ts, ts_epoch, resumed_candidates) VALUES (?, ?, 0)", (ts_text(T0), T0))
    conn.execute("INSERT INTO version (ts_epoch, version) VALUES (?, 'x')", (T0,))
    RESTART = T0 + 15 * H
    conn.execute("INSERT INTO stop (ts, ts_epoch, visits) VALUES (?, ?, 10)", (ts_text(RESTART - 10 * M), RESTART - 10 * M))
    conn.execute("INSERT INTO start (ts, ts_epoch, resumed_candidates) VALUES (?, ?, 20)", (ts_text(RESTART), RESTART))
    conn.execute("INSERT INTO version (ts_epoch, version) VALUES (?, 'x')", (RESTART,))
    conn.execute("INSERT INTO stop (ts, ts_epoch, visits) VALUES (?, ?, 10)", (ts_text(END), END))

    A, B = "srcA", "srcB"
    P1, P2, P3 = "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
    c1, c2, c3, c9, c10 = "192.0.2.1:8080", "192.0.2.2:8080", "192.0.2.3:8080", "192.0.2.9:8080", "192.0.2.10:8080"
    judge_self = "198.51.100.9:8080"   # judge 自身（self 先于 not_public 判）
    n1, n2, n4, n5 = "198.51.100.1:3128", "198.51.100.2:3128", "198.51.100.4:3128", "198.51.100.5:3128"
    n3 = "203.0.113.200:8080"          # 密集 /24
    n11, n12 = "10.0.0.5:8080", "198.51.100.12:22"   # not_public、skip_port
    n6 = "192.0.2.106:1080"            # 聚合器抽样条目后来进了常规列表（pool_already）
    r1 = "192.0.2.41:8080"             # 重启后的首次快照才出现
    e1 = "192.0.2.51:8080"             # 边界：重启时 A/http 的 base 快照没有它、B/http 的 base 快照（同一时刻）第一次列出它
    g1, g2 = "192.0.2.61:1080", "192.0.2.62:1080"   # 聚合器抽样条目：只在聚合器里
    a1 = "192.0.2.71:1080"             # 聚合器抽样 → 5h 进 A/http → 10h 被 A/http 删掉：prober 里聚合器仍列着（agg_held）
    # 首次快照（T0+5s）
    s.snap(T0 + 5, A, "http", changed=1, base=1, n=6, add=[c1, c2, c9, c10, judge_self, e1])
    s.snap(T0 + 5, A, "socks5", changed=1, base=1, n=0, add=[])
    s.snap(T0 + 5, B, "http", changed=1, base=1, n=2, add=[c2, c3])
    s.snap(T0 + 6, "aggX", "http", changed=1, n=1000)  # 聚合器：只有数量
    conn.execute("UPDATE snap SET agg = 1 WHERE src = 'aggX'")
    for k in (n6, g1, g2, a1):
        conn.execute("INSERT INTO agg_member (ts_epoch, src, cand, cand_ip, cand_port, prefix24) VALUES (?, 'aggX', ?, ?, ?, ?)",
                     (T0 + 10, k, k.rsplit(":", 1)[0], int(k.rsplit(":", 1)[1]), P1))
    # 无变化、304、失败各一条，给序列用
    s.snap(T0 + 10 * M, A, "http", status=200)
    s.snap(T0 + 20 * M, A, "http", status=304)
    s.snap(T0 + 30 * M, B, "http", status=0, err="dial: boom")
    # 新上榜
    s.snap(T0 + 1 * H, A, "http", changed=1, n=6, add=[n1])
    s.snap(T0 + 1 * H, B, "http", changed=1, n=3, add=[n2])
    s.snap(T0 + 2 * H, A, "http", changed=1, n=8, add=[n3, n4])
    s.snap(T0 + 3 * H, A, "http", changed=1, n=11, add=[n5, n11, n12])
    s.snap(T0 + 4 * H, A, "socks5", changed=1, n=1, add=[n6])
    s.snap(T0 + 5 * H, A, "http", changed=1, n=12, add=[a1])
    # 下榜
    s.snap(T0 + 6 * H, A, "http", changed=1, n=11, dele=[c1])            # c1 候选层面下榜（已死 1 小时）
    s.snap(T0 + 8 * H, A, "http", changed=1, n=10, dele=[c2])            # c2 来源 A 下榜，仍在 B
    s.snap(T0 + 9 * H, B, "http", changed=1, n=2, dele=[c3])             # c3 从未可用
    s.snap(T0 + 10 * H, A, "http", changed=1, n=9, dele=[a1])            # a1：常规列表删掉，但聚合器仍列着（agg_held）
    s.snap(T0 + 12 * H, B, "http", changed=1, n=1, dele=[c2])            # c2 候选层面下榜（仍可用）
    # 重启后的首次快照：c9 无声消失；r1 新出现
    s.snap(RESTART + 5, A, "http", changed=1, base=1, n=9, add=[c10, judge_self, n1, n3, n4, n5, n11, n12, r1])
    s.snap(RESTART + 5, A, "socks5", changed=1, base=1, n=1, add=[n6])
    s.snap(RESTART + 5, B, "http", changed=1, base=1, n=2, add=[n2, e1])
    s.snap(T0 + 20 * H, A, "http", changed=1, n=10, add=[c1])            # c1 再上榜（距下榜 14 小时，不是抖动）
    # 坏抓取：B/http 在 22h 解析出 0 条（Del=全部），下一轮又全部加回 → 文件层面抖动 + 两条 10 分钟内的再上榜
    s.snap(T0 + 22 * H, B, "http", changed=1, n=0, dele=[n2, e1])
    s.snap(T0 + 22 * H + 10 * M, B, "http", changed=1, n=2, add=[n2, e1])
    s.snap(T0 + 30 * H, A, "http", changed=1, n=9, dele=[c10])           # c10 下榜，观察不足 24 小时
    # 探访
    def visits(cand, start, end, step, okfn, listedfn=lambda t: 1, grp=None):
        t = start
        while t <= end:
            s.visit(t, cand, okfn(t), listed=listedfn(t), grp=grp)
            t += step
    # c1：可用到 T0+5h，之后不可用；6h 下榜；10h 又可用一次；20h 再上榜
    visits(c1, T0 + 10 * M, T0 + 5 * H, 20 * M, lambda t: True)
    visits(c1, T0 + 5 * H + 20 * M, T0 + 9 * H, 20 * M, lambda t: False, lambda t: 1 if t < T0 + 6 * H else 0)
    s.visit(T0 + 10 * H, c1, True, listed=0)
    s.visit(T0 + 20 * H + 3 * M, c1, True, listed=1)
    # c2：一直可用
    visits(c2, T0 + 12 * M, END - 1, 20 * M, lambda t: True, lambda t: 1 if t < T0 + 12 * H else 0)
    # e1：一直可用、一直在榜（先在 A，重启后只在 B；22h 的坏抓取让它“下榜”10 分钟）
    visits(e1, T0 + 14 * M, END - 1, 60 * M, lambda t: True)
    # c3：一直不可用
    visits(c3, T0 + 15 * M, T0 + 9 * H + 50 * M, 20 * M, lambda t: False, lambda t: 1 if t < T0 + 9 * H else 0)
    # c9：可用；重启后无声下榜；16h 还可用
    visits(c9, T0 + 11 * M, RESTART - 15 * M, 20 * M, lambda t: True)
    s.visit(T0 + 16 * H, c9, True, listed=0)
    # c10：可用，30h 下榜，之后也可用
    visits(c10, T0 + 13 * M, END - 1, 20 * M, lambda t: True, lambda t: 1 if t < T0 + 30 * H else 0)
    # 新上榜的探访
    s.visit(T0 + 1 * H + 2 * M, n1, True)                 # 10 分钟内，可用
    s.visit(T0 + 1 * H + 5 * M, n2, False)                # 10 分钟内，不可用
    s.visit(T0 + 2 * H + 45 * M, n3, True, ms=0)          # 超时（密集 /24），延迟正好 45 分钟
    s.visit(T0 + 2 * H + 25 * M, n4, True)                # 超时（非密集）
    visits(n6, T0 + 20 * M, T0 + 5 * H, 60 * M, lambda t: True, lambda t: 1, grp=1)   # 聚合器抽样条目一直在探
    # a1：聚合器抽样条目，一直可用；进常规列表后 group 改成 0；prober 里重启前一直在榜（聚合器来源），重启后 Pool.Load 清空、不再被加回
    visits(a1, T0 + 20 * M, END - 1, 60 * M, lambda t: True, lambda t: 1 if t < RESTART else 0, grp=1)
    conn.execute("UPDATE visit SET \"group\" = 0 WHERE cand = ? AND ts_epoch >= ?", (a1, T0 + 5 * H))
    # 一条故意不一致的 listed 标志：c2 在 T0+12m 的探访说 listed=0
    conn.execute("UPDATE visit SET listed = 0 WHERE cand = ? AND ts_epoch = ?", (c2, T0 + 12 * M))
    # 状态文件：c9 的 delisted_at 是重启时刻（Pool.Load 痕迹）；n5 在候选池里但没探到；密集 /24 有 101 个候选
    rows = [(c1, P1, 0, 1, 20, T0 + 5, None), (c2, P1, 0, 0, 100, T0 + 5, T0 + 12 * H),
            (c3, P1, 0, 0, 30, T0 + 5, T0 + 9 * H), (c9, P1, 0, 0, 40, T0 + 5, RESTART),
            (c10, P1, 0, 0, 100, T0 + 5, T0 + 30 * H),
            (n1, P2, 0, 1, 1, T0 + 1 * H, None), (n2, P2, 0, 1, 1, T0 + 1 * H, None),
            (n3, P3, 0, 1, 1, T0 + 2 * H, None), (n4, P2, 0, 1, 1, T0 + 2 * H, None),
            (n5, P2, 0, 1, 0, T0 + 3 * H, None), (n6, P1, 0, 1, 5, T0 + 10, None),
            (r1, P1, 0, 1, 0, RESTART + 5, None), (e1, P1, 0, 1, 40, T0 + 5, None)]
    for i in range(1, 101):
        rows.append(("203.0.113.%d:8080" % i, P3, 0, 1, 0, T0 + 5, None))
    conn.executemany('INSERT INTO cands (key, prefix24, "group", listed, visits, first_seen_epoch, delisted_at_epoch) VALUES (?,?,?,?,?,?,?)', rows)
    conn.executemany("INSERT INTO cands VALUES (?,?,?,?,?,?,?,?,?)",
                     [(g1, P1, 1, 1, 3, T0 + 10, None, "working", 1),
                      (g2, P1, 1, 0, 3, T0 + 10, T0 + 20 * H, "working", 1),
                      (a1, P1, 0, 0, 40, T0 + 10, RESTART, "working", 1)])   # a1：Pool.Load 在重启时清空了聚合器来源 → delisted_at = 重启时刻
    # stat_pool：最后一次 start 之后，不进候选池的 add 事件：judge_self（self）1 次、n11（not_public）1 次、n12（skip_port）1 次
    for k, v in (("skipped_self", 1), ("skipped_not_public", 1), ("skipped_skip_port", 1), ("listed", 12)):
        conn.execute("INSERT INTO stat_pool (ts_epoch, key, value) VALUES (?, ?, ?)", (END - 1, k, v))
    conn.commit()
    conn.close()

    db = DB(path)
    rep = build(db, None, None, FRESH_WINDOW_MIN, DENSE_THRESHOLD, with_series=True, enforce_public=True, public_extra=DOC_NETS)
    text = json.dumps(rep, ensure_ascii=False, indent=1)
    assert_no_identifiers(text, db)
    assert "192.0.2.1" not in text and "judge.example" not in text and "198.51.100.9" not in text
    try:
        assert_no_identifiers(text + " 192.0.2.1:8080", db)
    except SystemExit:
        pass
    else:
        raise AssertionError("assert_no_identifiers 没有抓到 ip:port")
    try:
        assert_no_identifiers(text + " judge.example.test", db)
    except SystemExit:
        pass
    else:
        raise AssertionError("assert_no_identifiers 没有抓到 self_names 里的主机名")
    md = markdown(rep)
    assert_no_identifiers(md, db)
    assert rep["parameters"]["not_public_rule_enforced"] is True
    assert ineligible("10.0.0.5", 8080, PoolRules(set(), set(), True, _cidrs(DOC_NETS))) == "not_public"

    kinds = rep["listing_freshness"]["上榜事件按种类"]
    assert kinds == {"initial": 7, "new": 9, "relist": 3, "restart_base": 1}, kinds
    cls = rep["listing_freshness"]["新上榜按分类（kind=new 全部）"]
    assert cls == {"fresh": 2, "late": 2, "never_visited_in_pool": 1, "never_visited_ineligible": 2, "pool_already": 2}, cls
    nc = rep["listing_freshness"]["不算新上榜的 new 事件"]
    assert nc["pool_already"]["按原因"] == {"visited_before": 2}, nc    # n6、a1 上榜前都有探访（原因按优先级取一个）
    assert nc["不进候选池（sched.go ineligible）"]["按原因"] == {"not_public": 1, "skip_port": 1}, nc
    nl = rep["listing_freshness"]["新上榜"]
    assert nl["total"] == 5 and nl["10 分钟内完成第一次探访"] == {"num": 2, "den": 5, "pct": 40.0}, nl["10 分钟内完成第一次探访"]
    assert nl["10 分钟内开始第一次探访（敏感性）"] == {"num": 2, "den": 5, "pct": 40.0}
    assert nl["all"]["上榜新鲜度"] == {"num": 1, "den": 2, "pct": 50.0}, nl["all"]
    assert nl["all"]["第一次探访的状态"] == {"working": 1, "open": 0, "dead": 1}
    assert nl["first_hour_after_start"]["上榜新鲜度"]["den"] == 0 and nl["after_first_hour"]["上榜新鲜度"]["den"] == 2
    late = nl["其余条目（延迟超过 10 分钟或没探访到）"]
    assert late["dense_prefix"]["延迟超过 10 分钟"] == 1 and late["other_prefix"]["延迟超过 10 分钟"] == 1
    assert late["dense_prefix"]["延迟分布（超过 10 分钟的）"]["quantiles"]["p50"] == 45.0
    assert late["other_prefix"]["不进候选池（不算新上榜）"]["按原因"] == {"not_public": 1, "skip_port": 1}
    assert late["other_prefix"]["窗口内没探访到（可探测的）"] == {"total": 1, "候选池里排队没探到": 1, "原因不明（不在状态文件、规则也不排除）": 0,
                                                 "没有状态文件、无法区分": 0, "其中上榜到观察结束不足 10 分钟": 0}, late["other_prefix"]
    bs = rep["listing_freshness"]["by_source"]
    assert bs["srcA"]["可探测的新上榜（该来源参与的）"] == 4 and bs["srcA"]["不算新上榜的 new 事件（pool_already / 不进候选池）"] == 4, bs["srcA"]
    assert bs["srcB"]["可探测的新上榜（该来源参与的）"] == 1
    assert bs["srcB"]["上榜新鲜度"] == {"num": 0, "den": 1, "pct": 0.0}
    rl = rep["listing_freshness"]["再上榜（relist，下榜后又出现）"]
    assert rl["total"] == 3 and rl["其中换榜/抖动（距下榜 ≤ flap_min 或文件层面抖动）"] == 2, rl

    dl = rep["delisting"]
    d = dl["candidate_level"]["all"]
    assert d["下榜事件"] == 5 and d["其中无声下榜（重启后的首次快照里消失）"] == 1, d
    assert d["其中换榜/抖动（flap）"]["total"] == 0 and d["其中聚合器仍可能列着（agg_held）"] == 0
    assert d["下榜时的状态"] == {"died_before_delist": 1, "ok_at_delist": 3, "never_ok_before": 1}, d["下榜时的状态"]
    lag = d["下榜滞后（已死的：最后一次可用到下榜）"]
    assert lag["quantiles"]["p50"] == 70.0, lag["quantiles"]   # c1：最后一次可用 4h50（10m + 14×20m），6h 下榜
    assert lag["histogram"][2]["n"] == 1, lag["histogram"]      # [60, 120)
    # 24 小时内仍可用：c1 是、c2 是、c3 否、c9 是；c10 观察不足
    assert d["下榜后 24 小时内仍可用"] == {"num": 3, "den": 4, "pct": 75.0}, d["下榜后 24 小时内仍可用"]
    # c1 在下榜 14 小时后再上榜（24 小时内），变体里不算：剩 c2 是、c3 否、c9 是
    assert d["下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）"] == {"num": 2, "den": 3, "pct": 66.7}, d["下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）"]
    assert d["下榜后 24 小时的观察"]["不足 24 小时（不进分母）"] == 1 and d["下榜后 24 小时的观察"]["24 小时内又上榜"] == 1
    assert d["下榜后第一次探访可用"] == {"num": 3, "den": 5, "pct": 60.0}, d["下榜后第一次探访可用"]
    assert d["在榜时长（下榜时刻 − 这次上榜时刻；initial 的是下界）"]["quantiles"]["n"] == 5
    inc = dl["candidate_level"]["including_flaps_and_agg_held"]
    assert inc["下榜事件"] == 8 and inc["其中换榜/抖动（flap）"] == {"total": 2, "文件层面抖动": 2, "再上榜距下榜 ≤ flap_min": 2} and inc["其中聚合器仍可能列着（agg_held）"] == 1, inc
    fl = dl["candidate_level"]["flaps_only"]
    assert fl["下榜事件"] == 2 and fl["下榜时的状态"] == {"ok_at_delist": 1, "never_ok_before": 1}, fl
    ah = dl["candidate_level"]["agg_held_only"]
    assert ah["下榜事件"] == 1 and ah["下榜时的状态"] == {"ok_at_delist": 1}, ah
    assert dl["agg_held_vs_state_file"] == {"note": dl["agg_held_vs_state_file"]["note"], "compared": 1, "state_file_listed": 0,
                                           "state_file_delisted_at_restart": 1, "inconsistent": 0}, dl["agg_held_vs_state_file"]
    sl = dl["source_level"]
    # e1：A/http 的 base 快照（RESTART+5）没有它 → 来源 A 无声下榜；B/http 同一时刻的 base 快照列出它 → 候选层面不下榜
    # a1：来源层面是 A 的真实下榜（不排除）；n2、e1 在 22h 的来源 B 下榜是抖动（默认排除）
    assert sl["all"]["下榜事件"] == 8 and sl["including_flaps"]["下榜事件"] == 10 and sl["still_listed_elsewhere"] == 2, (sl["all"]["下榜事件"], sl["still_listed_elsewhere"])
    assert sl["by_source"]["srcA"]["下榜事件"] == 6 and sl["by_source"]["srcB"]["下榜事件"] == 2
    assert sl["by_source"]["srcA"]["其中无声下榜（重启后的首次快照里消失）"] == 2
    assert sl["agg_held（只作参考，来源层面不排除）"] == 1
    assert rep["n"]["其中无声下榜"] == 1 and rep["n"]["其中换榜/抖动（flap）"] == 2 and rep["n"]["其中聚合器仍可能列着（agg_held）"] == 1
    ag = dl["aggregator_sample_state_file"]
    assert ag["抽样条目（agg_member 成员）"] == 4 and ag["后来进了常规列表（group=0）"] == 2, ag
    g = ag["仍只在聚合器（group=1）"]
    assert g["抽样条目"] == 2 and g["结束时已下榜"] == 1 and g["已下榜且最后一次探访可用"] == {"num": 1, "den": 1, "pct": 100.0}, ag
    assert sl["by_source"]["srcB"]["下榜后 24 小时内仍可用"] == {"num": 1, "den": 2, "pct": 50.0}
    assert dl["still_alive_summary"]["下榜时最后一次探访仍可用"] == {"num": 3, "den": 5, "pct": 60.0}
    assert dl["still_alive_summary"]["含 flap 与 agg_held"]["下榜时最后一次探访仍可用"] == {"num": 5, "den": 8, "pct": 62.5}

    sn = rep["snapshots"]
    fa = [f for f in sn["files"] if f["src"] == "srcA" and f["label"] == "http"][0]
    assert fa["fetches"] == 13 and fa["failed_fetches"] == 0 and fa["base_snapshots"] == 2 and fa["base_entries"] == 15 and fa["flap_pairs"] == []
    rounds_a = sn["by_source"]["srcA"]["rows"]
    assert rounds_a[0][1] == 2 and rounds_a[0][4] == 2 and rounds_a[0][5] == 6, rounds_a[0]   # 首轮：2 个文件、2 个 base、条目 6+0
    assert rounds_a[0][0].endswith("Z") and len(rounds_a[0][0]) == len("2027-01-15T08:00:05Z")
    assert sum(r[6] for r in rounds_a) == 9 and sum(r[7] for r in rounds_a) == 4, rounds_a      # 来源 A 两个文件合计：增 8+1、减 4
    assert fa["adds"] == 8 and fa["dels"] == 4 and fa["entries_last"] == 9
    fb = [f for f in sn["files"] if f["src"] == "srcB"][0]
    assert fb["failed_fetches"] == 1 and len(fb["flap_pairs"]) == 1 and fb["flap_pairs"][0][2:] == [2, 2], fb["flap_pairs"]
    assert sn["by_source"]["aggX"]["aggregator"] is True
    assert sn["check_snap_vs_list_event"]["equal"]
    hours_with_new = {h["hour_index"]: h["new_listings"] for h in sn["hourly_candidate_events"] if h["new_listings"]}
    assert hours_with_new == {1: 2, 2: 2, 3: 1}, hours_with_new
    hourly = {h["hour_index"]: h for h in sn["hourly_candidate_events"]}
    assert hourly[3]["new_not_counted"] == 2 and hourly[4]["new_not_counted"] == 1 and hourly[5]["new_not_counted"] == 1, hourly
    assert hourly[1]["new_fresh"] == 2 and hourly[2]["new_late"] == 2 and hourly[3]["new_never_visited"] == 1
    assert hourly[22]["delists"] == 2 and hourly[22]["delists_flap"] == 2 and hourly[10]["delists_agg_held"] == 1, hourly

    ck = rep["checks"]
    lv = ck["visit_listed_vs_replay"]
    assert lv["visit_says_not_replay_says_listed"] == 1 and lv["visit_says_listed_replay_says_not"] == 0, lv
    sf = ck["state_file"]
    assert sf["delisted_at"] == {"compared": 5, "match_within_1s": 3, "restart_artifact_pool_load": 1, "agg_held_cleared_at_restart": 1,
                                 "no_replayed_delist": 0, "mismatch": 0}, sf["delisted_at"]
    assert sf["listed_flag_agree"]["num"] == sf["listed_flag_agree"]["den"]
    assert sf["first_seen_vs_first_add"]["compared"] == 12 and sf["first_seen_vs_first_add"]["match_within_1s"] == 12, sf["first_seen_vs_first_add"]
    assert ck["skipped_vs_stat_pool"]["agree"], ck["skipped_vs_stat_pool"]
    assert ck["replay_anomalies"]["del_events_for_unlisted_file"] == 0
    dp = rep["dense_prefixes"]["prefixes"][0]
    assert dp["prefix24"] == P3 and dp["候选"] == 101 and dp["探访到"] == 1 and dp["可探测的新上榜"] == 1, dp
    assert rep["n"]["visits_ok_state_mismatch"] == 0
    assert "srcA" in md and P3 in md

    # --since 落在运行中间（7h）：预热重放，起点时在榜的 15 个候选记为 implicit_initial；c1 在起点前下榜、20h 再出现 → relist
    rep2 = build(db, T0 + 7 * H, None, FRESH_WINDOW_MIN, DENSE_THRESHOLD, with_series=False, enforce_public=True, public_extra=DOC_NETS)
    assert_no_identifiers(json.dumps(rep2, ensure_ascii=False), db)
    assert rep2["window"]["since_on_start"] is False and rep2["window"]["warm_up_from_utc"] == iso_minute(T0 + 5), rep2["window"]
    kinds2 = rep2["listing_freshness"]["上榜事件按种类"]
    assert kinds2 == {"implicit_initial": 15, "restart_base": 1, "relist": 3}, kinds2
    d2 = rep2["delisting"]["candidate_level"]
    assert d2["including_flaps_and_agg_held"]["下榜事件"] == 7 and d2["all"]["下榜事件"] == 4 and d2["agg_held_only"]["下榜事件"] == 1, d2["all"]
    lv2 = rep2["checks"]["visit_listed_vs_replay"]
    assert lv2["agree"]["num"] == lv2["agree"]["den"] and lv2["visits_checked"] > 0, lv2
    # --since 落在 start 上：不预热，重启后的 base 快照记为 initial
    rep3 = build(db, RESTART, None, FRESH_WINDOW_MIN, DENSE_THRESHOLD, with_series=False, enforce_public=True, public_extra=DOC_NETS)
    assert rep3["window"]["since_on_start"] is True and rep3["window"]["warm_up_from_utc"] is None
    assert "implicit_initial" not in rep3["listing_freshness"]["上榜事件按种类"], rep3["listing_freshness"]["上榜事件按种类"]
    db.con.close()
    if keep:
        os.replace(path, keep)
        print("合成库保留在", keep)
    else:
        os.unlink(path)
    print("selftest ok：可探测的新上榜 %d（10 分钟内 %d，可用 %d），候选层面下榜 %d（不含 flap %d、agg_held %d；24 小时内仍可用 %d/%d），来源层面下榜 %d" % (
        nl["total"], nl["all"]["上榜新鲜度"]["den"], nl["all"]["上榜新鲜度"]["num"], d["下榜事件"],
        inc["其中换榜/抖动（flap）"]["total"], inc["其中聚合器仍可能列着（agg_held）"],
        d["下榜后 24 小时内仍可用"]["num"], d["下榜后 24 小时内仍可用"]["den"], sl["all"]["下榜事件"]))


# ---------------------------------------------------------------- 入口

def main():
    ap = argparse.ArgumentParser(description="列表时效：上榜新鲜度、下榜滞后、快照增减序列（PROTOCOL“指标定义”）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 freshness.json")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--since", help="观察窗口起点（RFC 3339；默认按 PROTOCOL 规则从 start 记录推）")
    ap.add_argument("--until", help="观察窗口终点（RFC 3339；默认最后一条 visit/snap/stop）")
    ap.add_argument("--fresh-window-min", type=float, default=FRESH_WINDOW_MIN,
                    help="“上榜后 N 分钟内完成第一次探访”的 N（默认 %d，PROTOCOL）" % FRESH_WINDOW_MIN)
    ap.add_argument("--dense-threshold", type=int, default=DENSE_THRESHOLD,
                    help="“候选密集的 /24”的阈值（默认 %d，PROTOCOL 1.2）" % DENSE_THRESHOLD)
    ap.add_argument("--flap-min", type=float, default=FLAP_MIN,
                    help="下榜后 N 分钟内又上榜算换榜/抖动，不算下榜（默认 %d，一轮快照）" % FLAP_MIN)
    ap.add_argument("--no-series", action="store_true", help="不输出每个文件逐次快照的序列（缩小 JSON）")
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
    db = DB(args.db)
    t0 = time.time()
    rep = build(db, since, until, args.fresh_window_min, args.dense_threshold, with_series=not args.no_series, flap_min=args.flap_min)
    rep["seconds"] = round(time.time() - t0, 1)
    text = json.dumps(rep, ensure_ascii=False, indent=1)
    assert_no_identifiers(text, db)
    md = markdown(rep)
    assert_no_identifiers(md, db)
    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, OUTPUT_NAME)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    if args.markdown:
        sys.stdout.write(md)
    nl = rep["listing_freshness"]["新上榜"]
    d = rep["delisting"]["candidate_level"]["all"]
    sys.stderr.write("写出 %s（%d 字节）：新上榜 %d（10 分钟内 %d，其中可用 %d），候选层面下榜 %d（24 小时内仍可用 %d/%d），用时 %.1f 秒\n" % (
        out_path, len(text.encode("utf-8")), nl["total"], nl["all"]["上榜新鲜度"]["den"], nl["all"]["上榜新鲜度"]["num"],
        d["下榜事件"], d["下榜后 24 小时内仍可用"]["num"], d["下榜后 24 小时内仍可用"]["den"], rep["seconds"]))


if __name__ == "__main__":
    main()
