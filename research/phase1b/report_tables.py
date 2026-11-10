#!/usr/bin/env python3
"""第一阶段 1B 实测：把九个指标模块和事后分析（m_posthoc，决策 D14）的 out/*.json 整理成报告里用到的 Markdown 表格和关键数字，避免手抄出错。

用法：
  python3 report_tables.py                         # 读本目录 out/*.json，打印到标准输出
  python3 report_tables.py --db 库.sqlite --write out/report.md --strict
  python3 report_tables.py --selftest              # 核对范围判断、输出检查和 PROTOCOL 常量

参数：
  --out-dir  模块输出目录（默认本目录 out/）
  --db       ingest.py 建的库（只读）。给了就从 self_names / self_ips / node 读出 judge 的名字和地址、节点标识与主机名，
             确认报告里一个都没有（不写进源码的保险）；再数出候选超过 100 个的 /24（候选 = 状态文件 ∪ 尝试记录），
             报告里出现的每个 a.b.c.0/24 都必须在其中（只有候选密集的 /24 才许点名）
  --write    同时写到这个文件（先写临时文件，检查通过才换上）
  --strict   缺 JSON 文件、缺键、PROTOCOL 常量对不上时以非零退出、不写文件（run_all.sh 用它）
  --no-appendix  不附各模块自己的详细表格

报告的结构：
  一、数据与观察窗口（各模块的正式起点是否一致、是否跑满 72 小时、候选密集的 /24）
  二、仪器核对（m_instrument 的 verdict）
  三、PROTOCOL“与文献对账”的预期范围 vs 实测（范围值抄在 EXPECTED_RANGES 里，并与 PROTOCOL.md 原文核对）
  四、与文献逐项对照（文献数字抄在 PAPER_ROWS 里，同样与 PROTOCOL.md 核对）
  五、按 PROTOCOL“要回答的问题”整理的关键数字
  六、与 fieldtest 自带汇总（summary.json）的交叉核对
  七、事后分析（m_posthoc，决策 D14：看过数据以后加的，与原定口径分开）
  八、各模块的提醒、本脚本的读取问题
  附录：九个模块自己的详细表格（调用模块里的 print_markdown / markdown，喂给它们的是 out/*.json，与模块 --markdown 的输出相同）

每张表前一行写口径；每个比例写成“分子/分母（百分比）”，百分比取模块 JSON 里的 pct（一位小数），
“在范围内”按未取整的 分子/分母 判断。所有数字都来自 out/*.json，本脚本不读原始记录、不连库算数（--db 只用于输出检查）。
"""
import argparse
import contextlib
import importlib
import io
import json
import os
import re
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "out")
PROTOCOL_PATH = os.path.join(HERE, "..", "fieldtest", "PROTOCOL.md")
PROTOCOL_VERSION = "1.2"

# 九个模块：键（= out/<键>.json，m_<键>.py）、中文名、模块里的 Markdown 渲染函数、对应的 PROTOCOL 小节
MODULES = [
    ("instrument", "仪器核对", "print_markdown", "“对照与自检”“频率与限速”“正式测量的起止”“记录”"),
    ("availability", "可用率", "print_markdown", "“指标定义”：连得上、有协议回应、可用、时点可用率、累计可用率；“测量对象”（聚合器抽样）"),
    ("lifetime", "寿命", "markdown", "“指标定义”：寿命（Kaplan–Meier）；“对照与自检”（回环失败时段不算死亡）"),
    ("freshness", "列表时效", "markdown", "“指标定义”：上榜新鲜度、下榜滞后"),
    ("labels", "标签准确率", "print_markdown", "“指标定义”：标签准确率；“一次探访”（完整识别、端口策略、端口是否说 TLS）"),
    ("integrity", "内容与请求完整性、匿名、重放、出口", "print_markdown", "“指标定义”：内容被改、请求被改、匿名程度、重放、出口地址"),
    ("mitm", "中间人细分", "print_markdown", "“指标定义”：中间人；1.2 版“‘中间人’的细分”"),
    ("nodes", "免费节点", "print_markdown", "“指标定义”：节点可用（严格 / 照链接）；“频率与限速”（节点轮次）"),
    ("literature", "与文献对账", "print_markdown", "“与文献对账”"),
    ("posthoc", "事后分析（D14）", "print_markdown", "无：看过数据以后加的（决策 D14），不是 PROTOCOL 原定口径"),
]
POSTHOC = "posthoc"
MODULE_NAME = {k: n for k, n, _, _ in MODULES}

# ---------------------------------------------------------------- 从 PROTOCOL 抄来的常量
# 来源：research/fieldtest/PROTOCOL.md 第 1.2 版（2026-11-06）“与文献对账”一节的第二张表（预期范围）。
# check_protocol_constants() 会读 PROTOCOL.md 核对这里的每一行；PROTOCOL 改了而这里没跟着改，--strict 下报错。
EXPECTED_RANGES = [
    {"key": "point", "指标": "常规列表的时点可用率", "lo": 5.0, "hi": 40.0,
     "依据": "文献是 8% 到 35%；本次的列表多数由维护者自动筛过，应偏高"},
    {"key": "mitm", "指标": "证书被替换的代理占可用隧道代理", "lo": 0.0, "hi": 5.0,
     "依据": "Mani 等 1.06%"},
    {"key": "body", "指标": "明文正文不符的代理占能转发的代理", "lo": 5.0, "hi": 40.0,
     "依据": "Mani 等按请求 10.5%，Tsirantonakis 等按代理 38%（含无害改动）"},
    {"key": "partial", "指标": "其中属于局部改动的", "lo": 0.5, "hi": 10.0,
     "依据": "Mani 等恶意 2.2%，Tsirantonakis 等 5.15%"},
    {"key": "leak", "指标": "请求头带出客户端地址的代理占能转发的代理", "lo": 30.0, "hi": 80.0,
     "依据": "Mani 等 66%"},
]

# 来源：同一节的第一张表（文献数字）。“原文”一列逐字抄自 PROTOCOL.md，check_protocol_constants() 核对它出现在 PROTOCOL 里；
# num/den 是能从原文算出比例的那几行（按 PROTOCOL 给的计数算，不是论文里另找的数）。
PAPER_ROWS = [
    {"key": "mani_responsive", "研究": "Mani 等，ACSAC 2018", "口径": "每天有回应的占每天列出的",
     "原文": "中位数 3,283 / 41,520，约 8%", "num": 3283, "den": 41520},
    {"key": "mani_html", "研究": "Mani 等，ACSAC 2018", "口径": "明文 HTML 内容不符（按请求）",
     "原文": "10.5% 的请求", "pct": 10.5},
    {"key": "mani_html_benign", "研究": "Mani 等，ACSAC 2018", "口径": "不符的请求里无害的",
     "原文": "其中约 80% 无害，多为错误页", "pct": 80.0},
    {"key": "mani_html_malicious", "研究": "Mani 等，ACSAC 2018", "口径": "恶意的占全部 HTML 请求",
     "原文": "恶意的占全部 HTML 请求的 2.2%", "pct": 2.2},
    {"key": "mani_cert", "研究": "Mani 等，ACSAC 2018", "口径": "证书被替换（支持 HTTPS 的代理里）",
     "原文": "支持 HTTPS 的代理里 1.06%（102 / 9,625）", "num": 102, "den": 9625},
    {"key": "mani_leak", "研究": "Mani 等，ACSAC 2018", "口径": "请求头带出客户端地址",
     "原文": "66.08%（9,079 / 13,740）", "num": 9079, "den": 13740},
    {"key": "mani_sslstrip", "研究": "Mani 等，ACSAC 2018", "口径": "把 https 链接改成 http",
     "原文": "没有发现"},
    {"key": "tsir_tcp", "研究": "Tsirantonakis 等，NDSS 2018", "口径": "TCP 连得上过（占全部 HTTP 代理条目）",
     "原文": "49,444 个", "num": 49444, "den": 65871},
    {"key": "tsir_fetch", "研究": "Tsirantonakis 等，NDSS 2018", "口径": "取回过测试页（占全部 HTTP 代理条目）",
     "原文": "19,473 个", "num": 19473, "den": 65871},
    {"key": "tsir_mod", "研究": "Tsirantonakis 等，NDSS 2018", "口径": "改动了内容（占取回过测试页的）",
     "原文": "7,441 个，占取回过测试页的 38%", "num": 7441, "den": 19473},
    {"key": "tsir_mal", "研究": "Tsirantonakis 等，NDSS 2018", "口径": "恶意或不受欢迎（占取回过测试页的）",
     "原文": "恶意或不受欢迎的 1,004 个，占 5.15%", "num": 1004, "den": 19473},
    {"key": "mehanna_active", "研究": "Mehanna 等，MADWeb 2024", "口径": "至少活跃过一次",
     "原文": "34.5%", "pct": 34.5},
]
# PAPER_ROWS 里 den 取的总数也要出现在 PROTOCOL 原文里
PAPER_TOTALS = ["107,034", "65,871", "640,600"]

# 与论文原文的核对（2026-11-10 逐字读过原文；PROTOCOL 是测量开始前写的，72 小时实测开始后不改，抄录的偏差记在这里）。
# 出处：Mani 等 arXiv 1806.10258（草稿版）；Tsirantonakis 等 NDSS 2018 论文 PDF（只读到第四节开头，第四、五节未核对）；
# Mehanna 等 MADWeb 2024 论文 PDF（DOI 10.14722/madweb.2024.23035，全文）。
PAPER_CHECKS = {
    "mani_responsive": "**PROTOCOL 抄录有误**：原文没有“约 8% 有回应”。第 5 节说聚合站列出的开放代理 92% 以上离线或不可用；"
                       "每天有回应的中位数 3,283、每天列出的中位数 41,520 都是原文，但 3,283/41,520 是我们把两个中位数相除，不是论文给的比例。"
                       "原文第 5.2 节的“约 8%”说的是“至少有时返回意外内容的代理”，与有回应无关",
    "mani_html": "一致：第 6 节 10.5% of requests for HTML pages produced unexpected HTML content，按请求（2xx 的 HTML 请求）。"
                 "原文另有一天的按代理抽样：169/1,259（13.4%）",
    "mani_html_benign": "原文：意外 HTML 里 16.6% 是恶意的，其余 83.4%；PROTOCOL 的“约 80% 无害”是取整",
    "mani_html_malicious": "一致：恶意的占全部 HTML 请求 2.2%（意外 HTML 的 16.6%）",
    "mani_cert": "一致：第 8 节 1.06%（102/9,625）支持 HTTPS 的代理插入了改过的证书，按代理。注意原文经 CONNECT 和 SOCKS 两种代理测 HTTPS，"
                 "所以本表“我们”一列取全部隧道协议；只算 CONNECT 的数字见第三节",
    "mani_leak": "一致：第 5.3 节 9,079/13,740 连上 web 应用的代理插入了带客户端 IP 的请求头",
    "mani_sslstrip": "一致：第 8 节没有发现把页面里的 https 链接换掉的代理",
    "tsir_tcp": "一致：表 I，Tested 65,871、Alive 49,444（至少一次 TCP 探测成功，每天约 22 次）",
    "tsir_fetch": "一致：表 I，Working 19,473（用 Selenium/Firefox 取回并渲染至少一个测试网站）",
    "tsir_mod": "一致：表 I，7,441（38.21%），分母是 Working 19,473",
    "tsir_mal": "一致：表 I，1,004（5.15%），分母是 Working 19,473（摘要写成 of the tested proxies，以表为准）；"
                "恶意含广告注入或替换、联盟 ID 替换、挖矿脚本、跟踪、SSL 剥离、跳转钓鱼或恶意软件",
    "mehanna_active": "**总数抄录不准**：正文（第 III-A、IV 节）的总数是 640,693，“over 640,600”只出现在摘要、引言和结论；"
                      "221,319 个至少通过一次校验，221,319/640,693 = 34.54%。原文的“通过校验”= 请求到达 honeysite 且 60 秒内有响应，"
                      "不要求内容正确，比我们的“可用”宽，更接近我们的“曾有协议回应”（literature.json 两种都给）。"
                      "原文另有两项可作参照（PROTOCOL 没抄）：平均每轮 5.7% 的活跃代理返回被改的内容（honeysite 只有 2 字节，原文认为多是配置错误）；"
                      "17,924 个代理被观察到的地址与列出的地址不同（最后 233 轮）；"
                      "寿命按第一次到最后一次见到活跃的天数算，30.8% 超过 100 天、9.1% 超过 500 天，曾活跃的代理里 46.4% 第一次测试时就活着。"
                      "原文没有测 TLS 拦截，也没有核对协议标签",
}


# ---------------------------------------------------------------- 读 JSON 与取值

class Ctx:
    """装着全部模块的 JSON，以及读取过程中遇到的问题（缺文件、缺键）。"""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.j = {}
        self.problems = []
        for key, _, _, _ in MODULES:
            path = os.path.join(out_dir, key + ".json")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.j[key] = json.load(f)
            except FileNotFoundError:
                self.problems.append("缺 %s.json（模块没跑，或跑失败了）" % key)
            except ValueError as e:
                self.problems.append("%s.json 解析失败：%s" % (key, e))

    def has(self, mod):
        return mod in self.j

    def get(self, mod, *path, opt=False):
        """按路径取值。路径的每一段是键名；以 * 结尾表示按前缀匹配（必须唯一），整数表示列表下标。
        缺了返回 None；opt=False 时记一条读取问题（--strict 下报告不写出）。"""
        if mod not in self.j:
            return None
        cur = self.j[mod]
        for i, comp in enumerate(path):
            nxt = _step(cur, comp)
            if nxt is _MISSING:
                if not opt:
                    self.problems.append("%s.json 缺 %s" % (mod, " → ".join(str(c) for c in path[:i + 1])))
                return None
            cur = nxt
        return cur


_MISSING = object()


def _step(cur, comp):
    if isinstance(comp, int):
        if isinstance(cur, list) and -len(cur) <= comp < len(cur):
            return cur[comp]
        return _MISSING
    if not isinstance(cur, dict):
        return _MISSING
    if comp.endswith("*"):
        pre = comp[:-1]
        keys = [k for k in cur if k.startswith(pre)]
        return cur[keys[0]] if len(keys) == 1 else _MISSING
    return cur.get(comp, _MISSING)


# ---------------------------------------------------------------- 格式

def n(v):
    """计数与数值。"""
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "是" if v else "否"
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, float):
        return f"{v:,.1f}"
    return str(v)


def is_ratio(d):
    return isinstance(d, dict) and "num" in d and "den" in d


def r(d):
    """比例：分子/分母（百分比）。分母为 0 时百分比写“—”。"""
    if not is_ratio(d):
        return "—"
    num, den = d.get("num"), d.get("den")
    if num is None or den is None:
        return "—"
    pct = d.get("pct")
    if pct is None and den:
        pct = 100.0 * num / den
    return f"{n(num)}/{n(den)}（{'—' if pct is None or not den else f'{pct:.1f}%'}）"


def pct_exact(d):
    if not is_ratio(d) or d.get("num") is None or not d.get("den"):
        return None
    return 100.0 * d["num"] / d["den"]


def in_range(d, lo, hi):
    """按未取整的 分子/分母 判断是否落在 [lo, hi]（含两端）。"""
    if not is_ratio(d):
        return "—"
    p = pct_exact(d)
    if p is None:
        return "无法判断（分母为 0）"
    return "是" if lo <= p <= hi else "否"


def ratio_of(num, den):
    if num is None or den is None:
        return None
    return {"num": num, "den": den, "pct": round(100.0 * num / den, 1) if den else None}


def q(d, keys=("p50", "p90")):
    if not isinstance(d, dict):
        return "—"
    return " / ".join("—" if d.get(k) is None else f"{d[k]:,.1f}" for k in keys)


def cell(v):
    if is_ratio(v):
        return r(v)
    s = n(v)
    return s.replace("|", "\\|").replace("\n", " ")


class Out:
    def __init__(self):
        self.lines = []

    def p(self, s=""):
        self.lines.append(s)

    def table(self, caliber, header, rows):
        """每张表前一行写口径（与表之间空一行，GitHub 才把它当表格）。"""
        self.p("口径：" + caliber)
        self.p()
        self.p("| " + " | ".join(header) + " |")
        self.p("| " + " | ".join("---" for _ in header) + " |")
        if not rows:
            self.p("| " + " | ".join(["（没有）"] + [""] * (len(header) - 1)) + " |")
        for row in rows:
            self.p("| " + " | ".join(cell(c) for c in row) + " |")
        self.p()

    def text(self):
        return "\n".join(self.lines).rstrip() + "\n"


# ---------------------------------------------------------------- 一、数据与观察窗口

def minute(ts):
    """各模块的时间写法不同（分钟或毫秒），统一截到分钟比较。"""
    if not isinstance(ts, str) or len(ts) < 16:
        return ts
    return ts[:16] + "Z"


def window_of(c, mod):
    w = c.get(mod, "window") or {}
    if mod == "lifetime":
        return {"start": w.get("obs_start_utc"), "rule": "第一条 start" if c.get(mod, "parameters", "since", opt=True) is None else "--since",
                "end": w.get("obs_end_utc"), "hours": w.get("hours")}
    if mod == "freshness":
        return {"start": w.get("obs_start_utc"), "rule": w.get("rule"), "end": w.get("obs_end_utc"), "hours": w.get("hours")}
    if mod == "instrument":
        return {"start": w.get("formal_start_utc"), "rule": w.get("formal_start_rule"), "end": w.get("last_record_utc"),
                "hours": w.get("formal_hours")}
    return {"start": w.get("formal_start_utc"), "rule": w.get("formal_start_rule"), "end": w.get("end_utc"), "hours": w.get("hours")}


def section_window(c, o):
    o.p("## 一、数据与观察窗口")
    o.p()
    rows, starts, hours = [], set(), []
    for key, name, _, _ in MODULES:
        if not c.has(key):
            rows.append([name, key + ".json", "缺", "", "", "", ""])
            continue
        w = window_of(c, key)
        starts.add(minute(w["start"]))
        if isinstance(w["hours"], (int, float)):
            hours.append(w["hours"])
        rows.append([name, key + ".json", c.get(key, "generated_utc", opt=True), minute(w["start"]), w["rule"], minute(w["end"]), w["hours"]])
    o.table("正式起点按 PROTOCOL“正式测量的起止”由各模块自己从 start / version 记录推（m_lifetime 默认第一条 start，"
            "m_freshness 用同一规则；run_all.sh 给了 FORMAL_START 时全部用它）；结束是各模块所用记录的最晚时刻，所以会差几分钟；时间截到分钟",
            ["模块", "输出", "生成时间（UTC）", "正式起点（UTC）", "起点规则", "结束（UTC）", "小时"], rows)
    if len(starts) == 1:
        o.p("- 各模块的正式起点一致：%s" % next(iter(starts)))
    else:
        o.p("- **各模块的正式起点不一致**：%s。先用 FORMAL_START 指定同一个起点重跑 run_all.sh，再引用下面的数字" % "、".join(sorted(str(s) for s in starts)))
    if hours:
        hmin = min(hours)
        o.p("- 观察时长 %.2f 到 %.2f 小时；PROTOCOL 要求跑满 72 小时：%s" % (hmin, max(hours), "是" if hmin >= 72 else "**否**"))
    b72 = c.get("integrity", "window", "hours_beyond_72", opt=True)
    if b72:
        o.p("- 起点后超过 72 小时的部分 %s 小时，其间的尝试 %s 条（m_integrity）；各模块都没有裁掉上界（m_mitm 可用 --formal-end 72h 单独裁），"
            "引用数字时写明实际时长" % (n(b72), n(c.get("integrity", "window", "attempts_after_72h", opt=True))))
    w = c.get("instrument", "window") or {}
    if w:
        o.p("- start %s 条、stop %s 条；版本 %s（唯一：%s）；状态被清空的重启 %s 次；中断 %s 次，合计 %s 分钟（其中没有 stop 的崩溃重启 %s 次）" % (
            n(len(w.get("starts") or [])), n(len(w.get("stops") or [])), "、".join(str(v) for v in (w.get("versions") or [])) or "—",
            n(w.get("version_unique")), n(w.get("state_cleared_restarts")), n(len(w.get("interruptions") or [])),
            n(float(w.get("interruption_minutes_total") or 0)), n(w.get("interruptions_without_stop"))))
    tr = [(name, c.get(key, "window", k, opt=True)) for key, name, _, _ in MODULES
          for k in ("trial_run_visits_before_formal_start", "trial_run_attempts_before_formal_start")
          if c.get(key, "window", k, opt=True) is not None]
    if tr:
        o.p("- 正式起点之前的试运行（不并入）：" + "；".join("%s %s" % (name, n(v)) for name, v in tr))
    nn = c.get("instrument", "n") or {}
    if nn:
        o.p("- 入库记录：att %s（其中代理 %s、节点 %s、对照 %s），visit %s，judge 的 req %s（不同 nonce %s），snap %s，nsnap %s，npre %s，nround %s，evidence %s" % (
            n(nn.get("att")), n((nn.get("att_by_kind") or {}).get("proxy")), n((nn.get("att_by_kind") or {}).get("node")),
            n((nn.get("att_by_kind") or {}).get("control")), n(nn.get("visit")), n(nn.get("req")), n(nn.get("req_distinct_nonce")),
            n(nn.get("snap")), n(nn.get("nsnap")), n(nn.get("npre")), n(nn.get("nround")), n(nn.get("evidence"))))
    an = c.get("availability", "n") or {}
    nv = c.get("availability", "never_visited") or {}
    if an:
        o.p("- 候选 %s（常规 %s、聚合器抽样 %s），正式起点后探访过 %s，从没探访过 %s（不进任何比例的分母；其中常规 %s、聚合器抽样 %s，"
            "属于密集 /24 的 %s，只在试运行里探访过的 %s）；下榜超过 24 小时被丢弃、只在探访记录里的 %s" % (
                n(an.get("候选")), n((an.get("分组") or {}).get("regular")), n((an.get("分组") or {}).get("aggregator_sample")),
                n(an.get("探访过")), n(nv.get("total")), n((nv.get("分组") or {}).get("regular")),
                n((nv.get("分组") or {}).get("aggregator_sample")), n(nv.get("其中属于密集 /24")),
                n(nv.get("其中只在试运行期间探访过（cands.visits>0）")), n(an.get("其中有探访记录但不在状态文件里（下榜后被丢弃）"))))
    ck = c.get("availability", "checks", "结束时在榜：list_event 重建 vs cands.listed", opt=True) or {}
    if ck.get("cands.listed=1 且 group=0 却不在重建集合里"):
        o.p("- 结束时状态文件里在榜、group=0（常规）却不在常规列表重建里的候选 %s 个：结束时只有聚合器在列 %s、仍有常规来源 %s、状态文件里没有来源 %s。"
            "group 只降不升（sched.go Upsert 只把 1 改成 0），先上过常规列表、之后只剩聚合器还列着的候选仍记作常规；"
            "时点可用率用常规列表重建的在榜集合，不受影响" % (
                n(ck.get("cands.listed=1 且 group=0 却不在重建集合里")), n(ck.get("其中结束时只有聚合器在列（group 只降不升，sched.go Upsert）")),
                n(ck.get("其中结束时仍有常规来源（应为 0：重建漏了）")), n(ck.get("其中状态文件里没有来源"))))
    o.p()
    dp = c.get("availability", "dense_prefixes") or {}
    rows = [[x.get("prefix24"), x.get("候选"), x.get("探访过"), x.get("从没探访过"), x.get("可用过"), x.get("最近一次探访可用"),
             x.get("结束时在榜"), x.get("其中聚合器抽样")] for x in (dp.get("prefixes") or [])]
    o.table("候选数超过 %s 的 /24（PROTOCOL 1.2“候选密集的地址段”，看过数据以后加的口径）；候选 = 状态文件 ∪ 探访过的；"
            "“可用过”是 att 口径；“去掉密集 /24”的各组结果去掉的就是这些 /24 里的全部候选（m_availability）" % n(dp.get("threshold")),
            ["/24", "候选", "探访过", "从没探访过", "可用过", "最近一次探访可用", "结束时在榜", "其中聚合器抽样"], rows)
    if rows:
        o.p("合计：%s 个 /24，候选 %s，探访过 %s，可用过 %s" % (n(dp.get("count")), n(dp.get("candidates_total")),
                                                       n(dp.get("visited_total")), n(dp.get("ever_ok_total"))))
        o.p()
    same, diff = dense_consistency(c)
    if same:
        o.p("- 各模块“去掉密集 /24”去掉的是同一组 /24，每个 /24 的候选数也相同（%s）：%s 个" % ("、".join(same), n(len(dense_sets(c)["availability"]))))
    for d in diff:
        o.p("- **%s**" % d)
        c.problems.append(d)
    if same or diff:
        o.p()


# 各模块输出里“被去掉的密集 /24”列表的位置（m_integrity 只给逐个列表；m_literature、m_posthoc 直接用 m_integrity 的建表函数）
DENSE_LIST_PATHS = {
    "availability": ("dense_prefixes", "prefixes"),
    "lifetime": ("dense_prefixes_excluded", "prefixes"),
    "freshness": ("dense_prefixes", "prefixes"),
    "labels": ("dense_prefixes", "prefixes"),
    "integrity": ("n", "候选密集的 /24（逐个）"),
    "mitm": ("dense_prefixes", "prefixes"),
}


def dense_sets(c):
    out = {}
    for key, path in DENSE_LIST_PATHS.items():
        if c.has(key):
            lst = c.get(key, *path, opt=True)
            if isinstance(lst, list):
                out[key] = {x.get("prefix24") for x in lst if isinstance(x, dict)}
    return out


# 各模块输出里每个密集 /24 的候选数（判定用的那个数）叫什么
DENSE_COUNT_KEYS = {"availability": "判定用的候选（状态文件 ∪ 尝试记录）", "lifetime": "cands"}


def dense_counts(c):
    out = {}
    for key, path in DENSE_LIST_PATHS.items():
        lst = c.get(key, *path, opt=True) if c.has(key) else None
        if isinstance(lst, list):
            ck = DENSE_COUNT_KEYS.get(key, "候选")
            out[key] = {x.get("prefix24"): x.get(ck) for x in lst if isinstance(x, dict)}
    return out


def dense_consistency(c):
    """各模块去掉的密集 /24 是否与 m_availability 的一组相同，每个 /24 的候选数是否也相同。返回 (相同的模块名列表, 不同的说明列表)。"""
    sets = dense_sets(c)
    counts = dense_counts(c)
    base = sets.get("availability")
    if base is None:
        return [], []
    same, diff = [], []
    for key, st in sets.items():
        if st != base:
            diff.append("%s 去掉的密集 /24 与 m_availability 不同：多 %d 个、少 %d 个（“去掉密集 /24”的数字不可直接并列）"
                        % (key, len(st - base), len(base - st)))
            continue
        bad = sorted(p for p in st if (counts.get(key) or {}).get(p) != (counts.get("availability") or {}).get(p))
        if bad:
            diff.append("%s 与 m_availability 去掉的是同一组 /24，但其中 %d 个 /24 的候选数不同（候选的数法不一致）" % (key, len(bad)))
        else:
            same.append(key)
    return same, diff


# ---------------------------------------------------------------- 二、仪器核对

VERDICT_EXPECT = {  # verdict 键 → (说明, 期望值)；没列出的数值键期望 0、布尔键期望 True
    "any_invariant_violation": ("不变量有任何一次违反（judge 收到、TLS 内请求一致、ClientHello 指纹、节点出口、回显、对照）", False),
    "node_egress_not_self_determinable": ("“节点出口不是本机”能否判定", True),
    "version_unique": ("探测器版本唯一", True),
    "config_unique": ("judge 与探测配置唯一", True),
    "node_egress_not_self_status": ("“节点出口不是本机”的判定依据", None),
    "tls_ok_but_http_failed_content_level": ("TLS 校验通过后内容层失败（不该出现）", 0),
    "tls_ok_but_http_failed_transport_level": ("TLS 校验通过后连接层失败（代理行为，只作参考）", None),
    "segments_without_stop": ("没有 stop 记录的运行段（崩溃或被杀）", 0),
    "interruptions_without_stop": ("没有 stop 的中断", 0),
    "loopback_fail_minutes_total": ("回环对照失败的分钟", 0),
    "loopback_fail_minutes_to_next_ok_total": ("回环对照失败到下一次成功的分钟", 0),
    "unexplained_stat_gaps": ("重启解释不了的 stat 空洞", 0),
    "unexplained_idle_gaps": ("重启解释不了的空闲空洞（≥5 分钟没有连接）", 0),
    "unexplained_missing_hours": ("重启解释不了的缺失小时文件", 0),
    "rate_minutes_over_limit": ("连接速率超过 40 条/秒的分钟", 0),
    "evidence_missing_attempts": ("证据文件找不到的尝试", 0),
    "crosscheck_mismatches": ("与 summary.json 不一致的项（见第六节）", 0),
    "preflight_selftest_mismatches": ("测量机上 fieldtest 仪器自检不符的项（preflight.txt）", 0),
    "preflight_failures": ("测量机上预检失败的项（preflight.txt）", 0),
}


def verdict_explained(c, k, val):
    """verdict 里不为期望值、但模块输出里有解释的几项：返回一句说明（数字都取自 instrument.json）；解释不成立时返回 None。"""
    I = lambda *p: c.get("instrument", *p, opt=True)  # noqa: E731
    if k == "rate_minutes_over_limit":
        peak10, rate = I("rate", "per_sec_peak_10min"), I("rate", "configured_conn_per_sec")
        if peak10 is None or rate is None:
            return None
        cap = rate + rate / 600.0   # 令牌桶：每秒 rate 个，桶容量 rate（cfg ConnPerSec），10 分钟最多 600×rate + rate
        if peak10 <= cap:
            return ("按分钟分桶有 %s 分钟超过 %s 条，但按 10 分钟分桶的峰值 %s 条/秒不超过令牌桶允许的 %.2f 条/秒（%s/秒、桶容量 %s）："
                    "令牌桶允许短时突发，且节点预检的时间戳在排队之前记下，会落到前一个分钟桶" % (
                        n(val), n(I("rate", "minutes_over_limit", "limit_per_minute")), n(peak10), cap, n(rate), n(rate)))
        return None
    if k == "evidence_missing_attempts":
        b, d = I("evidence", "body", "缺失率（按尝试）"), I("evidence", "der", "缺失率（按尝试）")
        orphan = I("evidence", "orphan_files_not_referenced") or {}
        if b is None or d is None:
            return None
        return ("证据文件有存储上限（%s），超限不保存：正文缺 %s，证书链缺 %s；没有被引用的孤儿文件 %s" % (
            I("evidence", "limit_note") or "—", r(b), r(d), "、".join("%s %s" % (x, n(y)) for x, y in orphan.items()) or "—"))
    if k == "crosscheck_mismatches":
        jr = I("crosscheck", "judge_rotation") or {}
        mism = I("crosscheck", "mismatches") or []
        if jr.get("all_judge_mismatches_explained") and all(x.startswith("judge.") or x.startswith("findings.同一请求") for x in mism):
            return ("%s 项不一致全部来自 summary.json 漏读的 judge 文件：它生成于 %s 这一小时，读到一半时 judge 把这一小时的文件整点轮转（压缩改名），"
                    "rec.Each 跳过消失的文件；加上这 %s 个文件里的记录后逐项相等（第六节）" % (
                        n(val), jr.get("summary_generated_hour_utc"), n(jr.get("late_judge_files"))))
        return None
    return None


def section_instrument(c, o):
    o.p("## 二、仪器核对")
    o.p()
    v = c.get("instrument", "verdict")
    if not isinstance(v, dict):
        o.p("（缺 instrument.json 的 verdict）")
        o.p()
        return
    rows, notes = [], []
    for k, val in v.items():
        if k == "note":
            continue
        desc, want = VERDICT_EXPECT.get(k, (k, None if isinstance(val, str) else (True if isinstance(val, bool) else 0)))
        if isinstance(val, dict):
            ok = all(x == 0 for x in val.values() if isinstance(x, (int, float)))
            shown = "，".join("%s %s" % (a, n(b)) for a, b in val.items())
            rows.append([desc, shown, "全为 0", "通过" if ok else "要看"])
            continue
        if want is None:
            rows.append([desc, n(val), "—", "参考"])
        elif val == want:
            rows.append([desc, n(val), n(want), "通过"])
        else:
            why = verdict_explained(c, k, val)
            rows.append([desc, n(val), n(want), "有解释（见表下）" if why else "要看"])
            if why:
                notes.append("%s：%s" % (desc, why))
    o.table("m_instrument 的 verdict（PROTOCOL“对照与自检”：不变量出现一次就说明仪器有错；回环对照失败的时段代理失败不算死亡）；"
            "每项的分子分母在 instrument.json 对应小节，附录 A.1 有明细", ["核对项", "实际", "期望", "结论"], rows)
    tf = c.get("instrument", "invariants", "tls_ok_but_http_failed", opt=True) or {}
    if tf:
        notes.append("TLS 校验通过（钉扎的隧道）后 HTTP 阶段失败 %s 次（分母 %s）：内容层 %s，正文被截断 %s（收到的正文恰是期望正文的前缀，代理提前断开，"
                     "不是内容被改；截断单列是事后加的，决策 D14，按原定义它算内容层），连接层 %s" % (n(tf.get("attempts")), n(tf.get("denominator_tls_ok_to_judge_tls_not_canceled")),
                                         n(tf.get("content_level")), n(tf.get("body_truncated")), n(tf.get("transport_level"))))
    pf = c.get("instrument", "preflight", opt=True) or {}
    pfs, pfe = pf.get("仪器自检") or {}, pf.get("结论") or {}
    if pfs:
        notes.append("测量机上的仪器自检（PROTOCOL“对照与自检”：有任何一项不符，数据不可信）：预检时间 %s，%s，共核对 %s 项、不符 %s 项；"
                     "预检用的 sing-box %s；预检结论失败 %s 项、注意 %s 项（preflight.txt，只取这几样；它不记探测器版本）" % (
                         pf.get("预检时间") or "—", pfs.get("状态") or "—", n(pfs.get("核对")), n(pfs.get("不符")),
                         pf.get("sing-box 版本") or "—", n(pfe.get("失败")), n(pfe.get("注意"))))
    for x in notes:
        o.p("- " + x)
    if notes:
        o.p()
    bl = c.get("instrument", "backlog", opt=True) or {}
    rv = bl.get("revisit_ratio") or {}
    if rv.get("by_hour"):
        def f2(v):
            return "—" if v is None else "%.2f" % v
        rows = []
        for h in rv["by_hour"][:3]:
            rows.append(["%s（%s）" % (h.get("hour"), h.get("hour_utc"))] + [
                "%s / %s（%s）" % (f2((h.get(st) or {}).get("median")), f2((h.get(st) or {}).get("p90")), n((h.get(st) or {}).get("pairs")))
                for st in ("working", "open", "dead")])
        om = rv.get("overall_median") or {}
        rows.append(["全部 %s 个小时" % n(len(rv["by_hour"]))] + ["%s / —（%s）" % (f2((om.get(st) or {}).get("median")), n((om.get(st) or {}).get("pairs")))
                                                         for st in ("working", "open", "dead")])
        o.table("启动积压：同一候选相邻两次探访的实际间隔 ÷ 计划间隔，按前一次探访所在的小时（从正式起点算）和那次探访后的状态分组；跨中断的对子不算（m_instrument backlog）",
                ["小时", "working 中位数 / p90（对子）", "open 中位数 / p90（对子）", "dead 中位数 / p90（对子）"], rows)
    po = rv.get("hours_p90_over_2") or {}
    if po:
        o.p("- 复测间隔比 p90 超过 2（实际间隔超过计划的两倍）的小时（对子数够数的小时里）：" + "；".join(
            "%s %s/%s 个小时（p90 最大 %s，在第 %s 小时）" % (st, n((po.get(st) or {}).get("hours")), n((po.get(st) or {}).get("hours_with_enough_pairs")),
                                                  (po.get(st) or {}).get("max_p90"), (po.get(st) or {}).get("max_p90_hour"))
            for st in ("working", "open", "dead")))
    bd = rv.get("by_dense_24") or {}
    if bd:
        parts = []
        for st in ("working", "open", "dead"):
            x = (bd.get("by_state") or {}).get(st) or {}
            parts.append("%s：密集 /24 %s，其他 /24 %s" % (st, r((x.get("密集 /24") or {}).get("间隔比超过 2 的对子")),
                                                     r((x.get("其他 /24") or {}).get("间隔比超过 2 的对子"))))
        pn = (bd.get("hours_p90_over_2_excluding_dense") or {}).get("dead") or {}
        o.p("- 复测间隔比超过 2 的对子按候选所在 /24 分开（%s 个候选密集的 /24，看过数据以后加的分解，只用来找原因）：%s。"
            "去掉密集 /24 后 dead 一类 p90 超过 2 的小时 %s/%s 个（p90 最大 %s）" % (
                n(bd.get("dense_prefixes")), "；".join(parts), n(pn.get("hours")), n(pn.get("hours_with_enough_pairs")), pn.get("max_p90")))
    pf = bl.get("pool_at_first_stat") or {}
    if pf:
        o.p("- 启动时的候选池：正式起点后第一条 stat（%s，起点后 %s 分钟）pool.total %s、其中还没探访过的 new %s；整个窗口里 pool.total 最大 %s（%s）" % (
            pf.get("utc"), pf.get("minutes_after_formal_start"), n((pf.get("pool") or {}).get("total")), n((pf.get("pool") or {}).get("new")),
            n(pf.get("pool_total_max")), pf.get("pool_total_max_utc")))
    if po or pf:
        o.p()
    nr = bl.get("node_rounds") or {}
    if nr:
        o.p("- 节点轮次 %s 轮：第一轮 %s 分钟，之后中位 %s 分钟，最长 %s 分钟，出错 %s 轮" % (
            n(nr.get("count")), nr.get("first_round_minutes"), nr.get("median_minutes_after_first"), nr.get("max_minutes"),
            n(nr.get("rounds_with_error"))))
        o.p()
    ctrl = c.get("instrument", "controls", "items") or {}
    rows = [[k, x.get("成功率"), x.get("period_s"), x.get("期望次数"), x.get("实际/期望")] for k, x in ctrl.items() if isinstance(x, dict)]
    o.table("对照（不经代理直接访问 judge 和回显服务）；成功率分母 = 该对照项的全部尝试（不含 canceled）；期望次数 = 各运行段 floor(时长/周期)+1 之和",
            ["对照项", "成功率", "周期（秒）", "期望次数", "实际/期望"], rows)


# ---------------------------------------------------------------- 三、预期范围

def range_rows(c):
    """每个预期范围给出若干行（不同模块、不同口径），每行：(我们的口径, 全部的比例, 去掉密集 /24 的比例)。"""
    out = {}
    # 1. 常规列表的时点可用率（m_availability）：观察结束时刻，以及时点序列各点的最小值和最大值
    rows = []
    end_all = c.get("availability", "point_end", "all", "regular", "时点可用率")
    end_ex = c.get("availability", "point_end", "excluding_dense", "regular", "时点可用率")
    rows.append(("观察结束时刻；分母 = 在榜且探访过的常规列表条目（m_availability point_end）", end_all, end_ex))
    series = c.get("availability", "point_series") or []
    for label, pick in (("时点序列里最低的一点", min), ("时点序列里最高的一点", max)):
        cells = []
        for scope in ("all", "excluding_dense"):
            pts = [(pct_exact(p[scope]["regular"]["时点可用率"]), p) for p in series
                   if isinstance(p.get(scope), dict) and pct_exact(p[scope]["regular"].get("时点可用率")) is not None]
            if pts:
                val, p = pick(pts, key=lambda t: t[0])
                cells.append(dict(p[scope]["regular"]["时点可用率"], _at=p.get("t_utc")))
            else:
                cells.append(None)
        at = cells[0].get("_at") if cells[0] else None
        rows.append(("%s（每 %s 小时一点，%s 个点%s）" % (label, n(c.get("availability", "step_hours", opt=True)), n(len(series)),
                                                   "；全部条目这一点在 %s" % minute(at) if at else ""), cells[0], cells[1]))
    out["point"] = rows
    # 2. 证书被替换的代理占可用隧道代理（m_mitm 总数；m_literature 的 CONNECT 口径和“冒充 judge”一层）
    rows = []
    rows.append(("中间人总数（原定义）÷ 隧道曾可用或遇到过中间人的候选；隧道 = socks5/socks4/connect→judge_tls（m_mitm）",
                 c.get("mitm", "total", "ratios", "all", "中间人候选 / 隧道曾可用或遇到过中间人的候选"),
                 c.get("mitm", "total", "ratios", "excluding_dense", "中间人候选 / 隧道曾可用或遇到过中间人的候选")))
    rows.append(("中间人总数 ÷ 隧道建立过（hs_ok=1）的候选（m_mitm，第二分母）",
                 c.get("mitm", "total", "ratios", "all", "中间人候选 / 隧道建立过的候选"),
                 c.get("mitm", "total", "ratios", "excluding_dense", "中间人候选 / 隧道建立过的候选")))
    for scope, label in (("tunnel", "全部隧道协议"), ("connect", "只算 HTTP CONNECT")):
        rows.append(("中间人总数，%s；分母 = 隧道曾可用或遇到过中间人（m_literature）" % label,
                     c.get("literature", "mani_2018", "cert_replaced", "all", "ours", scope, "中间人候选 / 隧道曾可用或遇到过中间人*"),
                     c.get("literature", "mani_2018", "cert_replaced", "excluding_dense", "ours", scope, "中间人候选 / 隧道曾可用或遇到过中间人*")))
        rows.append(("其中“冒充 judge”一层（按候选取最严重一层），%s；同上分母（m_literature，细分来自 m_mitm）" % label,
                     c.get("literature", "mani_2018", "cert_replaced", "all", "ours", scope, "三层细分", "冒充 judge", "候选（最严重一层）/ 隧道曾可用或遇到过中间人*"),
                     c.get("literature", "mani_2018", "cert_replaced", "excluding_dense", "ours", scope, "三层细分", "冒充 judge", "候选（最严重一层）/ 隧道曾可用或遇到过中间人*")))
    out["mitm"] = rows
    # 3–5. 内容被改、局部改动、带出地址（m_integrity 主口径；m_literature 只看 HTML 的 HTTP 转发）
    EA, EF = "全部协议*", "只算 HTTP 转发*"
    pe = lambda k, g: c.get("integrity", "protocol_expectations", k, g, "结果")  # noqa: E731
    den_ex = c.get("integrity", "content", "excluding_dense", "按代理", "能转发的代理（至少一次明文响应 200）")
    leak_ex_num = (c.get("integrity", "request_tamper", "excluding_dense", "plain_seen", "请求头里带出探测器地址", "代理") or {}).get("num")
    lit = lambda scope, k: c.get("literature", "mani_2018", "html_modified", scope, "ours", "forward", "按代理", k)  # noqa: E731
    out["body"] = [
        ("全部协议、全部载荷（HTML/JS/二进制）；分母 = 至少一次明文响应 200 的代理（m_integrity 主口径）",
         pe("明文正文不符的代理占能转发的代理", EA), c.get("integrity", "content", "excluding_dense", "按代理", "正文不符的代理（占能转发的）")),
        ("只算 HTTP 转发、全部载荷（m_integrity，与文献可比的一组；去掉密集 /24 的这一组模块没给）",
         pe("明文正文不符的代理占能转发的代理", EF), None),
        ("只算 HTTP 转发、只看 HTML；分母 = judge 收到过它转发请求的代理（m_literature，Mani 等的对象）",
         lit("all", "正文不符的代理 / 能转发的代理*"), lit("excluding_dense", "正文不符的代理 / 能转发的代理*")),
    ]
    out["partial"] = [
        ("局部改动的代理 ÷ 能转发的代理，全部协议、全部载荷（m_integrity 主口径）",
         pe("其中属于局部改动的", EA),
         c.get("integrity", "content", "excluding_dense", "按代理", "各类（一个代理可属多类）", "正文被局部改动（注入或改写）")),
        ("同上，只算 HTTP 转发（m_integrity；去掉密集 /24 的这一组模块没给）", pe("其中属于局部改动的", EF), None),
        ("只算 HTTP 转发、只看 HTML（m_literature）",
         lit("all", "局部改动的代理 / 能转发的代理*"), lit("excluding_dense", "局部改动的代理 / 能转发的代理*")),
    ]
    out["leak"] = [
        ("judge 收到的明文请求（不限 class）里带出探测器地址的代理 ÷ 能转发的代理，全部协议（m_integrity 主口径；"
         "去掉密集 /24 的一组由 request_tamper 与 content 两节拼出）",
         pe("请求头带出客户端地址的代理占能转发的代理", EA),
         ratio_of(leak_ex_num, den_ex) if leak_ex_num is not None and den_ex is not None else None),
        ("同上，只算 HTTP 转发（m_integrity；去掉密集 /24 的这一组模块没给）", pe("请求头带出客户端地址的代理占能转发的代理", EF), None),
        ("HTTP 转发、judge 收到过它转发请求的代理（m_literature 主口径）",
         c.get("literature", "mani_2018", "client_ip_leak", "all", "ours", "按代理（主口径*", "带出客户端地址的代理"),
         c.get("literature", "mani_2018", "client_ip_leak", "excluding_dense", "ours", "按代理（主口径*", "带出客户端地址的代理")),
    ]
    return out


def section_ranges(c, o):
    o.p("## 三、PROTOCOL“与文献对账”的预期范围 vs 实测")
    o.p()
    o.p("范围值抄自 `research/fieldtest/PROTOCOL.md` 第 %s 版“与文献对账”的第二张表（本脚本的 EXPECTED_RANGES，运行时与 PROTOCOL 原文核对）。"
        "PROTOCOL 的规矩是：落在范围之外时先检查探测器，再谈结论。PROTOCOL 没写死分母的指标，各模块给了几种口径，这里逐行列出，不替读者选。" % PROTOCOL_VERSION)
    o.p()
    rows_by = range_rows(c)
    rows = []
    for er in EXPECTED_RANGES:
        rng = "%s%% 到 %s%%" % (_fmt_bound(er["lo"]), _fmt_bound(er["hi"]))
        for i, (cal, a, ex) in enumerate(rows_by.get(er["key"], [])):
            rows.append([er["指标"] if i == 0 else "〃", rng if i == 0 else "", cal, r(a), in_range(a, er["lo"], er["hi"]),
                         r(ex) if ex is not None else "—（模块没给）", in_range(ex, er["lo"], er["hi"]) if ex is not None else "—",
                         er["依据"] if i == 0 else ""])
    o.table("“全部”= 全部候选；“去掉密集 /24”= 去掉候选超过 100 个的 /24（PROTOCOL 1.2，看过数据以后加的口径）；“在范围内”按未取整的分子/分母判断，含两端；"
            "“证书被替换”与“中间人”细分里哪一层可比，PROTOCOL 写明待定，所以总数和“冒充 judge”一层都列",
            ["指标", "预期范围", "我们的口径（模块）", "全部", "在范围内", "去掉密集 /24", "在范围内", "依据（PROTOCOL）"], rows)
    # 两个模块算同一件事时应当一致
    notes = []
    a = c.get("mitm", "total", "ratios", "all", "中间人候选 / 隧道曾可用或遇到过中间人的候选", opt=True)
    b = c.get("literature", "mani_2018", "cert_replaced", "all", "ours", "tunnel", "中间人候选 / 隧道曾可用或遇到过中间人*", opt=True)
    if is_ratio(a) and is_ratio(b):
        notes.append("中间人总数÷隧道曾可用或遇到过中间人：m_mitm %s，m_literature（全部隧道协议）%s，%s" % (
            r(a), r(b), "一致" if (a["num"], a["den"]) == (b["num"], b["den"]) else "**不一致，先查两个模块**"))
    a = c.get("integrity", "protocol_expectations", "明文正文不符的代理占能转发的代理", "全部协议*", "结果", opt=True)
    b = c.get("integrity", "content", "all", "按代理", "正文不符的代理（占能转发的）", opt=True)
    if is_ratio(a) and is_ratio(b):
        notes.append("正文不符的代理：m_integrity 的 protocol_expectations %s 与 content.all.按代理 %s，%s" % (
            r(a), r(b), "一致" if (a["num"], a["den"]) == (b["num"], b["den"]) else "**不一致**"))
    a = c.get("integrity", "protocol_expectations", "请求头带出客户端地址的代理占能转发的代理", "全部协议*", "结果", opt=True)
    num = (c.get("integrity", "request_tamper", "all", "plain_seen", "请求头里带出探测器地址", "代理", opt=True) or {}).get("num")
    den = c.get("integrity", "content", "all", "按代理", "能转发的代理（至少一次明文响应 200）", opt=True)
    if is_ratio(a) and num is not None and den is not None:
        notes.append("带出地址：protocol_expectations %s；用 request_tamper 与 content 两节拼出的同一比例（“去掉密集 /24”一列就是这样拼的）%s，%s" % (
            r(a), r(ratio_of(num, den)), "一致" if (a["num"], a["den"]) == (num, den) else "**不一致，去掉密集 /24 那一格不可用**"))
    if notes:
        o.p("同一比例在不同模块或不同小节里的核对：")
        o.p()
        for x in notes:
            o.p("- " + x)
        o.p()


def _fmt_bound(v):
    return ("%g" % v)


# ---------------------------------------------------------------- 四、与文献逐项对照

def section_papers(c, o):
    o.p("## 四、与文献逐项对照")
    o.p()
    o.p("文献数字抄自 PROTOCOL“与文献对账”第一张表（本脚本的 PAPER_ROWS）。口径和对象都不同，这些数字只用来判断我们的结果是否离谱（PROTOCOL 原话）。"
        "每一行的差异说明在 literature.json 对应小节的 difference 里。")
    o.p()
    L = lambda *p: c.get("literature", *p)  # noqa: E731
    mani, tsir, meh = "mani_2018", "tsirantonakis_2018", "mehanna_2024"

    def resp(scope):
        m = L(mani, "responsive_daily", scope, "ours", "中位数") or {}
        if not m:
            return "—"
        return "中位数：有回应 %s / 在榜 %s，比例中位数 %s%%（%s 个测量日，%s）" % (
            n(m.get("当天有协议回应")), n(m.get("在榜条目")), n(m.get("有回应 / 在榜（%）")), n(m.get("取中位数的测量日数")),
            "只用完整测量日" if m.get("只用完整测量日") else "含不完整的测量日")

    def sslstrip(scope):
        s = L(mani, "sslstrip", scope, "ours", "forward") or {}
        if not s:
            return "—"
        return ("局部改动里至少一个链接被改的请求 %s（涉及 %s 个代理）；不算剥离的：整页替换里回显 http://<judge>/ 的 %s、局部改动里加前缀的 %s；"
                "有证据可读的 HTML 不符请求 %s，无证据 %s") % (
            n(s.get("至少一个 https 链接被改成 http 的请求")), n(s.get("涉及的代理")), n(_first(s, "整页替换的正文里出现")),
            n(_first(s, "局部改动里多出")), n(s.get("有证据正文可读")), n(_first(s, "无证据")))

    def tsir_v(scope, *p):
        return L(tsir, scope, "ours", "httpish", *p)

    rows_spec = {
        "mani_responsive": ("每测量日（从正式起点起的 24 小时窗口）有协议回应的 ÷ 当天在任一常规列表里的条目（含被排除、不进候选池的）",
                            resp("all"), resp("excluding_dense")),
        "mani_html": ("HTTP 转发、HTML 载荷、状态 200 的请求里正文不符的",
                      L(mani, "html_modified", "all", "ours", "forward", "按请求", "正文不符 / HTML 200"),
                      L(mani, "html_modified", "excluding_dense", "ours", "forward", "按请求", "正文不符 / HTML 200")),
        "mani_html_benign": ("不符的请求里“截断 + 整页替换”（多半无害；我们不做人工判定）",
                             L(mani, "html_modified", "all", "ours", "forward", "按请求", "其中截断 + 整页替换*"),
                             L(mani, "html_modified", "excluding_dense", "ours", "forward", "按请求", "其中截断 + 整页替换*")),
        "mani_html_malicious": ("局部改动的请求 ÷ HTML 200 请求（有害的上界候选）",
                                L(mani, "html_modified", "all", "ours", "forward", "按请求", "局部改动 / HTML 200*"),
                                L(mani, "html_modified", "excluding_dense", "ours", "forward", "按请求", "局部改动 / HTML 200*")),
        "mani_cert": ("全部隧道协议（socks5/socks4/connect）：中间人总数 ÷ 隧道曾可用或遇到过中间人的代理",
                      L(mani, "cert_replaced", "all", "ours", "tunnel", "中间人候选 / 隧道曾可用或遇到过中间人*"),
                      L(mani, "cert_replaced", "excluding_dense", "ours", "tunnel", "中间人候选 / 隧道曾可用或遇到过中间人*")),
        "mani_leak": ("HTTP 转发：带出探测器地址的代理 ÷ judge 收到过它转发请求的代理",
                      L(mani, "client_ip_leak", "all", "ours", "按代理（主口径*", "带出客户端地址的代理"),
                      L(mani, "client_ip_leak", "excluding_dense", "ours", "按代理（主口径*", "带出客户端地址的代理")),
        "mani_sslstrip": ("在存下的局部改动正文里数 https://<judge 主机名>/ 少了几个、http:// 多了几个（证据库有上限、改成别的主机名数不到，会少数；"
                          "同一正文既删了 https 链接又加了 http://<judge>/ 会多数，被改链接数的分布见附录）",
                          sslstrip("all"), sslstrip("excluding_dense")),
        "tsir_tcp": ("标签含 http/https/connect 的常规列表条目，含从没探访过的（文献口径）",
                     tsir_v("all", "TCP 连得上过", "/ 全部条目*"), tsir_v("excluding_dense", "TCP 连得上过", "/ 全部条目*")),
        "tsir_fetch": ("HTTP 转发取回过 HTML 测试页（状态 200，不论正文对不对）÷ 全部条目",
                       tsir_v("all", "取回过测试页*", "/ 全部条目*"), tsir_v("excluding_dense", "取回过测试页*", "/ 全部条目*")),
        "tsir_mod": ("至少一次 HTML 正文不符的代理 ÷ 取回过测试页的",
                     tsir_v("all", "改动了内容", "/ 取回过测试页"), tsir_v("excluding_dense", "改动了内容", "/ 取回过测试页")),
        "tsir_mal": ("其中局部改动（有害的上界候选）÷ 取回过测试页的",
                     tsir_v("all", "其中局部改动*", "/ 取回过测试页"), tsir_v("excluding_dense", "其中局部改动*", "/ 取回过测试页")),
        "mehanna_active": ("曾通过端到端校验的候选 ÷ 全部候选（常规列表 + 聚合器抽样，含从没探访过的，文献口径）",
                           L(meh, "all", "ours", "ranges", "all", "曾通过端到端校验*", "/ 全部候选*"),
                           L(meh, "excluding_dense", "ours", "ranges", "all", "曾通过端到端校验*", "/ 全部候选*")),
    }
    rows = []
    for pr in PAPER_ROWS:
        cal, a, ex = rows_spec.get(pr["key"], ("—", None, None))
        if "num" in pr:
            paper = "%s（%s/%s = %.2f%%）" % (pr["原文"], n(pr["num"]), n(pr["den"]), 100.0 * pr["num"] / pr["den"])
        else:
            paper = pr["原文"]
        rows.append([pr["研究"], pr["口径"], paper, cal, a if is_ratio(a) else (a or "—"), ex if is_ratio(ex) else (ex or "—")])
    o.table("“文献”一列是 PROTOCOL 抄录的数字（括号里的百分比由本脚本从 PROTOCOL 给的计数算出）；“我们”取 literature.json，"
            "主口径都只算正式起点之后；“去掉密集 /24”是 PROTOCOL 1.2 看过数据以后加的口径",
            ["研究", "文献口径", "文献", "我们的口径", "我们（全部）", "我们（去掉密集 /24）"], rows)
    o.table("PROTOCOL 抄录的文献数字与论文原文的逐字核对（2026-11-10）。核对的版本：Mani 等是 arXiv 1806.10258 草稿版（节号按草稿版，"
            "未与 ACSAC 2018 正式版逐字对照）；Tsirantonakis 等是 NDSS 2018 论文 PDF（只读到第四节开头）；Mehanna 等是 MADWeb 2024 论文 PDF 全文。"
            "PROTOCOL 在测量开始前写好、实测开始后不改，偏差记在这里；上表“文献”一列仍是 PROTOCOL 的原样，引用时以本表为准",
            ["研究", "文献口径", "与原文核对"], [[pr["研究"], pr["口径"], PAPER_CHECKS.get(pr["key"], "未核对")] for pr in PAPER_ROWS])
    meh_r = L(meh, "all", "ours", "ranges") or {}
    if meh_r:
        o.p("Mehanna 等对照的分组细节（曾通过端到端校验 ÷ 探访过的 / ÷ 全部候选）：" + "；".join(
            "%s %s / %s" % ({"regular": "常规列表", "aggregator_sample": "聚合器抽样", "all": "合计"}.get(k, k),
                            r(_get(v, "曾通过端到端校验*", "/ 探访过的")), r(_get(v, "曾通过端到端校验*", "/ 全部候选*")))
            for k, v in meh_r.items() if isinstance(v, dict)))
        o.p()
        o.p("Mehanna 等的“通过校验”不要求内容正确，按更宽的“曾有协议回应”比（同样两个分母）：" + "；".join(
            "%s %s / %s" % ({"regular": "常规列表", "aggregator_sample": "聚合器抽样", "all": "合计"}.get(k, k),
                            r(_get(v, "曾有协议回应*", "/ 探访过的")), r(_get(v, "曾有协议回应*", "/ 全部候选*")))
            for k, v in meh_r.items() if isinstance(v, dict)))
        o.p()


def _get(d, *path):
    cur = d
    for comp in path:
        cur = _step(cur, comp)
        if cur is _MISSING:
            return None
    return cur


def _first(d, prefix):
    v = _step(d, prefix + "*")
    return None if v is _MISSING else v


# ---------------------------------------------------------------- 五、关键数字

def section_key_numbers(c, o):
    o.p("## 五、按 PROTOCOL“要回答的问题”整理的关键数字")
    o.p()
    o.p("每个问题一张主表，明细在附录里对应模块的表格。分母里不含从没探访过的条目（PROTOCOL 1.2“候选密集的地址段”）。")
    o.p()
    A = lambda *p, **kw: c.get("availability", *p, **kw)  # noqa: E731

    # 问题 1：能当代理用的有多少，各来源差多少
    o.p("### 1. 公开列表里的条目有多少能当代理用，各来源差多少")
    o.p()
    rows = []
    for g, gname in (("regular", "常规列表"), ("aggregator_sample", "聚合器抽样"), ("total", "合计")):
        for scope, sname in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
            f = A("funnel", scope, g) or {}
            if g == "regular":
                pt = A("point_end", scope, "regular", "时点可用率")
            elif g == "aggregator_sample":
                pt = A("point_end", scope, "aggregator_sample", "all_samples", "时点可用率")
            else:
                pt = None
            rows.append([gname, sname, f.get("seen"), f.get("连得上"), f.get("有协议回应"), f.get("累计可用率"),
                         f.get("最近一次探访可用"), pt if pt is not None else "—", f.get("要求认证")])
    o.table("分母 = 正式起点后探访过的候选（aborted 的探访不算）；连得上 = 至少一次 TCP 通过；有协议回应 = 握手通过或有应答码或有 HTTP 状态码（Mani 等的 responsive）；"
            "累计可用率 = 至少一次 class=ok 到 judge（att 口径）；时点可用率 = 观察结束时刻在榜且探访过的条目里最近一次探访可用（聚合器抽样不逐条记在榜，取全部抽样条目）（m_availability）",
            ["分组", "范围", "探访过", "连得上", "有协议回应", "累计可用率", "最近一次探访可用", "时点可用率（结束时刻）", "要求认证"], rows)
    bs_all = A("by_source", "all") or {}
    bs_ex = A("by_source", "excluding_dense", opt=True) or {}
    rows = []
    for src, x in sorted(bs_all.items(), key=lambda kv: -(pct_exact(kv[1].get("累计可用率（曾经在榜）")) or -1)):
        ex = bs_ex.get(src) or {}
        rows.append([src, x.get("结束时在榜"), x.get("时点可用率（结束时刻）"), x.get("曾经在榜"), x.get("累计可用率（曾经在榜）"),
                     x.get("要求认证"), ex.get("时点可用率（结束时刻）"), ex.get("累计可用率（曾经在榜）")])
    o.table("每个常规列表来源；“曾经在榜”= 正式起点后任何一次 add 事件（含首次快照）里出现过；累计可用率的分母是其中探访过的；"
            "时点可用率取观察结束时刻；一个条目可属多个来源，各行不能相加（m_availability by_source）；按累计可用率从高到低",
            ["来源", "结束时在榜", "时点可用率（结束时刻）", "曾经在榜", "累计可用率（曾经在榜）", "要求认证", "去掉密集 /24：时点", "去掉密集 /24：累计"], rows)

    # 问题 2：寿命
    o.p("### 2. 能用的代理能用多久")
    o.p()
    rows = []
    groups = c.get("lifetime", "groups") or {}
    gname = {"regular": "常规列表", "regular_excluding_dense_prefixes": "常规列表（去掉密集 /24，PROTOCOL 没要求、本模块额外给）",
             "aggregator_sample": "聚合器抽样"}
    for g, x in groups.items():
        km = x.get("first_life_km") or {}
        sa = km.get("survival_at") or {}

        def s_at(h):
            y = sa.get(h) or {}
            if y.get("survival_pct") is None:
                return "—"
            ci = y.get("ci95_pct") or [None, None]
            return "%.1f%%（%s–%s）" % (y["survival_pct"], "—" if ci[0] is None else "%.1f" % ci[0], "—" if ci[1] is None else "%.1f" % ci[1])
        med = km.get("median_h")
        mci = km.get("median_ci95_h") or [None, None]
        med_s = "—（未达到）" if med is None and km.get("n_subjects") else ("—" if med is None else "%.2f（%s–%s）" % (
            med, "—" if mci[0] is None else "%.2f" % mci[0], "—" if mci[1] is None else "%.2f" % mci[1]))
        res = x.get("resurrection") or {}
        rows.append([gname.get(g, g), (x.get("n") or {}).get("candidates_visited"), km.get("n_subjects"), km.get("events"), km.get("censored"),
                     med_s, s_at("1h"), s_at("6h"), s_at("24h"), s_at("48h"),
                     ratio_of(res.get("candidates_revived"), res.get("candidates_with_confirmed_death"))])
    o.table("寿命 = 从第一次可用到其后连续两次探访都不可用的第一次（死亡时刻取那次不可用的探访），观察结束仍可用的右删失（删失时刻取最后一次可用），"
            "Kaplan–Meier 估计、log(-log) 95% 区间；回环对照失败和停机时段里的不可用不算；分辨率 20 分钟；死而复生 = 确认死亡后又可用（m_lifetime）",
            ["分组", "探访过", "曾可用（个体）", "死亡", "删失", "中位寿命（小时，95% 区间）", "1 小时仍存活", "6 小时", "24 小时", "48 小时", "死而复生 / 确认死亡过"], rows)
    lw = c.get("lifetime", "window") or {}
    if lw:
        dt = lw.get("downtime") or {}
        lc = lw.get("loopback_control") or {}
        o.p("- 停机合计 %s 小时（%s 段）；回环对照 %s 次、失败 %s 次；常规列表第一次探访就可用的候选 %s 个（寿命起点可能早于观察起点，"
            "主结果照 PROTOCOL“从第一次可用起”算，没有做左截断修正）；--since 之前就可用过的 %s 个" % (
                n(dt.get("total_h")), n(dt.get("windows") if not isinstance(dt.get("windows"), list) else len(dt["windows"])),
                n(lc.get("attempts")), n(lc.get("failed")),
                n(c.get("lifetime", "groups", "regular", "n", "candidates_ok_at_first_visit", opt=True)),
                n(c.get("lifetime", "groups", "regular", "n", "left_truncated_candidates", opt=True))))
        o.p()

    # 问题 3：列表时效
    o.p("### 3. 列表更新是否及时：上榜时还活着吗，死了多久才下榜，下榜的是不是其实还活着")
    o.p()
    F = lambda *p, **kw: c.get("freshness", *p, **kw)  # noqa: E731
    nl = F("listing_freshness", "新上榜") or {}
    rest = nl.get("其余条目（延迟超过 10 分钟或没探访到）") or {}
    rows = []
    for scope, sname in (("all", "全部"), ("excluding_dense", "去掉密集 /24"), ("dense_only", "只看密集 /24"),
                         ("first_hour_after_start", "起点后 1 小时内上榜（积压期）"), ("after_first_hour", "起点 1 小时后上榜")):
        x = nl.get(scope) or {}
        st = x.get("第一次探访的状态") or {}
        rows.append([sname, x.get("上榜新鲜度"), "%s / %s / %s" % (n(st.get("working")), n(st.get("open")), n(st.get("dead"))),
                     q((x.get("第一次探访延迟（10 分钟内的）") or {}), ("p50", "p90"))])
    o.p("新上榜（窗口内第一次出现、且是 base=0 的 add，不含首次快照与重启快照）%s 条，其中 10 分钟内完成第一次探访 %s。" % (
        n(nl.get("total")), r(nl.get("10 分钟内完成第一次探访"))))
    o.p()
    o.table("上榜新鲜度 = 上榜后 10 分钟内完成第一次探访的新上榜条目里，那次探访可用的比例（PROTOCOL 1.2：只算 10 分钟内完成第一次探访的）（m_freshness）",
            ["范围", "上榜新鲜度", "第一次探访 working / open / dead", "第一次探访延迟 p50 / p90（分钟）"], rows)
    rows = []
    for k, kname in (("dense_prefix", "候选密集的 /24"), ("other_prefix", "其他 /24")):
        x = rest.get(k) or {}
        nv = x.get("窗口内没探访到（可探测的）") or {}
        dist = (x.get("延迟分布（超过 10 分钟的）") or {}).get("quantiles") or {}
        rows.append([kname, x.get("延迟超过 10 分钟"), q(dist, ("p50", "p90", "max")), nv.get("total"), nv.get("候选池里排队没探到")])
    o.table("新上榜但不在上一张表里的条目：第一次探访晚于 10 分钟，或窗口内没探访到（PROTOCOL 1.2 要求单独报告条数和延迟分布）（m_freshness）",
            ["/24 类别", "延迟超过 10 分钟", "延迟 p50 / p90 / 最大（分钟）", "窗口内没探访到", "其中候选池里排队没探到"], rows)
    rows = []
    for scope, sname in (("all", "全部"), ("excluding_dense", "去掉密集 /24"), ("first_delist_only", "每个候选只算第一次下榜")):
        x = F("delisting", "candidate_level", scope) or {}
        lag = (x.get("下榜滞后（已死的：最后一次可用到下榜）") or {}).get("quantiles") or {}
        rows.append([sname, x.get("下榜事件"), x.get("下榜时仍可用（最后一次探访可用）"), x.get("下榜时已死（曾可用、最后一次探访不可用）"),
                     x.get("下榜时从未可用"), q(lag, ("p50", "p90")), x.get("下榜后第一次探访可用"), x.get("下榜后 24 小时内仍可用"),
                     x.get("下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）")])
    o.table("候选层面下榜 = 从所有列表文件消失（默认不含 10 分钟内又回来的换榜抖动和聚合器仍可能列着的）；下榜滞后 = 最后一次可用到下榜，只对“已死”一类；"
            "下榜后 24 小时内仍可用的分母只含观察满 24 小时且期间探访过的下榜事件；它的 24 小时里含又上榜之后的时段，"
            "最后一列只留 24 小时内没再上榜的事件（分析时补的变体，不是 PROTOCOL 事先写下的口径）（m_freshness）",
            ["范围", "下榜事件", "下榜时仍可用", "下榜时已死", "下榜时从未可用", "已死的下榜滞后 p50 / p90（分钟）", "下榜后第一次探访可用",
             "下榜后 24 小时内仍可用", "同上，只算没再上榜的"], rows)

    # 问题 4：标签
    o.p("### 4. 列表给的协议标签准不准")
    o.p()
    rows = []
    acc_all = c.get("labels", "accuracy", "all", "total") or {}
    acc_ex = c.get("labels", "accuracy", "excluding_dense", "total", opt=True) or {}
    for lab, x in acc_all.items():
        ex = acc_ex.get(lab) or {}
        rows.append([lab, x.get("探访过"), _get(x, "曾经通过", "严格", "占探访过"), _get(x, "曾经通过", "宽松", "占探访过"),
                     _get(x, "曾经通过", "严格", "占曾经可用"), _get(x, "最近一次通过", "严格", "占探访过"),
                     _get(ex, "曾经通过", "严格", "占探访过")])
    o.table("标签准确率 = 带该标签、探访过的候选里，标签声称的协议实测通过过的比例；严格 = http→转发、https/connect→CONNECT、socks4/5→自身，"
            "宽松 = 探测器为该标签先试的协议集合；“占曾经可用”把“代理死了”和“标签错了”分开；实测通过按 visit.ok（m_labels）",
            ["标签", "探访过", "曾经通过·严格", "曾经通过·宽松", "曾经通过·严格（占曾经可用）", "最近一次通过·严格", "去掉密集 /24：曾经通过·严格"], rows)

    # 问题 5：篡改、中间人、请求头、带出地址、重放
    o.p("### 5. 多少代理会改明文内容、冒充 TLS、改请求头、带出客户端地址、重放请求")
    o.p()
    I = lambda *p, **kw: c.get("integrity", *p, **kw)  # noqa: E731
    M = lambda *p, **kw: c.get("mitm", *p, **kw)  # noqa: E731
    rows = []

    def both(label, cal, fa, fe):
        rows.append([label, cal, fa, fe])
    both("正文不符的代理", "÷ 能转发的代理（至少一次明文 200），全部协议、全部载荷",
         I("content", "all", "按代理", "正文不符的代理（占能转发的）"), I("content", "excluding_dense", "按代理", "正文不符的代理（占能转发的）"))
    for k in ("正文被截断", "正文被局部改动（注入或改写）", "正文被整页替换"):
        both("　其中" + k.replace("正文被", ""), "同上分母，按最差一类归一（局部改动才算篡改）",
             I("content", "all", "按代理", "按最差一类归一", k), I("content", "excluding_dense", "按代理", "按最差一类归一", k))
    both("正文不符的请求", "÷ 明文响应 200 的请求", I("content", "all", "按请求", "正文不符（全部）"),
         I("content", "excluding_dense", "按请求", "正文不符（全部）"))
    gz = I("content", "all", "gzip") or {}
    gz_same = _first(gz, "解开后正文相同") or {}
    both("擅自加 gzip、解开后相同（不算内容被改，单独计数）", "尝试数 / 代理数", "%s / %s" % (n(gz_same.get("尝试")), n(gz_same.get("代理"))), "—")
    both("中间人（总数，不分层；代理→judge_tls 的主口径）", "÷ 隧道曾可用或遇到过中间人的候选（socks5/socks4/connect→judge_tls）",
         M("total", "ratios", "all", "中间人候选 / 隧道曾可用或遇到过中间人的候选"), M("total", "ratios", "excluding_dense", "中间人候选 / 隧道曾可用或遇到过中间人的候选"))
    for layer in ("冒充 judge", "被送到别的网站", "去向不明", "证据未存（无法判链）"):
        both("　" + layer, "÷ 中间人候选，按候选取最严重一层（PROTOCOL 1.2 细分，看过数据以后加的）",
             M("layers", "all", "layers", layer, "候选（最严重一层）"), M("layers", "excluding_dense", "layers", layer, "候选（最严重一层）"))
    both("　遇到过“去向不明”的（不互斥）", "÷ 中间人候选；一个候选可以几层都遇到过（“按最严重一层”是 m_mitm 的排序，PROTOCOL 没规定）",
         M("layers", "all", "layers", "去向不明", "候选（不互斥）"), M("layers", "excluding_dense", "layers", "去向不明", "候选（不互斥）"))
    both("tls_pin_mismatch（证书链有效、公钥不是 judge 的）", "÷ 隧道建立过的候选",
         M("total", "ratios", "all", "tls_pin_mismatch 候选 / 隧道建立过的候选"), M("total", "ratios", "excluding_dense", "tls_pin_mismatch 候选 / 隧道建立过的候选"))
    both("请求被改（任一项）的代理", "÷ judge 收到过明文请求的代理（不限 class）",
         I("request_tamper", "all", "plain_seen", "请求被改（任一项）", "代理"), I("request_tamper", "excluding_dense", "plain_seen", "请求被改（任一项）", "代理"))
    both("请求头带出探测器地址的代理", "同上分母",
         I("request_tamper", "all", "plain_seen", "请求头里带出探测器地址", "代理"), I("request_tamper", "excluding_dense", "plain_seen", "请求头里带出探测器地址", "代理"))
    for lv in ("透明（带出探测器地址）", "匿名（只暴露代理身份）", "高匿"):
        both("匿名程度：" + lv.split("（")[0], "HTTP 转发、class=ok、judge 收到，按代理取最差一级（summary.go Anon 口径）",
             I("anonymity", "all", "forward_ok", "按代理（取最差）", lv), I("anonymity", "excluding_dense", "forward_ok", "按代理（取最差）", lv))
    both("有请求被重放的代理", "÷ class=ok 且 judge 收到过请求的代理；重放 = 同一 nonce 被 judge 收到不止一次",
         I("replay", "all", "归到代理（class=ok 且 judge 收到）", "有请求被重放的代理"),
         I("replay", "excluding_dense", "归到代理（class=ok 且 judge 收到）", "有请求被重放的代理"))
    both("被收到不止一次的 nonce（judge 侧）", "÷ judge 收到的不同 nonce（全部，不裁正式起点）",
         I("replay", "all", "judge 侧（全部 nonce）", "被收到不止一次的 nonce"), I("replay", "excluding_dense", "judge 侧（全部 nonce）", "被收到不止一次的 nonce"))
    o.table("请求头、重放以 judge 的记录为准（PROTOCOL：出口、请求被改、重放只以 judge 的记录为准）；正文是否被改由探测器比对收到的正文哈希判定，只算明文；分母各行不同，见“分母”一列（m_integrity、m_mitm）",
            ["指标", "分母", "全部", "去掉密集 /24"], rows)

    # 问题 6：出口
    o.p("### 6. 出口地址与入口是否相同，是否稳定，不同目的地看到的是否一致")
    o.p()
    rows = []
    for k in ("全部相同", "全部不同", "有时相同有时不同"):
        rows.append(["与入口：" + k, I("egress", "all", "按代理", k), I("egress", "excluding_dense", "按代理", k)])
    for k in ("1 个出口地址", "2 到 3 个出口地址", "4 个以上出口地址"):
        rows.append(["稳定性：" + k, I("egress", "all", "稳定性（每个代理不同出口地址的个数）", k),
                     I("egress", "excluding_dense", "稳定性（每个代理不同出口地址的个数）", k)])
    ob_all = I("egress", "all", "两个回显服务 vs judge", opt=True) or {}
    ob_ex = I("egress", "excluding_dense", "两个回显服务 vs judge", opt=True) or {}
    for name, x in ob_all.items():
        if isinstance(x, dict):
            rows.append(["回显服务 %s 看到的出口与同一探访里 judge 看到的相同（按尝试）" % name, _first(x, "与同一探访里 judge 看到的出口相同"),
                         _first(ob_ex.get(name) or {}, "与同一探访里 judge 看到的出口相同")])
    rows.append(["两个回显服务看到的出口一致（同一探访都成功时，按探访）", I("egress", "all", "两个回显服务之间*", "一致", opt=True),
                 I("egress", "excluding_dense", "两个回显服务之间*", "一致", opt=True)])
    o.table("出口地址 = judge 日志里的对端地址（回显服务看到的只用来核对）；按代理的分母 = class=ok 且 judge 收到过请求的代理；稳定性 = 观察期内不同出口地址的个数（m_integrity）",
            ["指标", "全部", "去掉密集 /24"], rows)
    # 免费节点的出口（brief 1B 第 4 条的“出口 IP 与入口 IP 不一致的比例”也问节点）
    ne = I("nodes_egress", "judge_tls", opt=True) or {}
    if ne:
        att_ne, dn = ne.get("按尝试") or {}, ne.get("节点")
        byn = ne.get("按节点（一个节点可属多类）") or {}
        dist = ne.get("不同出口个数的分布（按节点）") or {}
        oc = c.get("nodes", "egress", "observers_consistent", "同一探访里 judge 与观察者看到的出口全部相同", opt=True)
        o.p("- 免费节点（judge_tls、class=ok 且 judge 收到；入口 = 该尝试之前最近一次预检解析出的地址；m_integrity nodes_egress）："
            "按尝试与入口相同 %s、不同 %s；按节点（一个节点可属两类）出现过与入口不同的 %s、出现过相同的 %s；"
            "不同出口地址 1 个 %s、2 到 3 个 %s、4 个以上 %s；同一探访里 judge 与观察者看到的出口全部相同 %s"
            "（m_nodes egress，按探访；口径与上表“两个回显服务看到的出口一致”不同，不能直接比）" % (
                r(ratio_of(att_ne.get("与入口相同"), ne.get("尝试"))), r(ratio_of(att_ne.get("与入口不同"), ne.get("尝试"))),
                r(ratio_of(byn.get("与入口不同"), dn)), r(ratio_of(byn.get("与入口相同"), dn)),
                r(ratio_of(dist.get("1 个"), dn)), r(ratio_of(dist.get("2 到 3 个"), dn)), r(ratio_of(dist.get("4 个以上"), dn)), r(oc)))
        o.p()

    # 问题 7：节点
    o.p("### 7. 免费节点有多少可用，严格校验证书会损失多少")
    o.p()
    N = lambda *p, **kw: c.get("nodes", *p, **kw)  # noqa: E731
    na = N("availability", "all") or {}
    rows = []
    for k in ("节点可用（严格）", "只有照链接才可用", "曾经可用（任一分组）"):
        x = na.get(k) or {}
        rows.append([k, x.get("占见过"), x.get("占可探测"), x.get("占探测过")])
    o.table("节点可用（严格）= 不管链接怎么写都完整校验证书、走完全部阶段到 judge_tls 至少一次；只有照链接才可用 = 照链接跳过校验才通过、严格从没通过；"
            "三个分母：见过（去重）、可探测（sing-box 支持）、探测过（PROTOCOL 没写分母，三种都给）（m_nodes）",
            ["指标", "占见过", "占可探测", "占探测过"], rows)
    o.p("- 见过 %s 个节点，可探测 %s，探测过 %s；严格校验损失（只有照链接才可用 ÷ 曾经可用）%s" % (
        n(na.get("见过")), n(na.get("可探测")), n(na.get("探测过")), r(na.get("严格校验损失（只有照链接才可用 / 曾经可用）"))))
    o.p()
    rows = []
    for sch, x in (N("availability", "by_scheme") or {}).items():
        rows.append([sch, x.get("见过"), x.get("可探测"), x.get("探测过"), _get(x, "节点可用（严格）", "占探测过"),
                     _get(x, "只有照链接才可用", "占探测过")])
    o.table("按协议；比例的分母是探测过的节点（m_nodes availability.by_scheme）",
            ["协议", "见过", "可探测", "探测过", "严格可用", "只有照链接才可用"], rows)
    # 决策 D6 的已知代价：vless、vmess、trojan 里 sing-box 够不着的比例（普查时 7.2%，主要是 xhttp 传输和 vless 的 encryption）
    bs = N("nodes", "by_scheme", opt=True) or {}
    ub = N("nodes", "unsupported_by_scheme", opt=True) or {}
    d6 = ("vless", "vmess", "trojan")
    if all(k in bs for k in d6):
        seen = sum(int((bs[k] or {}).get("见过") or 0) for k in d6)
        uns = sum(sum(int(v) for v in (ub.get(k) or {}).values()) for k in d6)
        xh = sum(int((ub.get(k) or {}).get("transport_xhttp") or 0) for k in d6)
        enc = sum(int((ub.get(k) or {}).get("vless_encryption") or 0) for k in d6)
        # 普查时的比例从第一阶段普查的输出读，不手抄（research/census/out/nodes_summary.json 的 transport.out_of_reach_for_singbox）
        census = "普查的输出没找到"
        cpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "census", "out", "nodes_summary.json")
        try:
            with open(cpath, encoding="utf-8") as f:
                ct = json.load(f).get("transport") or {}
            reach = ct.get("out_of_reach_for_singbox") or {}
            census = "普查时 %s（xhttp 等 sing-box 没有的传输 ∪ vless 的 encryption 不是 none，research/census/out/nodes_summary.json 的 transport）" % (
                r(ratio_of(reach.get("nodes"), ct.get("nodes_vless_vmess_trojan"))))
        except (OSError, ValueError):
            pass
        o.p("- 决策 D6 的已知代价（vless、vmess、trojan 里 sing-box 1.14.4 够不着的）：%s，其中 xhttp 传输 %s、vless 的 encryption 不是 none %s，"
            "这两类合计 %s（每个节点只记一个原因）；%s；其余是 REALITY 缺公钥、不认识的传输或 TCP 伪装头（m_nodes nodes.unsupported_by_scheme）" % (
                r(ratio_of(uns, seen)), n(xh), n(enc), r(ratio_of(xh + enc, seen)), census))
        o.p()

    # 问题 8：聚合器
    o.p("### 8. 聚合器独有的条目有多少可用")
    o.p()
    rows = []
    for scope, sname in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        for agg, x in (A("aggregators", scope) or {}).items():
            if agg == "_all_aggregators":
                rows.append([sname, "全部聚合器（去重）", x.get("抽样条目（去重）"), "—", "—", x.get("独有条目"),
                             x.get("独有条目的时点可用率（结束时刻）"), x.get("独有条目的累计可用率")])
            else:
                rows.append([sname, agg, x.get("抽样条目"), x.get("时点可用率（结束时刻）"), x.get("累计可用率"), x.get("独有条目"),
                             x.get("独有条目的时点可用率（结束时刻）"), x.get("独有条目的累计可用率")])
    o.table("每个聚合器只从“不在任何常规列表里”的条目中抽 5,000 条；独有 = 整个观察期从未出现在任何常规列表快照里；时点可用率取观察结束时刻、"
            "分母是抽样条目里探访过的（聚合器不逐条记在榜）；累计可用率的分母同样是探访过的（m_availability）",
            ["范围", "聚合器", "抽样条目", "时点可用率", "累计可用率", "独有条目", "独有：时点", "独有：累计"], rows)


# ---------------------------------------------------------------- 六、交叉核对

def crosscheck_summary(c, key):
    cc = c.get(key, "crosscheck", opt=True)
    if cc is None:
        return None
    if key == "mitm":
        items = cc.get("items") or {}
        flags = [v.get(f) for v in items.values() for f in ("attempts_match", "candidates_match")]
        flags = [f for f in flags if f is not None]
        mism = ["%s（%s）" % (k, f) for k, v in items.items() for f in ("attempts_match", "candidates_match") if v.get(f) is False]
        return sum(1 for f in flags if f), len(flags), mism
    if key == "instrument":
        comps = cc.get("comparisons") or {}
        mm = cc.get("mismatches") or []
        return len(comps) - len(mm), len(comps), mm
    return cc.get("matched"), cc.get("total"), cc.get("mismatches") or []


def section_crosscheck(c, o):
    o.p("## 六、与 fieldtest 自带汇总（summary.json）的交叉核对")
    o.p()
    rows = []
    for key, name, _, _ in MODULES:
        if not c.has(key):
            rows.append([name, "缺 %s.json" % key, "", ""])
            continue
        s = crosscheck_summary(c, key)
        if s is None:
            rows.append([name, "—", "—", "本模块不与 summary.json 对账" if key in ("lifetime", "freshness", POSTHOC) else "没给 --summary，没有核对"])
            continue
        m, t, mism = s
        rows.append([name, "%s/%s" % (n(m), n(t)), "一致" if not mism else "%s 项不一致" % n(len(mism)), "；".join(str(x) for x in mism) or "—"])
    o.table("各模块按 summary.go 的口径（不裁正式起点等）重算 summary.json 里的计数逐项比较（事后分析不对账）",
            ["模块", "一致/比对", "结论", "不一致的项"], rows)
    jr = c.get("instrument", "crosscheck", "judge_rotation", opt=True) or {}
    ex = jr.get("explained") or {}
    if ex:
        comps = c.get("instrument", "crosscheck", "comparisons", opt=True) or {}
        rows = []
        for k, e in ex.items():
            v = comps.get(k) or {}
            rows.append([k, v.get("summary"), v.get("computed"), e.get("late") if "late" in e else "按 summary 读到的记录重数：%s" % n(e.get("summary_visible_recount")),
                         "是" if e.get("explained") else "**否**"])
        o.table("仪器核对模块的不一致项逐项归因：summary.json 生成于 %s 这一小时；这一小时及以后的 judge 文件 %s 个（%s）没被它读到"
                "（这一小时的文件在读的过程中被整点轮转、压缩改名，rec.go eachFile 遇到消失的文件直接跳过；之后的文件是生成后才写的）。"
                "这些文件里生成时刻之前就写入的 req 有 %s 条" % (
                    jr.get("summary_generated_hour_utc"), n(jr.get("late_judge_files")), "、".join(jr.get("late_judge_file_hours") or []),
                    n(jr.get("late_req_before_generated"))),
                ["项", "summary.json", "本模块", "漏读文件里的记录", "summary + 漏读 = 本模块"], rows)


# ---------------------------------------------------------------- 七、事后分析

def render_module(c, key, fn, problems):
    """调用模块自己的 Markdown 渲染函数（输入是 out/<key>.json）；出错记成读取问题、返回 None。"""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    try:
        mod = importlib.import_module("m_" + key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ret = getattr(mod, fn)(c.j[key])
        return buf.getvalue() + (ret if isinstance(ret, str) else "")
    except Exception as e:  # 模块的渲染函数出错不拦整份报告
        problems.append("m_%s.%s 渲染 %s.json 出错：%s: %s" % (key, fn, key, type(e).__name__, e))
        return None


def section_posthoc(c, o, problems):
    o.p("## 七、事后分析（决策 D14，不是 PROTOCOL 原定口径）")
    o.p()
    o.p("这一节的内容都是看过 72 小时数据以后加的（`m_posthoc.py`，决策 D14）：把主要比例从“候选（ip:port）”换成“IP”再算一遍，"
        "并拆开“整页替换”、经 Cloudflare 转发的请求和中间人 IP 的两群。它与原定口径分开报告，不替换原定口径；引用时要写明是事后分析。")
    o.p()
    if not c.has(POSTHOC):
        o.p("（缺 posthoc.json）")
        o.p()
        return
    defs = flatten_defs(c.j[POSTHOC].get("definitions") or {})
    if defs:
        o.p("<details><summary>口径（%d 条）</summary>" % len(defs))
        o.p()
        for k, v in defs:
            o.p("- **%s**：%s" % (k, v.replace("\n", " ")))
        o.p()
        o.p("</details>")
        o.p()
    md = render_module(c, POSTHOC, "print_markdown", problems)
    if md is None:
        o.p("（m_posthoc 的表格没能生成）")
    else:
        o.p(demote(md).rstrip())
    o.p()
    ck = c.get(POSTHOC, "checks", opt=True) or {}
    if ck:
        o.p("内部核对：" + "；".join("%s %s" % (k, "通过" if v in (True, 0) else "**不通过（%s）**" % v) for k, v in ck.items()))
        o.p()


# ---------------------------------------------------------------- 八、提醒

def collect_warnings(obj, path=()):
    """模块 JSON 里所有叫 warnings 的非空字符串列表。"""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "warnings" and isinstance(v, list):
                out += [(path + (k,), x) for x in v if isinstance(x, str)]
            else:
                out += collect_warnings(v, path + (k,))
    return out


def section_warnings(c, o, extra):
    o.p("## 八、各模块的提醒与本脚本的读取问题")
    o.p()
    any_w = False
    for key, name, _, _ in MODULES:
        if not c.has(key):
            continue
        for path, w in collect_warnings(c.j[key]):
            o.p("- %s（%s.json → %s）：%s" % (name, key, " → ".join(path), w))
            any_w = True
    if not any_w:
        o.p("- 各模块的 warnings 都是空的")
    for x in extra:
        o.p("- 本脚本：" + x)
    o.p()


# ---------------------------------------------------------------- 附录

def demote(md):
    """模块输出的标题降一级（### → ####），挂在本报告附录的“### A.n 模块”标题下面。"""
    out = []
    for line in md.splitlines():
        m = re.match(r"^(#{1,4}) ", line)
        out.append(("#" * min(6, len(m.group(1)) + 1) + line[len(m.group(1)):]) if m else line)
    return "\n".join(out)


def flatten_defs(d, prefix=""):
    out = []
    if isinstance(d, dict):
        for k, v in d.items():
            out += flatten_defs(v, prefix + str(k) + " → " if not isinstance(v, str) else prefix + str(k))
    elif isinstance(d, list):
        out.append((prefix.rstrip(" →"), "；".join(str(x) for x in d)))
    elif d is not None:
        out.append((prefix, str(d)))
    return out


def section_appendix(c, o, problems):
    o.p("## 附录：各模块的详细表格")
    o.p()
    o.p("下面是各模块自己的 Markdown 表格（模块里的 print_markdown / markdown 函数，输入是 out/*.json，与 `python3 m_<模块>.py --markdown` 的输出相同）。"
        "每节开头折叠着该模块 definitions 里的口径（每条注明 PROTOCOL 小节），表格的标题写明了分母。")
    o.p()
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    for i, (key, name, fn, sect) in enumerate([m for m in MODULES if m[0] != POSTHOC], 1):
        o.p("### A.%d %s（m_%s.py → out/%s.json）" % (i, name, key, key))
        o.p()
        if not c.has(key):
            o.p("（缺 %s.json）" % key)
            o.p()
            continue
        o.p("口径：PROTOCOL %s；每个指标的一句话定义见下面折叠的列表。" % sect)
        o.p()
        defs = flatten_defs(c.j[key].get("definitions") or {})
        if defs:
            o.p("<details><summary>口径（%d 条）</summary>" % len(defs))
            o.p()
            for k, v in defs:
                o.p("- **%s**：%s" % (k, v.replace("\n", " ")))
            o.p()
            o.p("</details>")
            o.p()
        md = render_module(c, key, fn, problems)
        if md is None:
            o.p("（m_%s 的表格没能生成）" % key)
            o.p()
            continue
        o.p(demote(md).rstrip())
        o.p()


# ---------------------------------------------------------------- PROTOCOL 常量核对

def check_protocol_constants(path=PROTOCOL_PATH):
    """读 PROTOCOL.md，核对 EXPECTED_RANGES 和 PAPER_ROWS 与原文一致。返回问题列表（空 = 一致）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        return ["读不到 PROTOCOL.md（%s），无法核对抄来的常量" % e]
    probs = []
    m = re.search(r"版本\s*([0-9.]+)", text)
    if not m or m.group(1) != PROTOCOL_VERSION:
        probs.append("PROTOCOL.md 的版本是 %s，本脚本抄的是 %s" % (m.group(1) if m else "（没找到）", PROTOCOL_VERSION))
    sec = re.search(r"^## 与文献对账\n(.*?)(?=^## )", text, re.S | re.M)
    if not sec:
        return probs + ["PROTOCOL.md 里找不到“## 与文献对账”一节"]
    body = sec.group(1)
    ranges = {}
    for line in body.splitlines():
        cells = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(cells) == 3:
            mm = re.fullmatch(r"([0-9.]+)% 到 ([0-9.]+)%", cells[1])
            if mm:
                ranges[cells[0]] = (float(mm.group(1)), float(mm.group(2)), cells[2])
    for er in EXPECTED_RANGES:
        got = ranges.get(er["指标"])
        if got is None:
            probs.append("PROTOCOL 的预期范围表里没有“%s”" % er["指标"])
        elif (got[0], got[1]) != (er["lo"], er["hi"]):
            probs.append("“%s”的范围 PROTOCOL 是 %g%% 到 %g%%，本脚本是 %g%% 到 %g%%" % (er["指标"], got[0], got[1], er["lo"], er["hi"]))
        elif got[2] != er["依据"]:
            probs.append("“%s”的依据与 PROTOCOL 原文不同" % er["指标"])
    extra = set(ranges) - {er["指标"] for er in EXPECTED_RANGES}
    if extra:
        probs.append("PROTOCOL 的预期范围表多出了本脚本没抄的行：%s" % "、".join(sorted(extra)))
    for pr in PAPER_ROWS:
        if pr["原文"] not in body:
            probs.append("文献数字“%s”不在 PROTOCOL“与文献对账”原文里" % pr["原文"])
    for t in PAPER_TOTALS:
        if t not in body:
            probs.append("文献总数“%s”不在 PROTOCOL 原文里" % t)
    return probs


# ---------------------------------------------------------------- 输出检查

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d|\.\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
LINK_RE = re.compile(r"\b(ss|ssr|vmess|vless|trojan|hysteria2?|tuic)://", re.I)


def exceptions_from_json(c):
    """允许出现、但长得像 IPv4 的值：根证书包的版本号（形如 20260816ubuntu0.24.04.1，m_mitm / m_literature 输出它是 PROTOCOL 要求写明根库版本）。"""
    out = set()

    def walk(x, k=None):
        if isinstance(x, dict):
            for kk, v in x.items():
                walk(v, kk)
        elif isinstance(x, list):
            for v in x:
                walk(v, k)
        elif isinstance(x, str) and k and "package_version" in str(k):
            out.add(x)
    for d in c.j.values():
        walk(d)
    return sorted(out, key=len, reverse=True)


DENSE_MIN = 100   # PROTOCOL 1.2“候选密集的地址段”：候选超过 100 个的 /24 才许点名


def dense_prefixes_for_guard(con):
    """候选超过 DENSE_MIN 的 /24，候选 = 状态文件（cands）∪ 尝试记录里的代理候选（各模块“去掉密集 /24”用的同一口径，决策 D14）。
    报告里点名的 /24 都必须在这个集合里。"""
    parts = []
    if con.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'cands'").fetchone()[0]:
        parts.append("SELECT key AS cand, prefix24 FROM cands")
    if con.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'att'").fetchone()[0]:
        parts.append("SELECT DISTINCT cand, prefix24 FROM att WHERE cand_kind = 'proxy' AND prefix24 IS NOT NULL")
    if not parts:
        return set()
    sql = "SELECT prefix24 FROM (%s) GROUP BY prefix24 HAVING COUNT(DISTINCT cand) > ?" % " UNION ".join(parts)
    return {r[0] for r in con.execute(sql, (DENSE_MIN,)) if r[0]}


def load_guards(db_path):
    """从库里读 judge 的名字与地址、节点标识与主机名，以及许点名的 /24。只用于检查，不输出。返回 (names, ips, prefixes)；
    没给库时 prefixes 是 None（不检查 /24 是否密集）。"""
    names, ips = set(), set()
    if not db_path:
        return names, ips, None
    con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(db_path), uri=True)
    try:
        for sql, dst in (("SELECT name FROM self_names", names), ("SELECT ip FROM self_ips", ips),
                         ("SELECT DISTINCT id FROM node WHERE id IS NOT NULL", names),
                         ("SELECT DISTINCT host FROM node WHERE host LIKE '%.%' OR host LIKE '%:%'", names)):
            try:
                dst.update(str(r[0]) for r in con.execute(sql) if r[0])
            except sqlite3.Error:
                pass
        prefixes = dense_prefixes_for_guard(con)
    finally:
        con.close()
    return {x for x in names if len(x) >= 4}, {x for x in ips if x}, prefixes


def check_output(text, exceptions, names, ips, prefixes=None):
    """报告里不许有：judge 的主机名或地址、单个代理的 ip:port 或 IPv4（a.b.c.0/24 前缀除外）、节点标识与主机名、邮箱、分享链接。
    给了 prefixes（许点名的 /24 集合）时，出现的 a.b.c.0/24 还必须在其中。返回问题列表（只写类别和行号，不回显命中的值）。"""
    probs = []
    # 只由 ASCII 字母数字、- _ 和点组成的名字按“整词”查集合（与 _contains_token 的判定等价，见 _name_hit），
    # 其余的名字逐个 find。库里有几万个节点标识，逐个 find 在几 MB 的 JSON 上要半个多小时
    simple, other = set(), []
    for x in names:
        lx = x.lower()
        if SIMPLE_NAME_RE.fullmatch(lx):
            simple.add(lx)
        else:
            other.append(lx)
    for no, line in enumerate(text.splitlines(), 1):
        scan = line
        for e in exceptions:
            scan = scan.replace(e, " ")
        for m in IPV4_RE.finditer(scan):
            if not (m.group(4) == "0" and scan[m.end():m.end() + 3] == "/24"):
                probs.append("第 %d 行有 IPv4 地址（只允许 a.b.c.0/24 形式的前缀）" % no)
                break
            if prefixes is not None and (m.group(0) + "/24") not in prefixes:
                probs.append("第 %d 行点名了候选不超过 %d 个的 /24（只许点名候选密集的 /24）" % (no, DENSE_MIN))
                break
        if EMAIL_RE.search(scan):
            probs.append("第 %d 行有邮箱样式的字符串" % no)
        if LINK_RE.search(scan):
            probs.append("第 %d 行有分享链接" % no)
        low = scan.lower()
        if _name_hit(low, simple) or any(_contains_token(low, x) for x in other):
            probs.append("第 %d 行含库里 self_names / 节点的标识或主机名" % no)
        for x in ips:
            if _contains_token(scan, x):
                probs.append("第 %d 行含库里 self_ips 的地址" % no)
                break
    return probs


SIMPLE_NAME_RE = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")
NAME_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")


def _name_hit(low, simple):
    """low 里有没有一个完整的词恰好是 simple 里的名字。词 = 最长的“字母数字 - _，中间可夹单个点”的串，前面不是点。
    这与 _contains_token 对这类名字的判定相同：名字前面是名字字符或点、后面是名字字符或“.名字字符”时都不算。"""
    if not simple:
        return False
    for m in NAME_TOKEN_RE.finditer(low):
        if m.start() > 0 and low[m.start() - 1] == ".":
            continue
        if m.group(0) in simple:
            return True
    return False


def _wordch(ch):
    """ASCII 字母数字和 - _ 算名字的一部分；汉字、标点、空白都算边界（str.isalnum 会把汉字当字母，不能用）。"""
    return ch.isascii() and (ch.isalnum() or ch in "-_")


def _contains_token(hay, needle):
    """needle 作为一个完整的名字或地址出现在 hay 里（前后不是名字的一部分；后面跟“.字母数字”说明是更长的名字）。"""
    i = hay.find(needle)
    while i >= 0:
        j = i + len(needle)
        before = hay[i - 1] if i > 0 else " "
        after = hay[j] if j < len(hay) else " "
        longer = after == "." and j + 1 < len(hay) and _wordch(hay[j + 1])
        if not (_wordch(before) or before == ".") and not _wordch(after) and not longer:
            return True
        i = hay.find(needle, i + 1)
    return False


# ---------------------------------------------------------------- 主程序

def build(out_dir, appendix=True):
    c = Ctx(out_dir)
    o = Out()
    o.p("# 第一阶段 1B 实测：报告用的表格和数字")
    o.p()
    o.p("由 `research/phase1b/report_tables.py` 从 `out/*.json` 生成，不要手改；数据或口径变了就重跑 `run_all.sh`。"
        "口径以 `research/fieldtest/PROTOCOL.md` 第 %s 版为准。比例写成“分子/分母（百分比）”，百分比保留一位小数；“—”表示没有定义（分母为 0 或模块没给）。"
        "“去掉密集 /24”= 去掉候选超过 100 个的 /24 里的全部候选；它和“中间人”的三层细分是 PROTOCOL 1.2 看过数据以后加的两条口径，引用时要标明；"
        "第七节（按 IP 重算等）是 72 小时实测结束后加的事后分析（决策 D14），同样要标明。" % PROTOCOL_VERSION)
    o.p()
    const_probs = check_protocol_constants()
    section_window(c, o)
    section_instrument(c, o)
    section_ranges(c, o)
    section_papers(c, o)
    section_key_numbers(c, o)
    section_crosscheck(c, o)
    # 事后分析与附录都先渲染：渲染出错要记进第八节，而第八节排在它们后面（事后分析）或前面（附录）
    post, app, app_probs = Out(), Out(), []
    section_posthoc(c, post, app_probs)
    o.lines += post.lines
    if appendix:
        section_appendix(c, app, app_probs)
    problems = list(dict.fromkeys(c.problems + app_probs))
    extra = ["PROTOCOL 常量核对：" + x for x in const_probs] + ["读取问题：" + x for x in problems]
    section_warnings(c, o, extra)
    o.lines += app.lines
    return c, o.text(), const_probs, problems


def main():
    ap = argparse.ArgumentParser(description="把 out/*.json 整理成 1B 报告用的 Markdown 表格")
    ap.add_argument("--out-dir", default=DEFAULT_OUT, help="模块输出目录（默认本目录 out/）")
    ap.add_argument("--db", help="ingest.py 建的库（只读），用来确认报告里没有 judge 与节点的标识")
    ap.add_argument("--write", help="同时写到这个文件")
    ap.add_argument("--strict", action="store_true", help="缺文件、缺键、PROTOCOL 常量对不上时以非零退出")
    ap.add_argument("--no-appendix", action="store_true", help="不附各模块自己的详细表格")
    ap.add_argument("--selftest", action="store_true", help="核对范围判断、输出检查和 PROTOCOL 常量")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    c, text, const_probs, problems = build(args.out_dir, appendix=not args.no_appendix)
    names, ips, prefixes = load_guards(args.db)
    if prefixes is not None:
        ds = dense_sets(c).get("availability")
        if ds is not None and ds != prefixes:
            problems.append("m_availability 的密集 /24 与库里按“状态文件 ∪ 尝试记录”数出的不同：多 %d 个、少 %d 个" % (len(ds - prefixes), len(prefixes - ds)))
    exc = exceptions_from_json(c)
    leaks = check_output(text, exc, names, ips, prefixes)
    # out/*.json 也要进仓库：同一套检查对每个 JSON 的原文再做一遍（各模块写出前已按自己的规则查过，这里统一按报告的规则）
    for key, _, _, _ in MODULES:
        path = os.path.join(args.out_dir, key + ".json")
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                leaks += ["%s.json %s" % (key, x) for x in check_output(f.read(), exc, names, ips, prefixes)]
    if leaks:
        sys.stderr.write("报告或模块 JSON 里有不该公开的内容，没有输出：\n" + "\n".join("  " + x for x in leaks[:50]) + "\n")
        return 3
    bad = const_probs + problems
    if bad:
        sys.stderr.write("注意（%d 条）：\n%s\n" % (len(bad), "\n".join("  " + x for x in bad)))
        if args.strict:
            sys.stderr.write("--strict：不写出报告\n")
            return 1
    sys.stdout.write(text)
    if args.write:
        d = os.path.dirname(os.path.abspath(args.write))
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".report-", suffix=".md", dir=d)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        # mkstemp 建的文件是 0600；换成按 umask 的普通权限，和各模块直接写出的 JSON 一致
        um = os.umask(0)
        os.umask(um)
        os.chmod(tmp, 0o666 & ~um)
        os.replace(tmp, args.write)
        sys.stderr.write("已写出 %s（%d 行%s）\n" % (args.write, text.count("\n"),
                                                  "；输出检查用了库里 %d 个名字、%d 个地址、%d 个许点名的 /24" % (len(names), len(ips), len(prefixes or ()))
                                                  if args.db else "；没给 --db，只做了正则检查"))
    return 0


# ---------------------------------------------------------------- 自检

def selftest():
    fails = []

    def expect(name, got, want):
        if got != want:
            fails.append("%s：得到 %r，期望 %r" % (name, got, want))

    # 范围判断按未取整的比例、含两端
    expect("下界含端点", in_range({"num": 1, "den": 20, "pct": 5.0}, 5.0, 40.0), "是")
    expect("刚好低于下界（取整后显示 5.0%）", in_range({"num": 499, "den": 10000, "pct": 5.0}, 5.0, 40.0), "否")
    expect("上界含端点", in_range({"num": 2, "den": 5, "pct": 40.0}, 5.0, 40.0), "是")
    expect("分母为 0", in_range({"num": 0, "den": 0, "pct": None}, 0.0, 5.0), "无法判断（分母为 0）")
    expect("零在 0% 到 5% 里", in_range({"num": 0, "den": 7, "pct": 0.0}, 0.0, 5.0), "是")
    expect("比例格式", r({"num": 1234, "den": 5678, "pct": 21.7}), "1,234/5,678（21.7%）")
    expect("比例格式（分母 0）", r({"num": 0, "den": 0, "pct": None}), "0/0（—）")
    # 路径取值：前缀匹配必须唯一
    d = {"a": {"按代理（主口径：x）": {"v": 1}, "按代理（第二口径）": {"v": 2}, "唯一前缀abc": 3}}
    expect("前缀唯一", _get(d, "a", "唯一前缀*"), 3)
    expect("前缀不唯一", _get(d, "a", "按代理*"), None)
    expect("前缀（主口径）", _get(d, "a", "按代理（主口径*", "v"), 1)
    # 各模块的密集 /24：集合相同、每个 /24 的候选数也要相同
    cx = Ctx.__new__(Ctx)
    cx.out_dir, cx.problems = None, []
    cx.j = {"availability": {"dense_prefixes": {"prefixes": [{"prefix24": "203.0.113.0/24", "候选": 101, "判定用的候选（状态文件 ∪ 尝试记录）": 120}]}},
            "lifetime": {"dense_prefixes_excluded": {"prefixes": [{"prefix24": "203.0.113.0/24", "cands": 120}]}},
            "mitm": {"dense_prefixes": {"prefixes": [{"prefix24": "203.0.113.0/24", "候选": 101}]}}}
    same, diff = dense_consistency(cx)
    expect("密集 /24 一致：按判定用的候选数比", (sorted(same), len(diff)), (["availability", "lifetime"], 1))
    # 输出检查
    expect("/24 前缀可以", check_output("候选密集的 /24：203.0.113.0/24", [], set(), set()), [])
    expect("单个地址不行", len(check_output("x 203.0.113.7:8080 y", [], set(), set())), 1)
    expect("非 .0 的 /24 也不行", len(check_output("198.51.100.5/24", [], set(), set())), 1)
    expect("句末的单个地址也拦（后面跟句号）", len(check_output("代理 203.0.113.7.", [], set(), set())), 1)
    expect("五段的版本号不拦", check_output("版本 1.2.3.4.5", [], set(), set()), [])
    expect("密集的 /24 可以点名", check_output("203.0.113.0/24", [], set(), set(), {"203.0.113.0/24"}), [])
    expect("不密集的 /24 不许点名", len(check_output("198.51.100.0/24", [], set(), set(), {"203.0.113.0/24"})), 1)
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE cands (key TEXT, prefix24 TEXT)")
    con.execute("CREATE TABLE att (cand TEXT, prefix24 TEXT, cand_kind TEXT)")
    con.executemany("INSERT INTO cands VALUES (?, '203.0.113.0/24')", [("203.0.113.1:%d" % i,) for i in range(60)])
    con.executemany("INSERT INTO att VALUES (?, '203.0.113.0/24', 'proxy')", [("203.0.113.1:%d" % i,) for i in range(30, 101)])
    con.executemany("INSERT INTO att VALUES (?, '198.51.100.0/24', 'node')", [("n%d" % i,) for i in range(200)])
    expect("密集 /24 = cands ∪ att 的代理候选（101 个）", dense_prefixes_for_guard(con), {"203.0.113.0/24"})
    con.close()
    expect("包版本例外", check_output("包版本 20260816ubuntu0.24.04.1", ["20260816ubuntu0.24.04.1"], set(), set()), [])
    expect("没有例外时包版本会被拦", len(check_output("包版本 20260816ubuntu0.24.04.1", [], set(), set())), 1)
    expect("库里的名字（不分大小写）", len(check_output("judge 是 Probe.Example.org", [], {"probe.example.org"}, set())), 1)
    expect("名字是更长名字的一部分时不算", check_output("sub-probe.example.organic", [], {"probe.example.org"}, set()), [])
    expect("句末的名字", len(check_output("连到 probe.example.org。", [], {"probe.example.org"}, set())), 1)
    expect("紧挨汉字的名字", len(check_output("连到probe.example.org的", [], {"probe.example.org"}, set())), 1)
    expect("节点标识", len(check_output("节点 0123456789ab 可用", [], {"0123456789ab"}, set())), 1)
    expect("邮箱", len(check_output("联系 someone@example.org", [], set(), set())), 1)
    expect("分享链接", len(check_output("vless://abc", [], set(), set())), 1)
    expect("版本号不是地址", check_output("Go go1.24.7，Python 3.13.18", [], set(), set()), [])
    # 按集合查名字与逐个 find 的判定相同
    nm = ["probe.example.org", "0123456789ab", "a-b_c", "x.y", "q"]
    lines = ["probe.example.org", "sub.probe.example.org", "probe.example.org.", "probe.example.org.x", "(probe.example.org)",
             ".probe.example.org", "..probe.example.org", "probe.example.org-1", "连到probe.example.org的", "0123456789ab,",
             "00123456789ab", "a-b_c.", "a-b_c.-", "x.y.z", "w.x.y", "x.y", "q", "q.", ".q", "q-", "Q", "x..y", "x. y",
             "tag:x.y/1", "x.y:443", "a-b_c..x"]
    for ln in lines:
        low = ln.lower()
        old = any(_contains_token(low, x) for x in nm)
        expect("按集合查名字 %r" % ln, _name_hit(low, set(nm)), old)
    # 标题降级
    expect("标题降一级", demote("### 甲\n#### 乙\n正文"), "#### 甲\n##### 乙\n正文")
    # PROTOCOL 常量与原文一致
    expect("PROTOCOL 常量", check_protocol_constants(), [])
    # 改坏一个常量要能查出来
    saved = EXPECTED_RANGES[0]["hi"]
    EXPECTED_RANGES[0]["hi"] = 41.0
    expect("改坏的常量能查出", len(check_protocol_constants()), 1)
    EXPECTED_RANGES[0]["hi"] = saved
    if fails:
        sys.stderr.write("自检失败 %d 项：\n%s\n" % (len(fails), "\n".join("  " + x for x in fails)))
        return 1
    sys.stderr.write("自检通过\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
