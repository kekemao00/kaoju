#!/usr/bin/env python3
"""核对 1B 报告正文里的数字都出自脚本输出（CLAUDE.md：数字不手抄）。

用法：
  python3 check_report_numbers.py                      # 默认读 docs/research/phase1b-report.md 和本目录 out/
  python3 check_report_numbers.py --report 报告.md --out-dir out/
  python3 check_report_numbers.py --selftest

做法：把 out/report.md 的全文和 out/*.json 里的全部数值收成一个集合（去掉千分位逗号；JSON 里的小数另按一位、两位小数取整），
报告正文里的每个数（千分位数、百分比、小数、两位以上的整数）都必须在集合里。代码块、行内代码、链接地址、日期、时刻、
版本号、决策编号、文件名里的数不查。查不到的逐个列出（带行号）；文献原文的数字已由 report_tables.py 写进 report.md 第四节，
也在集合里。确实不是数据的数（例如“第 2 阶段”），写进下面的 ALLOWED，并注明为什么。
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPORT = os.path.join(HERE, "..", "..", "docs", "research", "phase1b-report.md")
DEFAULT_OUT = os.path.join(HERE, "out")

# 正文里出现、但不是测量数据的数：数 → 为什么允许
ALLOWED = {
    "10": "PROTOCOL 的常量：10 分钟（快照间隔、上榜新鲜度的时限）、每 10 秒的 judge 余量",
    "20": "PROTOCOL 的常量：寿命的分辨率 20 分钟",
    "24": "PROTOCOL 的常量：下榜后继续探测 24 小时、/24",
    "40": "PROTOCOL 的常量：每秒 40 条连接",
    "72": "PROTOCOL 的常量：72 小时",
    "100": "PROTOCOL 1.2 的常量：候选超过 100 个的 /24",
    "5000": "PROTOCOL 的常量：每个聚合器抽 5,000 条",
}

NUM_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
TOKEN_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+\.\d+|\d+)(%?)(?![\w])")
SKIP_RES = [
    re.compile(r"```.*?```", re.S),                      # 代码块
    re.compile(r"`[^`\n]*`"),                            # 行内代码
    re.compile(r"\]\([^)]*\)"),                          # 链接地址
    re.compile(r"https?://\S+"),
    re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?"),  # 日期、时刻
    re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b"),         # 时刻
    re.compile(r"\b\d+\.\d+\.\d+[\w.+-]*"),              # 版本号
    re.compile(r"\bRFC ?\d+(?:、(?:RFC ?)?\d{4}(?!\d))*"),          # 规范编号（含“RFC 9110、9112、1928”这样用顿号的列举；逗号之后的数照查）
    re.compile(r"\b(?:D|ACSAC |NDSS |MADWeb |arXiv )\d[\d.]*"),  # 决策编号、会议
    re.compile(r"(?<![\d.,])(?:19|20)\d\d ?年"),                  # 年份（只认后面紧跟“年”的；“2017 到 2018 年”写成“2017 年到 2018 年”）
    re.compile(r"\b(?:Python|Go) ?\d+\.\d+(?:\.\d+)?"),          # 语言版本
    re.compile(r"[\w/.-]+\.(?:md|py|go|json|sh|gz|sqlite)\b"),  # 文件名
    re.compile(r"第 ?\d+(?:\.\d+)? ?(?:版|阶段|节|项|部分)"),     # 版本、阶段、节号
    re.compile(r"(?:PROTOCOL|版本) ?\d+\.\d+"),
    re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,64}\b"),  # 提交号、哈希（至少有一个字母；纯数字的长整数照查）
]


def known_numbers(out_dir):
    """out/report.md 全文里的数和 out/*.json 里的全部数值（去逗号的字符串）。"""
    known = set()
    path = os.path.join(out_dir, "report.md")
    if not os.path.isfile(path):
        raise SystemExit("缺 %s：先跑 run_all.sh" % path)
    with open(path, encoding="utf-8") as f:
        for m in NUM_RE.finditer(f.read()):
            known.add(norm(m.group(0)))

    def walk(x):
        if isinstance(x, bool):
            return
        if isinstance(x, (int, float)):
            known.add(norm(repr(x)))
            if isinstance(x, float):
                for nd in (1, 2):
                    known.add(norm("%.*f" % (nd, x)))
        elif isinstance(x, dict):
            for k, v in x.items():
                for m in NUM_RE.finditer(str(k)):
                    known.add(norm(m.group(0)))
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str):
            for m in NUM_RE.finditer(x):
                known.add(norm(m.group(0)))
    for name in sorted(os.listdir(out_dir)):
        if name.endswith(".json"):
            with open(os.path.join(out_dir, name), encoding="utf-8") as f:
                walk(json.load(f))
    return known


def norm(s):
    s = s.replace(",", "").rstrip(".")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def unchecked_text(line):
    for r in SKIP_RES:
        line = r.sub(" ", line)
    return line


def check(report_text, known):
    probs = []
    text = SKIP_RES[0].sub(lambda m: "\n" * m.group(0).count("\n"), report_text)  # 代码块按行数留空，行号不变
    for no, line in enumerate(text.splitlines(), 1):
        scan = unchecked_text(line)
        for m in TOKEN_RE.finditer(scan):
            raw, pct = m.group(1), m.group(2)
            v = norm(raw)
            if not pct and "," not in raw and "." not in raw and len(v) < 2:
                continue   # 一位整数不查（“3 个测量日”“两层”这类）
            if v in known or v in ALLOWED:
                continue
            probs.append("第 %d 行：%s%s" % (no, raw, pct))
    return probs


def selftest():
    known = {"18383", "42607", "43.1", "0.47"}
    text = "\n".join([
        "中间人 18,383/42,607（43.1%），中位寿命 0.47 小时。",
        "手抄错了 43.2%。",
        "`12,345` 在代码里不查；2026-11-10 08:06 不查；PROTOCOL 1.2 不查；D14 不查；第 2 阶段不查。",
        "RFC 9110、9112、1928 不查；2017 年到 2018 年不查；Python 3.11 和 Python 3.13 不查；提交号 1a2b3c4d 不查。",
        "节点 2034 到 2100 个；共 1234567 条；RFC 9110，2345 个代理。",
        "```",
        "99,999",
        "```",
        "72 小时是常量。",
    ])
    got = check(text, known)
    want = ["第 2 行：43.2%", "第 5 行：2034", "第 5 行：2100", "第 5 行：1234567", "第 5 行：2345"]
    if got != want:
        print("自检失败：得到 %r，应为 %r" % (got, want), file=sys.stderr)
        return 1
    print("自检通过", file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="核对 1B 报告正文里的数字都出自脚本输出")
    ap.add_argument("--report", default=DEFAULT_REPORT)
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    known = known_numbers(args.out_dir)
    with open(args.report, encoding="utf-8") as f:
        probs = check(f.read(), known)
    if probs:
        print("报告里有 %d 个数在 out/report.md 和 out/*.json 里找不到：" % len(probs), file=sys.stderr)
        for p in probs:
            print("  " + p, file=sys.stderr)
        return 1
    print("报告里的数都能在脚本输出里找到（集合 %d 个数）" % len(known), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
