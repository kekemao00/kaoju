#!/usr/bin/env python3
"""检查 expectations/<列>.json 能不能被 matrix.py 的 expectation_diff 机器比对。

检查的内容：
- 应有的 11 个文件都在，没有多余的 .json；
- 每个文件是合法 JSON，variant 与文件名一致，rows 是对象；
- rows 恰好包含 rows.json 的全部行号；
- 每行有 expect、basis（非空字符串）和 confidence（high、medium、low）；
- expect 是“不知道”、通用取值“不支持”“不适用”，或者符合该行 values 的词表：
  固定取值照抄；占位取值按格式（见 PLACEHOLDERS 和 check_value）。

另有两种写法不在行表的词表里，但确实是 matrix.py 会输出的字符串，算合格并逐条列为“提示”：
- “其他：<消息>”，消息必须与 matrix.py 里某个 raise Other("...") 的字面量逐字相同
  （带 % 格式化的消息无法静态核对，不算）；
- “<合格取值>（不含 <用例号>：<不支持|不适用|没有结果|未通过核对>、…）”，
  这是 matrix.py 在多用例的行里有用例被排除时加的后缀（eval_repeat），用例号必须属于这一行，
  而且这一行不是自己处理排除的行（@row(..., handles_excluded=True)）。

用法：
    python3 runner/check_expectations.py            # 检查，有问题退出 1 并逐条列出
    python3 runner/check_expectations.py --stats    # 另外打印每列的统计（Markdown 表）
    python3 runner/check_expectations.py --json     # 把问题和统计以 JSON 打印

只用 Python 标准库；只读文件，不发起任何连接。
"""

import argparse
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VARIANTS = [
    "curl",
    "curl-anyauth",
    "requests",
    "go",
    "node-fetch-env",
    "node-http-env",
    "node-undici",
    "node-agents",
    "node-axios",
    "chromium-pw",
    "firefox-pw",
]

UNKNOWN = "不知道"
GENERIC = ("不支持", "不适用")
CONFIDENCE = ("high", "medium", "low")
LIST_ITEMS = ["状态码", "原因短语", "响应头", "正文"]

# 占位取值 → 说明（报错时用）
PLACEHOLDERS = {
    "（整数）": "十进制整数字符串，如 1",
    "（n/m）": "n/m，如 4/1",
    "（n 次，成功）": "如 2 次，成功",
    "（n 次，失败）": "如 1 次，失败",
    "（列表）": "“状态码、原因短语、响应头、正文”的子序列，用顿号连接",
    "（原样）": "任意非空字符串",
    "（头的列表）": "任意非空字符串",
    "有（用例号）": "如 有（F01、F02）",
    "失败（用例号）": "如 失败（F05）",
    "不完整（用例号）": "如 不完整（C03）",
}

RE_INT = re.compile(r"(0|[1-9][0-9]*)\Z")
RE_NM = re.compile(r"(0|[1-9][0-9]*)/(0|[1-9][0-9]*)\Z")
RE_TIMES = re.compile(r"(0|[1-9][0-9]*) 次，(成功|失败)\Z")
RE_EXCLUDED = re.compile(r"(.+)（不含 ([^（）]+)）\Z")
RE_OTHER_LITERAL = re.compile(r'raise Other\("((?:[^"\\]|\\.)*)"\)')
RE_HANDLES = re.compile(r'@row\("(R[0-9]+)"[^\n]*handles_excluded=True')
OTHER = "其他："
EXCLUDED_LABELS = ("不支持", "不适用", "没有结果", "未通过核对")
RE_CASES = re.compile(r"(有|失败|不完整)（([^（）]+)）\Z")


def is_subsequence(parts, full):
    """parts 是 full 的非空子序列（保持顺序、不重复）。"""
    if not parts:
        return False
    i = 0
    for p in parts:
        while i < len(full) and full[i] != p:
            i += 1
        if i == len(full):
            return False
        i += 1
    return True


def match_placeholder(ph, expect, row_cases, all_cases):
    """expect 是否符合占位取值 ph 的格式。返回 (是否符合, 不符合时的补充说明)。"""
    if ph == "（整数）":
        return bool(RE_INT.match(expect)), ""
    if ph == "（n/m）":
        return bool(RE_NM.match(expect)), ""
    if ph in ("（n 次，成功）", "（n 次，失败）"):
        m = RE_TIMES.match(expect)
        return bool(m and m.group(2) == ph[-3:-1]), ""
    if ph == "（列表）":
        return is_subsequence(expect.split("、"), LIST_ITEMS), ""
    if ph in ("（原样）", "（头的列表）"):
        return bool(expect.strip()), ""
    if ph in ("有（用例号）", "失败（用例号）", "不完整（用例号）"):
        m = RE_CASES.match(expect)
        if not m or m.group(1) != ph[: ph.index("（")]:
            return False, ""
        ids = m.group(2).split("、")
        bad = [c for c in ids if c not in all_cases]
        if bad:
            return False, "括号里不是用例号：%s" % "、".join(bad)
        stray = [c for c in ids if c not in row_cases]
        if stray:
            return False, "用例号不属于这一行的用例：%s" % "、".join(stray)
        if len(set(ids)) != len(ids):
            return False, "用例号重复"
        return True, ""
    return False, "检查器不认识占位取值 %s" % ph


def matrix_facts(matrix_path):
    """从 matrix.py 的源码里读出 Other 的字面消息和自己处理排除的行。读不到返回空集合。"""
    try:
        with open(matrix_path, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        return set(), set()
    literals = set(m for m in RE_OTHER_LITERAL.findall(src) if "%" not in m)
    return literals, set(RE_HANDLES.findall(src))


def check_derived(expect, row_def, all_cases, facts):
    """matrix.py 的两种派生写法。返回 None（不是派生写法或不合格）或一句提示。"""
    literals, handles = facts
    if expect.startswith(OTHER):
        if expect[len(OTHER) :] in literals:
            return "“其他：”开头，消息与 matrix.py 的字面量相同：%s" % expect
        return None
    m = RE_EXCLUDED.match(expect)
    if not m or row_def["id"] in handles or len(row_def.get("cases", [])) < 2:
        return None
    seen = []
    for part in m.group(2).split("、"):
        case, sep, label = part.partition("：")
        if not sep or case not in row_def["cases"] or label not in EXCLUDED_LABELS or case in seen:
            return None
        seen.append(case)
    if seen != [c for c in row_def["cases"] if c in seen] or len(seen) == len(row_def["cases"]):
        return None
    head = m.group(1)
    if head in GENERIC or head == UNKNOWN or check_value(head, row_def, all_cases) is not None:
        return None
    return "带 matrix.py 的“（不含 …）”后缀：%s" % expect


def check_value(expect, row_def, all_cases):
    """返回 None（合格）或一句问题说明。"""
    if expect == UNKNOWN or expect in GENERIC:
        return None
    values = row_def.get("values", [])
    hints = []
    for v in values:
        if v in PLACEHOLDERS:
            ok, hint = match_placeholder(v, expect, row_def.get("cases", []), all_cases)
            if ok:
                return None
            if hint:
                hints.append(hint)
        elif v.startswith("（") and v.endswith("）"):
            hints.append("检查器不认识占位取值 %s" % v)
        elif expect == v:
            return None
    allowed = []
    for v in values:
        allowed.append("%s[%s]" % (v, PLACEHOLDERS[v]) if v in PLACEHOLDERS else v)
    msg = "取值 %r 不在词表里（%s）" % (expect, " | ".join(allowed))
    if hints:
        msg += "；" + "；".join(hints)
    return msg


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def row_key(rid):
    m = re.match(r"R([0-9]+)\Z", rid)
    return (0, int(m.group(1))) if m else (1, rid)


def check_file(path, variant, row_defs, all_cases, facts=(frozenset(), frozenset()), notes=None):
    """返回 (问题列表, 统计)。问题是 (行号或 None, 说明)；提示追加到 notes。"""
    problems = []
    notes = [] if notes is None else notes
    stats = {"rows": 0, "given": 0, "unknown": 0, "high": 0, "medium": 0, "low": 0, "unsupported": 0, "na": 0}
    try:
        doc = load(path)
    except (OSError, ValueError) as e:
        return [(None, "不是合法 JSON：%s" % e)], stats
    if not isinstance(doc, dict):
        return [(None, "顶层不是对象")], stats
    if doc.get("variant") != variant:
        problems.append((None, "variant 是 %r，与文件名 %s 不一致" % (doc.get("variant"), variant)))
    rows = doc.get("rows")
    if not isinstance(rows, dict):
        problems.append((None, "rows 不是对象（matrix.py 只认 {行号: {...}}）"))
        return problems, stats
    missing = sorted((r for r in row_defs if r not in rows), key=row_key)
    extra = sorted((r for r in rows if r not in row_defs), key=row_key)
    if missing:
        problems.append((None, "缺 %d 行：%s" % (len(missing), "、".join(missing))))
    if extra:
        problems.append((None, "多出行表里没有的行：%s" % "、".join(extra)))
    for rid in sorted((r for r in rows if r in row_defs), key=row_key):
        stats["rows"] += 1
        e = rows[rid]
        if not isinstance(e, dict):
            problems.append((rid, "这一行不是对象"))
            continue
        expect, basis, conf = e.get("expect"), e.get("basis"), e.get("confidence")
        if not isinstance(expect, str) or not expect:
            problems.append((rid, "没有 expect（要字符串）"))
        else:
            if expect != expect.strip():
                problems.append((rid, "expect 首尾有空白：%r" % expect))
            else:
                msg = check_value(expect, row_defs[rid], all_cases)
                derived = check_derived(expect, row_defs[rid], all_cases, facts) if msg else None
                if derived:
                    notes.append((rid, derived))
                elif msg:
                    problems.append((rid, msg))
            if expect.strip() == UNKNOWN:
                stats["unknown"] += 1
            else:
                stats["given"] += 1
                if conf in CONFIDENCE:
                    stats[conf] += 1
                if expect.strip() == "不支持":
                    stats["unsupported"] += 1
                elif expect.strip() == "不适用":
                    stats["na"] += 1
        if not isinstance(basis, str) or not basis.strip():
            problems.append((rid, "没有 basis（要非空字符串）"))
        if conf not in CONFIDENCE:
            problems.append((rid, "confidence 是 %r，应为 high、medium、low 之一" % (conf,)))
    return problems, stats


def check_all(exp_dir, rows_path, cases_path, matrix_path=None):
    facts = matrix_facts(matrix_path) if matrix_path else (set(), set())
    row_defs = {r["id"]: r for r in load(rows_path)["rows"]}
    cases = load(cases_path)["cases"]
    all_cases = set(c["id"] for c in cases) if isinstance(cases, list) else set(cases)
    report = {"files": {}, "missing_files": [], "extra_files": [], "row_count": len(row_defs)}
    for v in VARIANTS:
        path = os.path.join(exp_dir, v + ".json")
        if not os.path.isfile(path):
            report["missing_files"].append(v + ".json")
            continue
        notes = []
        problems, stats = check_file(path, v, row_defs, all_cases, facts, notes)
        report["files"][v] = {
            "problems": [{"row": r, "msg": m} for r, m in problems],
            "notes": [{"row": r, "msg": m} for r, m in notes],
            "stats": stats,
        }
    if os.path.isdir(exp_dir):
        for name in sorted(os.listdir(exp_dir)):
            if name.endswith(".json") and name[: -len(".json")] not in VARIANTS:
                report["extra_files"].append(name)
    return report


def stats_table(report):
    lines = [
        "| 列 | 给了预期 | high | medium | low | 不知道 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for v in VARIANTS:
        f = report["files"].get(v)
        if not f:
            lines.append("| `%s` | （缺文件） | | | | |" % v)
            continue
        s = f["stats"]
        lines.append("| `%s` | %d | %d | %d | %d | %d |" % (v, s["given"], s["high"], s["medium"], s["low"], s["unknown"]))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="检查预期文件能否被 matrix.py 机器比对")
    ap.add_argument("--expectations", default=os.path.join(BASE, "expectations"))
    ap.add_argument("--rows", default=os.path.join(BASE, "rows.json"))
    ap.add_argument("--cases", default=os.path.join(BASE, "cases.json"))
    ap.add_argument("--matrix", default=os.path.join(BASE, "runner", "matrix.py"), help="用来核对派生写法的 matrix.py")
    ap.add_argument("--stats", action="store_true", help="打印每列的统计表")
    ap.add_argument("--json", action="store_true", help="以 JSON 打印问题和统计")
    args = ap.parse_args(argv)

    report = check_all(args.expectations, args.rows, args.cases, args.matrix)
    n = len(report["missing_files"]) + len(report["extra_files"])
    n += sum(len(f["problems"]) for f in report["files"].values())

    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=1)
        print()
        return 1 if n else 0

    for name in report["missing_files"]:
        print("%s: 缺文件" % name)
    for name in report["extra_files"]:
        print("%s: 不在应有的 %d 个文件之内（matrix.py 会把它当成一列）" % (name, len(VARIANTS)))
    for v in VARIANTS:
        f = report["files"].get(v)
        if not f:
            continue
        for p in f["problems"]:
            print("%s.json%s: %s" % (v, " " + p["row"] if p["row"] else "", p["msg"]))
        for p in f["notes"]:
            print("%s.json %s: 提示（合格）：%s" % (v, p["row"], p["msg"]))
    if args.stats:
        print(stats_table(report))
    if n:
        print("check_expectations: %d 个问题" % n, file=sys.stderr)
        return 1
    print("check_expectations: %d 个文件、每个 %d 行，都合格" % (len(report["files"]), report["row_count"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
