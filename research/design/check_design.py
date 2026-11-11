#!/usr/bin/env python3
"""核对设计文档（docs/design/*.md）里的引用。只用标准库。

查四样东西：
1. 第 2 阶段矩阵的格子引用 `R行[列]=值` 和规范条款号：复用 research/phase2/tools/report_tables.py 的规则。
2. 1B 数据引用 `1B[模块 » 键 » 键 …]=值`：到 research/phase1b/out/<模块>.json 里按键逐级取值，必须与写的值相同
   （写的值可以带千分位逗号）。两个值相除写成 `1B÷[甲 ÷ 乙]=百分数%`，脚本自己除一遍，按写出来的小数位数四舍五入后必须相同。
3. 编号：不变量 INV-n、验收标准 AC-n、设计决定 DD-n 各自只能定义一次（定义的写法是行首的 `**INV-n**`、表格首列的 `AC-n`、`DD-n`）；
   文中引用到的编号必须有定义；每个不变量至少被一条验收标准引用。
4. 文档之间的相对链接指向的文件存在。
5. 表格每一行的列数与表头相同。

用法：python3 research/design/check_design.py            # 退出码 0 没有问题，1 有问题
      python3 research/design/check_design.py --selftest
"""
import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "phase2", "tools"))
import report_tables  # noqa: E402

CITE_1B = re.compile(r"`1B\[([^\]`]+)\]=([^`]+)`")
RATIO_1B = re.compile(r"`1B÷\[([^\]`]+?) ÷ ([^\]`]+)\]=([\d.]+)%`")
ID_REF = re.compile(r"(?<![\w-])((?:INV|AC|DD)-\d+)(?![\w-])")
ID_DEF = [
    re.compile(r"^\*\*((?:INV|DD)-\d+)\*\*", re.M),
    re.compile(r"^\| ((?:AC|DD|INV)-\d+) \|", re.M),
]
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
SEP = " » "


def lookup(out_dir, cite, cache):
    parts = [p for p in cite.split(SEP)]
    module, keys = parts[0].strip(), parts[1:]
    if module not in cache:
        path = os.path.join(out_dir, module + ".json")
        if not os.path.isfile(path):
            raise KeyError("没有 %s.json" % module)
        with open(path, encoding="utf-8") as fh:
            cache[module] = json.load(fh)
    cur = cache[module]
    for k in keys:
        if isinstance(cur, list):
            cur = cur[int(k)]
        elif isinstance(cur, dict):
            if k not in cur:
                raise KeyError("没有键 “%s”" % k)
            cur = cur[k]
        else:
            raise KeyError("“%s” 之前已经是叶子" % k)
    if isinstance(cur, (dict, list)):
        raise KeyError("取到的不是一个值")
    return cur


def same(actual, written):
    w = written.strip().replace(",", "")
    if isinstance(actual, bool) or actual is None:
        return str(actual) == w
    if isinstance(actual, (int, float)):
        try:
            return float(w) == float(actual)
        except ValueError:
            return False
    return str(actual) == w


def check_text(name, text, p2data, out_dir, cache):
    problems = []
    generated_stub = ""
    # 第 2 阶段的引用和条款号；设计文档里没有生成的表格，去掉那一条检查
    p2, cites, clauses = report_tables.check_report(text + "\n" + report_tables.BEGIN + "\n" + report_tables.END, p2data, generated_stub)
    problems += ["%s：%s" % (name, p) for p in p2]
    n1b = 0
    for cite, value in CITE_1B.findall(text):
        n1b += 1
        try:
            actual = lookup(out_dir, cite, cache)
        except (KeyError, IndexError, ValueError) as e:
            problems.append("%s：1B[%s]：%s" % (name, cite, e))
            continue
        if not same(actual, value):
            problems.append("%s：1B[%s]：文档写的是 %s，数据里是 %s" % (name, cite, value.strip(), actual))
    for a, b, value in RATIO_1B.findall(text):
        n1b += 1
        try:
            va, vb = lookup(out_dir, a, cache), lookup(out_dir, b, cache)
            digits = len(value.split(".")[1]) if "." in value else 0
            actual = round(100.0 * float(va) / float(vb), digits)
        except (KeyError, IndexError, ValueError, TypeError, ZeroDivisionError) as e:
            problems.append("%s：1B÷[%s ÷ %s]：%s" % (name, a, b, e))
            continue
        if actual != float(value):
            problems.append("%s：1B÷[%s ÷ %s]：文档写的是 %s%%，算出来是 %s%%" % (name, a, b, value, actual))
    return problems, cites, clauses, n1b


def check_ids(texts):
    problems = []
    defined = {}
    for name, text in texts.items():
        for rx in ID_DEF:
            for m in rx.finditer(text):
                i = m.group(1)
                if i in defined:
                    problems.append("%s：%s 重复定义（另一处在 %s）" % (name, i, defined[i]))
                defined[i] = name
    referenced = {}
    for name, text in texts.items():
        for i in ID_REF.findall(text):
            referenced.setdefault(i, set()).add(name)
    for i in sorted(referenced):
        if i not in defined:
            problems.append("%s：引用了没有定义的 %s" % ("、".join(sorted(referenced[i])), i))
    # 每个不变量至少被一条验收标准引用：找验收标准表格的行
    ac_rows = "\n".join(line for text in texts.values() for line in text.splitlines() if re.match(r"^\| AC-\d+ \|", line))
    for i in sorted(defined):
        if i.startswith("INV-") and not re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(i), ac_rows):
            problems.append("%s 没有被任何一条验收标准引用" % i)
    return problems, defined


def check_links(name, path, text):
    problems = []
    for target in LINK.findall(text):
        if re.match(r"^[a-z]+:", target):
            continue
        if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(path), target))):
            problems.append("%s：链接 %s 指向的文件不存在" % (name, target))
    return problems


def check_tables(name, text):
    problems, width = [], None
    for n, line in enumerate(text.split("\n"), 1):
        if line.startswith("|"):
            cols = len(re.findall(r"(?<!\\)\|", line)) - 1
            if width is None:
                width = cols
            elif cols != width:
                problems.append("%s 第 %d 行：表格这一行有 %d 列，表头是 %d 列" % (name, n, cols, width))
        else:
            width = None
    return problems


def run(design_dir, out_dir, phase2_dir):
    p2data = report_tables.load_all(phase2_dir)
    texts, problems, cache = {}, [], {}
    totals = [0, 0, 0]
    for path in sorted(glob.glob(os.path.join(design_dir, "*.md"))):
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        texts[name] = text
        p, cites, clauses, n1b = check_text(name, text, p2data, out_dir, cache)
        problems += p + check_links(name, path, text) + check_tables(name, text)
        totals[0] += cites
        totals[1] += clauses
        totals[2] += n1b
    p, defined = check_ids(texts)
    problems += p
    return problems, totals, defined


def selftest():
    cache = {"m": {"a": {"b": [1, 2.5, "x"]}, "n": 1234}}
    assert lookup("/nonexistent", "m » a » b » 1", cache) == 2.5
    assert same(1234, "1,234") and same(2.5, "2.5") and not same(2.5, "2.6") and same("x", "x")
    try:
        lookup("/nonexistent", "m » a » c", cache)
        raise AssertionError("应当报错")
    except KeyError:
        pass
    cache["lifetime"] = {"c": [[0, 100.0], [1, 22.7], [2, 21.5]]}
    p, _c, _k, n = check_text("t.md", "`1B÷[lifetime » c » 2 » 1 ÷ lifetime » c » 1 » 1]=94.7%` `1B÷[lifetime » c » 2 » 1 ÷ lifetime » c » 1 » 1]=95.0%`",
                              {"matrix": {"rows": []}, "clauses": {}}, "/nonexistent", cache)
    assert n == 2 and len(p) == 1 and "算出来是 94.7%" in p[0], p
    texts = {"a.md": "**INV-1** 甲\n\n**INV-2** 乙\n", "b.md": "| AC-1 | 证明 INV-1 |\n| AC-1 | 重复 |\n引用 INV-9\n"}
    p, _ = check_ids(texts)
    joined = "\n".join(p)
    assert "AC-1 重复定义" in joined and "没有定义的 INV-9" in joined and "INV-2 没有被任何一条验收标准引用" in joined
    assert "INV-1 没有被" not in joined
    assert len(check_tables("t.md", "| a | b |\n| --- | --- |\n| 1 | 2 | 3 |\n\n| x |\n")) == 1
    print("check_design: 自检通过")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="核对设计文档里的引用")
    ap.add_argument("--design", default=os.path.join(ROOT, "docs", "design"))
    ap.add_argument("--phase1b-out", default=os.path.join(ROOT, "research", "phase1b", "out"))
    ap.add_argument("--phase2", default=os.path.join(ROOT, "research", "phase2"))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    problems, totals, defined = run(args.design, args.phase1b_out, args.phase2)
    for p in problems:
        print("check_design: %s" % p, file=sys.stderr)
    kinds = {}
    for i in defined:
        kinds[i.split("-")[0]] = kinds.get(i.split("-")[0], 0) + 1
    print("check_design: 矩阵格子引用 %d 处、条款号 %d 个、1B 数据引用 %d 处；不变量 %d 条、验收标准 %d 条、设计决定 %d 条；问题 %d 个" % (
        totals[0], totals[1], totals[2], kinds.get("INV", 0), kinds.get("AC", 0), kinds.get("DD", 0), len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
