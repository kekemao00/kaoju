#!/usr/bin/env python3
"""仪器自检的最后一步：rawref 那一列与手写答案逐行比较。

口径见 ../PROTOCOL.md“仪器自检”一节。rawref 发出的每个字节都是写死的，矩阵里它那一列该是什么值由
selfcheck_expected.json 事先手写；这里只做比较，不取值。只用 Python 标准库。

    python3 runner/selfcheck.py --out out          # 读 out/selfcheck.json（没有时读 out/matrix.json 里 rawref 一列）
    python3 runner/selfcheck.py --actual 某个.json --expected selfcheck_expected.json

退出码：0 行表里的每一行都与答案相同；1 有不一致（逐条列在标准输出）；2 输入文件读不了或格式不对。

比较不依赖 matrix.py 自己算出来的 pass 和 mismatches（那是被检验的一方），而是重新逐行比：

- 行表（rows.json）里的每一行都必须在答案里有值、在实测里有格子；
- 格子必须稳定（各遍取值相同），值与答案逐字相同；
- 答案里多出来的行（行表里没有）也算不一致，防止行表改了而答案没跟上。
"""

import argparse
import json
import os
import re
import sys

P2_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLUMN = "rawref"


class InputError(Exception):
    pass


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise InputError("读不了 %s：%s" % (path, exc)) from exc


def row_key(rid):
    m = re.fullmatch(r"R(\d+)", rid)
    return (0, int(m.group(1))) if m else (1, rid)


def expected_values(obj):
    """答案文件 → {行号: 值}。只接受 {"rows": {"R01": {"value": "…"}}}，值必须是字符串。"""
    rows = obj.get("rows") if isinstance(obj, dict) else None
    if not isinstance(rows, dict):
        raise InputError("答案文件里没有 rows 对象")
    out = {}
    for rid, v in rows.items():
        value = v.get("value") if isinstance(v, dict) else v
        if not isinstance(value, str):
            raise InputError("答案文件 %s 的 value 不是字符串" % rid)
        out[rid] = value
    return out


def actual_cells(obj):
    """实测文件 → {行号: 格子或 None}。

    接受 matrix.py 写的 selfcheck.json（rows 是 {行号: 格子}），
    或 matrix.json（rows 是列表，每行的 cells 里有 rawref 一列）。
    """
    if not isinstance(obj, dict):
        raise InputError("实测文件不是 JSON 对象")
    rows = obj.get("rows")
    if isinstance(rows, dict):
        if obj.get("has_data") is False:
            raise InputError("实测文件里没有 rawref 的数据（%s）" % (obj.get("note") or "has_data 为假"))
        return dict(rows)
    if isinstance(rows, list):
        out = {}
        for rd in rows:
            cells = rd.get("cells") if isinstance(rd, dict) else None
            if not isinstance(cells, dict) or COLUMN not in cells:
                raise InputError("matrix.json 里没有 rawref 一列（matrix.py 把它单独写在 selfcheck.json 里）")
            out[rd["id"]] = cells[COLUMN]
        return out
    raise InputError("实测文件里没有 rows")


def compare(row_ids, expected, cells):
    """逐行比较，返回不一致的列表，每项是 {"row", "expected", "actual", "why"}。"""
    problems = []
    for rid in row_ids:
        exp = expected.get(rid)
        cell = cells.get(rid)
        if exp is None:
            problems.append({"row": rid, "expected": None, "actual": _show(cell), "why": "答案文件里没有这一行"})
            continue
        if not isinstance(cell, dict) or not isinstance(cell.get("value"), str):
            problems.append({"row": rid, "expected": exp, "actual": None, "why": "实测里没有这一行的取值（rawref 没跑这一行的用例？）"})
            continue
        if cell.get("stable") is not True:
            problems.append({"row": rid, "expected": exp, "actual": _show(cell), "why": "各遍取值不同：%s" % json.dumps(cell.get("per_repeat"), ensure_ascii=False, sort_keys=True)})
            continue
        if cell["value"] != exp:
            why = "不相同"
            if cell.get("footnotes"):
                why += "；脚注：%s" % "；".join(str(n) for n in cell["footnotes"])
            problems.append({"row": rid, "expected": exp, "actual": cell["value"], "why": why})
    known = set(row_ids)
    for rid in sorted(set(expected) - known, key=row_key):
        problems.append({"row": rid, "expected": expected[rid], "actual": None, "why": "答案文件里有、行表里没有的行"})
    return problems


def _show(cell):
    if not isinstance(cell, dict):
        return None
    value = cell.get("value")
    return value if cell.get("stable") is True else "%s（不稳定）" % value


def find_actual(out_dir):
    for name in ("selfcheck.json", "matrix.json"):
        p = os.path.join(out_dir, name)
        if os.path.isfile(p):
            return p
    raise InputError("%s 下没有 selfcheck.json 或 matrix.json，先跑 derive.py 和 matrix.py" % out_dir)


def main(argv=None):
    ap = argparse.ArgumentParser(description="rawref 一列与手写答案逐行比较")
    ap.add_argument("--out", default=os.path.join(P2_DIR, "out"), help="matrix.py 的输出目录")
    ap.add_argument("--actual", default=None, help="实测文件；默认是 <out>/selfcheck.json，没有时用 <out>/matrix.json")
    ap.add_argument("--expected", default=os.path.join(P2_DIR, "selfcheck_expected.json"), help="手写的答案")
    ap.add_argument("--rows", default=os.path.join(P2_DIR, "rows.json"), help="行表")
    args = ap.parse_args(argv)

    try:
        actual_path = args.actual or find_actual(args.out)
        rows_obj = load_json(args.rows)
        if not isinstance(rows_obj, dict) or not isinstance(rows_obj.get("rows"), list):
            raise InputError("行表 %s 里没有 rows 列表" % args.rows)
        row_ids = [rd["id"] for rd in rows_obj["rows"]]
        expected = expected_values(load_json(args.expected))
        cells = actual_cells(load_json(actual_path))
    except InputError as exc:
        print("selfcheck: %s" % exc, file=sys.stderr)
        return 2

    problems = compare(row_ids, expected, cells)
    same = len(row_ids) - len({p["row"] for p in problems if p["row"] in set(row_ids)})
    print("selfcheck: 行表 %d 行，与答案相同 %d 行，不一致 %d 处（实测：%s）" % (len(row_ids), same, len(problems), actual_path))
    for p in problems:
        print("  %s：答案 %s，实测 %s。%s" % (p["row"], _quote(p["expected"]), _quote(p["actual"]), p["why"]))
    if problems:
        print("selfcheck: 仪器自检不通过，其他客户端的数据不能采信", file=sys.stderr)
        return 1
    print("selfcheck: 仪器自检通过")
    return 0


def _quote(v):
    return "（无）" if v is None else "“%s”" % v


if __name__ == "__main__":
    sys.exit(main())
