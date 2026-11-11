#!/usr/bin/env python3
"""CI 日志末尾的小结：把另一个环境的结论用几百行以内的文字打出来，读日志的尾部就够。

    ci_summary.py --ci-out DIR [--column firefox-pw] [--compare DIR/compare_env.json]

打印三样东西，都夹在 BEGIN/END 记号之间：

1. 两个环境逐格比较里不一致的格子（compare_env.py --json 的输出）；
2. 指定的列（默认 firefox-pw，本机跑不了的那一列）每一行的取值、与预期的比较、抓包核对的小结、版本；
3. 这一列原始记录（raw/<列>.jsonl.gz）的 SHA-256。原始记录本身在构件 phase2-out 里，
   取回后放进仓库时拿这个哈希核对。

只读、只用标准库。指定的列没有数据时退出码 1。
"""

import argparse
import hashlib
import json
import os
import sys

BEGIN = "-----BEGIN KAOJU CI SUMMARY-----"
END = "-----END KAOJU CI SUMMARY-----"


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def clip(text, n=240):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def summary_lines(ci_out, column, compare_path=None):
    L = []
    ok = True
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"):
        if os.environ.get(key):
            L.append("%s=%s" % (key, os.environ[key]))
    compare_path = compare_path or os.path.join(ci_out, "compare_env.json")
    L.append("## 两个环境的比较")
    if os.path.exists(compare_path):
        cmp_doc = load(compare_path).get("compare") or {}
        L.append("比较 %s 格，相同 %s 格；只有 CI 有数据的列：%s；只有仓库有数据的列：%s" % (
            cmp_doc.get("compared"), cmp_doc.get("same"),
            "、".join(cmp_doc.get("only_ci") or []) or "无", "、".join(cmp_doc.get("only_repo") or []) or "无"))
        for d in cmp_doc.get("diffs") or []:
            L.append("DIFF %s [%s] CI=%s | 仓库=%s" % (d["row"], d["column"], clip(d["ci"], 120), clip(d["repo"], 120)))
    else:
        L.append("没有 %s" % compare_path)
    L.append("## %s" % column)
    matrix = load(os.path.join(ci_out, "matrix.json"))
    if column not in matrix.get("columns_with_data", []):
        L.append("这一列没有数据")
        return L, False
    raw = os.path.join(ci_out, "raw", "%s.jsonl.gz" % column)
    L.append("SHA-256 raw/%s.jsonl.gz = %s（%d 字节）" % (column, sha256(raw), os.path.getsize(raw)))
    versions = load(os.path.join(ci_out, "versions.json"))
    L.append("版本：" + json.dumps((versions.get("variants") or {}).get(column, {}).get("versions"), ensure_ascii=False, sort_keys=True))
    L.append("环境：" + json.dumps(versions.get("env"), ensure_ascii=False, sort_keys=True))
    pc_path = os.path.join(ci_out, "pcap_check.json")
    if os.path.exists(pc_path):
        pc = (load(pc_path).get("columns") or {}).get(column) or {}
        L.append("抓包核对：" + json.dumps({k: v for k, v in pc.items() if k != "not_ok"}, ensure_ascii=False, sort_keys=True))
        for item in (pc.get("not_ok") or [])[:20]:
            L.append("NOT_OK " + clip(json.dumps(item, ensure_ascii=False), 300))
    diff_path = os.path.join(ci_out, "expectation_diff.json")
    diffs = {}
    if os.path.exists(diff_path):
        e = (load(diff_path).get("columns") or {}).get(column) or {}
        L.append("与预期：比较 %s 格，相符 %s 格，预期是不知道 %s 行" % (e.get("compared"), e.get("matched"), e.get("unknown")))
        if isinstance(e.get("diffs"), list):
            diffs = {d["row"]: d for d in e["diffs"]}
    for rd in matrix["rows"]:
        cell = rd["cells"].get(column)
        if cell is None:
            L.append("%s （没有数据）" % rd["id"])
            continue
        line = "%s %s%s" % (rd["id"], clip(cell["value"], 160), "" if cell["stable"] else " （不稳定）")
        if rd["id"] in diffs:
            line += " | 预期=%s" % clip(diffs[rd["id"]].get("expect"), 80)
        if cell["value"] != "不支持" and cell.get("footnotes"):
            line += " | 注：" + clip("；".join(cell["footnotes"]), 240)
        L.append(line)
    return L, ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="CI 日志末尾的小结")
    ap.add_argument("--ci-out", required=True)
    ap.add_argument("--column", default="firefox-pw")
    ap.add_argument("--compare", default=None)
    args = ap.parse_args(argv)
    try:
        lines, ok = summary_lines(args.ci_out, args.column, args.compare)
    except (OSError, ValueError, KeyError) as exc:
        print("ci_summary: 读不了输入：%s" % exc, file=sys.stderr)
        return 2
    print(BEGIN)
    print("\n".join(lines))
    print(END)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
