#!/usr/bin/env python3
"""第 2 阶段报告里的数字：从 out/ 和 spec/ 生成表格，并核对报告里引用的格子和条款。

    report_tables.py                      # 写 out/report_tables.md
    report_tables.py --update 报告.md     # 另把生成的表格写进报告里 BEGIN/END 记号之间
    report_tables.py --check 报告.md      # 只核对，不写文件；有问题退出码 1

报告的规矩（CLAUDE.md）：数字不手抄。报告正文里凡是说到矩阵的格子，都写成反引号里的
`R10[node-agents,node-axios]=3` 这种形式；说到 RFC 条款，都写条款号（如 9110-9.2.2-5）。--check 做三件事：

1. 每个 `R…[列,…]=值` 与 out/matrix.json 逐格比较（值要完全相同，“不稳定”的格子不许引用）；
2. 每个条款号在 spec/clauses/*.json 里存在；
3. 报告里 BEGIN/END 记号之间的内容与现在生成的逐字相同（数据变了而报告没重新生成会被发现）。

只用标准库。
"""

import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
P2 = os.path.dirname(HERE)
BEGIN = "<!-- BEGIN report_tables：由 research/phase2/tools/report_tables.py 生成，不要手改 -->"
END = "<!-- END report_tables -->"
CITE = re.compile(r"`(R\d+)\[([^\]`]+)\]=([^`]+)`")
CLAUSE = re.compile(r"(?<![\w.-])((?:1928|1929|6455|7617|9110|9112|9113|9209)-[A-Z]?[\d.]*\d-\d+)(?![\w-])")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_all(p2=P2):
    out = os.path.join(p2, "out")
    clauses = {}
    per_rfc = []
    for path in sorted(glob.glob(os.path.join(p2, "spec", "clauses", "*.json"))):
        doc = load(path)
        per_rfc.append((doc["rfc"], doc.get("title", ""), len(doc["clauses"])))
        for cl in doc["clauses"]:
            clauses[cl["id"]] = cl
    return {
        "matrix": load(os.path.join(out, "matrix.json")),
        "pcap": load(os.path.join(out, "pcap_check.json")),
        "versions": load(os.path.join(out, "versions.json")),
        "diff": load(os.path.join(out, "expectation_diff.json")),
        "selfcheck": load(os.path.join(out, "selfcheck.json")),
        "cases": load(os.path.join(p2, "cases.json")),
        "rows": load(os.path.join(p2, "rows.json")),
        "caveats": load(os.path.join(p2, "caveats.json")) if os.path.exists(os.path.join(p2, "caveats.json")) else {"caveats": []},
        "clauses": clauses,
        "per_rfc": per_rfc,
    }


VERSION_KEYS = {
    "curl": ["curl", "distro_packages", "openssl", "nghttp2"],
    "curl-anyauth": ["curl", "distro_packages"],
    "requests": ["requests", "urllib3", "PySocks", "python", "openssl"],
    "go": ["go"],
    "node-fetch-env": ["node", "node 内置的 undici", "openssl"],
    "node-http-env": ["node"],
    "node-undici": ["node", "undici"],
    "node-agents": ["node", "http-proxy-agent", "https-proxy-agent", "socks-proxy-agent", "socks"],
    "node-axios": ["node", "axios", "axios 自带的 https-proxy-agent", "follow-redirects"],
    "chromium-pw": ["playwright", "browser_version", "node"],
    "firefox-pw": ["playwright", "browser_version", "node"],
}


def fmt_version(col, info):
    vv = (info or {}).get("versions") or {}
    parts = []
    for k in VERSION_KEYS.get(col, sorted(vv)):
        if k in vv and vv[k] not in (None, ""):
            v = vv[k]
            parts.append("%s %s" % (k, "、".join(v) if isinstance(v, list) else v))
    return "；".join(parts) or "（没有记录）"


def count(x):
    return x if isinstance(x, int) else len(x or [])


def tables(d):
    m, pc, ver, diff = d["matrix"], d["pcap"], d["versions"], d["diff"]["columns"]
    cols = m["columns"]
    L = []
    cases = d["cases"]["cases"]
    groups = {}
    for c in cases:
        groups[c["id"][0]] = groups.get(c["id"][0], 0) + 1
    L.append("**规模。** 用例 %d 个（%s），每个 %d 遍；矩阵 %d 行 × %d 列，其中有数据的 %d 列%s。" % (
        len(cases), "、".join("%s 组 %d" % (g, n) for g, n in sorted(groups.items())), d["cases"].get("repeats"),
        len(m["rows"]), len(cols), len(m["columns_with_data"]),
        "，没有数据的列：%s" % "、".join("`%s`" % c for c in m["columns_missing"]) if m["columns_missing"] else ""))
    L.append("")
    sc = d["selfcheck"]
    L.append("**仪器自检。** 参照客户端 `rawref` 一列与手写答案比较 %d 行，不一致 %d 行，结论：%s。" % (
        count(sc.get("rows")), count(sc.get("mismatches")), "通过" if sc.get("pass") else "不通过"))
    L.append("")
    L.append("**各列的版本和正式运行的时刻**（`out/versions.json`）")
    L.append("")
    L.append("| 列 | 版本 | 运行时刻（UTC） | 系统 |")
    L.append("| --- | --- | --- | --- |")
    for col in cols + ["rawref"]:
        info = ver["variants"].get(col)
        if not info:
            L.append("| `%s` | （没有数据） | | |" % col)
            continue
        env = info.get("env") or {}
        L.append("| `%s` | %s | %s | %s，内核 %s |" % (col, fmt_version(col, info), env.get("run_at_utc", ""), env.get("os", ""), env.get("kernel", "")))
    L.append("")
    L.append("**运行次数和抓包核对**（`out/pcap_check.json`）")
    L.append("")
    L.append("| 列 | 运行 | 按用例的 only 跳过 | 逐字节相同 | prefix | 不一致 | tcpdump 丢包 | 运行器出错 | 驱动超时 | 驱动非零退出 |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")

    def pc_row(name, s):
        st = s["status"]
        other = sum(n for k, n in st.items() if k not in ("ok", "prefix"))
        return "| %s | %d | %d | %d | %d | %d | %s | %s | %s | %s |" % (
            name, s["runs"], s["skipped"], st.get("ok", 0), st.get("prefix", 0), other,
            s.get("tcpdump_dropped_runs", ""), s.get("runner_error_runs", ""), s.get("driver_timeout_runs", ""), s.get("driver_nonzero_exit_runs", ""))

    tot = {k: 0 for k in ("tcpdump_dropped_runs", "runner_error_runs", "driver_timeout_runs", "driver_nonzero_exit_runs")}
    for col in sorted(pc["columns"]):
        s = pc["columns"][col]
        L.append(pc_row("`%s`" % col, s))
        for k in tot:
            tot[k] += s[k]
    L.append(pc_row("合计", dict(pc["total"], **tot)))
    L.append("")
    L.append("**实测与预期**（`out/expectation_diff.md`；预期写于实测之前）")
    L.append("")
    L.append("| 列 | 比较的格子 | 相符 | 不符 | 预期是“不知道” | 不符的行 |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    tc = tm = td = 0
    for col in cols:
        e = diff.get(col)
        if not e or not e.get("compared"):
            L.append("| `%s` | 0 | | | | （没有实测数据） |" % col)
            continue
        rows = "、".join(x["row"] for x in e["diffs"]) if isinstance(e.get("diffs"), list) else ""
        nd = len(e["diffs"]) if isinstance(e.get("diffs"), list) else e.get("diffs", 0)
        L.append("| `%s` | %d | %d | %d | %d | %s |" % (col, e["compared"], e["matched"], nd, e.get("unknown", 0), rows))
        tc += e["compared"]
        tm += e["matched"]
        td += nd
    L.append("| 合计 | %d | %d | %d | | |" % (tc, tm, td))
    L.append("")
    other = unstable = unsupported = 0
    cav = 0
    for rd in m["rows"]:
        for col in cols:
            cell = rd["cells"].get(col)
            if not cell:
                continue
            if not cell["stable"]:
                unstable += 1
            if cell["value"].startswith("其他："):
                other += 1
            if cell["value"] == "不支持":
                unsupported += 1
            if cell.get("caveats"):
                cav += 1
    L.append("**矩阵里的格子。** 各遍取值不同（不稳定）的 %d 格；落到“其他：”的 %d 格；“不支持”的 %d 格；挂了读数须知的 %d 格（`caveats.json` 共 %d 条）。" % (
        unstable, other, unsupported, cav, len(d["caveats"]["caveats"])))
    L.append("")
    L.append("**规范条款**（`spec/clauses/`，引文由 `spec/check_quotes.py` 逐字核对）")
    L.append("")
    L.append("| RFC | 条款数 | 其中标了矩阵行的 |")
    L.append("| --- | --- | --- |")
    total = linked = 0
    by_rfc = {}
    for cid, cl in d["clauses"].items():
        r = cid.split("-")[0]
        a = by_rfc.setdefault(r, [0, 0])
        a[0] += 1
        a[1] += 1 if cl.get("rows") else 0
    for rfc, _title, n in d["per_rfc"]:
        key = str(rfc).replace("RFC", "").strip()
        a = by_rfc.get(key, [n, 0])
        L.append("| RFC %s | %d | %d |" % (key, a[0], a[1]))
        total += a[0]
        linked += a[1]
    L.append("| 合计 | %d | %d |" % (total, linked))
    return "\n".join(L) + "\n"


def check_report(text, d, generated):
    problems = []
    by_id = {rd["id"]: rd for rd in d["matrix"]["rows"]}
    cites = 0
    for rid, cols, value in CITE.findall(text):
        value = value.strip()
        for col in [c.strip() for c in cols.split(",")]:
            cites += 1
            rd = by_id.get(rid)
            if rd is None:
                problems.append("引用了不存在的行 %s" % rid)
                continue
            cell = rd["cells"].get(col)
            if cell is None:
                problems.append("%s[%s]：这一格没有数据（或没有这一列）" % (rid, col))
            elif not cell["stable"]:
                problems.append("%s[%s]：这一格不稳定，不能当成一个值引用" % (rid, col))
            elif cell["value"] != value:
                problems.append("%s[%s]：报告写的是“%s”，矩阵里是“%s”" % (rid, col, value, cell["value"]))
    clause_ids = set(CLAUSE.findall(text))
    for cid in sorted(clause_ids):
        if cid not in d["clauses"]:
            problems.append("条款号 %s 不在 spec/clauses/ 里" % cid)
    if BEGIN in text and END in text:
        inner = text.split(BEGIN, 1)[1].split(END, 1)[0].strip("\n")
        if inner != generated.strip("\n"):
            problems.append("报告里生成的表格与现在的数据不一致，重新运行 --update")
    else:
        problems.append("报告里没有 BEGIN/END report_tables 记号")
    return problems, cites, len(clause_ids)


def update_report(text, generated):
    if BEGIN not in text or END not in text:
        raise ValueError("报告里没有 BEGIN/END report_tables 记号")
    head, rest = text.split(BEGIN, 1)
    _old, tail = rest.split(END, 1)
    return head + BEGIN + "\n\n" + generated.strip("\n") + "\n\n" + END + tail


def main(argv=None):
    ap = argparse.ArgumentParser(description="第 2 阶段报告的表格和引用核对")
    ap.add_argument("--update", metavar="报告", help="把表格写进这份报告的记号之间")
    ap.add_argument("--check", metavar="报告", help="只核对这份报告，不写任何文件")
    ap.add_argument("--phase2", default=P2, help="research/phase2 的位置")
    args = ap.parse_args(argv)
    d = load_all(args.phase2)
    generated = tables(d)
    if args.check:
        with open(args.check, encoding="utf-8") as fh:
            problems, cites, clauses = check_report(fh.read(), d, generated)
        for p in problems:
            print("report_tables: %s" % p, file=sys.stderr)
        print("report_tables: 核对了 %d 处格子引用、%d 个条款号，问题 %d 个" % (cites, clauses, len(problems)))
        return 1 if problems else 0
    with open(os.path.join(args.phase2, "out", "report_tables.md"), "w", encoding="utf-8") as fh:
        fh.write("# 第 2 阶段报告用的表格\n\n由 `tools/report_tables.py` 生成，不要手改。\n\n" + generated)
    if args.update:
        with open(args.update, encoding="utf-8") as fh:
            text = fh.read()
        with open(args.update, "w", encoding="utf-8") as fh:
            fh.write(update_report(text, generated))
    print("report_tables: 已生成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
