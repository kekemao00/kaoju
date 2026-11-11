#!/usr/bin/env python3
"""两个环境的矩阵逐格比较（../PROTOCOL.md“两个环境”一节）。

CI 上重跑全部用例以后，把得到的 matrix.json 与仓库里提交的那份逐格比较，把不一致的格子打印出来。
只用 Python 标准库。

    python3 runner/compare_env.py --ci-out "$RUNNER_TEMP/p2-out"            # 仓库一侧默认是 research/phase2/out
    python3 runner/compare_env.py --ci-out DIR --repo-out DIR --json diff.json

退出码：

- 0：比较做完了。格子不一致不算失败（两个环境的客户端版本、调度都可能不同，差异要人看），只打印。
  仓库里还没有提交 matrix.json 时也是 0，只说明没得比。
- 1：CI 这一侧的数据本身不能采信：仪器自检（selfcheck.py）不通过，或者有运行的抓包核对结论是 mismatch。
- 2：CI 一侧的输入读不了（没有 matrix.json、没有 raw 目录等）。

一个格子按“取值 + 是否稳定”比较：两边都稳定且取值逐字相同才算一致。某一列在一边整列没有数据时不逐格列出，
只在小结里说明（比如 firefox-pw 在本机跑不了，仓库里可能还没有它的数据）。
"""

import argparse
import glob
import gzip
import json
import os
import sys

RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))
P2_DIR = os.path.dirname(RUNNER_DIR)

NO_DATA = "（没有数据）"


class InputError(Exception):
    pass


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise InputError("读不了 %s：%s" % (path, exc)) from exc


def show(cell):
    """格子 → 用来比较和打印的字符串。"""
    if not isinstance(cell, dict):
        return NO_DATA
    value = cell.get("value")
    if cell.get("stable") is True:
        return str(value)
    per = cell.get("per_repeat")
    if isinstance(per, dict) and per:
        return "%s（不稳定：%s）" % (value, json.dumps(per, ensure_ascii=False, sort_keys=True))
    return "%s（不稳定）" % value


def index(matrix):
    """matrix.json → (列的顺序, 行的顺序, {行号: 标题}, {(行号, 列): 格子})。"""
    if not isinstance(matrix, dict) or not isinstance(matrix.get("rows"), list):
        raise InputError("matrix.json 里没有 rows 列表")
    columns = list(matrix.get("columns") or [])
    rows, titles, cells = [], {}, {}
    for rd in matrix["rows"]:
        rid = rd.get("id")
        rows.append(rid)
        titles[rid] = rd.get("title") or ""
        for col, cell in (rd.get("cells") or {}).items():
            if col not in columns:
                columns.append(col)
            cells[(rid, col)] = cell
    return columns, rows, titles, cells


def compare(ci, repo):
    """两份 matrix.json → {"diffs": […], "only_ci": [列], "only_repo": [列], "no_data": [列], "compared": 格子数, "same": 格子数}。"""
    ci_cols, ci_rows, ci_titles, ci_cells = index(ci)
    repo_cols, repo_rows, repo_titles, repo_cells = index(repo)
    columns = ci_cols + [c for c in repo_cols if c not in ci_cols]
    rows = ci_rows + [r for r in repo_rows if r not in ci_rows]

    def has_data(cells, col):
        return any(isinstance(cells.get((rid, col)), dict) for rid in rows)

    only_ci, only_repo, no_data, both = [], [], [], []
    for col in columns:
        a, b = has_data(ci_cells, col), has_data(repo_cells, col)
        if a and b:
            both.append(col)
        elif a:
            only_ci.append(col)
        elif b:
            only_repo.append(col)
        else:
            no_data.append(col)

    diffs, compared, same = [], 0, 0
    for rid in rows:
        for col in both:
            a, b = show(ci_cells.get((rid, col))), show(repo_cells.get((rid, col)))
            compared += 1
            if a == b:
                same += 1
            else:
                diffs.append({"row": rid, "title": ci_titles.get(rid) or repo_titles.get(rid) or "", "column": col, "ci": a, "repo": b})
    return {
        "diffs": diffs,
        "only_ci": only_ci,
        "only_repo": only_repo,
        "no_data": no_data,
        "compared": compared,
        "same": same,
        "rows_only_ci": [r for r in ci_rows if r not in repo_rows],
        "rows_only_repo": [r for r in repo_rows if r not in ci_rows],
    }


def pcap_statuses(raw_dir):
    """out/raw 下每一列的抓包核对结论计数，以及 mismatch 的运行。

    返回 ({列: {结论: 次数}}, [(列, 用例, 遍数)])。没有运行的记录（skipped）不计。
    """
    files = sorted(glob.glob(os.path.join(raw_dir, "*.jsonl.gz")))
    if not files:
        raise InputError("%s 下没有 *.jsonl.gz" % raw_dir)
    counts, bad = {}, []
    for path in files:
        col = os.path.basename(path)[: -len(".jsonl.gz")]
        per = counts.setdefault(col, {})
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    if rec.get("skipped"):
                        continue
                    pc = rec.get("pcap_check")
                    status = pc.get("status") if isinstance(pc, dict) else None
                    status = str(status) if status is not None else "（没有核对结论）"
                    per[status] = per.get(status, 0) + 1
                    if status == "mismatch":
                        bad.append((rec.get("variant") or col, rec.get("case"), rec.get("repeat")))
        except (OSError, ValueError, EOFError) as exc:
            raise InputError("读不了 %s：%s" % (path, exc)) from exc
    return counts, bad


def run_selfcheck(ci_out):
    """调用同目录的 selfcheck.py，返回它的退出码。"""
    sys.path.insert(0, RUNNER_DIR)
    try:
        import selfcheck  # noqa: PLC0415  与本文件同目录
    finally:
        sys.path.pop(0)
    return selfcheck.main(["--out", ci_out])


def main(argv=None):
    ap = argparse.ArgumentParser(description="CI 的矩阵与仓库里提交的矩阵逐格比较")
    ap.add_argument("--ci-out", required=True, help="CI 这次运行的输出目录（run_all.sh 的 --out）")
    ap.add_argument("--repo-out", default=os.path.join(P2_DIR, "out"), help="仓库里提交的输出目录")
    ap.add_argument("--json", default=None, help="把比较结果另写一份 JSON")
    ap.add_argument("--skip-selfcheck", action="store_true", help="不重新跑 selfcheck.py（只供单元测试）")
    args = ap.parse_args(argv)

    failed = False
    report = {"selfcheck_exit": None, "pcap": None, "pcap_mismatch": [], "compare": None, "note": None}

    # 一、CI 这一侧的数据能不能采信
    try:
        counts, bad = pcap_statuses(os.path.join(args.ci_out, "raw"))
        ci_matrix = load_json(os.path.join(args.ci_out, "matrix.json"))
    except InputError as exc:
        print("compare_env: %s" % exc, file=sys.stderr)
        return 2
    report["pcap"] = counts
    report["pcap_mismatch"] = [list(x) for x in bad]
    print("compare_env: 抓包核对的结论（CI 一侧，按列）")
    for col in sorted(counts):
        print("  %s：%s" % (col, "，".join("%s %d" % (k, v) for k, v in sorted(counts[col].items()))))
    if bad:
        failed = True
        print("compare_env: 有 %d 次运行的抓包核对是 mismatch：" % len(bad), file=sys.stderr)
        for col, case, rep in bad:
            print("  %s %s 第 %s 遍" % (col, case, rep), file=sys.stderr)

    if not args.skip_selfcheck:
        code = run_selfcheck(args.ci_out)
        report["selfcheck_exit"] = code
        if code != 0:
            failed = True
            print("compare_env: 仪器自检没有通过（selfcheck.py 退出码 %d）" % code, file=sys.stderr)

    # 二、逐格比较
    repo_path = os.path.join(args.repo_out, "matrix.json")
    if not os.path.isfile(repo_path):
        report["note"] = "仓库里没有提交 matrix.json，没得比"
        print("compare_env: %s 不存在：仓库里还没有提交矩阵，这次不比较" % repo_path)
    else:
        try:
            res = compare(ci_matrix, load_json(repo_path))
        except InputError as exc:
            # 仓库里的文件坏了不是 CI 数据的问题：说明白，不因此失败
            report["note"] = "仓库里的 matrix.json 用不了：%s" % exc
            print("compare_env: 仓库里的 matrix.json 用不了，这次不比较：%s" % exc)
            res = None
        if res is not None:
            report["compare"] = res
            print(
                "compare_env: 两边都有数据的列逐格比较：共 %d 格，相同 %d 格，不一致 %d 格"
                % (res["compared"], res["same"], len(res["diffs"]))
            )
            if res["only_ci"]:
                print("  只有 CI 有数据的列（不比较）：%s" % "、".join(res["only_ci"]))
            if res["only_repo"]:
                print("  只有仓库有数据的列（不比较）：%s" % "、".join(res["only_repo"]))
            if res["no_data"]:
                print("  两边都没有数据的列：%s" % "、".join(res["no_data"]))
            if res["rows_only_ci"] or res["rows_only_repo"]:
                print(
                    "  行表不同：只在 CI 的行 %s；只在仓库的行 %s"
                    % ("、".join(res["rows_only_ci"]) or "无", "、".join(res["rows_only_repo"]) or "无")
                )
            for d in res["diffs"]:
                print("  %s %s（%s）：CI “%s”，仓库 “%s”" % (d["row"], d["column"], d["title"], d["ci"], d["repo"]))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=1, sort_keys=True)
            fh.write("\n")

    if failed:
        print("compare_env: CI 这一侧的数据不能采信，见上", file=sys.stderr)
        return 1
    print("compare_env: 完成（格子不一致不算失败）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
