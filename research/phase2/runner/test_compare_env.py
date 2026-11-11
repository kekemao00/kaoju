"""compare_env.py 的单元测试：只用临时目录里的假数据，不启动任何进程、不联网。"""

import contextlib
import gzip
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_env  # noqa: E402


def cell(value, stable=True, per=None):
    return {"value": value, "stable": stable, "per_repeat": per or {"1": value}, "footnotes": [], "cases": {}}


def matrix(cells_by_row, columns):
    return {
        "columns": columns,
        "rows": [{"id": rid, "title": "标题" + rid, "cells": cells} for rid, cells in cells_by_row.items()],
    }


def write_out(d, m, records):
    os.makedirs(os.path.join(d, "raw"))
    if m is not None:
        with open(os.path.join(d, "matrix.json"), "w", encoding="utf-8") as fh:
            json.dump(m, fh, ensure_ascii=False)
    by_col = {}
    for r in records:
        by_col.setdefault(r["variant"], []).append(r)
    for col, recs in by_col.items():
        with gzip.open(os.path.join(d, "raw", col + ".jsonl.gz"), "wt", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def rec(col, case, status, skipped=None):
    return {"variant": col, "case": case, "repeat": 1, "skipped": skipped, "pcap_check": {"status": status} if status else None}


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = compare_env.main(args)
    return code, out.getvalue(), err.getvalue()


class CompareTest(unittest.TestCase):
    def test_compare_lists_only_real_differences(self):
        ci = matrix({"R01": {"a": cell("x"), "b": cell("y"), "c": None}, "R02": {"a": cell("1"), "b": cell("2"), "c": None}}, ["a", "b", "c"])
        repo = matrix(
            {"R01": {"a": cell("x"), "b": None, "c": None}, "R02": {"a": cell("1", stable=False, per={"1": "1", "2": "3"}), "b": None, "c": None}},
            ["a", "b", "c"],
        )
        res = compare_env.compare(ci, repo)
        self.assertEqual(res["compared"], 2)
        self.assertEqual(res["same"], 1)
        self.assertEqual([(d["row"], d["column"]) for d in res["diffs"]], [("R02", "a")])
        self.assertEqual(res["only_ci"], ["b"])
        self.assertEqual(res["no_data"], ["c"])

    def test_differences_do_not_fail(self):
        with tempfile.TemporaryDirectory() as t:
            ci, repo = os.path.join(t, "ci"), os.path.join(t, "repo")
            write_out(ci, matrix({"R01": {"a": cell("x")}}, ["a"]), [rec("a", "A01", "ok"), rec("a", "A02", "prefix"), rec("a", "A03", None, skipped="only")])
            write_out(repo, matrix({"R01": {"a": cell("y")}}, ["a"]), [])
            report = os.path.join(t, "diff.json")
            code, out, _ = run(["--ci-out", ci, "--repo-out", repo, "--skip-selfcheck", "--json", report])
            self.assertEqual(code, 0)
            self.assertIn("R01 a", out)
            with open(report, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)["compare"]["diffs"]), 1)

    def test_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as t:
            ci, repo = os.path.join(t, "ci"), os.path.join(t, "repo")
            write_out(ci, matrix({"R01": {"a": cell("x")}}, ["a"]), [rec("a", "A01", "ok"), rec("a", "A02", "mismatch")])
            write_out(repo, matrix({"R01": {"a": cell("x")}}, ["a"]), [])
            code, _, err = run(["--ci-out", ci, "--repo-out", repo, "--skip-selfcheck"])
            self.assertEqual(code, 1)
            self.assertIn("a A02", err)

    def test_missing_repo_matrix_is_not_failure(self):
        with tempfile.TemporaryDirectory() as t:
            ci = os.path.join(t, "ci")
            write_out(ci, matrix({"R01": {"a": cell("x")}}, ["a"]), [rec("a", "A01", "ok")])
            code, out, _ = run(["--ci-out", ci, "--repo-out", os.path.join(t, "nope"), "--skip-selfcheck"])
            self.assertEqual(code, 0)
            self.assertIn("不比较", out)

    def test_selfcheck_failure_fails(self):
        with tempfile.TemporaryDirectory() as t:
            ci = os.path.join(t, "ci")
            # 没有 rawref 的数据：selfcheck.py 退出 2，这里按不通过处理
            write_out(ci, matrix({"R01": {"a": cell("x")}}, ["a"]), [rec("a", "A01", "ok")])
            code, _, err = run(["--ci-out", ci, "--repo-out", os.path.join(t, "nope")])
            self.assertEqual(code, 1)
            self.assertIn("仪器自检没有通过", err)

    def test_missing_ci_input_is_usage_error(self):
        with tempfile.TemporaryDirectory() as t:
            code, _, _ = run(["--ci-out", t, "--skip-selfcheck"])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
