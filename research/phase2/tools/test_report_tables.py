"""report_tables.py 的单元测试：引用核对要有牙齿。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_tables as rt  # noqa: E402


def data():
    cell = {"value": "3", "stable": True, "per_repeat": {}, "footnotes": []}
    shaky = {"value": "1 / 2", "stable": False, "per_repeat": {}, "footnotes": []}
    return {
        "matrix": {"rows": [{"id": "R10", "cells": {"go": cell, "curl": shaky, "firefox-pw": None}}]},
        "clauses": {"9110-9.2.2-5": {}, "9112-C.2.2-1": {}},
    }


def wrap(body, generated="表"):
    return "%s\n%s\n\n%s\n\n%s\n" % (body, rt.BEGIN, generated, rt.END)


class CheckReportTest(unittest.TestCase):
    def check(self, body, generated="表"):
        return rt.check_report(wrap(body), data(), generated)

    def test_correct_citations_pass(self):
        problems, cites, clauses = self.check("见 `R10[go]=3`，条款 9110-9.2.2-5 和 9112-C.2.2-1。")
        self.assertEqual((problems, cites, clauses), ([], 1, 2))

    def test_wrong_value_unknown_row_missing_cell_unstable(self):
        problems, cites, _ = self.check("`R10[go]=4` `R99[go]=3` `R10[firefox-pw]=3` `R10[nope]=3` `R10[curl]=1 / 2`")
        self.assertEqual(cites, 5)
        self.assertEqual(len(problems), 5)
        self.assertIn("矩阵里是“3”", problems[0])
        self.assertIn("不稳定", problems[4])

    def test_several_columns_in_one_citation(self):
        problems, cites, _ = self.check("`R10[go,curl]=3`")
        self.assertEqual((cites, len(problems)), (2, 1))

    def test_unknown_clause(self):
        problems, _, _ = self.check("条款 9110-99.9-1。")
        self.assertEqual(len(problems), 1)

    def test_stale_generated_block_and_missing_markers(self):
        problems, _, _ = self.check("正文", generated="新的表")
        self.assertTrue(any("重新运行" in p for p in problems))
        problems, _, _ = rt.check_report("没有记号", data(), "表")
        self.assertTrue(any("记号" in p for p in problems))

    def test_update_replaces_only_the_block(self):
        out = rt.update_report(wrap("前文", "旧表") + "后文\n", "新表")
        self.assertIn("前文", out)
        self.assertIn("后文", out)
        self.assertIn("新表", out)
        self.assertNotIn("旧表", out)
        self.assertEqual(rt.check_report(out, data(), "新表")[0], [])


if __name__ == "__main__":
    unittest.main()
