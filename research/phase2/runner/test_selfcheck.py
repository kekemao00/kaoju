"""selfcheck.py 的单元测试：只用临时目录里的小文件，不跑仪器。"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import selfcheck  # noqa: E402


def cell(value, stable=True, per_repeat=None, footnotes=None):
    return {"value": value, "stable": stable, "per_repeat": per_repeat or {"1": value}, "footnotes": footnotes or [], "cases": {}}


class CompareTest(unittest.TestCase):
    def test_all_same(self):
        self.assertEqual(selfcheck.compare(["R01", "R02"], {"R01": "甲", "R02": "乙"}, {"R01": cell("甲"), "R02": cell("乙")}), [])

    def test_different_value(self):
        got = selfcheck.compare(["R01"], {"R01": "甲"}, {"R01": cell("乙", footnotes=["注"])})
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]["row"], got[0]["expected"], got[0]["actual"]), ("R01", "甲", "乙"))
        self.assertIn("注", got[0]["why"])

    def test_unstable_cell_is_a_mismatch_even_if_text_contains_answer(self):
        got = selfcheck.compare(["R01"], {"R01": "甲"}, {"R01": cell("甲", stable=False, per_repeat={"1": "甲", "2": "乙"})})
        self.assertEqual(len(got), 1)
        self.assertIn("各遍取值不同", got[0]["why"])

    def test_missing_cell(self):
        for missing in ({}, {"R01": None}):
            got = selfcheck.compare(["R01"], {"R01": "甲"}, missing)
            self.assertEqual(len(got), 1)
            self.assertIsNone(got[0]["actual"])

    def test_missing_answer(self):
        got = selfcheck.compare(["R01"], {}, {"R01": cell("甲")})
        self.assertEqual(got[0]["why"], "答案文件里没有这一行")

    def test_answer_for_unknown_row(self):
        got = selfcheck.compare(["R01"], {"R01": "甲", "R99": "丙"}, {"R01": cell("甲")})
        self.assertEqual([p["row"] for p in got], ["R99"])


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.write("rows.json", {"rows": [{"id": "R01"}, {"id": "R02"}]})
        self.write("expected.json", {"variant": "rawref", "rows": {"R01": {"value": "甲", "why": ""}, "R02": {"value": "乙", "why": ""}}})

    def write(self, name, obj):
        with open(os.path.join(self.dir, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False)

    def run_main(self, *extra):
        argv = ["--out", self.dir, "--rows", os.path.join(self.dir, "rows.json"), "--expected", os.path.join(self.dir, "expected.json")]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = selfcheck.main(argv + list(extra))
        return code, out.getvalue(), err.getvalue()

    def test_pass(self):
        self.write("selfcheck.json", {"has_data": True, "pass": True, "rows": {"R01": cell("甲"), "R02": cell("乙")}})
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("相同 2 行", out)

    def test_fail_lists_rows_and_ignores_pass_flag(self):
        # matrix.py 自己写的 pass 是被检验的一方，这里不信它
        self.write("selfcheck.json", {"has_data": True, "pass": True, "mismatches": [], "rows": {"R01": cell("甲"), "R02": cell("错")}})
        code, out, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("R02", out)
        self.assertIn("“乙”", out)
        self.assertIn("“错”", out)
        self.assertIn("不通过", err)

    def test_no_rawref_data(self):
        self.write("selfcheck.json", {"has_data": False, "rows": {}, "note": "没有 rawref 的数据"})
        code, _, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("没有 rawref 的数据", err)

    def test_matrix_json_with_rawref_column(self):
        self.write("matrix.json", {"rows": [{"id": "R01", "cells": {"rawref": cell("甲")}}, {"id": "R02", "cells": {"rawref": cell("乙")}}]})
        self.assertEqual(self.run_main()[0], 0)

    def test_matrix_json_without_rawref_column(self):
        self.write("matrix.json", {"rows": [{"id": "R01", "cells": {"curl": cell("甲")}}]})
        self.assertEqual(self.run_main()[0], 2)

    def test_no_files(self):
        self.assertEqual(self.run_main()[0], 2)

    def test_real_answer_file_covers_every_row(self):
        # 定稿的行表和仓库里的答案必须一一对应
        rows = [rd["id"] for rd in selfcheck.load_json(os.path.join(selfcheck.P2_DIR, "rows.json"))["rows"]]
        expected = selfcheck.expected_values(selfcheck.load_json(os.path.join(selfcheck.P2_DIR, "selfcheck_expected.json")))
        self.assertEqual(sorted(rows), sorted(expected))


if __name__ == "__main__":
    unittest.main()
