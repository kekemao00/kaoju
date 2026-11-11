"""ci_summary.py 的单元测试。"""

import gzip
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_summary  # noqa: E402


def make(tmp, with_data=True):
    cell = {"value": "先带", "stable": True, "footnotes": ["脚注"], "per_repeat": {}}
    matrix = {"columns_with_data": ["firefox-pw"] if with_data else [],
              "rows": [{"id": "R30", "cells": {"firefox-pw": cell if with_data else None}},
                       {"id": "R31", "cells": {"firefox-pw": {"value": "1 / 2", "stable": False, "footnotes": []} if with_data else None}}]}
    os.makedirs(os.path.join(tmp, "raw"))
    for name, doc in (("matrix.json", matrix),
                      ("versions.json", {"env": {"os": "x"}, "variants": {"firefox-pw": {"versions": {"browser_version": "1"}}}}),
                      ("pcap_check.json", {"columns": {"firefox-pw": {"runs": 2, "status": {"ok": 2}, "not_ok": []}}}),
                      ("expectation_diff.json", {"columns": {"firefox-pw": {"compared": 2, "matched": 1, "unknown": 0,
                                                                            "diffs": [{"row": "R30", "expect": "等 407 再带"}]}}}),
                      ("compare_env.json", {"compare": {"compared": 4, "same": 3, "only_ci": ["firefox-pw"], "only_repo": [],
                                                        "diffs": [{"row": "R07", "column": "curl", "ci": "a", "repo": "b"}]}})):
        with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
    with gzip.open(os.path.join(tmp, "raw", "firefox-pw.jsonl.gz"), "wt") as fh:
        fh.write("{}\n")


class CiSummaryTest(unittest.TestCase):
    def test_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            make(tmp)
            lines, ok = ci_summary.summary_lines(tmp, "firefox-pw")
            digest = ci_summary.sha256(os.path.join(tmp, "raw", "firefox-pw.jsonl.gz"))
        text = "\n".join(lines)
        self.assertTrue(ok)
        self.assertIn("DIFF R07 [curl] CI=a | 仓库=b", text)
        self.assertIn("只有 CI 有数据的列：firefox-pw", text)
        self.assertIn(digest, text)
        self.assertIn("R30 先带 | 预期=等 407 再带 | 注：脚注", text)
        self.assertIn("R31 1 / 2 （不稳定）", text)

    def test_column_without_data_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            make(tmp, with_data=False)
            self.assertEqual(ci_summary.main(["--ci-out", tmp]), 1)

    def test_unreadable_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(ci_summary.main(["--ci-out", tmp]), 2)


if __name__ == "__main__":
    unittest.main()
