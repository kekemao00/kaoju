"""collect.py 的单元测试。"""

import gzip
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect  # noqa: E402


def rec(case, status, skipped=None, dropped=0, errors=(), timeout=False, exit_code=0):
    return {"case": case, "repeat": 1, "skipped": skipped,
            "pcap_check": None if skipped else {"status": status, "conns": [{}, {}], "problems": ["p"],
                                               "fields": {"compared": 3, "mismatched": ["x"] if status == "mismatch" else []}},
            "tcpdump": {"dropped": dropped}, "runner_errors": list(errors),
            "driver": {"timeout": timeout, "exit": exit_code}}


class CollectTest(unittest.TestCase):
    def test_pcap_summary_counts(self):
        s = collect.pcap_summary([
            rec("A01", "ok"), rec("A02", "prefix"), rec("A03", "mismatch", dropped=2, errors=["e"]),
            rec("A15", None, skipped="only"), rec("A04", "ok", timeout=True), rec("A05", "ok", exit_code=3),
        ])
        self.assertEqual((s["runs"], s["skipped"]), (5, 1))
        self.assertEqual(s["status"], {"mismatch": 1, "ok": 3, "prefix": 1})
        self.assertEqual((s["tcpdump_dropped_runs"], s["runner_error_runs"]), (1, 1))
        self.assertEqual((s["driver_timeout_runs"], s["driver_nonzero_exit_runs"]), (1, 1))
        self.assertEqual((s["conns_compared"], s["fields_compared"], s["fields_mismatched"]), (10, 15, 1))
        self.assertEqual([(n["case"], n["status"]) for n in s["not_ok"]], [("A03", "mismatch")])

    def test_main_writes_both_files_deterministically(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "raw"))
            os.makedirs(os.path.join(tmp, "versions.d"))
            with gzip.open(os.path.join(tmp, "raw", "curl.jsonl.gz"), "wt", encoding="utf-8") as fh:
                fh.write(json.dumps(rec("A01", "ok")) + "\n")
            with open(os.path.join(tmp, "versions.d", "curl.json"), "w", encoding="utf-8") as fh:
                json.dump({"versions": {"curl": "8"}}, fh)
            self.assertEqual(collect.main(["--out", tmp]), 0)
            first = [open(os.path.join(tmp, n), "rb").read() for n in ("pcap_check.json", "versions.json")]
            self.assertEqual(collect.main(["--out", tmp]), 0)
            second = [open(os.path.join(tmp, n), "rb").read() for n in ("pcap_check.json", "versions.json")]
            self.assertEqual(first, second)
            pc = json.loads(first[0])
            self.assertEqual(pc["total"], {"runs": 1, "skipped": 0, "status": {"ok": 1}})
            self.assertEqual(json.loads(first[1])["variants"]["curl"]["versions"], {"curl": "8"})

    def test_main_without_raw_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(collect.main(["--out", tmp]), 2)


if __name__ == "__main__":
    unittest.main()
