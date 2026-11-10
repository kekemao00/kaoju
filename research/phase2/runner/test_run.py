"""run.py 里纯函数的单元测试：python3 -m unittest discover -s research/phase2/runner -p 'test_*.py'"""

import gzip
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run  # noqa: E402


class RunPureTest(unittest.TestCase):
    def test_body_bytes(self):
        for n in (0, 1, 250, 251, 252, 1024, 70000):
            self.assertEqual(run.body_bytes(n), bytes((i * 131 + 7) % 251 for i in range(n)))

    def test_clean_env_inherits_nothing_else(self):
        old = dict(os.environ)
        try:
            for name in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "SSL_CERT_FILE", "CURL_CA_BUNDLE",
                         "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
                os.environ[name] = "x"
            env = run.clean_env("/h", "/w", {"EXTRA": "1"})
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertEqual(sorted(env), ["EXTRA", "HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"])
        self.assertEqual((env["HOME"], env["TMPDIR"], env["LANG"]), ("/h", "/w", "C.UTF-8"))

    def test_runtime_case(self):
        case = {
            "id": "X01", "proxy": "socks5h", "profile": {}, "users": [],
            "steps": [
                {"id": "s1", "op": "request", "method": "POST", "body_bytes": 300, "user": None,
                 "url": "https://localhost:{origin_https_port}/echo?k=X01.s1"},
                {"id": "p", "op": "parallel", "steps": [
                    {"id": "p1", "op": "request", "method": "GET", "user": None,
                     "url": "http://localhost:{origin_http_port}/echo?k=X01.p1"}]},
            ],
        }
        ports = {"proxy_port": 1001, "origin_http_port": 1002, "origin_https_port": 1003}
        with tempfile.TemporaryDirectory() as tmp:
            rc = run.runtime_case(case, "curl", ports, 15, "/ca.pem", "/home", "/drv", tmp)
            self.assertEqual(rc["proxy"], {"scheme": "socks5h", "host": "127.0.0.1", "port": 1001})
            self.assertEqual(rc["steps"][0]["url"], "https://localhost:1003/echo?k=X01.s1")
            self.assertEqual(rc["steps"][1]["steps"][0]["url"], "http://localhost:1002/echo?k=X01.p1")
            self.assertEqual(rc["steps"][0]["body_bytes"], 300)
            with open(rc["steps"][0]["body_file"], "rb") as fh:
                self.assertEqual(fh.read(), run.body_bytes(300))
            self.assertEqual((rc["variant"], rc["timeout_s"], rc["ca_file"]), ("curl", 15, "/ca.pem"))
        self.assertEqual(case["steps"][0]["url"], "https://localhost:{origin_https_port}/echo?k=X01.s1")

    def test_driver_budget(self):
        case = {"steps": [{"op": "request"}, {"op": "sleep", "ms": 3000}, {"op": "parallel", "steps": [{}, {}]}]}
        self.assertEqual(run.driver_budget(case, 15), 15 + 3 + 15 + 30)

    def test_raw_roundtrip_is_sorted_merged_and_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "raw", "x.jsonl.gz")
            recs = {("B02", 1): {"case": "B02", "repeat": 1, "v": "old"}, ("A01", 2): {"case": "A01", "repeat": 2}}
            run.write_raw(path, recs)
            with open(path, "rb") as fh:
                first = fh.read()
            merged = run.load_raw(path)
            merged.update({("B02", 1): {"case": "B02", "repeat": 1, "v": "new"}, ("A01", 1): {"case": "A01", "repeat": 1}})
            run.write_raw(path, merged)
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                rows = [json.loads(line) for line in fh]
            self.assertEqual([(r["case"], r["repeat"]) for r in rows], [("A01", 1), ("A01", 2), ("B02", 1)])
            self.assertEqual(rows[2]["v"], "new")
            run.write_raw(path, recs)
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), first)
            self.assertEqual(first[4:8], b"\x00\x00\x00\x00")  # gzip 头里的 mtime

    def test_tcpdump_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "e")
            with open(path, "w") as fh:
                fh.write("tcpdump: listening on lo\n10 packets captured\n20 packets received by filter\n"
                         "0 packets dropped by kernel\n")
            self.assertEqual(run.tcpdump_stats(path), {"captured": 10, "received": 20, "dropped": 0})

    def test_registry_and_argv(self):
        reg = run.load_registry()
        self.assertIn("curl", reg)
        self.assertIn("curl-anyauth", reg)
        argv = run.driver_argv(reg["curl"], {"ca_file": "/c", "home": "/h", "work": "/w", "repo": "/r"})
        self.assertTrue(os.path.isabs(argv[1]) and os.path.exists(argv[1]))
        self.assertEqual(run.driver_env({"env": {"A": "{ca_file}:{home}:{work}:{repo}"}},
                                        {"ca_file": "/c", "home": "/h", "work": "/w", "repo": "/r"}),
                         {"A": "/c:/h:/w:/r"})


class PcapCheckImportTest(unittest.TestCase):
    """pcap_check 由别人写；这里只验证容错导入和接口约定。"""

    def setUp(self):
        self.saved = sys.modules.pop("pcap_check", None)
        self.saved_path = list(sys.path)
        run._pc_state.update({"tried": False, "mod": None, "why": None})

    def tearDown(self):
        sys.modules.pop("pcap_check", None)
        if self.saved is not None:
            sys.modules["pcap_check"] = self.saved
        sys.path[:] = self.saved_path
        run._pc_state.update({"tried": False, "mod": None, "why": None})

    def _fake(self, check):
        import types

        mod = types.ModuleType("pcap_check")
        if check is not None:
            mod.check = check
        sys.modules["pcap_check"] = mod

    def test_passthrough(self):
        seen = []

        def check(pcap, events):
            seen.append((pcap, events))
            return {"status": "ok", "conns": [], "fields": {"compared": 0, "mismatched": []}, "problems": []}

        self._fake(check)
        self.assertEqual(run.run_pcap_check("a.pcap", "e.jsonl")["status"], "ok")
        self.assertEqual(seen, [("a.pcap", "e.jsonl")])

    def test_module_without_check_is_missing(self):
        self._fake(None)
        res = run.run_pcap_check("a.pcap", "e.jsonl")
        self.assertEqual(res["status"], "missing")
        self.assertIn("check", res["why"])

    def test_exception_and_bad_shape_are_errors(self):
        def boom(pcap, events):
            raise ValueError("x")

        self._fake(boom)
        self.assertEqual(run.run_pcap_check("a", "b")["status"], "error")
        run._pc_state.update({"tried": False, "mod": None, "why": None})
        self._fake(lambda pcap, events: ["not a dict"])
        self.assertEqual(run.run_pcap_check("a", "b")["status"], "error")


if __name__ == "__main__":
    unittest.main()
