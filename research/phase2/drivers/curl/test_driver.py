"""curl 驱动里纯函数的单元测试：python3 -m unittest discover -s research/phase2/drivers/curl -p 'test_*.py'"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import driver  # noqa: E402


def req(i, **kw):
    st = {"id": i, "op": "request", "method": "GET", "url": "http://a.kaoju.test/echo?k=X." + i, "user": None}
    st.update(kw)
    return st


CASE = {
    "proxy": {"scheme": "socks5h", "host": "127.0.0.1", "port": 1080},
    "users": [{"user": "sess@ab%41+c/d e", "pass": ""}],
    "ca_file": "/ca.pem", "timeout_s": 15,
}


class DriverTest(unittest.TestCase):
    def test_rate(self):
        self.assertEqual(driver.rate_for(3000), "20/m")
        self.assertEqual(driver.rate_for(500), "2/s")
        self.assertIsNone(driver.rate_for(7000))

    def test_plan(self):
        t, mode, info, why = driver.plan({"steps": [req("s1"), {"id": "z", "op": "sleep", "ms": 3000}, req("s2")]})
        self.assertEqual((len(t), mode, info["rate"], why), (2, "serial", "20/m", None))
        _, _, _, why = driver.plan({"steps": [req("s1"), req("s2"), {"id": "z", "op": "sleep", "ms": 3000}, req("s3")]})
        self.assertIsNotNone(why)
        t, mode, info, why = driver.plan({"steps": [{"id": "p", "op": "parallel", "steps": [req("p1"), req("p2")]}]})
        self.assertEqual((len(t), mode, info["parallel_max"], why), (2, "parallel", 2, None))
        _, _, _, why = driver.plan({"steps": [req("s1"), {"id": "p", "op": "parallel", "steps": [req("p1")]}]})
        self.assertIsNotNone(why)

    def test_argv_passes_credentials_verbatim(self):
        case = dict(CASE, steps=[req("s1", user=0, follow=True), req("s2", method="POST", body_file="/b.bin")])
        files = {i: {"body": "/o/" + i, "hdr": "/h/" + i} for i in ("s1", "s2")}
        for variant in driver.VARIANTS:
            argv, _ = driver.build_argv(case, variant, case["steps"], "serial", {}, files)
            self.assertEqual(argv[argv.index("-U") + 1], "sess@ab%41+c/d e:")
            self.assertEqual(argv[argv.index("-x") + 1], "socks5h://127.0.0.1:1080")
            self.assertEqual(argv.count("--next"), 1)
            self.assertEqual(argv.count("-U"), 1)
            self.assertEqual(argv.count("--proxy-anyauth"), 2 if variant == "curl-anyauth" else 0)
            self.assertIn("-L", argv[: argv.index("--next")])
            tail = argv[argv.index("--next"):]
            self.assertEqual(tail[tail.index("--data-binary") + 1], "@/b.bin")
            self.assertIn("Content-Type: application/octet-stream", tail)
            # 白名单：除了这些，不许出现任何别的选项（尤其是会改变代理行为或证书校验的）
            allowed = {"--no-progress-meter", "-v", "--trace-ids", "--next", "-x", "-U", "--proxy-anyauth",
                       "--cacert", "-L", "--data-binary", "-H", "--max-time", "-o", "-D", "-w"}
            used = {a for a in argv[1:] if a.startswith("-") and not a.startswith("-U:")}
            self.assertEqual(used - allowed, set())

    def test_split_stderr(self):
        steps = [req("s1"), req("s2")]
        text = "\n".join([
            "[0-0] * Connected",
            "[0-0] < HTTP/1.1 502 KaojuReasonMarker",
            "curl: (56) CONNECT tunnel failed, response 502",
            driver.MARK + " s1 " + json.dumps({"xfer_id": 0, "exitcode": 56, "http_code": 0}),
            "Note: Transfer took 1 ms, waits 2999ms as set by --rate",
            "[1-x] * looking",
            "[0-0] * late line of first transfer",
            "[1-1] > GET / HTTP/1.1",
            driver.MARK + " s2 " + json.dumps({"xfer_id": 1, "exitcode": 0, "http_code": 200}),
            "",
        ])
        per, orphans = driver.split_stderr(text, steps)
        self.assertEqual(orphans, [])
        self.assertEqual(per["s1"]["plain"], ["curl: (56) CONNECT tunnel failed, response 502"])
        self.assertEqual(per["s1"]["verbose"],
                         ["* Connected", "< HTTP/1.1 502 KaojuReasonMarker", "* late line of first transfer"])
        self.assertEqual(per["s2"]["verbose"], ["* looking", "> GET / HTTP/1.1"])
        self.assertEqual(per["s2"]["plain"], ["Note: Transfer took 1 ms, waits 2999ms as set by --rate"])
        self.assertEqual(per["s2"]["json"]["http_code"], 200)

    def test_split_without_marker_falls_back_to_order(self):
        per, orphans = driver.split_stderr("[1-0] * hung\n", [req("s1"), req("s2")])
        self.assertEqual(per["s2"]["verbose"], ["* hung"])
        self.assertIsNone(per["s2"]["json"])
        self.assertEqual(orphans, [])


if __name__ == "__main__":
    unittest.main()
