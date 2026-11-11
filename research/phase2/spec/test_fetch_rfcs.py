#!/usr/bin/env python3
"""fetch_rfcs.sh 的测试：不连外网。

apt 来源用现做的假 .deb（--debs），rfc-editor 来源用本机起的 HTTP 服务（KAOJU_RFC_BASE_URL）。
真的 apt-get download 和真的 rfc-editor 不在这里测。

    python3 -m unittest discover -s research/phase2/spec -p 'test_*.py'
"""
import functools
import gzip
import hashlib
import http.server
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "fetch_rfcs.sh"

TEXT_A = "假的 RFC 9901\n\n   A proxy MUST forward the request.\n"
TEXT_B = "\n\n\nfake RFC 9902\n\f\n   second page\n"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which("bash"), "没有 bash")
class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.dest = self.root / "dest"
        self.registry = self.root / "rfc_sha256.txt"
        self.registry.write_text(f"{sha(TEXT_A)}  rfc9901.txt\n{sha(TEXT_B)}  rfc9902.txt\n", encoding="utf-8")

    def run_script(self, *args, base_url=None):
        env = dict(os.environ)
        env["TMPDIR"] = str(self.root)
        env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
        # 默认指向一个连不上的地址：测试里任何没有明说的下载都立刻失败，不会真的出网
        env["KAOJU_RFC_BASE_URL"] = base_url or "http://127.0.0.1:1/rfc"
        p = subprocess.run(["bash", str(SCRIPT), "--sha256-file", str(self.registry), *args],
                           env=env, capture_output=True, text=True, timeout=120)
        return p.returncode, p.stdout + p.stderr

    def make_deb(self, package, files):
        """做一个假的 .deb。files 是 {包里的路径: 字节}。"""
        tree = self.root / f"tree-{package}"
        (tree / "DEBIAN").mkdir(parents=True)
        (tree / "DEBIAN" / "control").write_text(
            f"Package: {package}\nVersion: 1\nArchitecture: all\nMaintainer: test <test@example.invalid>\n"
            "Description: test fixture\n", encoding="utf-8")
        for rel, data in files.items():
            path = tree / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        debs = self.root / "debs"
        debs.mkdir(exist_ok=True)
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(tree), str(debs / f"{package}_1_all.deb")],
                       check=True, capture_output=True)
        return debs

    def standard_debs(self):
        # 与真的包一样：一个文件压缩过，一个没有压缩，分在两个包里
        self.make_deb("doc-rfc-std", {"usr/share/doc/RFC/standard/rfc9901.txt.gz": gzip.compress(TEXT_A.encode())})
        return self.make_deb("doc-rfc-std-proposed",
                             {"usr/share/doc/RFC/proposed-standard/rfc9902.txt": TEXT_B.encode(),
                              "usr/share/doc/RFC/proposed-standard/rfc9902.html": b"<html>"})

    def serve(self, files):
        """在 127.0.0.1 上起一个 HTTP 服务，/rfc/ 下放 files。返回地址前缀。"""
        web = self.root / "web" / "rfc"
        web.mkdir(parents=True)
        for name, text in files.items():
            (web / name).write_bytes(text.encode("utf-8"))
        handler = functools.partial(QuietHandler, directory=str(self.root / "web"))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/rfc"

    def assertFetched(self):
        self.assertEqual((self.dest / "rfc9901.txt").read_bytes(), TEXT_A.encode("utf-8"))
        self.assertEqual((self.dest / "rfc9902.txt").read_bytes(), TEXT_B.encode("utf-8"))
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()), ["rfc9901.txt", "rfc9902.txt"])
        self.assertEqual(list(self.root.glob("tmp.*")), [])        # 临时目录清理掉了


class TestUsage(Case):
    def test_no_destination(self):
        code, out = self.run_script()
        self.assertEqual(code, 2)
        self.assertIn("用法", out)

    def test_bad_arguments(self):
        self.assertEqual(self.run_script("--from", "ftp", str(self.dest))[0], 2)
        self.assertEqual(self.run_script("--frm", "apt", str(self.dest))[0], 2)
        self.assertEqual(self.run_script("--debs", str(self.root / "nowhere"), str(self.dest))[0], 2)
        self.assertEqual(self.run_script("--from", "rfc-editor", "--debs", str(self.root), str(self.dest))[0], 2)

    def test_bad_registry(self):
        self.registry.write_text("not-a-hash  rfc9901.txt\n", encoding="utf-8")
        self.assertEqual(self.run_script(str(self.dest))[0], 2)
        self.registry.write_text(f"{sha(TEXT_A)}  ../evil.txt\n", encoding="utf-8")
        self.assertEqual(self.run_script(str(self.dest))[0], 2)
        self.registry.write_text("", encoding="utf-8")
        self.assertEqual(self.run_script(str(self.dest))[0], 2)

    def test_registry_in_repo_is_well_formed(self):
        lines = (HERE / "rfc_sha256.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 8)
        for line in lines:
            self.assertRegex(line, r"^[0-9a-f]{64}  rfc\d+\.txt$")
        self.assertEqual(sorted(line.split()[1] for line in lines),
                         [f"rfc{n}.txt" for n in (1928, 1929, 6455, 7617, 9110, 9112, 9113, 9209)])


@unittest.skipUnless(shutil.which("dpkg-deb"), "没有 dpkg-deb")
class TestApt(Case):
    def test_from_debs(self):
        debs = self.standard_debs()
        code, out = self.run_script("--debs", str(debs), str(self.dest))
        self.assertEqual(code, 0, out)
        self.assertFetched()
        self.assertIn("2 个文件全部就绪", out)
        self.assertNotIn("下载", out)              # 给了 --debs、没写 --from：不碰 rfc-editor

    def test_second_run_fetches_nothing(self):
        debs = self.standard_debs()
        self.assertEqual(self.run_script("--debs", str(debs), str(self.dest))[0], 0)
        empty = self.root / "empty"
        empty.mkdir()
        code, out = self.run_script("--debs", str(empty), str(self.dest))
        self.assertEqual(code, 0, out)
        self.assertIn("不用取", out)

    def test_hash_mismatch_is_rejected(self):
        debs = self.standard_debs()
        self.registry.write_text(f"{sha(TEXT_A)}  rfc9901.txt\n{'0' * 64}  rfc9902.txt\n", encoding="utf-8")
        code, out = self.run_script("--debs", str(debs), str(self.dest))
        self.assertEqual(code, 1, out)
        self.assertIn("哈希不一致", out)
        self.assertIn(sha(TEXT_B), out)             # 报出取到的那份的哈希
        self.assertTrue((self.dest / "rfc9901.txt").exists())
        self.assertFalse((self.dest / "rfc9902.txt").exists())
        self.assertEqual((self.dest / "rfc9902.txt.rejected").read_bytes(), TEXT_B.encode("utf-8"))

    def test_stale_file_is_replaced(self):
        debs = self.standard_debs()
        self.dest.mkdir()
        (self.dest / "rfc9901.txt").write_text("旧的、不对的内容", encoding="utf-8")
        code, out = self.run_script("--debs", str(debs), str(self.dest))
        self.assertEqual(code, 0, out)
        self.assertFetched()

    def test_stale_file_that_cannot_be_refetched_fails(self):
        self.dest.mkdir()
        (self.dest / "rfc9901.txt").write_text("旧的、不对的内容", encoding="utf-8")
        (self.dest / "rfc9902.txt").write_bytes(TEXT_B.encode("utf-8"))
        empty = self.root / "empty"
        empty.mkdir()
        code, out = self.run_script("--debs", str(empty), str(self.dest))
        self.assertEqual(code, 1, out)
        self.assertIn("rfc9901.txt  目标目录里的那份哈希与登记不一致", out)

    def test_file_missing_from_packages(self):
        debs = self.make_deb("doc-rfc-std", {"usr/share/doc/RFC/standard/rfc9901.txt.gz": gzip.compress(TEXT_A.encode())})
        code, out = self.run_script("--debs", str(debs), str(self.dest))
        self.assertEqual(code, 1, out)
        self.assertIn("rfc9902.txt  没有取到", out)
        self.assertTrue((self.dest / "rfc9901.txt").exists())

    def test_similar_names_are_not_taken(self):
        # rfc99010.txt、xrfc9901.txt 不是 rfc9901.txt
        debs = self.make_deb("doc-rfc-std", {"usr/share/doc/RFC/standard/rfc99010.txt": TEXT_A.encode(),
                                             "usr/share/doc/RFC/standard/xrfc9901.txt": TEXT_A.encode(),
                                             "usr/share/doc/RFC/standard/rfc9901.txt.gz.bak": TEXT_A.encode()})
        code, out = self.run_script("--debs", str(debs), str(self.dest))
        self.assertEqual(code, 1, out)
        self.assertFalse((self.dest / "rfc9901.txt").exists())


@unittest.skipUnless(shutil.which("curl"), "没有 curl")
class TestRfcEditor(Case):
    def test_download(self):
        base = self.serve({"rfc9901.txt": TEXT_A, "rfc9902.txt": TEXT_B})
        code, out = self.run_script("--from", "rfc-editor", str(self.dest), base_url=base)
        self.assertEqual(code, 0, out)
        self.assertFetched()

    def test_hash_mismatch_is_rejected(self):
        base = self.serve({"rfc9901.txt": TEXT_A, "rfc9902.txt": TEXT_B + "被改过\n"})
        code, out = self.run_script("--from", "rfc-editor", str(self.dest), base_url=base)
        self.assertEqual(code, 1, out)
        self.assertIn("哈希不一致", out)
        self.assertFalse((self.dest / "rfc9902.txt").exists())
        self.assertTrue((self.dest / "rfc9902.txt.rejected").exists())

    def test_not_found(self):
        base = self.serve({"rfc9901.txt": TEXT_A})
        code, out = self.run_script("--from", "rfc-editor", str(self.dest), base_url=base)
        self.assertEqual(code, 1, out)
        self.assertIn("rfc9902.txt  下载失败", out)
        self.assertTrue((self.dest / "rfc9901.txt").exists())     # 取得到的照样取

    def test_unreachable(self):
        code, out = self.run_script("--from", "rfc-editor", str(self.dest))
        self.assertEqual(code, 1, out)
        self.assertIn("没有取到", out)

    @unittest.skipUnless(shutil.which("dpkg-deb"), "没有 dpkg-deb")
    def test_auto_falls_back_to_packages(self):
        debs = self.standard_debs()
        base = self.serve({"rfc9901.txt": TEXT_A})                 # 9902 下载不到，改从包里取
        code, out = self.run_script("--from", "auto", "--debs", str(debs), str(self.dest), base_url=base)
        self.assertEqual(code, 0, out)
        self.assertFetched()
        self.assertIn("改用 apt 来源", out)
        self.assertIn("rfc9901.txt  取到，哈希一致（http://127.0.0.1", out)
        self.assertIn("rfc9902.txt  取到，哈希一致（doc-rfc-std-proposed_1_all.deb）", out)

    @unittest.skipUnless(shutil.which("dpkg-deb"), "没有 dpkg-deb")
    def test_auto_falls_back_when_the_download_has_the_wrong_hash(self):
        debs = self.standard_debs()
        base = self.serve({"rfc9901.txt": TEXT_A, "rfc9902.txt": TEXT_B + "被改过\n"})
        code, out = self.run_script("--from", "auto", "--debs", str(debs), str(self.dest), base_url=base)
        self.assertEqual(code, 0, out)
        self.assertEqual((self.dest / "rfc9902.txt").read_bytes(), TEXT_B.encode("utf-8"))
        # 对不上的那一份留着，结尾提醒
        self.assertEqual((self.dest / "rfc9902.txt.rejected").read_bytes(), (TEXT_B + "被改过\n").encode("utf-8"))
        self.assertIn("哈希不一致", out)
        self.assertIn("rfc9902.txt.rejected 是某个来源给出的、与登记不一致的文本", out)


if __name__ == "__main__":
    unittest.main()
