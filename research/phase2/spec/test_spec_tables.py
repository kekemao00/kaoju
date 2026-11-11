#!/usr/bin/env python3
"""spec_tables.py 的单元测试。条款用 test_check_quotes.py 里那两篇假 RFC 的。

    python3 -m unittest discover -s research/phase2/spec -p 'test_*.py'
"""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import spec_tables as st  # noqa: E402
from test_check_quotes import clause, new_file, old_file, sha, NEW_RFC, OLD_RFC  # noqa: E402


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.clauses_dir = self.root / "clauses"
        self.clauses_dir.mkdir()
        self.rows = self.root / "rows.json"
        self.rows.write_text(json.dumps({"rows": [
            {"id": "R01", "title": "第一行"}, {"id": "R02", "title": "第二行"}, {"id": "R03", "title": "带|竖线的行"}]}),
            encoding="utf-8")
        self.registry = self.root / "rfc_sha256.txt"
        self.registry.write_text(f"{sha(NEW_RFC)}  rfc9901.txt\n{sha(OLD_RFC)}  rfc9902.txt\n", encoding="utf-8")
        self.out = self.root / "out" / "spec_clauses.md"

    def write(self, name, data):
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        (self.clauses_dir / name).write_text(text, encoding="utf-8")

    def render(self):
        return st.render(st.load(self.clauses_dir), st.load_rows(self.rows), st.registered_rfcs(self.registry))

    def main(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = st.main(["--clauses", str(self.clauses_dir), "--rows", str(self.rows),
                            "--sha256-file", str(self.registry), "--out", str(self.out), *argv])
        return code, err.getvalue()

    def section(self, text, heading):
        """heading 那一节的正文（到下一个同级或更高级的标题为止）。"""
        lines = text.split("\n")
        start = lines.index(heading)
        level = len(heading) - len(heading.lstrip("#"))
        end = next((i for i in range(start + 1, len(lines))
                    if lines[i].startswith("#") and len(lines[i]) - len(lines[i].lstrip("#")) <= level), len(lines))
        return "\n".join(lines[start:end])


class TestRender(Case):
    def test_every_clause_has_a_row_and_its_quote(self):
        self.write("rfc9901.json", new_file())
        self.write("rfc9902.json", old_file())
        text = self.render()
        for f in (new_file(), old_file()):
            for c in f["clauses"]:
                sec = self.section(text, f"### {c['topic']}：{st.TOPIC_TITLES[c['topic']]}")
                rows = [line for line in sec.split("\n") if line.startswith(f"| {c['id']} |")]
                self.assertEqual(len(rows), 1, c["id"])
                cells = [x.strip() for x in rows[0].strip("|").split(" | ")]
                self.assertEqual(cells[1], f"RFC {f['rfc']} §{c['section']} {c['section_title']}")
                self.assertEqual(cells[2:6], [c["level"], c["binds"], c["side"], c["gateway"]])
                self.assertEqual(cells[6], "、".join(c["rows"]) or "—")
                # 原文在同一节的折叠块里，紧跟在条款编号后面
                self.assertIn(f"**{c['id']}**　RFC {f['rfc']} §{c['section']}\n\n> {st.esc_block(c['quote'])}\n", sec)
        self.assertEqual(text.count("<details>"), text.count("</details>"))
        self.assertEqual(text.count("<details>"), 5)       # 用到了五个主题
        self.assertNotIn("### via", text)                  # 没有条款的主题不出小节

    def test_overview_counts(self):
        self.write("rfc9901.json", new_file())
        self.write("rfc9902.json", old_file())
        over = self.section(self.render(), "## 概览")
        self.assertIn(f"| RFC 9901 | Test Protocol Semantics | 11 | `clauses/rfc9901.json` | `{sha(NEW_RFC)}` |", over)
        self.assertIn(f"| RFC 9902 | Test Relay Protocol | 7 | `clauses/rfc9902.json` | `{sha(OLD_RFC)}` |", over)
        self.assertIn("| 合计 | | 18 | | |", over)
        # 级别：MUST、MUST NOT、SHOULD、SHOULD NOT、MAY、REQUIRED、RECOMMENDED、OPTIONAL、statement、合计
        self.assertIn("| RFC 9901 | 2 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 2 | 11 |", over)
        self.assertIn("| RFC 9902 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 5 | 7 |", over)
        self.assertIn("| 合计 | 3 | 1 | 1 | 1 | 2 | 1 | 1 | 1 | 7 | 18 |", over)
        # 主题：条款数、入口、上游、两侧、客户端
        self.assertIn("| connect：CONNECT 方法 | 11 | 10 | 0 | 0 | 1 |", over)
        self.assertIn("| socks-negotiation：SOCKS5 方法协商 | 4 | 3 | 0 | 0 | 1 |", over)
        self.assertIn("| via：Via | 0 | 0 | 0 | 0 | 0 |", over)
        self.assertNotIn("还没有条款文件的 RFC", over)

    def test_reverse_index(self):
        self.write("rfc9901.json", new_file())
        self.write("rfc9902.json", old_file())
        back = self.section(self.render(), "## 按矩阵行反查")
        self.assertIn("| R01 | 第一行 | 9901-2-1 |", back)
        self.assertIn("| R02 | 第二行 | 9902-2-3 |", back)
        self.assertIn("| R03 | 带\\|竖线的行 | 9901-2-1 |", back)
        self.assertIn("行表共 3 行，3 行有条款指到。", back)

    def test_reverse_index_lists_uncovered_and_unknown_rows(self):
        f = new_file()
        f["clauses"] = [clause("9901-2.1-1", "Forwarding", "A proxy MUST forward the request target unchanged.", "MUST",
                               rows=["R02", "R77"])]
        self.write("rfc9901.json", f)
        back = self.section(self.render(), "## 按矩阵行反查")
        self.assertIn("| R02 | 第二行 | 9901-2.1-1 |", back)
        self.assertIn("| R77 | （rows.json 里没有这一行） | 9901-2.1-1 |", back)
        self.assertIn("行表共 3 行，1 行有条款指到。没有条款指到的 2 行：R01、R03。", back)

    def test_deterministic_and_independent_of_file_order(self):
        self.write("rfc9901.json", new_file())
        self.write("rfc9902.json", old_file())
        first = self.render()
        self.assertEqual(first, self.render())
        f = new_file()
        f["clauses"].reverse()
        self.write("rfc9901.json", f)
        self.assertEqual(first, self.render())
        self.assertTrue(first.endswith("\n") and not first.endswith("\n\n"))

    def test_order_within_topic(self):
        # 题目指定的四篇在前（9110、9112、1928、1929），其余按编号；章节号逐级按数字比；同一节按序号
        def one(cid, rfc):
            c = clause(cid, "T", "Q MUST.", "MUST")
            return {"rfc": rfc, "title": "T", "text_sha256": "0" * 64, "clauses": [c]}
        self.write("rfc7617.json", one("7617-2-1", 7617))
        self.write("rfc1928.json", one("1928-3-1", 1928))
        f = one("9110-9.3.6-1", 9110)
        f["clauses"] += [clause("9110-9.10-1", "T", "Q", "MUST"), clause("9110-9.3.6-10", "T", "Q", "MUST"),
                         clause("9110-9.3.6-2", "T", "Q", "MUST"), clause("9110-B.1-1", "T", "Q", "MUST"),
                         clause("9110-10-1", "T", "Q", "MUST")]
        self.write("rfc9110.json", f)
        sec = self.section(self.render(), "### connect：CONNECT 方法")
        ids = [line.split(" | ")[0][2:] for line in sec.split("\n") if line[:3] in ("| 9", "| 1", "| 7")]
        self.assertEqual(ids, ["9110-9.3.6-1", "9110-9.3.6-2", "9110-9.3.6-10", "9110-9.10-1", "9110-10-1",
                               "9110-B.1-1", "1928-3-1", "7617-2-1"])

    def test_markdown_in_quotes_is_escaped(self):
        f = new_file()
        f["clauses"] = [clause("9901-2.1-1", "The <a|b> *form*",
                               "*Note:* a [proxy] sends `x` | <y> & A_B ~z~ \\ MUST.", "MUST",
                               gateway="保留 `代码` 的写法，竖线 | 要转义"),
                        clause("9901-2.1-2", "T", "1. first MUST", "MUST"),
                        clause("9901-2.1-3", "T", "- dash MUST", "MUST")]
        self.write("rfc9901.json", f)
        text = self.render()
        self.assertIn("> \\*Note:\\* a \\[proxy\\] sends \\`x\\` \\| \\<y\\> &amp; A\\_B \\~z\\~ \\\\ MUST.\n", text)
        self.assertIn("§2.1 The \\<a\\|b\\> \\*form\\* |", text)
        self.assertIn("| 保留 `代码` 的写法，竖线 \\| 要转义 |", text)
        self.assertIn("> 1\\. first MUST\n", text)
        self.assertIn("> \\- dash MUST\n", text)
        # 表格每一行的列数不变：没有转义的竖线只有分隔列的那些
        for line in self.section(text, "### connect：CONNECT 方法").split("\n"):
            if line.startswith("| 9901"):
                self.assertEqual(line.replace("\\|", "").count("|"), 8, line)

    def test_whitespace_in_quote_is_folded(self):
        f = new_file()
        f["clauses"] = [clause("9901-2.1-1", "T", "A proxy MUST\n   forward  it.", "MUST", gateway="两\n行")]
        self.write("rfc9901.json", f)
        text = self.render()
        self.assertIn("> A proxy MUST forward it.\n", text)
        self.assertIn("| 两 行 |", text)


class TestIncomplete(Case):
    def test_no_clause_files(self):
        text = self.render()
        self.assertIn("还没有条款文件。", text)
        self.assertIn("登记了文本（`spec/rfc_sha256.txt`）、还没有条款文件的 RFC：RFC 9901、RFC 9902。", text)
        self.assertIn("还没有条款。", text)
        self.assertIn("还没有条款指到矩阵的行。", text)
        self.assertNotIn("<details>", text)

    def test_missing_clauses_directory(self):
        self.clauses_dir.rmdir()
        self.assertIn("还没有条款文件。", self.render())

    def test_some_rfcs_missing(self):
        self.write("rfc9902.json", old_file())
        text = self.render()
        self.assertIn("还没有条款文件的 RFC：RFC 9901。", text)
        self.assertIn("| 合计 | | 7 | | |", text)

    def test_file_with_no_clauses(self):
        f = new_file()
        f["clauses"] = []
        self.write("rfc9901.json", f)
        self.assertIn("| RFC 9901 | Test Protocol Semantics | 0 |", self.render())

    def test_missing_fields_do_not_crash(self):
        self.write("rfc9901.json", {"rfc": 9901, "clauses": [{"quote": "Q"}, {"id": "9901-1-1", "topic": "别的", "rows": "R01"}]})
        text = self.render()
        self.assertIn("| RFC 9901 | （缺） | 2 | `clauses/rfc9901.json` | （缺） |", text)
        sec = self.section(text, "### topic 不在允许的取值里")
        self.assertIn("| rfc9901.json 第 1 条 | RFC 9901 §（缺） （缺） | （缺） | （缺） | （缺） | （缺） | — |", sec)
        self.assertIn("| 9901-1-1 |", sec)
        self.assertIn("另有 2 条的 level 不在允许的取值里", text)

    def test_missing_rows_and_registry(self):
        self.write("rfc9901.json", new_file())
        self.rows.unlink()
        self.registry.unlink()
        text = self.render()
        self.assertIn("| R01 | （rows.json 里没有这一行） | 9901-2-1 |", text)
        self.assertNotIn("登记了文本", text)


class TestMain(Case):
    def test_write_and_check(self):
        self.write("rfc9901.json", new_file())
        code, err = self.main("--check")
        self.assertEqual(code, 1)                    # 还没有输出文件
        code, err = self.main()
        self.assertEqual(code, 0)
        self.assertIn("1 个条款文件、11 条条款", err)
        self.assertEqual(self.out.read_text(encoding="utf-8"), self.render())
        self.assertEqual(self.main("--check")[0], 0)
        self.write("rfc9902.json", old_file())       # 条款变了，旧的输出就过期了
        code, err = self.main("--check")
        self.assertEqual(code, 1)
        self.assertIn("不一致", err)

    def test_stdout(self):
        self.write("rfc9901.json", new_file())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = st.main(["--clauses", str(self.clauses_dir), "--rows", str(self.rows),
                            "--sha256-file", str(self.registry), "--out", "-"])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), self.render())
        self.assertFalse(self.out.exists())

    def test_bad_json(self):
        self.write("rfc9901.json", "{")
        code, err = self.main()
        self.assertEqual(code, 2)
        self.assertIn("rfc9901.json", err)
        self.assertFalse(self.out.exists())
        self.write("rfc9901.json", "[]")
        self.assertEqual(self.main()[0], 2)
        self.write("rfc9901.json", {"rfc": 9901, "clauses": ["x"]})
        self.assertEqual(self.main()[0], 2)

    def test_topic_titles_cover_all_topics(self):
        self.assertEqual(tuple(st.TOPIC_TITLES), st.cq.TOPICS)


if __name__ == "__main__":
    unittest.main()
