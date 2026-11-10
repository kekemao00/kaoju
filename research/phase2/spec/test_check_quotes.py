#!/usr/bin/env python3
"""check_quotes.py 的单元测试。

用两篇假的 RFC（一篇不分页的新格式，一篇带分页的旧格式）和对应的条款，
覆盖“全部通过”和每一种问题、每一种提示。假 RFC 的文字是自己编的，不是任何 RFC 的原文。

    python3 -m unittest discover -s research/phase2/spec -p 'test_*.py'

设了 KAOJU_RFC_DIR 时多跑一组：对着真的 RFC 文本核对章节解析和登记的哈希。
"""
import contextlib
import copy
import hashlib
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_quotes as cq  # noqa: E402

# ---- 假的新格式 RFC：有 BOM、缩进的目录、多级章节、旁注、表格、附录、文末的无编号标题 ----

NEW_RFC = chr(0xFEFF) + """


Internet Engineering Task Force (IETF)                         A. Tester
Request for Comments: 9901                                       Example
Category: Standards Track                                      June 2022
ISSN: 2070-1721


                        Test Protocol Semantics

Abstract

   This document is a made-up specification used to test the checker.

Table of Contents

   1.  Introduction
   2.  Proxies
     2.1.  Forwarding
       2.1.1.  Loops
     2.2.  Tunnels
   3.  Security Considerations
   Appendix A.  Collected Notes
     A.1.  First Note
   Acknowledgements
   Authors' Addresses

1.  Introduction

   This protocol lets a client ask a proxy to relay a request.  A proxy
   that relays a request is called a forwarder.

   The forwarding modes are named as follows

   Direct mode relays bytes unchanged.

2.  Proxies

   A proxy MUST NOT forward a request to itself.  A proxy SHOULD log
   every request that it refuses.

2.1.  Forwarding

   A proxy MUST forward the request target unchanged.  A proxy MAY add
   a Via field, and it SHOULD NOT remove one that is already present.

      |  *Note:* A proxy that rewrites the target is not a forwarder
      |  in the sense of this document.

   The following table lists the forwarding modes:

   +======+=============+
   | Mode | Description |
   +======+=============+
   | 1    | direct      |
   +------+-------------+

                               Table 1

2.1.1.  Loops

   A proxy MUST detect a loop before it forwards a request.  Support
   for loop detection across protocol versions is OPTIONAL.

2.2.  Tunnels

   A tunnel is REQUIRED to relay bytes in both directions.  It is
   RECOMMENDED that a tunnel be closed when either side closes.  Closing
   a tunnel early is NOT RECOMMENDED.

   *  A client MUST send the port number.

   *  A server must answer within a reasonable time

3.  Security Considerations

   A proxy MUST NOT forward a request to itself.  This repeats the rule
   given earlier.

Appendix A.  Collected Notes

A.1.  First Note

   Forwarders are described in the section on proxies.

Acknowledgements

   Thanks to everyone who helped.

Authors' Addresses

   A. Tester
   Example
"""

# ---- 假的旧格式 RFC：分页（页脚、换页符、页眉），句子跨页，行尾连字符，没有编号的小标题 ----

OLD_RFC = """





Network Working Group                                          A. Tester
Request for Comments: 9902                                       Example
Category: Standards Track                                     March 1996


                          Test Relay Protocol

Status of this Memo

   This memo is a made-up specification used to test the checker.

1.  Introduction

   The relay protocol has a client and a server.  Unless otherwise
   noted, the decimal numbers appearing in packet-
   format diagrams represent the length of the corresponding field.

2.  Negotiation

   The client connects to the server and sends a greeting.  If the
   connection request succeeds, the client enters a negotiation for the



Tester                      Standards Track                     [Page 1]
\f
RFC 9902                  Test Relay Protocol                 March 1996


   authentication method to be used.  The server selects one method.

   The values currently defined for METHOD are:

          o  X'00' NO AUTHENTICATION REQUIRED
          o  X'02' USERNAME/PASSWORD
          o  X'FF' NO ACCEPTABLE METHODS

   If the selected METHOD is X'FF', the client MUST close the
   connection.

Note:

   Where a given octet must take on a specific value, the syntax X'hh'
   is used.

3.  Replies

   The server evaluates the request and returns a reply.

CONNECT

   In the reply to a CONNECT, BND.PORT contains the port number that
   the server assigned.  The server MAY close the connection after



Tester                      Standards Track                     [Page 2]
\f
RFC 9902                  Test Relay Protocol                 March 1996


   sending a failure reply.

4.  Security Considerations

   This memo does not discuss security.  The reply has this layout:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+



Tester                      Standards Track                     [Page 3]
\f
RFC 9902                  Test Relay Protocol                 March 1996


   A STATUS field of X'00' indicates success.

Author's Address

   A. Tester



Tester                      Standards Track                     [Page 4]
\f
"""


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clause(cid, title, quote, level, **kw):
    rfc, section, _ = cid.split("-")
    c = {"id": cid, "section": section, "section_title": title, "quote": quote, "level": level,
         "binds": "proxy", "side": "入口", "topic": "connect", "gateway": "测试用", "rows": []}
    c.update(kw)
    return c


def new_file():
    """新格式那篇的一组全部合格的条款，九种 level 各有一条。"""
    return {"rfc": 9901, "title": "Test Protocol Semantics", "text_sha256": sha(NEW_RFC), "clauses": [
        clause("9901-1-1", "Introduction", "A proxy that relays a request is called a forwarder.", "statement"),
        clause("9901-2-1", "Proxies", "A proxy MUST NOT forward a request to itself.", "MUST NOT", rows=["R01", "R03"]),
        clause("9901-2-2", "Proxies", "A proxy SHOULD log every request that it refuses.", "SHOULD"),
        clause("9901-2.1-1", "Forwarding", "A proxy MUST forward the request target unchanged.", "MUST"),
        clause("9901-2.1-2", "Forwarding",
               "A proxy MAY add a Via field, and it SHOULD NOT remove one that is already present.", "SHOULD NOT"),
        clause("9901-2.1-3", "Forwarding",
               "A proxy MAY add a Via field, and it SHOULD NOT remove one that is already present.", "MAY"),
        clause("9901-2.1.1-1", "Loops", "Support for loop detection across protocol versions is OPTIONAL.", "OPTIONAL"),
        clause("9901-2.2-1", "Tunnels", "A tunnel is REQUIRED to relay bytes in both directions.", "REQUIRED"),
        clause("9901-2.2-2", "Tunnels",
               "It is RECOMMENDED that a tunnel be closed when either side closes.", "RECOMMENDED"),
        clause("9901-2.2-3", "Tunnels", "A client MUST send the port number.", "MUST", binds="client", side="客户端"),
        clause("9901-A.1-1", "First Note", "Forwarders are described in the section on proxies.", "statement"),
    ]}


def old_file():
    """旧格式那篇的一组全部合格的条款。"""
    return {"rfc": 9902, "title": "Test Relay Protocol", "text_sha256": sha(OLD_RFC), "clauses": [
        # 行尾的连字符不做处理：折叠以后是“packet- format”
        clause("9902-1-1", "Introduction",
               "Unless otherwise noted, the decimal numbers appearing in packet- format diagrams "
               "represent the length of the corresponding field.", "statement", topic="socks-request"),
        # 这一句跨页
        clause("9902-2-1", "Negotiation",
               "If the connection request succeeds, the client enters a negotiation for the "
               "authentication method to be used.", "statement", topic="socks-negotiation"),
        # 方法名里的 REQUIRED 不是规范性关键词
        clause("9902-2-2", "Negotiation", "X'00' NO AUTHENTICATION REQUIRED", "statement", topic="socks-negotiation"),
        clause("9902-2-3", "Negotiation",
               "If the selected METHOD is X'FF', the client MUST close the connection.", "MUST",
               binds="client", side="客户端", topic="socks-negotiation", rows=["R02"]),
        # 小写的 must 不算关键词；“Note:”没有编号，算在第 2 节里
        clause("9902-2-4", "Negotiation",
               "Where a given octet must take on a specific value, the syntax X'hh' is used.", "statement",
               topic="socks-negotiation"),
        # 没有编号的小标题 CONNECT 算在第 3 节里；这一句也跨页
        clause("9902-3-1", "Replies", "The server MAY close the connection after sending a failure reply.", "MAY",
               binds="server", topic="socks-reply"),
        # 上一页以图结尾，这一句是下一页的第一段
        clause("9902-4-1", "Security Considerations", "A STATUS field of X'00' indicates success.", "statement",
               binds="server", topic="socks-auth"),
    ]}


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.rfc_dir = self.root / "rfc"
        self.clauses_dir = self.root / "clauses"
        self.rfc_dir.mkdir()
        self.clauses_dir.mkdir()
        (self.rfc_dir / "rfc9901.txt").write_text(NEW_RFC, encoding="utf-8")
        (self.rfc_dir / "rfc9902.txt").write_text(OLD_RFC, encoding="utf-8")
        self.rows = self.root / "rows.json"
        self.rows.write_text(json.dumps({"rows": [{"id": "R01"}, {"id": "R02"}, {"id": "R03"}]}), encoding="utf-8")
        self.registry = self.root / "rfc_sha256.txt"
        self.registry.write_text(f"{sha(NEW_RFC)}  rfc9901.txt\n{sha(OLD_RFC)}  rfc9902.txt\n", encoding="utf-8")
        self.new = new_file()
        self.old = old_file()

    def write(self, name, data):
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=1)
        (self.clauses_dir / name).write_text(text, encoding="utf-8")

    def check(self, registry=True):
        """把 self.new、self.old 写成条款文件再核对。"""
        if self.new is not None:
            self.write("rfc9901.json", self.new)
        if self.old is not None:
            self.write("rfc9902.json", self.old)
        return cq.check(self.clauses_dir, self.rfc_dir, self.rows, self.registry if registry else None)

    def by_id(self, data, cid):
        return next(c for c in data["clauses"] if c["id"] == cid)

    def assertProblems(self, result, *codes):
        """问题的代号正好是 codes（顺序不论），一个不多一个不少。"""
        got = sorted(p["code"] for p in result["problems"])
        self.assertEqual(got, sorted(codes), json.dumps(result["problems"], ensure_ascii=False, indent=1))
        self.assertEqual(result["ok"], not codes)

    def assertNotes(self, result, *codes):
        got = sorted(p["code"] for p in result["notes"])
        self.assertEqual(got, sorted(codes), json.dumps(result["notes"], ensure_ascii=False, indent=1))


class TestPass(Case):
    def test_all_valid(self):
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r)
        self.assertEqual(r["total_clauses"], 18)
        self.assertEqual([(f["file"], f["rfc"], f["clauses"], f["problems"], f["notes"]) for f in r["files"]],
                         [("rfc9901.json", 9901, 11, 0, 0), ("rfc9902.json", 9902, 7, 0, 0)])
        self.assertEqual(r["registered_without_clauses"], [])

    def test_every_level_is_exercised(self):
        used = {c["level"] for f in (self.new, self.old) for c in f["clauses"]}
        self.assertEqual(used, set(cq.LEVELS))

    def test_only_some_files_present(self):
        self.old = None
        r = self.check()
        self.assertProblems(r)
        self.assertEqual(r["registered_without_clauses"], [9902])

    def test_empty_clause_list(self):
        self.new["clauses"] = []
        r = self.check()
        self.assertProblems(r)
        self.assertEqual(r["files"][0]["clauses"], 0)


class TestQuote(Case):
    def test_reworded(self):
        self.by_id(self.new, "9901-2.1-1")["quote"] = "A proxy MUST forward the request target without changes."
        r = self.check()
        self.assertProblems(r, "quote-not-found")
        msg = r["problems"][0]["message"]
        self.assertIn("开头 7 个词", msg)          # 说得出从哪儿开始对不上
        self.assertIn("§2.1（Forwarding）", msg)
        self.assertIn("unchanged.", msg)

    def test_ellipsis(self):
        self.by_id(self.new, "9901-2.1-2")["quote"] = "A proxy MAY add a Via field ... SHOULD NOT remove one that is already present."
        self.assertProblems(self.check(), "quote-not-found")

    def test_case_matters(self):
        self.by_id(self.new, "9901-2.1-1")["quote"] = "a proxy MUST forward the request target unchanged."
        self.assertProblems(self.check(), "quote-not-found")

    def test_whitespace_is_folded_on_both_sides(self):
        self.by_id(self.new, "9901-2.1-1")["quote"] = " A proxy MUST forward\n   the request  target unchanged.\n"
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r, "quote-whitespace")

    def test_line_end_hyphen_is_not_joined(self):
        q = self.by_id(self.old, "9902-1-1")
        self.assertIn("packet- format", q["quote"])
        q["quote"] = q["quote"].replace("packet- format", "packet-format")
        self.assertProblems(self.check(), "quote-not-found")

    def test_page_footer_and_header_are_not_text(self):
        # 页脚、页眉去掉以后不在文本里；夹着它们的引文对不上
        self.by_id(self.old, "9902-2-1")["quote"] = (
            "the client enters a negotiation for the Tester Standards Track [Page 1] "
            "RFC 9902 Test Relay Protocol March 1996 authentication method to be used.")
        self.assertProblems(self.check(), "quote-not-found")

    def test_aside_bar_optional(self):
        # 旁注：不带竖线的引文和照文本原样带竖线的引文都认
        c = self.by_id(self.new, "9901-2.1-1")
        c["level"] = "statement"
        c["quote"] = "*Note:* A proxy that rewrites the target is not a forwarder in the sense of this document."
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r)
        c["quote"] = "*Note:* A proxy that rewrites the target is not a forwarder | in the sense of this document."
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r)

    def test_table_rows_keep_their_bars(self):
        c = self.by_id(self.new, "9901-2.1-1")
        c["level"] = "statement"
        c["quote"] = "| 1 | direct |"
        self.assertProblems(self.check())
        c["quote"] = "1 | direct"
        self.assertProblems(self.check())
        c["quote"] = "1 direct"
        self.assertProblems(self.check(), "quote-not-found")

    def test_empty_quote(self):
        self.by_id(self.new, "9901-2.1-1")["quote"] = "  "
        self.assertProblems(self.check(), "field")


class TestSection(Case):
    def test_wrong_section(self):
        c = self.by_id(self.new, "9901-2.2-1")       # 引文在 2.2，声明成 2.1
        c["id"], c["section"], c["section_title"] = "9901-2.1-9", "2.1", "Forwarding"
        r = self.check()
        self.assertProblems(r, "section-mismatch")
        self.assertIn("§2.2（Tunnels）", r["problems"][0]["message"])

    def test_child_declared_but_quote_in_parent(self):
        c = self.by_id(self.new, "9901-2.1-1")       # 引文在 2.1 的正文里，声明成 2.1.1
        c["id"], c["section"], c["section_title"] = "9901-2.1.1-9", "2.1.1", "Loops"
        self.assertProblems(self.check(), "section-mismatch")

    def test_parent_section_is_accepted_with_note(self):
        # 章节的范围到下一个同级或更高级的标题为止，所以 2.1 包含 2.1.1，2 包含 2.1.1
        c = self.by_id(self.new, "9901-2.1.1-1")
        c["id"], c["section"], c["section_title"] = "9901-2.1-9", "2.1", "Forwarding"
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r, "section-deeper")
        self.assertIn("§2.1.1（Loops）", r["notes"][0]["message"])
        c["id"], c["section"], c["section_title"] = "9901-2-9", "2", "Proxies"
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r, "section-deeper")

    def test_section_ends_at_next_sibling(self):
        c = self.by_id(self.new, "9901-2.2-1")       # 2.2 不在 2.1 里，但在 2 里
        c["id"], c["section"], c["section_title"] = "9901-2-9", "2", "Proxies"
        self.assertProblems(self.check())
        c["id"], c["section"], c["section_title"] = "9901-1-9", "1", "Introduction"
        self.assertProblems(self.check(), "section-mismatch")

    def test_same_sentence_in_two_sections(self):
        # “A proxy MUST NOT forward a request to itself.”在第 2 节和第 3 节各出现一次
        c = self.by_id(self.new, "9901-2-1")
        c["id"], c["section"], c["section_title"] = "9901-3-1", "3", "Security Considerations"
        self.assertProblems(self.check())
        c["id"], c["section"], c["section_title"] = "9901-1-9", "1", "Introduction"
        r = self.check()
        self.assertProblems(r, "section-mismatch")
        self.assertIn("§2（Proxies）、§3（Security Considerations）", r["problems"][0]["message"])

    def test_quote_may_not_run_past_the_section_end(self):
        c = self.by_id(self.new, "9901-2-1")
        c["id"], c["section"], c["section_title"] = "9901-3-1", "3", "Security Considerations"
        c["quote"] = ("A proxy MUST NOT forward a request to itself. This repeats the rule given earlier. "
                      "Appendix A. Collected Notes A.1. First Note Forwarders are described in the section on proxies.")
        r = self.check()
        self.assertProblems(r, "section-mismatch")
        self.assertIn("越过了这一节的结尾", r["problems"][0]["message"])

    def test_unknown_section(self):
        c = self.by_id(self.new, "9901-2.1-1")
        c["id"], c["section"] = "9901-2.9-1", "2.9"
        r = self.check()
        self.assertProblems(r, "section-unknown")
        self.assertIn("§2.1（Forwarding）", r["problems"][0]["message"])   # 顺带说出引文实际在哪儿

    def test_section_title(self):
        self.by_id(self.new, "9901-2.1-1")["section_title"] = "Forwarding Requests"
        r = self.check()
        self.assertProblems(r, "section-title")
        self.assertIn("“Forwarding”", r["problems"][0]["message"])

    def test_malformed_section(self):
        c = self.by_id(self.new, "9901-2.1-1")
        c["section"] = "§2.1"
        self.assertProblems(self.check(), "field")   # id 与 section 的比较、章节核对都跳过，只报一次

    def test_back_matter_is_not_part_of_last_appendix(self):
        c = self.by_id(self.new, "9901-A.1-1")
        c["quote"] = "Thanks to everyone who helped."
        r = self.check()
        self.assertProblems(r, "section-mismatch")
        self.assertIn("“Acknowledgements”", r["problems"][0]["message"])

    def test_appendix_top_level(self):
        c = self.by_id(self.new, "9901-A.1-1")       # “Appendix A.”的章节号是 A，包含 A.1
        c["id"], c["section"], c["section_title"] = "9901-A-1", "A", "Collected Notes"
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r, "section-deeper")

    def test_unnumbered_subheading_stays_in_enclosing_section(self):
        doc = cq.RfcText(OLD_RFC, 9902).plain
        self.assertEqual([(h.number, h.title) for h in doc.headings],
                         [(None, "Status of this Memo"), ("1", "Introduction"), ("2", "Negotiation"),
                          ("3", "Replies"), ("4", "Security Considerations"), (None, "Author's Address")])
        start, end = doc.span("3")
        self.assertTrue(doc.text[start:end].startswith("3. Replies The server evaluates"))
        self.assertTrue(doc.text[start:end].endswith("CONNECT, BND.PORT contains the port number that the server assigned. "
                                                     "The server MAY close the connection after sending a failure reply. "))
        start, end = doc.span("4")                  # 第 4 节跨页，到没有编号的 Author's Address 为止
        self.assertTrue(doc.text[start:end].endswith("+----+--------+ A STATUS field of X'00' indicates success. "))

    def test_what_counts_as_a_heading(self):
        # 标题要顶格、前面是空行；缩进的行、夹在段落里的顶格行都不是
        def numbers(lines):
            return [h.number or h.title for h in cq.Folded(lines).headings]
        self.assertEqual(numbers(["1.  One", "", "   text.", "", "2.  Two", "", "   text."]), ["1", "2"])
        self.assertEqual(numbers(["1.  One", "", "   text.", "", "   2.  Indented", "", "   Index", "", "   text."]), ["1"])
        self.assertEqual(numbers(["1.  One", "", "   see item", "2.  of the list", "", "   text."]), ["1"])
        self.assertEqual(numbers(["1.  One", "", "Index", "", "   text.", "", "Note:", "", "   text."]), ["1", "Index"])
        self.assertEqual(numbers(["1  No dot", "", "1.1  Sub", "", "Appendix A.  App", "", "A.1.  Sub", "", "A.  Not this"]),
                         ["1", "1.1", "A", "A.1"])
        doc = cq.Folded(["1.  One", "", "   a.", "", "1.  Again", "", "   b."])
        self.assertEqual(doc.duplicates, ["1"])

    def test_toc_lines_are_not_headings(self):
        doc = cq.RfcText(NEW_RFC, 9901).plain
        self.assertEqual([h.number or h.title for h in doc.headings],
                         ["Abstract", "Table of Contents", "1", "2", "2.1", "2.1.1", "2.2", "3", "A", "A.1",
                          "Acknowledgements", "Authors' Addresses"])
        start, _ = doc.span("1")
        self.assertTrue(doc.text[start:].startswith("1. Introduction This protocol lets"))
        self.assertEqual(doc.doc_title(), "Test Protocol Semantics")


class TestPagination(unittest.TestCase):
    def test_old_format_is_depaginated(self):
        text = cq.strip_pagination(OLD_RFC, 9902)
        self.assertNotIn("\f", text)
        self.assertNotIn("[Page", text)
        self.assertNotIn("RFC 9902", text)
        self.assertIn("negotiation for the authentication method to be used.", cq.fold(text))
        self.assertIn("Request for Comments: 9902", text)     # 文件头不是页眉，留着
        self.assertFalse(cq.RfcText(NEW_RFC, 9901).paginated)
        self.assertTrue(cq.RfcText(OLD_RFC, 9902).paginated)

    def test_new_format_is_left_alone(self):
        # 没有换页符就什么都不去掉，即使某一行长得像页脚或页眉
        text = "1.  Title\n\nTester      Standards Track      [Page 1]\nRFC 9901      Something      June 2022\n"
        self.assertEqual(cq.strip_pagination(text, 9901), text)

    def test_only_this_rfcs_header_is_removed(self):
        page = "   one\n\nTester      Standards Track      [Page 1]\n\f\nRFC 1234      Other Memo      March 1996\n\n   two\n"
        self.assertIn("RFC 1234", cq.strip_pagination(page, 9902))
        self.assertNotIn("RFC 1234", cq.strip_pagination(page, 1234))
        self.assertNotIn("[Page 1]", cq.strip_pagination(page, 9902))

    def test_aside_bar(self):
        self.assertEqual(cq.strip_aside("      |  *Note:* A proxy that rewrites"), "         *Note:* A proxy that rewrites")
        self.assertEqual(cq.strip_aside("      |"), "")
        self.assertEqual(cq.strip_aside("      |  "), "")
        for line in ("   | Mode | Description |", "   |  centred  |  cells  |", "   |      | continued   |",
                     "   +------+-------------+", "   text | with a bar", "|  at column zero", "   |one space"):
            self.assertEqual(cq.strip_aside(line), line)

    def test_indented_page_marker_is_text(self):
        page = "   see the note on\n   Standards Track      [Page 1]\n\f\n   more\n"
        self.assertIn("[Page 1]", cq.strip_pagination(page, 9902))


class TestLevel(Case):
    def set_level(self, cid, level):
        data = self.new if cid.startswith("9901") else self.old
        self.by_id(data, cid)["level"] = level

    def test_must_but_only_must_not(self):
        self.set_level("9901-2-1", "MUST")
        r = self.check()
        self.assertProblems(r, "level")
        self.assertIn("MUST NOT", r["problems"][0]["message"])

    def test_must_not_but_only_must(self):
        self.set_level("9901-2.1-1", "MUST NOT")
        self.assertProblems(self.check(), "level")

    def test_should_but_only_should_not(self):
        c = self.by_id(self.new, "9901-2.1-2")
        c["quote"] = "A proxy MAY add a Via field, and it SHOULD NOT remove one that is already present."
        c["level"] = "SHOULD"
        self.assertProblems(self.check(), "level")

    def test_should_not_but_only_should(self):
        self.set_level("9901-2-2", "SHOULD NOT")
        self.assertProblems(self.check(), "level")

    def test_recommended_is_not_not_recommended(self):
        c = self.by_id(self.new, "9901-2.2-2")
        c["quote"] = "Closing a tunnel early is NOT RECOMMENDED."
        self.assertProblems(self.check(), "level")

    def test_wrong_keyword(self):
        for cid, level in (("9901-2.1-1", "MAY"), ("9901-2.2-1", "OPTIONAL"), ("9901-2.2-2", "REQUIRED"),
                           ("9901-2.1.1-1", "RECOMMENDED"), ("9901-2.2-3", "SHOULD")):
            with self.subTest(cid=cid, level=level):
                self.new = new_file()
                self.set_level(cid, level)
                self.assertProblems(self.check(), "level")

    def test_statement_with_keyword(self):
        self.set_level("9901-2.1-1", "statement")
        r = self.check()
        self.assertProblems(r, "level")
        self.assertIn("MUST", r["problems"][0]["message"])

    def test_keyword_missing_entirely(self):
        self.set_level("9901-1-1", "MUST")
        self.assertProblems(self.check(), "level")

    def test_lowercase_must_is_not_a_keyword(self):
        self.set_level("9902-2-4", "MUST")
        self.assertProblems(self.check(), "level")

    def test_old_format_uses_the_same_rule(self):
        self.set_level("9902-2-3", "statement")
        self.assertProblems(self.check(), "level")
        self.old = old_file()
        self.set_level("9902-3-1", "MUST")
        self.assertProblems(self.check(), "level")

    def test_method_name_is_not_a_keyword(self):
        self.set_level("9902-2-2", "REQUIRED")      # “NO AUTHENTICATION REQUIRED”是方法名
        self.assertProblems(self.check(), "level")

    def test_keywords_in(self):
        self.assertEqual(cq.keywords_in("A MUST and a MUST NOT, then MUST again"), ["MUST", "MUST NOT"])
        self.assertEqual(cq.keywords_in("it MUST\n   NOT do that"), ["MUST NOT"])
        self.assertEqual(cq.keywords_in("it MUST NOTIFY the peer"), ["MUST"])
        self.assertEqual(cq.keywords_in("is NOT RECOMMENDED"), ["NOT RECOMMENDED"])
        self.assertEqual(cq.keywords_in("SHALL, SHALL NOT, SHOULD, SHOULD NOT"), ["SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT"])
        self.assertEqual(cq.keywords_in("REQUIRED RECOMMENDED MAY OPTIONAL"), ["REQUIRED", "RECOMMENDED", "MAY", "OPTIONAL"])
        self.assertEqual(cq.keywords_in("the HTTP_1_1_REQUIRED error, in May, a must, Should, MUSTARD"), [])
        self.assertEqual(cq.keywords_in("o X'00' NO AUTHENTICATION REQUIRED"), [])
        self.assertEqual(cq.keywords_in("NO AUTHENTICATION REQUIRED, but a realm is REQUIRED"), ["REQUIRED"])
        self.assertEqual(cq.keywords_in('the key word "MUST"'), ["MUST"])


class TestId(Case):
    def test_format(self):
        for bad in ("9901_2.1_1", "9901-2.1", "9901-2.1-0", "9901-2.1.-1", "rfc9901-2.1-1", "9901-2.1-01", "9901-a.1-1"):
            with self.subTest(bad=bad):
                self.new = new_file()
                self.by_id(self.new, "9901-2.1-1")["id"] = bad
                self.assertProblems(self.check(), "id-format")

    def test_rfc_number(self):
        self.by_id(self.new, "9901-2.1-1")["id"] = "9902-2.1-1"
        self.assertProblems(self.check(), "id-rfc")

    def test_section_number(self):
        self.by_id(self.new, "9901-2.1-1")["id"] = "9901-2.2-9"
        self.assertProblems(self.check(), "id-section")

    def test_duplicate(self):
        self.new["clauses"].append(copy.deepcopy(self.by_id(self.new, "9901-2.1-1")))
        r = self.check()
        self.assertProblems(r, "id-duplicate")
        self.assertEqual(r["problems"][0]["id"], "9901-2.1-1")

    def test_missing_id_is_reported_by_position(self):
        del self.new["clauses"][3]["id"]
        r = self.check()
        self.assertProblems(r, "field")
        self.assertEqual(r["problems"][0]["id"], "第 4 条")


class TestFields(Case):
    def test_enums(self):
        for key in ("level", "binds", "side", "topic"):
            with self.subTest(key=key):
                self.new = new_file()
                self.by_id(self.new, "9901-2.1-1")[key] = "别的"
                r = self.check()
                self.assertProblems(r, "enum")
                self.assertIn(key, r["problems"][0]["message"])

    def test_enum_values_are_exact(self):
        for key, value in (("level", "must"), ("level", "Statement"), ("binds", "origin"), ("side", "入口侧"),
                           ("topic", "auth")):
            with self.subTest(key=key, value=value):
                self.new = new_file()
                self.by_id(self.new, "9901-2.1-1")[key] = value
                self.assertProblems(self.check(), "enum")

    def test_all_declared_values_are_accepted(self):
        c = self.by_id(self.new, "9901-1-1")
        for key, allowed in (("binds", cq.BINDS), ("side", cq.SIDES), ("topic", cq.TOPICS)):
            for value in allowed:
                c[key] = value
                self.assertProblems(self.check())

    def test_rows(self):
        c = self.by_id(self.new, "9901-2.1-1")
        c["rows"] = ["R01", "R99"]
        r = self.check()
        self.assertProblems(r, "rows")
        self.assertIn("R99", r["problems"][0]["message"])
        self.assertNotIn("R01", r["problems"][0]["message"])
        c["rows"] = "R01"
        self.assertProblems(self.check(), "rows")
        c["rows"] = [1]
        self.assertProblems(self.check(), "rows")
        c["rows"] = ["R01", "R01"]
        self.assertProblems(self.check(), "rows")
        c["rows"] = None
        self.assertProblems(self.check(), "rows")

    def test_missing_field(self):
        for key in cq.CLAUSE_FIELDS:
            if key == "id":
                continue
            with self.subTest(key=key):
                self.new = new_file()
                del self.by_id(self.new, "9901-2.1-1")[key]
                r = self.check()
                self.assertProblems(r, "field")
                self.assertIn(key, r["problems"][0]["message"])

    def test_wrong_type_and_empty(self):
        c = self.by_id(self.new, "9901-2.1-1")
        c["gateway"] = ""
        self.assertProblems(self.check(), "field")
        c["gateway"] = ["背景"]
        self.assertProblems(self.check(), "field")
        self.new = new_file()
        self.new["clauses"][0] = "不是对象"
        self.assertProblems(self.check(), "field")

    def test_unknown_field_is_a_note(self):
        self.by_id(self.new, "9901-2.1-1")["comment"] = "多出来的"
        r = self.check()
        self.assertProblems(r)
        self.assertNotes(r, "unknown-field")


class TestFile(Case):
    def test_not_json(self):
        self.new = None
        self.write("rfc9901.json", "{不是 JSON")
        self.assertProblems(self.check(), "json")

    def test_top_level_not_object(self):
        self.new = None
        self.write("rfc9901.json", "[]")
        self.assertProblems(self.check(), "json")

    def test_file_name(self):
        self.write("http.json", self.new)
        self.new = None
        self.assertProblems(self.check(), "filename")      # 其余的照常核对（RFC 号取文件里的）

    def test_file_name_disagrees_with_rfc(self):
        self.new["rfc"] = 9902
        r = self.check()
        self.assertIn("filename", [p["code"] for p in r["problems"]])

    def test_top_fields(self):
        for key in cq.TOP_FIELDS:
            with self.subTest(key=key):
                self.new = new_file()
                del self.new[key]
                r = self.check()
                self.assertProblems(r, "top-field")
                self.assertIn(key, r["problems"][0]["message"])
        for key, value in (("rfc", "9901"), ("rfc", True), ("title", ""), ("text_sha256", "abc"),
                           ("text_sha256", sha(NEW_RFC).upper()), ("clauses", {})):
            with self.subTest(key=key, value=value):
                self.new = new_file()
                self.new[key] = value
                self.assertProblems(self.check(), "top-field")

    def test_title(self):
        self.new["title"] = "Test Protocol"
        r = self.check()
        self.assertProblems(r, "title")
        self.assertIn("“Test Protocol Semantics”", r["problems"][0]["message"])

    def test_sha256(self):
        self.new["text_sha256"] = "0" * 64
        self.assertProblems(self.check(), "sha256")

    def test_text_changed_after_registration(self):
        # 文本换了一份、条款文件的哈希也跟着改了，登记没改：对着登记查得出来
        changed = NEW_RFC.replace("made-up", "made up")
        (self.rfc_dir / "rfc9901.txt").write_text(changed, encoding="utf-8")
        self.new["text_sha256"] = sha(changed)
        self.assertProblems(self.check(), "registry")
        self.assertProblems(self.check(registry=False))

    def test_not_registered(self):
        self.registry.write_text(f"{sha(OLD_RFC)}  rfc9902.txt\n", encoding="utf-8")
        r = self.check()
        self.assertProblems(r, "registry")
        self.assertIn("没有登记", r["problems"][0]["message"])

    def test_text_missing(self):
        (self.rfc_dir / "rfc9901.txt").unlink()
        self.by_id(self.new, "9901-2.1-1")["level"] = "MAY"    # 不靠文本的检查照常做
        r = self.check()
        self.assertProblems(r, "text", "level")

    def test_text_not_utf8(self):
        (self.rfc_dir / "rfc9901.txt").write_bytes(b"\xff\xfe broken")
        self.new["text_sha256"] = hashlib.sha256(b"\xff\xfe broken").hexdigest()
        self.assertProblems(self.check(registry=False), "text")

    def test_cannot_run(self):
        with self.assertRaises(cq.CannotRun):
            cq.check(self.clauses_dir, self.rfc_dir, self.rows, None)            # 没有条款文件
        self.write("rfc9901.json", self.new)
        with self.assertRaises(cq.CannotRun):
            cq.check(self.clauses_dir, self.root / "nowhere", self.rows, None)   # 没有文本目录
        with self.assertRaises(cq.CannotRun):
            cq.check(self.clauses_dir, self.rfc_dir, self.root / "norows.json", None)
        with self.assertRaises(cq.CannotRun):
            cq.check(self.clauses_dir, self.rfc_dir, self.rows, self.root / "noreg.txt")
        self.registry.write_text("不是哈希\n", encoding="utf-8")
        with self.assertRaises(cq.CannotRun):
            cq.check(self.clauses_dir, self.rfc_dir, self.rows, self.registry)


class TestSentenceNote(Case):
    def quote(self, cid, text, level=None):
        data = self.new if cid.startswith("9901") else self.old
        c = self.by_id(data, cid)
        c["quote"] = text
        if level:
            c["level"] = level
        return self.check()

    def test_cut_at_the_start(self):
        r = self.quote("9901-2.1-2", "it SHOULD NOT remove one that is already present.")
        self.assertProblems(r)
        self.assertNotes(r, "sentence")
        self.assertIn("开头", r["notes"][0]["message"])
        self.assertNotIn("结尾", r["notes"][0]["message"])

    def test_cut_at_the_end(self):
        r = self.quote("9901-2.1-3", "A proxy MAY add a Via field")
        self.assertProblems(r)
        self.assertNotes(r, "sentence")
        self.assertIn("结尾", r["notes"][0]["message"])
        self.assertNotIn("开头", r["notes"][0]["message"])

    def test_cut_inside_a_word(self):
        r = self.quote("9901-2.1-1", "roxy MUST forward the request target unchanged.")
        self.assertProblems(r)
        self.assertNotes(r, "sentence")

    def test_cut_at_a_page_break(self):
        # 句子在翻页处被截断：上一页最后一行没有收尾的标点、两页缩进相同，算同一段
        r = self.quote("9902-3-1", "The server MAY close the connection after")
        self.assertProblems(r)
        self.assertNotes(r, "sentence")
        r = self.quote("9902-3-1", "sending a failure reply.", "statement")
        self.assertProblems(r)
        self.assertNotes(r, "sentence")

    def test_new_paragraph_after_a_page_break(self):
        # 上一页以图结尾（没有标点，缩进不同），下一页的第一句是新的一段，不该有提示
        r = self.check()
        self.assertEqual([n for n in r["notes"] if n["id"] == "9902-4-1"], [])
        doc = cq.RfcText(OLD_RFC, 9902).plain
        self.assertIn(doc.text.index("A STATUS field"), doc.para_starts)
        self.assertNotIn(doc.text.index("sending a failure reply."), doc.para_starts)
        self.assertNotIn(doc.text.index("authentication method to be used."), doc.para_starts)

    def test_two_whole_sentences(self):
        r = self.quote("9901-2-1", "A proxy MUST NOT forward a request to itself. A proxy SHOULD log every request that it refuses.")
        self.assertProblems(r)
        self.assertNotes(r)

    def test_list_items_and_unterminated_paragraphs(self):
        # 列表项：前面是行首的项目符号；没有句号的段落：后面是另一段的开头
        r = self.quote("9901-2.2-3", "A server must answer within a reasonable time", "statement")
        self.assertProblems(r)
        self.assertNotes(r)
        r = self.quote("9902-2-2", "X'02' USERNAME/PASSWORD")
        self.assertProblems(r)
        self.assertNotes(r)
        r = self.quote("9902-2-2", "The values currently defined for METHOD are:")
        self.assertProblems(r)
        self.assertNotes(r)
        r = self.quote("9901-1-1", "The forwarding modes are named as follows")
        self.assertProblems(r)
        self.assertNotes(r)
        r = self.quote("9901-1-1", "The forwarding modes are named")
        self.assertNotes(r, "sentence")


class TestCli(Case):
    def run_main(self, *argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        old_env = os.environ.get("KAOJU_RFC_DIR")
        try:
            if env is None:
                os.environ.pop("KAOJU_RFC_DIR", None)
            else:
                os.environ["KAOJU_RFC_DIR"] = env
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                # --rfc-dir 的默认值在解析参数时才读环境变量
                code = cq.main(["--clauses", str(self.clauses_dir), "--rows", str(self.rows),
                                "--sha256-file", str(self.registry), *argv])
        finally:
            if old_env is None:
                os.environ.pop("KAOJU_RFC_DIR", None)
            else:
                os.environ["KAOJU_RFC_DIR"] = old_env
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes_and_text(self):
        self.check()
        code, out, _ = self.run_main("--rfc-dir", str(self.rfc_dir))
        self.assertEqual(code, 0)
        self.assertIn("RFC 9901  rfc9901.json  11 条  问题 0  提示 0", out)
        self.assertIn("RFC 9902  rfc9902.json  7 条  问题 0  提示 0", out)
        self.assertIn("合计 2 个文件、18 条条款：问题 0，提示 0", out)
        self.assertTrue(out.rstrip().endswith("核对通过"))

        self.by_id(self.new, "9901-2.1-1")["quote"] = "A proxy MUST forward the request."
        self.check()
        code, out, _ = self.run_main("--rfc-dir", str(self.rfc_dir))
        self.assertEqual(code, 1)
        self.assertIn("问题 [quote-not-found] 9901-2.1-1：", out)
        self.assertIn("核对未通过", out)

    def test_json(self):
        self.by_id(self.new, "9901-2.1-1")["level"] = "MAY"
        self.check()
        code, out, _ = self.run_main("--rfc-dir", str(self.rfc_dir), "--json")
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["total_clauses"], 18)
        self.assertEqual([(p["file"], p["id"], p["code"]) for p in data["problems"]],
                         [("rfc9901.json", "9901-2.1-1", "level")])
        self.assertEqual(data["notes"], [])

    def test_rfc_dir_from_environment(self):
        self.check()
        code, _, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("KAOJU_RFC_DIR", err)
        code, _, _ = self.run_main(env=str(self.rfc_dir))
        self.assertEqual(code, 0)

    def test_cannot_run_is_exit_2(self):
        code, out, _ = self.run_main("--rfc-dir", str(self.rfc_dir), "--json")     # 还没有条款文件
        self.assertEqual(code, 2)
        self.assertIn("cannot_run", json.loads(out))

    def test_strict_turns_notes_into_failure(self):
        self.by_id(self.new, "9901-2.1-3")["quote"] = "A proxy MAY add a Via field"
        self.check()
        code, out, _ = self.run_main("--rfc-dir", str(self.rfc_dir))
        self.assertEqual(code, 0)
        self.assertIn("提示 [sentence] 9901-2.1-3：", out)
        code, out, _ = self.run_main("--rfc-dir", str(self.rfc_dir), "--strict")
        self.assertEqual(code, 1)

    def test_codes_are_documented(self):
        readme = (HERE / "README.md").read_text(encoding="utf-8")
        for code in list(cq.PROBLEM_CODES) + list(cq.NOTE_CODES):
            self.assertIn(f"`{code}`", readme, f"README.md 里没有写 {code}")


REAL_DIR = os.environ.get("KAOJU_RFC_DIR")
REGISTERED = cq.load_registry(cq.DEFAULT_REGISTRY) if cq.DEFAULT_REGISTRY.exists() else {}


@unittest.skipUnless(REAL_DIR and all((pathlib.Path(REAL_DIR) / n).exists() for n in REGISTERED) and REGISTERED,
                     "没有设 KAOJU_RFC_DIR，或那里的 RFC 文本不全")
class TestRealTexts(unittest.TestCase):
    """对着真的 RFC 文本：登记的哈希、章节解析。"""

    def test_registered_hashes(self):
        for name, digest in REGISTERED.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((pathlib.Path(REAL_DIR) / name).read_bytes()).hexdigest(), digest)

    def test_sections_match_the_table_of_contents(self):
        # 有目录的 RFC：正文里解析出的章节号与目录里列的完全相同
        for name in REGISTERED:
            number = int(name[3:-4])
            rfc, _, err = cq.load_rfc(REAL_DIR, number)
            self.assertIsNone(err)
            doc = rfc.plain
            self.assertEqual(doc.duplicates, [])
            parsed = [h.number for h in doc.headings if h.number]
            self.assertEqual(parsed, sorted(parsed, key=cq.section_key), name)
            raw = (pathlib.Path(REAL_DIR) / name).read_text(encoding="utf-8-sig")
            toc, inside = set(), False
            for line in cq.strip_pagination(raw, number).split("\n"):
                if line.strip() == "Table of Contents":
                    inside = True
                elif inside and line and not line[0].isspace():
                    break
                elif inside:
                    m = re.match(r"^\s+(?:Appendix )?((?:\d+|[A-Z])(?:\.\d+)*)\.\s+\S", line)
                    if m:
                        toc.add(m.group(1))
            if toc:
                with self.subTest(name=name):
                    self.assertEqual(set(parsed), toc)

    def test_known_headings(self):
        known = {9110: ("9.3.6", "CONNECT"), 9112: ("3.2.3", "authority-form"), 1928: ("6", "Replies"),
                 1929: ("2", "Initial negotiation")}
        for number, (section, title) in known.items():
            if f"rfc{number}.txt" not in REGISTERED:
                continue
            rfc, _, _ = cq.load_rfc(REAL_DIR, number)
            self.assertEqual(rfc.plain.heading(section).title, title)

    def test_pagination_is_gone(self):
        for name in REGISTERED:
            number = int(name[3:-4])
            rfc, _, _ = cq.load_rfc(REAL_DIR, number)
            self.assertNotIn("\f", rfc.plain.text)
            self.assertIsNone(re.search(r"\[Page \d+\]", rfc.plain.text), name)
            self.assertIsNone(re.search(rf"RFC {number} {{2,}}", rfc.plain.text))


if __name__ == "__main__":
    unittest.main()
