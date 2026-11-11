#!/usr/bin/env python3
"""逐条核对 clauses/*.json：引文是不是 RFC 原文、在不在声明的章节里、级别与关键词是否一致。

用法：
    python3 check_quotes.py --rfc-dir DIR            # 或者先设好环境变量 KAOJU_RFC_DIR
    python3 check_quotes.py --rfc-dir DIR --json     # 机器可读

RFC 文本不进仓库，用 fetch_rfcs.sh 取，格式和口径见 README.md。只用 Python 标准库。

退出码：0 全部通过；1 有问题；2 没法核对（没给文本目录、读不到行表或哈希登记、一个条款文件都没有）。
“提示”不影响退出码（加 --strict 就算）：它们要么是启发式的检查，要么是不影响核对的格式毛病，留给人看。

这个脚本核对的是“引文确实是原文、确实在那一节、级别与原文的关键词对得上”，以及格式。
binds、side、topic、gateway 这些是人的解读，脚本只查取值合不合法，不判断解读对不对。
"""
import argparse
import bisect
import hashlib
import json
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_CLAUSES = HERE / "clauses"
DEFAULT_ROWS = HERE.parent / "rows.json"
DEFAULT_REGISTRY = HERE / "rfc_sha256.txt"

# ---- 条款文件里允许的取值（spec_tables.py 也从这里取，只写一处） ----

LEVELS = ("MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY",
          "REQUIRED", "RECOMMENDED", "OPTIONAL", "statement")
BINDS = ("client", "proxy", "server", "tunnel", "sender", "recipient", "intermediary", "any")
SIDES = ("入口", "上游", "两侧", "客户端")
TOPICS = ("request-target", "connect", "tunnel", "proxy-auth", "hop-by-hop", "via", "framing",
          "smuggling", "connection", "retry", "expect", "status", "socks-negotiation", "socks-auth",
          "socks-request", "socks-reply", "basic", "proxy-status", "h2", "websocket")
TOP_FIELDS = ("rfc", "title", "text_sha256", "clauses")
CLAUSE_FIELDS = ("id", "section", "section_title", "quote", "level", "binds", "side", "topic",
                 "gateway", "rows")

SECTION_PAT = r"(?:\d+|[A-Z])(?:\.\d+)*"
SECTION_RE = re.compile(rf"^{SECTION_PAT}$")
ID_RE = re.compile(rf"^(\d+)-({SECTION_PAT})-([1-9]\d*)$")
FILE_RE = re.compile(r"^rfc(\d+)\.json$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

# 规范性关键词。十一个都认（RFC 9110 的 Requirements Notation 一节列的那些），
# 条款文件的 level 只许用 LEVELS 里的；长的排在前面，“MUST NOT”才不会被当成“MUST”
KEYWORD_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(MUST NOT|SHALL NOT|SHOULD NOT|NOT RECOMMENDED|MUST|SHALL|SHOULD|REQUIRED|RECOMMENDED|MAY|OPTIONAL)"
    r"(?![A-Za-z0-9_])")

# 全大写、但不是规范性关键词的专名。目前只有一个：RFC 1928 第 3 节的认证方法名里有 REQUIRED
NOT_KEYWORDS = ("NO AUTHENTICATION REQUIRED",)

# ---- 问题和提示的代号 ----

PROBLEM_CODES = {
    "json": "条款文件不是合法的 JSON 对象",
    "filename": "文件名不是 rfcNNNN.json，或与文件里的 rfc 不一致",
    "top-field": "文件顶层缺字段或类型不对",
    "text": "找不到或读不了对应的 RFC 文本",
    "title": "title 与 RFC 文本开头写的标题不一致",
    "sha256": "text_sha256 与实际的文本文件不一致",
    "registry": "文本文件与 rfc_sha256.txt 登记的不一致，或没有登记",
    "field": "条款缺字段、类型不对或为空",
    "id-format": "id 不是“RFC 号-章节号-序号”",
    "id-rfc": "id 里的 RFC 号与文件不一致",
    "id-section": "id 里的章节号与 section 不一致",
    "id-duplicate": "id 重复",
    "enum": "level、binds、side、topic 不在允许的取值里",
    "rows": "rows 不是行号的列表、有重复，或行号不在 rows.json 里",
    "quote-not-found": "引文不是 RFC 文本的子串",
    "section-unknown": "RFC 文本里没有声明的章节",
    "section-mismatch": "引文在原文里，但不在声明的章节里",
    "section-title": "section_title 与原文的章节标题不一致",
    "level": "level 与引文里的规范性关键词不一致",
}
NOTE_CODES = {
    "unknown-field": "条款里有格式之外的字段",
    "quote-whitespace": "引文里的空白没有折成一个空格",
    "section-deeper": "引文落在声明章节的下一级小节里，可以标得更细",
    "sentence": "引文的开头或结尾看起来不在句子边界上（启发式）",
}


class CannotRun(Exception):
    """没法核对（退出码 2）。"""


def fold(s):
    """换行和连续空白折成一个空格，首尾去掉。引文和 RFC 文本用的是同一个函数。"""
    return " ".join(s.split())


def keywords_in(quote):
    """引文里出现的规范性关键词（大写、独立成词），按出现顺序去重。"""
    s = fold(quote)
    for name in NOT_KEYWORDS:
        s = s.replace(name, "#")
    out = []
    for m in KEYWORD_RE.finditer(s):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out


def section_key(number):
    """章节号的排序键：数字章节在前，附录在后，逐级比较。"""
    return tuple((1, p) if p.isalpha() else (0, int(p)) for p in number.split("."))


# ---- RFC 文本：去分页、折叠空白、解析章节 ----

FOOTER_RE = re.compile(r"^\S.*\s{2,}\[Page [0-9ivxlc]+\]\s*$")
HEADER_RE = re.compile(r"^RFC (\d+)\s{2,}\S.*\s{2,}[A-Z][a-z]+ \d{4}\s*$")


def split_pages(text, number):
    """按换页符切成页，去掉分页留下的页脚和页眉，跨页的句子才能连起来。

    只对带换页符的文本（旧格式）起作用：每页最后一个非空行如果是页脚（顶格、以 [Page N] 结尾）
    就去掉，换页符后的第一个非空行如果是这篇 RFC 的页眉（“RFC 号  标题  年月”）就去掉。
    没有换页符的新格式原样返回，只有一页。
    """
    if "\f" not in text:
        return [text]
    pages = []
    for i, page in enumerate(text.split("\f")):
        lines = page.split("\n")
        if i > 0:
            j = 0
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                m = HEADER_RE.match(lines[j])
                if m and int(m.group(1)) == number:
                    lines = lines[j + 1:]
        k = len(lines) - 1
        while k >= 0 and not lines[k].strip():
            k -= 1
        if k >= 0 and FOOTER_RE.match(lines[k]):
            lines = lines[:k]
        pages.append("\n".join(lines))
    return pages


def strip_pagination(text, number):
    """去掉页脚、换页符和页眉以后的全文，页与页之间留一个空行。"""
    return "\n\n".join(split_pages(text, number))


ASIDE_RE = re.compile(r"^(\s+)\|(?:  (\S.*))?\s*$")


def strip_aside(line):
    """新格式里的旁注每行以“|  ”开头（竖线后两个空格），去掉这个竖线。表格的行以竖线结尾，不动。"""
    m = ASIDE_RE.match(line)
    if not m:
        return line
    body = m.group(2)
    if body is None:
        return ""
    if body.rstrip().endswith("|"):
        return line
    return m.group(1) + "   " + body


NUM_HEADING_RE = re.compile(r"^(\d+(?:\.\d+)*)\.?[ \t]+(\S.*)$")
APPENDIX_RE = re.compile(r"^Appendix ([A-Z])\.?[ \t]+(\S.*)$")
APPENDIX_SUB_RE = re.compile(r"^([A-Z](?:\.\d+)+)\.?[ \t]+(\S.*)$")
# 没有编号、但确实把正文隔开的顶格标题。其余没有编号的顶格行
# （比如 RFC 1928 第 6 节里的 CONNECT、BIND，第 2 节后面的 Note:）算在所在的编号章节里
BOUNDARY_TITLES = frozenset((
    "abstract", "status of this memo", "copyright notice", "table of contents",
    "acknowledgements", "acknowledgments", "contributors", "index",
    "author's address", "authors' addresses", "full copyright statement"))


def parse_heading(line):
    """顶格行是不是章节标题。返回 (章节号或 None, 标题)，不是标题返回 None。"""
    for rx in (NUM_HEADING_RE, APPENDIX_RE, APPENDIX_SUB_RE):
        m = rx.match(line)
        if m:
            return m.group(1), fold(m.group(2))
    if fold(line).lower() in BOUNDARY_TITLES:
        return None, fold(line)
    return None


class Heading:
    __slots__ = ("offset", "number", "title", "level")

    def __init__(self, offset, number, title):
        self.offset = offset
        self.number = number
        self.title = title
        self.level = 1 if number is None else number.count(".") + 1

    def label(self):
        return f"§{self.number}（{self.title}）" if self.number else f"“{self.title}”"


TERMINAL_RE = re.compile(r"[.!?:][\"')\]]*$")
BULLET_RE = re.compile(r"^(?:[o*+|-]|\d+\.|[a-z]\.|\(\w+\)|\[\d+\])$")


class Folded:
    """折叠空白后的文本，记着每个章节标题、每行、每段的开头在折叠后文本里的位置。

    lines 是去掉页脚页眉以后的各行，page_breaks 是每一页（第一页除外）第一行的下标。
    """

    def __init__(self, lines, page_breaks=()):
        parts = []
        pos = 0
        self.headings = []
        self.index = {}
        self.duplicates = []
        self.line_starts = set()
        self.para_starts = set()
        prev_blank = True
        after_break = False
        last = None
        for i, line in enumerate(lines):
            if i in page_breaks:
                after_break = True
                prev_blank = True
            words = line.split()
            if not words:
                prev_blank = True
                continue
            # 翻页处分不清是不是换了段：缩进相同、上一页最后一行没有收尾的标点，就当作同一段接着写
            new_para = prev_blank
            if after_break and last is not None:
                same_indent = len(line) - len(line.lstrip()) == len(last) - len(last.lstrip())
                if same_indent and not TERMINAL_RE.search(last.rstrip()):
                    new_para = False
            # 章节标题：顶格，前面是空行
            if prev_blank and not line[0].isspace():
                h = parse_heading(line)
                if h:
                    heading = Heading(pos, h[0], h[1])
                    if heading.number is not None and heading.number in self.index:
                        self.duplicates.append(heading.number)
                    else:
                        if heading.number is not None:
                            self.index[heading.number] = len(self.headings)
                        self.headings.append(heading)
            self.line_starts.add(pos)
            if new_para:
                self.para_starts.add(pos)
            for w in words:
                parts.append(w)
                pos += len(w) + 1
            prev_blank = False
            after_break = False
            last = line
        self.text = " ".join(parts)
        self._offsets = [h.offset for h in self.headings]

    def doc_title(self):
        """文档的标题：第一个章节标题之前的最后一段（文件头与标题之间隔着空行）。认不出来返回 None。"""
        if not self._offsets:
            return None
        end = self._offsets[0]
        starts = [p for p in self.para_starts if p < end]
        return self.text[max(starts):end].strip() if starts else None

    def find_all(self, needle):
        out = []
        i = self.text.find(needle)
        while i != -1:
            out.append(i)
            i = self.text.find(needle, i + 1)
        return out

    def span(self, number):
        """章节的范围：从它的标题行到下一个同级或更高级的标题行。没有这个章节返回 None。"""
        i = self.index.get(number)
        if i is None:
            return None
        h = self.headings[i]
        end = len(self.text)
        for g in self.headings[i + 1:]:
            if g.level <= h.level:
                end = g.offset
                break
        return h.offset, end

    def heading(self, number):
        i = self.index.get(number)
        return None if i is None else self.headings[i]

    def innermost(self, pos):
        """pos 所在的最里层章节（最近的一个标题）；在第一个标题之前返回 None。"""
        i = bisect.bisect_right(self._offsets, pos) - 1
        return self.headings[i] if i >= 0 else None

    def where(self, pos):
        h = self.innermost(pos)
        return h.label() if h else "第一个标题之前"

    def diverge(self, needle):
        """引文对不上时，找它能对上的最长开头。返回 (词数, 所在章节, 引文接下去的词, 原文接下去的词)。"""
        words = needle.split(" ")
        lo, hi = 0, len(words)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.text.find(" ".join(words[:mid])) != -1:
                lo = mid
            else:
                hi = mid - 1
        if lo == 0:
            return 0, None, "", ""
        head = " ".join(words[:lo])
        p = self.text.find(head)
        rest = self.text[p + len(head):p + len(head) + 200].split()
        return lo, self.where(p), " ".join(words[lo:lo + 6]), " ".join(rest[:6])

    def starts_sentence(self, s):
        """位置 s 是不是句子（或段落、列表项）的开头。启发式。"""
        if s == 0 or s in self.para_starts:
            return True
        if self.text[s - 1] != " ":
            return False
        j = self.text.rfind(" ", 0, s - 1) + 1
        prev = self.text[j:s - 1]
        if TERMINAL_RE.search(prev):
            return True
        return j in self.line_starts and bool(BULLET_RE.match(prev))

    def ends_sentence(self, e, needle):
        """位置 e（引文之后的第一个字符）是不是句子（或段落、列表项）的结尾。启发式。"""
        if e >= len(self.text):
            return True
        if self.text[e] != " ":
            return False
        if TERMINAL_RE.search(needle):
            return True
        nxt = e + 1
        if nxt in self.para_starts:
            return True
        k = self.text.find(" ", nxt)
        tok = self.text[nxt:] if k == -1 else self.text[nxt:k]
        return nxt in self.line_starts and bool(BULLET_RE.match(tok))


class RfcText:
    """一篇 RFC 的文本。plain 是按原样折叠的；noaside 是先去掉旁注竖线再折叠的（没有旁注时为 None）。"""

    def __init__(self, text, number):
        self.number = number
        self.paginated = "\f" in text
        lines = []
        breaks = set()
        for i, page in enumerate(split_pages(text.replace("\r\n", "\n"), number)):
            if i:
                breaks.add(len(lines))
            lines.extend(page.split("\n"))
        self.plain = Folded(lines, breaks)
        stripped = [strip_aside(line) for line in lines]
        self.noaside = Folded(stripped, breaks) if stripped != lines else None

    def variants(self):
        return [self.plain] if self.noaside is None else [self.plain, self.noaside]


def load_rfc(rfc_dir, number):
    """读 rfc_dir/rfcNNNN.txt。返回 (RfcText 或 None, 文件的 SHA-256 或 None, 出错说明或 None)。"""
    path = pathlib.Path(rfc_dir) / f"rfc{number}.txt"
    try:
        raw = path.read_bytes()
    except OSError as e:
        return None, None, f"读不了 {path.name}：{e.strerror or e}"
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        return None, digest, f"{path.name} 不是 UTF-8：{e}"
    return RfcText(text, number), digest, None


def load_registry(path):
    """读 rfc_sha256.txt（sha256sum 的格式）。返回 {文件名: 哈希}。"""
    out = {}
    try:
        lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise CannotRun(f"读不了哈希登记 {path}：{e.strerror or e}")
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        m = re.match(r"^([0-9a-f]{64})\s+\*?(\S+)$", line)
        if not m:
            raise CannotRun(f"{path} 第 {n} 行不是“哈希  文件名”")
        out[m.group(2)] = m.group(1)
    return out


def load_rows(path):
    """读 rows.json，返回行号的集合。"""
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        return {r["id"] for r in data["rows"]}
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise CannotRun(f"读不了行表 {path}：{e}")


# ---- 核对 ----

class Report:
    def __init__(self):
        self.problems = []
        self.notes = []

    def problem(self, file, cid, code, message):
        assert code in PROBLEM_CODES, code
        self.problems.append({"file": file, "id": cid, "code": code, "message": message})

    def note(self, file, cid, code, message):
        assert code in NOTE_CODES, code
        self.notes.append({"file": file, "id": cid, "code": code, "message": message})


def short(s, n=60):
    s = fold(s)
    return s if len(s) <= n else s[:n] + "……"


def check_text(rep, fname, cid, rfc, quote, section, title):
    """对着 RFC 文本核对一条条款的引文、章节和章节标题。section、title 为 None 表示那个字段本身不合格，跳过。"""
    needle = fold(quote)
    doc = None
    hits = []
    for variant in rfc.variants():
        hits = variant.find_all(needle)
        if hits:
            doc = variant
            break
    found_in = "、".join(dict.fromkeys(doc.where(p) for p in hits)) if hits else ""

    declared = rfc.plain.heading(section) if section is not None else None
    if section is not None and declared is None:
        rep.problem(fname, cid, "section-unknown", f"RFC {rfc.number} 的文本里没有 §{section}"
                    + (f"（引文在 {found_in} 里）" if hits else ""))
    elif declared is not None and title is not None and fold(title) != declared.title:
        rep.problem(fname, cid, "section-title",
                    f"§{section} 在原文里的标题是“{declared.title}”，条款写的是“{fold(title)}”")

    if not hits:
        k, where, q_next, t_next = rfc.plain.diverge(needle)
        msg = f"引文不是 RFC {rfc.number} 文本的子串（已折叠空白）：“{short(needle)}”"
        if k >= 4:
            msg += f"。开头 {k} 个词在 {where} 能对上，接下去引文是“{q_next}”，原文是“{t_next}”"
        rep.problem(fname, cid, "quote-not-found", msg)
        return
    if declared is None:
        return

    start, end = doc.span(section)
    inside = [p for p in hits if start <= p and p + len(needle) <= end]
    if not inside:
        if any(start <= p < end for p in hits):
            rep.problem(fname, cid, "section-mismatch", f"引文从 §{section} 里开始，但越过了这一节的结尾；一条引文不能跨节")
        else:
            rep.problem(fname, cid, "section-mismatch", f"引文不在 §{section} 里，在 {found_in} 里")
        return

    pos = inside[0]
    inner = doc.innermost(pos)
    if inner is not None and inner.number != section:
        rep.note(fname, cid, "section-deeper", f"引文在 {inner.label()} 里，声明的是 §{section}")
    head_ok = doc.starts_sentence(pos)
    tail_ok = doc.ends_sentence(pos + len(needle), needle)
    if not (head_ok and tail_ok):
        which = "、".join(w for w, ok in (("开头", head_ok), ("结尾", tail_ok)) if not ok)
        before = doc.text[max(0, pos - 40):pos].strip()
        after = doc.text[pos + len(needle):pos + len(needle) + 40].strip()
        rep.note(fname, cid, "sentence",
                 f"引文的{which}看起来不在句子边界上：原文里它前面是“…{before}”，后面是“{after}…”")


def check_clause(rep, fname, n, clause, number, rfc, rows, seen_ids):
    """核对一条条款。n 是它在文件里的序号（从 1 起），没有可用的 id 时用来指代它。"""
    if not isinstance(clause, dict):
        rep.problem(fname, f"第 {n} 条", "field", "条款不是 JSON 对象")
        return
    cid = clause.get("id") if isinstance(clause.get("id"), str) and clause.get("id") else f"第 {n} 条"

    ok = {}
    for key in CLAUSE_FIELDS:
        if key not in clause:
            rep.problem(fname, cid, "field", f"缺字段 {key}")
            ok[key] = False
        elif key == "rows":
            ok[key] = True
        elif not isinstance(clause[key], str):
            rep.problem(fname, cid, "field", f"{key} 应当是字符串")
            ok[key] = False
        elif not clause[key].strip():
            rep.problem(fname, cid, "field", f"{key} 是空的")
            ok[key] = False
        else:
            ok[key] = True
    extra = sorted(set(clause) - set(CLAUSE_FIELDS))
    if extra:
        rep.note(fname, cid, "unknown-field", "格式之外的字段：" + "、".join(extra))

    if ok["section"] and not SECTION_RE.match(clause["section"]):
        rep.problem(fname, cid, "field", f"section “{clause['section']}” 不是章节号（形如 9.3.6 或 B.1）")
        ok["section"] = False

    if ok["id"]:
        m = ID_RE.match(clause["id"])
        if not m:
            rep.problem(fname, cid, "id-format", f"id “{clause['id']}” 不是“RFC 号-章节号-序号”（如 9110-9.3.6-1）")
        else:
            if number is not None and int(m.group(1)) != number:
                rep.problem(fname, cid, "id-rfc", f"id 里的 RFC 号是 {m.group(1)}，文件是 RFC {number}")
            if ok["section"] and m.group(2) != clause["section"]:
                rep.problem(fname, cid, "id-section", f"id 里的章节号是 {m.group(2)}，section 是 {clause['section']}")
        if clause["id"] in seen_ids:
            rep.problem(fname, cid, "id-duplicate", f"id 与 {seen_ids[clause['id']]} 里的一条重复")
        else:
            seen_ids[clause["id"]] = fname

    for key, allowed in (("level", LEVELS), ("binds", BINDS), ("side", SIDES), ("topic", TOPICS)):
        if ok[key] and clause[key] not in allowed:
            rep.problem(fname, cid, "enum", f"{key} “{clause[key]}” 不在允许的取值里：" + "、".join(allowed))
            ok[key] = False

    if ok["rows"]:
        r = clause["rows"]
        if not isinstance(r, list) or not all(isinstance(x, str) for x in r):
            rep.problem(fname, cid, "rows", "rows 应当是行号的列表（没有就写空数组）")
        else:
            dup = sorted({x for x in r if r.count(x) > 1})
            if dup:
                rep.problem(fname, cid, "rows", "rows 里有重复：" + "、".join(dup))
            unknown = [x for x in dict.fromkeys(r) if x not in rows]
            if unknown:
                rep.problem(fname, cid, "rows", "rows.json 里没有这些行：" + "、".join(unknown))

    if ok["quote"]:
        if clause["quote"] != fold(clause["quote"]):
            rep.note(fname, cid, "quote-whitespace", "引文里有换行、连续空白或首尾空白，按格式应折成一个空格")
        if ok["level"]:
            found = keywords_in(clause["quote"])
            level = clause["level"]
            if level == "statement":
                if found:
                    rep.problem(fname, cid, "level", "level 是 statement，引文里却有规范性关键词：" + "、".join(found))
            elif level not in found:
                rep.problem(fname, cid, "level",
                            f"level 是 {level}，引文里没有这个关键词"
                            + ("（引文里有：" + "、".join(found) + "）" if found else "（引文里没有任何大写的规范性关键词）"))
        if rfc is not None:
            check_text(rep, fname, cid, rfc, clause["quote"],
                       clause["section"] if ok["section"] else None,
                       clause["section_title"] if ok["section_title"] else None)


def check_file(rep, path, rfc_dir, rows, registry, seen_ids):
    """核对一个条款文件。返回这个文件的小结。"""
    fname = path.name
    summary = {"file": fname, "rfc": None, "clauses": 0}
    m = FILE_RE.match(fname)
    number = int(m.group(1)) if m else None
    if not m:
        rep.problem(fname, None, "filename", "文件名应当是 rfcNNNN.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        rep.problem(fname, None, "json", f"读不出 JSON：{e}")
        return summary
    if not isinstance(data, dict):
        rep.problem(fname, None, "json", "顶层应当是一个对象")
        return summary

    for key in TOP_FIELDS:
        if key not in data:
            rep.problem(fname, None, "top-field", f"缺字段 {key}")
    if "rfc" in data:
        if not isinstance(data["rfc"], int) or isinstance(data["rfc"], bool):
            rep.problem(fname, None, "top-field", "rfc 应当是整数")
        elif number is None:
            number = data["rfc"]
        elif data["rfc"] != number:
            rep.problem(fname, None, "filename", f"文件名是 RFC {number}，文件里的 rfc 是 {data['rfc']}")
    summary["rfc"] = number
    title = data.get("title")
    if "title" in data and not (isinstance(title, str) and title.strip()):
        rep.problem(fname, None, "top-field", "title 应当是非空的字符串")
        title = None
    declared_sha = data.get("text_sha256")
    if "text_sha256" in data and not (isinstance(declared_sha, str) and SHA_RE.match(declared_sha)):
        rep.problem(fname, None, "top-field", "text_sha256 应当是 64 位小写十六进制")
        declared_sha = None
    clauses = data.get("clauses")
    if "clauses" in data and not isinstance(clauses, list):
        rep.problem(fname, None, "top-field", "clauses 应当是数组")
        clauses = None

    rfc = None
    if number is not None:
        rfc, actual_sha, err = load_rfc(rfc_dir, number)
        if err:
            rep.problem(fname, None, "text", err + "（引文没法核对）")
        if actual_sha is not None:
            if declared_sha is not None and declared_sha != actual_sha:
                rep.problem(fname, None, "sha256",
                            f"text_sha256 是 {declared_sha}，rfc{number}.txt 实际是 {actual_sha}")
            if registry is not None:
                registered = registry.get(f"rfc{number}.txt")
                if registered is None:
                    rep.problem(fname, None, "registry", f"rfc{number}.txt 没有登记在 rfc_sha256.txt 里")
                elif registered != actual_sha:
                    rep.problem(fname, None, "registry",
                                f"rfc_sha256.txt 登记的是 {registered}，rfc{number}.txt 实际是 {actual_sha}")
        if rfc is not None and title is not None and rfc.plain.doc_title() not in (None, fold(title)):
            rep.problem(fname, None, "title",
                        f"rfc{number}.txt 开头写的标题是“{rfc.plain.doc_title()}”，文件里的 title 是“{fold(title)}”")
        if rfc is not None and rfc.plain.duplicates:
            rep.problem(fname, None, "text", f"rfc{number}.txt 里有重复的章节号（文本的版式不是预期的）："
                        + "、".join(rfc.plain.duplicates))

    for n, clause in enumerate(clauses or [], 1):
        check_clause(rep, fname, n, clause, number, rfc, rows, seen_ids)
    summary["clauses"] = len(clauses or [])
    return summary


def check(clauses_dir, rfc_dir, rows_path, registry_path=None):
    """核对 clauses_dir 下的全部条款文件。registry_path 为 None 时不对照哈希登记。"""
    clauses_dir = pathlib.Path(clauses_dir)
    if rfc_dir is None or not pathlib.Path(rfc_dir).is_dir():
        raise CannotRun(f"RFC 文本目录不存在：{rfc_dir}。用 --rfc-dir 或环境变量 KAOJU_RFC_DIR 指定，文本用 fetch_rfcs.sh 取")
    files = sorted(clauses_dir.glob("*.json"), key=lambda p: p.name) if clauses_dir.is_dir() else []
    if not files:
        raise CannotRun(f"{clauses_dir} 下没有条款文件")
    rows = load_rows(rows_path)
    registry = load_registry(registry_path) if registry_path is not None else None

    rep = Report()
    seen_ids = {}
    summaries = [check_file(rep, p, rfc_dir, rows, registry, seen_ids) for p in files]
    for s in summaries:
        s["problems"] = sum(1 for p in rep.problems if p["file"] == s["file"])
        s["notes"] = sum(1 for p in rep.notes if p["file"] == s["file"])
    have = {s["rfc"] for s in summaries}
    missing = sorted(int(name[3:-4]) for name in (registry or {})
                     if re.match(r"^rfc\d+\.txt$", name) and int(name[3:-4]) not in have)
    return {
        "ok": not rep.problems,
        "clauses_dir": str(clauses_dir),
        "rfc_dir": str(rfc_dir),
        "files": summaries,
        "total_clauses": sum(s["clauses"] for s in summaries),
        "problems": rep.problems,
        "notes": rep.notes,
        "registered_without_clauses": missing,
    }


def render(result):
    out = []
    for s in result["files"]:
        name = f"RFC {s['rfc']}" if s["rfc"] is not None else "（RFC 号不明）"
        out.append(f"{name}  {s['file']}  {s['clauses']} 条  问题 {s['problems']}  提示 {s['notes']}")
        for kind, items in (("问题", result["problems"]), ("提示", result["notes"])):
            for p in items:
                if p["file"] == s["file"]:
                    who = f" {p['id']}" if p["id"] else ""
                    out.append(f"  {kind} [{p['code']}]{who}：{p['message']}")
    if result["registered_without_clauses"]:
        out.append("登记了文本、还没有条款文件的 RFC：" + "、".join(str(n) for n in result["registered_without_clauses"]))
    out.append(f"合计 {len(result['files'])} 个文件、{result['total_clauses']} 条条款："
               f"问题 {len(result['problems'])}，提示 {len(result['notes'])}")
    if result["problems"]:
        out.append("核对未通过")
    elif result["notes"]:
        out.append("核对通过，另有提示要人看一眼" if result["ok"] else "核对未通过（--strict：有提示也算）")
    else:
        out.append("核对通过")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="逐条核对条款文件里的引文、章节和级别")
    ap.add_argument("--rfc-dir", default=os.environ.get("KAOJU_RFC_DIR"),
                    help="放 rfcNNNN.txt 的目录（默认取环境变量 KAOJU_RFC_DIR）")
    ap.add_argument("--clauses", default=str(DEFAULT_CLAUSES), help="条款文件的目录（默认 spec/clauses）")
    ap.add_argument("--rows", default=str(DEFAULT_ROWS), help="矩阵的行表（默认 ../rows.json）")
    ap.add_argument("--sha256-file", default=str(DEFAULT_REGISTRY), help="文本哈希的登记（默认 spec/rfc_sha256.txt）")
    ap.add_argument("--json", action="store_true", help="输出机器可读的 JSON")
    ap.add_argument("--strict", action="store_true", help="有提示也算不通过（退出 1）")
    args = ap.parse_args(argv)
    try:
        if not args.rfc_dir:
            raise CannotRun("没有指定 RFC 文本目录。用 --rfc-dir 或环境变量 KAOJU_RFC_DIR 指定，文本用 fetch_rfcs.sh 取")
        result = check(args.clauses, args.rfc_dir, args.rows, args.sha256_file)
    except CannotRun as e:
        if args.json:
            print(json.dumps({"ok": False, "cannot_run": str(e)}, ensure_ascii=False, indent=1))
        else:
            print(f"没法核对：{e}", file=sys.stderr)
        return 2
    if args.strict and result["notes"]:
        result["ok"] = False
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        print(render(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
