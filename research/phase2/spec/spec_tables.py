#!/usr/bin/env python3
"""把 clauses/*.json 渲染成 Markdown：research/phase2/out/spec_clauses.md。

用法：
    python3 spec_tables.py              # 写到 ../out/spec_clauses.md
    python3 spec_tables.py --out -      # 打到标准输出
    python3 spec_tables.py --check      # 只比较：现有的文件是不是条款文件现在渲染出来的样子，不是就退出 1

按 topic 分节，每条条款一行，原文放在每节表后的折叠块里。输出只取决于条款文件、rows.json
和 rfc_sha256.txt，不带时间，同样的输入得到同样的字节。

这个脚本只渲染，不核对引文（不需要 RFC 文本）；核对用 check_quotes.py。
条款文件不全（有的 RFC 还没写、一个都没有）也能运行，表里会写明缺哪些。
只用 Python 标准库。
"""
import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_quotes as cq  # noqa: E402  取值表只写在 check_quotes.py 里

DEFAULT_OUT = HERE.parent / "out" / "spec_clauses.md"

# 题目指定的四篇排在前面，补充的几篇按编号排在后面
PRIMARY = (9110, 9112, 1928, 1929)

TOPIC_TITLES = {
    "request-target": "请求目标的形式",
    "connect": "CONNECT 方法",
    "tunnel": "隧道",
    "proxy-auth": "代理认证（407、Proxy-Authenticate、Proxy-Authorization）",
    "hop-by-hop": "逐跳的头字段",
    "via": "Via",
    "framing": "消息定界",
    "smuggling": "请求走私",
    "connection": "连接管理",
    "retry": "重试",
    "expect": "Expect 与 100-continue",
    "status": "状态码",
    "socks-negotiation": "SOCKS5 方法协商",
    "socks-auth": "SOCKS5 用户名密码认证",
    "socks-request": "SOCKS5 请求",
    "socks-reply": "SOCKS5 应答",
    "basic": "Basic 认证方案",
    "proxy-status": "Proxy-Status",
    "h2": "HTTP/2",
    "websocket": "WebSocket",
}
assert tuple(TOPIC_TITLES) == cq.TOPICS, "TOPIC_TITLES 要与 check_quotes.TOPICS 一一对应"

MISSING = "（缺）"


class BadInput(Exception):
    """条款文件读不出来（退出码 2）。"""


def rfc_order(number):
    if number in PRIMARY:
        return (0, PRIMARY.index(number))
    return (1, number) if isinstance(number, int) else (2, 0)


def clause_order(c):
    """同一个主题里的排序：先按 RFC，再按章节号（逐级按数字比），再按 id 里的序号。"""
    section = c.get("section")
    if isinstance(section, str) and cq.SECTION_RE.match(section):
        skey = (0, cq.section_key(section))
    else:
        skey = (1, ())
    m = cq.ID_RE.match(c["id"]) if isinstance(c.get("id"), str) else None
    return (rfc_order(c["_rfc"]), skey, int(m.group(3)) if m else 0, str(c.get("id")))


_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~])")


def esc(s):
    """RFC 的原话照字面显示：折叠空白，把会被 Markdown 当成标记的字符转义。"""
    s = cq.fold(str(s)).replace("&", "&amp;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def esc_block(s):
    """放在引用块里的原话：除了 esc 做的，行首的“1.”“-”“#”之类还会被当成列表或标题。"""
    s = re.sub(r"^(\d+)([.)])", r"\1\\\2", esc(s))
    return re.sub(r"^([#+=-])", r"\\\1", s)


def cell(s):
    """我们自己写的中文说明：当作 Markdown 行内文本，只处理会破坏表格的换行和竖线。"""
    return cq.fold(str(s)).replace("|", "\\|")


def text_of(c, key):
    v = c.get(key)
    return v if isinstance(v, str) and v.strip() else MISSING


def load(clauses_dir):
    """读全部条款文件。返回 [{"file", "rfc", "title", "sha", "clauses"}]，按 RFC 排好。"""
    files = []
    clauses_dir = pathlib.Path(clauses_dir)
    for path in sorted(clauses_dir.glob("*.json"), key=lambda p: p.name) if clauses_dir.is_dir() else []:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise BadInput(f"{path.name} 读不出 JSON：{e}")
        if not isinstance(data, dict):
            raise BadInput(f"{path.name} 的顶层不是对象")
        m = cq.FILE_RE.match(path.name)
        number = data.get("rfc") if isinstance(data.get("rfc"), int) else (int(m.group(1)) if m else None)
        clauses = []
        for n, c in enumerate(data.get("clauses") if isinstance(data.get("clauses"), list) else [], 1):
            if not isinstance(c, dict):
                raise BadInput(f"{path.name} 的第 {n} 条不是对象")
            c = dict(c)
            c["_rfc"] = number
            if not (isinstance(c.get("id"), str) and c["id"].strip()):
                c["id"] = f"{path.name} 第 {n} 条"
            clauses.append(c)
        files.append({"file": path.name, "rfc": number, "title": data.get("title"),
                      "sha": data.get("text_sha256"), "clauses": clauses})
    files.sort(key=lambda f: (rfc_order(f["rfc"]), f["file"]))
    return files


def load_rows(path):
    """rows.json 里的行号和标题，按文件里的顺序。读不到就返回空表（行号照样列出，只是没有标题）。"""
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        return {r["id"]: r.get("title", "") for r in data["rows"]}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def registered_rfcs(path):
    try:
        names = cq.load_registry(path)
    except cq.CannotRun:
        return []
    return sorted((int(n[3:-4]) for n in names if re.match(r"^rfc\d+\.txt$", n)), key=rfc_order)


def source(c):
    """出处：RFC 9110 §9.3.6 CONNECT。"""
    rfc = f"RFC {c['_rfc']}" if c["_rfc"] is not None else "RFC（号不明）"
    return f"{rfc} §{cell(text_of(c, 'section'))}"


def render(files, rows, registered):
    clauses = [c for f in files for c in f["clauses"]]
    out = []
    w = out.append

    w("# 规范条款表")
    w("")
    w("<!-- 由 research/phase2/spec/spec_tables.py 生成，不要手改；改了条款文件就重新生成 -->")
    w("")
    w("本表由 `research/phase2/spec/spec_tables.py` 从 `research/phase2/spec/clauses/*.json` 生成，不要手改。")
    w("")
    w("- “原文”是 RFC 的原话，逐字引用，只把换行和连续空白折成了一个空格，在每个主题的表后面，点开就能对照。")
    w("- “对网关的含义”是我们的解读，不是 RFC 的原话；写“背景”的是推不出具体要求的条款。")
    w("- 级别是原文里的规范性关键词；statement 指没有规范性关键词的事实陈述或定义。")
    w("- “约束谁”是条款约束的角色；“哪一侧”是对网关而言：入口（网关作为代理或 SOCKS5 服务端）、"
      "上游（网关作为上游代理的客户端）、两侧、客户端（只约束连到网关的客户端，网关据此判断客户端的行为是否合规）。")
    w("- 矩阵行是 `research/phase2/rows.json` 里的行号。")
    w("- 本表只是渲染，不代表核对过。引文是不是原文、在不在所标的章节里、级别与关键词是否一致，"
      "由 `spec/check_quotes.py` 对着 RFC 文本逐条核对；文本怎么取、怎么核对见 `spec/README.md`。")
    w("")

    w("## 概览")
    w("")
    if not files:
        w("还没有条款文件。")
        w("")
    else:
        w("| RFC | 标题 | 条款数 | 条款文件 | 所用文本的 SHA-256 |")
        w("| --- | --- | --- | --- | --- |")
        for f in files:
            number = f"RFC {f['rfc']}" if f["rfc"] is not None else "（号不明）"
            sha = f"`{f['sha']}`" if isinstance(f["sha"], str) and cq.SHA_RE.match(f["sha"]) else MISSING
            w(f"| {number} | {esc(f['title']) if isinstance(f['title'], str) and f['title'].strip() else MISSING} "
              f"| {len(f['clauses'])} | `clauses/{f['file']}` | {sha} |")
        w(f"| 合计 | | {len(clauses)} | | |")
        w("")
    have = {f["rfc"] for f in files}
    lacking = [n for n in registered if n not in have]
    if lacking:
        w("登记了文本（`spec/rfc_sha256.txt`）、还没有条款文件的 RFC：" + "、".join(f"RFC {n}" for n in lacking) + "。")
        w("")

    if clauses:
        w("按级别：")
        w("")
        w("| RFC | " + " | ".join(cq.LEVELS) + " | 合计 |")
        w("| --- |" + " --- |" * (len(cq.LEVELS) + 1))
        for f in files:
            counts = [sum(1 for c in f["clauses"] if c.get("level") == lv) for lv in cq.LEVELS]
            number = f"RFC {f['rfc']}" if f["rfc"] is not None else "（号不明）"
            w(f"| {number} | " + " | ".join(str(n) for n in counts) + f" | {len(f['clauses'])} |")
        counts = [sum(1 for c in clauses if c.get("level") == lv) for lv in cq.LEVELS]
        w("| 合计 | " + " | ".join(str(n) for n in counts) + f" | {len(clauses)} |")
        w("")
        other = sum(1 for c in clauses if c.get("level") not in cq.LEVELS)
        if other:
            w(f"另有 {other} 条的 level 不在允许的取值里，没有计入上面各列。")
            w("")
        w("按主题：")
        w("")
        w("| 主题 | 条款数 | " + " | ".join(cq.SIDES) + " |")
        w("| --- | --- |" + " --- |" * len(cq.SIDES))
        for topic in cq.TOPICS:
            group = [c for c in clauses if c.get("topic") == topic]
            sides = [sum(1 for c in group if c.get("side") == s) for s in cq.SIDES]
            w(f"| {topic}：{TOPIC_TITLES[topic]} | {len(group)} | " + " | ".join(str(n) for n in sides) + " |")
        w("")

    w("## 按主题")
    w("")
    groups = [(t, f"{t}：{TOPIC_TITLES[t]}", [c for c in clauses if c.get("topic") == t]) for t in cq.TOPICS]
    stray = [c for c in clauses if c.get("topic") not in cq.TOPICS]
    if stray:
        groups.append((None, "topic 不在允许的取值里", stray))
    if not clauses:
        w("还没有条款。")
        w("")
    for topic, title, group in groups:
        if not group:
            continue
        group.sort(key=clause_order)
        w(f"### {title}")
        w("")
        w("| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |")
        w("| --- | --- | --- | --- | --- | --- | --- |")
        for c in group:
            r = c.get("rows") if isinstance(c.get("rows"), list) else []
            w(f"| {cell(c['id'])} | {source(c)} {esc(text_of(c, 'section_title'))} | {cell(text_of(c, 'level'))} "
              f"| {cell(text_of(c, 'binds'))} | {cell(text_of(c, 'side'))} | {cell(text_of(c, 'gateway'))} "
              f"| {'、'.join(cell(x) for x in r) if r else '—'} |")
        w("")
        w("<details>")
        w(f"<summary>原文（{len(group)} 条）</summary>")
        w("")
        for c in group:
            w(f"**{cell(c['id'])}**　{source(c)}")
            w("")
            w(f"> {esc_block(text_of(c, 'quote'))}")
            w("")
        w("</details>")
        w("")

    w("## 按矩阵行反查")
    w("")
    by_row = {}
    for c in sorted(clauses, key=clause_order):
        for r in c.get("rows") if isinstance(c.get("rows"), list) else []:
            by_row.setdefault(str(r), []).append(str(c["id"]))
    if not by_row:
        w("还没有条款指到矩阵的行。")
        w("")
    else:
        w("| 矩阵行 | 这一行看什么 | 相关条款 |")
        w("| --- | --- | --- |")
        known = [r for r in rows if r in by_row]
        unknown = sorted(r for r in by_row if r not in rows)
        for r in known:
            w(f"| {r} | {cell(rows[r])} | {'、'.join(cell(x) for x in by_row[r])} |")
        for r in unknown:
            w(f"| {cell(r)} | （rows.json 里没有这一行） | {'、'.join(cell(x) for x in by_row[r])} |")
        w("")
        if rows:
            rest = [r for r in rows if r not in by_row]
            w(f"行表共 {len(rows)} 行，{len(known)} 行有条款指到。"
              + (f"没有条款指到的 {len(rest)} 行：" + "、".join(rest) + "。" if rest else ""))
            w("")
    return "\n".join(out).rstrip("\n") + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="把条款文件渲染成 Markdown")
    ap.add_argument("--clauses", default=str(cq.DEFAULT_CLAUSES), help="条款文件的目录（默认 spec/clauses）")
    ap.add_argument("--rows", default=str(cq.DEFAULT_ROWS), help="矩阵的行表（默认 ../rows.json）")
    ap.add_argument("--sha256-file", default=str(cq.DEFAULT_REGISTRY), help="文本哈希的登记（默认 spec/rfc_sha256.txt）")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="输出文件（默认 ../out/spec_clauses.md；- 表示标准输出）")
    ap.add_argument("--check", action="store_true", help="不写文件，只比较现有的输出文件是否与现在渲染的一致")
    args = ap.parse_args(argv)
    try:
        files = load(args.clauses)
    except BadInput as e:
        print(f"没法渲染：{e}", file=sys.stderr)
        return 2
    text = render(files, load_rows(args.rows), registered_rfcs(args.sha256_file))
    total = sum(len(f["clauses"]) for f in files)
    if args.out == "-":
        sys.stdout.write(text)
        return 0
    out = pathlib.Path(args.out)
    if args.check:
        try:
            same = out.read_text(encoding="utf-8") == text
        except OSError:
            same = False
        print(f"{out}：" + ("与条款文件一致" if same else "与条款文件不一致，重新运行 spec_tables.py"), file=sys.stderr)
        return 0 if same else 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"写了 {out}：{len(files)} 个条款文件、{total} 条条款（只渲染，没有核对引文）", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
