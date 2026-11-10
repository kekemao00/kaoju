#!/usr/bin/env python3
"""核对“与 summary.json 不一致”是否全由 summary 漏读的 judge 文件造成（SCHEMA 坑 20）。

summary.json 跨整点生成时，judge 当时那一小时的文件在读的过程中被压缩改名，rec.Each 跳过了它，之后新开的文件也没读到。
本脚本把这些文件（files.hour >= summary 生成时刻所在的小时、prefix='judge'）在库里藏起来，再按原样跑一遍指定的模块，
看它们与 summary.json 的交叉核对是不是逐项一致。藏的办法：每个模块打开库之后，用同名的 TEMP VIEW 盖住
req / noise / tls_fail / req_dropped / noise_dropped / req_header / file_kind（SQLite 先在 TEMP 里找表名），
视图里去掉这些文件的记录。库本身只读打开，不改。模块的计算一行不改，只是看到的 judge 记录少了这几个文件。

注意：改 PRAGMA temp_store 的取值会删掉连接上已有的全部 TEMP 对象，而各模块打开库后都会设 temp_store = FILE。
所以视图建在一个 Connection 子类上：建视图前先设 temp_store = FILE（之后模块再设同一个值不会清掉 TEMP），
模块每次改 temp_store 之后再补建一遍。第一版没有考虑这一点，视图被悄悄清掉、藏了等于没藏；自检里有一项专门核对。

用法：
  python3 crosscheck_as_summary_saw.py --db 库 --summary 数据目录/summary.json --data 数据目录 --certcheck certcheck \\
      [--modules instrument,integrity,nodes,literature] [--write out/rotation_check.json]
  python3 crosscheck_as_summary_saw.py --selftest

输出：每个模块藏文件前（读 out/<模块>.json，没有就跳过）与藏文件后的不一致项。模块自己的 JSON 写到临时目录，用完删掉。
只用 Python 标准库。结果只含模块名、比对项的名字和计数。
"""
import argparse
import contextlib
import re
import datetime as dt
import importlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
JUDGE_TABLES = ("req", "noise", "tls_fail", "req_dropped", "noise_dropped")
DEFAULT_MODULES = ("instrument", "integrity", "nodes", "literature")


def late_files(db_path, summary):
    gen = summary.get("generated")
    t = dt.datetime.fromisoformat(str(gen).replace("Z", "+00:00"))
    hour = t.astimezone(dt.timezone.utc).strftime("%Y%m%d-%H")
    con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(db_path), uri=True)
    try:
        rows = con.execute("SELECT id, hour FROM files WHERE prefix = 'judge' AND hour >= ? ORDER BY hour", (hour,)).fetchall()
    finally:
        con.close()
    return hour, rows


def hide_sql(ids):
    idl = ",".join(str(int(i)) for i in ids) or "NULL"
    out = ['CREATE TEMP VIEW "%s" AS SELECT * FROM main."%s" WHERE file_id NOT IN (%s)' % (t, t, idl) for t in JUDGE_TABLES]
    out.append('CREATE TEMP VIEW "req_header" AS SELECT * FROM main."req_header" '
               'WHERE req_rid NOT IN (SELECT rid FROM main."req" WHERE file_id IN (%s))' % idl)
    out.append('CREATE TEMP VIEW "file_kind" AS SELECT * FROM main."file_kind" WHERE file_id NOT IN (%s)' % idl)
    return out


TEMP_STORE_RE = re.compile(r"\s*PRAGMA\s+(?:temp\.)?temp_store\s*=", re.I)


class HidingConnection(sqlite3.Connection):
    """建好盖住 judge 表的 TEMP VIEW；有人改 temp_store（会清掉全部 TEMP 对象）之后补建。"""
    hide_stmts = ()

    def apply_hide(self):
        sqlite3.Connection.execute(self, "PRAGMA temp_store = FILE")
        for s in self.hide_stmts:
            sqlite3.Connection.execute(self, s.replace("CREATE TEMP VIEW", "CREATE TEMP VIEW IF NOT EXISTS", 1))

    def execute(self, sql, *a, **kw):
        cur = sqlite3.Connection.execute(self, sql, *a, **kw)
        if isinstance(sql, str) and TEMP_STORE_RE.match(sql):
            self.apply_hide()
        return cur


def _db_name(a, kw):
    name = str(a[0] if a else kw.get("database", ""))
    if name.startswith("file:"):
        name = name[5:].split("?", 1)[0]
    return os.path.abspath(name)


@contextlib.contextmanager
def hidden(db_path, ids):
    """在这个上下文里，凡是连到 db_path 的 sqlite3 连接都先建好盖住 judge 表的 TEMP VIEW。"""
    real = sqlite3.connect
    target = os.path.abspath(db_path)
    stmts = hide_sql(ids)

    def connect(*a, **kw):
        if _db_name(a, kw) != target or "factory" in kw:
            return real(*a, **kw)
        con = real(*a, factory=HidingConnection, **kw)
        con.hide_stmts = stmts
        con.apply_hide()
        return con
    sqlite3.connect = connect
    try:
        yield
    finally:
        sqlite3.connect = real


def mismatches(res):
    """各模块 crosscheck 的不一致项（名字列表）。"""
    cc = res.get("crosscheck") or {}
    if "mismatches" in cc:
        return sorted(str(x) for x in cc.get("mismatches") or [])
    items = cc.get("items") or {}
    return sorted("%s（%s）" % (k, f) for k, v in items.items() for f in ("attempts_match", "candidates_match") if v.get(f) is False)


def run_module(key, args, out_dir):
    mod = importlib.import_module("m_" + key)
    argv = ["m_" + key, "--db", args.db, "--out", out_dir, "--summary", args.summary]
    if key in ("literature", "mitm"):
        argv += ["--data", args.data] + (["--certcheck", args.certcheck] if args.certcheck else [])
    saved = sys.argv
    sys.argv = argv
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = mod.main()
    finally:
        sys.argv = saved
    if rc not in (None, 0):
        raise SystemExit("m_%s 退出码 %r" % (key, rc))
    with open(os.path.join(out_dir, key + ".json"), encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description="藏起 summary 漏读的 judge 文件，重跑模块的交叉核对")
    ap.add_argument("--db")
    ap.add_argument("--summary")
    ap.add_argument("--data")
    ap.add_argument("--certcheck")
    ap.add_argument("--modules", default=",".join(DEFAULT_MODULES))
    ap.add_argument("--before-dir", default=os.path.join(HERE, "out"), help="藏文件前的模块输出（默认本目录 out/）")
    ap.add_argument("--write")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not (args.db and args.summary):
        ap.error("要 --db 和 --summary")
    with open(args.summary, encoding="utf-8") as f:
        summary = json.load(f)
    hour, rows = late_files(args.db, summary)
    res = {"summary_generated_hour_utc": "%s-%s-%sT%s:00Z" % (hour[:4], hour[4:6], hour[6:8], hour[9:]),
           "hidden_judge_files": [h for _, h in rows], "modules": {}}
    tmp = tempfile.mkdtemp(prefix="rotation-check-")
    try:
        for key in [m.strip() for m in args.modules.split(",") if m.strip()]:
            before = None
            p = os.path.join(args.before_dir, key + ".json")
            if os.path.isfile(p):
                with open(p, encoding="utf-8") as f:
                    before = mismatches(json.load(f))
            print("==> m_%s（藏起 %d 个 judge 文件）" % (key, len(rows)), file=sys.stderr)
            with hidden(args.db, [i for i, _ in rows]):
                after = mismatches(run_module(key, args, tmp))
            res["modules"][key] = {"mismatches_before": before, "mismatches_after_hiding": after,
                                   "all_resolved": not after}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    res["all_resolved"] = all(v["all_resolved"] for v in res["modules"].values())
    text = json.dumps(res, ensure_ascii=False, indent=1)
    print(text)
    if args.write:
        with open(args.write, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return 0 if res["all_resolved"] else 1


def selftest():
    """合成一个小库：两个 judge 文件，藏起后一个，看视图是否只剩前一个的记录、库文件是否没被改。"""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.sqlite")
        con = sqlite3.connect(path)
        con.executescript("""
            CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, prefix TEXT, hour TEXT);
            CREATE TABLE req (rid INTEGER PRIMARY KEY, file_id INTEGER, nonce TEXT);
            CREATE TABLE noise (rid INTEGER PRIMARY KEY, file_id INTEGER);
            CREATE TABLE tls_fail (rid INTEGER PRIMARY KEY, file_id INTEGER);
            CREATE TABLE req_dropped (rid INTEGER PRIMARY KEY, file_id INTEGER, n INTEGER);
            CREATE TABLE noise_dropped (rid INTEGER PRIMARY KEY, file_id INTEGER, n INTEGER);
            CREATE TABLE req_header (rid INTEGER PRIMARY KEY, req_rid INTEGER, name TEXT);
            CREATE TABLE file_kind (file_id INTEGER, k TEXT, n INTEGER);
            INSERT INTO files VALUES (1, 'judge-20261109-07.jsonl.gz', 'judge', '20261109-07'),
                                     (2, 'judge-20261109-08.jsonl.gz', 'judge', '20261109-08'),
                                     (3, 'probe-20261109-08.jsonl.gz', 'probe', '20261109-08');
            INSERT INTO req VALUES (1, 1, 'a'), (2, 1, 'b'), (3, 2, 'c');
            INSERT INTO noise VALUES (1, 2);
            INSERT INTO req_header VALUES (1, 1, 'X'), (2, 3, 'Y');
            INSERT INTO file_kind VALUES (1, 'req', 2), (2, 'req', 1), (2, 'noise', 1);
        """)
        con.commit()
        con.close()
        before = os.path.getsize(path)
        hour, rows = late_files(path, {"generated": "2026-11-09T08:59:58.416Z"})
        fails = []
        if [i for i, _ in rows] != [2]:
            fails.append("要藏的文件：%r" % rows)
        with hidden(path, [i for i, _ in rows]):
            c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
            got = (c.execute("SELECT COUNT(*) FROM req").fetchone()[0], c.execute("SELECT COUNT(*) FROM noise").fetchone()[0],
                   c.execute("SELECT COUNT(*) FROM req_header").fetchone()[0], c.execute("SELECT SUM(n) FROM file_kind").fetchone()[0])
            c.close()
            # 像各模块那样打开库后改 temp_store（取值变了会清掉全部 TEMP 对象），视图要还在
            got2 = []
            for pragma in ("PRAGMA temp_store = FILE", "PRAGMA temp_store = MEMORY", "PRAGMA temp_store=2"):
                c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
                c.execute("PRAGMA cache_size = -1024")
                c.execute(pragma)
                c.execute("CREATE TEMP TABLE scratch AS SELECT 1 AS x")
                got2.append(c.execute("SELECT COUNT(*) FROM req").fetchone()[0])
                c.close()
        if got != (2, 0, 1, 2):
            fails.append("藏起后的计数：%r，应为 (2, 0, 1, 2)" % (got,))
        if got2 != [2, 2, 2]:
            fails.append("模块改了 temp_store 之后视图没了：%r，应为 [2, 2, 2]" % (got2,))
        c = sqlite3.connect(path)
        if c.execute("SELECT COUNT(*) FROM req").fetchone()[0] != 3:
            fails.append("上下文之外不该再藏")
        c.close()
        if os.path.getsize(path) != before:
            fails.append("库文件被改了")
    if fails:
        print("自检失败：\n  " + "\n  ".join(fails), file=sys.stderr)
        return 1
    print("自检通过", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
