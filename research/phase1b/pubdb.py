#!/usr/bin/env python3
"""真实库与公开库之间的接缝（`PUBLIC.md`）。只用标准库。

分析模块有几处要读库以外的东西：证据文件（证书链、被改的正文）、AWS 公布的地址段。公开库里没有证据文件，地址也换成了假名，
这几处就算不出来。做法是把它们的**结果**随公开库带上：

- 在真实库上跑的时候，设了环境变量 `PHASE1B_RECORD=<一个 SQLite 文件>`，模块就把这几处算出的结果记进这个文件（`Recorder`）；
- `pub_export.py` 把记下的结果脱敏以后放进公开库的 `pub_*` 表；
- 在公开库上跑的时候（`is_public()`），模块不去读证据文件，改从 `pub_*` 表取（`replay_rows()`、`replay_json()`）。

记下的是模块自己算出的中间结果，不是另写一份逻辑：真实库上“现算”和公开库上“取回”走的是同一段后续代码。
哪几处、各记了什么，见 `PUBLIC.md`“随库带上的中间结果”。
"""
import json
import os
import sqlite3

PSEUDO_V4 = "240.0.0.0/4"       # 公开库里代理地址的假名段（pub_pseudo.py）；本来是保留地址，在公开库上要当公网地址看
RECORD_ENV = "PHASE1B_RECORD"


def is_public(con):
    """这个库是不是 pub_export.py 导出的公开库（meta 里有 public_version）。"""
    try:
        row = con.execute("SELECT value FROM meta WHERE key = 'public_version'").fetchone()
    except sqlite3.Error:
        return False
    return row is not None and row[0] not in (None, "")


def pseudo_v4(con):
    """公开库的假名地址段（CIDR 文本）；真实库返回 None。"""
    if not is_public(con):
        return None
    row = con.execute("SELECT value FROM meta WHERE key = 'public_pseudo_v4'").fetchone()
    return row[0] if row and row[0] else PSEUDO_V4


def _has_table(con, name):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


# ---------------------------------------------------------------- 取回（公开库）

def replay_rows(con, name, scope=None):
    """公开库里 pub_<name> 表的全部行（不含 scope 列）。表不存在，或给了 scope 而库里没有这个 scope 的行，都报错停下：
    公开库只带了默认参数那一次运行的结果，换了参数（例如正式起点）就取不到。"""
    table = "pub_" + name
    if not _has_table(con, table):
        raise SystemExit("公开库里没有 %s 表：这个库不是用当前版本的 pub_export.py 导出的" % table)
    cols = [r[1] for r in con.execute('PRAGMA table_info("%s")' % table)]
    keep = [c for c in cols if c != "scope"]
    sql = 'SELECT %s FROM "%s"' % (", ".join('"%s"' % c for c in keep), table)
    if "scope" in cols:
        scope = "" if scope is None else scope
        scopes = [r[0] for r in con.execute('SELECT DISTINCT scope FROM "%s"' % table)]
        if scope not in scopes:
            raise SystemExit("公开库的 %s 里没有这组参数的结果（要的是 %r，库里有 %r）。公开库只带了默认参数那一次运行的中间结果，"
                             "见 PUBLIC.md“随库带上的中间结果”" % (table, scope, scopes))
        return con.execute(sql + " WHERE scope = ? ORDER BY rowid", (scope,)).fetchall()
    return con.execute(sql + " ORDER BY rowid").fetchall()


def has_replay(con, name):
    """公开库里有没有 pub_<name> 表（真实库上那一步没有跑、没有记下结果时就没有）。"""
    return _has_table(con, "pub_" + name)


def replay_json(con, name, scope=None, missing_ok=False):
    """公开库里 pub_json 表中 name（和 scope）对应的那个 JSON 值，键的顺序与记下时相同。
    没有就报错停下；missing_ok=True 时返回 None（真实库上本来就可能没有这一项的，例如没给 --roots-note）。"""
    if not _has_table(con, "pub_json"):
        raise SystemExit("公开库里没有 pub_json 表：这个库不是用当前版本的 pub_export.py 导出的")
    row = con.execute("SELECT value FROM pub_json WHERE name = ? AND scope = ?", (name, "" if scope is None else scope)).fetchone()
    if row is None and missing_ok:
        return None
    if row is None:
        raise SystemExit("公开库的 pub_json 里没有 %s（scope=%r）。公开库只带了默认参数那一次运行的中间结果，"
                         "见 PUBLIC.md“随库带上的中间结果”" % (name, scope))
    return json.loads(row[0])


# ---------------------------------------------------------------- 记下（真实库）

class Recorder:
    """把模块算出的中间结果记进 PHASE1B_RECORD 指向的 SQLite 文件。没设这个环境变量时什么都不做。

    同一个 (name, scope) 可以被记多次（m_mitm 和 m_literature 都会做证书链校验）：内容必须逐行相同，不同就报错——
    两个模块对同一批证据得出不同结果，说明哪里不对，不能悄悄留下其中一份。"""

    def __init__(self, path=None):
        self.path = path if path is not None else os.environ.get(RECORD_ENV)
        self.con = None
        if self.path:
            self.con = sqlite3.connect(self.path)
            self.con.execute("CREATE TABLE IF NOT EXISTS rec_json (name TEXT, scope TEXT, value TEXT, PRIMARY KEY (name, scope))")
            self.con.execute("CREATE TABLE IF NOT EXISTS rec_tables (name TEXT, scope TEXT, columns TEXT, n INTEGER, PRIMARY KEY (name, scope))")

    @property
    def on(self):
        return self.con is not None

    def put_json(self, name, value, scope=None):
        if not self.on:
            return
        text = json.dumps(value, ensure_ascii=False)     # 不排序：键的顺序是内容的一部分（模块的输出照这个顺序写）
        scope = "" if scope is None else scope
        old = self.con.execute("SELECT value FROM rec_json WHERE name = ? AND scope = ?", (name, scope)).fetchone()
        if old is not None and old[0] != text:
            raise SystemExit("记录中间结果：%s（scope=%r）与已经记下的不一样" % (name, scope))
        self.con.execute("INSERT OR REPLACE INTO rec_json VALUES (?, ?, ?)", (name, scope, text))
        self.con.commit()

    def put_rows(self, name, columns, rows, scope=None):
        """rows 是可迭代的元组，列数与 columns 相同。行的顺序是内容的一部分。"""
        if not self.on:
            return
        scope = "" if scope is None else scope
        table = "rec_" + name
        cols_sql = ", ".join('"%s"' % c for c in columns)
        self.con.execute('CREATE TABLE IF NOT EXISTS "%s" (scope TEXT, seq INTEGER, %s)' % (table, cols_sql))
        rows = [tuple(r) for r in rows]
        old = self.con.execute("SELECT columns, n FROM rec_tables WHERE name = ? AND scope = ?", (name, scope)).fetchone()
        if old is not None:
            have = self.con.execute('SELECT %s FROM "%s" WHERE scope = ? ORDER BY seq' % (cols_sql, table), (scope,)).fetchall()
            if json.loads(old[0]) != list(columns) or have != rows:
                raise SystemExit("记录中间结果：%s（scope=%r）与已经记下的不一样（已有 %d 行，这次 %d 行）" % (name, scope, len(have), len(rows)))
            return
        self.con.executemany('INSERT INTO "%s" VALUES (?, ?, %s)' % (table, ", ".join("?" * len(columns))),
                             [(scope, i) + r for i, r in enumerate(rows)])
        self.con.execute("INSERT INTO rec_tables VALUES (?, ?, ?, ?)", (name, scope, json.dumps(list(columns)), len(rows)))
        self.con.commit()

    def close(self):
        if self.con is not None:
            self.con.close()
            self.con = None


# ---------------------------------------------------------------- 自检

def selftest():
    import sys
    import tempfile
    fails = []

    def expect(what, got, want):
        if got != want:
            fails.append("%s：得到 %r，期望 %r" % (what, got, want))

    with tempfile.TemporaryDirectory() as tmp:
        side = os.path.join(tmp, "rec.sqlite")
        r = Recorder(side)
        expect("给了路径就在记", r.on, True)
        r.put_rows("t", ["a", "b"], [(1, "x"), (2, None)], scope="s1")
        r.put_rows("t", ["a", "b"], [(1, "x"), (2, None)], scope="s1")      # 相同内容再记一次：允许
        r.put_json("j", {"k": [1, 2]})
        r.put_json("j", {"k": [1, 2]})
        for bad in (lambda: r.put_rows("t", ["a", "b"], [(1, "y"), (2, None)], scope="s1"), lambda: r.put_json("j", {"k": [1]})):
            try:
                bad()
                fails.append("内容不同的第二次记录应该报错")
            except SystemExit:
                pass
        r.close()
        expect("没给路径就不记", Recorder(None if RECORD_ENV not in os.environ else "").on, False)

        db = os.path.join(tmp, "pub.sqlite")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE meta (key TEXT, value TEXT)")
        expect("没有 public_version 就不是公开库", is_public(con), False)
        expect("真实库没有假名地址段", pseudo_v4(con), None)
        con.execute("INSERT INTO meta VALUES ('public_version', '1')")
        expect("有 public_version 就是公开库", is_public(con), True)
        expect("假名地址段默认值", pseudo_v4(con), PSEUDO_V4)
        con.execute("CREATE TABLE pub_t (scope TEXT, a INTEGER, b TEXT)")
        con.executemany("INSERT INTO pub_t VALUES (?, ?, ?)", [("s1", 1, "x"), ("s1", 2, None), ("s2", 9, "z")])
        con.execute("CREATE TABLE pub_json (name TEXT, scope TEXT, value TEXT)")
        con.execute("INSERT INTO pub_json VALUES ('j', '', '{\"k\": [1, 2]}')")
        expect("按 scope 取回", replay_rows(con, "t", "s1"), [(1, "x"), (2, None)])
        expect("取回 JSON", replay_json(con, "j"), {"k": [1, 2]})
        expect("没有的 JSON：missing_ok", replay_json(con, "nope", missing_ok=True), None)
        expect("有没有这张表", (has_replay(con, "t"), has_replay(con, "nope")), (True, False))
        for bad in (lambda: replay_rows(con, "t", "s3"), lambda: replay_rows(con, "nope"), lambda: replay_json(con, "nope")):
            try:
                bad()
                fails.append("取不到应该报错停下")
            except SystemExit:
                pass
        con.close()
    for f in fails:
        print("不符：" + f, file=sys.stderr)
    print("pubdb 自检：%s" % ("通过" if not fails else "%d 项不符" % len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(selftest())
