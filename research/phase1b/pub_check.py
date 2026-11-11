#!/usr/bin/env python3
"""公开库的两项检查（决策 D16，`PUBLIC.md`）。只用标准库。

    python3 pub_check.py compare <公开库上重算的输出目录> out/       # 第三方也能跑
    python3 pub_check.py scan <公开库> --real <真实库> [--report 文件]  # 发布前在真实库旁边跑；只打印计数
    python3 pub_check.py linkage --real <真实库> [--write 文件]         # 假名能被公开列表的历史对回去的比例

compare：逐个文件比对。JSON 按结构逐项比，report.md 逐行比。允许的差别只有 `ALLOWED`、`ALLOWED_ORDER`、`ALLOWED_TIES` 里列出的那几处（每处写了原因，
PUBLIC.md“必然不同的字段”是同一张清单）；清单之外有一处不同就以非零退出，并列出路径。

scan：把真实库里的身份信息（judge 的主机名和地址、代理和节点的真实地址与主机名、证据哈希、叶子证书哈希……）收集起来，
到公开库的每一张表、每一列的每个不同值里找：整值相等、按记号切开以后相等、judge 的名字和地址按子串找；
另外，任何不在假名段里的公网 IPv4、任何没有点名的真实 /24 都算残留。命中一处就以非零退出。打印的只有计数和表名列名，
不打印命中的值。
"""
import argparse
import collections
import ipaddress
import json
import os
import re
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pub_pseudo  # noqa: E402

# ---------------------------------------------------------------- compare

# 允许的差别：(文件名, JSON 路径的正则（report.md 用行的正则）, 原因)。路径写法：/键/键/[序号]
ALLOWED = [
    ("*.json", r"/generated_utc", "生成时刻：每次运行都不同"),
    ("lifetime.json", r"/seconds", "模块自己的运行用时"),
    ("freshness.json", r"/seconds", "模块自己的运行用时"),
    ("instrument.json", r"/preflight/source",
     "真实库上 preflight.txt 是按 meta.data_dir 找到的（\"data_dir\"），公开库没有本机路径，由 run_public.sh 用 --preflight 给（\"argument\"）"),
    ("report.md", r"^\| .+ \| [a-z_]+\.json \| \d{4}-\d{2}-\d{2}T[\d:.]+Z \|",
     "报告开头“各模块的输出”表里每个模块的生成时刻（同 generated_utc）"),
]

# 允许“键相同、只是顺序不同”的地方：模块按候选键排序逐个处理、按先遇到的顺序建字典；候选键换成假名以后排序变了
ALLOWED_ORDER = [
    ("freshness.json", r"^/n/上榜事件（候选层面，按种类）$",
     "m_freshness.Replay 按 cand 排序重放 list_event，各种上榜事件按先遇到的顺序成为键；假名的排序与真实地址不同"),
]

# 允许“名次并列的条目之间顺序不同”的列表：(文件名, 列表的路径, 排序用的键, 原因)。比对时把两边并列的条目按内容排好再比，
# 条目本身（除了名次）和每个名次上的排序值都必须相同
ALLOWED_TIES = [
    ("posthoc.json", ("replaced_bodies", "前 10 种"), "尝试",
     "m_posthoc.replaced_bodies 按尝试数排序（ORDER BY n DESC），尝试数相同的正文按证据哈希的顺序排；证据哈希换成假名以后，并列的几种正文先后不同"),
]


def _untie(obj, path, key):
    """把 obj 里 path 指向的列表中排序值相同的相邻条目按内容排好，名次照原位置不动。返回改过的副本和有没有动过。"""
    obj = json.loads(json.dumps(obj))
    cur = obj
    for k in path[:-1]:
        cur = cur.get(k) if isinstance(cur, dict) else None
        if cur is None:
            return obj
    lst = cur.get(path[-1]) if isinstance(cur, dict) else None
    if not isinstance(lst, list):
        return obj
    out, i = [], 0
    while i < len(lst):
        j = i
        while j < len(lst) and lst[j].get(key) == lst[i].get(key):
            j += 1
        group = sorted(lst[i:j], key=lambda e: json.dumps({k: v for k, v in e.items() if k != "名次"}, ensure_ascii=False, sort_keys=True))
        for pos, e in zip(range(i, j), group):
            e = dict(e)
            if "名次" in e:
                e["名次"] = lst[pos].get("名次")
            out.append(e)
        i = j
    cur[path[-1]] = out
    return obj


def _allowed_order(fname, path):
    return any(pat == fname and re.search(rx, path) for pat, rx, _why in ALLOWED_ORDER)


def _allowed(fname, path):
    for pat, rx, _why in ALLOWED:
        if (pat == fname or (pat.startswith("*") and fname.endswith(pat[1:]))) and re.search(rx, path):
            return True
    return False


def diff_json(a, b, path=""):
    """a、b 的不同之处：[(路径, 说明)]。字典比键（顺序也比：输出的键序是内容的一部分），列表逐项比。"""
    if type(a) is not type(b):
        return [(path, "类型不同")]
    if isinstance(a, dict):
        out = []
        if list(a) != list(b):
            ka, kb = set(a), set(b)
            if ka != kb:
                for k in sorted(ka - kb, key=str):
                    out.append(("%s/%s" % (path, k), "只在新输出里"))
                for k in sorted(kb - ka, key=str):
                    out.append(("%s/%s" % (path, k), "只在仓库版本里"))
            else:
                out.append((path, "键的顺序不同"))
        for k in a:
            if k in b:
                out += diff_json(a[k], b[k], "%s/%s" % (path, k))
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [(path, "长度不同（%d / %d）" % (len(a), len(b)))]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff_json(x, y, "%s/[%d]" % (path, i))
        return out
    return [] if a == b else [(path, "值不同")]


def compare(new_dir, ref_dir):
    names = sorted(n for n in os.listdir(ref_dir) if n.endswith(".json") or n.endswith(".md"))
    bad, ok_diffs, same_bytes = [], collections.Counter(), 0
    for n in names:
        pa, pb = os.path.join(new_dir, n), os.path.join(ref_dir, n)
        if not os.path.exists(pa):
            bad.append((n, "", "新输出里没有这个文件"))
            continue
        with open(pa, "rb") as f:
            ba = f.read()
        with open(pb, "rb") as f:
            bb = f.read()
        if ba == bb:
            same_bytes += 1
            continue
        if n.endswith(".json"):
            ja, jb = json.loads(ba), json.loads(bb)
            for fname, path, key, _why in ALLOWED_TIES:
                if fname == n:
                    before = len(diff_json(ja, jb))
                    ja, jb = _untie(ja, path, key), _untie(jb, path, key)
                    if len(diff_json(ja, jb)) != before:
                        ok_diffs[(n, "/" + "/".join(path) + "（并列名次的顺序）")] += 1
            diffs = diff_json(ja, jb)
        else:
            la, lb = ba.decode("utf-8").split("\n"), bb.decode("utf-8").split("\n")
            if len(la) != len(lb):
                diffs = [("", "行数不同（%d / %d）" % (len(la), len(lb)))]
            else:
                diffs = []
                for i, (x, y) in enumerate(zip(la, lb)):
                    if x == y:
                        continue
                    if _allowed(n, x) and _allowed(n, y):
                        ok_diffs[(n, "（清单里的行）")] += 1
                    else:
                        diffs.append(("第 %d 行" % (i + 1), "行不同"))
        for p, what in diffs:
            if n.endswith(".json") and ((what == "值不同" and _allowed(n, p)) or (what == "键的顺序不同" and _allowed_order(n, p))):
                ok_diffs[(n, re.sub(r"\[\d+\]", "[]", p) + ("（键的顺序）" if what == "键的顺序不同" else ""))] += 1
            else:
                bad.append((n, p, what))
        if not diffs and n.endswith(".json") and not any(k[0] == n for k in ok_diffs):
            ok_diffs[(n, "（只是格式：内容相同）")] += 1
    print("逐字节相同的文件：%d / %d" % (same_bytes, len(names)))
    for (n, p), c in sorted(ok_diffs.items()):
        print("  清单里的差别：%s %s（%d 处）" % (n, p, c))
    for n, p, what in bad[:200]:
        print("清单之外的差别：%s %s %s" % (n, p, what))
    if len(bad) > 200:
        print("……清单之外的差别一共 %d 处" % len(bad))
    print("结论：%s" % ("只有清单里的差别" if not bad else "有 %d 处清单之外的差别" % len(bad)))
    return 1 if bad else 0


# ---------------------------------------------------------------- scan

TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*[A-Za-z0-9]|[A-Za-z0-9]")
IPV4_TOKEN = re.compile(r"(?<![\d./])(?:\d{1,3}\.){3}\d{1,3}(?!\d|/24)")   # 前面是 "/" 的不算（浏览器版本号 Chrome/120.0.0.0）
P24_TOKEN = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}0)/24\b")


def _distinct(con, table, col):
    return con.execute('SELECT DISTINCT "%s" FROM "%s" WHERE "%s" IS NOT NULL' % (col, table, col))


def _cols(con, table):
    return [r[1] for r in con.execute('PRAGMA table_info("%s")' % table)]


def _tables(con):
    return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]


def collect_secrets(real):
    """真实库里不许出现在公开库里的值。返回 (exact: 值 → 种类, judge_sub: 要按子串找的值, real24: 真实 /24 集合)。"""
    exact = {}
    have = set(_tables(real))

    def add(kind, table, col, lower=False, minlen=1):
        if table not in have or col not in _cols(real, table):
            return
        n = 0
        for (v,) in _distinct(real, table, col):
            if isinstance(v, str) and len(v) >= minlen:
                exact.setdefault(v.lower() if lower else v, kind)
                n += 1
        return n

    for t, c in (("cands", "ip"), ("att", "cand_ip"), ("att", "ip"), ("visit", "cand_ip"), ("list_event", "cand_ip"), ("agg_member", "cand_ip"),
                 ("npre_ip", "ip"), ("req", "remote"), ("noise", "remote"), ("tls_fail", "remote"), ("req_dropped", "remote"),
                 ("noise_dropped", "remote")):
        add("真实地址", t, c)
    for t, c in (("cands", "key"), ("att", "cand"), ("list_event", "cand"), ("agg_member", "cand")):
        add("真实 ip:port", t, c)
    add("节点入口", "node", "host", lower=True)
    add("节点编号", "node", "id")
    for t, c in (("evidence", "hash"), ("att", "ev"), ("att", "http_ev"), ("att", "http_sha")):
        add("证据/正文哈希", t, c, minlen=16)
    for t, c in (("att", "tls_leaf"), ("self_leaf", "leaf")):
        add("叶子证书哈希", t, c, minlen=16)
    add("judge 的地址", "self_ips", "ip")
    add("judge 的名字", "self_names", "name", lower=True)
    for t in ("req", "noise", "tls_fail"):
        add("Host/SNI 原文", t, "host", lower=True, minlen=4)
        add("Host/SNI 原文", t, "sni", lower=True, minlen=4)
    meta = dict(real.execute("SELECT key, value FROM meta")) if "meta" in have else {}
    for k in ("judge_host_sha8", "judge_ip_sha8"):
        for v in json.loads(meta.get(k) or "[]"):
            exact.setdefault(v, "judge 的 sha8")
    for k in ("judge_leaf_pem_sha256",):
        if meta.get(k):
            exact.setdefault(meta[k], "叶子证书哈希")
    if "start" in have:
        for (v,) in _distinct(real, "start", "payload_sha256"):
            d = json.loads(v)
            for x in (d.values() if isinstance(d, dict) else [d]):
                if isinstance(x, str) and len(x) >= 16:
                    exact.setdefault(x, "载荷哈希")
    for k in ("data_dir", "state_file", "sources_file"):
        if meta.get(k):
            exact.setdefault(meta[k], "本机路径")
    # 不算身份的值：保留地址（私网、回环、组播等，公开库里原样留着）、对照组的名字（control:…，探测器自己的）、不到 8 位的纯数字（会与计数撞上）
    for v in list(exact):
        host = v.rpartition(":")[0] if v.count(":") == 1 else v
        a = pub_pseudo._parse(host.strip("[]"))
        judge_private = exact[v] == "judge 的地址" and a is not None and not a.is_loopback   # judge 在 NAT 后的私网地址也算身份
        if ((a is not None and a.version == 4 and pub_pseudo._reserved(a)) or v.startswith("control:") or (v.isdigit() and len(v) < 8)) and not judge_private:
            del exact[v]
    judge_sub = [v for v, kind in exact.items() if kind in ("judge 的名字", "judge 的地址") and v not in ("127.0.0.1", "::1")]
    # judge 的名字去掉端口、末尾的点
    judge_sub = sorted({j.rsplit(":", 1)[0] if j.count(":") == 1 else j for j in judge_sub} | {j.rstrip(".") for j in judge_sub})
    real24 = set()
    for t in ("cands", "att", "list_event"):
        if t in have and "prefix24" in _cols(real, t):
            real24 |= {v for (v,) in _distinct(real, t, "prefix24")}
    return exact, judge_sub, real24


def scan(pub_path, real_path, report=None, named_from=None):
    pub = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(pub_path), uri=True)
    real = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(real_path), uri=True)
    if pub.execute("SELECT value FROM meta WHERE key = 'public_version'").fetchone() is None:
        raise SystemExit("--pub 给的不是公开库")
    exact, judge_sub, real24 = collect_secrets(real)
    # out/ 里已经点了名的 /24（公开库的 prefix24 列里原样留着）：只有这些真实 /24 允许出现
    import pub_export
    named24 = set(pub_export.named_prefixes(named_from or os.path.join(HERE, "out")))
    print("收集到的身份值：%d 个（%s）；judge 的名字和地址按子串找：%d 个；真实 /24：%d 个，其中点了名的：%d 个"
          % (len(exact), "、".join("%s %d" % (k, n) for k, n in collections.Counter(exact.values()).most_common()), len(judge_sub),
             len(real24), len(named24 & real24)))
    hits = collections.Counter()
    cells = 0
    for t in _tables(pub):
        for c in _cols(pub, t):
            for (v,) in _distinct(pub, t, c):
                if not isinstance(v, str):
                    continue
                cells += 1
                # out/ 里点了名的真实 /24 原样留着：先拿掉，免得它的网络地址被当成一个真实地址
                v = P24_TOKEN.sub(lambda m: "<p24>" if m.group(0) in named24 else m.group(0), v)
                low = v.lower()
                if v in exact or low in exact:
                    hits[(t, c, "整值是" + exact.get(v, exact.get(low)))] += 1
                    continue
                for tok in TOKEN.findall(v):
                    kind = exact.get(tok) or exact.get(tok.lower())
                    if kind:
                        hits[(t, c, "含" + kind)] += 1
                        break
                for j in judge_sub:
                    if j in low:
                        hits[(t, c, "含 judge 的名字或地址（子串）")] += 1
                        break
                for ip in IPV4_TOKEN.findall(v):
                    try:
                        a = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if a.version == 4 and not pub_pseudo._reserved(a):
                        hits[(t, c, "含假名段以外的公网 IPv4")] += 1
                        break
                for p in P24_TOKEN.findall(v):
                    p24 = p + "/24"
                    if p24 in real24 and p24 not in named24 and not pub_pseudo._reserved(ipaddress.ip_address(p)):
                        hits[(t, c, "含没有点名的真实 /24")] += 1
                        break
    print("扫描了 %d 张表的 %d 个不同文本值" % (len(_tables(pub)), cells))
    for (t, c, what), n in sorted(hits.items()):
        print("  命中：%s.%s %s（%d 个不同值）" % (t, c, what, n))
    print("结论：%s" % ("没有发现残留" if not hits else "有 %d 处残留" % sum(hits.values())))
    if report:
        with open(report, "w", encoding="utf-8") as f:
            json.dump({"身份值": dict(collections.Counter(exact.values())), "扫描的不同文本值": cells,
                       "命中": [{"表": t, "列": c, "类别": w, "不同值": n} for (t, c, w), n in sorted(hits.items())]},
                      f, ensure_ascii=False, indent=1)
    return 1 if hits else 0


def linkage(real_path, write=None):
    """假名挡不住的那一种对照（PUBLIC.md“挡不住什么”）：列表来源都是公开的 GitHub 仓库、有提交历史。
    公开库里每个候选在 list_event 里留下的是“端口 + 在哪个来源、哪次快照上榜或下榜”，这串记录就是它的指纹；
    指纹在全部候选里独一无二的，任何人拿列表的历史版本都能把假名对回真实的 ip:port。这里数一数有多少是独一无二的。
    只用真实库里的 list_event（公开库里同样的列都在），只输出计数。"""
    con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(real_path), uri=True)
    fps = {}
    cur = None
    for cand, port, src, event, ts in con.execute(
            "SELECT cand, cand_port, src, event, ts FROM list_event WHERE cand IS NOT NULL ORDER BY cand, src, event, ts"):
        if cand != cur:
            cur = cand
            fps[cand] = [port, []]
        fps[cand][1].append((src, event, ts))
    with_port = collections.Counter((p, tuple(ev)) for p, ev in fps.values())
    no_port = collections.Counter(tuple(ev) for _p, ev in fps.values())
    n = len(fps)
    uniq = sum(1 for p, ev in fps.values() if with_port[(p, tuple(ev))] == 1)
    le5 = sum(1 for p, ev in fps.values() if with_port[(p, tuple(ev))] <= 5)
    uniq_np = sum(1 for _p, ev in fps.values() if no_port[tuple(ev)] == 1)
    srcs = [r[0] for r in con.execute("SELECT DISTINCT src FROM list_event ORDER BY src")]
    out = collections.OrderedDict([
        ("说明", "每个候选的指纹 = 端口 + 它在 list_event 里的全部（来源, 上榜/下榜, 快照时刻）。指纹独一无二的候选，"
                 "拿公开列表的历史版本就能把假名对回真实地址"),
        ("list_event 里的候选", n),
        ("来源", len(srcs)),
        ("指纹独一无二的", uniq), ("独一无二的比例", round(uniq / n, 4) if n else None),
        ("指纹至多与 4 个别的候选相同的", le5), ("至多 5 个共用的比例", round(le5 / n, 4) if n else None),
        ("不算端口时独一无二的", uniq_np), ("不算端口时的比例", round(uniq_np / n, 4) if n else None),
    ])
    text = json.dumps(out, ensure_ascii=False, indent=1) + "\n"
    print(text, end="")
    if write:
        with open(write, "w", encoding="utf-8") as f:
            f.write(text)
    return 0


def main():
    ap = argparse.ArgumentParser(description="公开库的检查（PUBLIC.md）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("compare", help="公开库上重算的输出与仓库里的 out/ 比对")
    a.add_argument("new_dir")
    a.add_argument("ref_dir")
    b = sub.add_parser("scan", help="在公开库里找真实库的身份信息")
    b.add_argument("pub")
    b.add_argument("--real", required=True)
    b.add_argument("--report")
    b.add_argument("--named-from", help="点了名的 /24 从哪个目录的输出里收集（默认本目录 out/，与导出时相同）")
    c = sub.add_parser("linkage", help="数一数假名能被公开列表的历史对回去的比例（真实库）")
    c.add_argument("--real", required=True)
    c.add_argument("--write")
    args = ap.parse_args()
    if args.cmd == "linkage":
        return linkage(args.real, args.write)
    if args.cmd == "compare":
        return compare(args.new_dir, args.ref_dir)
    return scan(args.pub, args.real, args.report, args.named_from)


if __name__ == "__main__":
    raise SystemExit(main())
