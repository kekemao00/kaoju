#!/usr/bin/env python3
"""看过 72 小时数据以后加的分析（决策 D14）：把主要比例从“候选（ip:port）”换成“IP”再算一遍，并拆开“整页替换”和经 Cloudflare 转发的请求。

用法：
    python3 m_posthoc.py --db <sqlite> --out <目录> [--markdown] [--formal-start auto|first|<ISO 时间>] [--dense-threshold 100]
    python3 m_posthoc.py --selftest

为什么要加：PROTOCOL 的单位是候选（ip:port）。真实数据里少数 IP 各开了几十到几百个端口，每个端口都是一个候选，
于是“中间人候选占隧道建立过的候选 43%”这类数字主要由几百个 IP 决定。文献的“代理”多数也是 ip:port，
但它们的列表没有这么集中，所以对账时还要看按 IP 的数字。这些都是事后加的，报告里与原定口径分开写，不替换原定口径。

本模块只读 ingest.py 建好的库（mode=ro），结果写到 <目录>/posthoc.json。分类规则不另写：
内容被改、带出客户端地址都用同目录 m_integrity.build_tables 建的表（aj、pc），中间人用原定义（tls_class='tls_cert_invalid'）。
每个比例都给分子、分母和口径。只用 Python 3.10+ 标准库。

各节（口径细节见 DEFINITIONS）：
- concentration：每个 IP 有几个候选（端口），按桶给 IP 数和候选数；可用过的、遇到中间人的、正文不符的候选各自的集中度。
- funnel_by_ip：按 IP 的漏斗（探访过 → 连得上 → 有协议回应 → 可用过），全部候选与常规列表两组，各带去掉候选密集 /24 的一组。
- mitm_by_ip：隧道建立过的 IP 里遇到过中间人的比例。
- content_by_ip：经 HTTP 转发取回过 HTML 测试页（状态 200）的 IP 里正文不符的比例，按截断 / 局部改动 / 整页替换分。
- leak_by_ip：经 HTTP 转发成功、judge 收到的请求里带出探测器地址的 IP 比例。
- replaced_bodies：整页替换的正文按证据哈希归并，前几种各占多少、来自多少个 IP（只给名次和计数，不输出哈希）。
- cloudflare：judge 收到的转发请求里带 Cf-Connecting-Ip 头的（请求经 Cloudflare 转发）占多少请求、候选、IP。
"""
import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import m_integrity as mi  # noqa: E402  分类规则、DB、窗口、输出检查都用它的
import pubdb  # noqa: E402  真实库与公开库之间的接缝（PUBLIC.md）
import m_mitm as mm  # noqa: E402  证书名字的解析（dn_get）和地址正则

MODULE = "m_posthoc"
OUTPUT_NAME = "posthoc.json"
DENSE_THRESHOLD = 100
TUNNEL_PROTOS = ("socks5", "socks4", "connect")
PORT_BUCKETS = [(1, 1, "1"), (2, 9, "2-9"), (10, 99, "10-99"), (100, None, "100+")]
TOP_BODIES = 10

DEFINITIONS = {
    "事后": "本模块的全部内容都是看过 72 小时数据以后加的（决策 D14），与 PROTOCOL 原定口径分开报告，不替换原定口径。",
    "IP": "候选键 ip:port 里的 IP（att.cand_ip）。一个 IP 有几个候选，就是列表里出现过它的几个端口。",
    "按 IP 的布尔值": "IP 下任一候选满足条件，这个 IP 就算满足（例：任一端口可用过，IP 就算可用过）。",
    "尝试的范围": "正式起点之后、class 不含 canceled、cand_kind='proxy' 的尝试（与 m_availability / m_integrity 相同）。",
    "连得上 / 有协议回应 / 可用过": "与 m_availability 的 ac 表同一组表达式：tcp_ok；hs_ok 或收到握手/HTTP 状态码；class='ok' 且目的地是 judge。",
    "常规列表": "候选在窗口内任何一次（非 aborted）探访里 group=0（sched.go Upsert：group 只会从 1 改成 0）。按 IP 的常规列表组只用常规候选。",
    "中间人": "PROTOCOL 原定义：隧道协议（socks5/socks4/connect）到 judge_tls 的尝试里 tls_class='tls_cert_invalid'。"
              "分母“隧道建立过”= 同一范围里 hs_ok=1 过。三层细分见 m_mitm，这里不再细分。",
    "正文不符": "m_integrity.build_tables 的 pc 表（summary.go BodyChange 规则）：proxy、proto='forward'、dst='judge_http'、kind='h'（HTML）、"
               "状态 200。分母是这样取回过测试页的 IP。",
    "带出探测器地址": "m_integrity.build_tables 的 aj 表：proxy、proto='forward'、dst='judge_http'、class='ok'、judge 收到（seen=1），"
                   "anon='transparent'（任一非 Host 请求头的值含探测器的公网地址）。",
    "整页替换的正文": "pc 表里 body_change='正文被整页替换' 的尝试按证据哈希（pc.ev）归并；没有存证据的（超过存储上限）单列。"
                  "只输出名次、计数和长度，不输出哈希和正文。",
    "Cloudflare": "judge 收到的第一份请求（m_integrity 的 rq_first）里有 Cf-Connecting-Ip 头。代理把请求交给了 Cloudflare 的网络，"
                  "judge 看到的源地址按这个头推断是 Cloudflare 的（没有与 Cloudflare 公布的地址段核对）。只统计，不判断代理的性质。"
                  "另在同一范围里把 Accept-Encoding 被改（m_integrity 的 accept_encoding_changed：最后一个 Accept-Encoding 头的值不是 identity）"
                  "与经 Cloudflare 交叉，看请求头被改是不是 Cloudflare 那一段做的。",
    "judge 说明页": "judge 对“/”回的说明页（judge.go infoPage()）。整页替换的正文从证据文件读出，开头与说明页模板里联系方式之前的固定部分逐字节相同的，"
                   "就是代理把请求路径丢了、向 judge 要了“/”。judge 一侧另数收到的 GET /（noise 记录），按 Host 是否是 judge 自己的名字和 HTTP 版本分。",
    "中间人的两群": "遇到过中间人的 IP 按它在列表里有没有 100 个以上候选（端口）分两群。签发者组织取中间人证书 tls_issuer 的 O=。"
                 "给了 --aws-ranges（AWS 公布的 ip-ranges.json）时，数落在其中的 IP 和区域数；文件的 syncToken 和 createDate 一并输出，便于复现。",
    "候选密集的 /24": "m_integrity.build_tables 的 dense24（候选超过阈值的 /24，PROTOCOL 1.2）。excluding_dense 去掉这些 /24 里的 IP。",
}


def ratio(num, den):
    return mi.ratio(num, den)


def ip_expr(col="cand"):
    """从候选键取 IP（只处理 IPv4：探测器跳过 IPv6，sched.go ineligible）。"""
    return "substr(%s, 1, instr(%s, ':') - 1)" % (col, col)


def dense_cond(alias, exclude_dense):
    return (" AND %s.prefix24 NOT IN (SELECT prefix24 FROM dense24)" % alias) if exclude_dense else ""


# ---------------------------------------------------------------- 中间表

def build(db, fs):
    """pa：每个代理候选一行（IP、/24、是否常规、连得上、有回应、可用过、隧道建立过、遇到中间人）。只扫 att 一遍。"""
    db.x("""CREATE TEMP TABLE pa AS
            SELECT cand, cand_ip AS ip, prefix24,
                   MAX(COALESCE(tcp_ok, 0)) AS tcp,
                   MAX(CASE WHEN COALESCE(hs_ok, 0) = 1 OR hs_code IS NOT NULL OR http_code IS NOT NULL THEN 1 ELSE 0 END) AS resp,
                   MAX(CASE WHEN class = 'ok' AND dst IN ('judge_tls', 'judge_http') THEN 1 ELSE 0 END) AS ok,
                   MAX(CASE WHEN proto IN (%(t)s) AND dst = 'judge_tls' AND COALESCE(hs_ok, 0) = 1 THEN 1 ELSE 0 END) AS tun,
                   MAX(CASE WHEN proto IN (%(t)s) AND dst = 'judge_tls' AND class = 'ok' THEN 1 ELSE 0 END) AS tun_ok,
                   MAX(CASE WHEN proto IN (%(t)s) AND dst = 'judge_tls' AND tls_class = 'tls_cert_invalid' THEN 1 ELSE 0 END) AS mitm
            FROM att
            WHERE cand_kind = 'proxy' AND ts_epoch >= ? AND COALESCE(class, '') NOT LIKE '%%canceled%%'
            GROUP BY +cand""" % {"t": mi.sql_in(TUNNEL_PROTOS)}, (fs,))
    db.x("CREATE INDEX temp.pa_cand ON pa(cand)")
    db.x("CREATE INDEX temp.pa_ip ON pa(ip)")
    # 常规列表：窗口内任何一次非 aborted 探访 group=0
    db.x("""CREATE TEMP TABLE reg AS SELECT DISTINCT cand FROM visit
            WHERE ts_epoch >= ? AND COALESCE(aborted, 0) = 0 AND COALESCE("group", 0) = 0""", (fs,))
    db.x("CREATE INDEX temp.reg_cand ON reg(cand)")
    db.x("ALTER TABLE pa ADD COLUMN regular INTEGER")
    db.x("UPDATE pa SET regular = (cand IN (SELECT cand FROM reg))")
    db.x("CREATE TEMP TABLE ipn AS SELECT ip, COUNT(*) AS n FROM pa GROUP BY ip")
    db.x("CREATE INDEX temp.ipn_ip ON ipn(ip)")
    # 正文：proxy、HTTP 转发、HTML、200（pc 来自 m_integrity.build_tables）
    db.x("""CREATE TEMP TABLE pcf AS
            SELECT cand, %s AS ip, prefix24, body_change, ev, len FROM pc
            WHERE cand_kind = 'proxy' AND proto = 'forward' AND dst = 'judge_http' AND kind = 'h' AND http_code = 200 AND in_win = 1"""
         % ip_expr())
    db.x("CREATE INDEX temp.pcf_ip ON pcf(ip)")
    # 带出探测器地址：proxy、HTTP 转发、class=ok、judge 收到（aj 来自 m_integrity.build_tables）
    db.x("""CREATE TEMP TABLE ajf AS
            SELECT a.cand, a.cand_ip AS ip, a.prefix24, a.anon, a.nonce, r.req_rid, COALESCE(r.t_accept_encoding_changed, 0) AS aenc_changed
            FROM aj a LEFT JOIN rd r ON r.nonce = a.nonce
            WHERE a.cand_kind = 'proxy' AND a.proto = 'forward' AND a.dst = 'judge_http' AND a.class = 'ok' AND a.seen = 1 AND a.in_win = 1""")
    db.x("CREATE INDEX temp.ajf_ip ON ajf(ip)")
    db.x("CREATE INDEX temp.ajf_rid ON ajf(req_rid)")


# ---------------------------------------------------------------- 各节

def concentration(db):
    """每个 IP 的候选数分桶。subset 是 pa 上的条件（候选层面），IP 的候选数按该子集里的候选数算。"""
    def buckets(subset):
        db.x("DROP TABLE IF EXISTS temp.cc")
        db.x("CREATE TEMP TABLE cc AS SELECT ip, COUNT(*) AS n FROM pa WHERE %s GROUP BY ip" % subset)
        tot_ip, tot_c = db.one("SELECT COUNT(*), COALESCE(SUM(n), 0) FROM cc")
        out = {"IP": int(tot_ip), "候选": int(tot_c), "按每个 IP 的候选数": {}}
        for lo, hi, name in PORT_BUCKETS:
            cond = "n >= %d" % lo + ("" if hi is None else " AND n <= %d" % hi)
            n_ip, n_c = db.one("SELECT COUNT(*), COALESCE(SUM(n), 0) FROM cc WHERE " + cond)
            out["按每个 IP 的候选数"][name] = {"IP": int(n_ip), "候选": ratio(n_c, tot_c)}
        n_c10 = db.scalar("SELECT COALESCE(SUM(n), 0) FROM cc WHERE n >= 10")
        out["候选里属于有 10 个以上候选的 IP 的"] = ratio(n_c10, tot_c)
        out["候选最多的一个 IP 的候选数"] = int(db.scalar("SELECT COALESCE(MAX(n), 0) FROM cc"))
        top = db.q("SELECT n FROM cc ORDER BY n DESC LIMIT 20")
        out["候选最多的 20 个 IP 合计占候选"] = ratio(sum(r[0] for r in top), tot_c)
        return out
    return {
        "探访过的代理候选": buckets("1"),
        "常规列表的候选": buckets("regular = 1"),
        "可用过的候选": buckets("ok = 1"),
        "遇到过中间人的候选": buckets("mitm = 1"),
        "正文不符过的候选（HTTP 转发、HTML、200）": _content_conc(db),
    }


def _content_conc(db):
    db.x("DROP TABLE IF EXISTS temp.cc2")
    db.x("""CREATE TEMP TABLE cc2 AS SELECT ip, COUNT(DISTINCT cand) AS n FROM pcf WHERE body_change IS NOT NULL GROUP BY ip""")
    tot_ip, tot_c = db.one("SELECT COUNT(*), COALESCE(SUM(n), 0) FROM cc2")
    n_c10 = db.scalar("SELECT COALESCE(SUM(n), 0) FROM cc2 WHERE n >= 10")
    return {"IP": int(tot_ip), "候选": int(tot_c), "候选里属于有 10 个以上这类候选的 IP 的": ratio(n_c10, tot_c),
            "候选最多的一个 IP 的候选数": int(db.scalar("SELECT COALESCE(MAX(n), 0) FROM cc2"))}


def funnel_by_ip(db, regular_only, exclude_dense):
    base = "FROM pa p WHERE 1%s%s" % (" AND p.regular = 1" if regular_only else "", dense_cond("p", exclude_dense))
    n_c, c_tcp, c_resp, c_ok = db.one("SELECT COUNT(*), SUM(tcp), SUM(resp), SUM(ok) " + base)
    db.x("DROP TABLE IF EXISTS temp.fi")
    db.x("CREATE TEMP TABLE fi AS SELECT p.ip, MAX(tcp) AS tcp, MAX(resp) AS resp, MAX(ok) AS ok " + base + " GROUP BY p.ip")
    n_ip, i_tcp, i_resp, i_ok = db.one("SELECT COUNT(*), SUM(tcp), SUM(resp), SUM(ok) FROM fi")
    return {
        "按候选（对照）": {"探访过": int(n_c or 0), "连得上过": ratio(c_tcp, n_c), "有协议回应过": ratio(c_resp, n_c), "可用过": ratio(c_ok, n_c)},
        "按 IP": {"探访过": int(n_ip or 0), "连得上过": ratio(i_tcp, n_ip), "有协议回应过": ratio(i_resp, n_ip), "可用过": ratio(i_ok, n_ip)},
    }


def mitm_by_ip(db, exclude_dense):
    d = dense_cond("p", exclude_dense)
    c = db.one("SELECT SUM(tun), SUM(mitm), SUM(tun_ok OR mitm) FROM pa p WHERE 1" + d)
    db.x("DROP TABLE IF EXISTS temp.mi_ip")
    db.x("""CREATE TEMP TABLE mi_ip AS SELECT p.ip, MAX(tun) AS tun, MAX(tun_ok) AS tun_ok, MAX(mitm) AS mitm
            FROM pa p WHERE 1%s GROUP BY p.ip""" % d)
    i = db.one("SELECT SUM(tun), SUM(mitm), SUM(tun_ok OR mitm), SUM(mitm AND tun_ok) FROM mi_ip")
    return {
        "按候选（对照）": {"隧道建立过": int(c[0] or 0), "遇到过中间人 / 隧道建立过": ratio(c[1], c[0]),
                                    "遇到过中间人 / 隧道曾可用或遇到过中间人": ratio(c[1], c[2])},
        "按 IP": {"隧道建立过": int(i[0] or 0), "遇到过中间人 / 隧道建立过": ratio(i[1], i[0]),
                 "遇到过中间人 / 隧道曾可用或遇到过中间人": ratio(i[1], i[2]),
                 "遇到过中间人的 IP 里也有过正常 TLS 隧道（证书是 judge 的、走完全程）的": ratio(i[3], i[1])},
    }


def content_by_ip(db, exclude_dense):
    d = dense_cond("f", exclude_dense)
    kinds = [mi.BODY_KINDS[0], mi.BODY_KINDS[1], mi.BODY_KINDS[2]] if hasattr(mi, "BODY_KINDS") else \
        ["正文被截断", "正文被局部改动（注入或改写）", "正文被整页替换"]
    n_ip, n_any = db.one("SELECT COUNT(DISTINCT ip), COUNT(DISTINCT CASE WHEN body_change IS NOT NULL THEN ip END) FROM pcf f WHERE 1" + d)
    n_c, c_any = db.one("SELECT COUNT(DISTINCT cand), COUNT(DISTINCT CASE WHEN body_change IS NOT NULL THEN cand END) FROM pcf f WHERE 1" + d)
    out = {"按候选（对照）": {"取回过测试页": int(n_c or 0), "正文不符过": ratio(c_any, n_c), "各类": {}},
           "按 IP": {"取回过测试页": int(n_ip or 0), "正文不符过": ratio(n_any, n_ip), "各类": {}}}
    for k in kinds:
        ki, kc = db.one("SELECT COUNT(DISTINCT ip), COUNT(DISTINCT cand) FROM pcf f WHERE body_change = ?" + d, (k,))
        out["按 IP"]["各类"][k] = ratio(ki, n_ip)
        out["按候选（对照）"]["各类"][k] = ratio(kc, n_c)
    # 只有整页替换、从来没有正确取回过测试页的 IP（整页替换多半是错误页或门户页：这类 IP 其实没有转发能力）
    n_only = db.scalar("""SELECT COUNT(*) FROM (SELECT ip FROM pcf f WHERE 1%s GROUP BY ip
                          HAVING SUM(body_change IS NULL) = 0 AND SUM(body_change = ?) > 0)""" % d, (kinds[2],))
    out["按 IP"]["从没正确取回过、只有整页替换的"] = ratio(n_only, n_ip)
    return out


def leak_by_ip(db, exclude_dense):
    d = dense_cond("f", exclude_dense)
    n_ip, l_ip, n_c, l_c = db.one("""SELECT COUNT(DISTINCT ip), COUNT(DISTINCT CASE WHEN anon = 'transparent' THEN ip END),
                                            COUNT(DISTINCT cand), COUNT(DISTINCT CASE WHEN anon = 'transparent' THEN cand END)
                                     FROM ajf f WHERE 1""" + d)
    return {"按候选（对照）": {"能转发且 judge 收到过": int(n_c or 0), "带出过探测器地址": ratio(l_c, n_c)},
            "按 IP": {"能转发且 judge 收到过": int(n_ip or 0), "带出过探测器地址": ratio(l_ip, n_ip)}}


def replaced_bodies(db):
    k = mi.BODY_KINDS[2] if hasattr(mi, "BODY_KINDS") else "正文被整页替换"
    tot, no_ev = db.one("SELECT COUNT(*), SUM(ev IS NULL) FROM pcf WHERE body_change = ?", (k,))
    rows = db.q("""SELECT COUNT(*) AS n, COUNT(DISTINCT cand), COUNT(DISTINCT ip), COUNT(DISTINCT prefix24), MIN(len), MAX(len)
                   FROM pcf WHERE body_change = ? AND ev IS NOT NULL GROUP BY ev ORDER BY n DESC""", (k,))
    out = {"整页替换的尝试": int(tot or 0), "其中证据没存（超过存储上限）": int(no_ev or 0), "不同正文（按证据哈希）": len(rows)}
    cum = 0
    cover = {}
    for i, r in enumerate(rows, 1):
        cum += r[0]
        if i in (1, 10, 100):
            cover["前 %d 种" % i] = ratio(cum, tot)
    out["前几种正文覆盖整页替换尝试"] = cover
    out["前 %d 种" % TOP_BODIES] = [
        {"名次": i, "尝试": ratio(r[0], tot), "候选": int(r[1]), "IP": int(r[2]), "/24": int(r[3]),
         "长度（字节）": int(r[4]) if r[4] == r[5] else [int(r[4]), int(r[5])]}
        for i, r in enumerate(rows[:TOP_BODIES], 1)]
    return out


def cloudflare(db, exclude_dense):
    d = dense_cond("f", exclude_dense)
    db.x("DROP TABLE IF EXISTS temp.cfr")
    db.x("""CREATE TEMP TABLE cfr AS SELECT DISTINCT req_rid FROM req_header
            WHERE name = 'Cf-Connecting-Ip' AND req_rid IN (SELECT req_rid FROM ajf WHERE req_rid IS NOT NULL)""")
    db.x("CREATE INDEX temp.cfr_rid ON cfr(req_rid)")
    r = db.one("""SELECT COUNT(*), SUM(c.req_rid IS NOT NULL),
                         COUNT(DISTINCT f.cand), COUNT(DISTINCT CASE WHEN c.req_rid IS NOT NULL THEN f.cand END),
                         COUNT(DISTINCT f.ip), COUNT(DISTINCT CASE WHEN c.req_rid IS NOT NULL THEN f.ip END)
                  FROM ajf f LEFT JOIN cfr c ON c.req_rid = f.req_rid WHERE 1""" + d)
    # 请求头被改几乎都是 Accept-Encoding：看它与经 Cloudflare 转发是不是同一批（同一范围内交叉）
    e = db.one("""SELECT SUM(f.aenc_changed), SUM(f.aenc_changed AND c.req_rid IS NOT NULL),
                         COUNT(DISTINCT CASE WHEN f.aenc_changed = 1 THEN f.cand END),
                         COUNT(DISTINCT CASE WHEN f.aenc_changed = 1 AND c.req_rid IS NOT NULL THEN f.cand END)
                  FROM ajf f LEFT JOIN cfr c ON c.req_rid = f.req_rid WHERE 1""" + d)
    return {"口径": "HTTP 转发、class=ok、judge 收到的请求（同 leak_by_ip 的范围）",
            "请求": ratio(r[1], r[0]), "候选": ratio(r[3], r[2]), "IP": ratio(r[5], r[4]),
            "Accept-Encoding 被改": {
                "被改的请求里经 Cloudflare 的": ratio(e[1], e[0]),
                "经 Cloudflare 的请求里被改的": ratio(e[1], r[1]),
                "有被改请求的候选里、被改的请求经过 Cloudflare 的": ratio(e[3], e[2])}}


# ---------------------------------------------------------------- 主流程

def info_page_prefix():
    """judge 自己的说明页（judge.go infoPage()）里联系方式之前的固定部分。从源码读，不在这里另抄一份。"""
    src = os.path.join(HERE, "..", "fieldtest", "internal", "judge", "judge.go")
    try:
        text = open(src, encoding="utf-8").read()
    except OSError:
        return None, "读不到 %s" % os.path.relpath(src, HERE)
    i = text.find("func (s *Server) infoPage() string")
    j = text.find("return `", i) if i >= 0 else -1
    k = text.find("` + html.EscapeString(contact)", j) if j >= 0 else -1
    if min(i, j, k) < 0:
        return None, "judge.go 里找不到 infoPage() 的模板"
    return text[j + len("return `"):k].encode("utf-8"), "research/fieldtest/internal/judge/judge.go infoPage()"


def judge_info_page(db, data_dir):
    """整页替换的正文里有多少是 judge 自己的说明页（代理把请求路径丢了，向 judge 要了“/”）。
    正文从证据文件读（--data 给出数据目录时），与 judge.go 里说明页模板的固定前缀比对；judge 一侧数“/”的明文请求。只输出计数。"""
    k = mi.BODY_KINDS[2]
    prefix, src = info_page_prefix()
    out = {"说明页模板": src}
    # judge 一侧：收到的“GET /”，按 Host 是不是 judge 自己的名字、HTTP 版本分
    names = [r[0].lower() for r in db.q("SELECT DISTINCT name FROM self_names WHERE name IS NOT NULL AND name != ''")] \
        if db.has_table("self_names") else []
    if db.has_table("noise"):
        rows = db.q("SELECT LOWER(COALESCE(host, '')), proto, COALESCE(tls, 0), COUNT(*) FROM noise WHERE method = 'GET' AND target = '/' GROUP BY 1, 2, 3")
        jside = {"全部": 0, "Host 是 judge 的名字": {}}
        for host, proto, tls, n in rows:
            jside["全部"] += int(n)
            h = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            if h in names:
                key = "%s%s" % (proto or "?", "（TLS）" if tls else "")
                jside["Host 是 judge 的名字"][key] = jside["Host 是 judge 的名字"].get(key, 0) + int(n)
        out["judge 收到的 GET /（noise 记录）"] = jside
    # 公开库：正文不在，每个证据“是不是说明页”取回导出时记下的结果（PUBLIC.md“随库带上的中间结果”）
    public = pubdb.is_public(db.con) and pubdb.has_replay(db.con, "body_infopage")
    if prefix is None or (not data_dir and not public) or not db.has_table("evidence"):
        out["note"] = "没有比对正文：%s" % ("缺 --data" if not data_dir else (src if prefix is None else "库里没有 evidence 表"))
        return out
    evs = db.q("""SELECT ev, COUNT(*) FROM pcf WHERE body_change = ? AND ev IS NOT NULL GROUP BY ev""", (k,))
    # 一次把正文证据的路径读成字典。原来逐个哈希查 evidence，在真实数据上跑了很久也没完（查询计划走的是主键索引，慢的原因没查清）
    paths = {h: p for h, p in db.q("SELECT hash, path FROM evidence WHERE ext = 'body'")}
    hit = set()
    unread = 0
    states = dict(pubdb.replay_rows(db.con, "body_infopage")) if public else {}   # 证据哈希 → hit / miss / unread
    for ev, _n in evs:
        if public:
            if ev not in states:
                raise SystemExit("公开库的 pub_body_infopage 里没有这个正文证据的结果：换了参数？见 PUBLIC.md")
            if states[ev] == "unread":
                unread += 1
            elif states[ev] == "hit":
                hit.add(ev)
            continue
        path = paths.get(ev)
        if not path:
            states[ev] = "unread"
            unread += 1
            continue
        try:
            with open(os.path.join(data_dir, path), "rb") as f:
                head = f.read(len(prefix))
        except OSError:
            states[ev] = "unread"
            unread += 1
            continue
        states[ev] = "miss"
        if head == prefix:
            states[ev] = "hit"
            hit.add(ev)
    rec = pubdb.Recorder()
    if rec.on and not public:
        rec.put_rows("body_infopage", ["ev", "state"], [(ev, states[ev]) for ev, _n in evs])
        rec.close()
    db.x("DROP TABLE IF EXISTS temp.infoev")
    db.x("CREATE TEMP TABLE infoev (ev TEXT PRIMARY KEY)")
    db.con.executemany("INSERT INTO infoev VALUES (?)", [(e,) for e in hit])
    tot = db.scalar("SELECT COUNT(*) FROM pcf WHERE body_change = ?", (k,))
    a, c, i, p = db.one("""SELECT COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT ip), COUNT(DISTINCT prefix24)
                           FROM pcf WHERE body_change = ? AND ev IN (SELECT ev FROM infoev)""", (k,))
    db.x("DROP TABLE IF EXISTS temp.info_ip")
    db.x("CREATE TEMP TABLE info_ip AS SELECT DISTINCT ip FROM pcf WHERE body_change = ? AND ev IN (SELECT ev FROM infoev)", (k,))
    n_mitm = db.scalar("SELECT COUNT(*) FROM info_ip WHERE ip IN (SELECT ip FROM pa WHERE mitm = 1)")
    n_big = db.scalar("SELECT COUNT(*) FROM info_ip WHERE ip IN (SELECT ip FROM ipn WHERE n >= 100)")
    out.update({
        "整页替换的不同正文里是 judge 说明页的": len(hit), "读不到证据文件的正文": unread,
        "是 judge 说明页的整页替换": {"尝试": ratio(a, tot), "候选": int(c), "IP": int(i), "/24": int(p)},
        "这些 IP 里也遇到过中间人的": ratio(n_mitm, i), "这些 IP 里有 100 个以上候选的": ratio(n_big, i),
    })
    return out


DOMAIN_RE = re.compile(r"\b[A-Za-z0-9-]+\.[A-Za-z]{2,}\b")


def _issuer_org(issuer, guard_names):
    """tls_issuer 是 Go pkix.Name.String()（RFC 2253 风格），按 m_mitm.dn_get 取 O=（只取组织名，不取 CN）。
    att.tls_issuer 不在可输出列白名单里（公开证书的 CN 是 judge 主机名），所以 O 进输出前与 m_mitm.safe_text 同样处理：
    含地址、邮箱样式、judge 的名字的隐去；另外像域名的也隐去（第三方主机名不进仓库）。"""
    if not issuer:
        return None
    orgs = [o.strip() for o in mm.dn_get(issuer, "O") if o and o.strip()]
    if not orgs:
        return None
    o = orgs[0]
    if mm.HOSTPORT_RE.search(o) or mm.IPV4_RE.search(o) or "@" in o:
        return "（含地址，已隐去）"
    if any(h and h.lower() in o.lower() for h in guard_names):
        return "（含 judge 身份，已隐去）"
    if DOMAIN_RE.search(o):
        return "（像域名，已隐去）"
    return o[:60]


def mitm_fleet(db, fs, aws_ranges):
    """遇到过中间人的 IP 按“有没有 100 个以上候选”分两群：IP 数、候选数、中间人尝试数；
    中间人证书的签发者组织（O）按 IP 数排；给了 AWS 公布的地址段文件时，数各群里落在其中的 IP 和区域数。"""
    db.x("DROP TABLE IF EXISTS temp.mip")
    db.x("""CREATE TEMP TABLE mip AS SELECT p.ip, (n.n >= 100) AS big, n.n AS ncand
            FROM (SELECT DISTINCT ip FROM pa WHERE mitm = 1) p JOIN ipn n ON n.ip = p.ip""")
    out = {}
    issuers = {}
    guard = [r[0] for r in db.q("SELECT DISTINCT name FROM self_names WHERE name IS NOT NULL AND name != ''")] \
        if db.has_table("self_names") else []
    for ip, issuer in db.q("""SELECT DISTINCT cand_ip, tls_issuer FROM att
                             WHERE cand_kind = 'proxy' AND dst = 'judge_tls' AND proto IN (%s) AND tls_class = 'tls_cert_invalid'
                               AND ts_epoch >= ? AND COALESCE(class, '') NOT LIKE '%%canceled%%'"""
                          % mi.sql_in(TUNNEL_PROTOS), (fs,)):
        o = _issuer_org(issuer, guard) or "（没有 O）"
        issuers.setdefault(o, set()).add(ip)
    groups = {r[0]: bool(r[1]) for r in db.q("SELECT ip, big FROM mip")}
    nets = None
    aws_note = None
    # 公开库：地址是假名，对不上 AWS 的地址段；每个中间人 IP 落在哪个区域取回导出时记下的结果（真实库上没给 --aws-ranges 就没有）
    public = pubdb.is_public(db.con)
    aws_region = None
    if public:
        if pubdb.has_replay(db.con, "aws"):
            aws_region = dict(pubdb.replay_rows(db.con, "aws"))
            aws_note = pubdb.replay_json(db.con, "aws_note")
    elif aws_ranges:
        aws_region = {}
        import ipaddress
        with open(aws_ranges, encoding="utf-8") as f:
            d = json.load(f)
        nets = [(ipaddress.ip_network(p["ip_prefix"]), p.get("region")) for p in d.get("prefixes", [])]
        aws_note = {"文件": os.path.basename(aws_ranges), "syncToken": str(d.get("syncToken")), "createDate": d.get("createDate"),
                    "IPv4 地址段": len(nets)}
    for big, name in ((True, "有 100 个以上候选的 IP"), (False, "其余 IP")):
        ips = [ip for ip, b in groups.items() if b == big]
        n_c = db.scalar("SELECT COUNT(*) FROM pa WHERE mitm = 1 AND ip IN (SELECT ip FROM mip WHERE big = ?)", (1 if big else 0,))
        g = {"IP": len(ips), "遇到过中间人的候选": int(n_c)}
        # 组织名门槛同 m_mitm（ORG_MIN_IPS）：整体上出现在不到这么多个 IP 上的组织名不列出，只给合并后的 IP 数
        ipset, min_ips = set(ips), mm.ORG_MIN_IPS
        orgs = sorted(((o, len(s & ipset)) for o, s in issuers.items() if len(s) >= min_ips), key=lambda x: (-x[1], x[0]))
        g["中间人证书的签发者组织（按 IP 数，前 8）"] = {o: n for o, n in orgs[:8] if n}
        small = set()
        for o, s_ in issuers.items():
            if len(s_) < min_ips:
                small |= s_ & ipset
        g["签发者组织出现在不到 %d 个 IP 上的（不列名字，合并后的 IP 数）" % min_ips] = len(small)
        if aws_region is not None:
            import ipaddress
            regions = []
            for ip in ips:
                if public:
                    if ip not in aws_region:
                        raise SystemExit("公开库的 pub_aws 里没有这个 IP 的结果：换了参数？见 PUBLIC.md")
                else:
                    a = ipaddress.ip_address(ip)
                    aws_region[ip] = next((reg for net, reg in nets if a.version == net.version and a in net), None)
                r = aws_region[ip]
                if r is not None:
                    regions.append(r)
            g["落在 AWS 公布地址段里的 IP"] = ratio(len(regions), len(ips))
            g["这些 IP 分布的 AWS 区域数"] = len(set(regions))
        out[name] = g
    if aws_note:
        out["AWS 地址段文件"] = aws_note
    rec = pubdb.Recorder()
    if rec.on and not public and aws_region is not None:
        rec.put_rows("aws", ["ip", "region"], sorted(aws_region.items()))
        rec.put_json("aws_note", aws_note)
        rec.close()
    out["note"] = ("签发者组织只是证书里写的名字：链按公共根校验不过（m_mitm），名字可以随便写，不代表真是这家 CA 签的。"
                   "整体上出现在不到 %d 个 IP 上的组织名不列出（同 m_mitm 的门槛：只在一两个 IP 上出现的名字能把一家真实机构和一个具体的代理对上号）" % mm.ORG_MIN_IPS)
    return out


def run(db_path, out_dir, dense_threshold=DENSE_THRESHOLD, formal_start="auto", markdown=False, write=True,
        data_dir=None, aws_ranges=None):
    db = mi.DB(db_path)
    wl_source = mi.check_whitelist(db)
    for t in ("att", "visit", "req", "req_header"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表" % t)
    win = mi.observation_window(db, formal_start)
    fs = win.pop("_fs")
    win.pop("_end", None)
    if fs is None:
        raise SystemExit("库里没有任何尝试记录")
    plen, plen_src = mi.payload_lengths(db)
    mi.build_tables(db, fs, dense_threshold, plen)
    build(db, fs)
    res = {
        "module": MODULE, "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol_version": "1.2", "post_hoc": True, "decision": "D14", "whitelist_source": wl_source,
        "dense_threshold": dense_threshold, "rules_source": "m_integrity.build_tables（aj、pc、rd、dense24）",
        "definitions": DEFINITIONS, "window": win,
        "concentration": concentration(db),
        "funnel_by_ip": {g: {"all": funnel_by_ip(db, g == "regular", False), "excluding_dense": funnel_by_ip(db, g == "regular", True)}
                         for g in ("all_candidates", "regular")},
        "mitm_by_ip": {"all": mitm_by_ip(db, False), "excluding_dense": mitm_by_ip(db, True)},
        "content_by_ip": {"all": content_by_ip(db, False), "excluding_dense": content_by_ip(db, True)},
        "leak_by_ip": {"all": leak_by_ip(db, False), "excluding_dense": leak_by_ip(db, True)},
        "replaced_bodies": replaced_bodies(db),
        "cloudflare": {"all": cloudflare(db, False), "excluding_dense": cloudflare(db, True)},
        "judge_info_page": judge_info_page(db, data_dir),
        "mitm_fleet": mitm_fleet(db, fs, aws_ranges),
    }
    res["checks"] = checks(db, res)
    text = json.dumps(res, ensure_ascii=False, indent=1)
    try:
        mi.assert_clean(text, db)
    finally:
        db.con.close()
    if write:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, OUTPUT_NAME)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("已写出 %s（%d 字节）" % (path, len(text.encode("utf-8"))), file=sys.stderr)
    if markdown:
        print_markdown(res)
    return res


def checks(db, res):
    """内部一致性：按 IP 的分子不大于按候选的分子；按候选的数与 m_integrity / m_mitm 同口径的直接计数一致。"""
    out = {}
    f = res["funnel_by_ip"]["all_candidates"]["all"]
    out["IP 数不大于候选数（漏斗各级）"] = all(
        f["按 IP"][k]["num"] <= f["按候选（对照）"][k]["num"] for k in ("连得上过", "有协议回应过", "可用过"))
    m = res["mitm_by_ip"]["all"]
    out["中间人：按 IP 的分子不大于按候选的"] = m["按 IP"]["遇到过中间人 / 隧道建立过"]["num"] <= \
        m["按候选（对照）"]["遇到过中间人 / 隧道建立过"]["num"]
    # pa 的候选数与 att 里正式起点后的代理候选数一致
    out["pa 的候选都有 IP（应为 0 个例外）"] = int(db.scalar("SELECT COUNT(*) FROM pa WHERE ip IS NULL OR ip = ''") or 0)
    out["pcf 的 IP 与 att.cand_ip 一致（应为 0 个例外）"] = int(db.scalar(
        "SELECT COUNT(*) FROM (SELECT DISTINCT cand, ip FROM pcf) x JOIN pa p ON p.cand = x.cand WHERE p.ip != x.ip") or 0)
    return out


def print_markdown(res):
    def rf(r):
        return mi.rfmt(r)
    print("### 按 IP 重算（事后，决策 D14）\n")
    print("每行的范围和分母见指标名；“按候选”一列与按 IP 同范围，用来对照单位的变化，不一定等于主口径（第五节）里同名指标的数。\n")
    print("| 指标 | 按候选（ip:port） | 按 IP | 按 IP，去掉候选密集的 /24 |")
    print("| --- | --- | --- | --- |")
    fa, fd = res["funnel_by_ip"]["regular"]["all"], res["funnel_by_ip"]["regular"]["excluding_dense"]
    for k in ("连得上过", "有协议回应过", "可用过"):
        print(f"| 常规列表：{k} / 探访过 | {rf(fa['按候选（对照）'][k])} | {rf(fa['按 IP'][k])} | {rf(fd['按 IP'][k])} |")
    ma, md = res["mitm_by_ip"]["all"], res["mitm_by_ip"]["excluding_dense"]
    for k in ("遇到过中间人 / 隧道建立过", "遇到过中间人 / 隧道曾可用或遇到过中间人"):
        print(f"| 中间人：{k} | {rf(ma['按候选（对照）'][k])} | {rf(ma['按 IP'][k])} | {rf(md['按 IP'][k])} |")
    ca, cd = res["content_by_ip"]["all"], res["content_by_ip"]["excluding_dense"]
    print(f"| 正文不符过 / 取回过测试页（HTTP 转发、HTML 载荷） | {rf(ca['按候选（对照）']['正文不符过'])} | {rf(ca['按 IP']['正文不符过'])} | {rf(cd['按 IP']['正文不符过'])} |")
    for kk in ca["按 IP"]["各类"]:
        print(f"| 　其中{kk} | {rf(ca['按候选（对照）']['各类'][kk])} | {rf(ca['按 IP']['各类'][kk])} | {rf(cd['按 IP']['各类'][kk])} |")
    la, ld = res["leak_by_ip"]["all"], res["leak_by_ip"]["excluding_dense"]
    print(f"| 带出探测器地址 / HTTP 转发、class=ok 且 judge 收到过 | {rf(la['按候选（对照）']['带出过探测器地址'])} | {rf(la['按 IP']['带出过探测器地址'])} | {rf(ld['按 IP']['带出过探测器地址'])} |")
    print()
    c = res["concentration"]["探访过的代理候选"]
    print(f"- 探访过的代理候选 {mi.fmt(c['候选'])} 个，来自 {mi.fmt(c['IP'])} 个 IP；"
          f"属于有 10 个以上候选的 IP 的占 {rf(c['候选里属于有 10 个以上候选的 IP 的'])}；"
          f"候选最多的 20 个 IP 合计占 {rf(c['候选最多的 20 个 IP 合计占候选'])}")
    rb = res["replaced_bodies"]
    cov = "，".join(f"{k} {rf(v)}" for k, v in rb["前几种正文覆盖整页替换尝试"].items())
    print(f"- 整页替换 {mi.fmt(rb['整页替换的尝试'])} 次，不同正文 {mi.fmt(rb['不同正文（按证据哈希）'])} 种；{cov}")
    cf = res["cloudflare"]["all"]
    print(f"- 经 Cloudflare 转发（带 Cf-Connecting-Ip）：请求 {rf(cf['请求'])}，候选 {rf(cf['候选'])}，IP {rf(cf['IP'])}")
    ae = cf.get("Accept-Encoding 被改") or {}
    if ae:
        print("- 同一范围里 Accept-Encoding 被改与经 Cloudflare 交叉：" + "；".join("%s %s" % (k, rf(v)) for k, v in ae.items()))
    jp = res["judge_info_page"]
    if "是 judge 说明页的整页替换" in jp:
        x = jp["是 judge 说明页的整页替换"]
        print(f"- 整页替换里是 judge 自己说明页的（代理丢了路径，要了“/”）：尝试 {rf(x['尝试'])}，候选 {mi.fmt(x['候选'])}，"
              f"IP {mi.fmt(x['IP'])}，/24 {mi.fmt(x['/24'])}；这些 IP 里也遇到过中间人的 {rf(jp['这些 IP 里也遇到过中间人的'])}，"
              f"有 100 个以上候选的 {rf(jp['这些 IP 里有 100 个以上候选的'])}")
    else:
        print(f"- judge 说明页：{jp.get('note')}")
    for name, g in res["mitm_fleet"].items():
        if not isinstance(g, dict) or "IP" not in g:
            continue
        line = f"- 中间人 IP，{name}：{mi.fmt(g['IP'])} 个，候选 {mi.fmt(g['遇到过中间人的候选'])} 个"
        if "落在 AWS 公布地址段里的 IP" in g:
            line += f"；落在 AWS 公布地址段里 {rf(g['落在 AWS 公布地址段里的 IP'])}，{g['这些 IP 分布的 AWS 区域数']} 个区域"
        orgs = "、".join(f"{o} {n}" for o, n in g["中间人证书的签发者组织（按 IP 数，前 8）"].items())
        print(line + f"；证书里写的签发者组织（IP 数）：{orgs}")


# ---------------------------------------------------------------- 自检

def selftest():
    """用 m_integrity 的合成库跑一遍，再用 Python 直接从原始行算同样几个数，逐项比对。"""
    fails = []

    def expect(name, got, want):
        if got != want:
            fails.append("%s：得到 %r，应为 %r" % (name, got, want))

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.sqlite")
        mi._synthetic_db(path)
        con = sqlite3.connect(path)
        # m_integrity 的合成库只有它用到的列：补上本模块要的列和 visit 表，再加几条隧道尝试（同一 IP 两个端口、一个遇到中间人）
        have = {r[1] for r in con.execute("PRAGMA table_info(att)")}
        for col, typ in (("tcp_ok", "INTEGER"), ("hs_ok", "INTEGER"), ("hs_code", "INTEGER"), ("tls_class", "TEXT"), ("tls_issuer", "TEXT")):
            if col not in have:
                con.execute("ALTER TABLE att ADD COLUMN %s %s" % (col, typ))
        if not con.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'visit'").fetchone()[0]:
            con.execute('CREATE TABLE visit (rid INTEGER PRIMARY KEY, ts_epoch REAL, cand TEXT, "group" INTEGER, aborted INTEGER)')
        fs = con.execute("SELECT MIN(ts_epoch) FROM start").fetchone()[0]
        extra = [  # cand, proto, class, hs_ok, tls_class, tls_ok
            ("198.51.100.9:1080", "socks5", "ok", 1, None, 1),
            ("198.51.100.9:1081", "socks5", "tls_cert_invalid", 1, "tls_cert_invalid", 0),
            ("198.51.100.8:1080", "socks5", "tls_cert_invalid", 1, "tls_cert_invalid", 0),
            ("198.51.100.7:1080", "socks5", "hs_refused", 0, None, None),
        ]
        for i, (cand, proto, cls, hs, tlsc, tok) in enumerate(extra):
            ip, port = cand.split(":")
            issuer = {"198.51.100.9": "CN=Fake Root,O=Test Org\\, Inc.", "198.51.100.8": "CN=x,O=evil.example"}.get(ip) if tlsc else None
            con.execute("""INSERT INTO att (ts_epoch, visit, cand, proto, dst, kind, class, tcp_ok, hs_ok, tls_class, tls_ok,
                                            cand_kind, cand_ip, cand_port, prefix24, tls_issuer)
                           VALUES (?, ?, ?, ?, 'judge_tls', 'h', ?, 1, ?, ?, ?, 'proxy', ?, ?, '198.51.100.0/24', ?)""",
                        (fs + 60 + i, "vx%d" % i, cand, proto, cls, hs, tlsc, tok, ip, int(port), issuer))
            con.execute('INSERT INTO visit (ts_epoch, cand, "group", aborted) VALUES (?, ?, 0, 0)', (fs + 60 + i, cand))
        con.commit()
        # Python 直接算：按 IP 的“可用过”和中间人
        rows = con.execute("""SELECT cand, cand_ip, class, dst, proto, hs_ok, tls_class, ts_epoch FROM att
                              WHERE cand_kind = 'proxy' AND COALESCE(class, '') NOT LIKE '%canceled%'""").fetchall()
        con.close()
        res = run(path, tmp, write=False)
        ok_ip, tun_ip, mitm_ip, ips = set(), set(), set(), set()
        for cand, ip, cls, dst, proto, hs, tlsc, ts in rows:
            if ts < fs:
                continue
            ips.add(ip)
            if cls == "ok" and dst in ("judge_tls", "judge_http"):
                ok_ip.add(ip)
            if proto in TUNNEL_PROTOS and dst == "judge_tls":
                if hs == 1:
                    tun_ip.add(ip)
                if tlsc == "tls_cert_invalid":
                    mitm_ip.add(ip)
        f = res["funnel_by_ip"]["all_candidates"]["all"]["按 IP"]
        expect("按 IP 探访过", f["探访过"], len(ips))
        expect("按 IP 可用过", f["可用过"]["num"], len(ok_ip))
        m = res["mitm_by_ip"]["all"]["按 IP"]
        expect("按 IP 隧道建立过", m["隧道建立过"], len(tun_ip))
        expect("按 IP 中间人", m["遇到过中间人 / 隧道建立过"]["num"], len(mitm_ip))
        orgs = res["mitm_fleet"]["其余 IP"]["中间人证书的签发者组织（按 IP 数，前 8）"]
        # 合成库每个组织只在 1 个 IP 上：默认门槛下一个也不列，只给合并后的 IP 数
        expect("签发者组织：门槛下不列名字", orgs, {})
        expect("签发者组织：门槛下合并的 IP 数", res["mitm_fleet"]["其余 IP"]["签发者组织出现在不到 %d 个 IP 上的（不列名字，合并后的 IP 数）" % mm.ORG_MIN_IPS], 2)
        keep = mm.ORG_MIN_IPS
        mm.ORG_MIN_IPS = 1
        try:
            res1 = run(path, tmp, write=False)
        finally:
            mm.ORG_MIN_IPS = keep
        expect("签发者组织：转义逗号、像域名的隐去", res1["mitm_fleet"]["其余 IP"]["中间人证书的签发者组织（按 IP 数，前 8）"],
               {"Test Org, Inc.": 1, "（像域名，已隐去）": 1})
        for k, v in res["checks"].items():
            if v not in (True, 0):
                fails.append("核对 %s 不通过：%r" % (k, v))
    if fails:
        print("自检失败：\n  " + "\n  ".join(fails), file=sys.stderr)
        return 1
    print("自检通过", file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="事后分析（决策 D14）：按 IP 重算主要比例，拆开整页替换和经 Cloudflare 转发的请求")
    ap.add_argument("--db")
    ap.add_argument("--out")
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--dense-threshold", type=int, default=DENSE_THRESHOLD)
    ap.add_argument("--formal-start", default="auto")
    ap.add_argument("--data", help="解包后的数据目录（读证据正文，判断整页替换是不是 judge 的说明页）")
    ap.add_argument("--aws-ranges", help="AWS 公布的 ip-ranges.json（可选；给了就数中间人 IP 有多少落在 AWS 地址段里）")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    data = args.data
    if data and not any(n.startswith("probe-") for n in os.listdir(data)) and os.path.isdir(os.path.join(data, "fieldtest")):
        data = os.path.join(data, "fieldtest")
    run(args.db, args.out, dense_threshold=args.dense_threshold, formal_start=args.formal_start, markdown=args.markdown,
        data_dir=data, aws_ranges=args.aws_ranges)


if __name__ == "__main__":
    main()
