#!/usr/bin/env python3
"""derive.py 和 matrix.py 的单元测试。

    python3 -m unittest discover -s research/phase2/runner -p 'test_matrix.py'

- 每一行（rows.json 的 104 行）至少两组合成的事实，覆盖至少两个取值；
- 通用规则：不支持、不适用、未通过核对、没有结果、不稳定、“其他：”；
- derive 用 EVENTS.md 里那种事件拼出的记录检验；
- 有真实数据时（环境变量 KAOJU_P2_RAW 指向 out/raw 目录）再冒烟一遍。
"""

import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import tempfile
import unittest

import derive
import matrix

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROWS_DOC = matrix.load_json(os.path.join(BASE, "rows.json"))
CASES_DOC = matrix.load_json(os.path.join(BASE, "cases.json"))
ROW = {r["id"]: r for r in ROWS_DOC["rows"]}
CASE = {c["id"]: c for c in CASES_DOC["cases"]}
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False)


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def quiet(fn, argv):
    """调命令行入口，不让它的输出混进测试输出。"""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(argv)


# ---------------------------------------------------------------------------
# 合成事实的小工具


def run(**kw):
    d = {
        "skipped": None,
        "unsupported": None,
        "has_result": True,
        "driver_timeout": False,
        "driver_exit": 0,
        "runner_errors": [],
        "pcap_status": "ok",
        "pcap_problems": 0,
        "tcpdump_dropped": 0,
        "events_complete": True,
        "late_events": 0,
        "log_errors": 0,
        "k_mismatches": 0,
    }
    d.update(kw)
    return d


def F(reqs=(), oreqs=(), tunnels=(), steps=(), socks=(), actions=(), proxy=None, direct=0, profile=None, **runkw):
    reqs, tunnels = list(reqs), list(tunnels)
    if proxy is None:
        ids = sorted({r["conn"] for r in reqs} | {t["conn"] for t in tunnels} | {s["conn"] for s in socks})
        proxy = [pconn(c) for c in ids]
    return {
        "run": run(**runkw),
        "profile": profile or {"auth": {"on407": "keepalive"}, "connect": {"fail": None}},
        "proxy_conns": list(proxy),
        "proxy_conn_count": len(proxy),
        "direct_conns": [{"conn": 100 + i, "listener": "origin_https"} for i in range(direct)],
        "direct_conn_count": direct,
        "http_requests": reqs,
        "tunnels": tunnels,
        "origin_conns": [{"oconn": t["tunnel"], "conn": t["conn"], "via": "tunnel", "tunnel": t["tunnel"]} for t in tunnels],
        "origin_requests": list(oreqs),
        "socks": list(socks),
        "actions": list(actions),
        "steps": list(steps),
        "markers": {},
    }


def pconn(conn=1, first="47"):
    return {"conn": conn, "listener": "proxy", "first_byte": first, "first_hex": first, "first_kind": "http"}


def creds(user, pw):
    return "Basic " + base64.b64encode(user.encode() + b":" + pw.encode()).decode()


def rq(k=None, form="absolute", conn=1, seq=1, auth="none", user=None, raw=None, headers=(), status=200, close=False, target=None, method=None, version="HTTP/1.1", body_len=0):
    if target is None:
        target = "a.kaoju.test:443" if form == "connect" else "http://a.kaoju.test/echo?k=%s" % k
    if method is None:
        method = "CONNECT" if form == "connect" else "GET"
    headers = [list(h) for h in headers]
    a = {"present": auth != "none", "scheme": "Basic" if auth != "none" else None, "raw": raw, "result": auth, "user": user, "user_hex": user.encode().hex() if user is not None else None, "pass_hex": None, "lenient": False}
    resp = {"status": status, "reason": "", "by": "proxy", "cause": "", "close": close, "header_names": []} if status is not None else None
    return {
        "conn": conn,
        "seq": seq,
        "form": form,
        "method": method,
        "target": target,
        "version": version,
        "header_names": [h[0] for h in headers],
        "headers": headers,
        "k": None if form == "connect" else k,
        "auth": a,
        "body_len": body_len,
        "error": None,
        "responses": [resp] if resp else [],
        "response": resp,
    }


def orq(k, via="tunnel", tunnel=1, proto="HTTP/1.1", pa=False, body_len=0, sha=EMPTY_SHA, headers=(), action="respond"):
    return {
        "k": k,
        "via": via,
        "tunnel": tunnel if via == "tunnel" else None,
        "conn": 1,
        "proto": proto,
        "has_proxy_authorization": pa,
        "body_len": body_len,
        "body_sha256": sha,
        "headers": [list(h) for h in headers],
        "action": action,
        "status": 200 if action == "respond" else None,
    }


def tn(tunnel=1, via="connect", port=443, conn=1, kind="tls_client_hello", record_len=512, alpn=("h2", "http/1.1"), user=None, host="a.kaoju.test", nofirst=False):
    first = None
    if not nofirst:
        tls = kind == "tls_client_hello"
        first = {"kind": kind, "hex": "16030102", "record_len": record_len if tls else None, "tls_complete": True if tls else None, "sni": host if tls else None, "alpn": list(alpn) if tls else None}
    opener = {"kind": via, "auth_result": "ok" if user else "none", "user": user, "user_hex": user.encode().hex() if user else None}
    return {"tunnel": tunnel, "via": via, "conn": conn, "req_seq": 1, "target_host": host, "target_port": port, "mapped": "origin_https", "first": first, "close_by": "client", "bytes_c2s": 100, "bytes_s2c": 100, "opener": opener}


def st(sid="s1", ok=True, status=200, text="", extra=None, how=None):
    return {"id": sid, "op": None, "ok": ok, "status": status if ok else None, "default_text": text, "extra_text": extra, "extra_how": how}


def fail(sid="s1", text="boom", extra=None, how=None):
    return st(sid, ok=False, text=text, extra=extra, how=how)


def sk(conn=1, methods=(0,), atyp=None, auth=None, host="a.kaoju.test"):
    return {
        "conn": conn,
        "greeting": {"methods": list(methods), "raw_hex": ""},
        "selected": 0,
        "auth": auth,
        "request": {"cmd": 1, "atyp": atyp, "host": host, "port": 443} if atyp is not None else None,
        "reply": None,
    }


def sauth(user, pw, status=0):
    return {"user": user, "user_hex": user.encode().hex(), "pass_hex": pw.encode().hex(), "ulen": len(user.encode()), "plen": len(pw.encode()), "status": status, "result": "ok" if status == 0 else "bad"}


def act(what, k=None):
    return {"what": what, "how": "fin", "k": k, "conn": 1, "tunnel": None, "oconn": None}


def cell(rid, facts, variant="curl", **kw):
    """facts：{用例: 事实} 或 {用例: {遍数: 事实}}。"""
    col = {}
    for c, v in facts.items():
        col[c] = v if "run" not in v else {"1": v}
    return matrix.compute_cell(ROW[rid], variant, col, CASE, **kw)


def val(rid, facts, variant="curl"):
    return cell(rid, facts, variant)["value"]


def body_sha(n):
    return hashlib.sha256(bytes((i * 131 + 7) % 251 for i in range(n))).hexdigest()


U1, U2 = "kaoju-user", "kaoju-user-2"
MARK_ALL = "HTTP/1.1 502 KaojuReasonMarker\nX-Kaoju-Note: KaojuHeaderMarker\n\nKaojuBodyMarker"


def ok_steps(case):
    return [st(s["id"]) for s in matrix.request_steps(CASE[case])]


# ---------------------------------------------------------------------------
# 每一行的合成用例：行号 -> [({用例: 事实}, 预期取值)…]

T = {}

T["R01"] = [
    ({"A01": F(reqs=[rq("A01.s1")])}, "绝对形式"),
    ({"A01": F(tunnels=[tn(port=80, kind="http")], oreqs=[orq("A01.s1")])}, "CONNECT 到 80 端口"),
    ({"A01": F(oreqs=[orq("A01.s1", via="direct")], direct=1)}, "直连"),
    ({"A01": F(steps=[fail()])}, "没到"),
    ({"A01": F(tunnels=[tn(port=80, kind="http")])}, "其他：隧道里有字节往来，但源站没能解析出请求"),
    ({"A01": F(reqs=[rq("A01.s1", form="origin")])}, "其他：代理端口上的请求形式是 origin"),
]
T["R02"] = [
    ({"A01": F(reqs=[rq("A01.s1", headers=[("Host", "a.kaoju.test"), ("Proxy-Connection", "Keep-Alive"), ("Accept", "*/*")])])}, "Proxy-Connection: Keep-Alive"),
    ({"A01": F(reqs=[rq("A01.s1", headers=[("connection", "keep-alive"), ("Proxy-Authorization", "Basic xx"), ("TE", "trailers")])])}, "connection: keep-alive; Proxy-Authorization; TE: trailers"),
    ({"A01": F(reqs=[rq("A01.s1", headers=[("Host", "a.kaoju.test")])])}, "无"),
    ({"A01": F()}, "其他：带 k=A01.s1 的请求没到"),
]
T["R03"] = [
    ({"A02": F(reqs=[rq(form="connect")])}, "a.kaoju.test:443 HTTP/1.1"),
    ({"A02": F(reqs=[rq(form="connect", version="HTTP/1.0")])}, "a.kaoju.test:443 HTTP/1.0"),
    ({"A02": F()}, "没有 CONNECT"),
]
T["R04"] = [
    ({"A02": F(reqs=[rq(form="connect", headers=[("Host", "a.kaoju.test:443"), ("User-Agent", "x"), ("Proxy-Connection", "Keep-Alive")])])}, "Host, User-Agent, Proxy-Connection"),
    ({"A02": F(reqs=[rq(form="connect", headers=[("host", "a.kaoju.test:443")])])}, "host"),
    ({"A02": F()}, "其他：没有 CONNECT"),
]
T["R05"] = [
    ({"A02": F(reqs=[rq(form="connect", headers=[("Host", "a.kaoju.test:443")])])}, "同目标"),
    ({"A02": F(reqs=[rq(form="connect", headers=[("Host", "a.kaoju.test")])])}, "不同"),
    ({"A02": F(reqs=[rq(form="connect", headers=[("User-Agent", "x")])])}, "没有"),
]
for _rid, _case in (("R06", "A02"), ("R115", "S01"), ("R116", "S02")):
    T[_rid] = [
        ({_case: F(tunnels=[tn()])}, "TLS ClientHello"),
        ({_case: F(tunnels=[tn(kind="http")])}, "明文 HTTP"),
        ({_case: F(tunnels=[tn(kind="other")])}, "其他"),
        ({_case: F()}, "其他：没有隧道"),
        ({_case: F(tunnels=[tn(nofirst=True)])}, "其他：隧道里没有收到任何字节"),
    ]
T["R07"] = [
    ({"A02": F(tunnels=[tn(record_len=512)])}, "不超过 1460 字节"),
    ({"A02": F(tunnels=[tn(record_len=1455)])}, "不超过 1460 字节"),
    ({"A02": F(tunnels=[tn(record_len=1456)])}, "超过 1460 字节"),
    ({"A02": F(tunnels=[tn(kind="http")])}, "其他：隧道首包不是 ClientHello（http）"),
]
T["R08"] = [
    ({"A02": F(tunnels=[tn()])}, "h2,http/1.1"),
    ({"A02": F(tunnels=[tn(alpn=())])}, "无"),
]
T["R09"] = [
    ({"A02": F(oreqs=[orq("A02.s1", proto="HTTP/2.0")])}, "HTTP/2.0"),
    ({"A02": F(oreqs=[orq("A02.s1")])}, "HTTP/1.1"),
    ({"A02": F()}, "其他：带 k=A02.s1 的请求没到源站"),
]
for _rid, _case in (("R10", "A03"), ("R12", "A05"), ("R14", "A07"), ("R15", "A08"), ("R38", "B07")):
    T[_rid] = [
        ({_case: F(tunnels=[tn()], steps=ok_steps(_case))}, "1"),
        ({_case: F(tunnels=[tn(1), tn(2, conn=2), tn(3, conn=3)], steps=ok_steps(_case))}, "3"),
        ({_case: F(steps=ok_steps(_case))}, "0"),
    ]
for _rid, _case in (("R11", "A04"), ("R13", "A06"), ("R16", "A09"), ("R122", "S12"), ("R123", "S13")):
    T[_rid] = [
        ({_case: F(proxy=[pconn(1)], steps=ok_steps(_case))}, "1"),
        ({_case: F(proxy=[pconn(i) for i in range(1, 7)], steps=ok_steps(_case))}, "6"),
    ]
T["R17"] = [
    ({"A10": F(reqs=[rq("A10.s1")], steps=[st()])}, "经代理"),
    ({"A10": F(oreqs=[orq("A10.s1", via="direct")], direct=1, steps=[st()])}, "直连"),
    ({"A10": F(steps=[fail()])}, "报错"),
    ({"A10": F(steps=[st()])}, "其他：请求哪里都没出现，驱动却报告成功"),
]
T["R18"] = [
    ({"A11": F(tunnels=[tn()], oreqs=[orq("A11.s1")], steps=[st()])}, "经代理"),
    ({"A11": F(oreqs=[orq("A11.s1", via="direct")], direct=1, steps=[st()])}, "直连"),
    ({"A11": F(steps=[fail()])}, "报错"),
]
T["R19"] = [
    ({"A12": F(reqs=[rq("A12.s1", headers=[("Content-Length", "65536")])])}, "Content-Length"),
    ({"A12": F(reqs=[rq("A12.s1", headers=[("Transfer-Encoding", "chunked")])])}, "chunked"),
    ({"A12": F(reqs=[rq("A12.s1")])}, "其他：请求既没有 Transfer-Encoding: chunked 也没有 Content-Length"),
]
T["R20"] = [
    ({"A14": F(reqs=[rq("A14.s1", headers=[("Expect", "100-continue")])])}, "发"),
    ({"A14": F(reqs=[rq("A14.s1", headers=[("Content-Length", "2097152")])])}, "不发"),
]
T["R21"] = [
    ({"A15": F(tunnels=[tn(port=80, kind="http")], oreqs=[orq("A15.w1")])}, "CONNECT 到 80 端口，隧道里明文升级"),
    ({"A15": F(reqs=[rq("A15.w1", headers=[("Upgrade", "websocket")])])}, "绝对形式的 GET 加 Upgrade"),
    ({"A15": F(oreqs=[orq("A15.w1", via="direct")], direct=1)}, "直连"),
    ({"A15": F()}, "没到"),
]
T["R22"] = [
    ({"A16": F(tunnels=[tn()], oreqs=[orq("A16.w1")])}, "CONNECT 到 443 端口，隧道里 TLS"),
    ({"A16": F(oreqs=[orq("A16.w1", via="direct")], direct=1)}, "直连"),
    ({"A16": F()}, "没到"),
    ({"A16": F(tunnels=[tn(kind="http")], oreqs=[orq("A16.w1")])}, "其他：请求在隧道里，隧道经由 connect、目标端口 443、首包 http"),
]
T["R23"] = [
    ({"A01": F(proxy=[pconn(1, "47")]), "A02": F(proxy=[pconn(1, "43")]), "S01": F(proxy=[pconn(1, "05")])}, "G / C / 05"),
    ({"A01": F(proxy=[pconn(1, "50")]), "A02": F(proxy=[pconn(1, "16")]), "S01": F(proxy=[])}, "P / 16 / 没有连接"),
]


def _post(case, n, **kw):
    return F(oreqs=[orq("%s.s1" % case, body_len=kw.get("got", n), sha=kw.get("sha", body_sha(n)))])


T["R24"] = [
    ({"A12": _post("A12", 65536), "A13": _post("A13", 65536), "A14": _post("A14", 2097152)}, "完整"),
    ({"A12": _post("A12", 65536), "A13": _post("A13", 65536, got=100), "A14": F()}, "不完整（A13、A14）"),
    ({"A12": _post("A12", 65536, sha=EMPTY_SHA), "A13": _post("A13", 65536), "A14": _post("A14", 2097152)}, "不完整（A12）"),
]
T["R30"] = [
    ({"B01": F(reqs=[rq("B01.s1", auth="ok", user=U1)])}, "先带"),
    ({"B01": F(reqs=[rq("B01.s1", status=407), rq("B01.s1", seq=2, auth="ok", user=U1)])}, "等 407 再带"),
    ({"B01": F(reqs=[rq("B01.s1", status=407)])}, "始终不带"),
    ({"B01": F()}, "其他：代理端口上没有请求"),
]
T["R31"] = [
    ({"B02": F(reqs=[rq(form="connect", auth="ok", user=U1)])}, "先带"),
    ({"B02": F(reqs=[rq(form="connect", status=407), rq(form="connect", conn=2, auth="ok", user=U1)])}, "等 407 再带"),
    ({"B02": F(reqs=[rq(form="connect", status=407)])}, "始终不带"),
]
for _rid, _case, _form in (("R32", "B01", "absolute"), ("R33", "B02", "connect")):
    T[_rid] = [
        ({_case: F(reqs=[rq("x", form=_form, status=407), rq("x", form=_form, seq=2, auth="ok", user=U1)])}, "原连接"),
        ({_case: F(reqs=[rq("x", form=_form, status=407), rq("x", form=_form, conn=2, auth="ok", user=U1)])}, "新连接"),
        ({_case: F(reqs=[rq("x", form=_form, auth="ok", user=U1)])}, "不适用"),
        ({_case: F(reqs=[rq("x", form=_form, status=407)])}, "没有重试"),
        ({_case: F(reqs=[rq("x", form=_form, status=407, auth="bad", user=U1)])}, "其他：收到 407 之前就已经带了凭据"),
    ]
for _rid, _case in (("R34", "B03"), ("R35", "B04")):
    T[_rid] = [
        ({_case: F(reqs=[rq("x", status=407, close=True), rq("x", conn=2, auth="ok", user=U1)], steps=[st()])}, "成功"),
        ({_case: F(reqs=[rq("x", status=407, close=True)], steps=[fail()])}, "失败"),
        ({_case: F(reqs=[rq("x", auth="ok", user=U1)], steps=[st()])}, "不适用"),
    ]
T["R36"] = [
    ({"B05": F(reqs=[rq("B05.s%d" % i, seq=i, auth="ok", user=U1) for i in (1, 2, 3)], steps=ok_steps("B05"))}, "3/0"),
    ({"B05": F(reqs=[rq("B05.s1", seq=i, status=407) for i in (1, 3, 5)] + [rq("B05.s1", seq=i, auth="ok", user=U1) for i in (2, 4, 6)], steps=ok_steps("B05"))}, "6/3"),
]
_b = "b.kaoju.test:443"
T["R37"] = [
    ({"B06": F(reqs=[rq(form="connect", auth="ok", user=U1), rq(form="connect", conn=2, target=_b, auth="ok", user=U1)])}, "先带"),
    ({"B06": F(reqs=[rq(form="connect", auth="ok", user=U1), rq(form="connect", conn=2, target=_b, status=407), rq(form="connect", conn=2, seq=2, target=_b, auth="ok", user=U1)])}, "等 407 再带"),
    ({"B06": F(reqs=[rq(form="connect", auth="ok", user=U1)])}, "其他：没有目标是 b.kaoju.test 的 CONNECT"),
    ({"B06": F(reqs=[rq(form="connect", target=_b, status=407)])}, "其他：对 b.kaoju.test 的 CONNECT 始终不带凭据"),
]
_r39 = ["B02", "B07", "B08", "B09", "B10", "B12"]
T["R39"] = [
    ({c: F(oreqs=[orq("%s.s1" % c)]) for c in _r39}, "没有"),
    (dict({c: F(oreqs=[orq("%s.s1" % c)]) for c in _r39}, B08=F(oreqs=[orq("B08.s1b", pa=True)]), B10=F(oreqs=[orq("B10.s1b", via="direct", pa=True)])), "有（B08、B10）"),
    (dict({c: F(oreqs=[orq("%s.s1" % c)]) for c in _r39}, B07=F(oreqs=[orq("B07.s1", via="forward", pa=True)])), "没有"),
]
T["R40"] = [
    ({c: F(oreqs=[orq("%s.s1b" % c)], steps=[st()]) for c in ("B08", "B09", "B10")}, "都成功"),
    ({"B08": F(oreqs=[orq("B08.s1b")], steps=[st()]), "B09": F(steps=[fail()]), "B10": F(oreqs=[orq("B10.s1b")], steps=[st(status=302)])}, "失败（B09、B10）"),
]
T["R41"] = [
    ({"B11": F(reqs=[rq("B11.s1", auth="ok", user=U1), rq("B11.s2", seq=2, auth="ok", user=U2), rq("B11.s3", seq=3, auth="ok", user=U1)])}, "各用各的凭据"),
    ({"B11": F(reqs=[rq("B11.s1", auth="ok", user=U1), rq("B11.s2", seq=2, auth="ok", user=U1), rq("B11.s3", seq=3, auth="ok", user=U1)])}, "用错了凭据"),
    ({"B11": F(reqs=[rq("B11.s1", auth="ok", user=U1)])}, "其他：s2 没有通过认证的请求"),
]
for _rid, _case, _via, _good, _bad in (("R42", "B12", "connect", "各开各的隧道", "用了别人的隧道"), ("R124", "S14", "socks5", "各开各的连接", "用了别人的连接")):
    T[_rid] = [
        ({_case: F(tunnels=[tn(1, via=_via, user=U1), tn(2, via=_via, conn=2, user=U2)], oreqs=[orq("%s.s1" % _case), orq("%s.s2" % _case, tunnel=2), orq("%s.s3" % _case)])}, _good),
        ({_case: F(tunnels=[tn(1, via=_via, user=U1)], oreqs=[orq("%s.s1" % _case), orq("%s.s2" % _case), orq("%s.s3" % _case)])}, _bad),
        ({_case: F(tunnels=[tn(1, via=_via, user=U1)], oreqs=[orq("%s.s1" % _case)])}, "其他：s2 的请求没到源站"),
    ]
T["R43"] = [
    ({"B13": F(reqs=[rq("B13.s1", auth="ok", user=U1, body_len=65536)], steps=[st()])}, "1"),
    ({"B13": F(reqs=[rq("B13.s1", status=407, body_len=65536), rq("B13.s1", seq=2, auth="ok", user=U1, body_len=65536)], steps=[st()])}, "2"),
    ({"B13": F(reqs=[rq("B13.s1", status=407, body_len=0), rq("B13.s1", seq=2, auth="ok", user=U1, body_len=65536)], steps=[st()])}, "1"),
]
T["R44"] = [
    ({"B14": F(reqs=[rq(form="connect", conn=i, auth="ok", user=U1) for i in range(1, 7)], steps=ok_steps("B14"))}, "0"),
    ({"B14": F(reqs=[rq(form="connect", conn=i, status=407) for i in range(1, 7)] + [rq(form="connect", conn=i, seq=2, auth="ok", user=U1) for i in range(1, 7)], steps=ok_steps("B14"))}, "6"),
]
for _rid, _case, _code in (("R45", "C01", 407), ("R46", "C02", 407), ("R49", "C04", 407), ("R50", "C05", 403), ("R51", "C08", 403)):
    T[_rid] = [
        ({_case: F(steps=[st(status=_code)])}, "拿到 %d 响应" % _code),
        ({_case: F(steps=[fail(text="CONNECT tunnel failed, response %d" % _code)])}, "报错，提到 %d" % _code),
        ({_case: F(steps=[fail(text="tunnel failed x%d0 on port 1%d" % (_code, _code))])}, "报错，没提 %d" % _code),
        ({_case: F(steps=[st(status=200)])}, "200"),
    ]
for _rid, _case, _form in (("R47", "C03", "absolute"), ("R48", "C04", "connect")):
    T[_rid] = [
        ({_case: F(reqs=[rq("x", form=_form, auth="bad", user=U1, status=407)])}, "1"),
        ({_case: F(reqs=[rq("x", form=_form, status=407), rq("x", form=_form, seq=2, auth="bad", user=U1, status=407), rq("x", form=_form, seq=3, auth="bad", user=U1, status=407)])}, "2"),
        ({_case: F(reqs=[rq("x", form=_form, status=407)])}, "0"),
    ]
for _rid, _case, _form in (("R52", "C06", "absolute"), ("R53", "C07", "connect")):
    T[_rid] = [
        ({_case: F(reqs=[rq("x", form=_form, auth="ok", user=U1)])}, "带"),
        ({_case: F(reqs=[rq("x", form=_form)])}, "不带"),
        ({_case: F()}, "其他：代理端口上没有请求"),
    ]
for _n in range(60, 71):
    _rid = "R%d" % _n
    _case = ROW[_rid]["cases"][0]
    _u = CASE[_case]["users"][0]
    T[_rid] = [
        ({_case: F(reqs=[rq(form="connect", status=407), rq(form="connect", seq=2, auth="ok", user=_u["user"], raw=creds(_u["user"], _u["pass"]))], steps=[st()])}, "原样"),
        ({_case: F(reqs=[rq(form="connect", auth="ok", user="x", raw=creds(_u["user"] + "x", _u["pass"]))], steps=[st()])}, "变了"),
        ({_case: F(reqs=[rq(form="connect", auth="bad", raw="Basic !!!notbase64")], steps=[fail()])}, "变了"),
        ({_case: F(reqs=[rq(form="connect", status=407)], steps=[fail()])}, "客户端报错"),
        ({_case: F(reqs=[rq(form="connect")], steps=[st()])}, "没发凭据"),
    ]
for _rid, _case, _code in (("R80", "E01", 502), ("R82", "E02", 403), ("R86", "E05", 403)):
    T[_rid] = [
        ({_case: F(steps=[fail(text=MARK_ALL.replace("502", str(_code)))])}, "状态码、原因短语、响应头、正文"),
        ({_case: F(steps=[fail(text="tunnel failed, response %d" % _code)])}, "状态码"),
        ({_case: F(steps=[fail(text="Proxy-Status: KaojuStatusMarker")])}, "响应头"),
        ({_case: F(steps=[fail(text="connection failed (port 1%d)" % _code)])}, "都看不到"),
    ]
T["R81"] = [
    ({"E01": F(steps=[fail(text="response 502", extra="< HTTP/1.1 502 KaojuReasonMarker\n< X-Kaoju-Note: KaojuHeaderMarker", how="-v")])}, "状态码、原因短语、响应头"),
    ({"E01": F(steps=[fail(text="failed", extra="nothing useful", how="-v")])}, "都看不到"),
    ({"E01": F(steps=[fail(text="response 502")])}, "没有这样的手段"),
]
T["R83"] = [
    ({"E03": F(reqs=[rq(form="connect", status=503)])}, "1"),
    ({"E03": F(reqs=[rq(form="connect", status=503), rq(form="connect", conn=2, status=503)])}, "2"),
]
for _rid, _case in (("R84", "E04"), ("R87", "E06")):
    T[_rid] = [
        ({_case: F(steps=[st(text="200 OK\nX-Kaoju-Note: KaojuHeaderMarker")])}, "看得到"),
        ({_case: F(steps=[st(text="200 OK\nProxy-Status: kaoju; details=\"KaojuStatusMarker\"")])}, "看得到"),
        ({_case: F(steps=[st(text="200 OK", extra="KaojuHeaderMarker")])}, "看不到"),
    ]
T["R85"] = [
    ({"E04": F(steps=[st(text="200", extra="< X-Kaoju-Note: KaojuHeaderMarker", how="-v")])}, "看得到"),
    ({"E04": F(steps=[st(text="200", extra="< HTTP/1.1 200 Connection established", how="-v")])}, "看不到"),
    ({"E04": F(steps=[st(text="200 KaojuHeaderMarker")])}, "没有这样的手段"),
]
_f = "fail.kaoju.test:443"
T["R88"] = [
    ({"E07": F(reqs=[rq(form="connect", target=_f, status=502), rq(form="connect", seq=2)])}, "原连接"),
    ({"E07": F(reqs=[rq(form="connect", target=_f, status=502), rq(form="connect", conn=2)])}, "新连接"),
    ({"E07": F(reqs=[rq(form="connect", target=_f, status=502)])}, "没有第二个 CONNECT"),
    ({"E07": F(reqs=[rq(form="connect")])}, "其他：没有目标是 fail.kaoju.test 的 CONNECT"),
]
T["R89"] = [
    ({"E07": F(steps=[fail("s1"), st("s2")])}, "成功"),
    ({"E07": F(steps=[fail("s1"), fail("s2")])}, "失败"),
]
T["R90"] = [
    ({"F01": F(reqs=[rq("F01.s1"), rq("F01.s2", conn=2)], steps=[st("s1"), st("s2")], actions=[act("conn_idle_close")])}, "换新连接，成功"),
    ({"F01": F(reqs=[rq("F01.s1")], steps=[st("s1"), fail("s2")], actions=[act("conn_idle_close")])}, "失败"),
    ({"F01": F(reqs=[rq("F01.s1"), rq("F01.s2", seq=2)], steps=[st("s1"), st("s2")])}, "其他：s2 成功，但与 s1 在同一条代理连接上（空闲关闭没有发生）"),
]
T["R91"] = [
    ({"F02": F(tunnels=[tn(1), tn(2, conn=2)], oreqs=[orq("F02.s1"), orq("F02.s2", tunnel=2)], steps=[st("s1"), st("s2")], actions=[act("tunnel_idle_close")])}, "换新隧道，成功"),
    ({"F02": F(tunnels=[tn(1)], oreqs=[orq("F02.s1")], steps=[st("s1"), fail("s2")])}, "失败"),
]
for _rid in ("R92", "R93", "R96", "R98"):
    _case = ROW[_rid]["cases"][0]
    _k = CASE[_case]["profile"]["conn"]["drop"]["k"]
    _sid = _k.split(".")[1]
    T[_rid] = [
        ({_case: F(reqs=[rq(_k), rq(_k, conn=2)], steps=[st(_sid)], actions=[act("conn_drop", _k)])}, "2 次，成功"),
        ({_case: F(reqs=[rq(_k)], steps=[fail(_sid)], actions=[act("conn_drop", _k)])}, "1 次，失败"),
        ({_case: F(reqs=[rq(_k)], steps=[st(_sid)])}, "未触发"),
    ]
for _rid in ("R94", "R95", "R97", "R99", "R101"):
    _case = ROW[_rid]["cases"][0]
    _k = CASE[_case]["profile"]["origin"]["drop"]["k"]
    _sid = _k.split(".")[1]
    T[_rid] = [
        ({_case: F(oreqs=[orq(_k, action="drop"), orq(_k, tunnel=2)], steps=[st(_sid)], actions=[act("origin_drop", _k)])}, "2 次，成功"),
        ({_case: F(oreqs=[orq(_k, action="drop")], steps=[fail(_sid)], actions=[act("origin_drop", _k)])}, "1 次，失败"),
        ({_case: F(oreqs=[orq(_k)], steps=[st(_sid)], actions=[act("conn_drop", _k)])}, "未触发"),
    ]
T["R100"] = [
    ({"F11": F(reqs=[rq(form="connect", status=None)], steps=[fail()], actions=[act("connect_drop")])}, "1 次，失败"),
    ({"F11": F(reqs=[rq(form="connect", status=None), rq(form="connect", conn=2)], steps=[st()], actions=[act("connect_drop")])}, "2 次，成功"),
]
for _rid, _case in (("R110", "S01"), ("R111", "S05")):
    T[_rid] = [
        ({_case: F(socks=[sk(methods=(0,))])}, "00"),
        ({_case: F(socks=[sk(methods=(0, 1, 2))])}, "00,01,02"),
        ({_case: F()}, "其他：没有 SOCKS5 的方法协商"),
    ]
T["R112"] = [
    ({"S01": F(socks=[sk(atyp=3)])}, "域名"),
    ({"S01": F(socks=[sk(atyp=1)])}, "IPv4"),
    ({"S01": F(socks=[sk(atyp=4)])}, "IPv6"),
    ({"S01": F(socks=[sk()])}, "其他：没有 socks5_request"),
]
T["R113"] = [
    ({"S03": F(socks=[sk(atyp=3)])}, "域名"),
    ({"S03": F(socks=[sk(atyp=1)])}, "IPv4"),
    ({"S03": F(socks=[sk(atyp=4)])}, "IPv6"),
    ({"S03": F(direct=1)}, "直连"),
    ({"S03": F()}, "没连代理"),
]
T["R114"] = [
    ({"S04": F(steps=[fail()])}, "没连代理就报错"),
    ({"S04": F(socks=[sk(atyp=3)], steps=[st()])}, "把域名交给了代理"),
    ({"S04": F(socks=[sk()], steps=[fail()])}, "其他"),
    ({"S04": F(socks=[sk(atyp=1)], steps=[st()])}, "其他"),
]
T["R117"] = [
    ({"S05": F(socks=[sk(auth=sauth(U1, "kaoju-pass-1"))], steps=[st()])}, "成功"),
    ({"S05": F(socks=[sk(auth=sauth(U1, "x", status=1))], steps=[fail()])}, "失败"),
    ({"S05": F(socks=[sk()], steps=[st()])}, "失败"),
]
T["R118"] = [
    ({"S06": F(steps=[st()])}, "成功"),
    ({"S06": F(steps=[fail()])}, "失败"),
]
for _rid, _case in (("R119", "S07"), ("R120", "S08")):
    T[_rid] = [
        ({_case: F(steps=[fail(text="curl: (97) No authentication method was acceptable.")])}, "提到认证或方法"),
        ({_case: F(steps=[fail(text="SOCKS5 Password rejected")])}, "提到认证或方法"),
        ({_case: F(steps=[fail(text="connection closed unexpectedly")])}, "只说失败"),
        ({_case: F(steps=[st()])}, "其他：这一步没有报错（ok=True status=200）"),
    ]
T["R121"] = [
    ({c: F(steps=[fail(text="Can't complete SOCKS5 connection to a.kaoju.test?k=%s.s1 port 40%s23. (%d)" % (c, c[1:], n))]) for c, n in (("S09", 2), ("S10", 4), ("S11", 5))}, "能区分"),
    ({c: F(steps=[fail(text="SOCKS5 failed for k=%s.s1 after 1%s34 ms" % (c, c[1:]))]) for c in ("S09", "S10", "S11")}, "不能区分"),
    ({"S09": F(steps=[fail(text="a")]), "S10": F(steps=[fail(text="b")]), "S11": F(steps=[fail(text="a")])}, "不能区分"),
]
for _n in range(125, 133):
    _rid = "R%d" % _n
    _case = ROW[_rid]["cases"][0]
    _u = CASE[_case]["users"][0]
    T[_rid] = [
        ({_case: F(socks=[sk(auth=sauth(_u["user"], _u["pass"]))], steps=[st()])}, "原样"),
        ({_case: F(socks=[sk(auth=sauth(_u["user"][:5], _u["pass"]))], steps=[st()])}, "变了"),
        ({_case: F(socks=[sk(auth=sauth(_u["user"], _u["pass"] + "x"))], steps=[fail()])}, "变了"),
        ({_case: F(socks=[sk()], steps=[fail()])}, "客户端报错"),
        ({_case: F(socks=[sk()], steps=[st()])}, "没发凭据"),
    ]


def variant_for(rid):
    """A15、A16 只对 only 里的列运行，行函数的测试用其中一列。"""
    only = CASE[ROW[rid]["cases"][0]].get("only")
    return only[0] if only else "curl"


class RowTests(unittest.TestCase):
    def test_every_row_registered_and_documented(self):
        self.assertEqual(len(ROW), 104)
        for rid, rd in ROW.items():
            self.assertIn(rid, matrix.ROWS, rid)
            self.assertEqual(matrix.ROWS[rid].__doc__, rd["how"], "%s 的文档字符串应当是 rows.json 的 how" % rid)
        self.assertEqual(set(matrix.ROWS), set(ROW))

    def test_every_row_has_two_synthetic_values(self):
        for rid in ROW:
            self.assertIn(rid, T, "%s 没有合成用例" % rid)
            self.assertGreaterEqual(len(T[rid]), 2, rid)
            self.assertGreaterEqual(len({exp for _, exp in T[rid] if not exp.startswith("其他：")}), 2, "%s 至少要覆盖两个取值" % rid)

    def test_rows(self):
        for rid in sorted(T, key=lambda x: int(x[1:])):
            for i, (facts, expected) in enumerate(T[rid]):
                with self.subTest(row=rid, i=i):
                    c = cell(rid, facts, variant_for(rid))
                    self.assertEqual(c["value"], expected)
                    self.assertTrue(c["stable"])

    def test_synthetic_values_are_listed_in_rows_json(self):
        """合成用例的预期取值，凡是 rows.json 的 values 里是固定字符串的行，都应当出自那张列表。"""
        for rid, rows in T.items():
            listed = ROW[rid]["values"]
            if any(v.startswith("（") for v in listed):
                continue
            for _, expected in rows:
                if expected.startswith("其他：") or rid in ("R45", "R46", "R49", "R50", "R51") and expected.isdigit():
                    continue
                if any("（用例号）" in v and expected.startswith(v.split("（")[0] + "（") for v in listed):
                    continue
                self.assertIn(expected, listed, rid)

    def test_r07_footnote_has_min_and_max(self):
        col = {"A02": {str(i + 1): F(tunnels=[tn(record_len=n)]) for i, n in enumerate((512, 517, 1500))}}
        c = matrix.compute_cell(ROW["R07"], "curl", col, CASE)
        self.assertFalse(c["stable"])
        self.assertEqual(c["value"], "不超过 1460 字节 / 超过 1460 字节")
        self.assertTrue(any("最小 517、最大 1505" in n for n in c["footnotes"]), c["footnotes"])

    def test_changed_bytes_go_to_footnote(self):
        u = CASE["D03"]["users"][0]
        c = cell("R62", {"D03": F(reqs=[rq(form="connect", auth="ok", raw=creds("sess@abA+c/d e", u["pass"]))], steps=[st()])})
        self.assertEqual(c["value"], "变了")
        self.assertTrue(any(b"sess@abA+c/d e".hex() in n for n in c["footnotes"]), c["footnotes"])
        self.assertEqual(c["data"]["1"]["received_hex"], (b"sess@abA+c/d e:" + u["pass"].encode()).hex())

    def test_colon_in_user_compares_whole_string(self):
        u = CASE["D11"]["users"][0]
        self.assertEqual(val("R70", {"D11": F(reqs=[rq(form="connect", auth="ok", user="sess", raw=creds(u["user"], u["pass"]))], steps=[st()])}), "原样")

    def test_close_annotation(self):
        f = F(reqs=[rq(form="connect", status=407, close=True), rq(form="connect", conn=2, auth="ok", user=U1)])
        c = cell("R33", {"B02": f})
        self.assertEqual(c["value"], "新连接")
        self.assertTrue(any("close 为真而配置没有要求" in n for n in c["footnotes"]))
        f["profile"]["auth"]["on407"] = "close"
        self.assertEqual(cell("R33", {"B02": f})["footnotes"], [])

    def test_count_rows_note_failed_steps(self):
        c = cell("R10", {"A03": F(tunnels=[tn()], steps=[st("s1"), fail("s2"), st("s3")])})
        self.assertEqual(c["value"], "1")
        self.assertTrue(any("s2" in n for n in c["footnotes"]))

    def test_body_sha_matches_run_py(self):
        self.assertEqual(matrix.body_sha256(65536), body_sha(65536))
        self.assertEqual(matrix.body_sha256(1024), body_sha(1024))
        try:
            import run as run_mod
        except Exception:  # run.py 导入不了时只比上面两条
            return
        self.assertEqual(matrix.body_sha256(1000), hashlib.sha256(run_mod.body_bytes(1000)).hexdigest())


class GenericRuleTests(unittest.TestCase):
    def good(self):
        return F(reqs=[rq("A01.s1")], steps=[st()])

    def test_unsupported(self):
        c = cell("R01", {"A01": F(unsupported="这个客户端没法配代理凭据")})
        self.assertEqual(c["value"], "不支持")
        self.assertTrue(any("没法配代理凭据" in n for n in c["footnotes"]))
        self.assertEqual(val("R41", {"B11": F(unsupported="同一个进程换不了用户")}), "不支持")

    def test_not_applicable_by_only(self):
        c = matrix.compute_cell(ROW["R21"], "curl", {}, CASE)
        self.assertEqual(c["value"], "不适用")
        skipped = {"A15": {"1": {"run": run(skipped="only", has_result=False, pcap_status=None, tcpdump_dropped=None)}}}
        self.assertEqual(matrix.compute_cell(ROW["R21"], "curl", skipped, CASE)["value"], "不适用")
        f = F(reqs=[rq("A15.w1", headers=[("Upgrade", "websocket")])])
        self.assertEqual(val("R21", {"A15": f}, variant="chromium-pw"), "绝对形式的 GET 加 Upgrade")

    def test_unverified_when_any_repeat_fails_pcap(self):
        for bad in (dict(pcap_status="mismatch"), dict(pcap_status="error"), dict(pcap_status="missing"), dict(pcap_status=None), dict(tcpdump_dropped=3), dict(tcpdump_dropped=None)):
            col = {"A01": {"1": self.good(), "2": F(reqs=[rq("A01.s1")], steps=[st()], **bad), "3": self.good()}}
            c = matrix.compute_cell(ROW["R01"], "curl", col, CASE)
            self.assertEqual(c["value"], "未通过核对", bad)
            self.assertEqual(c["per_repeat"], {})
            self.assertTrue(any("第 2 遍" in n for n in c["footnotes"]))

    def test_prefix_passes_pcap(self):
        col = {"A01": {"1": self.good(), "2": F(reqs=[rq("A01.s1")], pcap_status="prefix")}}
        self.assertEqual(matrix.compute_cell(ROW["R01"], "curl", col, CASE)["value"], "绝对形式")

    def test_unverified_in_any_case_of_multi_case_row(self):
        col = {"A01": {"1": F(proxy=[pconn(1, "47")])}, "A02": {"1": F(proxy=[pconn(1, "43")], pcap_status="mismatch")}, "S01": {"1": F(proxy=[pconn(1, "05")])}}
        self.assertEqual(matrix.compute_cell(ROW["R23"], "curl", col, CASE)["value"], "未通过核对")

    def test_allow_unchecked_is_flagged(self):
        col = {"A01": {"1": F(reqs=[rq("A01.s1")], pcap_status="missing")}}
        c = matrix.compute_cell(ROW["R01"], "curl", col, CASE, allow_unchecked=True)
        self.assertEqual(c["value"], "绝对形式")
        self.assertTrue(any("未经抓包核对" in n for n in c["footnotes"]))

    def test_no_result(self):
        self.assertEqual(val("R01", {"A01": F(driver_timeout=True)}), "没有结果")
        self.assertEqual(val("R01", {"A01": F(has_result=False, driver_exit=1)}), "没有结果")
        self.assertEqual(val("R01", {"A01": F(reqs=[rq("A01.s1")], runner_errors=["obsproxy 没起来"])}), "没有结果")
        self.assertEqual(val("R01", {"A01": F(reqs=[rq("A01.s1")], events_complete=False)}), "没有结果")

    def test_unstable(self):
        col = {"A03": {"1": F(tunnels=[tn()], steps=ok_steps("A03")), "2": F(tunnels=[tn(1), tn(2, conn=2)], steps=ok_steps("A03")), "3": F(tunnels=[tn()], steps=ok_steps("A03"))}}
        c = matrix.compute_cell(ROW["R10"], "curl", col, CASE)
        self.assertEqual((c["value"], c["stable"]), ("1 / 2", False))
        self.assertEqual(c["per_repeat"], {"1": "1", "2": "2", "3": "1"})
        self.assertEqual(matrix.cell_text(c), "1 / 2（不稳定）")
        self.assertEqual(c["cases"], {"A03": ["1", "2", "3"]})

    def test_stable_three_repeats(self):
        col = {"A01": {str(i): self.good() for i in (1, 2, 3)}}
        c = matrix.compute_cell(ROW["R01"], "curl", col, CASE)
        self.assertEqual((c["value"], c["stable"], c["footnotes"]), ("绝对形式", True, []))

    def test_unsupported_in_one_repeat_is_unstable(self):
        col = {"A01": {"1": self.good(), "2": F(unsupported="x")}}
        c = matrix.compute_cell(ROW["R01"], "curl", col, CASE)
        self.assertEqual((c["value"], c["stable"]), ("绝对形式 / 不支持", False))

    def test_multi_case_partial(self):
        facts = {c: F(oreqs=[orq("%s.s1" % c)]) for c in _r39}
        facts["B12"] = F(unsupported="换不了用户")
        c = cell("R39", facts)
        self.assertEqual(c["value"], "没有（不含 B12：不支持）")
        self.assertTrue(any("换不了用户" in n for n in c["footnotes"]))
        self.assertEqual(val("R39", {c: F(unsupported="x") for c in _r39}), "不支持")

    def test_r23_per_position(self):
        facts = {"A01": F(proxy=[pconn(1, "47")]), "A02": F(proxy=[pconn(1, "43")]), "S01": F(unsupported="没有 SOCKS5")}
        self.assertEqual(val("R23", facts), "G / C / 不支持")

    def test_other_for_uncovered(self):
        v = val("R04", {"A02": F()})
        self.assertTrue(v.startswith("其他："))

    def test_unexpected_shape_is_reported_not_raised(self):
        f = F()
        f["http_requests"] = [{"k": "A01.s1"}, None]
        self.assertTrue(val("R01", {"A01": f}).startswith("其他：取值时出错"))

    def test_no_data_gives_none(self):
        self.assertIsNone(matrix.compute_cell(ROW["R01"], "curl", {}, CASE))

    def test_missing_step_is_other(self):
        self.assertEqual(val("R89", {"E07": F(steps=[st("s1")])}), "其他：驱动结果里没有 s2 这一步")


class OutputTests(unittest.TestCase):
    def observations(self):
        return {
            "curl": {"A01": {str(i): F(reqs=[rq("A01.s1", headers=[("Proxy-Connection", "Keep-Alive")])], steps=[st()]) for i in (1, 2, 3)}},
            "go": {"A01": {"1": F(reqs=[rq("A01.s1")], steps=[st()]), "2": F(tunnels=[tn(port=80, kind="http")], oreqs=[orq("A01.s1")], steps=[st()])}},
            "rawref": {"A01": {"1": F(reqs=[rq("A01.s1")], steps=[st()])}},
        }

    def test_columns_follow_protocol(self):
        cols = matrix.protocol_columns(os.path.join(BASE, "PROTOCOL.md"))
        self.assertEqual(cols, matrix.COLUMNS_FALLBACK)
        self.assertNotIn("rawref", cols)

    def test_matrix_and_markdown(self):
        m = matrix.build_matrix(ROWS_DOC["rows"], CASE, self.observations(), matrix.COLUMNS_FALLBACK)
        self.assertEqual(m["columns"], matrix.COLUMNS_FALLBACK)
        self.assertEqual(m["columns_with_data"], ["curl", "go"])
        self.assertIn("requests", m["columns_missing"])
        r01 = m["rows"][0]
        self.assertEqual(r01["cells"]["curl"]["value"], "绝对形式")
        self.assertIsNone(r01["cells"]["requests"])
        self.assertEqual(set(r01["cells"]["curl"]) - {"data"}, {"value", "stable", "per_repeat", "footnotes", "cases"})
        md = matrix.render_md(m, 3)
        self.assertNotIn("rawref", md)
        sections = [l[3:] for l in md.splitlines() if l.startswith("## ")]
        self.assertEqual(sections, ["基线", "认证", "用户名和密码的字节（HTTP 代理）", "代理报错时调用方能看到什么", "连接被关以后", "SOCKS5 入口"])
        line = next(l for l in md.splitlines() if l.startswith("| R01 "))
        cells = [c.strip() for c in line.strip("|").split("|")]
        self.assertEqual(len(cells), 1 + len(matrix.COLUMNS_FALLBACK))
        self.assertEqual(cells[1], "绝对形式")
        self.assertEqual(cells[3], "")
        self.assertEqual(cells[4], "绝对形式 / CONNECT 到 80 端口（不稳定）")
        self.assertIn("没有数据的列", md)
        self.assertIn("`go` ", md.split("不足 3 遍的格子数")[1].splitlines()[0])
        line21 = next(l for l in md.splitlines() if l.startswith("| R21 "))
        self.assertEqual([c.strip() for c in line21.strip("|").split("|")][1], "不适用")

    def test_markdown_footnotes(self):
        obs = {"curl": {"A02": {"1": F(tunnels=[tn(record_len=512)])}}}
        md = matrix.render_md(matrix.build_matrix(ROWS_DOC["rows"], CASE, obs, ["curl"]), 3)
        line = next(l for l in md.splitlines() if l.startswith("| R07 "))
        self.assertIn("不超过 1460 字节 [", line)
        self.assertIn("R07，`curl`：ClientHello 长度", md)

    def test_markdown_escapes_pipe(self):
        self.assertEqual(matrix.md_escape("a|b\nc"), "a\\|b c")

    def test_selfcheck(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "selfcheck_expected.json")
            answers = {rd["id"]: "不适用" for rd in ROWS_DOC["rows"]}
            answers["R01"] = "绝对形式"
            write_json(p, {"rows": answers})
            sc = matrix.build_selfcheck(ROWS_DOC["rows"], CASE, self.observations(), p)
            self.assertTrue(sc["has_data"])
            self.assertFalse(sc["pass"])
            bad = {m["row"] for m in sc["mismatches"]}
            self.assertNotIn("R01", bad)
            self.assertIn("R02", bad)
        sc = matrix.build_selfcheck(ROWS_DOC["rows"], CASE, {"curl": {}}, None)
        self.assertFalse(sc["has_data"])
        self.assertIsNone(sc["pass"])

    def test_expectation_diff(self):
        m = matrix.build_matrix(ROWS_DOC["rows"], CASE, self.observations(), matrix.COLUMNS_FALLBACK)
        with tempfile.TemporaryDirectory() as d:
            exp = {
                "variant": "curl",
                "rows": {
                    "R01": {"expect": "绝对形式", "basis": "文档", "confidence": "high"},
                    "R02": {"expect": "无", "basis": "源码 a|b", "confidence": "medium"},
                    "R03": {"expect": "不知道", "basis": "", "confidence": "low"},
                    "R05": {"expect": "同目标", "basis": "", "confidence": "low"},
                    "R21": {"expect": "不适用", "basis": "", "confidence": "high"},
                },
            }
            write_json(os.path.join(d, "curl.json"), exp)
            write_json(os.path.join(d, "go.json"), {"variant": "go", "rows": {"R01": {"expect": "绝对形式"}}})
            diff = matrix.build_expectation_diff(m, d)
        res = diff["columns"]["curl"]
        self.assertEqual((res["compared"], res["matched"], res["no_data"]), (3, 2, 1))
        self.assertEqual(res["unknown"], 104 - 4)
        self.assertEqual([x["row"] for x in res["diffs"]], ["R02"])
        self.assertEqual(res["diffs"][0]["actual"], "Proxy-Connection: Keep-Alive")
        self.assertEqual([x["row"] for x in diff["columns"]["go"]["diffs"]], ["R01"])
        self.assertFalse(diff["columns"]["go"]["diffs"][0]["stable"])
        md = matrix.render_diff_md(diff)
        self.assertIn("| R02 ", md)
        self.assertIn("源码 a\\|b", md)
        self.assertIsNone(matrix.build_expectation_diff(m, os.path.join(d, "nope")))


# ---------------------------------------------------------------------------
# derive


def ev(name, conn=None, **kw):
    d = {"t": 1.0, "ev": name}
    if conn is not None:
        d["conn"] = conn
    d.update(kw)
    return d


def auth_obj(user=None, pw=None, result="none"):
    if user is None:
        return {"present": False, "scheme": None, "raw": None, "user": None, "user_hex": None, "pass": None, "pass_hex": None, "lenient": False, "result": "none"}
    return {"present": True, "scheme": "Basic", "raw": creds(user, pw), "user": user, "user_hex": user.encode().hex(), "pass": pw, "pass_hex": pw.encode().hex(), "lenient": False, "result": result}


def record(case, events, steps, variant="curl", repeat=1, **kw):
    rec = {
        "variant": variant,
        "case": case,
        "repeat": repeat,
        "ports": {"proxy_port": 1, "origin_http_port": 2, "origin_https_port": 3},
        "events": [ev("start", profile={"auth": {"mode": "basic", "on407": "keepalive"}, "connect": {"fail": None}})] + events + [ev("end")],
        "result": {"variant": variant, "unsupported": None, "steps": steps},
        "driver": {"exit": 0, "timeout": False, "stderr_tail": "", "ms": 5},
        "tcpdump": {"captured": 10, "received": 20, "dropped": 0},
        "pcap_check": {"status": "ok", "problems": []},
        "skipped": None,
        "runner_errors": [],
    }
    rec.update(kw)
    return rec


def b02_events():
    """等 407 再带凭据的 HTTPS GET：一条连接，两个 CONNECT，一条隧道。"""
    return [
        ev("accept", 1, listener="proxy", peer_port=5),
        ev("first_bytes", 1, listener="proxy", n_first_read=60, hex="434f4e4e45435420", kind="http"),
        ev("http_request", 1, seq=1, form="connect", method="CONNECT", target="a.kaoju.test:443", version="HTTP/1.1", k=None, headers=[["Host", "a.kaoju.test:443"], ["Proxy-Connection", "Keep-Alive"]], body_len=0, body_sha256=EMPTY_SHA, auth=auth_obj(), error=None),
        ev("http_response", 1, seq=1, status=407, reason="Proxy Authentication Required", headers=[["Content-Length", "0"]], by="proxy", cause="auth_required", close=False),
        ev("http_request", 1, seq=2, form="connect", method="CONNECT", target="a.kaoju.test:443", version="HTTP/1.1", k=None, headers=[["Host", "a.kaoju.test:443"], ["Proxy-Authorization", creds(U1, "kaoju-pass-1")]], body_len=0, body_sha256=EMPTY_SHA, auth=auth_obj(U1, "kaoju-pass-1", "ok"), error=None),
        ev("http_response", 1, seq=2, status=200, reason="Connection established", headers=[], by="proxy", cause="connect_ok", close=False),
        ev("tunnel_open", 1, tunnel=1, via="connect", req_seq=2, target_host="a.kaoju.test", target_port=443, mapped="origin_https"),
        ev("tunnel_first_bytes", 1, tunnel=1, n_first_read=517, early_bytes=0, n_buffered=517, hex="16030102", kind="tls_client_hello", tls={"record_len": 512, "complete": True, "sni": "a.kaoju.test", "alpn": ["h2", "http/1.1"]}),
        ev("origin_conn", 1, oconn=1, via="tunnel", tunnel=1, listener="origin_https", tls=True, alpn="h2", error=None),
        ev("origin_request", 1, oconn=1, tunnel=1, via="tunnel", seq=1, req_seq=None, k="B02.s1", method="GET", path="/echo", query="k=B02.s1", proto="HTTP/2.0", host="a.kaoju.test", headers=[["Accept", "*/*"]], body_len=0, body_sha256=EMPTY_SHA, has_proxy_authorization=False, tls=True, action="respond", status=200),
        ev("tunnel_close", 1, tunnel=1, by="client", reason="client_eof", bytes_c2s=700, bytes_s2c=1500),
        ev("conn_end", 1, listener="proxy", by="client", close="fin", reason="client_eof", bytes_in=900, bytes_out=1700),
    ]


class DeriveTests(unittest.TestCase):
    def test_http_tunnel_flow(self):
        rec = record("B02", b02_events(), [{"id": "s1", "ok": True, "status": 200, "default_text": "200", "extra_text": "KaojuHeaderMarker", "extra_how": "-v"}])
        f = derive.derive(rec)
        self.assertEqual(f["proxy_conn_count"], 1)
        self.assertEqual(f["proxy_conns"][0]["first_byte"], "43")
        self.assertEqual(f["direct_conn_count"], 0)
        self.assertEqual([(r["conn"], r["seq"], r["form"], r["auth"]["result"], r["response"]["status"]) for r in f["http_requests"]], [(1, 1, "connect", "none", 407), (1, 2, "connect", "ok", 200)])
        self.assertTrue(f["http_requests"][0]["proxy_generated"])
        self.assertEqual(f["http_requests"][1]["header_names"], ["Host", "Proxy-Authorization"])
        self.assertEqual(f["http_requests"][1]["auth"]["user"], U1)
        t = f["tunnels"][0]
        self.assertEqual((t["via"], t["target_host"], t["target_port"], t["conn"]), ("connect", "a.kaoju.test", 443, 1))
        self.assertEqual((t["first"]["kind"], t["first"]["record_len"], t["first"]["sni"], t["first"]["alpn"]), ("tls_client_hello", 512, "a.kaoju.test", ["h2", "http/1.1"]))
        self.assertEqual(t["opener"]["user"], U1)
        o = f["origin_requests"][0]
        self.assertEqual((o["k"], o["tunnel"], o["via"], o["proto"], o["has_proxy_authorization"], o["action"]), ("B02.s1", 1, "tunnel", "HTTP/2.0", False, "respond"))
        self.assertEqual(f["steps"][0]["status"], 200)
        self.assertEqual(f["markers"]["s1"]["extra"]["header"], True)
        self.assertEqual(f["markers"]["s1"]["default"]["header"], False)
        self.assertTrue(f["run"]["events_complete"])
        self.assertEqual(f["run"]["pcap_status"], "ok")
        self.assertEqual(f["run"]["k_mismatches"], 0)
        # 事实接到矩阵上
        col = {"B02": {"1": f}}
        self.assertEqual(matrix.compute_cell(ROW["R31"], "curl", col, CASE)["value"], "等 407 再带")
        self.assertEqual(matrix.compute_cell(ROW["R33"], "curl", col, CASE)["value"], "原连接")

    def test_k_comes_from_target(self):
        events = [
            ev("accept", 1, listener="proxy", peer_port=5),
            ev("http_request", 1, seq=1, form="absolute", method="GET", target="http://a.kaoju.test/echo?delay=300&k=A%30 1.s1#frag", version="HTTP/1.1", k="WRONG", headers=[], body_len=0, auth=auth_obj(), error=None),
            ev("origin_request", 1, oconn=None, tunnel=None, via="forward", seq=None, req_seq=1, k=None, method="GET", path="/echo", query="x=1&k=A01.s1", proto="HTTP/1.1", headers=[], body_len=0, body_sha256=EMPTY_SHA, has_proxy_authorization=False, action="respond", status=200),
        ]
        f = derive.derive(record("A01", events, []))
        self.assertEqual(f["http_requests"][0]["k"], "A0 1.s1")
        self.assertEqual(f["origin_requests"][0]["k"], "A01.s1")
        self.assertEqual(f["run"]["k_mismatches"], 2)
        self.assertIsNone(derive.k_from_target("connect", "a.kaoju.test:443"))
        self.assertIsNone(derive.k_from_target("absolute", "http://a.kaoju.test/echo"))

    def test_100_continue_precedes_request(self):
        events = [
            ev("accept", 1, listener="proxy", peer_port=5),
            ev("http_response", 1, seq=1, status=100, reason="Continue", headers=[], by="proxy", cause="continue", close=False),
            ev("http_request", 1, seq=1, form="absolute", method="POST", target="http://a.kaoju.test/echo?k=A14.s1", version="HTTP/1.1", k="A14.s1", headers=[["Expect", "100-continue"]], body_len=2097152, auth=auth_obj(), error=None),
            ev("http_response", 1, seq=1, status=200, reason="OK", headers=[], by="origin", cause="forward", close=False),
        ]
        f = derive.derive(record("A14", events, []))
        r = f["http_requests"][0]
        self.assertEqual([x["status"] for x in r["responses"]], [100, 200])
        self.assertEqual(r["response"]["status"], 200)
        self.assertFalse(r["proxy_generated"])
        self.assertEqual(matrix.compute_cell(ROW["R20"], "curl", {"A14": {"1": f}}, CASE)["value"], "发")

    def test_socks_and_direct_and_action(self):
        events = [
            ev("accept", 1, listener="proxy", peer_port=5),
            ev("first_bytes", 1, listener="proxy", n_first_read=4, hex="05020002", kind="socks5"),
            ev("socks5_greeting", 1, version=5, methods=[0, 2], raw_hex="05020002"),
            ev("socks5_method", 1, selected=2),
            ev("socks5_auth", 1, version=1, ulen=10, plen=12, user=U1, user_hex=U1.encode().hex(), **{"pass": "kaoju-pass-1"}, pass_hex=b"kaoju-pass-1".hex(), status=0, result="ok"),
            ev("socks5_request", 1, version=5, cmd=1, rsv=0, atyp=3, host="a.kaoju.test", port=443, raw_hex="05"),
            ev("socks5_reply", 1, rep=0, cause="ok", raw_hex="05"),
            ev("tunnel_open", 1, tunnel=1, via="socks5", req_seq=None, target_host="a.kaoju.test", target_port=443, mapped="origin_https"),
            ev("accept", 2, listener="origin_https", peer_port=6),
            ev("first_bytes", 2, listener="origin_https", n_first_read=5, hex="1603010200", kind="tls"),
            ev("action", 1, what="origin_drop", how="fin", k="F05.s2", tunnel=1, oconn=1),
            ev("tunnel_close", 1, tunnel=1, by="proxy", reason="origin_drop", bytes_c2s=1, bytes_s2c=2),
            ev("conn_end", 1, listener="proxy", by="proxy", close="fin", reason="origin_drop", bytes_in=3, bytes_out=4),
        ]
        f = derive.derive(record("S05", events, []))
        s = f["socks"][0]
        self.assertEqual((s["greeting"]["methods"], s["selected"], s["auth"]["user"], s["auth"]["status"], s["request"]["atyp"], s["reply"]["rep"]), ([0, 2], 2, U1, 0, 3, 0))
        self.assertEqual(f["tunnels"][0]["opener"], {"kind": "socks5", "auth_result": "ok", "user": U1, "user_hex": U1.encode().hex()})
        self.assertIsNone(f["tunnels"][0]["first"])
        self.assertEqual((f["proxy_conn_count"], f["direct_conn_count"]), (1, 1))
        self.assertEqual(f["direct_conns"][0]["listener"], "origin_https")
        self.assertEqual(f["actions"], [{"what": "origin_drop", "how": "fin", "k": "F05.s2", "conn": 1, "tunnel": 1, "oconn": 1}])
        self.assertEqual(f["proxy_conns"][0]["end_reason"], "origin_drop")
        col = {"S05": {"1": f}}
        self.assertEqual(matrix.compute_cell(ROW["R111"], "curl", col, CASE)["value"], "00,02")

    def test_run_status_variants(self):
        f = derive.derive({"variant": "curl", "case": "A15", "repeat": 1, "ports": None, "events": [], "result": None, "driver": None, "tcpdump": None, "pcap_check": None, "skipped": "only", "runner_errors": []})
        self.assertEqual(f["run"]["skipped"], "only")
        self.assertEqual(matrix.compute_cell(ROW["R21"], "curl", {"A15": {"1": f}}, CASE)["value"], "不适用")
        rec = record("A01", [], [], result=None, driver={"exit": None, "timeout": True, "stderr_tail": "", "ms": 45000})
        f = derive.derive(rec)
        self.assertTrue(f["run"]["driver_timeout"])
        self.assertFalse(f["run"]["has_result"])
        self.assertEqual(matrix.compute_cell(ROW["R01"], "curl", {"A01": {"1": f}}, CASE)["value"], "没有结果")
        rec = record("A01", [], [], result={"unsupported": "做不到", "steps": []})
        f = derive.derive(rec)
        self.assertEqual(f["run"]["unsupported"], "做不到")
        self.assertEqual(matrix.compute_cell(ROW["R01"], "curl", {"A01": {"1": f}}, CASE)["value"], "不支持")
        rec = record("A01", [], [], tcpdump={"captured": 1, "received": 2, "dropped": 7}, pcap_check={"status": "ok"})
        self.assertEqual(matrix.compute_cell(ROW["R01"], "curl", {"A01": {"1": derive.derive(rec)}}, CASE)["value"], "未通过核对")
        rec = record("A01", [], [])
        rec["events"] = rec["events"][:-1]
        self.assertFalse(derive.derive(rec)["run"]["events_complete"])

    def test_parallel_steps_are_flattened(self):
        steps = [{"id": "p", "op": "parallel", "ok": None, "status": None, "steps": [{"id": "p1", "ok": True, "status": 200}]}, {"id": "p2", "ok": False, "status": None, "default_text": "x"}]
        f = derive.derive(record("A07", [], steps))
        self.assertEqual([s["id"] for s in f["steps"]], ["p", "p1", "p2"])

    def test_pure_and_does_not_mutate(self):
        rec = record("B02", b02_events(), [{"id": "s1", "ok": True, "status": 200}])
        before = json.dumps(rec, sort_keys=True)
        a = derive.derive(rec)
        b = derive.derive(rec)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(json.dumps(rec, sort_keys=True), before)


class CliTests(unittest.TestCase):
    def write_raw(self, d, variant, recs):
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        with gzip.open(os.path.join(d, "raw", variant + ".jsonl.gz"), "wt", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    def test_end_to_end_and_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            recs = [record("B02", b02_events(), [{"id": "s1", "ok": True, "status": 200, "default_text": "200"}], repeat=i) for i in (1, 2, 3)]
            self.write_raw(d, "curl", recs)
            self.write_raw(d, "rawref", recs[:1])
            exp = os.path.join(d, "expectations")
            os.makedirs(exp)
            write_json(os.path.join(exp, "curl.json"), {"variant": "curl", "rows": {"R31": {"expect": "先带", "basis": "x", "confidence": "high"}}})
            out = os.path.join(d, "out")
            self.assertEqual(quiet(derive.main, ["--raw", os.path.join(d, "raw"), "--out", os.path.join(out, "observations")]), 0)
            argv = ["--observations", os.path.join(out, "observations"), "--raw", os.path.join(d, "raw"), "--out", out, "--expectations", exp]
            self.assertEqual(quiet(matrix.main, argv), 0)
            names = ["matrix.json", "matrix.md", "selfcheck.json", "expectation_diff.json", "expectation_diff.md", os.path.join("observations", "curl.json")]
            first = {n: read_bytes(os.path.join(out, n)) for n in names}
            self.assertEqual(quiet(derive.main, ["--raw", os.path.join(d, "raw"), "--out", os.path.join(out, "observations")]), 0)
            self.assertEqual(quiet(matrix.main, argv), 0)
            for n in names:
                self.assertEqual(read_bytes(os.path.join(out, n)), first[n], n)
            m = json.loads(first["matrix.json"])
            self.assertEqual(len(m["rows"]), 104)
            self.assertNotIn("rawref", m["columns"])
            r31 = next(r for r in m["rows"] if r["id"] == "R31")
            self.assertEqual(r31["cells"]["curl"]["value"], "等 407 再带")
            self.assertEqual(r31["cells"]["curl"]["per_repeat"], {"1": "等 407 再带", "2": "等 407 再带", "3": "等 407 再带"})
            sc = json.loads(first["selfcheck.json"])
            self.assertTrue(sc["has_data"])
            self.assertEqual(sc["rows"]["R31"]["value"], "等 407 再带")
            diff = json.loads(first["expectation_diff.json"])
            self.assertEqual([x["row"] for x in diff["columns"]["curl"]["diffs"]], ["R31"])
            obs = json.loads(first[os.path.join("observations", "curl.json")])
            self.assertEqual(sorted(obs["cases"]["B02"]), ["1", "2", "3"])

    def test_matrix_derives_from_raw_when_observations_missing(self):
        with tempfile.TemporaryDirectory() as d:
            self.write_raw(d, "curl", [record("B02", b02_events(), [{"id": "s1", "ok": True, "status": 200}])])
            out = os.path.join(d, "out")
            self.assertEqual(quiet(matrix.main, ["--observations", os.path.join(d, "none"), "--raw", os.path.join(d, "raw"), "--out", out, "--expectations", os.path.join(d, "none")]), 0)
            self.assertTrue(os.path.isfile(os.path.join(out, "matrix.md")))
            self.assertFalse(os.path.exists(os.path.join(out, "expectation_diff.json")))


@unittest.skipUnless(os.environ.get("KAOJU_P2_RAW") and os.path.isdir(os.environ.get("KAOJU_P2_RAW", "")), "没有设置 KAOJU_P2_RAW（指向真实的 out/raw 目录）")
class RealDataSmoke(unittest.TestCase):
    """用真实数据冒烟：derive 和 matrix 不抛异常，没有“其他：”开头的值。

    KAOJU_P2_ALLOW_UNCHECKED=1 时对没有抓包核对结论的旧数据也取值（只为检查行函数）。
    """

    def test_real_data(self):
        raw = os.environ["KAOJU_P2_RAW"]
        allow = os.environ.get("KAOJU_P2_ALLOW_UNCHECKED") == "1"
        obs = {}
        for col, path in derive.raw_columns(raw).items():
            obs[col] = derive.derive_column(derive.read_raw(path), col)["cases"]
        self.assertTrue(obs)
        m = matrix.build_matrix(ROWS_DOC["rows"], CASE, obs, matrix.COLUMNS_FALLBACK, allow_unchecked=allow)
        matrix.render_md(m, 3)
        others = []
        valued = 0
        for rd in m["rows"]:
            for col, c in rd["cells"].items():
                if c is None:
                    continue
                for r, v in c["per_repeat"].items():
                    valued += 1
                    if v.startswith("其他："):
                        others.append((rd["id"], col, r, v))
        self.assertEqual(others, [])
        if allow:
            self.assertGreater(valued, 0)


class LoadObservationsTests(unittest.TestCase):
    def test_non_observation_json_is_not_a_column(self):
        """observations 目录里的 versions.json 之类没有 cases 的文件不算一列。"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "curl.json"), "w", encoding="utf-8") as fh:
                json.dump({"variant": "curl", "cases": {"A01": {"1": {}}}}, fh)
            with open(os.path.join(tmp, "versions.json"), "w", encoding="utf-8") as fh:
                json.dump({"generated": "x", "variants": {"curl": {}}}, fh)
            with open(os.path.join(tmp, "list.json"), "w", encoding="utf-8") as fh:
                json.dump([1, 2], fh)
            got = matrix.load_observations(tmp, None)
        self.assertEqual(sorted(got), ["curl"])


if __name__ == "__main__":
    unittest.main()
