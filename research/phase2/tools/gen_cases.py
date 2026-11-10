# 生成 research/phase2/cases.json。用例表是手写的设计，这个脚本只是为了少敲重复的 JSON。
import json, sys
from urllib.parse import quote

A, B, FAILH = "a.kaoju.test", "b.kaoju.test", "fail.kaoju.test"
U0 = {"user": "kaoju-user", "pass": "kaoju-pass-1"}
U1 = {"user": "kaoju-user-2", "pass": "kaoju-pass-2"}
BAD = {"user": "kaoju-user", "pass": "wrong-pass"}
NOTE = ["X-Kaoju-Note", "KaojuHeaderMarker"]
PSTAT = ["Proxy-Status", 'kaoju; error=destination_unavailable; details="KaojuStatusMarker"']

cases = []

def url(scheme, host, path="/echo", k=None, **q):
    qs = "&".join([f"{a}={quote(str(b), safe='')}" for a, b in q.items()] + [f"k={k}"])
    return f"{scheme}://{host}{path}?{qs}"

def req(cid, sid, scheme, host=A, method="GET", user=None, path="/echo", follow=False, body_bytes=None, **q):
    s = {"id": sid, "op": "request", "method": method, "url": url(scheme, host, path, f"{cid}.{sid}", **q), "user": user}
    if follow: s["follow"] = True
    if body_bytes is not None: s["body_bytes"] = body_bytes
    return s

def par(cid, scheme, n=6, user=None):
    return {"id": "p", "op": "parallel",
            "steps": [req(cid, f"p{i}", scheme, user=user, delay=300) for i in range(1, n + 1)]}

def sleep(ms): return {"id": "z", "op": "sleep", "ms": ms}

def case(cid, title, proxy, steps, profile=None, users=None, only=None, notes=None):
    c = {"id": cid, "group": cid[0], "title": title, "proxy": proxy,
         "profile": profile or {}, "users": users or [], "steps": steps}
    if only: c["only"] = only
    if notes: c["notes"] = notes
    cases.append(c)

def basic(accept, **kw):
    a = {"mode": "basic", "accept": [[u["user"], u["pass"]] for u in accept]}
    a.update(kw)
    return {"auth": a}

# ---------- A 基线：不要求认证 ----------
case("A01", "明文 GET 一次", "http", [req("A01", "s1", "http")])
case("A02", "HTTPS GET 一次", "http", [req("A02", "s1", "https")])
case("A03", "HTTPS 同一个源连续 3 次", "http", [req("A03", f"s{i}", "https") for i in (1, 2, 3)])
case("A04", "明文同一个源连续 3 次", "http", [req("A04", f"s{i}", "http") for i in (1, 2, 3)])
case("A05", "HTTPS 两个源交替各 2 次", "http",
     [req("A05", f"s{i}", "https", host=h) for i, h in enumerate((A, B, A, B), 1)])
case("A06", "明文两个源交替各 2 次", "http",
     [req("A06", f"s{i}", "http", host=h) for i, h in enumerate((A, B, A, B), 1)])
case("A07", "HTTPS 同一个源 6 个并发，源站支持 h2", "http", [par("A07", "https")])
case("A08", "HTTPS 同一个源 6 个并发，源站只说 HTTP/1.1", "http", [par("A08", "https")],
     profile={"origin": {"h2": False}})
case("A09", "明文同一个源 6 个并发", "http", [par("A09", "http")])
case("A10", "明文，目标是 localhost", "http",
     [req("A10", "s1", "http", host="localhost:{origin_http_port}")],
     notes="看客户端会不会对回环地址绕过代理。直连时请求落在源站的监听端口上，记为直连。")
case("A11", "HTTPS，目标是 localhost", "http",
     [req("A11", "s1", "https", host="localhost:{origin_https_port}")])
case("A12", "明文 POST 64 KiB", "http", [req("A12", "s1", "http", method="POST", body_bytes=65536)])
case("A13", "HTTPS POST 64 KiB", "http", [req("A13", "s1", "https", method="POST", body_bytes=65536)])
case("A14", "明文 POST 2 MiB", "http", [req("A14", "s1", "http", method="POST", body_bytes=2097152)],
     notes="看客户端发不发 Expect: 100-continue。代理收到后先回 100。")
WS_ONLY = ["chromium-pw", "firefox-pw", "node-fetch-env", "rawref"]
case("A15", "ws:// 明文 WebSocket", "http",
     [{"id": "w1", "op": "ws", "url": url("ws", A, "/ws", "A15.w1"), "page": url("http", A, "/page", "A15.pre")}],
     only=WS_ONLY, notes="只对自带 WebSocket 客户端的列有意义：两个浏览器和 Node 内置的 WebSocket。")
case("A16", "wss:// WebSocket", "http",
     [{"id": "w1", "op": "ws", "url": url("wss", A, "/ws", "A16.w1"), "page": url("https", A, "/page", "A16.pre")}],
     only=WS_ONLY)

# ---------- B 认证，凭据正确 ----------
case("B01", "明文 GET 一次", "http", [req("B01", "s1", "http", user=0)], basic([U0]), [U0])
case("B02", "HTTPS GET 一次", "http", [req("B02", "s1", "https", user=0)], basic([U0]), [U0])
case("B03", "明文 GET，407 带 Connection: close", "http", [req("B03", "s1", "http", user=0)],
     basic([U0], on407="close"), [U0])
case("B04", "HTTPS GET，407 带 Connection: close", "http", [req("B04", "s1", "https", user=0)],
     basic([U0], on407="close"), [U0])
case("B05", "明文同一个源连续 3 次", "http", [req("B05", f"s{i}", "http", user=0) for i in (1, 2, 3)],
     basic([U0]), [U0])
case("B06", "HTTPS 先后访问两个源", "http",
     [req("B06", "s1", "https", host=A, user=0), req("B06", "s2", "https", host=B, user=0)], basic([U0]), [U0])
case("B07", "HTTPS 同一个源连续 3 次", "http", [req("B07", f"s{i}", "https", user=0) for i in (1, 2, 3)],
     basic([U0]), [U0])
case("B08", "重定向：明文跳到 HTTPS（换了源）", "http",
     [req("B08", "s1", "http", host=A, user=0, path="/redirect", follow=True, to=url("https", B, "/echo", "B08.s1b"))],
     basic([U0]), [U0])
case("B09", "重定向：HTTPS 跳到另一个源的 HTTPS", "http",
     [req("B09", "s1", "https", host=A, user=0, path="/redirect", follow=True, to=url("https", B, "/echo", "B09.s1b"))],
     basic([U0]), [U0])
case("B10", "重定向：HTTPS 跳到另一个源的明文", "http",
     [req("B10", "s1", "https", host=A, user=0, path="/redirect", follow=True, to=url("http", B, "/echo", "B10.s1b"))],
     basic([U0]), [U0])
case("B11", "明文，同一个进程里两个用户交替", "http",
     [req("B11", "s1", "http", user=0), req("B11", "s2", "http", user=1), req("B11", "s3", "http", user=0)],
     basic([U0, U1]), [U0, U1])
case("B12", "HTTPS，同一个进程里两个用户交替", "http",
     [req("B12", "s1", "https", user=0), req("B12", "s2", "https", user=1), req("B12", "s3", "https", user=0)],
     basic([U0, U1]), [U0, U1])
case("B13", "明文 POST 64 KiB", "http", [req("B13", "s1", "http", method="POST", user=0, body_bytes=65536)],
     basic([U0]), [U0], notes="等 407 再带凭据的客户端会把正文发两遍。")
case("B14", "HTTPS 同一个源 6 个并发，源站只说 HTTP/1.1", "http", [par("B14", "https", user=0)],
     {**basic([U0]), "origin": {"h2": False}}, [U0])

# ---------- C 认证失败 ----------
case("C01", "明文，没配凭据，代理要求认证", "http", [req("C01", "s1", "http")], basic([U0]))
case("C02", "HTTPS，没配凭据，代理要求认证", "http", [req("C02", "s1", "https")], basic([U0]))
case("C03", "明文，密码错，代理一直回 407", "http", [req("C03", "s1", "http", user=0)], basic([U0]), [BAD])
case("C04", "HTTPS，密码错，代理一直回 407", "http", [req("C04", "s1", "https", user=0)], basic([U0]), [BAD])
case("C05", "HTTPS，密码错，代理回 403", "http", [req("C05", "s1", "https", user=0)],
     basic([U0], reject_status=403), [BAD])
case("C06", "明文，配了凭据但代理不要求认证", "http", [req("C06", "s1", "http", user=0)], None, [U0])
case("C07", "HTTPS，配了凭据但代理不要求认证", "http", [req("C07", "s1", "https", user=0)], None, [U0])
case("C08", "明文，密码错，代理回 403", "http", [req("C08", "s1", "http", user=0)],
     basic([U0], reject_status=403), [BAD])

# ---------- D 用户名和密码的字节 ----------
def long_user(n):
    s = "kaoju-session-"
    while len(s) < n: s += "0123456789abcdef"
    return s[:n]

D_USERS = [
    ("01", "常见的参数写法（连字符）", "kaoju-session-ab12CD-ttl-600-country-us", "kaoju-pass-1", None),
    ("02", "下划线、点、波浪号、等号、分号、逗号", "sess_ab.12~x=1;ttl=600,cc=us", "kaoju-pass-1", None),
    ("03", "要转义的字符：@ % + / 和空格", "sess@ab%41+c/d e", "kaoju-pass-1", None),
    ("04", "UTF-8 用户名，质询不带 charset", "用户-séssion-ß", "kaoju-pass-1", None),
    ("05", "UTF-8 用户名，质询带 charset=\"UTF-8\"", "用户-séssion-ß", "kaoju-pass-1",
     ['Basic realm="kaoju", charset="UTF-8"']),
    ("06", "用户名 255 字节", long_user(255), "kaoju-pass-1", None),
    ("07", "用户名 256 字节", long_user(256), "kaoju-pass-1", None),
    ("08", "用户名 1024 字节", long_user(1024), "kaoju-pass-1", None),
    ("09", "密码里有冒号、@、空格、%2F、加号", "kaoju-user", "p:a@s s%2Fw+d", None),
    ("10", "空密码", "kaoju-user", "", None),
    ("11", "用户名里有冒号", "sess:ab12", "kaoju-pass-1", None),
]
for n, title, u, p, chal in D_USERS:
    prof = {"auth": {"mode": "basic", "accept": [[u, p]], "accept_any_user": True}}
    if chal: prof["auth"]["challenge"] = chal
    case(f"D{n}", title, "http", [req(f"D{n}", "s1", "https", user=0)], prof, [{"user": u, "pass": p}])

# ---------- E 报错可见性 ----------
def fail(status, close=True, hosts=None, extra=None):
    f = {"status": status, "reason": "KaojuReasonMarker", "headers": [NOTE, PSTAT] + (extra or []),
         "body": "KaojuBodyMarker\n", "close": close}
    if hosts: f["hosts"] = hosts
    return f
case("E01", "CONNECT 回 502", "http", [req("E01", "s1", "https")], {"connect": {"fail": fail(502)}})
case("E02", "CONNECT 回 403", "http", [req("E02", "s1", "https")], {"connect": {"fail": fail(403)}})
case("E03", "CONNECT 回 503，带 Retry-After: 1", "http", [req("E03", "s1", "https")],
     {"connect": {"fail": fail(503, extra=[["Retry-After", "1"]])}})
case("E04", "CONNECT 成功，200 里带附加的头", "http", [req("E04", "s1", "https")],
     {"connect": {"ok_headers": [NOTE, ["Proxy-Status", 'kaoju; details="KaojuStatusMarker"']]}})
case("E05", "明文请求被代理回 403", "http", [req("E05", "s1", "http")], {"forward": {"fail": fail(403)}})
case("E06", "明文请求成功，代理在响应里附加了头", "http", [req("E06", "s1", "http")],
     {"forward": {"add_response_headers": [NOTE, ["Proxy-Status", 'kaoju; details="KaojuStatusMarker"']]}})
case("E07", "CONNECT 回 502 但不关连接，接着访问另一个源", "http",
     [req("E07", "s1", "https", host=FAILH), req("E07", "s2", "https", host=A)],
     {"connect": {"fail": fail(502, close=False, hosts=[FAILH])}})

# ---------- F 断连与重发 ----------
def drop(k, how="fin", reused=True):
    d = {"k": k, "times": 1, "how": how}
    if reused: d["only_if_reused"] = True
    return d
case("F01", "明文：空闲 1.5 秒的连接被代理关掉，3 秒后再请求", "http",
     [req("F01", "s1", "http"), sleep(3000), req("F01", "s2", "http")], {"conn": {"idle_close_ms": 1500}})
case("F02", "HTTPS：静默 1.5 秒的隧道被代理关掉，3 秒后再请求", "http",
     [req("F02", "s1", "https"), sleep(3000), req("F02", "s2", "https")], {"tunnel": {"idle_close_ms": 1500}})
case("F03", "明文：复用的连接上，GET 发出后连接被关（FIN）", "http",
     [req("F03", "s1", "http"), req("F03", "s2", "http")], {"conn": {"drop": drop("F03.s2")}})
case("F04", "明文：复用的连接上，POST 发出后连接被关（FIN）", "http",
     [req("F04", "s1", "http"), req("F04", "s2", "http", method="POST", body_bytes=1024)],
     {"conn": {"drop": drop("F04.s2")}})
case("F05", "HTTPS：复用的隧道里，GET 到达源站后隧道被切断（FIN）", "http",
     [req("F05", "s1", "https"), req("F05", "s2", "https")], {"origin": {"h2": False, "drop": drop("F05.s2")}})
case("F06", "HTTPS：复用的隧道里，POST 到达源站后隧道被切断（FIN）", "http",
     [req("F06", "s1", "https"), req("F06", "s2", "https", method="POST", body_bytes=1024)],
     {"origin": {"h2": False, "drop": drop("F06.s2")}})
case("F07", "明文：新连接上的第一个 GET 发出后连接被关", "http",
     [req("F07", "s1", "http")], {"conn": {"drop": drop("F07.s1", reused=False)}})
case("F08", "HTTPS：新隧道里的第一个 GET 到达源站后隧道被切断", "http",
     [req("F08", "s1", "https")], {"origin": {"h2": False, "drop": drop("F08.s1", reused=False)}})
case("F09", "明文：复用的连接上，GET 发出后连接被复位（RST）", "http",
     [req("F09", "s1", "http"), req("F09", "s2", "http")], {"conn": {"drop": drop("F09.s2", how="rst")}})
case("F10", "HTTPS：复用的隧道里，GET 到达源站后隧道被复位（RST）", "http",
     [req("F10", "s1", "https"), req("F10", "s2", "https")],
     {"origin": {"h2": False, "drop": drop("F10.s2", how="rst")}})
case("F11", "HTTPS：CONNECT 发出后代理什么都不回就关连接", "http",
     [req("F11", "s1", "https")], {"connect": {"drop": {"times": 1, "how": "fin"}}})
case("F12", "HTTPS：源站支持 h2，复用的隧道里 GET 到达源站后隧道被切断", "http",
     [req("F12", "s1", "https"), req("F12", "s2", "https")], {"origin": {"h2": True, "drop": drop("F12.s2")}})

# ---------- S SOCKS5 入口 ----------
def socks(auth="none", accept=None, any_user=False, **kw):
    p = {"socks": {"auth": auth, **kw}}
    if accept is not None:
        p["auth"] = {"accept": [[u["user"], u["pass"]] for u in accept]}
        if any_user: p["auth"]["accept_any_user"] = True
    return p
case("S01", "域名交给代理解析，HTTPS GET", "socks5h", [req("S01", "s1", "https")], socks())
case("S02", "域名交给代理解析，明文 GET", "socks5h", [req("S02", "s1", "http")], socks())
case("S03", "客户端自己解析，目标是 localhost", "socks5",
     [req("S03", "s1", "https", host="localhost:{origin_https_port}")], socks())
case("S04", "客户端自己解析，目标域名本机解析不了", "socks5", [req("S04", "s1", "https")], socks())
case("S05", "用户名密码认证，凭据正确", "socks5h", [req("S05", "s1", "https", user=0)], socks("userpass", [U0]), [U0])
case("S06", "配了凭据，但代理选了无认证", "socks5h", [req("S06", "s1", "https", user=0)], socks(), [U0])
case("S07", "代理要求认证，客户端没配凭据", "socks5h", [req("S07", "s1", "https")], socks("userpass", [U0]))
case("S08", "密码错", "socks5h", [req("S08", "s1", "https", user=0)], socks("userpass", [U0]), [BAD])
case("S09", "应答码 2（规则不允许）", "socks5h", [req("S09", "s1", "https")], socks(rep=2))
case("S10", "应答码 4（主机不可达）", "socks5h", [req("S10", "s1", "https")], socks(rep=4))
case("S11", "应答码 5（连接被拒绝）", "socks5h", [req("S11", "s1", "https")], socks(rep=5))
case("S12", "HTTPS 同一个源连续 3 次", "socks5h", [req("S12", f"s{i}", "https") for i in (1, 2, 3)], socks())
case("S13", "HTTPS 同一个源 6 个并发，源站只说 HTTP/1.1", "socks5h", [par("S13", "https")],
     {**socks(), "origin": {"h2": False}})
case("S14", "同一个进程里两个用户交替", "socks5h",
     [req("S14", "s1", "https", user=0), req("S14", "s2", "https", user=1), req("S14", "s3", "https", user=0)],
     socks("userpass", [U0, U1]), [U0, U1])
S_USERS = [
    ("15", "常见的参数写法（连字符）", "kaoju-session-ab12CD-ttl-600-country-us", "kaoju-pass-1"),
    ("16", "要转义的字符：@ % + / 和空格", "sess@ab%41+c/d e", "kaoju-pass-1"),
    ("17", "UTF-8 用户名", "用户-séssion-ß", "kaoju-pass-1"),
    ("18", "用户名 255 字节", long_user(255), "kaoju-pass-1"),
    ("19", "用户名 256 字节（超出 RFC 1929 的上限）", long_user(256), "kaoju-pass-1"),
    ("20", "密码里有冒号、@、空格、%2F、加号", "kaoju-user", "p:a@s s%2Fw+d"),
    ("21", "空密码", "kaoju-user", ""),
    ("22", "用户名里有冒号", "sess:ab12", "kaoju-pass-1"),
]
for n, title, u, p in S_USERS:
    uu = {"user": u, "pass": p}
    case(f"S{n}", title, "socks5h", [req(f"S{n}", "s1", "https", user=0)], socks("userpass", [uu], any_user=True), [uu])

doc = {
    "version": "1.0",
    "说明": "用例表。运行时 run.py 把 {origin_http_port}、{origin_https_port} 换成实际端口，按 body_bytes 生成正文文件"
            "（第 i 个字节是 (i*131+7)%251，Content-Type 是 application/octet-stream），其余原样交给驱动。"
            "profile 只写与默认值不同的字段。only 非空时只对列出的列运行，其余列记“不适用”。",
    "repeats": 3,
    "timeout_s": 15,
    "cases": cases,
}
ids = [c["id"] for c in cases]
assert len(ids) == len(set(ids)) == 90, len(ids)
json.dump(doc, open(sys.argv[1], "w"), ensure_ascii=False, indent=1)
print(len(cases), {g: sum(1 for c in cases if c["group"] == g) for g in "ABCDEFS"})
