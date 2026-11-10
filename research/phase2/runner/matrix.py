#!/usr/bin/env python3
"""矩阵生成：按 ../rows.json 的规则，从事实（derive.py 的输出）里给每一行、每一列取值。

口径见 ../PROTOCOL.md“矩阵”“预期”两节和 ../rows.json。只用 Python 标准库。
rows.json 的每一行在这里是一个函数（按行号注册，文档字符串引用该行的 how）；取值是纯函数。

    python3 runner/matrix.py --observations out/observations --raw out/raw --out out

输出：

- out/matrix.json：rows × 列，每格有 value、stable、per_repeat、footnotes、cases
- out/matrix.md：按 rows.json 的 section 分表；列的顺序是 PROTOCOL.md“被测客户端”表的顺序
- out/selfcheck.json：rawref 那一列（仪器自检），有手写答案文件时逐格比较
- out/expectation_diff.json、.md：实测与 ../expectations/<列>.json 不符的格子（目录不存在时不写）

通用规则（rows.json 的“说明”、PROTOCOL.md“矩阵”一节）：

- 用例的 only 不含该列：“不适用”
- 任何一遍的 pcap_check.status 不是 ok 或 prefix，或 tcpdump 丢包：“未通过核对”，不给值
- 驱动报 unsupported：“不支持”，原因进脚注
- 驱动超时或没有结果（含运行器出错、事件文件不完整）：“没有结果”
- 各遍取值相同就是该值；不同则把出现过的值用“ / ”连起来，stable 为 false
- 规则没覆盖的情况一律写“其他：<简短事实>”，不硬套某个取值

一行看多个用例而只有一部分用例可用时（其余是不支持、没有结果等）：按可用的用例取值，
并在值后面注明“（不含 用例：原因）”；R23 例外，它按位置逐个写。
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import derive as derive_mod  # noqa: E402

MATRIX_VERSION = 1

# PROTOCOL.md“被测客户端”表的顺序。运行时从 PROTOCOL.md 里再读一遍，读不到才用这一份。
COLUMNS_FALLBACK = [
    "curl",
    "curl-anyauth",
    "requests",
    "go",
    "node-fetch-env",
    "node-http-env",
    "node-undici",
    "node-agents",
    "node-axios",
    "chromium-pw",
    "firefox-pw",
]
SELFCHECK_COLUMN = "rawref"

NA = "不适用"
UNSUPPORTED = "不支持"
UNVERIFIED = "未通过核对"
NO_RESULT = "没有结果"
OTHER = "其他："

PASS_PCAP = ("ok", "prefix")


class Other(Exception):
    """规则没覆盖的情况。消息是简短的事实，格子写成“其他：<消息>”。"""


# ---------------------------------------------------------------------------
# 行函数的注册

ROWS = {}
SUMMARIZERS = {}
HANDLES_EXCLUDED = set()


def row(rid, summarize=None, handles_excluded=False):
    def deco(fn):
        ROWS[rid] = fn
        if summarize is not None:
            SUMMARIZERS[rid] = summarize
        if handles_excluded:
            HANDLES_EXCLUDED.add(rid)
        return fn

    return deco


class Ctx:
    """一个格子、一遍的取值环境。

    facts：{用例号: 事实}，只含可用的用例；excluded：{用例号: 原因（不支持、没有结果…）}；
    case_defs：cases.json 里的用例定义；notes：这一遍的脚注；data：给汇总函数用的数。
    """

    def __init__(self, row_def, variant, facts, excluded, case_defs):
        self.row = row_def
        self.variant = variant
        self.facts = facts
        self.excluded = excluded
        self.case_defs = case_defs
        self.notes = []
        self.data = {}

    def f(self, case=None):
        case = case or self.row["cases"][0]
        if case not in self.facts:
            raise Other("没有 %s 的数据" % case)
        return self.facts[case]

    def case(self, case=None):
        return self.case_defs.get(case or self.row["cases"][0]) or {}

    def usable(self):
        return [c for c in self.row["cases"] if c in self.facts]

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)


# ---------------------------------------------------------------------------
# 从事实里取东西的小函数


def reqs(f, k=None, form=None):
    out = f.get("http_requests") or []
    if k is not None:
        out = [r for r in out if r.get("k") == k]
    if form is not None:
        out = [r for r in out if r.get("form") == form]
    return out


def oreqs(f, k=None, via=None):
    out = f.get("origin_requests") or []
    if k is not None:
        out = [r for r in out if r.get("k") == k]
    if via is not None:
        vias = (via,) if isinstance(via, str) else via
        out = [r for r in out if r.get("via") in vias]
    return out


def tunnel_of(f, tid):
    for t in f.get("tunnels") or []:
        if t.get("tunnel") == tid:
            return t
    return None


def has_auth(r):
    return (r.get("auth") or {}).get("result", "none") != "none"


def got_status(r, status):
    return any(x.get("status") == status for x in r.get("responses") or [])


def header_values(headers, name):
    name = name.lower()
    return [h[1] for h in headers or [] if h[0].lower() == name]


def step(f, sid):
    for s in f.get("steps") or []:
        if s.get("id") == sid:
            return s
    raise Other("驱动结果里没有 %s 这一步" % sid)


def ok200(s):
    return s.get("ok") is True and s.get("status") == 200


def failed(s):
    return s.get("ok") is not True


def flat_steps(case_def):
    out = []

    def walk(steps):
        for s in steps or []:
            if s.get("op") == "parallel":
                walk(s.get("steps"))
            else:
                out.append(s)

    walk(case_def.get("steps"))
    return out


def request_steps(case_def):
    return [s for s in flat_steps(case_def) if s.get("op") in ("request", "ws")]


def expected_user(case_def, st):
    """这一步该用的用户：{"user":…, "pass":…}；没配凭据是 None。"""
    idx = st.get("user")
    users = case_def.get("users") or []
    if idx is None or not (0 <= idx < len(users)):
        return None
    return users[idx]


def case_k(case_def, sid):
    return "%s.%s" % (case_def.get("id"), sid)


_BODY_CACHE = {}


def body_sha256(n):
    """run.py 生成的正文（第 i 个字节是 (i*131+7)%251）的 SHA-256。"""
    if n not in _BODY_CACHE:
        period = bytes((i * 131 + 7) % 251 for i in range(251))
        data = (period * (n // 251 + 1))[:n]
        _BODY_CACHE[n] = hashlib.sha256(data).hexdigest()
    return _BODY_CACHE[n]


def target_host(target):
    """CONNECT 目标里的主机（去掉端口和方括号）。"""
    host = target or ""
    if host.startswith("["):
        return host[1:].partition("]")[0]
    return host.rpartition(":")[0] if ":" in host else host


def unparsed_tunnel(f):
    """EVENTS.md 的盲区：有源站连接、两个方向都有字节、却没有任何 origin_request 的隧道。"""
    with_req = {r.get("tunnel") for r in oreqs(f, via="tunnel")}
    with_oconn = {c.get("tunnel") for c in f.get("origin_conns") or [] if c.get("via") == "tunnel"}
    for t in f.get("tunnels") or []:
        if t["tunnel"] in with_oconn and t["tunnel"] not in with_req:
            if (t.get("bytes_c2s") or 0) > 0 and (t.get("bytes_s2c") or 0) > 0:
                return t
    return None


def count_note(ctx, f, case_def):
    """计数类的行：有步骤没成功时在脚注里说一声，数字本身照规则写。"""
    bad = []
    for st in request_steps(case_def):
        try:
            s = step(f, st["id"])
        except Other:
            bad.append(st["id"])
            continue
        if not ok200(s):
            bad.append(st["id"])
    if bad:
        ctx.note("%s 有步骤没有拿到 200：%s" % (case_def.get("id"), "、".join(bad)))


def close_note(ctx, resp_close, configured, what):
    """EVENTS.md：响应的 close 为真而配置没要求关，说明是请求一侧要求关的，要加标注。"""
    if resp_close and not configured:
        ctx.note("%s的 close 为真而配置没有要求关连接（请求自带 Connection: close 或是 HTTP/1.0），之后换连接不是客户端在“代理留着连接”的前提下做的选择" % what)


# ---------------------------------------------------------------------------
# 基线


def find_arrival(ctx, f, k):
    """带 k 的请求是怎么到的。返回 [(种类, 请求)]，种类：absolute、tunnel、direct、其他形式。"""
    found = []
    for r in reqs(f, k=k):
        found.append((r.get("form"), r))
    for r in oreqs(f, k=k, via=("tunnel", "direct")):
        found.append((r.get("via"), r))
    return found


def _one_kind(found):
    kinds = []
    for kind, _ in found:
        if kind not in kinds:
            kinds.append(kind)
    if len(kinds) > 1:
        raise Other("同一个 k 以多种方式到达：%s" % "、".join(str(x) for x in kinds))
    return kinds[0], found[0][1]


@row("R01")
def r01(ctx):
    """找到带 k=A01.s1 的请求是怎么到的：代理端口上的 http_request 且 form=absolute；或先有到 80 端口的隧道、请求出现在隧道里的 origin_request；或源站端口上的直连。"""
    f = ctx.f()
    found = find_arrival(ctx, f, "A01.s1")
    if not found:
        if unparsed_tunnel(f):
            raise Other("隧道里有字节往来，但源站没能解析出请求")
        return "没到"
    kind, r = _one_kind(found)
    if kind == "absolute":
        return "绝对形式"
    if kind == "tunnel":
        t = tunnel_of(f, r.get("tunnel")) or {}
        if t.get("via") == "connect" and t.get("target_port") == 80:
            return "CONNECT 到 80 端口"
        raise Other("请求在隧道里，隧道经由 %s、目标端口 %s" % (t.get("via"), t.get("target_port")))
    if kind == "direct":
        return "直连"
    raise Other("代理端口上的请求形式是 %s" % kind)


CONN_HEADERS = (
    "proxy-connection",
    "connection",
    "keep-alive",
    "via",
    "forwarded",
    "x-forwarded-for",
    "te",
    "upgrade",
    "proxy-authorization",
)


@row("R02")
def r02(ctx):
    """取 R01 找到的那个请求的头，按出现顺序列出名字属于 Proxy-Connection、Connection、Keep-Alive、Via、Forwarded、X-Forwarded-For、TE、Upgrade、Proxy-Authorization 的，写成“名: 值”，用分号加空格连接（Proxy-Authorization 只写名字）。"""
    f = ctx.f()
    found = find_arrival(ctx, f, "A01.s1")
    if not found:
        raise Other("带 k=A01.s1 的请求没到")
    kind, r = _one_kind(found)
    if kind in ("tunnel", "direct"):
        ctx.note("请求不在代理端口上（%s），头由源站解析：名字是规范化以后的写法，按名字排序，不是线上的原样" % kind)
    parts = []
    for name, value in r.get("headers") or []:
        if name.lower() in CONN_HEADERS:
            parts.append(name if name.lower() == "proxy-authorization" else "%s: %s" % (name, value))
    return "; ".join(parts) if parts else "无"


def first_connect(f):
    cs = reqs(f, form="connect")
    return cs[0] if cs else None


@row("R03")
def r03(ctx):
    """第一个 form=connect 的 http_request：目标、空格、版本。"""
    c = first_connect(ctx.f())
    if c is None:
        return "没有 CONNECT"
    return "%s %s" % (c.get("target"), c.get("version"))


@row("R04")
def r04(ctx):
    """同一个请求的头的名字，原大小写、原顺序，用逗号加空格连接。"""
    c = first_connect(ctx.f())
    if c is None:
        raise Other("没有 CONNECT")
    if not c.get("header_names"):
        raise Other("CONNECT 没有带任何头")
    return ", ".join(c["header_names"])


@row("R05")
def r05(ctx):
    """Host 头的值与请求目标逐字节相同是“同目标”。"""
    c = first_connect(ctx.f())
    if c is None:
        raise Other("没有 CONNECT")
    hosts = header_values(c.get("headers"), "host")
    if not hosts:
        return "没有"
    if len(hosts) > 1:
        ctx.note("CONNECT 带了 %d 个 Host 头，只看第一个" % len(hosts))
    if hosts[0] == c.get("target"):
        return "同目标"
    ctx.note("Host 头是 %r，请求目标是 %r" % (hosts[0], c.get("target")))
    return "不同"


FIRST_KIND = {"tls_client_hello": "TLS ClientHello", "http": "明文 HTTP", "other": "其他"}


def first_tunnel(f):
    ts = f.get("tunnels") or []
    if not ts:
        raise Other("没有隧道")
    return ts[0]


def tunnel_first_kind(ctx):
    t = first_tunnel(ctx.f())
    first = t.get("first")
    if first is None:
        raise Other("隧道里没有收到任何字节")
    kind = first.get("kind")
    if kind not in FIRST_KIND:
        raise Other("首包归类是 %s" % kind)
    if kind == "other":
        ctx.note("首包的前 16 个字节（十六进制）：%s" % first.get("hex"))
    return FIRST_KIND[kind]


@row("R06")
def r06(ctx):
    """第一条隧道的 tunnel_first_bytes 的归类。"""
    return tunnel_first_kind(ctx)


def client_hello(ctx):
    t = first_tunnel(ctx.f())
    first = t.get("first")
    if first is None:
        raise Other("隧道里没有收到任何字节")
    if first.get("kind") != "tls_client_hello":
        raise Other("隧道首包不是 ClientHello（%s）" % first.get("kind"))
    return first


def r07_summary(per_repeat_data):
    lens = [d["client_hello_len"] for d in per_repeat_data if "client_hello_len" in d]
    if not lens:
        return []
    return ["ClientHello 长度（TLS 记录长度加 5 字节记录头）：%d 遍里最小 %d、最大 %d 字节" % (len(lens), min(lens), max(lens))]


@row("R07", summarize=r07_summary)
def r07(ctx):
    """TLS 记录长度加 5 个字节的记录头。按以太网上一个 TCP 包最多 1460 字节的载荷分两档；3 遍里的最小值和最大值另记在脚注。"""
    first = client_hello(ctx)
    if not isinstance(first.get("record_len"), int):
        raise Other("ClientHello 没有解析出记录长度")
    n = first["record_len"] + 5
    ctx.data["client_hello_len"] = n
    if first.get("tls_complete") is False:
        ctx.note("第一条 TLS 记录等了 2 秒没有到齐，长度取自记录头")
    return "不超过 1460 字节" if n <= 1460 else "超过 1460 字节"


@row("R08")
def r08(ctx):
    """ClientHello 里的 ALPN 列表，用逗号连接。"""
    alpn = client_hello(ctx).get("alpn") or []
    return ",".join(alpn) if alpn else "无"


@row("R09")
def r09(ctx):
    """带 k=A02.s1 的 origin_request 的协议。"""
    rs = oreqs(ctx.f(), k="A02.s1")
    if not rs:
        raise Other("带 k=A02.s1 的请求没到源站")
    protos = []
    for r in rs:
        if r.get("proto") not in protos:
            protos.append(r.get("proto"))
    if len(protos) > 1:
        raise Other("同一个 k 到达多次，协议不同：%s" % "、".join(str(p) for p in protos))
    return str(protos[0])


def count_tunnels(ctx):
    f = ctx.f()
    count_note(ctx, f, ctx.case())
    return str(len(f.get("tunnels") or []))


def count_proxy_conns(ctx):
    f = ctx.f()
    count_note(ctx, f, ctx.case())
    return str(f.get("proxy_conn_count") or 0)


@row("R10")
def r10(ctx):
    """tunnel_open 的个数。"""
    return count_tunnels(ctx)


@row("R11")
def r11(ctx):
    """代理端口上 accept 的个数。"""
    return count_proxy_conns(ctx)


@row("R12")
def r12(ctx):
    """tunnel_open 的个数。"""
    return count_tunnels(ctx)


@row("R13")
def r13(ctx):
    """代理端口上 accept 的个数。"""
    return count_proxy_conns(ctx)


@row("R14")
def r14(ctx):
    """tunnel_open 的个数。"""
    return count_tunnels(ctx)


@row("R15")
def r15(ctx):
    """tunnel_open 的个数。"""
    return count_tunnels(ctx)


@row("R16")
def r16(ctx):
    """代理端口上 accept 的个数。"""
    return count_proxy_conns(ctx)


@row("R17")
def r17(ctx):
    """带 k 的请求出现在代理端口上是“经代理”；出现在源站端口的直连上是“直连”；都没有且驱动这一步失败是“报错”。"""
    f = ctx.f()
    k = "A10.s1"
    on_proxy = bool(reqs(f, k=k))
    in_tunnel = bool(oreqs(f, k=k, via="tunnel"))
    direct = bool(oreqs(f, k=k, via="direct"))
    if (on_proxy or in_tunnel) and direct:
        raise Other("请求既经代理又直连到达")
    if on_proxy:
        return "经代理"
    if in_tunnel:
        ctx.note("请求经 CONNECT 隧道到达，不是绝对形式")
        return "经代理"
    if direct:
        return "直连"
    if failed(step(f, "s1")):
        return "报错"
    raise Other("请求哪里都没出现，驱动却报告成功")


@row("R18")
def r18(ctx):
    """同 R17；经代理指请求出现在隧道里。"""
    f = ctx.f()
    k = "A11.s1"
    in_tunnel = bool(oreqs(f, k=k, via="tunnel"))
    direct = bool(oreqs(f, k=k, via="direct"))
    if in_tunnel and direct:
        raise Other("请求既经代理又直连到达")
    if in_tunnel:
        return "经代理"
    if direct:
        return "直连"
    if reqs(f, k=k):
        raise Other("请求以 %s 形式出现在代理端口上，不在隧道里" % reqs(f, k=k)[0].get("form"))
    if failed(step(f, "s1")):
        if reqs(f, form="connect"):
            ctx.note("代理端口上有 CONNECT，但带 k 的请求没到源站")
        return "报错"
    raise Other("请求哪里都没出现，驱动却报告成功")


@row("R19")
def r19(ctx):
    """带 k 的 http_request 有 Transfer-Encoding: chunked 是 chunked，否则看 Content-Length。"""
    rs = reqs(ctx.f(), k="A12.s1")
    if not rs:
        raise Other("代理端口上没有带 k=A12.s1 的请求")
    vals = []
    for r in rs:
        te = ",".join(header_values(r.get("headers"), "transfer-encoding")).lower()
        if "chunked" in te:
            v = "chunked"
        elif header_values(r.get("headers"), "content-length"):
            v = "Content-Length"
        else:
            raise Other("请求既没有 Transfer-Encoding: chunked 也没有 Content-Length")
        if v not in vals:
            vals.append(v)
    if len(vals) > 1:
        raise Other("同一个 k 的几个请求分帧方式不同：%s" % "、".join(vals))
    return vals[0]


@row("R20")
def r20(ctx):
    """带 k 的 http_request 有没有 Expect 头。"""
    rs = reqs(ctx.f(), k="A14.s1")
    if not rs:
        raise Other("代理端口上没有带 k=A14.s1 的请求")
    expects = [v for r in rs for v in header_values(r.get("headers"), "expect")]
    if not expects:
        return "不发"
    if any(v.strip().lower() != "100-continue" for v in expects):
        raise Other("Expect 头的值是 %s" % "、".join(expects))
    if any(not header_values(r.get("headers"), "expect") for r in rs):
        ctx.note("同一个 k 的 %d 个请求里只有一部分带 Expect" % len(rs))
    return "发"


@row("R21")
def r21(ctx):
    """带 k=A15.w1 的请求：出现在到 80 端口的隧道里（origin_request）是第一种；出现在代理端口上的绝对形式请求里是第二种。"""
    f = ctx.f()
    found = find_arrival(ctx, f, "A15.w1")
    if not found:
        if unparsed_tunnel(f):
            raise Other("隧道里有字节往来，但源站没能解析出请求")
        return "没到"
    kind, r = _one_kind(found)
    if kind == "tunnel":
        t = tunnel_of(f, r.get("tunnel")) or {}
        if t.get("via") == "connect" and t.get("target_port") == 80:
            return "CONNECT 到 80 端口，隧道里明文升级"
        raise Other("请求在隧道里，隧道经由 %s、目标端口 %s" % (t.get("via"), t.get("target_port")))
    if kind == "absolute":
        if r.get("method") == "GET" and header_values(r.get("headers"), "upgrade"):
            return "绝对形式的 GET 加 Upgrade"
        raise Other("绝对形式的 %s，%s Upgrade 头" % (r.get("method"), "有" if header_values(r.get("headers"), "upgrade") else "没有"))
    if kind == "direct":
        return "直连"
    raise Other("代理端口上的请求形式是 %s" % kind)


@row("R22")
def r22(ctx):
    """带 k=A16.w1 的请求出现在到 443 端口的隧道里，且隧道首包是 TLS。"""
    f = ctx.f()
    found = find_arrival(ctx, f, "A16.w1")
    if not found:
        if unparsed_tunnel(f):
            raise Other("隧道里有字节往来，但源站没能解析出请求")
        return "没到"
    kind, r = _one_kind(found)
    if kind == "tunnel":
        t = tunnel_of(f, r.get("tunnel")) or {}
        first = (t.get("first") or {}).get("kind")
        if t.get("via") == "connect" and t.get("target_port") == 443 and first == "tls_client_hello":
            return "CONNECT 到 443 端口，隧道里 TLS"
        raise Other("请求在隧道里，隧道经由 %s、目标端口 %s、首包 %s" % (t.get("via"), t.get("target_port"), first))
    if kind == "direct":
        return "直连"
    raise Other("请求以 %s 形式出现在代理端口上" % kind)


def show_byte(hx):
    """可打印的（0x21 到 0x7e）写成字符，否则写两位十六进制。"""
    b = int(hx, 16)
    return chr(b) if 0x21 <= b <= 0x7E else "%02x" % b


@row("R23", handles_excluded=True)
def r23(ctx):
    """三个用例里第一条代理连接的 first_bytes 的第一个字节，可打印的写成字符，否则写两位十六进制，用“ / ”连接（顺序：明文、HTTPS、SOCKS5）。"""
    parts = []
    for case in ctx.row["cases"]:
        if case in ctx.excluded:
            parts.append(ctx.excluded[case])
            continue
        conns = ctx.f(case).get("proxy_conns") or []
        if not conns:
            parts.append("没有连接")
        elif not conns[0].get("first_byte"):
            parts.append("没有字节")
        else:
            parts.append(show_byte(conns[0]["first_byte"]))
    return " / ".join(parts)


@row("R24")
def r24(ctx):
    """三个用例里带 k 的 origin_request 的正文长度和 SHA-256 与 run.py 生成的正文文件相同。"""
    bad = []
    for case in ctx.usable():
        cd = ctx.case(case)
        f = ctx.f(case)
        for st in request_steps(cd):
            n = st.get("body_bytes")
            if n is None:
                continue
            rs = oreqs(f, k=case_k(cd, st["id"]))
            if not rs:
                ctx.note("%s：带 k 的请求没到源站" % case)
                bad.append(case)
                continue
            wrong = [r for r in rs if r.get("body_len") != n or r.get("body_sha256") != body_sha256(n)]
            if wrong:
                ctx.note("%s：源站收到 %d 个带 k 的请求，正文长度 %s，应为 %d" % (case, len(rs), "、".join(str(r.get("body_len")) for r in rs), n))
                bad.append(case)
    if not bad:
        return "完整"
    uniq = [c for i, c in enumerate(bad) if c not in bad[:i]]
    return "不完整（%s）" % "、".join(uniq)


# ---------------------------------------------------------------------------
# 认证


def when_auth(rs, what):
    if not rs:
        raise Other("代理端口上没有%s" % what)
    if has_auth(rs[0]):
        return "先带"
    if any(has_auth(r) for r in rs[1:]):
        return "等 407 再带"
    return "始终不带"


@row("R30")
def r30(ctx):
    """代理端口上按时间第一个 http_request 的 auth 判定不是 none 就是“先带”；是 none 而后面有带凭据的请求是“等 407 再带”。"""
    return when_auth(reqs(ctx.f()), "请求")


@row("R31")
def r31(ctx):
    """同 R30，看 form=connect 的请求。"""
    return when_auth(reqs(ctx.f(), form="connect"), " CONNECT")


def retry_conn(ctx):
    f = ctx.f()
    rs = reqs(f)
    i407 = next((i for i, r in enumerate(rs) if got_status(r, 407)), None)
    if i407 is None:
        return NA
    iauth = next((i for i, r in enumerate(rs) if has_auth(r)), None)
    if iauth is None:
        return "没有重试"
    if iauth <= i407:
        raise Other("收到 407 之前就已经带了凭据")
    on407 = ((f.get("profile") or {}).get("auth") or {}).get("on407")
    resp = next((x for x in rs[i407].get("responses") or [] if x.get("status") == 407), {})
    close_note(ctx, resp.get("close"), on407 == "close", "407 ")
    return "原连接" if rs[iauth].get("conn") == rs[i407].get("conn") else "新连接"


@row("R32")
def r32(ctx):
    """第一个收到 407 的请求和第一个带凭据的请求是否在同一条代理连接上。没有收到过 407 是“不适用”。"""
    return retry_conn(ctx)


@row("R33")
def r33(ctx):
    """同 R32。"""
    return retry_conn(ctx)


def after_407_close(ctx):
    f = ctx.f()
    if not any(got_status(r, 407) for r in reqs(f)):
        return NA
    return "成功" if ok200(step(f, "s1")) else "失败"


@row("R34")
def r34(ctx):
    """驱动这一步 ok 且 status 为 200 是“成功”。没有收到过 407 是“不适用”。"""
    return after_407_close(ctx)


@row("R35")
def r35(ctx):
    """同 R34。"""
    return after_407_close(ctx)


@row("R36")
def r36(ctx):
    """代理端口上 http_request 的总数，斜杠，其中 auth 判定为 none 的个数。"""
    f = ctx.f()
    count_note(ctx, f, ctx.case())
    rs = reqs(f)
    return "%d/%d" % (len(rs), sum(1 for r in rs if not has_auth(r)))


@row("R37")
def r37(ctx):
    """目标是 b.kaoju.test 的 CONNECT 里按时间第一个的 auth 判定。"""
    cs = [r for r in reqs(ctx.f(), form="connect") if target_host(r.get("target")) == "b.kaoju.test"]
    if not cs:
        raise Other("没有目标是 b.kaoju.test 的 CONNECT")
    if has_auth(cs[0]):
        return "先带"
    if any(has_auth(r) for r in cs[1:]):
        return "等 407 再带"
    raise Other("对 b.kaoju.test 的 CONNECT 始终不带凭据")


@row("R38")
def r38(ctx):
    """tunnel_open 的个数。"""
    return count_tunnels(ctx)


@row("R39")
def r39(ctx):
    """这些用例里隧道内或直连的 origin_request 有没有带 Proxy-Authorization 的。绝对形式的请求由仪器转给源站，不算。有的话列出用例号。"""
    leaked = []
    for case in ctx.usable():
        if any(r.get("has_proxy_authorization") for r in oreqs(ctx.f(case), via=("tunnel", "direct"))):
            leaked.append(case)
    return "有（%s）" % "、".join(leaked) if leaked else "没有"


@row("R40")
def r40(ctx):
    """三个用例里跳转后的请求（k 以 b 结尾）都到达源站且驱动拿到 200。"""
    bad = []
    for case in ctx.usable():
        f = ctx.f(case)
        arrived = bool(oreqs(f, k="%s.s1b" % case))
        s = step(f, "s1")
        if not (arrived and ok200(s)):
            ctx.note("%s：跳转后的请求%s源站，驱动 ok=%s status=%s" % (case, "到了" if arrived else "没到", s.get("ok"), s.get("status")))
            bad.append(case)
    return "失败（%s）" % "、".join(bad) if bad else "都成功"


def utf8_hex(s):
    return (s or "").encode("utf-8").hex()


@row("R41")
def r41(ctx):
    """每一步带 k 的、auth 判定为 ok 的 http_request，解出的用户名是否等于这一步该用的用户。驱动报 unsupported 是“不支持”。"""
    f = ctx.f()
    cd = ctx.case()
    wrong = []
    for st in request_steps(cd):
        want = expected_user(cd, st)
        if want is None:
            continue
        oks = [r for r in reqs(f, k=case_k(cd, st["id"])) if (r.get("auth") or {}).get("result") == "ok"]
        if not oks:
            raise Other("%s 没有通过认证的请求" % st["id"])
        for r in oks:
            if r["auth"].get("user_hex") != utf8_hex(want["user"]):
                wrong.append("%s 用的是 %r" % (st["id"], r["auth"].get("user")))
    if wrong:
        ctx.note("；".join(wrong))
        return "用错了凭据"
    return "各用各的凭据"


def tunnel_users(ctx, via, same, wrong_value):
    f = ctx.f()
    cd = ctx.case()
    wrong = []
    for st in request_steps(cd):
        want = expected_user(cd, st)
        if want is None:
            continue
        rs = oreqs(f, k=case_k(cd, st["id"]))
        if not rs:
            raise Other("%s 的请求没到源站" % st["id"])
        for r in rs:
            if r.get("via") != "tunnel":
                raise Other("%s 的请求不在隧道里（%s）" % (st["id"], r.get("via")))
            t = tunnel_of(f, r.get("tunnel")) or {}
            opener = t.get("opener") or {}
            if t.get("via") != via:
                raise Other("%s 所在的隧道经由 %s" % (st["id"], t.get("via")))
            if opener.get("user_hex") is None:
                raise Other("%s 所在的隧道建立时没有带凭据" % st["id"])
            if opener["user_hex"] != utf8_hex(want["user"]):
                wrong.append("%s 走的隧道是 %r 建的" % (st["id"], opener.get("user")))
    if wrong:
        ctx.note("；".join(wrong))
        return wrong_value
    return same


@row("R42")
def r42(ctx):
    """每一步带 k 的 origin_request 所在的隧道，建立它的 CONNECT 解出的用户名是否等于这一步该用的用户。"""
    return tunnel_users(ctx, "connect", "各开各的隧道", "用了别人的隧道")


@row("R43")
def r43(ctx):
    """带 k 的 http_request 里正文长度等于 65536 的个数。"""
    f = ctx.f()
    count_note(ctx, f, ctx.case())
    return str(sum(1 for r in reqs(f, k="B13.s1") if r.get("body_len") == 65536))


@row("R44")
def r44(ctx):
    """状态码是 407 的 http_response 的个数。"""
    f = ctx.f()
    count_note(ctx, f, ctx.case())
    return str(sum(1 for r in reqs(f) for x in r.get("responses") or [] if x.get("status") == 407))


def caller_sees(ctx, code):
    s = step(ctx.f(), "s1")
    if s.get("ok") is True:
        if s.get("status") == code:
            return "拿到 %d 响应" % code
        return str(s.get("status"))
    if re.search(r"\b%d\b" % code, s.get("default_text") or ""):
        return "报错，提到 %d" % code
    return "报错，没提 %d" % code


@row("R45")
def r45(ctx):
    """驱动结果里这一步 ok 为真且 status 等于 407，是“拿到 407 响应”；ok 为假时看 default_text 里有没有 \\b407\\b。其余情况原样写出 status。"""
    return caller_sees(ctx, 407)


@row("R46")
def r46(ctx):
    """驱动结果里这一步 ok 为真且 status 等于 407，是“拿到 407 响应”；ok 为假时看 default_text 里有没有 \\b407\\b。其余情况原样写出 status。"""
    return caller_sees(ctx, 407)


def count_with_auth(ctx):
    return str(sum(1 for r in reqs(ctx.f()) if has_auth(r)))


@row("R47")
def r47(ctx):
    """auth 判定不是 none 的 http_request 的个数。"""
    return count_with_auth(ctx)


@row("R48")
def r48(ctx):
    """同 R47。"""
    return count_with_auth(ctx)


@row("R49")
def r49(ctx):
    """驱动结果里这一步 ok 为真且 status 等于 407，是“拿到 407 响应”；ok 为假时看 default_text 里有没有 \\b407\\b。其余情况原样写出 status。"""
    return caller_sees(ctx, 407)


@row("R50")
def r50(ctx):
    """驱动结果里这一步 ok 为真且 status 等于 403，是“拿到 403 响应”；ok 为假时看 default_text 里有没有 \\b403\\b。其余情况原样写出 status。"""
    return caller_sees(ctx, 403)


@row("R51")
def r51(ctx):
    """驱动结果里这一步 ok 为真且 status 等于 403，是“拿到 403 响应”；ok 为假时看 default_text 里有没有 \\b403\\b。其余情况原样写出 status。"""
    return caller_sees(ctx, 403)


def sends_unasked(ctx):
    rs = reqs(ctx.f())
    if not rs:
        raise Other("代理端口上没有请求")
    return "带" if any(has_auth(r) for r in rs) else "不带"


@row("R52")
def r52(ctx):
    """代理端口上有没有 auth 判定不是 none 的 http_request。"""
    return sends_unasked(ctx)


@row("R53")
def r53(ctx):
    """同 R52。"""
    return sends_unasked(ctx)


# ---------------------------------------------------------------------------
# 用户名和密码的字节（HTTP 代理）


def show_bytes(b):
    if len(b) <= 96:
        out = "%d 字节，十六进制 %s" % (len(b), b.hex())
        try:
            out += "，按 UTF-8 读是 %r" % b.decode("utf-8")
        except UnicodeDecodeError:
            out += "，不是合法的 UTF-8"
        return out
    return "%d 字节，十六进制开头 %s…结尾 %s，SHA-256 %s" % (len(b), b[:48].hex(), b[-16:].hex(), hashlib.sha256(b).hexdigest())


def basic_bytes(ctx):
    """R60 到 R70 共用。"""
    f = ctx.f()
    cd = ctx.case()
    st = request_steps(cd)[0]
    want = expected_user(cd, st)
    if want is None:
        raise Other("用例没有配凭据")
    expect = want["user"].encode("utf-8") + b":" + want["pass"].encode("utf-8")
    with_auth = [r for r in reqs(f) if (r.get("auth") or {}).get("present")]
    if not with_auth:
        return "客户端报错" if failed(step(f, st["id"])) else "没发凭据"
    raw = (with_auth[-1]["auth"].get("raw") or "").strip()
    scheme, _, rest = raw.partition(" ")
    if scheme.lower() != "basic":
        ctx.note("Proxy-Authorization 的方案是 %r，不是 Basic" % scheme)
        return "变了"
    try:
        got = base64.b64decode(rest.strip(), validate=True)
    except (binascii.Error, ValueError):
        ctx.note("Basic 后面的 base64 解不开：%r" % rest[:200])
        return "变了"
    if got == expect:
        return "原样"
    ctx.data["received_hex"] = got.hex()
    ctx.note("实际收到 %s；用例里的是 %d 字节" % (show_bytes(got), len(expect)))
    return "变了"


BASIC_HOW = "取代理端口上最后一个带 Proxy-Authorization 的 http_request，把 Basic 后面的 base64 解开，与“用例里的用户名、冒号、密码”的 UTF-8 字节逐字节比较。没有任何带凭据的请求：驱动这一步失败是“客户端报错”，否则是“没发凭据”。变了的格子，实际收到的字节记在脚注。"


def _register_same(ids, impl, how):
    for rid in ids:

        def fn(ctx, _impl=impl):
            return _impl(ctx)

        fn.__name__ = rid.lower()
        fn.__doc__ = how
        row(rid)(fn)


_register_same(["R%d" % n for n in range(60, 71)], basic_bytes, BASIC_HOW)


# ---------------------------------------------------------------------------
# 代理报错时调用方能看到什么

HEADER_MARKERS = ("KaojuHeaderMarker", "KaojuStatusMarker")


def visible(text, code):
    out = []
    if re.search(r"\b%d\b" % code, text):
        out.append("状态码")
    if "KaojuReasonMarker" in text:
        out.append("原因短语")
    if any(m in text for m in HEADER_MARKERS):
        out.append("响应头")
    if "KaojuBodyMarker" in text:
        out.append("正文")
    return "、".join(out) if out else "都看不到"


def visible_default(ctx, code):
    s = step(ctx.f(), "s1")
    return visible(s.get("default_text") or "", code)


def visible_extra(ctx, code):
    s = step(ctx.f(), "s1")
    if not s.get("extra_text"):
        return "没有这样的手段"
    if s.get("extra_how"):
        ctx.note("手段：%s" % s["extra_how"])
    return visible((s.get("default_text") or "") + "\n" + s["extra_text"], code)


@row("R80")
def r80(ctx):
    """在这一步的 default_text 里找：状态码看 \\b502\\b 是否出现；原因短语看 KaojuReasonMarker；响应头看 KaojuHeaderMarker 或 KaojuStatusMarker；正文看 KaojuBodyMarker。把看得见的按“状态码、原因短语、响应头、正文”的顺序用顿号连起来；一样都看不见写“都看不到”"""
    return visible_default(ctx, 502)


@row("R81")
def r81(ctx):
    """在这一步的 default_text 和 extra_text 里找：状态码看 \\b502\\b 是否出现；原因短语看 KaojuReasonMarker；响应头看 KaojuHeaderMarker 或 KaojuStatusMarker；正文看 KaojuBodyMarker。把看得见的按“状态码、原因短语、响应头、正文”的顺序用顿号连起来；一样都看不见写“都看不到”。驱动没有用任何额外手段（extra_text 为空）写“没有这样的手段”。"""
    return visible_extra(ctx, 502)


@row("R82")
def r82(ctx):
    """在这一步的 default_text 里找：状态码看 \\b403\\b 是否出现；原因短语看 KaojuReasonMarker；响应头看 KaojuHeaderMarker 或 KaojuStatusMarker；正文看 KaojuBodyMarker。把看得见的按“状态码、原因短语、响应头、正文”的顺序用顿号连起来；一样都看不见写“都看不到”"""
    return visible_default(ctx, 403)


@row("R83")
def r83(ctx):
    """form=connect 的 http_request 的个数。"""
    return str(len(reqs(ctx.f(), form="connect")))


def header_marker_default(ctx):
    s = step(ctx.f(), "s1")
    text = s.get("default_text") or ""
    return "看得到" if any(m in text for m in HEADER_MARKERS) else "看不到"


@row("R84")
def r84(ctx):
    """default_text 里有没有 KaojuHeaderMarker 或 KaojuStatusMarker。"""
    return header_marker_default(ctx)


@row("R85")
def r85(ctx):
    """default_text 和 extra_text 里有没有那两个记号。extra_text 为空写“没有这样的手段”。"""
    s = step(ctx.f(), "s1")
    if not s.get("extra_text"):
        return "没有这样的手段"
    if s.get("extra_how"):
        ctx.note("手段：%s" % s["extra_how"])
    text = (s.get("default_text") or "") + "\n" + s["extra_text"]
    return "看得到" if any(m in text for m in HEADER_MARKERS) else "看不到"


@row("R86")
def r86(ctx):
    """在这一步的 default_text 里找：状态码看 \\b403\\b 是否出现；原因短语看 KaojuReasonMarker；响应头看 KaojuHeaderMarker 或 KaojuStatusMarker；正文看 KaojuBodyMarker。把看得见的按“状态码、原因短语、响应头、正文”的顺序用顿号连起来；一样都看不见写“都看不到”"""
    return visible_default(ctx, 403)


@row("R87")
def r87(ctx):
    """default_text 里有没有 KaojuHeaderMarker 或 KaojuStatusMarker。"""
    return header_marker_default(ctx)


@row("R88")
def r88(ctx):
    """目标是 a.kaoju.test 的 CONNECT 与目标是 fail.kaoju.test 的 CONNECT 是否在同一条代理连接上。"""
    f = ctx.f()
    cs = reqs(f, form="connect")
    fails = [(i, r) for i, r in enumerate(cs) if target_host(r.get("target")) == "fail.kaoju.test"]
    if not fails:
        raise Other("没有目标是 fail.kaoju.test 的 CONNECT")
    nxt = next(((i, r) for i, r in enumerate(cs) if target_host(r.get("target")) == "a.kaoju.test"), None)
    if nxt is None:
        return "没有第二个 CONNECT"
    before = [r for i, r in fails if i < nxt[0]]
    if not before:
        raise Other("对 a.kaoju.test 的 CONNECT 排在对 fail.kaoju.test 的之前")
    configured = bool((((f.get("profile") or {}).get("connect") or {}).get("fail") or {}).get("close"))
    for r in before:
        resp = r.get("response") or {}
        close_note(ctx, resp.get("close"), configured, "失败响应")
    return "原连接" if nxt[1].get("conn") in {r.get("conn") for r in before} else "新连接"


@row("R89")
def r89(ctx):
    """驱动的 s2 这一步 ok 且 status 为 200。"""
    return "成功" if ok200(step(ctx.f(), "s2")) else "失败"


# ---------------------------------------------------------------------------
# 连接被关以后


def has_action(f, what, k=None):
    for a in f.get("actions") or []:
        if a.get("what") == what and (k is None or a.get("k") == k):
            return True
    return False


@row("R90")
def r90(ctx):
    """s2 成功且它的请求与 s1 的请求不在同一条代理连接上是第一种。"""
    f = ctx.f()
    if not ok200(step(f, "s2")):
        return "失败"
    r1, r2 = reqs(f, k="F01.s1"), reqs(f, k="F01.s2")
    if not r1 or not r2:
        raise Other("s2 成功，但代理端口上找不到 s1 或 s2 的请求")
    idle = has_action(f, "conn_idle_close")
    if r2[-1].get("conn") in {r.get("conn") for r in r1}:
        raise Other("s2 成功，但与 s1 在同一条代理连接上（空闲关闭%s发生）" % ("已" if idle else "没有"))
    if not idle:
        ctx.note("仪器的空闲关闭没有发生：新连接不是因为旧连接被代理关掉")
    return "换新连接，成功"


@row("R91")
def r91(ctx):
    """s2 成功且它的 origin_request 与 s1 的不在同一条隧道里是第一种。"""
    f = ctx.f()
    if not ok200(step(f, "s2")):
        return "失败"
    r1, r2 = oreqs(f, k="F02.s1", via="tunnel"), oreqs(f, k="F02.s2", via="tunnel")
    if not r1 or not r2:
        raise Other("s2 成功，但隧道里找不到 s1 或 s2 的请求")
    idle = has_action(f, "tunnel_idle_close")
    if r2[-1].get("tunnel") in {r.get("tunnel") for r in r1}:
        raise Other("s2 成功，但与 s1 在同一条隧道里（空闲关闭%s发生）" % ("已" if idle else "没有"))
    if not idle:
        ctx.note("仪器的空闲关闭没有发生：新隧道不是因为旧隧道被代理关掉")
    return "换新隧道，成功"


def after_drop(ctx, where):
    """R92 到 R99、R101 共用。where：conn（请求到达代理的次数）或 origin（到达源站的次数）。"""
    f = ctx.f()
    cd = ctx.case()
    drop = ((cd.get("profile") or {}).get(where) or {}).get("drop") or {}
    k = drop.get("k")
    if not k:
        raise Other("用例的配置里没有 %s.drop.k" % where)
    if not has_action(f, "%s_drop" % where, k):
        return "未触发"
    n = len(reqs(f, k=k)) if where == "conn" else len(oreqs(f, k=k))
    s = step(f, k.split(".", 1)[1])
    return "%d 次，%s" % (n, "成功" if ok200(s) else "失败")


DROP_PROXY_HOW = "仪器的丢弃动作没有发生（action 事件里没有）写“未触发”。否则写：被丢弃的那一步的请求到达代理（带 k 的 http_request）的次数（含被丢弃的那次），逗号，驱动这一步是否 ok 且 status 为 200。"
DROP_ORIGIN_HOW = "仪器的丢弃动作没有发生（action 事件里没有）写“未触发”。否则写：被丢弃的那一步的请求到达源站（带 k 的 origin_request）的次数（含被丢弃的那次），逗号，驱动这一步是否 ok 且 status 为 200。"

_register_same(["R92", "R93", "R96", "R98"], lambda ctx: after_drop(ctx, "conn"), DROP_PROXY_HOW)
_register_same(["R94", "R95", "R97", "R99", "R101"], lambda ctx: after_drop(ctx, "origin"), DROP_ORIGIN_HOW)


@row("R100")
def r100(ctx):
    """form=connect 的 http_request 的个数，逗号，驱动这一步是否 ok 且 status 为 200。"""
    f = ctx.f()
    if not has_action(f, "connect_drop"):
        ctx.note("仪器的 connect_drop 动作没有发生")
    return "%d 次，%s" % (len(reqs(f, form="connect")), "成功" if ok200(step(f, "s1")) else "失败")


# ---------------------------------------------------------------------------
# SOCKS5 入口

ATYP = {1: "IPv4", 3: "域名", 4: "IPv6"}


def greeting_methods(ctx):
    for s in ctx.f().get("socks") or []:
        if s.get("greeting"):
            return ",".join("%02x" % m for m in s["greeting"].get("methods") or [])
    raise Other("没有 SOCKS5 的方法协商")


@row("R110")
def r110(ctx):
    """第一条 SOCKS5 连接的 socks5_greeting 里的方法，两位十六进制，用逗号连接。"""
    return greeting_methods(ctx)


@row("R111")
def r111(ctx):
    """同 R110。"""
    return greeting_methods(ctx)


def first_socks_request(f):
    for s in f.get("socks") or []:
        if s.get("request"):
            return s["request"]
    return None


def atyp_name(req):
    if req.get("atyp") not in ATYP:
        raise Other("地址类型是 %s" % req.get("atyp"))
    return ATYP[req["atyp"]]


@row("R112")
def r112(ctx):
    """第一个 socks5_request 的地址类型。"""
    req = first_socks_request(ctx.f())
    if req is None:
        raise Other("没有 socks5_request")
    return atyp_name(req)


@row("R113")
def r113(ctx):
    """同 R112。代理端口上没有连接而源站端口上有直连是“直连”；都没有是“没连代理”。"""
    f = ctx.f()
    req = first_socks_request(f)
    if req is not None:
        return atyp_name(req)
    if not f.get("proxy_conn_count"):
        return "直连" if f.get("direct_conn_count") else "没连代理"
    raise Other("代理端口上有连接，但没有 socks5_request")


@row("R114")
def r114(ctx):
    """代理端口上没有任何连接且驱动这一步失败是第一种；socks5_request 的地址类型是域名是第二种。"""
    f = ctx.f()
    s = step(f, "s1")
    req = first_socks_request(f)
    if not f.get("proxy_conn_count") and failed(s):
        return "没连代理就报错"
    if req is not None and req.get("atyp") == 3:
        return "把域名交给了代理"
    if req is not None:
        ctx.note("socks5_request 的地址类型是 %s，主机 %s" % (ATYP.get(req.get("atyp"), req.get("atyp")), req.get("host")))
    else:
        ctx.note("代理端口上有 %d 条连接，没有 socks5_request；驱动 ok=%s" % (f.get("proxy_conn_count") or 0, s.get("ok")))
    return "其他"


@row("R115")
def r115(ctx):
    """第一条隧道的 tunnel_first_bytes 的归类。"""
    return tunnel_first_kind(ctx)


@row("R116")
def r116(ctx):
    """同 R115。"""
    return tunnel_first_kind(ctx)


def last_socks_auth(f):
    auths = [s["auth"] for s in f.get("socks") or [] if s.get("auth")]
    return auths[-1] if auths else None


@row("R117")
def r117(ctx):
    """驱动这一步 ok 且 status 为 200，且 socks5_auth 的状态是 0。"""
    f = ctx.f()
    a = last_socks_auth(f)
    if ok200(step(f, "s1")) and a is not None and a.get("status") == 0:
        return "成功"
    if a is None:
        ctx.note("没有 socks5_auth")
    return "失败"


@row("R118")
def r118(ctx):
    """驱动这一步 ok 且 status 为 200。"""
    return "成功" if ok200(step(ctx.f(), "s1")) else "失败"


AUTH_WORDS = ("auth", "method", "credential", "password", "认证", "方法")


def error_mentions_auth(ctx):
    s = step(ctx.f(), "s1")
    if not failed(s):
        raise Other("这一步没有报错（ok=%s status=%s）" % (s.get("ok"), s.get("status")))
    text = (s.get("default_text") or "").lower()
    return "提到认证或方法" if any(w in text for w in AUTH_WORDS) else "只说失败"


@row("R119")
def r119(ctx):
    """default_text 转小写后含有 auth、method、credential、password、认证、方法 之一是“提到认证或方法”，否则是“只说失败”。"""
    return error_mentions_auth(ctx)


@row("R120")
def r120(ctx):
    """default_text 转小写后含有 auth、method、credential、password、认证、方法 之一是“提到认证或方法”，否则是“只说失败”。"""
    return error_mentions_auth(ctx)


@row("R121")
def r121(ctx):
    """取三个用例里失败那一步的 default_text，去掉用例号（S09、S10、S11）和 3 位以上的数字串以后两两不同是“能区分”。"""
    cases = ctx.usable()
    if len(cases) < 2:
        raise Other("只有 %d 个用例有结果，没法比较" % len(cases))
    texts = []
    for case in cases:
        s = step(ctx.f(case), "s1")
        if not failed(s):
            raise Other("%s 这一步没有失败" % case)
        t = s.get("default_text") or ""
        for cid in ctx.row["cases"]:
            t = t.replace(cid, "")
        texts.append(re.sub(r"\d{3,}", "", t))
    return "能区分" if len(set(texts)) == len(texts) else "不能区分"


@row("R122")
def r122(ctx):
    """代理端口上 accept 的个数。"""
    return count_proxy_conns(ctx)


@row("R123")
def r123(ctx):
    """代理端口上 accept 的个数。"""
    return count_proxy_conns(ctx)


@row("R124")
def r124(ctx):
    """每一步带 k 的 origin_request 所在的隧道，它那条连接的 socks5_auth 的用户名是否等于这一步该用的用户。"""
    return tunnel_users(ctx, "socks5", "各开各的连接", "用了别人的连接")


def socks_bytes(ctx):
    """R125 到 R132 共用。"""
    f = ctx.f()
    cd = ctx.case()
    st = request_steps(cd)[0]
    want = expected_user(cd, st)
    if want is None:
        raise Other("用例没有配凭据")
    a = last_socks_auth(f)
    if a is None:
        return "客户端报错" if failed(step(f, st["id"])) else "没发凭据"
    eu, ep = utf8_hex(want["user"]), utf8_hex(want["pass"])
    if a.get("user_hex") == eu and a.get("pass_hex") == ep:
        return "原样"
    if a.get("user_hex") != eu:
        ctx.note("用户名实际收到 %s；用例里的是 %d 字节" % (show_bytes(bytes.fromhex(a.get("user_hex") or "")), len(eu) // 2))
    if a.get("pass_hex") != ep:
        ctx.note("密码实际收到 %s；用例里的是 %d 字节" % (show_bytes(bytes.fromhex(a.get("pass_hex") or "")), len(ep) // 2))
    return "变了"


SOCKS_HOW = "取最后一个 socks5_auth，用户名和密码的字节分别与用例里的 UTF-8 字节比较，两样都相同是“原样”。没有 socks5_auth：驱动这一步失败是“客户端报错”，否则是“没发凭据”。驱动报 unsupported 是“不支持”。"

_register_same(["R%d" % n for n in range(125, 133)], socks_bytes, SOCKS_HOW)


# ---------------------------------------------------------------------------
# 通用规则


def gate_problem(facts):
    """这次运行没通过抓包核对的原因；通过了是 None。跳过（only）的运行不核对。"""
    run = facts.get("run") or {}
    if run.get("skipped"):
        return None
    if run.get("pcap_status") not in PASS_PCAP:
        return "pcap_check 是 %s" % run.get("pcap_status")
    dropped = run.get("tcpdump_dropped")
    if dropped is None:
        return "没有 tcpdump 的统计"
    if dropped:
        return "tcpdump 丢了 %s 个包" % dropped
    return None


def run_status(case_def, variant, facts):
    """一次运行的通用状态：(标签, 说明)；可以取值时是 (None, None)。不含抓包核对。"""
    only = case_def.get("only") or []
    if only and variant not in only:
        return NA, None
    run = facts.get("run") or {}
    if run.get("skipped"):
        return NA, "运行被跳过（%s）" % run["skipped"]
    if run.get("runner_errors"):
        return NO_RESULT, "运行器出错：%s" % str(run["runner_errors"][0])[:200]
    if run.get("driver_timeout"):
        return NO_RESULT, "驱动超时"
    if not run.get("has_result"):
        return NO_RESULT, "驱动没有写出结果（退出码 %s）" % run.get("driver_exit")
    if run.get("unsupported"):
        return UNSUPPORTED, "不支持的原因：%s" % str(run["unsupported"])
    if not run.get("events_complete"):
        return NO_RESULT, "事件文件不完整（缺 start 或 end）"
    if run.get("log_errors"):
        return NO_RESULT, "事件里有 log_error"
    return None, None


def eval_repeat(row_def, variant, facts_by_case, case_defs):
    """一个格子的一遍：返回 (值, 脚注列表, 数据)。facts_by_case 里每个用例都有事实。"""
    rid = row_def["id"]
    usable, excluded, notes = {}, {}, []
    for case in row_def["cases"]:
        label, why = run_status(case_defs.get(case) or {}, variant, facts_by_case[case])
        if label is None:
            usable[case] = facts_by_case[case]
            if (facts_by_case[case].get("run") or {}).get("late_events"):
                notes.append("%s 有 late 事件，事件的先后不可靠" % case)
        else:
            excluded[case] = label
            if why:
                notes.append("%s：%s" % (case, why) if len(row_def["cases"]) > 1 else why)
    if not usable:
        labels = [x for i, x in enumerate(excluded.values()) if x not in list(excluded.values())[:i]]
        return "、".join(labels), notes, {}
    ctx = Ctx(row_def, variant, usable, excluded, case_defs)
    fn = ROWS.get(rid)
    if fn is None:
        return OTHER + "没有实现这一行", notes, {}
    try:
        value = fn(ctx)
    except Other as exc:
        value = OTHER + str(exc)
    except Exception as exc:  # 事实的形状出乎意料：照实写出来，不让整张表失败
        value = OTHER + "取值时出错（%s: %s）" % (type(exc).__name__, str(exc)[:120])
    if excluded and rid not in HANDLES_EXCLUDED:
        value += "（不含 %s）" % "、".join("%s：%s" % (c, excluded[c]) for c in row_def["cases"] if c in excluded)
    return value, notes + ctx.notes, ctx.data


def repeat_key(r):
    try:
        return (0, int(r))
    except (TypeError, ValueError):
        return (1, str(r))


def compute_cell(row_def, variant, col_cases, case_defs, allow_unchecked=False):
    """一个格子。col_cases 是这一列的 {用例: {遍数: 事实}}。这一行的用例一条数据都没有时返回 None。"""
    cases = row_def["cases"]
    static_na = [c for c in cases if (case_defs.get(c) or {}).get("only") and variant not in case_defs[c]["only"]]
    if len(static_na) == len(cases):
        return {"value": NA, "stable": True, "per_repeat": {}, "footnotes": [], "cases": {c: [] for c in cases}}
    need = [c for c in cases if c not in static_na]
    have = {c: col_cases.get(c) or {} for c in cases}
    if not any(have[c] for c in need):
        return None

    footnotes = []
    problems = []
    for c in need:
        for r in sorted(have[c], key=repeat_key):
            why = gate_problem(have[c][r])
            if why:
                problems.append("%s 第 %s 遍：%s" % (c, r, why))
    used = {c: sorted(have[c], key=repeat_key) for c in cases}
    if problems and not allow_unchecked:
        return {"value": UNVERIFIED, "stable": True, "per_repeat": {}, "footnotes": problems, "cases": used}
    if problems:
        footnotes.append("未经抓包核对（--allow-unchecked）：%s" % "；".join(problems[:3]) + ("…" if len(problems) > 3 else ""))

    all_reps = sorted({r for c in need for r in have[c]}, key=repeat_key)
    reps = [r for r in all_reps if all(r in have[c] for c in need)]
    if len(reps) < len(all_reps):
        footnotes.append("有的用例缺遍数，只取各用例都有的 %d 遍" % len(reps))
    if not reps:
        return None

    per_repeat, notes_by_rep, datas = {}, {}, []
    for r in reps:
        fbc = {}
        for c in cases:
            fbc[c] = have[c].get(r) or {"run": {"skipped": "only"}}
        value, notes, data = eval_repeat(row_def, variant, fbc, case_defs)
        per_repeat[r] = value
        notes_by_rep[r] = notes
        datas.append(data)

    uniq = []
    for r in reps:
        if per_repeat[r] not in uniq:
            uniq.append(per_repeat[r])
    stable = len(uniq) == 1
    value = uniq[0] if stable else " / ".join(uniq)

    if all(notes_by_rep[r] == notes_by_rep[reps[0]] for r in reps):
        footnotes.extend(notes_by_rep[reps[0]])
    else:
        for r in reps:
            for n in notes_by_rep[r]:
                footnotes.append("第 %s 遍：%s" % (r, n))
    summarize = SUMMARIZERS.get(row_def["id"])
    if summarize is not None:
        footnotes.extend(summarize(datas))
    cell = {"value": value, "stable": stable, "per_repeat": per_repeat, "footnotes": footnotes, "cases": {c: [r for r in reps if r in have[c]] for c in cases}}
    extra = {}
    for r, d in zip(reps, datas):
        if d:
            extra[r] = d
    if extra:
        cell["data"] = extra
    return cell


# ---------------------------------------------------------------------------
# 读输入


def phase2_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def protocol_columns(path):
    """PROTOCOL.md“被测客户端”一节那张表第一列的列名，按表里的顺序。读不到返回 None。"""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    m = re.search(r"^## 被测客户端\s*$(.*?)(?=^## )", text, re.S | re.M)
    if not m:
        return None
    cols = re.findall(r"^\|\s*`([^`]+)`\s*\|", m.group(1), re.M)
    return cols or None


def load_observations(obs_dir, raw_dir):
    """{列: {用例: {遍数: 事实}}}。observations 里没有而 raw 里有的列，当场提取。"""
    out = {}
    if obs_dir and os.path.isdir(obs_dir):
        for name in sorted(os.listdir(obs_dir)):
            if name.endswith(".json"):
                obs = load_json(os.path.join(obs_dir, name))
                # 目录里可能还有 versions.json 之类不是观测的文件：没有 cases 的不算一列
                if not isinstance(obs, dict) or not isinstance(obs.get("cases"), dict):
                    continue
                out[name[: -len(".json")]] = obs["cases"]
    if raw_dir:
        for col, path in derive_mod.raw_columns(raw_dir).items():
            if col not in out:
                out[col] = derive_mod.derive_column(derive_mod.read_raw(path), col)["cases"]
    return out


# ---------------------------------------------------------------------------
# 矩阵


def build_matrix(rows_def, case_defs, observations, columns, allow_unchecked=False):
    """rows_def：rows.json 的 rows；observations：{列: {用例: {遍数: 事实}}}；columns：要出的列，按顺序。"""
    present = [c for c in columns if c in observations]
    out_rows = []
    for rd in rows_def:
        cells = {}
        for col in columns:
            cells[col] = compute_cell(rd, col, observations[col], case_defs, allow_unchecked) if col in observations else None
        out_rows.append({"id": rd["id"], "section": rd["section"], "title": rd["title"], "cases": rd["cases"], "cells": cells})
    return {
        "matrix_version": MATRIX_VERSION,
        "columns": list(columns),
        "columns_with_data": present,
        "columns_missing": [c for c in columns if c not in observations],
        "pcap_gate": "off" if allow_unchecked else "on",
        "rows": out_rows,
    }


def md_escape(s):
    return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def cell_text(cell):
    if cell is None:
        return ""
    return cell["value"] if cell["stable"] else "%s（不稳定）" % cell["value"]


def render_md(matrix, expected_repeats):
    cols = matrix["columns"]
    lines = ["# 客户端行为矩阵", ""]
    lines.append("由 `runner/matrix.py` 从 `out/observations/` 生成，不要手改。行的取值规则见 `rows.json`，口径见 `PROTOCOL.md`。")
    lines.append("格子里的“（不稳定）”表示各遍取值不同；方括号里的数字指向表后的脚注。")
    if matrix["pcap_gate"] == "off":
        lines.append("")
        lines.append("**注意：这份矩阵是用 `--allow-unchecked` 生成的，没有通过抓包核对的运行也取了值，不能当作正式结果。**")
    if matrix["columns_missing"]:
        lines.append("")
        lines.append("没有数据的列（格子留空）：%s。" % "、".join("`%s`" % c for c in matrix["columns_missing"]))
    short = {}
    for rd in matrix["rows"]:
        for col in cols:
            cell = rd["cells"].get(col)
            if cell and cell["per_repeat"] and len(cell["per_repeat"]) < expected_repeats:
                short[col] = short.get(col, 0) + 1
    if short:
        lines.append("")
        lines.append("不足 %d 遍的格子数：%s。" % (expected_repeats, "、".join("`%s` %d 个" % (c, short[c]) for c in cols if c in short)))
    sections = []
    for rd in matrix["rows"]:
        if rd["section"] not in sections:
            sections.append(rd["section"])
    for sec in sections:
        lines += ["", "## %s" % sec, ""]
        lines.append("| 行 | " + " | ".join("`%s`" % c for c in cols) + " |")
        lines.append("| --- |" + " --- |" * len(cols))
        notes = []
        for rd in matrix["rows"]:
            if rd["section"] != sec:
                continue
            texts = []
            for col in cols:
                cell = rd["cells"].get(col)
                t = md_escape(cell_text(cell))
                if cell and cell["footnotes"]:
                    notes.append((rd["id"], col, cell["footnotes"]))
                    t += " [%d]" % len(notes)
                texts.append(t)
            lines.append("| %s %s | %s |" % (rd["id"], md_escape(rd["title"]), " | ".join(texts)))
        if notes:
            lines.append("")
            for i, (rid, col, fns) in enumerate(notes, 1):
                lines.append("- [%d] %s，`%s`：%s" % (i, rid, col, md_escape("；".join(fns))))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 仪器自检


def read_expected_values(obj):
    """手写答案或预期文件里的 {行号: 值}。接受 {"rows": {...}} 或直接 {...}；值可以是字符串，或带 value / expect 的对象。"""
    rows = obj.get("rows") if isinstance(obj.get("rows"), dict) else obj
    out = {}
    for rid, v in rows.items():
        if not isinstance(rid, str) or not re.fullmatch(r"R\d+", rid):
            continue
        if isinstance(v, dict):
            v = v.get("value", v.get("expect"))
        if isinstance(v, str):
            out[rid] = v
    return out


def build_selfcheck(rows_def, case_defs, observations, expected_path, allow_unchecked=False):
    out = {"variant": SELFCHECK_COLUMN, "has_data": SELFCHECK_COLUMN in observations, "expected_file": None, "pass": None, "rows": {}, "mismatches": []}
    if not out["has_data"]:
        out["note"] = "没有 rawref 的数据，仪器自检没有做"
        return out
    for rd in rows_def:
        out["rows"][rd["id"]] = compute_cell(rd, SELFCHECK_COLUMN, observations[SELFCHECK_COLUMN], case_defs, allow_unchecked)
    if expected_path and os.path.isfile(expected_path):
        out["expected_file"] = os.path.basename(expected_path)
        expected = read_expected_values(load_json(expected_path))
        for rd in rows_def:
            rid = rd["id"]
            cell = out["rows"][rid]
            actual = cell_text(cell) if cell else None
            if rid not in expected:
                out["mismatches"].append({"row": rid, "expected": None, "actual": actual, "why": "答案文件里没有这一行"})
            elif actual != expected[rid]:
                out["mismatches"].append({"row": rid, "expected": expected[rid], "actual": actual, "why": "不相同"})
        out["pass"] = not out["mismatches"]
    else:
        out["note"] = "没有找到手写的答案文件（selfcheck_expected.json），只输出了 rawref 的取值，没有比较"
    return out


# ---------------------------------------------------------------------------
# 与预期比较

UNKNOWN = "不知道"


def build_expectation_diff(matrix, exp_dir):
    """读 expectations/<列>.json，列出实测与预期不符的格子。目录不存在返回 None。"""
    if not exp_dir or not os.path.isdir(exp_dir):
        return None
    by_id = {rd["id"]: rd for rd in matrix["rows"]}
    out = {"columns": {}}
    for name in sorted(os.listdir(exp_dir)):
        if not name.endswith(".json"):
            continue
        col = name[: -len(".json")]
        exp = load_json(os.path.join(exp_dir, name))
        rows = exp.get("rows") if isinstance(exp.get("rows"), dict) else {}
        res = {"compared": 0, "matched": 0, "unknown": 0, "no_data": 0, "unknown_rows": [], "diffs": []}
        for rid in sorted(by_id, key=lambda x: int(x[1:])):
            e = rows.get(rid)
            expect = e.get("expect") if isinstance(e, dict) else None
            if not isinstance(expect, str) or not expect.strip() or expect.strip() == UNKNOWN:
                res["unknown"] += 1
                continue
            cell = by_id[rid]["cells"].get(col)
            if cell is None:
                res["no_data"] += 1
                continue
            res["compared"] += 1
            if cell["stable"] and cell["value"] == expect.strip():
                res["matched"] += 1
                continue
            res["diffs"].append(
                {
                    "row": rid,
                    "title": by_id[rid]["title"],
                    "expect": expect,
                    "actual": cell["value"],
                    "stable": cell["stable"],
                    "per_repeat": cell["per_repeat"],
                    "footnotes": cell["footnotes"],
                    "basis": e.get("basis"),
                    "confidence": e.get("confidence"),
                }
            )
        res["unknown_rows"] = sorted((r for r in rows if r not in by_id), key=str)
        out["columns"][col] = res
    return out


def render_diff_md(diff):
    lines = ["# 实测与预期不符的格子", ""]
    lines.append("由 `runner/matrix.py` 生成。预期在 `expectations/<列>.json`，写于第一次正式运行之前；预期是“不知道”或没写的行不比。")
    lines.append("不符的格子先怀疑仪器和驱动，确认以后记进报告；预期文件不改。")
    if not diff["columns"]:
        lines += ["", "expectations 目录里没有预期文件。", ""]
        return "\n".join(lines)
    for col, res in diff["columns"].items():
        lines += ["", "## `%s`" % col, ""]
        lines.append("比较了 %d 格，相符 %d 格，不符 %d 格；预期为“不知道”或没写 %d 行；有预期但没有实测 %d 行。" % (res["compared"], res["matched"], len(res["diffs"]), res["unknown"], res["no_data"]))
        if res["unknown_rows"]:
            lines.append("预期文件里有、行表里没有的行：%s。" % "、".join(res["unknown_rows"]))
        if not res["diffs"]:
            continue
        lines += ["", "| 行 | 预期 | 实测 | 把握 | 依据 |", "| --- | --- | --- | --- | --- |"]
        for d in res["diffs"]:
            actual = d["actual"] if d["stable"] else "%s（不稳定）" % d["actual"]
            lines.append("| %s %s | %s | %s | %s | %s |" % (d["row"], md_escape(d["title"]), md_escape(d["expect"]), md_escape(actual), md_escape(d.get("confidence") or ""), md_escape(d.get("basis") or "")))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------


def write_text(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def find_selfcheck_expected(base):
    for rel in ("selfcheck_expected.json", os.path.join("drivers", "rawref", "selfcheck_expected.json")):
        p = os.path.join(base, rel)
        if os.path.isfile(p):
            return p
    return None


def main(argv=None):
    base = phase2_dir()
    ap = argparse.ArgumentParser(description="按 rows.json 从事实里生成矩阵")
    ap.add_argument("--observations", default=os.path.join(base, "out", "observations"), help="derive.py 的输出目录")
    ap.add_argument("--raw", default=None, help="out/raw 目录；observations 里没有的列从这里当场提取")
    ap.add_argument("--out", default=os.path.join(base, "out"), help="输出目录")
    ap.add_argument("--rows", default=os.path.join(base, "rows.json"))
    ap.add_argument("--cases", default=os.path.join(base, "cases.json"))
    ap.add_argument("--protocol", default=os.path.join(base, "PROTOCOL.md"))
    ap.add_argument("--expectations", default=os.path.join(base, "expectations"))
    ap.add_argument("--selfcheck-expected", default=None, help="rawref 的手写答案；默认在 phase2/ 和 drivers/rawref/ 下找 selfcheck_expected.json")
    ap.add_argument("--allow-unchecked", action="store_true", help="只供开发时冒烟：没通过抓包核对的运行也取值（输出里会标明，不能当正式结果）")
    args = ap.parse_args(argv)

    rows_def = load_json(args.rows)["rows"]
    cases_doc = load_json(args.cases)
    case_defs = {c["id"]: c for c in cases_doc["cases"]}
    missing_impl = [r["id"] for r in rows_def if r["id"] not in ROWS]
    if missing_impl:
        print("matrix: 这些行没有实现：%s" % "、".join(missing_impl), file=sys.stderr)
        return 2
    observations = load_observations(args.observations, args.raw)
    if not observations:
        print("matrix: 没有任何列的数据（%s）" % args.observations, file=sys.stderr)
        return 1

    columns = list(protocol_columns(args.protocol) or COLUMNS_FALLBACK)
    extra = sorted(c for c in observations if c not in columns and c != SELFCHECK_COLUMN)
    columns += extra

    matrix = build_matrix(rows_def, case_defs, observations, columns, args.allow_unchecked)
    if extra:
        matrix["columns_not_in_protocol"] = extra
    os.makedirs(args.out, exist_ok=True)
    derive_mod.dump_json(matrix, os.path.join(args.out, "matrix.json"))
    write_text(os.path.join(args.out, "matrix.md"), render_md(matrix, int(cases_doc.get("repeats") or 3)))

    exp_path = args.selfcheck_expected or find_selfcheck_expected(base)
    selfcheck = build_selfcheck(rows_def, case_defs, observations, exp_path, args.allow_unchecked)
    derive_mod.dump_json(selfcheck, os.path.join(args.out, "selfcheck.json"))

    diff = build_expectation_diff(matrix, args.expectations)
    if diff is not None:
        derive_mod.dump_json(diff, os.path.join(args.out, "expectation_diff.json"))
        write_text(os.path.join(args.out, "expectation_diff.md"), render_diff_md(diff))

    others = unverified = 0
    for rd in matrix["rows"]:
        for cell in rd["cells"].values():
            if cell is None:
                continue
            if any(v.startswith(OTHER) for v in cell["per_repeat"].values()):
                others += 1
            if cell["value"] == UNVERIFIED:
                unverified += 1
    print("matrix: %d 行 × %d 列（有数据的 %d 列）；“其他：”的格子 %d 个，未通过核对的格子 %d 个" % (len(matrix["rows"]), len(columns), len(matrix["columns_with_data"]), others, unverified))
    if selfcheck["pass"] is False:
        print("matrix: 仪器自检不通过，%d 格与手写答案不同" % len(selfcheck["mismatches"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
