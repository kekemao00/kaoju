#!/usr/bin/env python3
"""抓包核对：独立于 obsproxy 的第二个见证方。

从 tcpdump 写出的经典 pcap 文件里按序号重建每条 TCP 连接，然后与 obsproxy 的事件文件比两件事：

1. 每条连接两个方向的字节数和 SHA-256（对 conn_end 的 bytes_in/sha256_in、bytes_out/sha256_out）；
2. 用这里自己的解析器从代理端口的字节流里重新解析 HTTP 请求、SOCKS5 握手和隧道首包，
   与 http_request、socks5_*、tunnel_first_bytes 等事件逐项比。

只用 Python 标准库；不导入、不调用 obsproxy 的任何代码。口径见 ../PROTOCOL.md 的“抓包核对”一节，
事件字段见 ../harness/EVENTS.md。

用法：
    python3 pcap_check.py --pcap X.pcap --events E.jsonl --out check.json
    import pcap_check; pcap_check.check(pcap_path, events_path) -> dict

退出码：0 表示 ok 或 prefix，1 表示 mismatch，2 表示 error。
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import struct
import sys

MASK32 = 0xFFFFFFFF

# 链路类型（pcap 文件头里的 network 字段）
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

SUPPORTED_DLT = {
    DLT_NULL: "NULL",
    DLT_EN10MB: "EN10MB",
    DLT_RAW_BSD: "RAW",
    DLT_RAW: "RAW",
    DLT_LOOP: "LOOP",
    DLT_LINUX_SLL: "LINUX_SLL",
    DLT_IPV4: "IPV4",
    DLT_IPV6: "IPV6",
    DLT_LINUX_SLL2: "LINUX_SLL2",
}

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_ACK = 0x10

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class PcapError(Exception):
    """抓包文件读不了或格式不认识。"""


class EventsError(Exception):
    """事件文件读不了或结构不对。"""


# ---------------------------------------------------------------------------
# 第一步：读 pcap
# ---------------------------------------------------------------------------


def read_pcap(path):
    """读经典 pcap 文件，返回 (链路类型, [(序号, 包的字节, 是否被截短)…], 说明列表)。"""
    with open(path, "rb") as fh:
        data = fh.read()
    notes = []
    if len(data) < 24:
        raise PcapError("抓包文件不足 24 个字节，连文件头都不完整")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic == b"\x0a\x0d\x0d\x0a":
        raise PcapError("这是 pcapng 文件；只支持经典 pcap（tcpdump -w 的默认格式）")
    else:
        raise PcapError("不认识的文件魔数 %s" % magic.hex())
    _vmaj, _vmin, _zone, _sig, _snaplen, network = struct.unpack(endian + "HHiIII", data[4:24])
    linktype = network & 0x0FFFFFFF
    if linktype not in SUPPORTED_DLT:
        raise PcapError("不支持的链路类型 %d" % linktype)
    packets = []
    pos = 24
    idx = 0
    total = len(data)
    while pos < total:
        if pos + 16 > total:
            notes.append("抓包文件末尾有 %d 个字节凑不成一个包头（文件被截断）" % (total - pos))
            break
        _sec, _frac, caplen, origlen = struct.unpack(endian + "IIII", data[pos : pos + 16])
        pos += 16
        if pos + caplen > total:
            notes.append("第 %d 个包声称有 %d 个字节，文件里只剩 %d 个（文件被截断）" % (idx + 1, caplen, total - pos))
            break
        packets.append((idx, data[pos : pos + caplen], caplen < origlen))
        pos += caplen
        idx += 1
    return linktype, packets, notes


def strip_link(linktype, frame):
    """去掉链路层头，返回 IP 包的字节；不是 IP 返回 None。"""
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return None
        off = 12
        etype = struct.unpack(">H", frame[off : off + 2])[0]
        off += 2
        while etype in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 4:
            etype = struct.unpack(">H", frame[off + 2 : off + 4])[0]
            off += 4
        if etype not in (0x0800, 0x86DD):
            return None
        return frame[off:]
    if linktype == DLT_LINUX_SLL:
        if len(frame) < 16:
            return None
        etype = struct.unpack(">H", frame[14:16])[0]
        if etype not in (0x0800, 0x86DD):
            return None
        return frame[16:]
    if linktype == DLT_LINUX_SLL2:
        if len(frame) < 20:
            return None
        etype = struct.unpack(">H", frame[0:2])[0]
        if etype not in (0x0800, 0x86DD):
            return None
        return frame[20:]
    if linktype in (DLT_NULL, DLT_LOOP):
        # 4 个字节的地址族（NULL 是主机字节序，LOOP 是网络字节序）；族的编号各系统不同，
        # 所以不看它，直接看后面 IP 头的版本号。
        if len(frame) < 4:
            return None
        return frame[4:]
    # RAW、IPV4、IPV6：直接就是 IP 包
    return frame


def parse_ip_tcp(ip):
    """解析 IP 和 TCP 头。

    返回 (源地址, 源端口, 目的地址, 目的端口, seq, flags, 载荷, 说明或 None)；
    不是 TCP、或头不完整时返回 None；是分片时返回字符串说明。
    """
    if not ip:
        return None
    ver = ip[0] >> 4
    if ver == 4:
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            return None
        total = struct.unpack(">H", ip[2:4])[0]
        frag = struct.unpack(">H", ip[6:8])[0]
        proto = ip[9]
        if proto != 6:
            return None
        if frag & 0x3FFF:  # MF 置位，或分片偏移不是 0
            return "IPv4 分片"
        src = ip[12:16]
        dst = ip[16:20]
        # 总长度是 0 的包（某些网卡的 TSO）按实际抓到的长度算
        end = total if ihl <= total <= len(ip) else len(ip)
        seg = ip[ihl:end]
        short = total > len(ip)
    elif ver == 6:
        if len(ip) < 40:
            return None
        plen = struct.unpack(">H", ip[4:6])[0]
        nxt = ip[6]
        src = ip[8:24]
        dst = ip[24:40]
        off = 40
        end = 40 + plen if 0 < plen and 40 + plen <= len(ip) else len(ip)
        short = 40 + plen > len(ip)
        while nxt in (0, 43, 60):  # 逐跳、路由、目的地选项
            if len(ip) < off + 8:
                return None
            nxt, hlen = ip[off], ip[off + 1]
            off += (hlen + 1) * 8
        if nxt == 44:
            return "IPv6 分片"
        if nxt != 6:
            return None
        seg = ip[off:end]
    else:
        return None
    if len(seg) < 20:
        return None
    sport, dport, seq, _ack, offres, flags = struct.unpack(">HHIIBB", seg[:14])
    doff = (offres >> 4) * 4
    if doff < 20 or len(seg) < doff:
        return None
    return (src, sport, dst, dport, seq, flags, seg[doff:], "包被截短" if short else None)


# ---------------------------------------------------------------------------
# 第二步：重建 TCP 流
# ---------------------------------------------------------------------------


def _sdiff(a, b):
    """32 位序号的有符号差 a-b（回绕安全）。"""
    return ((a - b + 0x80000000) & MASK32) - 0x80000000


class Stream:
    """一个方向的字节流。"""

    def __init__(self):
        self.has_syn = False
        self.ref_seq = None  # 已见到的最高字节之后的 32 位序号
        self.ref_abs = 0  # 它对应的流内偏移（不回绕）
        self.buf = bytearray()  # 从偏移 0 起连续的部分
        self.pending = []  # 还接不上的段 [(偏移, 字节)]
        self.fin_idx = None
        self.fin_off = None
        self.rst_idx = None
        self.packets = 0
        self.retrans_bytes = 0
        self.conflict_bytes = 0
        self.out_of_order = 0

    def add(self, seq, flags, payload, idx):
        self.packets += 1
        if flags & TH_RST:
            # RST 的序号不可靠（可能取自对方的确认号），载荷是诊断信息，都不计入流
            if self.rst_idx is None:
                self.rst_idx = idx
            return
        data_seq = seq
        if flags & TH_SYN:
            data_seq = (seq + 1) & MASK32
            if self.ref_seq is None:
                self.has_syn = True
                self.ref_seq = data_seq
                self.ref_abs = 0
            elif not self.has_syn and not self.buf and not self.pending:
                self.has_syn = True
                self.ref_seq = data_seq
                self.ref_abs = 0
        elif self.ref_seq is None:
            # 没见到 SYN：只能拿见到的第一个包的序号当起点
            self.ref_seq = data_seq
            self.ref_abs = 0
        off = self.ref_abs + _sdiff(data_seq, self.ref_seq)
        if off < 0:
            if self.has_syn:
                # 序号落在初始序号之前（比如 keepalive 探测），截掉这部分
                payload = payload[-off:]
                off = 0
            else:
                # 没有 SYN 的流里出现了更早的数据：把已有的内容整体后移
                shift = -off
                if self.buf:
                    self.pending.append((0, bytes(self.buf)))
                    self.buf = bytearray()
                self.pending = [(o + shift, d) for o, d in self.pending]
                self.ref_abs += shift
                if self.fin_off is not None:
                    self.fin_off += shift
                off = 0
        end = off + len(payload)
        if end > self.ref_abs:
            self.ref_abs = end
            self.ref_seq = (data_seq + len(payload)) & MASK32
        if payload:
            self._insert(off, payload)
            self._drain()
        if flags & TH_FIN and self.fin_idx is None:
            self.fin_idx = idx
            self.fin_off = end

    def _insert(self, off, data):
        n = len(self.buf)
        end = off + len(data)
        if end <= n:
            self.retrans_bytes += len(data)
            if self.buf[off:end] != data:
                self.conflict_bytes += len(data)
        elif off <= n:
            keep = n - off
            if keep:
                self.retrans_bytes += keep
                if self.buf[off:n] != data[:keep]:
                    self.conflict_bytes += keep
            self.buf += data[keep:]
        else:
            self.out_of_order += 1
            self.pending.append((off, data))

    def _drain(self):
        if not self.pending:
            return
        self.pending.sort(key=lambda p: p[0])
        while self.pending and self.pending[0][0] <= len(self.buf):
            off, data = self.pending.pop(0)
            n = len(self.buf)
            end = off + len(data)
            if end <= n:
                self.retrans_bytes += len(data)
                if self.buf[off:end] != data:
                    self.conflict_bytes += len(data)
            else:
                keep = n - off
                if keep:
                    self.retrans_bytes += keep
                    if self.buf[off:n] != data[:keep]:
                        self.conflict_bytes += keep
                self.buf += data[keep:]

    def data(self):
        return bytes(self.buf)

    def gap(self):
        """流里有接不上的缺口时返回 (缺口起点, 缺口之后还有多少字节)，否则 None。"""
        if not self.pending:
            return None
        return (len(self.buf), sum(len(d) for _, d in self.pending))


class Conn:
    """抓包里的一条 TCP 连接。"""

    def __init__(self, first_idx):
        self.first_idx = first_idx
        self.client = None  # (地址, 端口)
        self.server = None
        self.c2s = Stream()
        self.s2c = Stream()
        self.saw_syn = False
        self.saw_synack = False
        self.client_after_synack = False
        self.guessed = False  # 方向是猜的（没有 SYN）
        self.truncated = 0
        self.ended = False

    def closed(self):
        """返回 (先关的一方, 关法)；抓包里没有 FIN 或 RST 时返回 (None, None)。"""
        cands = []
        for side, st in (("client", self.c2s), ("proxy", self.s2c)):
            if st.fin_idx is not None:
                cands.append((st.fin_idx, side, "fin"))
            if st.rst_idx is not None:
                cands.append((st.rst_idx, side, "rst"))
        if not cands:
            return None, None
        cands.sort()
        return cands[0][1], cands[0][2]


def rebuild(linktype, packets, server_ports=()):
    """把包归到连接里并重建两个方向的流。

    server_ports：已知的监听端口，只在连接没有 SYN、要猜哪边是服务端时用。
    返回 (连接列表, 说明列表)。
    """
    notes = []
    conns = []
    live = {}  # 规范化的四元组 -> Conn
    frag = 0
    trunc = 0
    for idx, frame, cut in packets:
        ip = strip_link(linktype, frame)
        if ip is None:
            continue
        parsed = parse_ip_tcp(ip)
        if parsed is None:
            continue
        if isinstance(parsed, str):
            frag += 1
            continue
        src, sport, dst, dport, seq, flags, payload, short = parsed
        a = (src, sport)
        b = (dst, dport)
        key = (a, b) if a <= b else (b, a)
        conn = live.get(key)
        syn_only = bool(flags & TH_SYN) and not flags & TH_ACK
        if conn is not None and syn_only:
            # 同一个四元组上又来了一个 SYN：序号与原来的不同就是新连接（端口被复用），相同是重传
            old = conn.c2s if conn.client == a else conn.s2c
            same = conn.saw_syn and conn.client == a and old.has_syn and ((seq + 1) & MASK32) == _first_seq(old)
            if not same:
                conn = None
        if conn is None:
            conn = Conn(idx)
            conn.key = key
            conns.append(conn)
            live[key] = conn
            if syn_only:
                conn.client, conn.server = a, b
            elif flags & TH_SYN:  # SYN+ACK，SYN 没抓到
                conn.client, conn.server = b, a
            else:
                conn.guessed = True
                if sport in server_ports and dport not in server_ports:
                    conn.client, conn.server = b, a
                elif dport in server_ports and sport not in server_ports:
                    conn.client, conn.server = a, b
                elif sport < dport:  # 实在没有依据：端口号小的当服务端
                    conn.client, conn.server = b, a
                else:
                    conn.client, conn.server = a, b
        if cut or short:
            conn.truncated += 1
            trunc += 1
        from_client = a == conn.client
        if flags & TH_SYN:
            if flags & TH_ACK:
                conn.saw_synack = True
            else:
                conn.saw_syn = True
        elif from_client and conn.saw_synack:
            conn.client_after_synack = True
        (conn.c2s if from_client else conn.s2c).add(seq, flags, payload, idx)
    if frag:
        notes.append("抓包里有 %d 个 IP 分片，没有重组（回环上不应出现）" % frag)
    if trunc:
        notes.append("抓包里有 %d 个包被截短（抓包时 snaplen 太小），相应连接的字节不全" % trunc)
    return conns, notes


def _first_seq(stream):
    """流的偏移 0 对应的 32 位序号。"""
    return (stream.ref_seq - stream.ref_abs) & MASK32


# ---------------------------------------------------------------------------
# 第三步：读事件
# ---------------------------------------------------------------------------


def read_events(path):
    """读事件文件，返回 (start, end, {conn: [事件…]}, 连接编号按 accept 的先后, 说明列表)。"""
    with open(path, "rb") as fh:
        raw = fh.read()
    notes = []
    events = []
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    else:
        notes.append("事件文件的最后一行没有以换行结尾（仪器没写完就停了）")
    for no, line in enumerate(lines, 1):
        try:
            ev = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise EventsError("事件文件第 %d 行不是合法的 JSON：%s" % (no, exc))
        if not isinstance(ev, dict) or "ev" not in ev:
            raise EventsError("事件文件第 %d 行不是事件对象" % no)
        events.append(ev)
    if not events or events[0]["ev"] != "start":
        raise EventsError("事件文件的第一行不是 start")
    if events[-1]["ev"] != "end":
        raise EventsError("事件文件的最后一行不是 end（仪器不是正常退出的，这次运行不能用）")
    start = events[0]
    end = events[-1]
    by_conn = {}
    order = []
    for ev in events[1:-1]:
        name = ev["ev"]
        if name == "log_error":
            raise EventsError("事件文件里有 log_error（事件编码失败），这次运行不能用")
        if name in ("start", "end"):
            raise EventsError("事件文件中间出现了 %s" % name)
        cid = ev.get("conn")
        if not isinstance(cid, int):
            raise EventsError("事件 %s 没有 conn 字段" % name)
        if name == "accept":
            if cid in by_conn:
                raise EventsError("连接 %d 有两个 accept" % cid)
            order.append(cid)
        if ev.get("late"):
            notes.append("连接 %d 的 %s 事件带 late 标记（写在 conn_end 之后），事件的先后不可靠" % (cid, name))
        by_conn.setdefault(cid, []).append(ev)
    for cid, evs in by_conn.items():
        if evs[0]["ev"] != "accept":
            raise EventsError("连接 %d 的第一个事件不是 accept" % cid)
        if sum(1 for e in evs if e["ev"] == "conn_end") != 1:
            raise EventsError("连接 %d 没有恰好一个 conn_end" % cid)
    return start, end, by_conn, order, notes


# ---------------------------------------------------------------------------
# 第四步：自己的解析器（HTTP、SOCKS5），只看字节流
# ---------------------------------------------------------------------------


def _read_head(buf, pos):
    """从 pos 起读一个 HTTP 头（起始行到空行）。

    先跳过起始行之前的空行。返回 (头的起点, 头的终点, [行…])；头没到齐时返回 (起点, None, None)。
    行以 LF 结尾，行末的 CR 去掉。
    """
    n = len(buf)
    while True:
        if buf.startswith(b"\r\n", pos):
            pos += 2
        elif buf.startswith(b"\n", pos):
            pos += 1
        else:
            break
    start = pos
    lines = []
    while True:
        j = buf.find(b"\n", pos)
        if j < 0:
            return start, None, None
        line = buf[pos:j]
        if line.endswith(b"\r"):
            line = line[:-1]
        pos = j + 1
        if not line:
            return start, pos, lines
        lines.append(line)
        if pos >= n:
            return start, None, None


def _headers(lines):
    """把头的各行拆成 [(小写的名, 值)…]；值去掉首尾的空格和制表符。续行并到上一个头里。"""
    out = []
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t") and out:
            name, val = out[-1]
            out[-1] = (name, val + b" " + line.strip(b" \t"))
            continue
        k = line.find(b":")
        if k < 0:
            out.append((line.lower(), b""))
            continue
        out.append((line[:k].lower(), line[k + 1 :].strip(b" \t")))
    return out


def _first(headers, name):
    for k, v in headers:
        if k == name:
            return v
    return None


def _has_token(headers, name, token):
    """名为 name 的头里（逗号分隔的列表）有没有 token，不分大小写。"""
    for k, v in headers:
        if k == name:
            for tok in v.split(b","):
                if tok.strip(b" \t").lower() == token:
                    return True
    return False


def _is_chunked(headers):
    last = None
    for k, v in headers:
        if k == b"transfer-encoding":
            for tok in v.split(b","):
                tok = tok.strip(b" \t").lower()
                if tok:
                    last = tok
    return last == b"chunked"


def _content_length(headers):
    """返回 Content-Length 的值；没有返回 None；写得不对返回 -1。"""
    v = _first(headers, b"content-length")
    if v is None:
        return None
    if not v.isdigit():
        return -1
    return int(v)


def _skip_chunked(buf, pos):
    """跳过一个 chunked 正文。返回 (终点, 解开后的字节)；没到齐或格式不对时终点是 None。"""
    body = bytearray()
    while True:
        j = buf.find(b"\n", pos)
        if j < 0:
            return None, bytes(body)
        line = buf[pos:j].rstrip(b"\r")
        k = line.find(b";")
        if k >= 0:
            line = line[:k]
        line = line.strip(b" \t")
        try:
            size = int(line, 16)
        except ValueError:
            return None, bytes(body)
        pos = j + 1
        if size == 0:
            break
        if pos + size > len(buf):
            body += buf[pos:]
            return None, bytes(body)
        body += buf[pos : pos + size]
        pos += size
        if buf.startswith(b"\r\n", pos):
            pos += 2
        elif buf.startswith(b"\n", pos):
            pos += 1
        else:
            return None, bytes(body)
    # 尾部：若干行，到空行为止
    while True:
        j = buf.find(b"\n", pos)
        if j < 0:
            return None, bytes(body)
        line = buf[pos:j].rstrip(b"\r")
        pos = j + 1
        if not line:
            return pos, bytes(body)


def _text(b):
    """字节转成用来和事件比的字符串；不是合法 UTF-8 时返回带转义的写法（必然与事件不等）。"""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1").encode("unicode_escape").decode("ascii")


def parse_http(c2s, s2c):
    """解析代理端口上一条 HTTP 连接的两个方向。

    返回 dict：
      requests：[{head, method, target, version, line_ok, proxy_auth, body_len, body_sha256,
                  body_state, answered}…]
      responses：[{req（第几个请求，从 1 起）, status}…]，含 1xx
      tunnel：None，或 {"req": n, "c2s_off": 隧道在 c2s 里的起点, "s2c_off": …}
      stop：停在哪里的说明
    """
    reqs = []
    resps = []
    tunnel = None
    cp = 0
    sp = 0
    stop = "c2s 读完"
    while True:
        start, end, lines = _read_head(c2s, cp)
        if start >= len(c2s):
            break
        if end is None:
            reqs.append({"head": c2s[start:], "head_complete": False, "answered": False, "body_state": "none"})
            stop = "第 %d 个请求的头没到齐" % len(reqs)
            break
        parts = lines[0].split(b" ")
        req = {
            "head": c2s[start:end],
            "head_complete": True,
            "line_ok": len(parts) == 3,
            "method": _text(parts[0]),
            "target": _text(b" ".join(parts[1:-1])) if len(parts) >= 3 else (_text(parts[1]) if len(parts) == 2 else ""),
            "version": _text(parts[-1]) if len(parts) >= 3 else "",
            "answered": False,
        }
        headers = _headers(lines)
        pa = _first(headers, b"proxy-authorization")
        req["proxy_auth"] = None if pa is None else _text(pa)
        cp = end
        body = b""
        state = "complete"
        if _is_chunked(headers):
            bend, body = _skip_chunked(c2s, cp)
            if bend is None:
                state = "incomplete"
            else:
                cp = bend
        else:
            clen = _content_length(headers)
            if clen is not None and clen < 0:
                state = "bad_framing"
            elif clen:
                body = c2s[cp : cp + clen]
                if len(body) < clen:
                    state = "incomplete"
                cp += len(body)
        req["body_state"] = state
        req["body_len"] = len(body)
        req["body_sha256"] = hashlib.sha256(body).hexdigest()
        reqs.append(req)
        seq = len(reqs)
        # 反方向：这个请求的响应（先跳过 1xx）
        final = None
        resp_close = False
        until_close = False
        resp_incomplete = False
        while True:
            rstart, rend, rlines = _read_head(s2c, sp)
            if rend is None:
                break
            sparts = rlines[0].split(b" ", 2)
            try:
                code = int(sparts[1])
            except (IndexError, ValueError):
                code = -1
            sp = rend
            resps.append({"req": seq, "status": code})
            if 100 <= code < 200 and code != 101:
                continue
            final = code
            rheaders = _headers(rlines)
            resp_close = _has_token(rheaders, b"connection", b"close")
            is_connect = req["method"] == "CONNECT"
            if code == 101 or (is_connect and 200 <= code < 300):
                break
            if req["method"] == "HEAD" or code in (204, 304):
                break
            if _is_chunked(rheaders):
                bend, _ = _skip_chunked(s2c, sp)
                if bend is None:
                    resp_incomplete = True
                    sp = len(s2c)
                else:
                    sp = bend
            else:
                clen = _content_length(rheaders)
                if clen is None or clen < 0:
                    until_close = True
                    sp = len(s2c)
                else:
                    if sp + clen > len(s2c):
                        resp_incomplete = True
                        sp = len(s2c)
                    else:
                        sp += clen
            break
        if final is None:
            stop = "第 %d 个请求在抓包里没有最终响应" % seq
            break
        req["answered"] = True
        if state != "complete":
            stop = "第 %d 个请求的正文%s" % (seq, "没到齐" if state == "incomplete" else "长度写得不对")
            break
        if req["method"] == "CONNECT" and 200 <= final < 300:
            tunnel = {"req": seq, "c2s_off": cp, "s2c_off": sp}
            stop = "第 %d 个请求建了隧道" % seq
            break
        if final == 101:
            stop = "第 %d 个请求升级了协议（101）" % seq
            break
        if until_close or resp_incomplete:
            stop = "第 %d 个响应的正文到连接关闭为止" % seq
            break
        if resp_close:
            # 响应带 Connection: close：这条连接上此后的字节不会再被当成请求处理
            stop = "第 %d 个响应带 Connection: close" % seq
            break
    return {"requests": reqs, "responses": resps, "tunnel": tunnel, "stop": stop}


def _socks_host(atyp, addr):
    if atyp == 1:
        return ".".join(str(x) for x in addr)
    if atyp == 4:
        return addr  # 16 个字节，比较时按地址比
    try:
        return addr.decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse_socks5(c2s, s2c):
    """解析代理端口上一条 SOCKS5 连接（RFC 1928、1929）。

    返回 dict，键 greeting、method、auth、request、reply 各自是 dict 或 None（字节没到齐），
    外加 tunnel（同 parse_http）。
    """
    out = {"greeting": None, "method": None, "auth": None, "request": None, "reply": None, "tunnel": None}
    cp = 0
    sp = 0
    if len(c2s) < 2 or len(c2s) < 2 + c2s[1]:
        return out
    n = c2s[1]
    out["greeting"] = {"version": c2s[0], "methods": list(c2s[2 : 2 + n]), "raw_hex": c2s[: 2 + n].hex()}
    cp = 2 + n
    if len(s2c) < 2:
        return out
    selected = s2c[1]
    out["method"] = {"version": s2c[0], "selected": selected}
    sp = 2
    if selected == 0xFF:
        return out
    if selected == 2:
        if len(c2s) < cp + 2:
            return out
        ver = c2s[cp]
        ulen = c2s[cp + 1]
        if len(c2s) < cp + 2 + ulen + 1:
            return out
        user = c2s[cp + 2 : cp + 2 + ulen]
        plen = c2s[cp + 2 + ulen]
        if len(c2s) < cp + 3 + ulen + plen:
            return out
        pw = c2s[cp + 3 + ulen : cp + 3 + ulen + plen]
        auth = {"version": ver, "ulen": ulen, "plen": plen, "user_hex": user.hex(), "pass_hex": pw.hex(), "status": None}
        out["auth"] = auth
        cp += 3 + ulen + plen
        if len(s2c) < sp + 2:
            return out
        auth["status"] = s2c[sp + 1]
        sp += 2
        if auth["status"] != 0:
            return out
    if len(c2s) < cp + 4:
        return out
    ver, cmd, rsv, atyp = c2s[cp], c2s[cp + 1], c2s[cp + 2], c2s[cp + 3]
    req = {"version": ver, "cmd": cmd, "rsv": rsv, "atyp": atyp, "host": None, "port": None}
    if atyp == 1:
        alen, aoff = 4, cp + 4
    elif atyp == 4:
        alen, aoff = 16, cp + 4
    elif atyp == 3:
        if len(c2s) < cp + 5:
            return out
        alen, aoff = c2s[cp + 4], cp + 5
    else:
        alen = None
    if alen is None:
        req["raw_hex"] = c2s[cp : cp + 4].hex()
        cp += 4
    else:
        if len(c2s) < aoff + alen + 2:
            return out
        req["host"] = _socks_host(atyp, c2s[aoff : aoff + alen])
        req["port"] = struct.unpack(">H", c2s[aoff + alen : aoff + alen + 2])[0]
        req["raw_hex"] = c2s[cp : aoff + alen + 2].hex()
        cp = aoff + alen + 2
    out["request"] = req
    if len(s2c) < sp + 4:
        return out
    ratyp = s2c[sp + 3]
    if ratyp == 1:
        rlen = 10
    elif ratyp == 4:
        rlen = 22
    elif ratyp == 3:
        if len(s2c) < sp + 5:
            return out
        rlen = 7 + s2c[sp + 4]
    else:
        return out
    if len(s2c) < sp + rlen:
        return out
    out["reply"] = {"version": s2c[sp], "rep": s2c[sp + 1], "raw_hex": s2c[sp : sp + rlen].hex()}
    sp += rlen
    if out["reply"]["rep"] == 0 and alen is not None:
        out["tunnel"] = {"req": None, "c2s_off": cp, "s2c_off": sp}
    return out


# ---------------------------------------------------------------------------
# 第五步：比较
# ---------------------------------------------------------------------------


def compare_direction(data, rec_len, rec_sha, allow_unsent=False):
    """比一个方向的字节。返回结果 dict（含 verdict）。

    allow_unsent：事件比抓包长时是否可以记 prefix（见函数末尾）。
    """
    plen = len(data)
    res = {
        "pcap_len": plen,
        "pcap_sha256": hashlib.sha256(data).hexdigest(),
        "rec_len": rec_len,
        "rec_sha256": rec_sha,
    }
    if not isinstance(rec_len, int) or not isinstance(rec_sha, str):
        res["verdict"] = "mismatch"
        res["detail"] = "事件里没有这个方向的字节数或哈希"
        return res
    if plen == rec_len:
        res["verdict"] = "exact" if res["pcap_sha256"] == rec_sha else "mismatch"
        if res["verdict"] == "mismatch":
            res["detail"] = "长度相同，哈希不同"
        return res
    if plen > rec_len:
        # 抓包比事件长：取抓包的前 rec_len 个字节算哈希，与事件的哈希比
        if hashlib.sha256(data[:rec_len]).hexdigest() == rec_sha:
            res["verdict"] = "prefix"
            res["longer"] = "pcap"
            res["diff_bytes"] = plen - rec_len
            res["verified"] = True
        else:
            res["verdict"] = "mismatch"
            res["detail"] = "抓包多 %d 个字节，但事件记的不是抓包的前缀" % (plen - rec_len)
        return res
    # 事件比抓包长：手里只有事件的哈希，没有那些字节，前缀关系验证不了。
    # 只有一种情况说得通：仪器写进套接字的字节还没发出去连接就被复位了（allow_unsent）。
    # 仪器读到的字节不可能比线上的多，所以客户端方向一律算 mismatch。
    res["longer"] = "events"
    res["diff_bytes"] = rec_len - plen
    res["verified"] = False
    if allow_unsent:
        res["verdict"] = "prefix"
    else:
        res["verdict"] = "mismatch"
        res["detail"] = "事件比抓包多 %d 个字节，而抓包里没有能解释这一点的复位" % (rec_len - plen)
    return res


class Fields:
    """字段比较的记账。"""

    def __init__(self):
        self.compared = 0
        self.mismatched = []

    def eq(self, conn, field, pcap, events):
        self.compared += 1
        if pcap != events:
            self.mismatched.append({"conn": conn, "field": field, "pcap": pcap, "events": events})

    def bad(self, conn, field, pcap, events):
        self.compared += 1
        self.mismatched.append({"conn": conn, "field": field, "pcap": pcap, "events": events})


def _evs(evs, name):
    return [e for e in evs if e["ev"] == name]


def compare_http(cid, parsed, evs, c2s_res, fields, problems):
    reqs = parsed["requests"]
    ereqs = _evs(evs, "http_request")
    cend = _evs(evs, "conn_end")[0]
    n_common = min(len(reqs), len(ereqs))
    for i in range(n_common):
        r, e = reqs[i], ereqs[i]
        tag = "http_request[%d]" % (i + 1)
        fields.eq(cid, tag + ".seq", i + 1, e.get("seq"))
        try:
            ehead = base64.b64decode(e.get("head_b64") or "", validate=True)
        except ValueError:
            ehead = None
        err = e.get("error")
        head_err = isinstance(err, str) and err.split(":")[0].split(" ")[0] in ("incomplete_head", "head_too_large", "bad_head")
        if head_err or not r["head_complete"]:
            # 头本身有问题的请求：各段怎么拆是仪器自己的规矩，这里只比头的原始字节。
            # 仪器记下的应是抓包里这个位置上字节的前缀（或者反过来，仪器没读到的那部分还在路上）。
            ok = ehead is not None and (r["head"].startswith(ehead) or ehead.startswith(r["head"]))
            fields.eq(cid, tag + ".head_b64(前缀)", True, ok)
            if not r["head_complete"]:
                fields.eq(cid, tag + ".error(头没到齐)", True, isinstance(err, str) and err.startswith("incomplete_head"))
            continue
        fields.eq(cid, tag + ".head_b64", base64.b64encode(r["head"]).decode("ascii"), e.get("head_b64"))
        fields.eq(cid, tag + ".method", r["method"], e.get("method"))
        fields.eq(cid, tag + ".target", r["target"], e.get("target"))
        fields.eq(cid, tag + ".version", r["version"], e.get("version"))
        auth = e.get("auth") or {}
        fields.eq(cid, tag + ".auth.present", r["proxy_auth"] is not None, auth.get("present"))
        fields.eq(cid, tag + ".auth.raw", r["proxy_auth"], auth.get("raw"))
        if err is None and r["body_state"] == "complete":
            fields.eq(cid, tag + ".body_len", r["body_len"], e.get("body_len"))
            fields.eq(cid, tag + ".body_sha256", r["body_sha256"], e.get("body_sha256"))
        elif err is None:
            fields.bad(cid, tag + ".error", "正文" + r["body_state"], None)
    if len(ereqs) > len(reqs):
        fields.bad(cid, "http_request.count", len(reqs), len(ereqs))
        problems.append("连接 %d：事件里有 %d 个 http_request，抓包里只解析出 %d 个（%s）" % (cid, len(ereqs), len(reqs), parsed["stop"]))
    elif len(reqs) > len(ereqs):
        # 抓包里多出来的请求：只有仪器确实没读到（它先关了，或字节只到了一部分）才说得通
        extra = reqs[len(ereqs) :]
        unread = all(not r["answered"] for r in extra) and (cend.get("by") == "proxy" or c2s_res.get("longer") == "pcap")
        if unread:
            fields.compared += 1
            problems.append(
                "连接 %d：抓包里比事件多 %d 个请求，都没有得到响应，仪器在读到它们之前就关了连接（不算不一致）" % (cid, len(extra))
            )
        else:
            fields.bad(cid, "http_request.count", len(reqs), len(ereqs))
            problems.append("连接 %d：抓包里解析出 %d 个请求，事件里只有 %d 个 http_request" % (cid, len(reqs), len(ereqs)))
    else:
        fields.eq(cid, "http_request.count", len(reqs), len(ereqs))
    # 响应：状态码的序列（含 1xx）。写的时候出了错的响应可能没上线，不比。
    eresp = [(e.get("seq"), e.get("status")) for e in _evs(evs, "http_response") if e.get("error") is None]
    presp = [(r["req"], r["status"]) for r in parsed["responses"]]
    fields.eq(cid, "http_response.(seq,status)", [list(x) for x in presp], [list(x) for x in eresp])
    # 隧道
    topen = [e for e in _evs(evs, "tunnel_open")]
    if parsed["tunnel"] is not None:
        if len(topen) == 1:
            fields.eq(cid, "tunnel_open.via", "connect", topen[0].get("via"))
            fields.eq(cid, "tunnel_open.req_seq", parsed["tunnel"]["req"], topen[0].get("req_seq"))
        else:
            fields.bad(cid, "tunnel_open.count", 1, len(topen))
    else:
        fields.eq(cid, "tunnel_open.count", 0, len(topen))


def _same_host(atyp, pcap_host, ev_host):
    if atyp == 4 and isinstance(pcap_host, bytes):
        try:
            return ipaddress.IPv6Address(pcap_host) == ipaddress.IPv6Address(ev_host)
        except (ValueError, TypeError):
            return False
    return pcap_host == ev_host


def compare_socks(cid, parsed, evs, fields, problems):
    def one(name):
        lst = _evs(evs, name)
        if len(lst) > 1:
            fields.bad(cid, name + ".count", None, len(lst))
        return lst[0] if lst else None

    def presence(name, p, e):
        if (p is None) != (e is None):
            fields.bad(cid, name + "(有没有)", p is not None, e is not None)
            problems.append("连接 %d：%s 在%s里有、在%s里没有" % (cid, name, "抓包" if p else "事件", "事件" if p else "抓包"))
            return False
        fields.compared += 1
        return p is not None

    p, e = parsed["greeting"], one("socks5_greeting")
    if presence("socks5_greeting", p, e):
        for k in ("version", "methods", "raw_hex"):
            fields.eq(cid, "socks5_greeting." + k, p[k], e.get(k))
    p, e = parsed["method"], one("socks5_method")
    if presence("socks5_method", p, e):
        fields.eq(cid, "socks5_method.selected", p["selected"], e.get("selected"))
    p, e = parsed["auth"], one("socks5_auth")
    if p is not None and p["status"] is None and e is None:
        p = None  # 子协商发了，服务端没回状态：事件是回了状态以后才写的
    if presence("socks5_auth", p, e):
        for k in ("version", "ulen", "plen", "user_hex", "pass_hex", "status"):
            fields.eq(cid, "socks5_auth." + k, p[k], e.get(k))
    p, e = parsed["request"], one("socks5_request")
    if presence("socks5_request", p, e):
        for k in ("version", "cmd", "rsv", "atyp", "port", "raw_hex"):
            fields.eq(cid, "socks5_request." + k, p[k], e.get(k))
        fields.compared += 1
        if not _same_host(p["atyp"], p["host"], e.get("host")):
            shown = p["host"]
            if isinstance(shown, bytes):
                shown = str(ipaddress.IPv6Address(shown))
            fields.mismatched.append({"conn": cid, "field": "socks5_request.host", "pcap": shown, "events": e.get("host")})
    p, e = parsed["reply"], one("socks5_reply")
    if presence("socks5_reply", p, e):
        for k in ("rep", "raw_hex"):
            fields.eq(cid, "socks5_reply." + k, p[k], e.get(k))
    topen = _evs(evs, "tunnel_open")
    if parsed["tunnel"] is not None:
        if len(topen) == 1:
            fields.eq(cid, "tunnel_open.via", "socks5", topen[0].get("via"))
        else:
            fields.bad(cid, "tunnel_open.count", 1, len(topen))
    else:
        fields.eq(cid, "tunnel_open.count", 0, len(topen))


def compare_tunnel(cid, tunnel, c2s, s2c, evs, c2s_res, s2c_res, fields, problems):
    tc = c2s[tunnel["c2s_off"] :]
    ts = s2c[tunnel["s2c_off"] :]
    tfb = _evs(evs, "tunnel_first_bytes")
    tclose = _evs(evs, "tunnel_close")
    if len(tfb) > 1:
        fields.bad(cid, "tunnel_first_bytes.count", None, len(tfb))
    if tfb:
        e = tfb[0]
        hx = e.get("hex") or ""
        want = hx[:10]
        got = tc[:5].hex()[: len(want)] if len(want) < 10 else tc[:5].hex()
        fields.eq(cid, "tunnel_first_bytes.hex[:5]", got, want)
        fields.eq(cid, "tunnel_first_bytes.hex(前缀)", True, tc[: len(hx) // 2].hex() == hx)
        tls = e.get("tls")
        if isinstance(tls, dict):
            if len(tc) >= 5:
                fields.eq(cid, "tunnel_first_bytes.tls.content_type", tc[0], 0x16)
                fields.eq(cid, "tunnel_first_bytes.tls.record_version", struct.unpack(">H", tc[1:3])[0], tls.get("record_version"))
                fields.eq(cid, "tunnel_first_bytes.tls.record_len", struct.unpack(">H", tc[3:5])[0], tls.get("record_len"))
            else:
                fields.bad(cid, "tunnel_first_bytes.tls.record_len", None, tls.get("record_len"))
    elif tc:
        # 抓包里隧道有字节而事件里没有首包：只有仪器确实没读到这些字节才说得通
        rec_len = c2s_res.get("rec_len")
        if isinstance(rec_len, int) and rec_len <= tunnel["c2s_off"]:
            fields.compared += 1
            problems.append("连接 %d：客户端在隧道里发了 %d 个字节，仪器没读到就关了（不算不一致）" % (cid, len(tc)))
        else:
            fields.bad(cid, "tunnel_first_bytes(有没有)", True, False)
    else:
        fields.compared += 1
    if len(tclose) == 1:
        # 隧道的边界：仪器说隧道里各有多少字节，应等于抓包里握手之后剩下的字节数
        if c2s_res.get("verdict") == "exact":
            fields.eq(cid, "tunnel_close.bytes_c2s", len(tc), tclose[0].get("bytes_c2s"))
        if s2c_res.get("verdict") == "exact":
            fields.eq(cid, "tunnel_close.bytes_s2c", len(ts), tclose[0].get("bytes_s2c"))
    else:
        fields.bad(cid, "tunnel_close.count", 1, len(tclose))


def compare_fields(cid, listener, c2s, s2c, evs, c2s_res, s2c_res, fields, problems):
    """对一条连接做字段比较，返回连接的种类。"""
    fb = _evs(evs, "first_bytes")
    if fb:
        hx = fb[0].get("hex") or ""
        fields.eq(cid, "first_bytes.hex(前缀)", True, len(hx) > 0 and c2s[: len(hx) // 2].hex() == hx)
    elif c2s and c2s_res.get("rec_len"):
        fields.bad(cid, "first_bytes(有没有)", True, False)
    if listener != "proxy":
        return "origin"
    if not c2s:
        kind = "empty"
    elif c2s[0] == 0x05:
        kind = "socks5"
    elif c2s[0] in (0x04, 0x16):
        kind = "refused"
    else:
        kind = "http"
    if kind == "http":
        parsed = parse_http(c2s, s2c)
        compare_http(cid, parsed, evs, c2s_res, fields, problems)
    else:
        n = len(_evs(evs, "http_request"))
        if n:
            fields.bad(cid, "http_request.count", 0, n)
    if kind == "socks5":
        parsed = parse_socks5(c2s, s2c)
        compare_socks(cid, parsed, evs, fields, problems)
    else:
        for name in ("socks5_greeting", "socks5_method", "socks5_auth", "socks5_request", "socks5_reply"):
            n = len(_evs(evs, name))
            if n:
                fields.bad(cid, name + ".count", 0, n)
    if kind in ("http", "socks5") and parsed["tunnel"] is not None:
        compare_tunnel(cid, parsed["tunnel"], c2s, s2c, evs, c2s_res, s2c_res, fields, problems)
    elif kind not in ("http", "socks5"):
        n = len(_evs(evs, "tunnel_open"))
        if n:
            fields.bad(cid, "tunnel_open.count", 0, n)
    return kind


# ---------------------------------------------------------------------------
# 总入口
# ---------------------------------------------------------------------------


def _result(status, problems, conns=None, fields=None):
    return {
        "status": status,
        "conns": conns or [],
        "fields": fields or {"compared": 0, "mismatched": []},
        "problems": problems,
    }


def check(pcap_path, events_path):
    """核对一次运行。返回值的结构见文件开头和 README。不抛异常：出错时 status 是 error。"""
    try:
        return _check(pcap_path, events_path)
    except (PcapError, EventsError) as exc:
        return _result("error", [str(exc)])
    except OSError as exc:
        return _result("error", ["读不了文件：%s" % exc])
    except Exception as exc:  # noqa: BLE001  核对工具自己的毛病也不能让调用方崩掉
        return _result("error", ["pcap_check 内部出错：%s: %s" % (type(exc).__name__, exc)])


def _check(pcap_path, events_path):
    problems = []
    start, end, by_conn, order, ev_notes = read_events(events_path)
    problems.extend(ev_notes)
    ports = {}
    for name in ("proxy", "origin_http", "origin_https"):
        port = start.get(name + "_port")
        if not isinstance(port, int):
            raise EventsError("start 事件里没有 %s_port" % name)
        ports[port] = name
    if isinstance(end.get("conns"), int) and end["conns"] != len(order):
        problems.append("end 事件说有 %d 条连接，文件里有 %d 个 accept" % (end["conns"], len(order)))

    linktype, packets, pcap_notes = read_pcap(pcap_path)
    truncated_file = bool(pcap_notes)
    problems.extend(pcap_notes)
    pconns, notes = rebuild(linktype, packets, set(ports))
    problems.extend(notes)

    # 按（监听端口，对端端口）对上；同一个键有多条时按先后配对
    pcap_by_key = {}
    other_ports = 0
    for pc in pconns:
        listener = ports.get(pc.server[1])
        if listener is None:
            other_ports += 1
            continue
        pcap_by_key.setdefault((listener, pc.client[1]), []).append(pc)
    if other_ports:
        problems.append("抓包里有 %d 条连接不在仪器的三个监听端口上，没有核对" % other_ports)

    fields = Fields()
    out = []
    bad = truncated_file
    any_prefix = False
    for cid in order:
        evs = by_conn[cid]
        acc = evs[0]
        cend = _evs(evs, "conn_end")[0]
        listener = acc.get("listener")
        peer = acc.get("peer_port")
        entry = {"conn": cid, "listener": listener, "peer_port": peer}
        cands = pcap_by_key.get((listener, peer))
        if not cands:
            bad = True
            problems.append("连接 %d（%s，对端端口 %s）：事件里有，抓包里没有" % (cid, listener, peer))
            for d, n, h in (("c2s", "bytes_in", "sha256_in"), ("s2c", "bytes_out", "sha256_out")):
                entry[d] = {"pcap_len": None, "pcap_sha256": None, "rec_len": cend.get(n), "rec_sha256": cend.get(h), "verdict": "mismatch"}
            entry.update({"complete": False, "closed_by": None, "how": None, "kind": None})
            out.append(entry)
            continue
        pc = cands.pop(0)
        c2s = pc.c2s.data()
        s2c = pc.s2c.data()
        complete = True
        if not pc.saw_syn or not pc.c2s.has_syn:
            complete = False
            problems.append(
                "连接 %d：抓包里没有客户端的 SYN（抓包从连接中途开始，或丢了包），客户端方向的起点是猜的；只有哈希对得上才可信" % cid
            )
        if not pc.s2c.has_syn and (pc.s2c.packets or cend.get("bytes_out")):
            complete = False
            problems.append("连接 %d：抓包里没有服务端的 SYN+ACK，服务端方向的起点是猜的；只有哈希对得上才可信" % cid)
        res = {}
        for d, st, data, n, h in (("c2s", pc.c2s, c2s, "bytes_in", "sha256_in"), ("s2c", pc.s2c, s2c, "bytes_out", "sha256_out")):
            # 仪器写了而没上线的字节：只在服务端方向、流的起点可靠、并且抓包里这条连接有 RST 时才说得通
            unsent = d == "s2c" and st.has_syn and (pc.c2s.rst_idx is not None or pc.s2c.rst_idx is not None)
            r = compare_direction(data, cend.get(n), cend.get(h), unsent)
            gap = st.gap()
            if gap is not None:
                complete = False
                r["verdict"] = "mismatch"
                r["detail"] = "抓包在偏移 %d 处有缺口（之后还有 %d 个字节接不上）" % gap
                problems.append("连接 %d 的 %s 方向：%s，抓包丢了包" % (cid, d, r["detail"]))
            if st.conflict_bytes:
                problems.append("连接 %d 的 %s 方向：有 %d 个重传字节与先到的内容不同（按先到的算）" % (cid, d, st.conflict_bytes))
            if pc.truncated:
                complete = False
            if r["verdict"] == "mismatch":
                bad = True
                problems.append(
                    "连接 %d 的 %s 方向字节对不上：抓包 %d 字节，事件 %s 字节。%s" % (cid, d, r["pcap_len"], r["rec_len"], r.get("detail", ""))
                )
            elif r["verdict"] == "prefix":
                any_prefix = True
                if r["longer"] == "pcap":
                    problems.append("连接 %d 的 %s 方向：事件记的是抓包的前缀，抓包多 %d 个字节（仪器没读到或没记）" % (cid, d, r["diff_bytes"]))
                else:
                    problems.append(
                        "连接 %d 的 %s 方向：事件比抓包多 %d 个字节，连接是被复位的（写了没发出去）；"
                        "手里只有事件的哈希，前缀关系无法验证（未验证）" % (cid, d, r["diff_bytes"])
                    )
            res[d] = r
        entry["c2s"] = res["c2s"]
        entry["s2c"] = res["s2c"]
        entry["complete"] = complete
        who, how = pc.closed()
        entry["closed_by"] = who
        entry["how"] = how
        if who is None:
            problems.append("连接 %d：抓包里没有 FIN 或 RST（抓包在连接关闭之前就停了）" % cid)
        elif (who, how) != (cend.get("by"), cend.get("close")):
            problems.append(
                "连接 %d：抓包里先关的是 %s（%s），conn_end 记的是 %s（%s）；可能是时序上的竞争，不影响结论"
                % (cid, who, how, cend.get("by"), cend.get("close"))
            )
        before = len(fields.mismatched)
        entry["kind"] = compare_fields(cid, listener, c2s, s2c, evs, res["c2s"], res["s2c"], fields, problems)
        for m in fields.mismatched[before:]:
            problems.append("连接 %d 的字段 %s 不一致：抓包 %r，事件 %r" % (cid, m["field"], m["pcap"], m["events"]))
        out.append(entry)

    # 抓包里有、事件里没有的连接
    for (listener, peer), rest in sorted(pcap_by_key.items()):
        for pc in rest:
            established = pc.saw_synack and pc.client_after_synack
            has_data = bool(pc.c2s.buf or pc.s2c.buf or pc.c2s.pending or pc.s2c.pending)
            if not established and not has_data and pc.saw_syn:
                problems.append("抓包里 %s 上对端端口 %d 的连接没有完成三次握手，仪器不可能接受它，忽略" % (listener, peer))
                continue
            bad = True
            problems.append("抓包里 %s 上对端端口 %d 的连接在事件里没有对应的 accept" % (listener, peer))
            who, how = pc.closed()
            entry = {"conn": None, "listener": listener, "peer_port": peer}
            for d, st in (("c2s", pc.c2s), ("s2c", pc.s2c)):
                data = st.data()
                entry[d] = {
                    "pcap_len": len(data),
                    "pcap_sha256": hashlib.sha256(data).hexdigest(),
                    "rec_len": None,
                    "rec_sha256": None,
                    "verdict": "mismatch",
                }
            entry.update({"complete": pc.saw_syn, "closed_by": who, "how": how, "kind": None})
            out.append(entry)

    if fields.mismatched:
        bad = True
    if bad:
        status = "mismatch"
    elif any_prefix:
        status = "prefix"
    else:
        status = "ok"
    result = _result(status, problems, out, {"compared": fields.compared, "mismatched": fields.mismatched})
    result["pcap"] = {"linktype": SUPPORTED_DLT[linktype], "packets": len(packets), "tcp_conns": len(pconns)}
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="抓包核对：把抓包里重建的字节流与 obsproxy 的事件比对")
    ap.add_argument("--pcap", required=True, help="tcpdump -w 写出的 pcap 文件")
    ap.add_argument("--events", required=True, help="obsproxy 的事件文件（JSONL）")
    ap.add_argument("--out", help="把结果写成 JSON 文件；不给就打印到标准输出")
    args = ap.parse_args(argv)
    res = check(args.pcap, args.events)
    text = json.dumps(res, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(
            "抓包核对：%s；%d 条连接，比了 %d 个字段，%d 个不一致，%d 条说明"
            % (res["status"], len(res["conns"]), res["fields"]["compared"], len(res["fields"]["mismatched"]), len(res["problems"])),
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    if res["status"] in ("ok", "prefix"):
        return 0
    return 1 if res["status"] == "mismatch" else 2


if __name__ == "__main__":
    sys.exit(main())
