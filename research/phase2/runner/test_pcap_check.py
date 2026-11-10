#!/usr/bin/env python3
"""pcap_check 的测试。

两部分：

- 手工拼出 pcap 字节（乱序、重传、重叠、序号回绕、大段、缺 SYN、缺口、各种链路类型），验证重建和比对；
- 真实数据：启动 obsproxy，tcpdump 抓回环，curl 在干净环境里走几种配置。没有 tcpdump、curl、
  不是 root、或者拿不到 obsproxy 二进制时跳过并说明原因。

运行：
    cd research/phase2/runner && python3 -m unittest -v test_pcap_check

obsproxy 的二进制：环境变量 PCAP_CHECK_OBSPROXY 指到一个现成的；不给就用 go 从 ../harness 现编一个放进临时目录。
所有连接都在 127.0.0.1 上。信任测试 CA 的办法是 curl --cacert，不关闭证书校验。
"""

import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pcap_check  # noqa: E402

HARNESS = os.path.join(HERE, "..", "harness")

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# ---------------------------------------------------------------------------
# 拼包用的小工具
# ---------------------------------------------------------------------------


def tcp_seg(sport, dport, seq, ack, flags, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0) + payload


def ip4(seg, total=None):
    total = 20 + len(seg) if total is None else total
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1])) + seg


def ip6(seg):
    lo = b"\x00" * 15 + b"\x01"
    return struct.pack(">IHBB", 0x60000000, len(seg), 6, 64) + lo + lo + seg


def link(linktype, ip, v6):
    etype = 0x86DD if v6 else 0x0800
    if linktype == pcap_check.DLT_EN10MB:
        return b"\x00" * 12 + struct.pack(">H", etype) + ip
    if linktype == pcap_check.DLT_LINUX_SLL:
        return struct.pack(">HHH8sH", 0, 772, 6, b"\x00" * 8, etype) + ip
    if linktype == pcap_check.DLT_LINUX_SLL2:
        return struct.pack(">HHIHBB8s", etype, 0, 1, 772, 0, 6, b"\x00" * 8) + ip
    if linktype == pcap_check.DLT_NULL:
        return struct.pack("<I", 10 if v6 else 2) + ip
    if linktype == pcap_check.DLT_LOOP:
        return struct.pack(">I", 24 if v6 else 2) + ip
    return ip  # RAW


def pcap_bytes(linktype, frames, endian="<", nsec=False):
    magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)
    for i, fr in enumerate(frames):
        out += struct.pack(endian + "IIII", 1700000000, i, len(fr), len(fr)) + fr
    return out


class Convo:
    """一条手工拼的连接：客户端端口 cport，服务端端口 sport。各方法返回一个 TCP 段。"""

    def __init__(self, cport, sport, isn_c=1000, isn_s=5000):
        self.cport, self.sport, self.isn_c, self.isn_s = cport, sport, isn_c, isn_s

    def syn(self):
        return tcp_seg(self.cport, self.sport, self.isn_c, 0, SYN)

    def synack(self):
        return tcp_seg(self.sport, self.cport, self.isn_s, self.isn_c + 1, SYN | ACK)

    def ack(self):
        return tcp_seg(self.cport, self.sport, self.isn_c + 1, self.isn_s + 1, ACK)

    def c(self, off, data, flags=ACK | PSH):
        return tcp_seg(self.cport, self.sport, self.isn_c + 1 + off, self.isn_s + 1, flags, data)

    def s(self, off, data, flags=ACK | PSH):
        return tcp_seg(self.sport, self.cport, self.isn_s + 1 + off, self.isn_c + 1, flags, data)

    def hs(self):
        return [self.syn(), self.synack(), self.ack()]


def sha(b):
    return hashlib.sha256(b).hexdigest()


PORTS = {"proxy_port": 40001, "origin_http_port": 40002, "origin_https_port": 40003}


def make_events(conns, ports=PORTS):
    """拼一个事件文件的文本。conns: [{listener, peer_port, cin, cout, by, close, extra:[事件…]}…]"""
    lines = [dict({"t": 0.1, "ev": "start", "events_version": 1}, **ports)]
    for i, c in enumerate(conns, 1):
        lines.append({"t": 1.0, "ev": "accept", "conn": i, "listener": c["listener"], "peer_port": c["peer_port"]})
        if c["cin"]:
            lines.append(
                {"t": 1.1, "ev": "first_bytes", "conn": i, "listener": c["listener"], "n_first_read": len(c["cin"]), "hex": c["cin"][:16].hex()}
            )
        for e in c.get("extra", []):
            lines.append(dict(e, conn=i))
        lines.append(
            {
                "t": 2.0,
                "ev": "conn_end",
                "conn": i,
                "listener": c["listener"],
                "by": c.get("by", "client"),
                "close": c.get("close", "fin"),
                "reason": "client_eof",
                "bytes_in": c.get("rec_in_len", len(c["cin"])),
                "bytes_out": c.get("rec_out_len", len(c["cout"])),
                "bytes_drained": 0,
                "sha256_in": c.get("rec_in_sha", sha(c["cin"])),
                "sha256_out": c.get("rec_out_sha", sha(c["cout"])),
                "dur_ms": 1.0,
            }
        )
    lines.append(dict({"t": 3.0, "ev": "end", "conns": len(conns)}, **ports))
    return "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in lines)


def http_request_event(head, seq=1, body=b"", auth_raw=None, error=None):
    line = head.split(b"\r\n")[0].decode()
    m, t, v = line.split(" ")
    return {
        "t": 1.2,
        "ev": "http_request",
        "seq": seq,
        "method": m,
        "target": t,
        "version": v,
        "head_b64": base64.b64encode(head).decode(),
        "body_len": len(body),
        "body_sha256": sha(body),
        "auth": {"present": auth_raw is not None, "raw": auth_raw},
        "error": error,
    }


class SynthBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pcapcheck-synth-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, linktype, segs, events_text, v6=False, endian="<", nsec=False):
        frames = [link(linktype, ip6(s) if v6 else ip4(s), v6) for s in segs]
        p = os.path.join(self.dir, "x.pcap")
        e = os.path.join(self.dir, "e.jsonl")
        with open(p, "wb") as fh:
            fh.write(pcap_bytes(linktype, frames, endian, nsec))
        with open(e, "w", encoding="utf-8") as fh:
            fh.write(events_text)
        return p, e

    def run_check(self, *a, **kw):
        p, e = self.write(*a, **kw)
        return pcap_check.check(p, e)


# ---------------------------------------------------------------------------
# 手工拼的抓包
# ---------------------------------------------------------------------------


class TestRebuild(SynthBase):
    REQ = b"GET /echo?k=T.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n"
    RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    def simple(self, cv):
        n, m = len(self.REQ), len(self.RESP)
        return cv.hs() + [cv.c(0, self.REQ), cv.s(0, self.RESP), cv.c(n, b"", FIN | ACK), cv.s(m, b"", FIN | ACK)]

    def events_origin(self, **over):
        c = {"listener": "origin_http", "peer_port": 50001, "cin": self.REQ, "cout": self.RESP}
        c.update(over)
        return make_events([c])

    def test_all_linktypes_and_headers(self):
        """各种链路类型、IPv4 和 IPv6、两种字节序、微秒和纳秒魔数。"""
        cv = Convo(50001, 40002)
        lts = [
            pcap_check.DLT_EN10MB,
            pcap_check.DLT_LINUX_SLL,
            pcap_check.DLT_LINUX_SLL2,
            pcap_check.DLT_NULL,
            pcap_check.DLT_LOOP,
            pcap_check.DLT_RAW,
        ]
        for lt in lts:
            for v6 in (False, True):
                for endian, nsec in (("<", False), (">", True), (">", False), ("<", True)):
                    with self.subTest(linktype=lt, v6=v6, endian=endian, nsec=nsec):
                        res = self.run_check(lt, self.simple(cv), self.events_origin(), v6=v6, endian=endian, nsec=nsec)
                        self.assertEqual(res["status"], "ok", res["problems"])
                        c = res["conns"][0]
                        self.assertEqual((c["c2s"]["verdict"], c["s2c"]["verdict"]), ("exact", "exact"))
                        self.assertEqual(c["c2s"]["pcap_len"], len(self.REQ))
                        self.assertEqual(c["s2c"]["pcap_sha256"], sha(self.RESP))
                        self.assertEqual((c["closed_by"], c["how"], c["complete"]), ("client", "fin", True))

    def test_vlan_and_ethernet_padding(self):
        """以太网帧带 VLAN 标签、帧尾有填充：以 IP 头里的总长度为准。"""
        cv = Convo(50001, 40002)
        frames = []
        for s in self.simple(cv):
            frames.append(b"\x00" * 12 + struct.pack(">HHH", 0x8100, 7, 0x0800) + ip4(s) + b"\x00" * 6)
        p = os.path.join(self.dir, "v.pcap")
        e = os.path.join(self.dir, "v.jsonl")
        with open(p, "wb") as fh:
            fh.write(pcap_bytes(pcap_check.DLT_EN10MB, frames))
        with open(e, "w") as fh:
            fh.write(self.events_origin())
        res = pcap_check.check(p, e)
        self.assertEqual(res["status"], "ok", res["problems"])

    def test_out_of_order_retransmit_overlap(self):
        """乱序、整段重传、部分重叠、SYN 重传：重建出的字节不变。"""
        cv = Convo(50001, 40002)
        r = self.REQ
        segs = [
            cv.syn(),
            cv.syn(),  # SYN 重传
            cv.synack(),
            cv.ack(),
            cv.c(20, r[20:35]),  # 先到后面的
            cv.c(0, r[:10]),
            cv.c(0, r[:10]),  # 重传
            cv.c(5, r[5:25]),  # 与前后都重叠
            cv.c(30, r[30:]),  # 与已有的重叠并延伸到末尾
            cv.s(0, self.RESP),
            cv.c(len(r), b"", FIN | ACK),
            cv.c(len(r), b"", FIN | ACK),  # FIN 重传
            cv.s(len(self.RESP), b"", FIN | ACK),
        ]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["status"], "ok", res["problems"])
        self.assertEqual(res["conns"][0]["c2s"]["pcap_sha256"], sha(r))

    def test_conflicting_retransmit_is_reported(self):
        """重传的内容与先到的不同：按先到的算，并在 problems 里说明。"""
        cv = Convo(50001, 40002)
        r = self.REQ
        segs = cv.hs() + [cv.c(0, r), cv.c(0, b"X" * 10), cv.s(0, self.RESP)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["conns"][0]["c2s"]["verdict"], "exact")
        self.assertTrue(any("重传字节与先到的内容不同" in p for p in res["problems"]), res["problems"])

    def test_sequence_wraparound(self):
        """初始序号贴着 2^32：数据跨过回绕点。"""
        body = bytes(range(256)) * 20
        cv = Convo(50001, 40002, isn_c=0xFFFFFF00, isn_s=0xFFFFFFFF)
        segs = cv.hs()
        for off in (3000, 0, 1000, 2000, 4000):  # 乱序，并且跨回绕点
            segs.append(cv.c(off, body[off : off + 1000]))
        segs.append(cv.c(5000, body[5000:]))
        segs.append(cv.s(0, self.RESP))
        res = self.run_check(pcap_check.DLT_LINUX_SLL, segs, self.events_origin(cin=body))
        self.assertEqual(res["status"], "ok", res["problems"])
        self.assertEqual(res["conns"][0]["c2s"]["pcap_len"], len(body))

    def test_large_gso_segment(self):
        """回环上一个包里的大段（接近 64 KiB），以及 IP 总长度写成 0 的包。"""
        big = os.urandom(65483)
        more = os.urandom(70000)
        cv = Convo(50001, 40002)
        frames = [link(pcap_check.DLT_EN10MB, ip4(s), False) for s in cv.hs() + [cv.c(0, big)]]
        # 超过 65535 的段：IP 总长度放不下，写成 0
        frames.append(link(pcap_check.DLT_EN10MB, ip4(cv.c(len(big), more), total=0), False))
        p = os.path.join(self.dir, "g.pcap")
        e = os.path.join(self.dir, "g.jsonl")
        with open(p, "wb") as fh:
            fh.write(pcap_bytes(pcap_check.DLT_EN10MB, frames))
        with open(e, "w") as fh:
            fh.write(self.events_origin(cin=big + more, cout=b""))
        res = pcap_check.check(p, e)
        self.assertEqual(res["status"], "ok", res["problems"])
        self.assertEqual(res["conns"][0]["c2s"]["pcap_len"], len(big) + len(more))

    def test_missing_syn_full_data(self):
        """缺 SYN 但数据齐全：哈希对得上，标记不完整并在 problems 里说明。"""
        cv = Convo(50001, 40002)
        segs = self.simple(cv)[2:]  # 去掉 SYN 和 SYN+ACK
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        c = res["conns"][0]
        self.assertFalse(c["complete"])
        self.assertEqual(c["c2s"]["verdict"], "exact")
        self.assertTrue(any("没有客户端的 SYN" in p for p in res["problems"]), res["problems"])
        self.assertTrue(any("没有服务端的 SYN+ACK" in p for p in res["problems"]), res["problems"])

    def test_missing_syn_midstream(self):
        """抓包从连接中途开始：字节对不上，报 mismatch，不当成功。"""
        cv = Convo(50001, 40002)
        r = self.REQ
        segs = [cv.c(10, r[10:]), cv.s(0, self.RESP), cv.c(len(r), b"", FIN | ACK)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["status"], "mismatch")
        c = res["conns"][0]
        self.assertFalse(c["complete"])
        self.assertEqual(c["c2s"]["verdict"], "mismatch")
        self.assertEqual(c["s2c"]["verdict"], "exact")

    def test_missing_syn_earlier_data_arrives_later(self):
        """缺 SYN，且先见到的不是最早的段：起点往前挪。"""
        cv = Convo(50001, 40002)
        r = self.REQ
        segs = [cv.c(10, r[10:]), cv.c(0, r[:10]), cv.s(0, self.RESP)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["conns"][0]["c2s"]["verdict"], "exact", res["problems"])
        self.assertFalse(res["conns"][0]["complete"])

    def test_gap_is_mismatch(self):
        """抓包中间丢了一个包：不能当成 prefix，更不能当成功。"""
        cv = Convo(50001, 40002)
        r = self.REQ
        segs = cv.hs() + [cv.c(0, r[:10]), cv.c(20, r[20:]), cv.s(0, self.RESP)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["status"], "mismatch")
        self.assertEqual(res["conns"][0]["c2s"]["verdict"], "mismatch")
        self.assertTrue(any("缺口" in p for p in res["problems"]), res["problems"])

    def test_prefix_pcap_longer(self):
        """事件记的是抓包的前缀：prefix，写出差多少字节。"""
        cv = Convo(50001, 40002)
        extra = b"GET /late HTTP/1.1\r\n\r\n"
        segs = cv.hs() + [cv.c(0, self.REQ), cv.s(0, self.RESP), cv.s(len(self.RESP), b"", FIN | ACK), cv.c(len(self.REQ), extra)]
        ev = self.events_origin(rec_in_len=len(self.REQ), rec_in_sha=sha(self.REQ), by="proxy")
        res = self.run_check(pcap_check.DLT_EN10MB, segs, ev)
        self.assertEqual(res["status"], "prefix", res["problems"])
        d = res["conns"][0]["c2s"]
        self.assertEqual((d["verdict"], d["longer"], d["diff_bytes"], d["verified"]), ("prefix", "pcap", len(extra), True))
        self.assertEqual((res["conns"][0]["closed_by"], res["conns"][0]["how"]), ("proxy", "fin"))

    def test_longer_but_not_prefix_is_mismatch(self):
        cv = Convo(50001, 40002)
        segs = cv.hs() + [cv.c(0, self.REQ + b"tail"), cv.s(0, self.RESP)]
        ev = self.events_origin(rec_in_len=len(self.REQ), rec_in_sha=sha(b"Z" * len(self.REQ)))
        res = self.run_check(pcap_check.DLT_EN10MB, segs, ev)
        self.assertEqual(res["status"], "mismatch")

    def test_events_longer_is_unverified_prefix(self):
        """事件比抓包长：记 prefix，但明说无法验证。"""
        cv = Convo(50001, 40002)
        segs = cv.hs() + [cv.c(0, self.REQ), cv.s(0, self.RESP[:10]), cv.s(10, b"", RST | ACK)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin(by="proxy", close="rst"))
        self.assertEqual(res["status"], "prefix", res["problems"])
        d = res["conns"][0]["s2c"]
        self.assertEqual((d["verdict"], d["longer"], d["verified"]), ("prefix", "events", False))
        self.assertTrue(any("未验证" in p for p in res["problems"]))
        self.assertEqual((res["conns"][0]["closed_by"], res["conns"][0]["how"]), ("proxy", "rst"))

    def test_events_longer_without_reset_is_mismatch(self):
        """事件比抓包长而连接是正常关的：没有解释，算 mismatch；客户端方向即使有 RST 也算。"""
        cv = Convo(50001, 40002)
        n = len(self.REQ)
        segs = cv.hs() + [cv.c(0, self.REQ), cv.s(0, self.RESP[:10]), cv.s(10, b"", FIN | ACK), cv.c(n, b"", FIN | ACK)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["status"], "mismatch")
        self.assertEqual(res["conns"][0]["s2c"]["verdict"], "mismatch")
        segs = cv.hs() + [cv.c(0, self.REQ[:10]), cv.s(0, self.RESP), cv.s(len(self.RESP), b"", RST | ACK)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["status"], "mismatch")
        self.assertEqual(res["conns"][0]["c2s"]["verdict"], "mismatch")

    def test_same_length_different_hash(self):
        cv = Convo(50001, 40002)
        res = self.run_check(pcap_check.DLT_EN10MB, self.simple(cv), self.events_origin(rec_out_sha=sha(b"other")))
        self.assertEqual(res["status"], "mismatch")
        self.assertEqual(res["conns"][0]["s2c"]["verdict"], "mismatch")

    def test_close_disagreement_only_in_problems(self):
        """谁先关的与事件不一致：只写进 problems，不影响 status。"""
        cv = Convo(50001, 40002)
        res = self.run_check(pcap_check.DLT_EN10MB, self.simple(cv), self.events_origin(by="proxy", close="rst"))
        self.assertEqual(res["status"], "ok")
        self.assertTrue(any("时序上的竞争" in p for p in res["problems"]), res["problems"])

    def test_port_reuse_two_conns(self):
        """同一个四元组先后两条连接（端口复用）：按先后配对。"""
        a = Convo(50001, 40002, isn_c=1000, isn_s=5000)
        b = Convo(50001, 40002, isn_c=900000, isn_s=800000)
        r2 = b"GET /second HTTP/1.1\r\n\r\n"
        segs = self.simple(a) + b.hs() + [b.c(0, r2), b.s(0, self.RESP), b.s(len(self.RESP), b"", RST | ACK)]
        ev = make_events(
            [
                {"listener": "origin_http", "peer_port": 50001, "cin": self.REQ, "cout": self.RESP},
                {"listener": "origin_http", "peer_port": 50001, "cin": r2, "cout": self.RESP, "by": "proxy", "close": "rst"},
            ]
        )
        res = self.run_check(pcap_check.DLT_EN10MB, segs, ev)
        self.assertEqual(res["status"], "ok", res["problems"])
        self.assertEqual([c["c2s"]["pcap_len"] for c in res["conns"]], [len(self.REQ), len(r2)])
        self.assertEqual(res["conns"][1]["how"], "rst")

    def test_conn_only_in_events_or_only_in_pcap(self):
        cv = Convo(50001, 40002)
        ev = make_events(
            [
                {"listener": "origin_http", "peer_port": 50001, "cin": self.REQ, "cout": self.RESP},
                {"listener": "origin_https", "peer_port": 50009, "cin": b"", "cout": b""},
            ]
        )
        res = self.run_check(pcap_check.DLT_EN10MB, self.simple(cv), ev)
        self.assertEqual(res["status"], "mismatch")
        self.assertTrue(any("事件里有，抓包里没有" in p for p in res["problems"]))
        other = Convo(50002, 40003)
        res = self.run_check(pcap_check.DLT_EN10MB, self.simple(cv) + self.simple(other), self.events_origin())
        self.assertEqual(res["status"], "mismatch")
        self.assertTrue(any("没有对应的 accept" in p for p in res["problems"]))
        self.assertEqual(len(res["conns"]), 2)

    def test_unestablished_syn_is_ignored_with_note(self):
        """只有 SYN、没握上手的连接仪器不可能接受：忽略，但说明。"""
        cv = Convo(50001, 40002)
        ghost = Convo(50077, 40002)
        segs = self.simple(cv) + [ghost.syn(), tcp_seg(40002, 50077, 0, ghost.isn_c + 1, RST | ACK)]
        res = self.run_check(pcap_check.DLT_EN10MB, segs, self.events_origin())
        self.assertEqual(res["status"], "ok", res["problems"])
        self.assertTrue(any("没有完成三次握手" in p for p in res["problems"]))

    def test_errors(self):
        p, e = self.write(pcap_check.DLT_EN10MB, self.simple(Convo(50001, 40002)), self.events_origin())
        self.assertEqual(pcap_check.check(os.path.join(self.dir, "nope.pcap"), e)["status"], "error")
        self.assertEqual(pcap_check.check(p, os.path.join(self.dir, "nope.jsonl"))["status"], "error")
        bad = os.path.join(self.dir, "bad.pcap")
        with open(bad, "wb") as fh:
            fh.write(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
        res = pcap_check.check(bad, e)
        self.assertEqual(res["status"], "error")
        self.assertIn("pcapng", res["problems"][0])
        with open(bad, "wb") as fh:
            fh.write(pcap_bytes(147, []))
        self.assertEqual(pcap_check.check(bad, e)["status"], "error")
        # 没有 end 的事件文件不能用
        noend = os.path.join(self.dir, "noend.jsonl")
        with open(e) as fh:
            lines = fh.read().splitlines(True)
        with open(noend, "w") as fh:
            fh.writelines(lines[:-1])
        res = pcap_check.check(p, noend)
        self.assertEqual(res["status"], "error")
        self.assertEqual(set(res), {"status", "conns", "fields", "problems"})

    def test_truncated_pcap_file_is_mismatch(self):
        p, e = self.write(pcap_check.DLT_EN10MB, self.simple(Convo(50001, 40002)), self.events_origin())
        with open(p, "rb") as fh:
            data = fh.read()
        with open(p, "wb") as fh:
            fh.write(data[:-7])
        res = pcap_check.check(p, e)
        self.assertEqual(res["status"], "mismatch")
        self.assertTrue(any("截断" in x for x in res["problems"]))

    def test_cli(self):
        p, e = self.write(pcap_check.DLT_EN10MB, self.simple(Convo(50001, 40002)), self.events_origin())
        out = os.path.join(self.dir, "check.json")
        script = os.path.join(HERE, "pcap_check.py")
        r = subprocess.run([sys.executable, script, "--pcap", p, "--events", e, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["status"], "ok")
        r = subprocess.run([sys.executable, script, "--pcap", p + ".x", "--events", e, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


class TestFieldsSynthetic(SynthBase):
    """代理端口上的字段比较（手工拼的字节和事件）。"""

    H1 = b"POST http://a.kaoju.test/echo?k=T.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nTransfer-Encoding: chunked\r\n\r\n"
    B1 = b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
    H2 = b"GET http://a.kaoju.test/echo?k=T.s2 HTTP/1.1\r\nhost: a.kaoju.test\r\nproxy-authorization:  Basic QTpC \r\n\r\n"
    R407 = b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 3\r\n\r\nno\n"
    R200 = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"

    def build(self, mutate=None):
        cin = self.H1 + self.B1 + self.H2
        cout = self.R407 + self.R200
        cv = Convo(50001, 40001)
        segs = cv.hs() + [cv.c(0, cin), cv.s(0, cout), cv.c(len(cin), b"", FIN | ACK)]  # 两个请求是管线发出的
        extra = [
            http_request_event(self.H1, 1, b"hello world"),
            {"ev": "http_response", "seq": 1, "status": 407, "error": None},
            http_request_event(self.H2, 2, b"", "Basic QTpC"),
            {"ev": "http_response", "seq": 2, "status": 100, "error": None},
            {"ev": "http_response", "seq": 2, "status": 200, "error": None},
        ]
        if mutate:
            mutate(extra)
        ev = make_events([{"listener": "proxy", "peer_port": 50001, "cin": cin, "cout": cout, "extra": extra}])
        return self.run_check(pcap_check.DLT_EN10MB, segs, ev)

    def test_pipelined_chunked_and_auth(self):
        res = self.build()
        self.assertEqual(res["status"], "ok", res["problems"])
        self.assertEqual(res["conns"][0]["kind"], "http")
        self.assertGreaterEqual(res["fields"]["compared"], 15)

    def test_each_field_mismatch_detected(self):
        def set_(i, path, val):
            def f(extra):
                d = extra[i]
                for k in path[:-1]:
                    d = d[k]
                d[path[-1]] = val

            return f

        cases = [
            (set_(0, ["method"], "GET"), "http_request[1].method"),
            (set_(2, ["target"], "http://a.kaoju.test/echo?k=T.s9"), "http_request[2].target"),
            (set_(2, ["version"], "HTTP/1.0"), "http_request[2].version"),
            (set_(2, ["auth", "raw"], "Basic QTpD"), "http_request[2].auth.raw"),
            (set_(0, ["auth", "present"], True), "http_request[1].auth.present"),
            (set_(0, ["body_len"], 12), "http_request[1].body_len"),
            (set_(0, ["body_sha256"], sha(b"x")), "http_request[1].body_sha256"),
            (set_(1, ["status"], 403), "http_response.(seq,status)"),
            (lambda extra: extra.pop(2), "http_request.count"),
            (lambda extra: extra.append(http_request_event(self.H2, 3)), "http_request.count"),
        ]
        for mutate, field in cases:
            with self.subTest(field=field):
                res = self.build(mutate)
                self.assertEqual(res["status"], "mismatch")
                self.assertIn(field, [m["field"] for m in res["fields"]["mismatched"]])
                self.assertTrue(all(m["conn"] == 1 for m in res["fields"]["mismatched"]))

    def connect_case(self, tunnel_c, tfb, tclose=True, status=b"200 OK"):
        head = b"CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\nProxy-Authorization: Basic QTpC\r\n\r\n"
        resp = b"HTTP/1.1 " + status + b"\r\n\r\n"
        tunnel_s = b"\x16\x03\x03\x00\x02hi" if status.startswith(b"2") else b""
        cin = head + tunnel_c
        cout = resp + tunnel_s
        cv = Convo(50001, 40001)
        segs = cv.hs() + [cv.c(0, head), cv.s(0, resp)]
        if tunnel_c:
            segs.append(cv.c(len(head), tunnel_c))
        if tunnel_s:
            segs.append(cv.s(len(resp), tunnel_s))
        segs.append(cv.c(len(cin), b"", FIN | ACK))
        extra = [http_request_event(head, 1, b"", "Basic QTpC"), {"ev": "http_response", "seq": 1, "status": int(status[:3]), "error": None}]
        if status.startswith(b"2"):
            extra.append({"ev": "tunnel_open", "tunnel": 1, "via": "connect", "req_seq": 1})
            if tfb is not None:
                extra.append(dict({"ev": "tunnel_first_bytes", "tunnel": 1}, **tfb))
            if tclose:
                extra.append({"ev": "tunnel_close", "tunnel": 1, "bytes_c2s": len(tunnel_c), "bytes_s2c": len(tunnel_s)})
        ev = make_events([{"listener": "proxy", "peer_port": 50001, "cin": cin, "cout": cout, "extra": extra}])
        return self.run_check(pcap_check.DLT_EN10MB, segs, ev)

    HELLO = b"\x16\x03\x01\x00\x10" + b"\x01" * 16

    def test_connect_tunnel_tls_first_bytes(self):
        tfb = {"hex": self.HELLO[:16].hex(), "kind": "tls_client_hello", "tls": {"record_len": 16, "record_version": 769}}
        res = self.connect_case(self.HELLO, tfb)
        self.assertEqual(res["status"], "ok", res["problems"])

    def test_connect_tunnel_mismatches(self):
        good = {"hex": self.HELLO[:16].hex(), "kind": "tls_client_hello", "tls": {"record_len": 16, "record_version": 769}}
        for tfb, field in [
            (dict(good, hex="16030100ff" + good["hex"][10:]), "tunnel_first_bytes.hex[:5]"),
            (dict(good, tls={"record_len": 17, "record_version": 769}), "tunnel_first_bytes.tls.record_len"),
            (None, "tunnel_first_bytes(有没有)"),
        ]:
            with self.subTest(field=field):
                res = self.connect_case(self.HELLO, tfb)
                self.assertEqual(res["status"], "mismatch")
                self.assertIn(field, [m["field"] for m in res["fields"]["mismatched"]])

    def test_connect_non_tls_tunnel_and_short_first_bytes(self):
        res = self.connect_case(b"GET", {"hex": b"GET".hex(), "kind": "other", "tls": None})
        self.assertEqual(res["status"], "ok", res["problems"])

    def test_connect_refused_has_no_tunnel(self):
        res = self.connect_case(b"", None, status=b"502 Bad Gateway")
        self.assertEqual(res["status"], "ok", res["problems"])

    def socks_case(self, mutate=None, atyp=3):
        greet = b"\x05\x02\x00\x02"
        auth = b"\x01\x04user\x06secret"
        if atyp == 3:
            req, host = b"\x05\x01\x00\x03\x0ca.kaoju.test\x00\x50", "a.kaoju.test"
        elif atyp == 1:
            req, host = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb", "127.0.0.1"
        else:
            req, host = b"\x05\x01\x00\x04" + b"\x00" * 15 + b"\x01" + b"\x01\xbb", "::1"
        port = struct.unpack(">H", req[-2:])[0]
        reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        tun = b"GET / HTTP/1.1\r\n\r\n"
        cin = greet + auth + req + tun
        cout = b"\x05\x02" + b"\x01\x00" + reply + b"HTTP/1.1 200 OK\r\n\r\n"
        cv = Convo(50001, 40001)
        segs = cv.hs() + [cv.c(0, cin[:3]), cv.c(3, cin[3:]), cv.s(0, cout), cv.c(len(cin), b"", FIN | ACK)]
        extra = [
            {"ev": "socks5_greeting", "version": 5, "methods": [0, 2], "raw_hex": greet.hex()},
            {"ev": "socks5_method", "selected": 2},
            {
                "ev": "socks5_auth",
                "version": 1,
                "ulen": 4,
                "plen": 6,
                "user": "user",
                "user_hex": b"user".hex(),
                "pass": "secret",
                "pass_hex": b"secret".hex(),
                "status": 0,
            },
            {"ev": "socks5_request", "version": 5, "cmd": 1, "rsv": 0, "atyp": atyp, "host": host, "port": port, "raw_hex": req.hex()},
            {"ev": "socks5_reply", "rep": 0, "raw_hex": reply.hex()},
            {"ev": "tunnel_open", "tunnel": 1, "via": "socks5", "req_seq": None},
            {"ev": "tunnel_first_bytes", "tunnel": 1, "hex": tun[:16].hex(), "kind": "http", "tls": None},
            {"ev": "tunnel_close", "tunnel": 1, "bytes_c2s": len(tun), "bytes_s2c": 19},
        ]
        if mutate:
            mutate(extra)
        ev = make_events([{"listener": "proxy", "peer_port": 50001, "cin": cin, "cout": cout, "extra": extra}])
        return self.run_check(pcap_check.DLT_EN10MB, segs, ev)

    def test_socks5_ok_all_address_types(self):
        for atyp in (1, 3, 4):
            with self.subTest(atyp=atyp):
                res = self.socks_case(atyp=atyp)
                self.assertEqual(res["status"], "ok", res["problems"])
                self.assertEqual(res["conns"][0]["kind"], "socks5")

    def test_socks5_each_field_mismatch_detected(self):
        cases = [
            (0, "methods", [2, 0], "socks5_greeting.methods"),
            (1, "selected", 0, "socks5_method.selected"),
            (2, "ulen", 5, "socks5_auth.ulen"),
            (2, "user_hex", b"usex".hex(), "socks5_auth.user_hex"),
            (2, "pass_hex", b"secreT".hex(), "socks5_auth.pass_hex"),
            (2, "status", 1, "socks5_auth.status"),
            (3, "cmd", 2, "socks5_request.cmd"),
            (3, "atyp", 1, "socks5_request.atyp"),
            (3, "host", "b.kaoju.test", "socks5_request.host"),
            (3, "port", 443, "socks5_request.port"),
            (4, "rep", 5, "socks5_reply.rep"),
            (7, "bytes_c2s", 17, "tunnel_close.bytes_c2s"),
            (6, "hex", b"PUT / HTTP/1.1\r\n".hex(), "tunnel_first_bytes.hex[:5]"),
        ]
        for i, key, val, field in cases:
            with self.subTest(field=field):
                res = self.socks_case(lambda extra, i=i, key=key, val=val: extra[i].__setitem__(key, val))
                self.assertEqual(res["status"], "mismatch")
                self.assertIn(field, [m["field"] for m in res["fields"]["mismatched"]])
        res = self.socks_case(lambda extra: extra.pop(2))
        self.assertIn("socks5_auth(有没有)", [m["field"] for m in res["fields"]["mismatched"]])


# ---------------------------------------------------------------------------
# 真实数据：obsproxy + tcpdump + curl
# ---------------------------------------------------------------------------


def _skip_reason():
    if not shutil.which("tcpdump"):
        return "没有 tcpdump"
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return "不是 root，抓不了回环"
    if not shutil.which("curl"):
        return "没有 curl"
    if not os.environ.get("PCAP_CHECK_OBSPROXY") and not shutil.which("go"):
        return "没有 obsproxy 二进制（PCAP_CHECK_OBSPROXY），也没有 go 可以现编"
    return None


USER, PASS = "kaoju-user", "kaoju-pass-1"
BASIC = {"auth": {"mode": "basic", "accept": [[USER, PASS]]}}


@unittest.skipIf(_skip_reason(), "真实数据的测试跳过：%s" % _skip_reason())
class TestReal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="pcapcheck-real-")
        os.chmod(cls.root, 0o755)  # tcpdump 会降权成 tcpdump 用户，要能走进来
        cls.addClassCleanup(shutil.rmtree, cls.root, True)
        cls.obsproxy = os.environ.get("PCAP_CHECK_OBSPROXY")
        if not cls.obsproxy:
            cls.obsproxy = os.path.join(cls.root, "obsproxy")
            r = subprocess.run(["go", "build", "-trimpath", "-o", cls.obsproxy, "."], cwd=HARNESS, capture_output=True, text=True)
            if r.returncode != 0:
                raise unittest.SkipTest("obsproxy 编不出来：%s" % r.stderr[-300:])
        cls.ca = os.path.join(cls.root, "ca")
        subprocess.run([cls.obsproxy, "gen-ca", "-dir", cls.ca], check=True, capture_output=True)
        cls.home = os.path.join(cls.root, "home")
        os.mkdir(cls.home)
        cls.n = 0
        cls.cache = {}

    def curl(self, *args, expect=None):
        """在干净环境里跑 curl（相当于 env -i PATH=$PATH HOME=临时目录）。返回退出码。"""
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.home}
        r = subprocess.run(
            ["curl", "-q", "-sS", "--max-time", "20", "-o", os.devnull, "--cacert", os.path.join(self.ca, "ca.pem")] + list(args),
            env=env,
            capture_output=True,
            text=True,
        )
        if expect is not None:
            self.assertIn(r.returncode, expect, "curl %s：%s" % (" ".join(args), r.stderr))
        return r.returncode

    def scenario(self, name, profile, act):
        """起 obsproxy 和 tcpdump，执行 act(ports)，收尾。返回 (pcap, events)。结果按名字缓存。"""
        if name in self.cache:
            return self.cache[name]
        type(self).n += 1
        d = os.path.join(self.root, "%02d-%s" % (self.n, name))
        os.mkdir(d)
        os.chmod(d, 0o777)
        prof = os.path.join(d, "profile.json")
        with open(prof, "w") as fh:
            json.dump(profile, fh)
        events = os.path.join(d, "events.jsonl")
        pcap = os.path.join(d, "run.pcap")
        obs = subprocess.Popen(
            [self.obsproxy, "serve", "-profile", prof, "-ca-dir", self.ca, "-events", events, "-max-seconds", "120"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        td = None
        try:
            ports = json.loads(obs.stdout.readline())
            flt = " or ".join("tcp port %d" % ports[k] for k in ("proxy_port", "origin_http_port", "origin_https_port"))
            td_err = os.path.join(d, "tcpdump.stderr")
            with open(td_err, "wb") as errfh:
                td = subprocess.Popen(
                    ["tcpdump", "-i", "lo", "-n", "--immediate-mode", "-B", "32768", "-U", "-s", "0", "-w", pcap, flt],
                    stdout=subprocess.DEVNULL,
                    stderr=errfh,
                )
            deadline = time.time() + 15
            while True:
                with open(td_err, errors="replace") as fh:
                    text = fh.read()
                if "listening on" in text:
                    break
                if td.poll() is not None or time.time() > deadline:
                    self.fail("tcpdump 没有起来：%s" % text[-300:])
                time.sleep(0.05)
            time.sleep(0.2)
            act(ports)
            time.sleep(0.3)
        finally:
            obs.send_signal(signal.SIGTERM)
            try:
                obs.wait(15)
            except subprocess.TimeoutExpired:
                obs.kill()
            obs.stdout.close()
            obs.stderr.close()
            if td is not None:
                time.sleep(0.5)
                td.send_signal(signal.SIGINT)
                try:
                    td.wait(15)
                except subprocess.TimeoutExpired:
                    td.kill()
        self.assertEqual(obs.returncode, 0, "obsproxy 没有正常退出")
        with open(td_err, errors="replace") as fh:
            m = re.search(r"(\d+) packets dropped by kernel", fh.read())
        self.assertIsNotNone(m, "读不到 tcpdump 的统计")
        self.assertEqual(int(m.group(1)), 0, "tcpdump 丢包了")
        self.cache[name] = (pcap, events)
        return pcap, events

    def events_of(self, name):
        with open(self.cache[name][1], encoding="utf-8") as fh:
            return [json.loads(x) for x in fh]

    def check_ok(self, name, profile, act, allow=("ok",), kinds=None, min_fields=1):
        pcap, events = self.scenario(name, profile, act)
        res = pcap_check.check(pcap, events)
        detail = json.dumps(res, ensure_ascii=False, indent=1)
        self.assertIn(res["status"], allow, detail)
        self.assertEqual(res["fields"]["mismatched"], [], detail)
        self.assertGreaterEqual(res["fields"]["compared"], min_fields, detail)
        for c in res["conns"]:
            self.assertTrue(c["complete"], detail)
            self.assertIn(c["c2s"]["verdict"], ("exact", "prefix"), detail)
            self.assertIn(c["s2c"]["verdict"], ("exact", "prefix"), detail)
            self.assertIsNotNone(c["closed_by"], detail)
        if kinds is not None:
            self.assertEqual(sorted(c["kind"] for c in res["conns"]), sorted(kinds), detail)
        return res

    # ---- 各种配置 ----

    def act_plain(self, ports):
        px = "http://127.0.0.1:%d" % ports["proxy_port"]
        self.curl("-x", px, "http://a.kaoju.test/echo?k=T01.s1", expect=(0,))
        self.curl("-x", px, "-d", "x=" + "y" * 5000, "http://a.kaoju.test/echo?k=T01.s2", expect=(0,))
        self.curl("-x", px, "-H", "Transfer-Encoding: chunked", "-d", "chunked-body", "http://a.kaoju.test/echo?k=T01.s3", expect=(0,))
        # 一个进程、同一条连接上的两个请求
        self.curl("-x", px, "http://a.kaoju.test/echo?k=T01.s4", "-o", os.devnull, "http://a.kaoju.test/echo?k=T01.s5", expect=(0,))

    def test_plain(self):
        res = self.check_ok("plain", {}, self.act_plain, kinds=["http"] * 4, min_fields=40)
        self.assertEqual(res["status"], "ok")

    def act_connect_auth(self, ports):
        px = "http://127.0.0.1:%d" % ports["proxy_port"]
        self.curl("-x", px, "-U", "%s:%s" % (USER, PASS), "https://a.kaoju.test/echo?k=T02.s1", expect=(0,))
        self.curl("-x", px, "-U", "%s:%s" % (USER, PASS), "--http1.1", "https://a.kaoju.test/echo?k=T02.s2", expect=(0,))

    def test_connect_with_auth(self):
        res = self.check_ok("connect-auth", BASIC, self.act_connect_auth, allow=("ok", "prefix"), kinds=["http", "http"], min_fields=30)
        evs = self.events_of("connect-auth")
        self.assertEqual(sum(1 for e in evs if e["ev"] == "tunnel_first_bytes" and e["tls"]), 2)

    def act_407(self, ports):
        px = "http://127.0.0.1:%d" % ports["proxy_port"]
        self.curl("-x", px, "--proxy-anyauth", "-U", "%s:%s" % (USER, PASS), "http://a.kaoju.test/echo?k=T03.s1", expect=(0,))
        self.curl("-x", px, "--proxy-anyauth", "-U", "%s:%s" % (USER, PASS), "https://a.kaoju.test/echo?k=T03.s2", expect=(0,))

    def test_407_keepalive(self):
        self.check_ok("407", BASIC, self.act_407, allow=("ok", "prefix"), min_fields=40)
        evs = self.events_of("407")
        # 确认这个场景真的走了“同一条连接上先 407 再带凭据重发”
        seq2 = [e for e in evs if e["ev"] == "http_request" and e["seq"] == 2]
        self.assertTrue(seq2 and all(e["auth"]["present"] for e in seq2))

    def act_socks(self, ports):
        px = "socks5h://%s:%s@127.0.0.1:%d" % (USER, PASS, ports["proxy_port"])
        self.curl("-x", px, "http://a.kaoju.test/echo?k=T04.s1", expect=(0,))
        self.curl("-x", px, "https://a.kaoju.test/echo?k=T04.s2", expect=(0,))
        # 密码不对：认证失败后仪器关连接
        bad = "socks5h://%s:wrong@127.0.0.1:%d" % (USER, ports["proxy_port"])
        self.curl("-x", bad, "http://a.kaoju.test/echo?k=T04.s3", expect=(7, 97))
        # socks5://（客户端自己解析）：.test 解析不了，用 IP 字面量，覆盖 ATYP=1
        ip = "socks5://%s:%s@127.0.0.1:%d" % (USER, PASS, ports["proxy_port"])
        self.curl("-x", ip, "http://127.0.0.1:80/echo?k=T04.s4", expect=(0,))

    def test_socks5_userpass(self):
        prof = {"socks": {"auth": "userpass"}, "auth": {"accept": [[USER, PASS]]}}
        self.check_ok("socks", prof, self.act_socks, allow=("ok", "prefix"), kinds=["socks5"] * 4, min_fields=60)

    def drop_profile(self, how):
        return {"conn": {"drop": {"k": "T05.s1", "times": 1, "how": how, "only_if_reused": False}}}

    def act_drop(self, ports):
        px = "http://127.0.0.1:%d" % ports["proxy_port"]
        self.curl("-x", px, "http://a.kaoju.test/echo?k=T05.s1", expect=(52, 56))
        self.curl("-x", px, "http://a.kaoju.test/echo?k=T05.s1", expect=(0,))  # 只生效一次

    def test_conn_drop_fin(self):
        res = self.check_ok("drop-fin", self.drop_profile("fin"), self.act_drop, allow=("ok", "prefix"), kinds=["http", "http"])
        self.assertEqual((res["conns"][0]["closed_by"], res["conns"][0]["how"]), ("proxy", "fin"))

    def test_conn_drop_rst(self):
        res = self.check_ok("drop-rst", self.drop_profile("rst"), self.act_drop, allow=("ok", "prefix"), kinds=["http", "http"])
        self.assertEqual((res["conns"][0]["closed_by"], res["conns"][0]["how"]), ("proxy", "rst"))

    def act_e01(self, ports):
        px = "http://127.0.0.1:%d" % ports["proxy_port"]
        self.curl("-x", px, "https://a.kaoju.test/echo?k=E01.s1", expect=(56,))

    def test_e01_connect_502(self):
        with open(os.path.join(HERE, "..", "cases.json"), encoding="utf-8") as fh:
            case = [c for c in json.load(fh)["cases"] if c["id"] == "E01"][0]
        self.check_ok("e01", case["profile"], self.act_e01, allow=("ok", "prefix"), kinds=["http"], min_fields=8)
        evs = self.events_of("e01")
        self.assertEqual([e["status"] for e in evs if e["ev"] == "http_response"], [502])

    def act_direct(self, ports):
        self.curl("--noproxy", "*", "http://127.0.0.1:%d/echo?k=T06.s1" % ports["origin_http_port"], expect=(0,))
        self.curl("--noproxy", "*", "https://127.0.0.1:%d/echo?k=T06.s2" % ports["origin_https_port"], expect=(0,))
        # 代理端口上只连不说话、以及一上来就是 TLS 的连接
        s = socket.create_connection(("127.0.0.1", ports["proxy_port"]))
        s.close()
        s = socket.create_connection(("127.0.0.1", ports["proxy_port"]))
        s.sendall(b"\x16\x03\x01\x00\x05hello")
        s.settimeout(5)
        try:
            while s.recv(4096):
                pass
        except OSError:
            pass
        s.close()

    def test_direct_and_odd_connections(self):
        self.check_ok("direct", {}, self.act_direct, allow=("ok", "prefix"), kinds=["origin", "origin", "empty", "refused"])

    def act_raw_socks(self, ports):
        """裸套接字说几种不规矩的 SOCKS5：子协商版本不对、请求版本不对、地址类型不认识、IPv6、BIND。"""

        def talk(*msgs):
            s = socket.create_connection(("127.0.0.1", ports["proxy_port"]))
            s.settimeout(3)
            try:
                for m in msgs:
                    s.sendall(m)
                    try:
                        if not s.recv(4096):
                            break
                    except OSError:
                        break
                    time.sleep(0.05)
            finally:
                s.close()

        up = bytes([len(USER)]) + USER.encode() + bytes([len(PASS)]) + PASS.encode()
        talk(b"\x05\x01\x02", b"\x02" + up)  # 子协商 VER=2
        talk(b"\x05\x01\x02", b"\x01" + up, b"\x04\x01\x00\x01\x7f\x00\x00\x01\x00\x50")  # 请求 VER=4
        talk(b"\x05\x01\x02", b"\x01" + up, b"\x05\x01\x00\x09\x01\x02\x03\x04\x00\x50")  # ATYP=9
        talk(b"\x05\x01\x02", b"\x01" + up, b"\x05\x01\x00\x04" + b"\x00" * 15 + b"\x01\x00\x50", b"GET / HTTP/1.0\r\n\r\n")
        talk(b"\x05\x01\x02", b"\x01" + up, b"\x05\x02\x07\x03\x0ca.kaoju.test\x01\xbb")  # BIND，RSV=7
        talk(b"\x05\x01\x00")  # 不提供用户名密码：0xFF
        talk(b"\x05\x02\x00\x02", b"\x01\x00\x00")  # 空用户名、空密码

    def test_raw_socks_edge_cases(self):
        prof = {"socks": {"auth": "userpass"}, "auth": {"accept": [[USER, PASS]]}}
        self.check_ok("raw-socks", prof, self.act_raw_socks, allow=("ok", "prefix"), kinds=["socks5"] * 7, min_fields=60)

    def act_raw_http(self, ports):
        """裸套接字说几种不规矩的 HTTP：管线、头没发完就关、请求行不对、请求行前有空行。"""

        def talk(data, wait=True):
            s = socket.create_connection(("127.0.0.1", ports["proxy_port"]))
            s.settimeout(3)
            try:
                s.sendall(data)
                if wait:
                    s.shutdown(socket.SHUT_WR)
                    try:
                        while s.recv(65536):
                            pass
                    except OSError:
                        pass
            finally:
                s.close()

        g = b"GET http://a.kaoju.test/echo?k=T08.%s HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n"
        talk(g % b"s1" + g % b"s2" + g % b"s3")  # 管线
        talk(b"GET http://a.kaoju.test/echo?k=T08.s4 HTTP/1.1\r\nHost: a.kao")  # 头没发完
        talk(b"NONSENSE\r\n\r\n")
        talk(b"\r\n\r\n" + g % b"s5")  # 请求行前有空行
        talk(b"POST http://a.kaoju.test/echo?k=T08.s6 HTTP/1.1\r\nHost: a.kaoju.test\r\nContent-Length: 10\r\n\r\nabc")  # 正文没发完
        talk(b"GET http://a.kaoju.test/echo?k=T08.s7 HTTP/1.1\r\nHost: a.kaoju.test\r\nConnection: close\r\n\r\n" + g % b"s8")

    def test_raw_http_edge_cases(self):
        self.check_ok("raw-http", {}, self.act_raw_http, allow=("ok", "prefix"), kinds=["http"] * 6, min_fields=30)

    # ---- 改坏事件，必须能发现 ----

    def tampered(self, name, profile, act, mutate):
        pcap, events = self.scenario(name, profile, act)
        with open(events, encoding="utf-8") as fh:
            evs = [json.loads(x) for x in fh]
        mutate(evs)
        bad = events + ".tampered-%d" % id(mutate)
        with open(bad, "w", encoding="utf-8") as fh:
            for e in evs:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        return pcap_check.check(pcap, bad)

    def test_tampered_field_is_detected(self):
        def mutate(evs):
            e = [x for x in evs if x["ev"] == "http_request" and x["seq"] == 2][0]
            e["target"] = e["target"].replace("T03", "T99")

        res = self.tampered("407", BASIC, self.act_407, mutate)
        self.assertEqual(res["status"], "mismatch")
        self.assertEqual([m["field"] for m in res["fields"]["mismatched"]], ["http_request[2].target"])
        self.assertIn("T99", res["fields"]["mismatched"][0]["events"])
        self.assertIn("T03", res["fields"]["mismatched"][0]["pcap"])

    def test_tampered_auth_and_socks_fields_are_detected(self):
        def mutate(evs):
            e = [x for x in evs if x["ev"] == "http_request" and x["auth"]["present"]][0]
            e["auth"]["raw"] = "Basic AAAA"

        res = self.tampered("407", BASIC, self.act_407, mutate)
        self.assertEqual([m["field"] for m in res["fields"]["mismatched"]], ["http_request[2].auth.raw"])

        def mutate2(evs):
            [x for x in evs if x["ev"] == "socks5_auth"][0]["pass_hex"] = b"kaoju-pass-2".hex()

        prof = {"socks": {"auth": "userpass"}, "auth": {"accept": [[USER, PASS]]}}
        res = self.tampered("socks", prof, self.act_socks, mutate2)
        self.assertEqual(res["status"], "mismatch")
        self.assertEqual([m["field"] for m in res["fields"]["mismatched"]], ["socks5_auth.pass_hex"])

    def test_tampered_hash_is_detected(self):
        def mutate(evs):
            e = [x for x in evs if x["ev"] == "conn_end"][0]
            e["sha256_in"] = hashlib.sha256(b"tampered").hexdigest()

        res = self.tampered("407", BASIC, self.act_407, mutate)
        self.assertEqual(res["status"], "mismatch")
        self.assertEqual(res["conns"][0]["c2s"]["verdict"], "mismatch")
        self.assertEqual(res["fields"]["mismatched"], [])

    def test_tampered_length_and_dropped_conn_are_detected(self):
        def mutate(evs):
            [x for x in evs if x["ev"] == "conn_end"][0]["bytes_out"] -= 1

        res = self.tampered("plain", {}, self.act_plain, mutate)
        self.assertEqual(res["status"], "mismatch")

        def mutate2(evs):
            evs[:] = [x for x in evs if x.get("conn") != 2]

        res = self.tampered("plain", {}, self.act_plain, mutate2)
        self.assertEqual(res["status"], "mismatch")
        self.assertTrue(any("没有对应的 accept" in p for p in res["problems"]), res["problems"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
