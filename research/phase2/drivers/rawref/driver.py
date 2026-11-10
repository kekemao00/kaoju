#!/usr/bin/env python3
"""参照客户端 rawref 的驱动（列 rawref）。

用法：
    driver.py <用例.json> <结果.json>
    driver.py --versions

约定见 research/phase2/PROTOCOL.md 的“驱动”和“仪器自检”两节。只用 Python 标准库。

rawref 不是被测对象，是用来检验仪器的：它用裸套接字说话，发出的每个字节都由本文件写死，
所以矩阵里它那一列该是什么值可以不看测量结果、只从 rows.json 和本文件推出来
（手写的答案在 research/phase2/selfcheck_expected.json）。策略的完整文字说明在同目录的 README.md，
改这里的任何行为都要同时改 README.md 和答案。
"""

import base64
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urljoin, urlsplit

VERSION = "1"
USER_AGENT = "kaoju-rawref/1"
BODY_HEAD = 4096
MAX_HEAD = 256 * 1024
MAX_REDIRECTS = 5
WS_KEY = base64.b64encode(b"kaoju-rawref-key").decode("ascii")  # 固定的 16 个字节
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_DRAIN_S = 2.0
TLS_GROUP = "prime256v1"
EXTRA_HOW = "rawref 自己记录的 CONNECT 响应"
CONFIG = (
    "rawref/1：裸套接字，策略写死（见 drivers/rawref/README.md）。"
    "HTTP 代理：明文用绝对形式，HTTPS 用 CONNECT 加 TLS；凭据先带（Basic），407 不重试；"
    "SOCKS5：没配凭据提供 [00]，配了提供 [00, 02]；连接池每个键最多 1 条连接，parallel 各开新连接；"
    "读到 EOF 或复位不重发。TLS：ssl.create_default_context(cafile=ca_file)，校验开启，"
    "SNI 是主机名，ALPN 只有 http/1.1，密钥交换组只有 " + TLS_GROUP + "。"
)

ERR_CLOSED = "rawref: connection closed"
ERR_TIMEOUT = "rawref: timeout"
ERR_RESOLVE = "rawref: resolve failed"
ERR_SOCKS_METHOD = "rawref: socks no acceptable method"
ERR_SOCKS_CRED = "rawref: socks credential too long"


class RawrefError(Exception):
    """这一步失败。消息就是写进 default_text 的全部文字。"""


class Target:
    """一个 URL 拆出来的各段。"""

    def __init__(self, url):
        u = urlsplit(url)
        self.scheme = u.scheme.lower()
        if self.scheme not in ("http", "https", "ws", "wss"):
            raise RawrefError("rawref: unsupported url scheme")
        if not u.hostname:
            raise RawrefError("rawref: bad url")
        self.secure = self.scheme in ("https", "wss")
        self.host = u.hostname
        self.port = u.port if u.port is not None else (443 if self.secure else 80)
        # Host 头：URL 里写了端口就带着，没写就不带
        self.host_header = u.netloc.rpartition("@")[2]
        path = u.path or "/"
        self.origin_form = path + ("?" + u.query if u.query else "")
        self.absolute_form = "%s://%s%s" % (u.scheme, self.host_header, self.origin_form)
        self.authority = "%s:%d" % (("[%s]" % self.host) if ":" in self.host else self.host, self.port)


class Response:
    def __init__(self, status, reason, headers, body, keep):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body
        self.keep = keep

    def header(self, name):
        for n, v in self.headers:
            if n.lower() == name.lower():
                return v
        return None

    def text(self):
        lines = ["%d %s" % (self.status, self.reason)]
        lines += ["%s: %s" % (n, v) for n, v in self.headers]
        return "\n".join(lines) + "\n\n" + self.body[:BODY_HEAD].decode("utf-8", "replace")


class Conn:
    """一条到代理的 TCP 连接（可能已经升级成隧道里的 TLS）。"""

    def __init__(self, sock, deadline):
        self.sock = sock
        self.buf = b""
        self.deadline = deadline

    def _arm(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise RawrefError(ERR_TIMEOUT)
        self.sock.settimeout(left)

    def send(self, data):
        try:
            self._arm()
            self.sock.sendall(data)
        except TimeoutError:
            raise RawrefError(ERR_TIMEOUT) from None
        except OSError:
            raise RawrefError(ERR_CLOSED) from None

    def _recv(self):
        """读一次。对端关闭（FIN、TLS 的 close_notify 或不带它的 EOF）返回空串。"""
        try:
            self._arm()
            return self.sock.recv(65536)
        except TimeoutError:
            raise RawrefError(ERR_TIMEOUT) from None
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
            return b""
        except OSError:
            raise RawrefError(ERR_CLOSED) from None

    def read_exact(self, n):
        while len(self.buf) < n:
            data = self._recv()
            if not data:
                raise RawrefError(ERR_CLOSED)
            self.buf += data
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_until(self, mark):
        while True:
            i = self.buf.find(mark)
            if i >= 0:
                out, self.buf = self.buf[: i + len(mark)], self.buf[i + len(mark) :]
                return out
            if len(self.buf) > MAX_HEAD:
                raise RawrefError("rawref: response head too large")
            data = self._recv()
            if not data:
                raise RawrefError(ERR_CLOSED)
            self.buf += data

    def read_to_eof(self):
        while True:
            try:
                data = self._recv()
            except RawrefError as e:
                if str(e) == ERR_CLOSED:
                    break  # 复位也算读完了
                raise
            if not data:
                break
            self.buf += data
        out, self.buf = self.buf, b""
        return out

    def read_head(self):
        """读一个响应头。返回 (版本, 状态码, 原因短语, [(名, 值)])。"""
        raw = self.read_until(b"\r\n\r\n")
        lines = raw[:-4].decode("latin-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
            raise RawrefError("rawref: bad response")
        headers = []
        for ln in lines[1:]:
            name, sep, value = ln.partition(":")
            if sep:
                headers.append((name, value.strip(" \t")))
        return parts[0], int(parts[1]), parts[2] if len(parts) > 2 else "", headers

    def read_response(self, no_body=False):
        """读一个完整的响应（跳过 101 以外的 1xx）。"""
        while True:
            version, status, reason, headers = self.read_head()
            if status == 101 or status >= 200:
                break
        low = {}
        for n, v in headers:
            low.setdefault(n.lower(), v)
        keep = version == "HTTP/1.1"
        if "close" in [t.strip().lower() for t in low.get("connection", "").split(",")]:
            keep = False
        if no_body or status in (101, 204, 304):
            body = b""
        elif "chunked" in low.get("transfer-encoding", "").lower():
            body = b""
            while True:
                size = int(self.read_until(b"\r\n")[:-2].split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.read_until(b"\r\n") != b"\r\n":
                        pass
                    break
                body += self.read_exact(size)
                self.read_exact(2)
        elif "content-length" in low:
            body = self.read_exact(int(low["content-length"]))
        else:
            body = self.read_to_eof()
            keep = False
        return Response(status, reason, headers, body, keep)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def basic_value(cred):
    """Basic 凭据：base64(用户名的 UTF-8 + ":" + 密码的 UTF-8)，不做任何转义。"""
    raw = cred[0].encode("utf-8") + b":" + cred[1].encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def encode_head(request_line, headers):
    lines = [request_line] + ["%s: %s" % (n, v) for n, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


class Client:
    def __init__(self, case):
        px = case["proxy"]
        self.proxy_scheme = px["scheme"]
        self.proxy_addr = (px["host"], int(px["port"]))
        self.ca_file = case["ca_file"]
        self.pool = {}
        self.tls = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_file)
        self.tls.set_alpn_protocols(["http/1.1"])
        self.tls.set_ecdh_curve(TLS_GROUP)

    # ---------- 建连接 ----------

    def dial_proxy(self, deadline):
        left = deadline - time.monotonic()
        if left <= 0:
            raise RawrefError(ERR_TIMEOUT)
        try:
            sock = socket.create_connection(self.proxy_addr, timeout=left)
        except TimeoutError:
            raise RawrefError(ERR_TIMEOUT) from None
        except OSError:
            raise RawrefError("rawref: proxy connect failed") from None
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return Conn(sock, deadline)

    def start_tls(self, conn, host):
        if conn.buf:
            raise RawrefError("rawref: unexpected bytes before tls")
        try:
            conn._arm()
            conn.sock = self.tls.wrap_socket(conn.sock, server_hostname=host)
        except TimeoutError:
            raise RawrefError(ERR_TIMEOUT) from None
        except ssl.SSLCertVerificationError as e:
            raise RawrefError("rawref: tls failed: certificate verify failed: %s" % e.verify_message) from None
        except ssl.SSLEOFError:
            raise RawrefError(ERR_CLOSED) from None
        except ssl.SSLError as e:
            raise RawrefError("rawref: tls failed: %s" % (e.reason or "error")) from None
        except OSError:
            raise RawrefError(ERR_CLOSED) from None

    def open_http_tunnel(self, cred, tgt, deadline, extra):
        conn = self.dial_proxy(deadline)
        try:
            headers = [("Host", tgt.authority), ("User-Agent", USER_AGENT), ("Proxy-Connection", "keep-alive")]
            if cred is not None:
                headers.append(("Proxy-Authorization", basic_value(cred)))
            conn.send(encode_head("CONNECT %s HTTP/1.1" % tgt.authority, headers))
            ok = False
            while True:
                version, status, reason, rheaders = conn.read_head()
                if status >= 200:
                    break
            if 200 <= status < 300:
                extra.append(Response(status, reason, rheaders, b"", True).text())
                ok = True
            else:
                # 失败的 CONNECT：先按头把响应记下来，正文读不全也不影响报错文字
                rec = Response(status, reason, rheaders, b"", False)
                extra.append(rec.text())
                try:
                    low = {n.lower(): v for n, v in rheaders}
                    if "content-length" in low:
                        rec.body = conn.read_exact(int(low["content-length"]))
                    elif status not in (204, 304):
                        rec.body = conn.read_to_eof()
                except (RawrefError, ValueError):
                    pass
                extra[-1] = rec.text()
                raise RawrefError("rawref: CONNECT failed: %d %s" % (status, reason))
            if ok:
                self.start_tls(conn, tgt.host)
            return conn
        except BaseException:
            conn.close()
            raise

    def open_socks(self, cred, tgt, deadline):
        user = pwd = b""
        if cred is not None:
            user, pwd = cred[0].encode("utf-8"), cred[1].encode("utf-8")
            if len(user) > 255 or len(pwd) > 255:
                raise RawrefError(ERR_SOCKS_CRED)
        if self.proxy_scheme == "socks5h":
            name = tgt.host.encode("idna") if not tgt.host.isascii() else tgt.host.encode("ascii")
            if len(name) > 255:
                raise RawrefError(ERR_RESOLVE)
            addr = b"\x03" + bytes([len(name)]) + name
        else:
            addr = self.resolve(tgt.host, tgt.port)
        conn = self.dial_proxy(deadline)
        try:
            conn.send(b"\x05\x01\x00" if cred is None else b"\x05\x02\x00\x02")
            ver, method = conn.read_exact(2)
            if method == 0xFF:
                raise RawrefError(ERR_SOCKS_METHOD)
            if method == 0x02 and cred is not None:
                conn.send(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
                _, st = conn.read_exact(2)
                if st != 0:
                    raise RawrefError("rawref: socks auth failed status=%d" % st)
            elif method != 0x00:
                raise RawrefError("rawref: socks unexpected method %d" % method)
            conn.send(b"\x05\x01\x00" + addr + tgt.port.to_bytes(2, "big"))
            _, rep, _, atyp = conn.read_exact(4)
            if rep != 0:
                raise RawrefError("rawref: socks reply %d" % rep)
            if atyp == 1:
                conn.read_exact(4 + 2)
            elif atyp == 4:
                conn.read_exact(16 + 2)
            elif atyp == 3:
                conn.read_exact(conn.read_exact(1)[0] + 2)
            else:
                raise RawrefError("rawref: socks bad reply")
            if tgt.secure:
                self.start_tls(conn, tgt.host)
            return conn
        except BaseException:
            conn.close()
            raise

    @staticmethod
    def resolve(host, port):
        """socks5：客户端自己解析。结果里有 IPv4 就用第一个 IPv4，否则用第一个 IPv6。"""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except (socket.gaierror, UnicodeError):
                raise RawrefError(ERR_RESOLVE) from None
            v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
            v6 = [i[4][0].split("%")[0] for i in infos if i[0] == socket.AF_INET6]
            if not v4 and not v6:
                raise RawrefError(ERR_RESOLVE) from None
            ip = ipaddress.ip_address(v4[0] if v4 else v6[0])
        return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed

    def open(self, cred, tgt, deadline, extra):
        if self.proxy_scheme == "http":
            if tgt.secure:
                return self.open_http_tunnel(cred, tgt, deadline, extra)
            return self.dial_proxy(deadline)
        if self.proxy_scheme in ("socks5", "socks5h"):
            return self.open_socks(cred, tgt, deadline)
        raise RawrefError("rawref: unsupported proxy scheme")

    # ---------- 一次请求、响应 ----------

    def exchange(self, cred, method, url, body, deadline, pooled, extra, ws=False):
        tgt = Target(url)
        absolute = self.proxy_scheme == "http" and not tgt.secure
        if absolute:
            key = ("plain", cred)
        else:
            key = (cred, "tls" if tgt.secure else "tcp", tgt.host, tgt.port)
        pooled = pooled and not ws
        conn = self.pool.get(key) if pooled else None
        if conn is None:
            conn = self.open(cred, tgt, deadline, extra)
            if pooled:
                self.pool[key] = conn
        conn.deadline = deadline
        headers = [("Host", tgt.host_header), ("User-Agent", USER_AGENT)]
        if ws:
            headers += [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", WS_KEY),
                ("Sec-WebSocket-Version", "13"),
            ]
        else:
            headers.append(("Accept", "*/*"))
            if absolute:
                headers.append(("Proxy-Connection", "keep-alive"))
        if absolute and cred is not None:
            headers.append(("Proxy-Authorization", basic_value(cred)))
        if body is not None:
            headers += [("Content-Type", "application/octet-stream"), ("Content-Length", str(len(body)))]
        line = "%s %s HTTP/1.1" % (method, tgt.absolute_form if absolute else tgt.origin_form)
        try:
            conn.send(encode_head(line, headers) + (body or b""))
            resp = conn.read_response()
            if ws and resp.status == 101:
                want = base64.b64encode(hashlib.sha1((WS_KEY + WS_GUID).encode("ascii")).digest()).decode("ascii")
                if resp.header("Sec-WebSocket-Accept") != want:
                    raise RawrefError("rawref: websocket accept mismatch")
                # 不发任何帧；等对端关闭（最多 2 秒）再关，免得带着没读的数据关连接
                conn.deadline = min(deadline, time.monotonic() + WS_DRAIN_S)
                try:
                    conn.read_to_eof()
                except RawrefError:
                    pass
        except BaseException:
            if self.pool.get(key) is conn:
                del self.pool[key]
            conn.close()
            raise
        if not pooled or not resp.keep:
            if self.pool.get(key) is conn:
                del self.pool[key]
            conn.close()
        return resp

    def request(self, cred, method, url, body, follow, deadline, pooled, extra):
        hops = 0
        while True:
            resp = self.exchange(cred, method, url, body, deadline, pooled, extra)
            loc = resp.header("Location")
            if not follow or hops >= MAX_REDIRECTS or resp.status not in (301, 302, 303, 307, 308) or not loc:
                return resp
            hops += 1
            url = urljoin(url, loc)
            if resp.status in (301, 302, 303):
                method, body = "GET", None

    def close_all(self):
        for conn in self.pool.values():
            conn.close()
        self.pool.clear()


# ---------- 步骤 ----------


def run_step(client, case, st, pooled):
    users = case.get("users", [])
    timeout_s = st.get("timeout_s", case.get("timeout_s", 15))
    cred = None
    if st.get("user") is not None:
        u = users[st["user"]]
        cred = (u["user"], u["pass"])
    t0 = time.monotonic()
    deadline = t0 + timeout_s
    extra = []
    res = {"id": st["id"], "ok": False, "status": None, "body_sha256": None, "ms": None,
           "default_text": None, "extra_text": None, "extra_how": None}
    try:
        if st["op"] == "ws":
            resp = client.exchange(cred, "GET", st["url"], None, deadline, False, extra, ws=True)
        else:
            method = st.get("method", "GET")
            body = None
            if st.get("body_file"):
                with open(st["body_file"], "rb") as fh:
                    body = fh.read()
            elif method in ("POST", "PUT", "PATCH"):
                body = b""
            resp = client.request(cred, method, st["url"], body, bool(st.get("follow")), deadline, pooled, extra)
        res["ok"] = True
        res["status"] = resp.status
        res["body_sha256"] = hashlib.sha256(resp.body).hexdigest()
        res["default_text"] = resp.text()
    except RawrefError as e:
        res["default_text"] = str(e)
    except Exception as e:  # 任何异常都落到这一步的结果里
        res["default_text"] = "rawref: internal error: %s: %s" % (type(e).__name__, e)
    res["ms"] = int(round((time.monotonic() - t0) * 1000))
    if extra:
        res["extra_text"] = "\n".join(extra)
        res["extra_how"] = EXTRA_HOW
    return res


def run_parallel(client, case, st):
    kids = st.get("steps", [])
    out = [None] * len(kids)
    gate = threading.Barrier(len(kids)) if kids else None

    def work(i, kid):
        try:
            gate.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        out[i] = run_step(client, case, kid, False)

    threads = [threading.Thread(target=work, args=(i, kid), daemon=True) for i, kid in enumerate(kids)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return out


def run_case(case):
    result = {"variant": "rawref", "versions": {"rawref": VERSION}, "config": CONFIG, "unsupported": None,
              "steps": [], "runtime": {"python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION}}
    client = Client(case)
    try:
        for st in case.get("steps", []):
            op = st.get("op")
            blank = {"id": st.get("id"), "op": op, "ok": None, "status": None, "body_sha256": None, "ms": None,
                     "default_text": None, "extra_text": None, "extra_how": None}
            if op in ("request", "ws"):
                result["steps"].append(run_step(client, case, st, True))
            elif op == "parallel":
                t0 = time.monotonic()
                kids = run_parallel(client, case, st)
                blank["ms"] = int(round((time.monotonic() - t0) * 1000))
                blank["children"] = [k["id"] for k in st.get("steps", [])]
                result["steps"].append(blank)
                result["steps"] += kids
            elif op == "sleep":
                time.sleep(st.get("ms", 0) / 1000.0)
                blank["ms"] = st.get("ms")
                result["steps"].append(blank)
            else:
                blank["ok"] = False
                blank["default_text"] = "rawref: unknown step op"
                result["steps"].append(blank)
    finally:
        client.close_all()
    return result


def main(argv):
    if "--versions" in argv:
        json.dump({"rawref": VERSION}, sys.stdout)
        sys.stdout.write("\n")
        return 0
    if len(argv) != 2:
        print("用法：driver.py <用例.json> <结果.json> | driver.py --versions", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        case = json.load(fh)
    result = run_case(case)
    tmp = argv[1] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    os.replace(tmp, argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
