package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A02：CONNECT 建隧道，隧道里 TLS，再发 HTTP/1.1 的请求。逐项核对隧道相关的事件。
func TestConnectTunnelTLS(t *testing.T) {
	e := startEnv(t, `{"connect":{"ok_headers":[["X-Kaoju-Note","KaojuHeaderMarker"],["Proxy-Status","kaoju; details=\"KaojuStatusMarker\""]]}}`)
	c := e.dialProxy()
	connectReq := "CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\nUser-Agent: rawtest/1\r\n\r\n"
	c.send(connectReq)
	r := c.readResp()
	wantEq(t, "CONNECT 的状态码", r.status, 200)
	wantEq(t, "CONNECT 的原因短语", r.reason, "Connection established")
	wantPairs(t, "200 里的头（只有 connect.ok_headers）", r.headers, [][2]string{
		{"X-Kaoju-Note", "KaojuHeaderMarker"}, {"Proxy-Status", `kaoju; details="KaojuStatusMarker"`},
	})
	afterConnect := c.received()

	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	st := tc.tc.ConnectionState()
	wantEq(t, "协商出的 ALPN", st.NegotiatedProtocol, "http/1.1")
	leaf := st.PeerCertificates[0]
	wantEq(t, "证书的 DNS 名字", strings.Join(leaf.DNSNames, ","), "*.kaoju.test,localhost")
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("证书的 IP 名字应当只有 127.0.0.1: %v", leaf.IPAddresses)
	}

	tc.send(getReq("/echo?k=A02.s1", "a.kaoju.test", "Proxy-Authorization: Basic c2hvdWxkOm5vdA==\r\n"))
	echo := tc.readResp().echo(t)
	wantEq(t, "echo.k", echo.str("k"), "A02.s1")
	wantEq(t, "echo.tls", echo["tls"], any(true))
	wantEq(t, "echo.via", echo.str("via"), "tunnel")
	wantEq(t, "echo.proto", echo.str("proto"), "HTTP/1.1")
	wantEq(t, "echo.host", echo.str("host"), "a.kaoju.test")
	wantEq(t, "echo.origin_conn", echo.num("origin_conn"), 1)
	wantEq(t, "echo.seq", echo.num("seq"), 1)
	tc.send(getReq("/echo?k=A02.s2", "a.kaoju.test"))
	wantEq(t, "同一条隧道里的第 2 个请求 echo.seq", tc.readResp().echo(t).num("seq"), 2)
	tc.close()

	evs := e.stop()
	id := e.connID(c)
	ce := evs.conn(id)
	wantEq(t, "事件序列", ce.names(),
		"accept first_bytes http_request http_response tunnel_open tunnel_first_bytes origin_conn origin_request origin_request tunnel_close conn_end")

	hr := ce.of("http_request")[0]
	wantEq(t, "http_request.form", hr.str("form"), "connect")
	wantEq(t, "http_request.method", hr.str("method"), "CONNECT")
	wantEq(t, "http_request.target", hr.str("target"), "a.kaoju.test:443")
	if hr["k"] != nil {
		t.Errorf("CONNECT 没有 k: %v", hr["k"])
	}
	hp := ce.of("http_response")[0]
	wantEq(t, "http_response.status", hp.num("status"), 200)
	wantEq(t, "http_response.reason", hp.str("reason"), "Connection established")
	wantEq(t, "http_response.cause", hp.str("cause"), "connect_ok")
	wantEq(t, "http_response.by", hp.str("by"), "proxy")
	wantPairs(t, "http_response.headers", hp.pairs("headers"), r.headers)

	to := ce.of("tunnel_open")[0]
	wantEq(t, "tunnel_open.tunnel", to.num("tunnel"), 1)
	wantEq(t, "tunnel_open.via", to.str("via"), "connect")
	wantEq(t, "tunnel_open.req_seq", to.num("req_seq"), 1)
	wantEq(t, "tunnel_open.target_host", to.str("target_host"), "a.kaoju.test")
	wantEq(t, "tunnel_open.target_port", to.num("target_port"), 443)
	wantEq(t, "tunnel_open.mapped", to.str("mapped"), "origin_https")

	// 测试这边 CONNECT 之后的第一次写就是 ClientHello（crypto/tls 一次写出一条完整的记录）。
	helloLen := c.writes[1]
	tf := ce.of("tunnel_first_bytes")[0]
	wantEq(t, "tunnel_first_bytes.tunnel", tf.num("tunnel"), 1)
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "tls_client_hello")
	wantEq(t, "tunnel_first_bytes.n_first_read", tf.num("n_first_read"), helloLen)
	wantEq(t, "tunnel_first_bytes.n_buffered", tf.num("n_buffered"), helloLen)
	wantEq(t, "tunnel_first_bytes.early_bytes", tf.num("early_bytes"), 0)
	if h := tf.str("hex"); len(h) != 32 || !strings.HasPrefix(h, "160301") && !strings.HasPrefix(h, "160303") {
		t.Errorf("tunnel_first_bytes.hex = %q", h)
	}
	th := tf.obj("tls")
	wantEq(t, "tls.record_len", th.num("record_len"), helloLen-5)
	wantEq(t, "tls.complete", th["complete"], any(true))
	wantEq(t, "tls.sni", th.str("sni"), "a.kaoju.test")
	wantEq(t, "tls.alpn", strings.Join(th.strs("alpn"), ","), "http/1.1")
	wantEq(t, "tls.legacy_version", th.num("legacy_version"), 0x0303)
	if vs := th.ints("versions"); len(vs) == 0 || vs[0] != 0x0304 {
		t.Errorf("tls.versions 应以 TLS 1.3（0x0304=772）开头: %v", vs)
	}
	if gs := th.ints("groups"); len(gs) == 0 {
		t.Error("tls.groups 不应为空")
	}
	if ks := th.ints("key_shares"); len(ks) == 0 {
		t.Error("tls.key_shares 不应为空")
	}
	if th["parse_error"] != nil {
		t.Errorf("tls.parse_error = %v", th["parse_error"])
	}

	oc := ce.of("origin_conn")[0]
	wantEq(t, "origin_conn.oconn", oc.num("oconn"), 1)
	wantEq(t, "origin_conn.via", oc.str("via"), "tunnel")
	wantEq(t, "origin_conn.tunnel", oc.num("tunnel"), 1)
	wantEq(t, "origin_conn.listener", oc.str("listener"), "origin_https")
	wantEq(t, "origin_conn.tls", oc["tls"], any(true))
	wantEq(t, "origin_conn.alpn", oc.str("alpn"), "http/1.1")
	wantEq(t, "origin_conn.tls_version", oc.str("tls_version"), "TLS 1.3")
	wantEq(t, "origin_conn.sni", oc.str("sni"), "a.kaoju.test")
	if oc["error"] != nil {
		t.Errorf("origin_conn.error = %v", oc["error"])
	}

	ors := ce.of("origin_request")
	or := ors[0]
	wantEq(t, "origin_request.via", or.str("via"), "tunnel")
	wantEq(t, "origin_request.oconn", or.num("oconn"), 1)
	wantEq(t, "origin_request.tunnel", or.num("tunnel"), 1)
	wantEq(t, "origin_request.seq", or.num("seq"), 1)
	wantEq(t, "origin_request.k", or.str("k"), "A02.s1")
	wantEq(t, "origin_request.proto", or.str("proto"), "HTTP/1.1")
	wantEq(t, "origin_request.host", or.str("host"), "a.kaoju.test")
	wantEq(t, "origin_request.tls", or["tls"], any(true))
	wantEq(t, "origin_request.has_proxy_authorization（隧道里带了）", or["has_proxy_authorization"], any(true))
	wantEq(t, "第 2 个 origin_request.seq", ors[1].num("seq"), 2)
	wantEq(t, "第 2 个 origin_request.has_proxy_authorization", ors[1]["has_proxy_authorization"], any(false))
	if or["req_seq"] != nil {
		t.Errorf("隧道里的 origin_request 的 req_seq 应为 null: %v", or["req_seq"])
	}

	tcl := ce.of("tunnel_close")[0]
	wantEq(t, "tunnel_close.by", tcl.str("by"), "client")
	wantEq(t, "tunnel_close.bytes_c2s", int64(tcl.num("bytes_c2s")), c.sent()-int64(len(connectReq)))
	wantEq(t, "tunnel_close.bytes_s2c", int64(tcl.num("bytes_s2c")), c.received()-afterConnect)
	end := ce.of("conn_end")[0]
	wantEq(t, "conn_end.by", end.str("by"), "client")
	wantEq(t, "conn_end.close", end.str("close"), "fin")
}

// CONNECT 用 HTTP/1.0 的请求行（有的客户端这样发）：照常建隧道，响应写 HTTP/1.1。
func TestConnectHTTP10(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("CONNECT a.kaoju.test:443 HTTP/1.0\r\n\r\n")
	r := c.readResp()
	wantEq(t, "状态码", r.status, 200)
	wantEq(t, "协议", r.proto, "HTTP/1.1")
	wantEq(t, "200 里的头的个数", len(r.headers), 0)
	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	tc.send(getReq("/echo?k=C10.s1", "a.kaoju.test"))
	wantEq(t, "隧道里的请求", tc.readResp().echo(t).str("k"), "C10.s1")
	tc.close()
	evs := e.stop()
	wantEq(t, "http_request.version", evs.of("http_request")[0].str("version"), "HTTP/1.0")
}

// 到 80 端口的隧道接明文源站：首批字节归为 http；按源站端口号连也能对上。
func TestConnectTunnelPlainAndPortMapping(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("b.kaoju.test:80")
	req := getReq("/echo?k=P80.s1", "b.kaoju.test")
	c.send(req)
	echo := c.readResp().echo(t)
	wantEq(t, "echo.tls", echo["tls"], any(false))
	wantEq(t, "echo.via", echo.str("via"), "tunnel")
	wantEq(t, "echo.host", echo.str("host"), "b.kaoju.test")
	c.finish()

	c2 := e.dialProxy()
	c2.connect(fmt.Sprintf("localhost:%d", e.hp))
	c2.send(getReq("/echo?k=P80.s2", "localhost"))
	wantEq(t, "按明文源站端口号连", c2.readResp().echo(t).str("k"), "P80.s2")
	c2.finish()

	c3 := e.dialProxy()
	c3.connect(fmt.Sprintf("localhost:%d", e.sp))
	tc := e.startTLS(c3, "localhost", "http/1.1")
	tc.send(getReq("/echo?k=P80.s3", "localhost"))
	wantEq(t, "按 HTTPS 源站端口号连", tc.readResp().echo(t).str("k"), "P80.s3")
	tc.close()

	// IPv6 字面量作目标也能解析。
	c4 := e.dialProxy()
	c4.connect("[::1]:80")
	c4.send(getReq("/echo?k=P80.s4", "[::1]"))
	wantEq(t, "IPv6 字面量", c4.readResp().echo(t).str("k"), "P80.s4")
	c4.finish()

	evs := e.stop()
	tf := evs.conn(e.connID(c)).of("tunnel_first_bytes")[0]
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "http")
	wantEq(t, "tunnel_first_bytes.n_first_read", tf.num("n_first_read"), len(req))
	wantEq(t, "tunnel_first_bytes.hex", tf.str("hex"), hex.EncodeToString([]byte(req[:16])))
	if tf["tls"] != nil {
		t.Errorf("明文的首批字节 tls 应为 null: %v", tf["tls"])
	}
	oc := evs.conn(e.connID(c)).of("origin_conn")[0]
	wantEq(t, "origin_conn.listener", oc.str("listener"), "origin_http")
	wantEq(t, "origin_conn.tls", oc["tls"], any(false))
	if oc["alpn"] != nil || oc["sni"] != nil || oc["tls_version"] != nil {
		t.Errorf("明文的 origin_conn 不应有 TLS 的字段: %v", oc)
	}
	opens := evs.of("tunnel_open")
	wantEq(t, "tunnel_open 的个数", len(opens), 4)
	wantEq(t, "隧道 2 的 mapped", opens[1].str("mapped"), "origin_http")
	wantEq(t, "隧道 2 的 target_port", opens[1].num("target_port"), e.hp)
	wantEq(t, "隧道 3 的 mapped", opens[2].str("mapped"), "origin_https")
	wantEq(t, "隧道 4 的 target_host", opens[3].str("target_host"), "::1")
	wantEq(t, "隧道 3 的 SNI", evs.conn(e.connID(c3)).of("origin_conn")[0].str("sni"), "localhost")
}

// earlyConn 把 CONNECT 请求和隧道里的第一次写（ClientHello）合在一次写里发出去，不等 200。
type earlyConn struct {
	*rawConn
	prefix   string
	wrote    bool
	stripped bool
}

func (c *earlyConn) Write(p []byte) (int, error) {
	if c.wrote {
		return c.rawConn.Write(p)
	}
	c.wrote = true
	n, err := c.rawConn.Write(append([]byte(c.prefix), p...))
	return max(0, n-len(c.prefix)), err
}

func (c *earlyConn) Read(p []byte) (int, error) {
	if !c.stripped {
		c.stripped = true
		if r := c.rawConn.readResp(); r.status != 200 {
			return 0, fmt.Errorf("CONNECT 得到 %d", r.status)
		}
	}
	return c.rawConn.Read(p)
}

// 客户端没等 200 就把 ClientHello 发来了：这些字节原样进隧道，early_bytes 记下有多少。
func TestConnectEarlyData(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	connectReq := "CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\n\r\n"
	ec := &earlyConn{rawConn: c, prefix: connectReq}
	tc := e.startTLS(ec, "a.kaoju.test", "http/1.1")
	tc.send(getReq("/echo?k=EARLY.s1", "a.kaoju.test"))
	wantEq(t, "隧道里的请求", tc.readResp().echo(t).str("k"), "EARLY.s1")
	tc.close()
	evs := e.stop()
	helloLen := c.writes[0] - len(connectReq)
	fb := one(t, evs.of("first_bytes"), "first_bytes")
	wantEq(t, "first_bytes.n_first_read（请求和 ClientHello 一起到）", fb.num("n_first_read"), c.writes[0])
	tf := one(t, evs.of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "tunnel_first_bytes.early_bytes", tf.num("early_bytes"), helloLen)
	wantEq(t, "tunnel_first_bytes.n_first_read", tf.num("n_first_read"), helloLen)
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "tls_client_hello")
	wantEq(t, "tls.record_len", tf.obj("tls").num("record_len"), helloLen-5)
	tcl := one(t, evs.of("tunnel_close"), "tunnel_close")
	wantEq(t, "tunnel_close.bytes_c2s（含提前发来的）", int64(tcl.num("bytes_c2s")), c.sent()-int64(len(connectReq)))
}

// splitConn 把某一次写拆成两次，中间停一会儿，模拟 ClientHello 跨两个 TCP 包到达。
type splitConn struct {
	*rawConn
	at   int
	gap  time.Duration
	done bool
}

func (c *splitConn) Write(p []byte) (int, error) {
	if c.done || len(p) <= c.at {
		return c.rawConn.Write(p)
	}
	c.done = true
	n1, err := c.rawConn.Write(p[:c.at])
	if err != nil {
		return n1, err
	}
	time.Sleep(c.gap)
	n2, err := c.rawConn.Write(p[c.at:])
	return n1 + n2, err
}

// ClientHello 分两次到：等整条记录到齐再解析，但第一次读到多少照实记录；源站看到的字节一个不少。
func TestTunnelClientHelloSplit(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:443")
	sc := &splitConn{rawConn: c, at: 100, gap: 200 * time.Millisecond}
	tc := e.startTLS(sc, "a.kaoju.test", "h2", "http/1.1")
	wantEq(t, "协商出的 ALPN", tc.tc.ConnectionState().NegotiatedProtocol, "h2")
	tc.close()
	evs := e.stop()
	helloLen := c.writes[1] + c.writes[2]
	tf := one(t, evs.of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "tunnel_first_bytes.n_first_read", tf.num("n_first_read"), 100)
	wantEq(t, "tunnel_first_bytes.n_buffered", tf.num("n_buffered"), helloLen)
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "tls_client_hello")
	th := tf.obj("tls")
	wantEq(t, "tls.record_len", th.num("record_len"), helloLen-5)
	wantEq(t, "tls.complete", th["complete"], any(true))
	wantEq(t, "tls.alpn", strings.Join(th.strs("alpn"), ","), "h2,http/1.1")
	wantEq(t, "tls.sni", th.str("sni"), "a.kaoju.test")
	// 握手成功本身说明多读的那部分字节原样交给了源站。
	wantEq(t, "origin_conn.alpn", one(t, evs.of("origin_conn"), "origin_conn").str("alpn"), "h2")
}

// 隧道里不是 TLS 也不是 HTTP：归为 other；HTTPS 源站握手失败，记在 origin_conn.error 里，然后关。
func TestTunnelGarbageToHTTPS(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:443")
	c.send("\x00\x01\x02 not tls at all\r\n")
	_ = c.tcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.Copy(io.Discard, c) // 源站回一个 TLS 警报，然后 FIN
	if err != nil {
		t.Fatalf("应当读到 EOF: %v", err)
	}
	c.finish()
	evs := e.stop()
	tf := one(t, evs.of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "other")
	oc := one(t, evs.of("origin_conn"), "origin_conn")
	if oc.str("error") == "" {
		t.Errorf("origin_conn.error 应当写明握手失败的原因: %v", oc)
	}
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 0)
	wantEq(t, "tunnel_close.by", one(t, evs.of("tunnel_close"), "tunnel_close").str("by"), "origin")
	end := one(t, evs.of("conn_end"), "conn_end")
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.reason", end.str("reason"), "tls_handshake_failed")
}

// 隧道建好以后客户端一个字节不发就关：没有 tunnel_first_bytes，tunnel_close 记 client、字节数为 0。
func TestTunnelClosedWithoutBytes(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:443")
	c.finish()
	evs := e.stop()
	wantEq(t, "事件序列", evs.conn(e.connID(c)).names(), "accept first_bytes http_request http_response tunnel_open tunnel_close conn_end")
	tcl := one(t, evs.of("tunnel_close"), "tunnel_close")
	wantEq(t, "tunnel_close.by", tcl.str("by"), "client")
	wantEq(t, "tunnel_close.bytes_c2s", tcl.num("bytes_c2s"), 0)
	wantEq(t, "tunnel_close.bytes_s2c", tcl.num("bytes_s2c"), 0)
}

// connect.fail：不建隧道，回配置里写的响应（E01）。
func TestConnectFail(t *testing.T) {
	e := startEnv(t, `{"connect":{"fail":{"status":502,"reason":"KaojuReasonMarker",
		"headers":[["X-Kaoju-Note","KaojuHeaderMarker"],["Proxy-Status","kaoju; error=destination_unavailable; details=\"KaojuStatusMarker\""]],
		"body":"KaojuBodyMarker\n","close":true}}}`)
	c := e.dialProxy()
	c.send("CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\n\r\n")
	r := c.readResp()
	wantEq(t, "响应的原文", r.head+string(r.body), "HTTP/1.1 502 KaojuReasonMarker\r\n"+
		"X-Kaoju-Note: KaojuHeaderMarker\r\n"+
		"Proxy-Status: kaoju; error=destination_unavailable; details=\"KaojuStatusMarker\"\r\n"+
		"Content-Length: 16\r\n"+
		"Connection: close\r\n"+
		"\r\n"+
		"KaojuBodyMarker\n")
	c.expectEOF(3 * time.Second)
	c.finish()
	evs := e.stop()
	wantEq(t, "事件序列", evs.conn(e.connID(c)).names(), "accept first_bytes http_request http_response conn_end")
	hp := one(t, evs.of("http_response"), "http_response")
	wantEq(t, "http_response.status", hp.num("status"), 502)
	wantEq(t, "http_response.reason", hp.str("reason"), "KaojuReasonMarker")
	wantEq(t, "http_response.cause", hp.str("cause"), "connect_fail")
	wantEq(t, "http_response.close", hp["close"], any(true))
	wantEq(t, "http_response.body_len", hp.num("body_len"), 16)
	end := one(t, evs.of("conn_end"), "conn_end")
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.reason", end.str("reason"), "response_close")
}

// connect.fail 的 hosts 和 close=false（E07）：只对列出的主机失败，连接留着，接着 CONNECT 别的主机能成。
func TestConnectFailHostsKeepAlive(t *testing.T) {
	e := startEnv(t, `{"connect":{"fail":{"status":502,"reason":"KaojuReasonMarker","body":"KaojuBodyMarker\n","close":false,"hosts":["fail.kaoju.test"]}}}`)
	c := e.dialProxy()
	c.send("CONNECT fail.kaoju.test:443 HTTP/1.1\r\nHost: fail.kaoju.test:443\r\n\r\n")
	r := c.readResp()
	wantEq(t, "对 fail.kaoju.test", r.status, 502)
	if _, ok := r.get("Connection"); ok {
		t.Error("close 为假时不应带 Connection 头")
	}
	wantEq(t, "正文", string(r.body), "KaojuBodyMarker\n")
	c.connect("a.kaoju.test:443")
	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	tc.send(getReq("/echo?k=E07.s2", "a.kaoju.test"))
	wantEq(t, "同一条连接上的第二个 CONNECT", tc.readResp().echo(t).str("k"), "E07.s2")
	tc.close()
	evs := e.stop()
	wantEq(t, "代理连接数", len(evs.of("accept")), 1)
	wantEq(t, "tunnel_open.req_seq", one(t, evs.of("tunnel_open"), "tunnel_open").num("req_seq"), 2)
}

// origin.h2：为真时 HTTPS 源站协商出 h2，为假时只有 http/1.1。
func TestOriginH2Switch(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			e := startEnv(t, fmt.Sprintf(`{"origin":{"h2":%v}}`, h2))
			c := e.dialProxy()
			c.connect("a.kaoju.test:443")
			tc := e.startTLS(c, "a.kaoju.test", "h2", "http/1.1")
			want := map[bool]string{true: "h2", false: "http/1.1"}[h2]
			wantEq(t, "协商出的 ALPN", tc.tc.ConnectionState().NegotiatedProtocol, want)
			if !h2 {
				tc.send(getReq("/echo?k=H2OFF.s1", "a.kaoju.test"))
				wantEq(t, "echo.proto", tc.readResp().echo(t).str("proto"), "HTTP/1.1")
			}
			tc.close()

			// 只提供 h2 的客户端：源站不支持时握手失败（no_application_protocol）。
			c2 := e.dialProxy()
			c2.connect("a.kaoju.test:443")
			tc2 := tls.Client(c2, &tls.Config{RootCAs: e.pool, ServerName: "a.kaoju.test", NextProtos: []string{"h2"}})
			_ = c2.SetDeadline(time.Now().Add(3 * time.Second))
			err := tc2.Handshake()
			if h2 && err != nil {
				t.Errorf("源站支持 h2 时只提供 h2 的握手应当成功: %v", err)
			}
			if !h2 && err == nil {
				t.Error("源站不支持 h2 时只提供 h2 的握手应当失败")
			}
			_ = c2.SetDeadline(time.Time{})
			if err == nil {
				_ = tc2.Close()
			}
			c2.finish()

			evs := e.stop()
			oc := evs.conn(e.connID(c)).of("origin_conn")[0]
			wantEq(t, "origin_conn.alpn", oc.str("alpn"), want)
			oc2 := evs.conn(e.connID(c2)).of("origin_conn")[0]
			if h2 {
				wantEq(t, "只提供 h2 的 origin_conn.alpn", oc2.str("alpn"), "h2")
			} else if oc2.str("error") == "" {
				t.Errorf("只提供 h2 而源站不支持：origin_conn.error 应当非空: %v", oc2)
			}
			wantEq(t, "start.profile.origin.h2", evs[0].obj("profile").obj("origin")["h2"], any(h2))
		})
	}
}

// h2Client 返回一个只在隧道里说话的 HTTP 客户端：到代理的那一段（CONNECT）仍然是测试用裸套接字自己写的，
// 隧道里的 TLS 和 h2 成帧交给标准库。它不配代理，也不读环境变量。
func (e *env) h2Client() (*http.Client, func() []*rawConn) {
	var conns []*rawConn
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c := e.dialProxy()
			conns = append(conns, c)
			c.send("CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n")
			if r := c.readResp(); r.status != 200 {
				return nil, fmt.Errorf("CONNECT 得到 %d", r.status)
			}
			host, _, _ := net.SplitHostPort(addr)
			tc := tls.Client(c, &tls.Config{RootCAs: e.pool, ServerName: host, NextProtos: []string{"h2", "http/1.1"}})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		},
	}
	e.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, func() []*rawConn { return conns }
}

// 隧道里走 h2：请求在同一条源站连接上按流计数。
func TestTunnelH2Requests(t *testing.T) {
	e := startEnv(t, `{}`)
	client, conns := e.h2Client()
	for i := 1; i <= 3; i++ {
		res, err := client.Get(fmt.Sprintf("https://a.kaoju.test/echo?k=H2.s%d", i))
		if err != nil {
			t.Fatalf("第 %d 个请求失败: %v", i, err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		wantEq(t, "响应的协议", res.Proto, "HTTP/2.0")
		wantEq(t, "状态码", res.StatusCode, 200)
		if !strings.Contains(string(body), fmt.Sprintf(`"k":"H2.s%d"`, i)) || !strings.Contains(string(body), `"proto":"HTTP/2.0"`) {
			t.Errorf("第 %d 个响应的正文不对: %s", i, body)
		}
	}
	// POST 的正文在 h2 下同样读完、算哈希。
	body := pattern(100000)
	res, err := client.Post("https://a.kaoju.test/echo?k=H2.s4", "application/octet-stream", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(rb), sha256hex(body)) {
		t.Errorf("h2 POST 的 echo 里没有正文的哈希: %s", rb)
	}
	client.CloseIdleConnections()
	wantEq(t, "隧道数", len(conns()), 1)
	evs := e.stop()
	ors := evs.of("origin_request")
	wantEq(t, "origin_request 的个数", len(ors), 4)
	for i, or := range ors {
		wantEq(t, "origin_request.proto", or.str("proto"), "HTTP/2.0")
		wantEq(t, "origin_request.seq", or.num("seq"), i+1)
		wantEq(t, "origin_request.oconn", or.num("oconn"), 1)
		wantEq(t, "origin_request.host", or.str("host"), "a.kaoju.test")
	}
	wantEq(t, "POST 的 origin_request.body_len", ors[3].num("body_len"), len(body))
	wantEq(t, "POST 的 origin_request.body_sha256", ors[3].str("body_sha256"), sha256hex(body))
	wantEq(t, "origin_conn.alpn", one(t, evs.of("origin_conn"), "origin_conn").str("alpn"), "h2")
	wantEq(t, "tunnel_open 的个数", len(evs.of("tunnel_open")), 1)
}

// 直接连到源站端口（绕过代理）：照样有 accept、first_bytes、origin_conn（via=direct）、conn_end。
func TestDirectToOrigin(t *testing.T) {
	e := startEnv(t, `{"origin":{"drop":{"k":"DIRECT.s1","times":5,"how":"rst"}}}`)
	c := e.dial(e.hp, "origin_http")
	req := getReq("/echo?k=DIRECT.s1", "localhost")
	c.send(req)
	echo := c.readResp().echo(t)
	wantEq(t, "echo.via", echo.str("via"), "direct")
	wantEq(t, "echo.tls", echo["tls"], any(false))
	c.finish()

	c2 := e.dial(e.sp, "origin_https")
	tc := e.startTLS(c2, "localhost", "http/1.1")
	tc.send(getReq("/echo?k=DIRECT.s1", "localhost"))
	echo2 := tc.readResp().echo(t)
	wantEq(t, "HTTPS 直连 echo.via", echo2.str("via"), "direct")
	wantEq(t, "HTTPS 直连 echo.tls", echo2["tls"], any(true))
	tc.close()

	// 证书对 127.0.0.1 也有效。
	c3 := e.dial(e.sp, "origin_https")
	tc3 := e.startTLS(c3, "127.0.0.1", "http/1.1")
	tc3.close()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "明文直连的事件序列", ce.names(), "accept first_bytes origin_conn origin_request conn_end")
	wantEq(t, "accept.listener", ce[0].str("listener"), "origin_http")
	wantEq(t, "first_bytes.listener", ce[1].str("listener"), "origin_http")
	wantEq(t, "first_bytes.kind", ce[1].str("kind"), "http")
	wantEq(t, "first_bytes.n_first_read", ce[1].num("n_first_read"), len(req))
	oc := ce[2]
	wantEq(t, "origin_conn.via", oc.str("via"), "direct")
	wantEq(t, "origin_conn.listener", oc.str("listener"), "origin_http")
	if oc["tunnel"] != nil {
		t.Errorf("直连的 origin_conn.tunnel 应为 null: %v", oc["tunnel"])
	}
	or := ce[3]
	wantEq(t, "origin_request.via", or.str("via"), "direct")
	wantEq(t, "origin_request.action（origin.drop 只对隧道里的请求生效）", or.str("action"), "respond")
	if or["tunnel"] != nil {
		t.Errorf("直连的 origin_request.tunnel 应为 null: %v", or["tunnel"])
	}
	wantEq(t, "conn_end.listener", ce[4].str("listener"), "origin_http")

	ce2 := evs.conn(e.connID(c2))
	wantEq(t, "HTTPS 直连的事件序列", ce2.names(), "accept first_bytes origin_conn origin_request conn_end")
	wantEq(t, "HTTPS 直连 first_bytes.kind", ce2[1].str("kind"), "tls")
	wantEq(t, "HTTPS 直连 origin_conn.tls", ce2[2]["tls"], any(true))
	wantEq(t, "HTTPS 直连 origin_conn.sni", ce2[2].str("sni"), "localhost")
	wantEq(t, "tunnel_open 的个数", len(evs.of("tunnel_open")), 0)
	wantEq(t, "action 的个数", len(evs.of("action")), 0)
}
