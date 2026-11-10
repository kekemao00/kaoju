package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// RFC 6455 第 1.3 节的例子：这个 Key 对应的 Accept 是固定的。
const (
	wsKey    = "dGhlIHNhbXBsZSBub25jZQ=="
	wsAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
)

func wsHandshake(target, host string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\nOrigin: http://a.kaoju.test\r\n\r\n"
}

func wantWS101(t *testing.T, r *resp) {
	t.Helper()
	wantEq(t, "状态码", r.status, 101)
	wantEq(t, "原因短语", r.reason, "Switching Protocols")
	if v, _ := r.get("Sec-WebSocket-Accept"); v != wsAccept {
		t.Errorf("Sec-WebSocket-Accept = %q，应为 %q", v, wsAccept)
	}
	if v, _ := r.get("Upgrade"); !strings.EqualFold(v, "websocket") {
		t.Errorf("Upgrade = %q", v)
	}
	if v, _ := r.get("Connection"); !strings.EqualFold(v, "upgrade") {
		t.Errorf("Connection = %q", v)
	}
	if _, ok := r.get("Content-Length"); ok {
		t.Error("101 不应带 Content-Length")
	}
}

// /redirect、/page、不存在的路径、/echo 的 delay：明文（经代理转发）和 HTTPS（隧道里）两条路都走一遍。
func TestOriginPaths(t *testing.T) {
	e := startEnv(t, `{"origin":{"h2":false}}`)
	c := e.dialProxy()
	abs := func(pathQuery string) *resp {
		c.send("GET http://a.kaoju.test" + pathQuery + " HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n")
		return c.readResp()
	}
	c2 := e.dialProxy()
	c2.connect("a.kaoju.test:443")
	tc := e.startTLS(c2, "a.kaoju.test", "http/1.1")
	tun := func(pathQuery string) *resp {
		tc.send(getReq(pathQuery, "a.kaoju.test"))
		return tc.readResp()
	}
	for name, get := range map[string]func(string) *resp{"明文": abs, "HTTPS": tun} {
		r := get("/redirect?to=https%3A%2F%2Fb.kaoju.test%2Fecho%3Fk%3DB08.s1b&k=B08.s1")
		wantEq(t, name+" /redirect 默认的状态码", r.status, 302)
		if v, _ := r.get("Location"); v != "https://b.kaoju.test/echo?k=B08.s1b" {
			t.Errorf("%s Location = %q", name, v)
		}
		r = get("/redirect?to=http://b.kaoju.test/echo?k=B09.s1b&code=307&k=B09.s1")
		wantEq(t, name+" /redirect code=307", r.status, 307)
		if v, _ := r.get("Location"); v != "http://b.kaoju.test/echo?k=B09.s1b" {
			t.Errorf("%s Location = %q", name, v)
		}
		wantEq(t, name+" /redirect 没有 to", get("/redirect?k=bad").status, 400)

		r = get("/page?k=A15.pre")
		wantEq(t, name+" /page 的状态码", r.status, 200)
		if v, _ := r.get("Content-Type"); !strings.HasPrefix(v, "text/html") {
			t.Errorf("%s /page 的 Content-Type = %q", name, v)
		}
		if !strings.Contains(string(r.body), "<title>kaoju A15.pre</title>") {
			t.Errorf("%s /page 的 title 里没有 k: %s", name, r.body)
		}
		r = get("/page?k=%3Cscript%3E")
		if strings.Contains(string(r.body), "<script>") {
			t.Errorf("%s /page 没有转义 k: %s", name, r.body)
		}

		wantEq(t, name+" 不存在的路径", get("/nope?k=N.s1").status, 404)

		start := time.Now()
		r = get("/echo?k=D.s1&delay=300")
		if d := time.Since(start); d < 290*time.Millisecond || d > 2*time.Second {
			t.Errorf("%s delay=300 的响应用了 %v", name, d)
		}
		wantEq(t, name+" 带 delay 的 /echo", r.echo(t).str("k"), "D.s1")
		if v, _ := r.get("Cache-Control"); v != "no-store" {
			t.Errorf("%s /echo 的 Cache-Control = %q", name, v)
		}
		if v, _ := r.get("Access-Control-Allow-Origin"); v != "*" {
			t.Errorf("%s /echo 的 Access-Control-Allow-Origin = %q", name, v)
		}
	}
	c.finish()
	tc.close()

	evs := e.stop()
	for _, id := range []int{e.connID(c), e.connID(c2)} {
		ors := evs.conn(id).of("origin_request")
		wantEq(t, "origin_request 的个数", len(ors), 7)
		wantEq(t, "/redirect 的 origin_request.path", ors[0].str("path"), "/redirect")
		wantEq(t, "/redirect 的 origin_request.k", ors[0].str("k"), "B08.s1")
		wantEq(t, "/redirect 的 origin_request.status", ors[0].num("status"), 302)
		wantEq(t, "code=307 的 origin_request.status", ors[1].num("status"), 307)
		wantEq(t, "/page 的 origin_request.path", ors[3].str("path"), "/page")
		wantEq(t, "404 的 origin_request.path", ors[5].str("path"), "/nope")
		wantEq(t, "404 的 origin_request.k", ors[5].str("k"), "N.s1")
		wantEq(t, "404 的 origin_request.status", ors[5].num("status"), 404)
		wantEq(t, "404 的 origin_request.action", ors[5].str("action"), "respond")
		wantEq(t, "带 delay 的 origin_request.query", ors[6].str("query"), "k=D.s1&delay=300")
	}
}

// 隧道里（HTTP/1.1）的 POST：正文读完并算哈希；Content-Length 和 chunked 都行。
func TestOriginPOSTInTunnel(t *testing.T) {
	e := startEnv(t, `{"origin":{"h2":false}}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:443")
	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	body := pattern(65536)
	tc.send(fmt.Sprintf("POST /echo?k=A13.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(body)))
	tc.send(string(body))
	echo := tc.readResp().echo(t)
	wantEq(t, "echo.method", echo.str("method"), "POST")
	wantEq(t, "echo.body_len", echo.num("body_len"), len(body))
	wantEq(t, "echo.body_sha256", echo.str("body_sha256"), sha256hex(body))
	tc.send("POST /echo?k=A13.s2 HTTP/1.1\r\nHost: a.kaoju.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	echo = tc.readResp().echo(t)
	wantEq(t, "chunked echo.body_len", echo.num("body_len"), 11)
	wantEq(t, "chunked echo.body_sha256", echo.str("body_sha256"), sha256hex([]byte("hello world")))
	tc.close()
	evs := e.stop()
	ors := evs.of("origin_request")
	wantEq(t, "origin_request.body_len", ors[0].num("body_len"), len(body))
	wantEq(t, "origin_request.body_sha256", ors[0].str("body_sha256"), sha256hex(body))
	wantEq(t, "origin_request.method", ors[0].str("method"), "POST")
	wantEq(t, "chunked origin_request.body_len", ors[1].num("body_len"), 11)
}

// /ws 在隧道里（wss:// 的走法）和到 80 端口的隧道里（ws:// 经 CONNECT 的走法）：
// 校验握手，回 101 和正确的 Sec-WebSocket-Accept，发一个关闭帧，然后关。
func TestWebSocketInTunnel(t *testing.T) {
	e := startEnv(t, `{}`)
	// wss：443 端口的隧道，TLS 里面。
	c := e.dialProxy()
	c.connect("a.kaoju.test:443")
	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	tc.send(wsHandshake("/ws?k=A16.w1", "a.kaoju.test"))
	wantWS101(t, tc.readResp())
	frame := make([]byte, 4)
	if _, err := io.ReadFull(tc.br, frame); err != nil {
		t.Fatalf("读关闭帧失败: %v", err)
	}
	wantBytes(t, "关闭帧（FIN、opcode 8、状态码 1000，不带掩码）", frame, []byte{0x88, 0x02, 0x03, 0xe8})
	if err := tlsReadErr(tc); !errors.Is(err, io.EOF) {
		t.Errorf("关闭帧之后应当读到 EOF，实际 %v", err)
	}
	// 上面的 EOF 是 TLS 的 close_notify。等源站把 TCP 也关了（FIN）测试这边再关，
	// 这样“谁先关”才是确定的：conn_end.by 说的是 TCP 这一层。
	c.expectEOF(3 * time.Second)
	tc.close()

	// ws 经 CONNECT：80 端口的隧道，明文。
	c2 := e.dialProxy()
	c2.connect("a.kaoju.test:80")
	c2.send(wsHandshake("/ws?k=A15.w1", "a.kaoju.test"))
	wantWS101(t, c2.readResp())
	wantBytes(t, "关闭帧", c2.readN(4), []byte{0x88, 0x02, 0x03, 0xe8})
	c2.expectEOF(3 * time.Second)
	c2.finish()

	// 握手不对：缺 Key 回 400；版本不是 13 回 426 并带 Sec-WebSocket-Version: 13。
	c3 := e.dialProxy()
	c3.connect("a.kaoju.test:80")
	c3.send("GET /ws?k=W.bad1 HTTP/1.1\r\nHost: a.kaoju.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n")
	wantEq(t, "缺 Sec-WebSocket-Key", c3.readResp().status, 400)
	c3.send("GET /ws?k=W.bad2 HTTP/1.1\r\nHost: a.kaoju.test\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 12\r\n\r\n")
	r := c3.readResp()
	wantEq(t, "版本不是 13", r.status, 426)
	if v, _ := r.get("Sec-WebSocket-Version"); v != "13" {
		t.Errorf("426 应带 Sec-WebSocket-Version: 13，实际 %q", v)
	}
	c3.send(getReq("/ws?k=W.bad3", "a.kaoju.test"))
	wantEq(t, "不带 Upgrade", c3.readResp().status, 400)
	c3.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	or := one(t, ce.of("origin_request"), "origin_request")
	wantEq(t, "origin_request.k", or.str("k"), "A16.w1")
	wantEq(t, "origin_request.path", or.str("path"), "/ws")
	wantEq(t, "origin_request.status", or.num("status"), 101)
	wantEq(t, "origin_request.tls", or["tls"], any(true))
	wantEq(t, "tunnel_first_bytes.kind", ce.of("tunnel_first_bytes")[0].str("kind"), "tls_client_hello")
	wantEq(t, "wss：tunnel_close.by", ce.of("tunnel_close")[0].str("by"), "origin")
	wantEq(t, "wss：conn_end.reason", ce.of("conn_end")[0].str("reason"), "origin_close")

	ce2 := evs.conn(e.connID(c2))
	or2 := one(t, ce2.of("origin_request"), "origin_request")
	wantEq(t, "ws 经 CONNECT：origin_request.k", or2.str("k"), "A15.w1")
	wantEq(t, "ws 经 CONNECT：origin_request.status", or2.num("status"), 101)
	wantEq(t, "ws 经 CONNECT：origin_request.via", or2.str("via"), "tunnel")
	wantEq(t, "ws 经 CONNECT：tunnel_open.target_port", ce2.of("tunnel_open")[0].num("target_port"), 80)
	wantEq(t, "ws 经 CONNECT：tunnel_first_bytes.kind", ce2.of("tunnel_first_bytes")[0].str("kind"), "http")
	end2 := ce2.of("conn_end")[0]
	wantEq(t, "ws 经 CONNECT：conn_end.by", end2.str("by"), "proxy")
	wantEq(t, "ws 经 CONNECT：conn_end.close", end2.str("close"), "fin")

	ors3 := evs.conn(e.connID(c3)).of("origin_request")
	wantEq(t, "握手不对的 origin_request 个数", len(ors3), 3)
	wantEq(t, "缺 Key 的 origin_request.status", ors3[0].num("status"), 400)
	wantEq(t, "版本不对的 origin_request.status", ors3[1].num("status"), 426)
}

// 绝对形式、带 Upgrade: websocket 的请求（ws:// 不经 CONNECT 的走法）：代理自己完成 101 握手，
// 发一个关闭帧，然后关连接；不交给源站，所以没有 origin_request。
func TestWebSocketAbsoluteForm(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["u","p"]]}}`)
	// 没带凭据：先判认证。
	c0 := e.dialProxy()
	c0.send(wsHandshake("http://a.kaoju.test/ws?k=A15.w0", "a.kaoju.test"))
	wantEq(t, "没带凭据", c0.readResp().status, 407)
	c0.finish()

	c := e.dialProxy()
	hs := strings.Replace(wsHandshake("http://a.kaoju.test/ws?k=A15.w1", "a.kaoju.test"),
		"\r\n\r\n", "\r\nProxy-Authorization: "+basicAuth("u", "p")+"\r\n\r\n", 1)
	c.send(hs)
	r := c.readResp()
	wantWS101(t, r)
	wantBytes(t, "关闭帧", c.readN(4), []byte{0x88, 0x02, 0x03, 0xe8})
	c.expectEOF(3 * time.Second)
	c.finish()

	// 握手不对：400，连接留着。
	c2 := e.dialProxy()
	c2.send("GET http://a.kaoju.test/ws?k=A15.bad HTTP/1.1\r\nHost: a.kaoju.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Proxy-Authorization: " + basicAuth("u", "p") + "\r\n\r\n")
	wantEq(t, "缺 Key", c2.readResp().status, 400)
	c2.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(), "accept first_bytes http_request http_response conn_end")
	hr := ce[2]
	wantEq(t, "http_request.form", hr.str("form"), "absolute")
	wantEq(t, "http_request.k", hr.str("k"), "A15.w1")
	wantEq(t, "http_request.target", hr.str("target"), "http://a.kaoju.test/ws?k=A15.w1")
	hp := ce[3]
	wantEq(t, "http_response.status", hp.num("status"), 101)
	wantEq(t, "http_response.by", hp.str("by"), "proxy")
	wantEq(t, "http_response.cause", hp.str("cause"), "websocket")
	wantEq(t, "http_response.close", hp["close"], any(true))
	wantEq(t, "http_response.body_len", hp.num("body_len"), 0)
	wantPairs(t, "http_response.headers", hp.pairs("headers"), r.headers)
	end := ce[4]
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.close", end.str("close"), "fin")
	wantEq(t, "conn_end.reason", end.str("reason"), "websocket_done")
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 0)
	wantEq(t, "握手不对的 http_response.cause", evs.conn(e.connID(c2)).of("http_response")[0].str("cause"), "websocket_rejected")
}
