package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A01：明文 GET 经代理。逐项核对这条连接上的每个事件。
func TestForwardGET(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	req := "GET http://a.kaoju.test/echo?k=A01.s1 HTTP/1.1\r\n" +
		"Host: a.kaoju.test\r\n" +
		"User-Agent: rawtest/1\r\n" +
		"X-MiXeD-cAsE:   padded value \t\r\n" +
		"x-dup: 1\r\n" +
		"X-Dup: 2\r\n" +
		"Proxy-Connection: Keep-Alive\r\n" +
		"\r\n"
	c.send(req)
	r := c.readResp()
	wantEq(t, "状态码", r.status, 200)
	wantEq(t, "协议", r.proto, "HTTP/1.1")
	wantEq(t, "原因短语", r.reason, "OK")
	if v, _ := r.get("Cache-Control"); v != "no-store" {
		t.Errorf("Cache-Control = %q", v)
	}
	if v, _ := r.get("Access-Control-Allow-Origin"); v != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q", v)
	}
	if _, ok := r.get("Connection"); ok {
		t.Error("保持连接的响应不应带 Connection 头")
	}
	echo := r.echo(t)
	wantEq(t, "echo.k", echo.str("k"), "A01.s1")
	wantEq(t, "echo.method", echo.str("method"), "GET")
	wantEq(t, "echo.proto", echo.str("proto"), "HTTP/1.1")
	wantEq(t, "echo.host", echo.str("host"), "a.kaoju.test")
	wantEq(t, "echo.via", echo.str("via"), "forward")
	wantEq(t, "echo.tls", echo["tls"], any(false))
	wantEq(t, "echo.body_len", echo.num("body_len"), 0)
	wantEq(t, "echo.body_sha256", echo.str("body_sha256"), emptySHA256)
	if echo["origin_conn"] != nil || echo["seq"] != nil {
		t.Errorf("转发的请求没有源站连接，origin_conn 和 seq 应为 null: %v %v", echo["origin_conn"], echo["seq"])
	}
	// 交给源站的头：逐跳头和 Proxy- 开头的去掉了，其余保持原顺序、原大小写。
	fwd := [][2]string{{"User-Agent", "rawtest/1"}, {"X-MiXeD-cAsE", "padded value"}, {"x-dup", "1"}, {"X-Dup", "2"}}
	wantPairs(t, "echo.headers", echo.pairs("headers"), fwd)
	c.finish()

	evs := e.stop()
	id := e.connID(c)
	ce := evs.conn(id)
	wantEq(t, "事件序列", ce.names(), "accept first_bytes http_request origin_request http_response conn_end")

	acc := ce[0]
	wantEq(t, "accept.listener", acc.str("listener"), "proxy")
	wantEq(t, "accept.peer_port", acc.num("peer_port"), c.localPort)

	fb := ce[1]
	wantEq(t, "first_bytes.n_first_read", fb.num("n_first_read"), len(req))
	wantEq(t, "first_bytes.hex", fb.str("hex"), hex.EncodeToString([]byte(req[:16])))
	wantEq(t, "first_bytes.kind", fb.str("kind"), "http")
	wantEq(t, "first_bytes.listener", fb.str("listener"), "proxy")

	hr := ce[2]
	wantEq(t, "http_request.seq", hr.num("seq"), 1)
	wantEq(t, "http_request.form", hr.str("form"), "absolute")
	wantEq(t, "http_request.method", hr.str("method"), "GET")
	wantEq(t, "http_request.target", hr.str("target"), "http://a.kaoju.test/echo?k=A01.s1")
	wantEq(t, "http_request.version", hr.str("version"), "HTTP/1.1")
	wantEq(t, "http_request.k", hr.str("k"), "A01.s1")
	wantPairs(t, "http_request.headers（原顺序、原大小写、值去掉首尾空白）", hr.pairs("headers"), [][2]string{
		{"Host", "a.kaoju.test"}, {"User-Agent", "rawtest/1"}, {"X-MiXeD-cAsE", "padded value"},
		{"x-dup", "1"}, {"X-Dup", "2"}, {"Proxy-Connection", "Keep-Alive"},
	})
	raw, err := base64.StdEncoding.DecodeString(hr.str("head_b64"))
	if err != nil || string(raw) != req {
		t.Errorf("head_b64 解出来不是发出去的请求头: %q", raw)
	}
	wantEq(t, "http_request.body_len", hr.num("body_len"), 0)
	wantEq(t, "http_request.body_sha256", hr.str("body_sha256"), emptySHA256)
	auth := hr.obj("auth")
	wantEq(t, "auth.present", auth["present"], any(false))
	wantEq(t, "auth.result", auth.str("result"), "none")
	if hr["error"] != nil {
		t.Errorf("http_request.error = %v", hr["error"])
	}
	if th, ok := hr["t_head"].(float64); !ok || th > hr["t"].(float64) {
		t.Errorf("t_head 应当不晚于 t: %v %v", hr["t_head"], hr["t"])
	}

	or := ce[3]
	wantEq(t, "origin_request.via", or.str("via"), "forward")
	wantEq(t, "origin_request.req_seq", or.num("req_seq"), 1)
	wantEq(t, "origin_request.k", or.str("k"), "A01.s1")
	wantEq(t, "origin_request.method", or.str("method"), "GET")
	wantEq(t, "origin_request.path", or.str("path"), "/echo")
	wantEq(t, "origin_request.query", or.str("query"), "k=A01.s1")
	wantEq(t, "origin_request.proto", or.str("proto"), "HTTP/1.1")
	wantEq(t, "origin_request.host", or.str("host"), "a.kaoju.test")
	wantPairs(t, "origin_request.headers", or.pairs("headers"), fwd)
	wantEq(t, "origin_request.has_proxy_authorization", or["has_proxy_authorization"], any(false))
	wantEq(t, "origin_request.tls", or["tls"], any(false))
	wantEq(t, "origin_request.action", or.str("action"), "respond")
	wantEq(t, "origin_request.status", or.num("status"), 200)
	if or["oconn"] != nil || or["tunnel"] != nil || or["seq"] != nil {
		t.Errorf("转发的 origin_request 的 oconn、tunnel、seq 应为 null: %v", or)
	}

	hp := ce[4]
	wantEq(t, "http_response.seq", hp.num("seq"), 1)
	wantEq(t, "http_response.status", hp.num("status"), 200)
	wantEq(t, "http_response.reason", hp.str("reason"), "OK")
	wantEq(t, "http_response.by", hp.str("by"), "origin")
	wantEq(t, "http_response.cause", hp.str("cause"), "forward")
	wantEq(t, "http_response.close", hp["close"], any(false))
	wantEq(t, "http_response.body_len", hp.num("body_len"), len(r.body))
	wantPairs(t, "http_response.headers 与线上的一致", hp.pairs("headers"), r.headers)

	end := ce[5]
	wantEq(t, "conn_end.by", end.str("by"), "client")
	wantEq(t, "conn_end.close", end.str("close"), "fin")
	wantEq(t, "conn_end.reason", end.str("reason"), "client_eof")
	wantEq(t, "conn_end.listener", end.str("listener"), "proxy")
	wantEq(t, "conn_end.bytes_in", end.num("bytes_in"), len(req))
	wantEq(t, "conn_end.bytes_out", end.num("bytes_out"), len(r.head)+len(r.body))
	wantEq(t, "conn_end.sha256_in", end.str("sha256_in"), sha256hex([]byte(req)))
	wantEq(t, "conn_end.sha256_out", end.str("sha256_out"), sha256hex([]byte(r.head+string(r.body))))
	if d, ok := end["dur_ms"].(float64); !ok || d <= 0 {
		t.Errorf("conn_end.dur_ms = %v", end["dur_ms"])
	}

	// start 事件带着完整的配置、端口和版本。
	st := evs[0]
	wantEq(t, "start.version", st.str("version"), version)
	wantEq(t, "start.proxy_port", st.num("proxy_port"), e.pp)
	wantEq(t, "start.origin_http_port", st.num("origin_http_port"), e.hp)
	wantEq(t, "start.origin_https_port", st.num("origin_https_port"), e.sp)
	wantEq(t, "start.profile.auth.mode", st.obj("profile").obj("auth").str("mode"), "none")
	en := evs[len(evs)-1]
	wantEq(t, "end.reason", en.str("reason"), "test")
	wantEq(t, "end.version", en.str("version"), version)
	wantEq(t, "end.proxy_port", en.num("proxy_port"), e.pp)
}

// 同一条连接上连续的请求：seq 递增；一次写出两个请求（管线）也按顺序各回各的。
func TestForwardKeepAliveAndPipelining(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=K.s1", "a.kaoju.test"))
	wantEq(t, "第 1 个响应的 k", c.readResp().echo(t).str("k"), "K.s1")
	c.send(getReq("http://b.kaoju.test/echo?k=K.s2", "b.kaoju.test"))
	r2 := c.readResp().echo(t)
	wantEq(t, "第 2 个响应的 k", r2.str("k"), "K.s2")
	wantEq(t, "第 2 个响应的 host", r2.str("host"), "b.kaoju.test")
	c.send(getReq("http://a.kaoju.test/echo?k=K.s3", "a.kaoju.test") + getReq("http://a.kaoju.test/echo?k=K.s4", "a.kaoju.test"))
	wantEq(t, "第 3 个响应的 k", c.readResp().echo(t).str("k"), "K.s3")
	wantEq(t, "第 4 个响应的 k", c.readResp().echo(t).str("k"), "K.s4")
	c.finish()
	evs := e.stop()
	reqs := evs.conn(e.connID(c)).of("http_request")
	if len(reqs) != 4 {
		t.Fatalf("http_request 应有 4 个，实际 %d 个", len(reqs))
	}
	for i, r := range reqs {
		wantEq(t, "seq", r.num("seq"), i+1)
		wantEq(t, "k", r.str("k"), fmt.Sprintf("K.s%d", i+1))
	}
	wantEq(t, "代理端口上的 accept 数", len(evs.of("accept")), 1)
}

// POST：正文按 Content-Length 读完，长度和哈希与发出的一致，源站看到的也一样。
func TestForwardPOSTContentLength(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	body := pattern(70000)
	c.send("POST http://a.kaoju.test/echo?k=A12.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nContent-Type: application/octet-stream\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
	c.send(string(body))
	echo := c.readResp().echo(t)
	wantEq(t, "echo.body_len", echo.num("body_len"), len(body))
	wantEq(t, "echo.body_sha256", echo.str("body_sha256"), sha256hex(body))
	c.finish()
	evs := e.stop()
	hr := one(t, evs.of("http_request"), "http_request")
	wantEq(t, "http_request.body_len", hr.num("body_len"), len(body))
	wantEq(t, "http_request.body_sha256", hr.str("body_sha256"), sha256hex(body))
	or := one(t, evs.of("origin_request"), "origin_request")
	wantEq(t, "origin_request.body_len", or.num("body_len"), len(body))
	wantEq(t, "origin_request.body_sha256", or.str("body_sha256"), sha256hex(body))
	wantEq(t, "origin_request.method", or.str("method"), "POST")
}

// POST chunked：块扩展、尾部的头都能读；记下的是解开以后的长度和哈希。
func TestForwardPOSTChunked(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("POST http://a.kaoju.test/echo?k=CH.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n")
	c.send("5\r\nhello\r\n")
	c.send("6;ext=1\r\n world\r\n")
	c.send("A\r\n0123456789\r\n")
	c.send("0\r\nX-Sum: abc\r\n\r\n")
	body := []byte("hello world0123456789")
	echo := c.readResp().echo(t)
	wantEq(t, "echo.body_len", echo.num("body_len"), len(body))
	wantEq(t, "echo.body_sha256", echo.str("body_sha256"), sha256hex(body))
	// 连接没有错位：接着还能用。
	c.send(getReq("http://a.kaoju.test/echo?k=CH.s2", "a.kaoju.test"))
	wantEq(t, "后一个请求的 k", c.readResp().echo(t).str("k"), "CH.s2")
	c.finish()
	evs := e.stop()
	hr := evs.of("http_request")[0]
	wantEq(t, "http_request.body_len", hr.num("body_len"), len(body))
	wantEq(t, "http_request.body_sha256", hr.str("body_sha256"), sha256hex(body))
	// Transfer-Encoding 是逐跳头，不交给源站。
	for _, h := range evs.of("origin_request")[0].pairs("headers") {
		if strings.EqualFold(h[0], "Transfer-Encoding") || strings.EqualFold(h[0], "Trailer") {
			t.Errorf("逐跳头 %s 被交给了源站", h[0])
		}
	}
}

// chunked 格式不对：回 400 并关连接，事件里写明原因。
func TestForwardBadChunked(t *testing.T) {
	for name, body := range map[string]string{
		"长度不是十六进制":   "zz\r\nhello\r\n0\r\n\r\n",
		"块后面不是 CRLF": "5\r\nhelloXX0\r\n\r\n",
		"行尾只有 LF":    "5\nhello\n0\n\n",
		"尾部的头没有冒号":   "0\r\nnot-a-header\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := startEnv(t, `{}`)
			c := e.dialProxy()
			c.send("POST http://a.kaoju.test/echo?k=BC.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
			r := c.readResp()
			wantEq(t, "状态码", r.status, 400)
			if v, _ := r.get("Connection"); v != "close" {
				t.Errorf("400 应带 Connection: close，实际 %q", v)
			}
			c.expectEOF(3 * time.Second)
			c.finish()
			evs := e.stop()
			hr := one(t, evs.of("http_request"), "http_request")
			if !strings.HasPrefix(hr.str("error"), "bad_body: ") {
				t.Errorf("http_request.error = %q", hr.str("error"))
			}
			if len(evs.of("origin_request")) != 0 {
				t.Error("格式不对的请求不应到达源站")
			}
			end := one(t, evs.of("conn_end"), "conn_end")
			wantEq(t, "conn_end.by", end.str("by"), "proxy")
			wantEq(t, "conn_end.close", end.str("close"), "fin")
			wantEq(t, "conn_end.reason", end.str("reason"), "response_close")
		})
	}
}

// Expect: 100-continue：forward.send_100_continue 为真时先回 100 再读正文。
func TestExpect100Continue(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	body := pattern(4096)
	c.send("POST http://a.kaoju.test/echo?k=A14.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nExpect: 100-continue\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
	interim := c.readResp()
	wantEq(t, "先到的状态码", interim.status, 100)
	wantEq(t, "100 的原因短语", interim.reason, "Continue")
	if len(interim.headers) != 0 {
		t.Errorf("100 不应带头: %v", interim.headers)
	}
	c.send(string(body))
	final := c.readResp()
	wantEq(t, "最终状态码", final.status, 200)
	wantEq(t, "echo.body_sha256", final.echo(t).str("body_sha256"), sha256hex(body))
	c.finish()
	evs := e.stop()
	resps := evs.of("http_response")
	if len(resps) != 2 {
		t.Fatalf("http_response 应有 2 个（100 和 200），实际 %d 个", len(resps))
	}
	wantEq(t, "第 1 个 http_response.status", resps[0].num("status"), 100)
	wantEq(t, "第 1 个 http_response.cause", resps[0].str("cause"), "continue")
	wantEq(t, "第 1 个 http_response.by", resps[0].str("by"), "proxy")
	wantEq(t, "第 2 个 http_response.status", resps[1].num("status"), 200)
	// 事件的先后：100 在 http_request（正文读完才写）之前。
	wantEq(t, "事件序列", evs.conn(e.connID(c)).names(),
		"accept first_bytes http_response http_request origin_request http_response conn_end")
}

func TestExpect100ContinueDisabled(t *testing.T) {
	e := startEnv(t, `{"forward":{"send_100_continue":false}}`)
	c := e.dialProxy()
	body := pattern(1000)
	c.send("POST http://a.kaoju.test/echo?k=A14.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nExpect: 100-continue\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
	c.expectSilence(400 * time.Millisecond) // 不回 100，也不回别的
	c.send(string(body))
	final := c.readResp()
	wantEq(t, "状态码", final.status, 200)
	c.finish()
	evs := e.stop()
	for _, r := range evs.of("http_response") {
		if r.num("status") == 100 {
			t.Error("send_100_continue 为假时不应回 100")
		}
	}
}

// 要求认证时：带 Expect 的请求也先回 100、把正文读完，再回 407，连接不错位。
func TestExpect100ContinueThen407(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["kaoju-user","kaoju-pass-1"]]}}`)
	c := e.dialProxy()
	body := pattern(3000)
	head := "POST http://a.kaoju.test/echo?k=B13.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nExpect: 100-continue\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body))
	c.send(head + "\r\n")
	wantEq(t, "先到的状态码", c.readResp().status, 100)
	c.send(string(body))
	wantEq(t, "没带凭据的最终状态码", c.readResp().status, 407)
	c.send(head + "Proxy-Authorization: " + basicAuth("kaoju-user", "kaoju-pass-1") + "\r\n\r\n")
	wantEq(t, "重试时先到的状态码", c.readResp().status, 100)
	c.send(string(body))
	r := c.readResp()
	wantEq(t, "带凭据的最终状态码", r.status, 200)
	wantEq(t, "echo.body_len", r.echo(t).num("body_len"), len(body))
	c.finish()
	evs := e.stop()
	full := 0
	for _, hr := range evs.of("http_request") {
		if hr.num("body_len") == len(body) {
			full++
		}
	}
	wantEq(t, "完整的正文到了几遍", full, 2)
}

// HTTP/1.0 的请求：照常处理，响应写 HTTP/1.1；没有 keep-alive 就在响应后关连接。
func TestHTTP10(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("GET http://a.kaoju.test/echo?k=H10.s1 HTTP/1.0\r\n\r\n")
	r := c.readResp()
	wantEq(t, "状态码", r.status, 200)
	wantEq(t, "响应的协议", r.proto, "HTTP/1.1")
	if v, _ := r.get("Connection"); v != "close" {
		t.Errorf("HTTP/1.0 且没有 keep-alive：响应应带 Connection: close，实际 %q", v)
	}
	wantEq(t, "echo.proto", r.echo(t).str("proto"), "HTTP/1.0")
	c.expectEOF(3 * time.Second)
	c.finish()

	// 带 Proxy-Connection: keep-alive 的 HTTP/1.0 请求：连接留着。
	c2 := e.dialProxy()
	c2.send("GET http://a.kaoju.test/echo?k=H10.s2 HTTP/1.0\r\nProxy-Connection: keep-alive\r\n\r\n")
	r2 := c2.readResp()
	if _, ok := r2.get("Connection"); ok {
		t.Error("带 keep-alive 的 HTTP/1.0 请求：响应不应带 Connection: close")
	}
	c2.send("GET http://a.kaoju.test/echo?k=H10.s3 HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
	wantEq(t, "同一条连接上的下一个请求", c2.readResp().echo(t).str("k"), "H10.s3")
	c2.finish()

	evs := e.stop()
	end := one(t, evs.conn(e.connID(c)).of("conn_end"), "conn_end")
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.close", end.str("close"), "fin")
	wantEq(t, "conn_end.reason", end.str("reason"), "response_close")
	hr := evs.conn(e.connID(c)).of("http_request")[0]
	wantEq(t, "http_request.version", hr.str("version"), "HTTP/1.0")
	hp := evs.conn(e.connID(c)).of("http_response")[0]
	wantEq(t, "http_response.close", hp["close"], any(true))
}

// 请求带 Connection: close：响应后代理关连接。
func TestRequestConnectionClose(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=CC.s1", "a.kaoju.test", "Connection: close\r\n"))
	r := c.readResp()
	wantEq(t, "状态码", r.status, 200)
	if v, _ := r.get("Connection"); v != "close" {
		t.Errorf("响应应带 Connection: close，实际 %q", v)
	}
	c.expectEOF(3 * time.Second)
	c.finish()
	e.stop()
}

// 代理端口上不合格的请求：各回各的状态码，然后关连接；事件里的 form 和 error 写明是什么问题。
func TestProxyRejectsMalformed(t *testing.T) {
	cases := []struct {
		name, req string
		status    int
		form      string
		kind      string
		errPrefix string
	}{
		{"源站形式", "GET /echo?k=x HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n", 400, "origin", "http", ""},
		{"星号形式", "OPTIONS * HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n", 400, "other", "http", ""},
		{"不是 HTTP", "\x01\x02\x03 binary\r\n\r\n", 400, "other", "other", "bad_head: "},
		{"版本不支持", "GET http://a.kaoju.test/ HTTP/2.0\r\n\r\n", 505, "absolute", "http", "unsupported_version"},
		{"头折行", "GET http://a.kaoju.test/ HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n", 400, "absolute", "http", "bad_head: "},
		{"头名字后有空格", "GET http://a.kaoju.test/ HTTP/1.1\r\nHost : a\r\n\r\n", 400, "absolute", "http", "bad_head: "},
		{"头没有冒号", "GET http://a.kaoju.test/ HTTP/1.1\r\nnocolon\r\n\r\n", 400, "absolute", "http", "bad_head: "},
		{"Content-Length 不一致", "POST http://a.kaoju.test/ HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", 400, "absolute", "http", "bad_framing: "},
		{"Content-Length 不是数字", "POST http://a.kaoju.test/ HTTP/1.1\r\nContent-Length: 3x\r\n\r\nabc", 400, "absolute", "http", "bad_framing: "},
		{"Transfer-Encoding 不是 chunked", "POST http://a.kaoju.test/ HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", 400, "absolute", "http", "bad_framing: "},
		{"CONNECT 的目标没有端口", "CONNECT a.kaoju.test HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n", 400, "connect", "http", ""},
		{"不支持的 scheme", "GET ftp://a.kaoju.test/x HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n", 400, "absolute", "http", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := startEnv(t, `{}`)
			c := e.dialProxy()
			c.send(tc.req)
			r := c.readResp()
			wantEq(t, "状态码", r.status, tc.status)
			if strings.Contains(string(r.body), fmt.Sprint(tc.status)) {
				t.Errorf("代理自己写的正文里不应出现状态码数字: %q", r.body)
			}
			if tc.errPrefix != "" || tc.form == "origin" || tc.form == "other" {
				c.expectEOF(3 * time.Second)
			}
			c.finish()
			evs := e.stop()
			wantEq(t, "first_bytes.kind", one(t, evs.of("first_bytes"), "first_bytes").str("kind"), tc.kind)
			hr := one(t, evs.of("http_request"), "http_request")
			wantEq(t, "http_request.form", hr.str("form"), tc.form)
			if tc.errPrefix == "" {
				if hr["error"] != nil {
					t.Errorf("http_request.error = %v，应为 null", hr["error"])
				}
			} else if !strings.HasPrefix(hr.str("error"), tc.errPrefix) {
				t.Errorf("http_request.error = %q，应以 %q 开头", hr.str("error"), tc.errPrefix)
			}
			raw, _ := base64.StdEncoding.DecodeString(hr.str("head_b64"))
			if !strings.HasPrefix(tc.req, string(raw)) || len(raw) == 0 {
				t.Errorf("head_b64 不是发出去的请求头的原文: %q", raw)
			}
			hp := one(t, evs.of("http_response"), "http_response")
			wantEq(t, "http_response.status", hp.num("status"), tc.status)
			wantEq(t, "http_response.by", hp.str("by"), "proxy")
			if len(evs.of("origin_request")) != 0 {
				t.Error("不合格的请求不应到达源站")
			}
		})
	}
}

// 请求头超过 64 KiB：回 431 并关连接。刚好不超过的照常处理。
func TestHeadSizeLimit(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("GET http://a.kaoju.test/echo?k=BIG.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nX-Pad: " + strings.Repeat("a", 70000))
	r := c.readResp()
	wantEq(t, "状态码", r.status, 431)
	c.expectEOF(3 * time.Second)
	c.finish()

	// 整个请求头恰好 65536 字节。
	c2 := e.dialProxy()
	prefix := "GET http://a.kaoju.test/echo?k=BIG.s2 HTTP/1.1\r\nHost: a.kaoju.test\r\nX-Pad: "
	req := prefix + strings.Repeat("b", maxHeadBytes-len(prefix)-4) + "\r\n\r\n"
	wantEq(t, "构造的请求头长度", len(req), maxHeadBytes)
	c2.send(req)
	wantEq(t, "恰好 64 KiB 的请求头", c2.readResp().status, 200)
	c2.finish()

	// 多一个字节就不行。
	c3 := e.dialProxy()
	c3.send(prefix + strings.Repeat("c", maxHeadBytes-len(prefix)-3) + "\r\n\r\n")
	wantEq(t, "64 KiB 加 1 字节的请求头", c3.readResp().status, 431)
	c3.expectEOF(3 * time.Second)
	c3.finish()

	evs := e.stop()
	hr := evs.conn(e.connID(c)).of("http_request")[0]
	wantEq(t, "http_request.error", hr.str("error"), "head_too_large")
	hr2 := evs.conn(e.connID(c2)).of("http_request")[0]
	raw, _ := base64.StdEncoding.DecodeString(hr2.str("head_b64"))
	wantEq(t, "head_b64 的长度", len(raw), maxHeadBytes)
}

// 请求头没发完连接就断了：留下一条带 error 的 http_request，不回任何东西。
func TestIncompleteHead(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("GET http://a.kaoju.test/echo?k=INC.s1 HTTP/1.1\r\nHost: a.kao")
	c.finish()
	evs := e.stop()
	hr := one(t, evs.of("http_request"), "http_request")
	if !strings.HasPrefix(hr.str("error"), "incomplete_head: ") {
		t.Errorf("http_request.error = %q", hr.str("error"))
	}
	wantEq(t, "http_response 的个数", len(evs.of("http_response")), 0)
	end := one(t, evs.of("conn_end"), "conn_end")
	wantEq(t, "conn_end.by", end.str("by"), "client")
	wantEq(t, "conn_end.bytes_out", end.num("bytes_out"), 0)
}

// 目标端口不是 80、443，也不是两个源站端口：按“连不上”处理，回 502，连接留着。
func TestUnmappedPortsAndHTTPSAbsolute(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test:8080/echo?k=U.s1", "a.kaoju.test:8080"))
	r := c.readResp()
	wantEq(t, "绝对形式到 8080", r.status, 502)
	c.send("CONNECT a.kaoju.test:8443 HTTP/1.1\r\nHost: a.kaoju.test:8443\r\n\r\n")
	wantEq(t, "CONNECT 到 8443", c.readResp().status, 502)
	c.send(getReq("https://a.kaoju.test/echo?k=U.s3", "a.kaoju.test"))
	wantEq(t, "绝对形式的 https", c.readResp().status, 502)
	// 明文请求指到 HTTPS 源站的端口上：内置的明文处理函数接不了，也是 502。
	c.send(getReq(fmt.Sprintf("http://localhost:%d/echo?k=U.s4", e.sp), "localhost"))
	wantEq(t, "明文请求到 HTTPS 源站端口", c.readResp().status, 502)
	// 指到明文源站的端口上：能通（A10 的写法）。
	c.send(getReq(fmt.Sprintf("http://localhost:%d/echo?k=U.s5", e.hp), "localhost"))
	r5 := c.readResp()
	wantEq(t, "明文请求到明文源站端口", r5.status, 200)
	wantEq(t, "echo.host", r5.echo(t).str("host"), fmt.Sprintf("localhost:%d", e.hp))
	c.finish()
	evs := e.stop()
	resps := evs.of("http_response")
	wantEq(t, "http_response 的个数", len(resps), 5)
	for i, want := range []string{"unmapped_port", "unmapped_port", "https_absolute", "unmapped_port", "forward"} {
		wantEq(t, fmt.Sprintf("第 %d 个 http_response.cause", i+1), resps[i].str("cause"), want)
	}
	wantEq(t, "tunnel_open 的个数", len(evs.of("tunnel_open")), 0)
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 1)
}

// forward.fail：不转发，回配置里写的响应；close 为真时发完就关。
func TestForwardFail(t *testing.T) {
	e := startEnv(t, `{"forward":{"fail":{"status":403,"reason":"KaojuReasonMarker",
		"headers":[["X-Kaoju-Note","KaojuHeaderMarker"],["Proxy-Status","kaoju; error=destination_unavailable; details=\"KaojuStatusMarker\""]],
		"body":"KaojuBodyMarker\n","close":true}}}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=E05.s1", "a.kaoju.test"))
	r := c.readResp()
	wantEq(t, "状态码", r.status, 403)
	wantEq(t, "原因短语", r.reason, "KaojuReasonMarker")
	wantPairs(t, "响应头", r.headers, [][2]string{
		{"X-Kaoju-Note", "KaojuHeaderMarker"},
		{"Proxy-Status", `kaoju; error=destination_unavailable; details="KaojuStatusMarker"`},
		{"Content-Length", "16"},
		{"Connection", "close"},
	})
	wantEq(t, "正文", string(r.body), "KaojuBodyMarker\n")
	c.expectEOF(3 * time.Second)
	c.finish()
	evs := e.stop()
	hp := one(t, evs.of("http_response"), "http_response")
	wantEq(t, "http_response.cause", hp.str("cause"), "forward_fail")
	wantEq(t, "http_response.by", hp.str("by"), "proxy")
	wantEq(t, "http_response.close", hp["close"], any(true))
	wantEq(t, "http_response.reason", hp.str("reason"), "KaojuReasonMarker")
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 0)
}

// forward.fail 的 hosts：只对列出的主机生效；close 为假时连接留着。
func TestForwardFailHostsKeepAlive(t *testing.T) {
	e := startEnv(t, `{"forward":{"fail":{"status":503,"hosts":["Fail.kaoju.test"]}}}`)
	c := e.dialProxy()
	c.send(getReq("http://fail.kaoju.test/echo?k=FH.s1", "fail.kaoju.test"))
	r := c.readResp()
	wantEq(t, "对 fail.kaoju.test", r.status, 503)
	wantEq(t, "缺省的原因短语", r.reason, "Service Unavailable")
	if _, ok := r.get("Connection"); ok {
		t.Error("close 为假时不应带 Connection: close")
	}
	c.send(getReq("http://a.kaoju.test/echo?k=FH.s2", "a.kaoju.test"))
	wantEq(t, "对 a.kaoju.test（同一条连接）", c.readResp().status, 200)
	c.finish()
	e.stop()
}

// forward.add_response_headers：转发成功时代理在响应里多加的头。
func TestForwardAddResponseHeaders(t *testing.T) {
	e := startEnv(t, `{"forward":{"add_response_headers":[["X-Kaoju-Note","KaojuHeaderMarker"],["Proxy-Status","kaoju; details=\"KaojuStatusMarker\""]]}}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=E06.s1", "a.kaoju.test"))
	r := c.readResp()
	wantEq(t, "状态码", r.status, 200)
	if v, _ := r.get("X-Kaoju-Note"); v != "KaojuHeaderMarker" {
		t.Errorf("X-Kaoju-Note = %q", v)
	}
	if v, _ := r.get("Proxy-Status"); v != `kaoju; details="KaojuStatusMarker"` {
		t.Errorf("Proxy-Status = %q", v)
	}
	c.finish()
	evs := e.stop()
	hp := one(t, evs.of("http_response"), "http_response")
	wantPairs(t, "http_response.headers", hp.pairs("headers"), r.headers)
}

// HEAD：带 Content-Length，不发正文，连接不错位。
func TestForwardHEAD(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("HEAD http://a.kaoju.test/echo?k=HD.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n")
	// 测试的解析器会按 Content-Length 去读正文，这里自己读头。
	_ = c.tcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	var head strings.Builder
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			t.Fatalf("读 HEAD 的响应失败: %v", err)
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if !strings.HasPrefix(head.String(), "HTTP/1.1 200 OK\r\n") || !strings.Contains(head.String(), "\r\nContent-Length: ") {
		t.Errorf("HEAD 的响应头不对: %q", head.String())
	}
	c.send(getReq("http://a.kaoju.test/echo?k=HD.s2", "a.kaoju.test"))
	wantEq(t, "HEAD 之后的请求", c.readResp().echo(t).str("k"), "HD.s2")
	c.finish()
	evs := e.stop()
	wantEq(t, "HEAD 的 http_response.body_len", evs.of("http_response")[0].num("body_len"), 0)
}

// 代理端口上首字节是 0x04（SOCKS4）或 0x16（TLS）：只记录，然后关。
func TestFirstByteSocks4AndTLS(t *testing.T) {
	for _, tc := range []struct {
		name, payload, kind, reason string
	}{
		{"socks4", "\x04\x01\x01\xbb\x7f\x00\x00\x01user\x00", "socks4", "socks4_unsupported"},
		{"tls", "\x16\x03\x01\x00\x05hello", "tls", "tls_on_proxy_port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := startEnv(t, `{}`)
			c := e.dialProxy()
			c.send(tc.payload)
			c.expectEOF(3 * time.Second)
			c.finish()
			evs := e.stop()
			wantEq(t, "事件序列", evs.conn(e.connID(c)).names(), "accept first_bytes conn_end")
			fb := one(t, evs.of("first_bytes"), "first_bytes")
			wantEq(t, "first_bytes.kind", fb.str("kind"), tc.kind)
			wantEq(t, "first_bytes.n_first_read", fb.num("n_first_read"), len(tc.payload))
			wantEq(t, "first_bytes.hex", fb.str("hex"), hex.EncodeToString([]byte(tc.payload)))
			end := one(t, evs.of("conn_end"), "conn_end")
			wantEq(t, "conn_end.by", end.str("by"), "proxy")
			wantEq(t, "conn_end.close", end.str("close"), "fin")
			wantEq(t, "conn_end.reason", end.str("reason"), tc.reason)
			wantEq(t, "conn_end.bytes_out", end.num("bytes_out"), 0)
		})
	}
}

// 连上以后什么都不发就关：没有 first_bytes，只有 accept 和 conn_end。
func TestConnectAndCloseWithoutBytes(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	time.Sleep(50 * time.Millisecond)
	c.finish()
	evs := e.stop()
	wantEq(t, "事件序列", evs.conn(e.connID(c)).names(), "accept conn_end")
	end := one(t, evs.of("conn_end"), "conn_end")
	wantEq(t, "conn_end.by", end.str("by"), "client")
	wantEq(t, "conn_end.bytes_in", end.num("bytes_in"), 0)
	wantEq(t, "conn_end.sha256_in", end.str("sha256_in"), emptySHA256)
	wantEq(t, "conn_end.sha256_out", end.str("sha256_out"), emptySHA256)
}

// 请求行之前的空行跳过；首批字节分几次到也能解析（first_bytes 记的是第一次读到的）。
func TestSlowAndFragmentedRequest(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	req := getReq("http://a.kaoju.test/echo?k=SL.s1", "a.kaoju.test")
	c.send(req[:7])
	time.Sleep(100 * time.Millisecond)
	c.send(req[7:40])
	time.Sleep(50 * time.Millisecond)
	c.send(req[40:])
	wantEq(t, "分三次发的请求", c.readResp().echo(t).str("k"), "SL.s1")
	c.send("\r\n" + getReq("http://a.kaoju.test/echo?k=SL.s2", "a.kaoju.test"))
	wantEq(t, "前面有空行的请求", c.readResp().echo(t).str("k"), "SL.s2")
	c.finish()
	evs := e.stop()
	fb := one(t, evs.of("first_bytes"), "first_bytes")
	wantEq(t, "first_bytes.n_first_read", fb.num("n_first_read"), 7)
	wantEq(t, "first_bytes.hex", fb.str("hex"), hex.EncodeToString([]byte(req[:7])))
	raw, _ := base64.StdEncoding.DecodeString(evs.of("http_request")[0].str("head_b64"))
	wantEq(t, "head_b64", string(raw), req)
}
