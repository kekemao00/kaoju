package main

// 对抗性审查留下的复现测试（TestReview…）。
//
// 每个测试的注释写明它对照的是 PROTOCOL.md、EVENTS.md 还是 RFC 的哪一句。
// 其中一部分是“仪器的行为与文字不一致”的复现，问题修好以后都应当通过；
// 另一部分是审查时补的覆盖（并发、退出、分片、半关）。
//
// 修复时改写了两个测试，因为它们断言的是修不到的行为，改成断言 EVENTS.md 现在写明的行为：
// TestReviewInvalidUTF8InStringFields（非法 UTF-8 在字符串字段里是 U+FFFD，原样字节在 head_b64）、
// TestReviewTunnelRequestRejectedByNetHTTP（net/http 自己拒掉的请求没有 origin_request，是写明的盲区）。

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// D11：用例的用户名里有冒号（sess:ab12），配置是 accept=[["sess:ab12","kaoju-pass-1"]] 加 accept_any_user。
// PROTOCOL.md：“accept_any_user 为真时任何用户名都接受，只要密码等于 accept[0][1]”；“auth.accept 按字节比较”。
// 客户端按 RFC 7617 发 base64("sess:ab12:kaoju-pass-1")。仪器按第一个冒号拆，得到密码 "ab12:kaoju-pass-1"，
// 与 accept[0][1] 不等，于是把配置里写明要接受的凭据判成 bad、回 407。
func TestReviewBasicUserWithColon(t *testing.T) {
	for _, anyUser := range []bool{true, false} {
		t.Run(fmt.Sprintf("accept_any_user=%v", anyUser), func(t *testing.T) {
			e := startEnv(t, fmt.Sprintf(
				`{"auth":{"mode":"basic","accept":[["sess:ab12","kaoju-pass-1"]],"accept_any_user":%v}}`, anyUser))
			c := e.dialProxy()
			c.send("GET http://a.kaoju.test/echo?k=D11.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\n" +
				"Proxy-Authorization: " + basicAuth("sess:ab12", "kaoju-pass-1") + "\r\n\r\n")
			r := c.readResp()
			c.finish()
			evs := e.stop()
			hr := one(t, evs.of("http_request"), "http_request")
			t.Logf("auth.user=%q auth.pass=%q auth.result=%q", hr.obj("auth").str("user"), hr.obj("auth").str("pass"),
				hr.obj("auth").str("result"))
			wantEq(t, "配置里写明要接受的凭据：状态码", r.status, 200)
			wantEq(t, "配置里写明要接受的凭据：auth.result", hr.obj("auth").str("result"), "ok")
		})
	}
}

// PROTOCOL.md：auth.on407=keepalive 是“407 带 Content-Length，连接留着”；connect.fail 的 close=false 是不关。
// 实现里请求带 Proxy-Connection: close（非标准头；https-proxy-agent 默认就在 CONNECT 里带它）时，
// 仪器照样加 Connection: close 并关连接。于是“407 之后重试走哪条连接”（R33）、
// “CONNECT 失败但代理没关连接”（R88）在这类客户端上量到的是仪器自己关的连接。
func TestReviewProxyConnectionCloseOverridesProfile(t *testing.T) {
	t.Run("on407=keepalive", func(t *testing.T) {
		e := startEnv(t, `{"auth":{"mode":"basic","accept":[["u","p"]]}}`)
		c := e.dialProxy()
		c.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\nProxy-Connection: close\r\n\r\n")
		r := c.readResp()
		wantEq(t, "状态码", r.status, 407)
		if v, ok := r.get("Connection"); ok {
			t.Errorf("on407=keepalive 的 407 带了 Connection: %s", v)
		}
		closed := peerClosedWithin(c, 500*time.Millisecond)
		if closed {
			t.Errorf("on407=keepalive：仪器把连接关了（PROTOCOL.md 写的是“连接留着”）")
		}
		c.finish()
		evs := e.stop()
		wantEq(t, "http_response.close", one(t, evs.of("http_response"), "http_response")["close"], any(false))
	})
	t.Run("connect.fail close=false", func(t *testing.T) {
		e := startEnv(t, `{"connect":{"fail":{"status":502,"close":false}}}`)
		c := e.dialProxy()
		c.send("CONNECT fail.kaoju.test:443 HTTP/1.1\r\nHost: fail.kaoju.test:443\r\nProxy-Connection: close\r\n\r\n")
		r := c.readResp()
		wantEq(t, "状态码", r.status, 502)
		if peerClosedWithin(c, 500*time.Millisecond) {
			t.Errorf("connect.fail 的 close=false：仪器把连接关了")
		}
		c.finish()
		e.stop()
	})
}

// peerClosedWithin 报告对端是否在 d 之内关了连接（FIN 或 RST）。
func peerClosedWithin(c *rawConn, d time.Duration) bool {
	_ = c.tcp.SetReadDeadline(time.Now().Add(d))
	defer c.tcp.SetReadDeadline(time.Time{})
	_, err := c.br.Peek(1)
	if err == nil {
		return false
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		c.mu.Lock()
		c.lossy = true
		c.mu.Unlock()
	}
	return true
}

// EVENTS.md“通用约定”：http_request 的 target、headers、auth.raw 没有 _hex 字段。非法 UTF-8 的字节在这些
// 字符串字段里每个换成一个 U+FFFD（JSON 表示不了原样的字节），所以 0xE9 和 0xFF 在事件里是同一个字符；
// 原样的字节在 head_b64 里。审查时这个测试断言“不出现 U+FFFD”，对照的是 EVENTS.md 当时写错的一句话；
// 修的是文档，测试改成断言文档现在写明的行为。
func TestReviewInvalidUTF8InStringFields(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	req := "GET http://a.kaoju.test/echo?k=U8.s1&x=\xff HTTP/1.1\r\nHost: a.kaoju.test\r\nX-Raw: caf\xe9\r\n" +
		"Proxy-Authorization: Basic \xe9\xe9\xe9=\r\n\r\n"
	c.send(req)
	wantEq(t, "状态码", c.readResp().status, 200)
	c.finish()
	evs := e.stop()
	hr := one(t, evs.of("http_request"), "http_request")
	raw, _ := base64.StdEncoding.DecodeString(hr.str("head_b64"))
	wantEq(t, "head_b64 是原样的字节", string(raw), req)
	const repl = "\ufffd"
	wantEq(t, "http_request.target", hr.str("target"), "http://a.kaoju.test/echo?k=U8.s1&x="+repl)
	wantEq(t, "http_request.k 不受影响", hr.str("k"), "U8.s1")
	wantPairs(t, "http_request.headers", hr.pairs("headers"), [][2]string{
		{"Host", "a.kaoju.test"}, {"X-Raw", "caf" + repl}, {"Proxy-Authorization", "Basic " + repl + repl + repl + "="}})
	a := hr.obj("auth")
	wantEq(t, "http_request.auth.raw", a.str("raw"), "Basic "+repl+repl+repl+"=")
	wantEq(t, "http_request.auth.result", a.str("result"), "malformed")
	if a["user"] != nil || a["user_hex"] != nil {
		t.Errorf("base64 解不开时 auth.user、auth.user_hex 应为 null: %v %v", a["user"], a["user_hex"])
	}
}

// RFC 9112 第 6.1 节：请求同时带 Content-Length 和 Transfer-Encoding 时，服务端可以拒绝，也可以只按
// Transfer-Encoding 处理，“Regardless, the server MUST close the connection after responding to such a request”。
// 仪器按 chunked 处理后把连接留着。
func TestReviewTEAndCLMustClose(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("POST http://a.kaoju.test/echo?k=TECL.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\n" +
		"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
	r := c.readResp()
	t.Logf("状态码 %d，Connection=%q", r.status, strings.Join(r.all("Connection"), ","))
	if !peerClosedWithin(c, 500*time.Millisecond) {
		t.Errorf("同时带 Content-Length 和 Transfer-Encoding 的请求回应之后，连接没有关（RFC 9112 6.1 要求关）")
	}
	c.finish()
	evs := e.stop()
	hr := one(t, evs.of("http_request"), "http_request")
	wantEq(t, "按 chunked 解出的正文长度", hr.num("body_len"), 5)
}

// RFC 9110 第 9.3.6 节：“A CONNECT request message does not have content. The interpretation of data sent after
// the header section of the CONNECT request message is specific to the version of HTTP in use.”
// 带 Content-Length 的 CONNECT 不读“正文”：马上回 200，之后的字节全是隧道数据；http_request.error 里记一笔。
func TestReviewConnectWithContentLength(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\nContent-Length: 5\r\n\r\n")
	wantEq(t, "CONNECT 的状态码", c.readResp().status, 200)
	get := getReq("/echo?k=CCL.s1", "a.kaoju.test")
	c.send(get)
	wantEq(t, "隧道里的请求", c.readResp().echo(t).str("k"), "CCL.s1")

	// Content-Length: 0 和不带一样，不记 error；带 Transfer-Encoding 的同样不读正文。
	c0 := e.dialProxy()
	c0.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\nContent-Length: 0\r\n\r\n")
	wantEq(t, "Content-Length: 0 的 CONNECT", c0.readResp().status, 200)
	c1 := e.dialProxy()
	c1.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\nTransfer-Encoding: chunked\r\n\r\n")
	wantEq(t, "带 Transfer-Encoding 的 CONNECT", c1.readResp().status, 200)
	c.finish()
	c0.finish()
	c1.finish()
	evs := e.stop()
	hr := one(t, evs.conn(e.connID(c)).of("http_request"), "http_request")
	wantEq(t, "http_request.body_len", hr.num("body_len"), 0)
	wantEq(t, "http_request.error", hr.str("error"), "connect_framing_ignored")
	tf := one(t, evs.conn(e.connID(c)).of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "tunnel_first_bytes.hex", tf.str("hex"), fmt.Sprintf("%x", get[:16]))
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "http")
	if v := one(t, evs.conn(e.connID(c0)).of("http_request"), "http_request")["error"]; v != nil {
		t.Errorf("Content-Length: 0 的 CONNECT：error = %v，应为 null", v)
	}
	wantEq(t, "带 Transfer-Encoding 的 CONNECT：error",
		one(t, evs.conn(e.connID(c1)).of("http_request"), "http_request").str("error"), "connect_framing_ignored")
}

// 客户端半关（发完请求就发 FIN，然后等响应）：响应照样送到，conn_end 记 client/fin，字节数对得上。
// 三条路都测：绝对形式、CONNECT 到 80 的隧道、SOCKS5 的隧道。
func TestReviewClientHalfClose(t *testing.T) {
	e := startEnv(t, `{}`)

	c1 := e.dialProxy()
	c1.send("GET http://a.kaoju.test/echo?k=HC.s1&delay=200 HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n")
	_ = c1.tcp.CloseWrite()
	wantEq(t, "绝对形式：半关以后的响应", c1.readResp().echo(t).str("k"), "HC.s1")
	c1.expectEOF(3 * time.Second)

	c2 := e.dialProxy()
	c2.connect("a.kaoju.test:80")
	c2.send(getReq("/echo?k=HC.s2&delay=200", "a.kaoju.test"))
	_ = c2.tcp.CloseWrite()
	wantEq(t, "CONNECT 隧道：半关以后的响应", c2.readResp().echo(t).str("k"), "HC.s2")
	c2.expectEOF(3 * time.Second)

	c3 := e.dialProxy()
	c3.sendBytes(append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 80)...))
	wantBytes(t, "方法应答", c3.readN(2), []byte{0x05, 0x00})
	wantBytes(t, "应答", c3.readN(10), socksOKReply)
	c3.send(getReq("/echo?k=HC.s3&delay=200", "a.kaoju.test"))
	_ = c3.tcp.CloseWrite()
	wantEq(t, "SOCKS5 隧道：半关以后的响应", c3.readResp().echo(t).str("k"), "HC.s3")
	c3.expectEOF(3 * time.Second)

	evs := e.stop()
	for i, c := range []*rawConn{c1, c2, c3} {
		end := one(t, evs.conn(e.connID(c)).of("conn_end"), "conn_end")
		wantEq(t, fmt.Sprintf("第 %d 条：conn_end.by", i+1), end.str("by"), "client")
		wantEq(t, fmt.Sprintf("第 %d 条：conn_end.close", i+1), end.str("close"), "fin")
	}
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 3)
}

// fin 关法在“接收队列里还有大量没读的数据”时也必须发 FIN 而不是 RST（PROTOCOL.md：先半关、把对方还在发的读掉）。
// 407 带 Connection: close 之后，客户端还有 4 MiB 在路上：对端应当先完整收到 407，再读到 EOF；
// 这 4 MiB 全部记进 bytes_in（超过 probePeer 一轮能清点的 2 MiB）。
func TestReviewFinCloseWithLargeBacklog(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["u","p"]],"on407":"close"}}`)
	c := e.dialProxy()
	junk := bytes.Repeat([]byte("x"), 4<<20)
	var wg sync.WaitGroup
	wg.Add(1)
	var werr error
	go func() {
		defer wg.Done()
		if _, werr = c.Write([]byte(absGet("BK.s1"))); werr != nil {
			return
		}
		if _, werr = c.Write(junk); werr != nil {
			return
		}
		_ = c.tcp.CloseWrite()
	}()
	r := c.readResp()
	wantEq(t, "状态码", r.status, 407)
	_ = c.tcp.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	n, err := c.br.Read(b[:])
	if n != 0 || err != io.EOF {
		t.Errorf("407 之后应当读到 EOF（FIN），实际 n=%d err=%v", n, err)
	}
	wg.Wait()
	if werr != nil {
		t.Errorf("客户端还在发的时候写失败了（说明仪器发了 RST）: %v", werr)
	}
	c.finish()
	evs := e.stop()
	end := one(t, evs.of("conn_end"), "conn_end")
	wantEq(t, "conn_end.bytes_in", int64(end.num("bytes_in")), c.sent())
	wantEq(t, "http_request 的个数", len(evs.of("http_request")), 1)
}

// conn.idle_close_ms 的计时起点（PROTOCOL.md：“在两个请求之间空闲这么久”）：
// 还没有请求的新连接不计时；请求在处理中（源站延迟）不算空闲；响应写完以后才开始计。
func TestReviewConnIdleTimerStart(t *testing.T) {
	e := startEnv(t, `{"conn":{"idle_close_ms":400}}`)
	c := e.dialProxy()
	c.expectSilence(900 * time.Millisecond) // 新连接，还没有请求：不关
	start := time.Now()
	c.send("GET http://a.kaoju.test/echo?k=IDLE.s1&delay=800 HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n")
	wantEq(t, "处理时间超过空闲上限的请求照样得到响应", c.readResp().status, 200)
	got := time.Since(start)
	if got < 780*time.Millisecond {
		t.Errorf("响应来得太早: %v", got)
	}
	w := c.expectEOF(3 * time.Second)
	if w < 300*time.Millisecond || w > 800*time.Millisecond {
		t.Errorf("响应之后 %v 才关，应当在 400 毫秒左右", w)
	}
	c.finish()

	// 请求头只发了一半：不属于“两个请求之间”。记下仪器实际怎么做（不关），不作为缺陷。
	c2 := e.dialProxy()
	c2.send(absGet("IDLE.s2"))
	wantEq(t, "状态码", c2.readResp().status, 200)
	c2.send("GET http://a.kaoju.test/echo?k=IDLE.s3 HTT")
	if peerClosedWithin(c2, 900*time.Millisecond) {
		t.Logf("请求头发到一半时仪器按空闲关了连接")
	} else {
		t.Logf("请求头发到一半时仪器不按空闲关连接（一直等到头发完或仪器退出）")
	}
	c2.finish()
	evs := e.stop()
	wantEq(t, "conn_idle_close 的个数", len(evs.of("action")), 1)
}

// tunnel.idle_close_ms：“隧道两个方向都静默这么久就按 fin 关”。源站处理请求的那段时间两个方向也是静默的，
// 所以处理时间超过上限的请求会被空闲关闭打断。这里只把这个行为记下来（cases.json 里 F02 的请求没有 delay，不受影响）。
func TestReviewTunnelIdleDuringSlowResponse(t *testing.T) {
	e := startEnv(t, `{"tunnel":{"idle_close_ms":300}}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:80")
	c.send(getReq("/echo?k=TI.s1&delay=900", "a.kaoju.test"))
	_ = c.tcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := c.br.ReadString('\n')
	_ = c.tcp.SetReadDeadline(time.Time{})
	t.Logf("隧道里处理时间 900 毫秒、空闲上限 300 毫秒：读到 %q，err=%v", line, err)
	c.finish()
	evs := e.stop()
	if a := evs.of("action"); len(a) == 1 {
		t.Logf("仪器在请求处理中按空闲切断了隧道（action.what=%s）", a[0].str("what"))
	}
}

// 并发 50 条连接（绝对形式、CONNECT+TLS、SOCKS5 三种各占三分之一），每条连接上发 4 个请求。
// 事件必须完整：每条连接一个 accept、一个 conn_end，编号 1..50 各出现一次；隧道、源站连接的编号不重复；
// 每个 k 恰好到达源站一次；每条连接上请求的序号从 1 连续增长；字节数和哈希逐条相符（stop 里核对）。
func TestReviewConcurrent50(t *testing.T) {
	e := startEnv(t, `{}`)
	const conns, reqs = 50, 4
	var wg sync.WaitGroup
	errs := make(chan string, conns*reqs)
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := e.dialProxy()
			check := func(j int, r *resp) {
				want := fmt.Sprintf("CC.%d.%d", i, j)
				var ev event
				if err := json.Unmarshal(r.body, &ev); err != nil || r.status != 200 || ev.str("k") != want {
					errs <- fmt.Sprintf("连接 %d 请求 %d：状态码 %d，正文 %q", i, j, r.status, r.body)
				}
			}
			switch i % 3 {
			case 0:
				for j := 0; j < reqs; j++ {
					c.send(absGet(fmt.Sprintf("CC.%d.%d", i, j)))
					check(j, c.readResp())
				}
				c.finish()
			case 1:
				c.connect("a.kaoju.test:443")
				tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
				for j := 0; j < reqs; j++ {
					tc.send(getReq(fmt.Sprintf("/echo?k=CC.%d.%d", i, j), "a.kaoju.test"))
					check(j, tc.readResp())
				}
				tc.close()
			case 2:
				c.sendBytes(append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, 0x03, []byte("b.kaoju.test"), 80)...))
				c.readN(12)
				for j := 0; j < reqs; j++ {
					c.send(getReq(fmt.Sprintf("/echo?k=CC.%d.%d", i, j), "b.kaoju.test"))
					check(j, c.readResp())
				}
				c.finish()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for m := range errs {
		t.Error(m)
	}
	evs := e.stop()

	seen := map[string]map[int]int{"accept": {}, "conn_end": {}, "tunnel_open": {}, "tunnel_close": {}, "origin_conn": {}}
	for _, ev := range evs {
		switch name := ev.str("ev"); name {
		case "accept", "conn_end":
			seen[name][ev.num("conn")]++
		case "tunnel_open", "tunnel_close":
			seen[name][ev.num("tunnel")]++
		case "origin_conn":
			seen[name][ev.num("oconn")]++
		}
	}
	wantIDs := func(name string, n int) {
		t.Helper()
		if len(seen[name]) != n {
			t.Errorf("%s 的编号有 %d 个，应为 %d 个", name, len(seen[name]), n)
		}
		for id := 1; id <= n; id++ {
			if seen[name][id] != 1 {
				t.Errorf("%s 的编号 %d 出现了 %d 次", name, id, seen[name][id])
			}
		}
	}
	wantIDs("accept", conns)
	wantIDs("conn_end", conns)
	tunnels := conns - (conns+2)/3
	wantIDs("tunnel_open", tunnels)
	wantIDs("tunnel_close", tunnels)
	wantIDs("origin_conn", tunnels)

	ks := map[string]int{}
	lastSeq := map[string]int{}
	for _, or := range evs.of("origin_request") {
		ks[or.str("k")]++
		key := fmt.Sprintf("c%d", or.num("conn"))
		seq := or.num("seq")
		if or.str("via") == "forward" {
			seq = or.num("req_seq")
		}
		if seq != lastSeq[key]+1 {
			t.Errorf("连接 %d 上 origin_request 的序号从 %d 跳到 %d", or.num("conn"), lastSeq[key], seq)
		}
		lastSeq[key] = seq
	}
	wantEq(t, "不同的 k 的个数", len(ks), conns*reqs)
	for k, n := range ks {
		if n != 1 {
			t.Errorf("k=%s 到达源站 %d 次", k, n)
		}
	}
	for _, ev := range evs {
		if ev["late"] != nil {
			t.Errorf("出现了 late 事件: %v", ev)
		}
	}
}

// 仪器退出时各种“卡在半路”的连接：每条都必须有 conn_end，Shutdown 不能被拖住，退出以后不留协程。
// 这里不经过 env.stop（它会先把客户端一侧关掉），而是让连接保持原样直接 Shutdown。
func TestReviewShutdownWithStuckConns(t *testing.T) {
	before := runtime.NumGoroutine()
	e := startEnv(t, `{"tunnel":{"idle_close_ms":60000},"conn":{"idle_close_ms":60000}}`)

	silent := e.dialProxy() // 一个字节都不发
	halfHead := e.dialProxy()
	halfHead.send("GET http://a.kaoju.test/echo?k=SD.half HTT")
	halfBody := e.dialProxy()
	halfBody.send("POST http://a.kaoju.test/echo?k=SD.body HTTP/1.1\r\nHost: a.kaoju.test\r\nContent-Length: 100\r\n\r\n0123456789")
	halfSocks := e.dialProxy()
	halfSocks.sendBytes([]byte{0x05, 0x01, 0x00, 0x05, 0x01})
	emptyTunnel := e.dialProxy()
	emptyTunnel.connect("a.kaoju.test:443")
	halfHello := e.dialProxy()
	halfHello.connect("a.kaoju.test:443")
	halfHello.sendBytes([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00})
	slowForward := e.dialProxy()
	slowForward.send("GET http://a.kaoju.test/echo?k=SD.fwd&delay=30000 HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n")
	slowTunnel := e.dialProxy()
	slowTunnel.connect("a.kaoju.test:80")
	slowTunnel.send(getReq("/echo?k=SD.tun&delay=30000", "a.kaoju.test"))
	idleKeepalive := e.dialProxy()
	idleKeepalive.send(absGet("SD.idle"))
	wantEq(t, "状态码", idleKeepalive.readResp().status, 200)
	direct := e.dial(e.sp, "origin_https")
	direct.sendBytes([]byte{0x16, 0x03})
	all := []*rawConn{silent, halfHead, halfBody, halfSocks, emptyTunnel, halfHello, slowForward, slowTunnel, idleKeepalive, direct}
	time.Sleep(300 * time.Millisecond)

	e.stopped = true
	start := time.Now()
	done := make(chan struct{})
	go func() { e.srv.Shutdown("test"); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown 10 秒没有返回")
	}
	took := time.Since(start)
	if took > 5*time.Second {
		t.Errorf("Shutdown 用了 %v", took)
	}
	t.Logf("Shutdown 用了 %v", took)
	for _, c := range all {
		c.mu.Lock()
		c.done = true
		c.mu.Unlock()
		_ = c.tcp.Close()
	}
	evs := readEvents(t, e.evPath)
	e.evs = evs

	wantEq(t, "第一个事件", evs[0].str("ev"), "start")
	wantEq(t, "最后一个事件", evs[len(evs)-1].str("ev"), "end")
	wantEq(t, "end.events", evs[len(evs)-1].num("events"), len(evs))
	ended := map[int]bool{}
	for i, ev := range evs {
		id := ev.num("conn")
		if ev.str("ev") == "conn_end" {
			if ended[id] {
				t.Errorf("连接 %d 有两个 conn_end", id)
			}
			ended[id] = true
			continue
		}
		if id != 0 && ended[id] && ev["late"] != true {
			t.Errorf("第 %d 行（%s）：连接 %d 已经 conn_end，事件却没有带 late", i+1, ev.str("ev"), id)
		}
		if ev["late"] == true {
			t.Logf("late 事件: %s conn=%d", ev.str("ev"), id)
		}
	}
	wantEq(t, "accept 的个数", len(evs.of("accept")), len(all))
	wantEq(t, "conn_end 的个数", len(evs.of("conn_end")), len(all))
	wantEq(t, "tunnel_open 与 tunnel_close 的个数相等", len(evs.of("tunnel_close")), len(evs.of("tunnel_open")))
	for _, c := range all {
		end := one(t, evs.conn(e.connID(c)).of("conn_end"), "conn_end")
		wantEq(t, "conn_end.reason", end.str("reason"), "shutdown")
		wantEq(t, "conn_end.bytes_in", int64(end.num("bytes_in")), c.sent())
	}

	// 协程：给收尾一点时间，然后不应比开始时多出一截。
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+2 {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Errorf("Shutdown 之后还有 %d 个协程（开始时 %d 个）\n%s", n, before, buf)
	}
}

// 客户端不读：隧道里连发很多请求但一个响应都不读，直到仪器的写阻塞。仪器退出时照样要能收尾。
func TestReviewShutdownWhenClientDoesNotRead(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:80")
	_ = c.tcp.SetReadBuffer(4096)
	big := strings.Repeat("a", 30000)
	req := getReq("/echo?k=NR.s1", "a.kaoju.test", "X-Pad: "+big+"\r\n")
	_ = c.tcp.SetWriteDeadline(time.Now().Add(3 * time.Second))
	sent := 0
	for i := 0; i < 400; i++ {
		if _, err := c.Write([]byte(req)); err != nil {
			break // 两边的缓冲区都满了：仪器的写已经阻塞
		}
		sent++
	}
	_ = c.tcp.SetWriteDeadline(time.Time{})
	t.Logf("写阻塞之前发出了 %d 个请求", sent)

	e.stopped = true
	done := make(chan struct{})
	start := time.Now()
	go func() { e.srv.Shutdown("test"); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("客户端不读时 Shutdown 10 秒没有返回")
	}
	t.Logf("Shutdown 用了 %v", time.Since(start))
	c.mu.Lock()
	c.done = true
	c.mu.Unlock()
	_ = c.tcp.Close()
	evs := readEvents(t, e.evPath)
	wantEq(t, "conn_end 的个数", len(evs.of("conn_end")), 1)
	wantEq(t, "最后一个事件", evs[len(evs)-1].str("ev"), "end")
}

// SOCKS5 整个握手一个字节一个字节地到（RFC 1928 第 3、4 节，RFC 1929 第 2 节），隧道里的请求也一样：
// 每条消息照样完整解析，事件里的 raw_hex 与发出的字节相同，应答逐字节符合 RFC。
func TestReviewSocks5ByteByByte(t *testing.T) {
	e := startEnv(t, `{"socks":{"auth":"userpass"},"auth":{"accept":[["kaoju-user","kaoju-pass-1"]]}}`)
	c := e.dialProxy()
	drip := func(b []byte) {
		for i := range b {
			c.sendBytes(b[i : i+1])
			time.Sleep(2 * time.Millisecond)
		}
	}
	greeting := []byte{0x05, 0x03, 0x00, 0x01, 0x02}
	drip(greeting)
	wantBytes(t, "方法应答（RFC 1928 第 3 节：VER=5，METHOD=2）", c.readN(2), []byte{0x05, 0x02})
	auth := socksUserPass([]byte("kaoju-user"), []byte("kaoju-pass-1"))
	drip(auth)
	wantBytes(t, "认证应答（RFC 1929 第 2 节：VER=1，STATUS=0）", c.readN(2), []byte{0x01, 0x00})
	req := socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 80)
	drip(req)
	wantBytes(t, "应答（RFC 1928 第 6 节）", c.readN(10), socksOKReply)
	drip([]byte(getReq("/echo?k=BB.s1", "a.kaoju.test")))
	wantEq(t, "隧道里的请求", c.readResp().echo(t).str("k"), "BB.s1")
	c.finish()
	evs := e.stop()
	wantEq(t, "first_bytes.n_first_read", one(t, evs.of("first_bytes"), "first_bytes").num("n_first_read"), 1)
	wantEq(t, "socks5_greeting.raw_hex", one(t, evs.of("socks5_greeting"), "greeting").str("raw_hex"), fmt.Sprintf("%x", greeting))
	a := one(t, evs.of("socks5_auth"), "socks5_auth")
	wantEq(t, "socks5_auth.user", a.str("user"), "kaoju-user")
	wantEq(t, "socks5_auth.pass", a.str("pass"), "kaoju-pass-1")
	wantEq(t, "socks5_request.raw_hex", one(t, evs.of("socks5_request"), "request").str("raw_hex"), fmt.Sprintf("%x", req))
	tf := one(t, evs.of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "tunnel_first_bytes.n_first_read", tf.num("n_first_read"), 1)
	wantEq(t, "tunnel_first_bytes.early_bytes", tf.num("early_bytes"), 0)
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 1)
}

// SOCKS5 的边角：方法数为 0、ULEN/PLEN 为 0、子协商版本不对、BIND、UDP ASSOCIATE、ATYP 4、不认识的 ATYP、域名长度 0。
func TestReviewSocks5Edges(t *testing.T) {
	t.Run("NMETHODS=0", func(t *testing.T) {
		e := startEnv(t, `{}`)
		c := e.dialProxy()
		c.sendBytes([]byte{0x05, 0x00})
		wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0xff})
		c.expectEOF(3 * time.Second)
		c.finish()
		evs := e.stop()
		g := one(t, evs.of("socks5_greeting"), "socks5_greeting")
		wantEq(t, "methods 是空数组而不是 null", fmt.Sprint(g["methods"]), "[]")
		wantEq(t, "conn_end.reason", one(t, evs.of("conn_end"), "conn_end").str("reason"), "socks_no_method")
	})
	t.Run("ULEN=0 PLEN=0", func(t *testing.T) {
		// accept_any_user 加空密码（S21 的配置）：空用户名、空密码也算通过。
		e := startEnv(t, `{"socks":{"auth":"userpass"},"auth":{"accept":[["kaoju-user",""]],"accept_any_user":true}}`)
		c := e.dialProxy()
		c.sendBytes([]byte{0x05, 0x01, 0x02})
		wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x02})
		c.sendBytes([]byte{0x01, 0x00, 0x00})
		wantBytes(t, "认证应答", c.readN(2), []byte{0x01, 0x00})
		c.sendBytes(socksRequest(0x01, 0x01, []byte{127, 0, 0, 1}, 80))
		wantBytes(t, "应答", c.readN(10), socksOKReply)
		c.finish()
		evs := e.stop()
		a := one(t, evs.of("socks5_auth"), "socks5_auth")
		wantEq(t, "ulen", a.num("ulen"), 0)
		wantEq(t, "plen", a.num("plen"), 0)
		wantEq(t, "user_hex", a["user_hex"], any(""))
		wantEq(t, "user", a["user"], any(""))
		wantEq(t, "result", a.str("result"), "ok")
	})
	t.Run("子协商 VER 不是 1", func(t *testing.T) {
		e := startEnv(t, `{"socks":{"auth":"userpass","auth_fail_status":7},"auth":{"accept":[["u","p"]]}}`)
		c := e.dialProxy()
		c.sendBytes([]byte{0x05, 0x01, 0x02})
		c.readN(2)
		c.sendBytes([]byte{0x05, 0x01, 'u', 0x01, 'p'})
		wantBytes(t, "认证应答（状态是配置的 auth_fail_status）", c.readN(2), []byte{0x01, 0x07})
		c.expectEOF(3 * time.Second)
		c.finish()
		evs := e.stop()
		wantEq(t, "result", one(t, evs.of("socks5_auth"), "socks5_auth").str("result"), "malformed")
		wantEq(t, "socks5_request 的个数", len(evs.of("socks5_request")), 0)
	})
	for _, tc := range []struct {
		name string
		req  []byte
		rep  byte
	}{
		{"BIND", socksRequest(0x02, 0x03, []byte("a.kaoju.test"), 80), 0x07},
		{"UDP ASSOCIATE", socksRequest(0x03, 0x01, []byte{0, 0, 0, 0}, 0), 0x07},
		{"ATYP 4 加 BIND", socksRequest(0x02, 0x04, make([]byte, 16), 80), 0x07},
		{"不认识的 ATYP", []byte{0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4, 0, 80}, 0x08},
		{"端口对不上", socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 8080), 0x05},
		{"请求的 VER 不是 5", []byte{0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}, 0x01},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := startEnv(t, `{}`)
			c := e.dialProxy()
			c.sendBytes([]byte{0x05, 0x01, 0x00})
			wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x00})
			c.sendBytes(tc.req)
			wantBytes(t, "应答", c.readN(10), []byte{0x05, tc.rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			c.expectEOF(3 * time.Second)
			c.finish()
			evs := e.stop()
			wantEq(t, "tunnel_open 的个数", len(evs.of("tunnel_open")), 0)
			wantEq(t, "conn_end.reason", one(t, evs.of("conn_end"), "conn_end").str("reason"), "socks_reply_failure")
		})
	}
	t.Run("ATYP 4 CONNECT", func(t *testing.T) {
		e := startEnv(t, `{}`)
		c := e.dialProxy()
		c.sendBytes([]byte{0x05, 0x01, 0x00})
		c.readN(2)
		v6 := make([]byte, 16)
		v6[15] = 1
		c.sendBytes(socksRequest(0x01, 0x04, v6, 80))
		wantBytes(t, "应答", c.readN(10), socksOKReply)
		c.send(getReq("/echo?k=V6.s1", "localhost"))
		wantEq(t, "隧道里的请求", c.readResp().echo(t).str("k"), "V6.s1")
		c.finish()
		evs := e.stop()
		wantEq(t, "socks5_request.host", one(t, evs.of("socks5_request"), "socks5_request").str("host"), "::1")
		wantEq(t, "tunnel_open.target_host", one(t, evs.of("tunnel_open"), "tunnel_open").str("target_host"), "::1")
	})
	t.Run("域名长度 0", func(t *testing.T) {
		// RFC 1928 没有禁止长度为 0 的域名，但它不指向任何主机。记下仪器的做法：照样建隧道。
		e := startEnv(t, `{}`)
		c := e.dialProxy()
		c.sendBytes([]byte{0x05, 0x01, 0x00})
		c.readN(2)
		c.sendBytes([]byte{0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 80})
		rep := c.readN(10)
		t.Logf("域名长度为 0 的 CONNECT：应答码 %d", rep[1])
		c.finish()
		e.stop()
	})
}

// HTTP 分帧的边角（RFC 9112 第 2.2、5、6、7.1 节）。每一行是一条连接上连续发出的字节和依次应当得到的状态码；
// closed 表示最后一个响应之后仪器应当关连接。
func TestReviewHTTPFramingEdges(t *testing.T) {
	const next = "GET http://a.kaoju.test/echo?k=NEXT HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n"
	post := func(headers, body string) string {
		return "POST http://a.kaoju.test/echo?k=FE HTTP/1.1\r\nHost: a.kaoju.test\r\n" + headers + "\r\n" + body
	}
	cases := []struct {
		name     string
		wire     string
		statuses []int
		bodyLen  int // 第一个请求的正文长度；-1 表示不查
		closed   bool
	}{
		{"请求行前的空行（2.2）", "\r\n\r\n" + next, []int{200}, 0, false},
		{"POST 正文后多一个 CRLF 再接下一个请求（2.2）", post("Content-Length: 3\r\n", "abc") + "\r\n" + next, []int{200, 200}, 3, false},
		{"Content-Length: 0 后接管线化的请求", post("Content-Length: 0\r\n", "") + next, []int{200, 200}, 0, false},
		{"两个相同的 Content-Length（6.3）", post("Content-Length: 3\r\nContent-Length: 3\r\n", "abc") + next, []int{200, 200}, 3, false},
		{"Content-Length: 3, 3（6.3）", post("Content-Length: 3, 3\r\n", "abc") + next, []int{200, 200}, 3, false},
		{"Content-Length 带正号", post("Content-Length: +3\r\n", "abc"), []int{400}, -1, true},
		{"Content-Length 为负", post("Content-Length: -1\r\n", ""), []int{400}, -1, true},
		{"Content-Length 溢出", post("Content-Length: 99999999999999999999\r\n", ""), []int{400}, -1, true},
		{"chunked：只有结束块", post("Transfer-Encoding: chunked\r\n", "0\r\n\r\n") + next, []int{200, 200}, 0, false},
		{"chunked：带 trailer（7.1.2）", post("Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\nX-T: 1\r\nX-U: 2\r\n\r\n") + next, []int{200, 200}, 5, false},
		{"chunked：大写十六进制、前导零、块扩展（7.1.1）", post("Transfer-Encoding: chunked\r\n", "00A;x=y;z\r\n0123456789\r\n0;last\r\n\r\n") + next, []int{200, 200}, 10, false},
		{"chunked：名字大小写不同", post("transfer-encoding: Chunked\r\n", "1\r\na\r\n0\r\n\r\n") + next, []int{200, 200}, 1, false},
		{"chunked：块长度行只有 LF", post("Transfer-Encoding: chunked\r\n", "5\nhello\r\n0\r\n\r\n"), []int{400}, -1, true},
		{"chunked：块数据后面不是 CRLF", post("Transfer-Encoding: chunked\r\n", "5\r\nhelloXX0\r\n\r\n"), []int{400}, -1, true},
		{"chunked：块长度不是十六进制", post("Transfer-Encoding: chunked\r\n", "5g\r\nhello\r\n0\r\n\r\n"), []int{400}, -1, true},
		{"chunked：块长度溢出", post("Transfer-Encoding: chunked\r\n", "FFFFFFFFFFFFFFFFF\r\n"), []int{400}, -1, true},
		{"chunked：块长度为负", post("Transfer-Encoding: chunked\r\n", "-5\r\nhello\r\n0\r\n\r\n"), []int{400}, -1, true},
		{"chunked：trailer 没有冒号", post("Transfer-Encoding: chunked\r\n", "0\r\nbroken\r\n\r\n"), []int{400}, -1, true},
		{"Transfer-Encoding: gzip, chunked", post("Transfer-Encoding: gzip, chunked\r\n", "0\r\n\r\n"), []int{400}, -1, true},
		{"Transfer-Encoding: chunked, chunked", post("Transfer-Encoding: chunked, chunked\r\n", "0\r\n\r\n"), []int{400}, -1, true},
		{"HTTP/1.0 带 Transfer-Encoding（6.1）", "POST http://a.kaoju.test/echo?k=FE HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", []int{400}, -1, true},
		{"头的值里有制表符（5.5）", "GET http://a.kaoju.test/echo?k=FE HTTP/1.1\r\nHost: a.kaoju.test\r\nX-Tab:\ta\tb\t\r\n\r\n", []int{200}, 0, false},
		{"请求行用制表符分隔（3）", "GET\thttp://a.kaoju.test/echo?k=FE\tHTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n", []int{400}, -1, true},
		{"请求行里两个空格（3）", "GET  http://a.kaoju.test/echo?k=FE HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n", []int{400}, -1, true},
		{"头的值里有裸 CR（2.2）", "GET http://a.kaoju.test/echo?k=FE HTTP/1.1\r\nHost: a.kaoju.test\r\nX-A: a\rb\r\n\r\n", []int{400}, -1, true},
		{"头的值里有 NUL", "GET http://a.kaoju.test/echo?k=FE HTTP/1.1\r\nHost: a.kaoju.test\r\nX-A: a\x00b\r\n\r\n", []int{400}, -1, true},
		{"Expect: 100-continue 但 Content-Length 是 0：不回 100", post("Expect: 100-continue\r\nContent-Length: 0\r\n", "") + next, []int{200, 200}, 0, false},
		{"Connection: close 后面管线化的请求不处理（9.6）", "GET http://a.kaoju.test/echo?k=FE HTTP/1.1\r\nHost: a.kaoju.test\r\nConnection: close\r\n\r\n" + next, []int{200}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := startEnv(t, `{}`)
			c := e.dialProxy()
			c.send(tc.wire)
			for i, want := range tc.statuses {
				r := c.readResp()
				wantEq(t, fmt.Sprintf("第 %d 个响应的状态码", i+1), r.status, want)
			}
			if tc.closed {
				c.expectEOF(3 * time.Second)
			} else {
				c.expectSilence(150 * time.Millisecond)
			}
			c.finish()
			evs := e.stop()
			hrs := evs.of("http_request")
			if len(hrs) != len(tc.statuses) {
				t.Errorf("http_request 有 %d 个，应为 %d 个", len(hrs), len(tc.statuses))
			}
			if tc.bodyLen >= 0 && len(hrs) > 0 {
				wantEq(t, "http_request.body_len", hrs[0].num("body_len"), tc.bodyLen)
			}
			// head_b64 必须是线上字节的原样片段。
			for _, hr := range hrs {
				raw, _ := base64.StdEncoding.DecodeString(hr.str("head_b64"))
				if len(raw) == 0 || !strings.Contains(tc.wire, string(raw)) {
					t.Errorf("head_b64 不是发出去的字节的原样片段: %q", raw)
				}
			}
			if tc.name == "头的值里有制表符（5.5）" && len(hrs) == 1 {
				hs := hrs[0].pairs("headers")
				wantEq(t, "X-Tab 的值（只去首尾的空白，中间的制表符原样）", hs[len(hs)-1][1], "a\tb")
			}
		})
	}
}

// 正文一个字节一个字节地到（Content-Length 和 chunked 各一次），后面紧跟管线化的请求：分帧不能错位。
func TestReviewBodyByteByByte(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["u","p"]]}}`)
	c := e.dialProxy()
	auth := "Proxy-Authorization: " + basicAuth("u", "p") + "\r\n"
	wire := "POST http://a.kaoju.test/echo?k=BB.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\nContent-Length: 11\r\n\r\nhello world" + // 没带凭据：407，正文要读完
		"POST http://a.kaoju.test/echo?k=BB.s2 HTTP/1.1\r\nHost: a.kaoju.test\r\n" + auth + "Transfer-Encoding: chunked\r\n\r\n" +
		"3\r\nabc\r\n8\r\n12345678\r\n0\r\nX-T: v\r\n\r\n" +
		"GET http://a.kaoju.test/echo?k=BB.s3 HTTP/1.1\r\nHost: a.kaoju.test\r\n" + auth + "\r\n"
	go func() {
		for i := 0; i < len(wire); i++ {
			if _, err := c.Write([]byte{wire[i]}); err != nil {
				return
			}
			if i%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	wantEq(t, "第 1 个（没带凭据）", c.readResp().status, 407)
	r2 := c.readResp()
	wantEq(t, "第 2 个", r2.status, 200)
	wantEq(t, "第 2 个的正文长度", r2.echo(t).num("body_len"), 11)
	wantEq(t, "第 2 个的正文哈希", r2.echo(t).str("body_sha256"), sha256hex([]byte("abc12345678")))
	wantEq(t, "第 3 个", c.readResp().echo(t).str("k"), "BB.s3")
	c.finish()
	evs := e.stop()
	hrs := evs.of("http_request")
	wantEq(t, "http_request 的个数", len(hrs), 3)
	wantEq(t, "第 1 个的 body_len", hrs[0].num("body_len"), 11)
	wantEq(t, "第 1 个的 body_sha256", hrs[0].str("body_sha256"), sha256hex([]byte("hello world")))
	wantEq(t, "first_bytes.n_first_read", one(t, evs.of("first_bytes"), "first_bytes").num("n_first_read"), 1)
}

// EVENTS.md“通用约定”：“字段的先后固定（t、ev、conn 在最前）。下面的表按字段出现的顺序列出。”
// 拿一次覆盖各种事件的真实运行，逐行核对事件文件里字段的先后与 eventFields（也就是 EVENTS.md 的表）一致，
// 嵌套的 auth、tls 对象也一样。
func TestReviewEventFieldOrder(t *testing.T) {
	e := startEnv(t, `{"socks":{"auth":"userpass"},"auth":{"accept":[["u","p"]]},"conn":{"drop":{"k":"FO.drop"}},
		"origin":{"drop":{"k":"FO.odrop"}}}`)
	c := e.dialProxy()
	c.send(absGet("FO.s1"))
	c.readResp()
	c.send(absGet("FO.drop"))
	c.expectEOF(3 * time.Second)
	c.finish()
	c2 := e.dialProxy()
	c2.connect("a.kaoju.test:443")
	tc := e.startTLS(c2, "a.kaoju.test", "http/1.1")
	tc.send(getReq("/echo?k=FO.s2", "a.kaoju.test"))
	tc.readResp()
	tc.send(getReq("/echo?k=FO.odrop", "a.kaoju.test"))
	_, _ = io.Copy(io.Discard, tc.br)
	c2.finish()
	c3 := e.dialProxy()
	c3.sendBytes([]byte{0x05, 0x01, 0x02})
	c3.readN(2)
	c3.sendBytes(socksUserPass([]byte("u"), []byte("p")))
	c3.readN(2)
	c3.sendBytes(socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 80))
	c3.readN(10)
	c3.send(getReq("/echo?k=FO.s3", "a.kaoju.test"))
	c3.readResp()
	c3.finish()
	e.stop()

	data, err := os.ReadFile(e.evPath)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		keys, nested := topLevelKeys(t, line)
		name := ""
		var ev event
		_ = json.Unmarshal(line, &ev)
		name = ev.str("ev")
		seen[name] = true
		want := []string{"t", "ev"}
		if name != "start" && name != "end" {
			want = append(want, "conn")
		}
		want = append(want, eventFields[name]...)
		if strings.Join(keys, ",") != strings.Join(want, ",") {
			t.Errorf("第 %d 行（%s）字段的先后是 %v，EVENTS.md 的表是 %v", i+1, name, keys, want)
		}
		if k, ok := nested["auth"]; ok && strings.Join(k, ",") != strings.Join(authFields, ",") {
			t.Errorf("第 %d 行 auth 对象字段的先后是 %v，应为 %v", i+1, k, authFields)
		}
		if k, ok := nested["tls"]; ok && strings.Join(k, ",") != strings.Join(tlsFields, ",") {
			t.Errorf("第 %d 行 tls 对象字段的先后是 %v，应为 %v", i+1, k, tlsFields)
		}
	}
	for name := range knownEvents {
		if !seen[name] {
			t.Errorf("这次运行没有出现 %s 事件，字段的先后没有核对到", name)
		}
	}
}

// topLevelKeys 按出现的顺序返回一行 JSON 对象的键，以及值是对象的那些字段各自的键。
func topLevelKeys(t *testing.T, line []byte) (keys []string, nested map[string][]string) {
	t.Helper()
	nested = map[string][]string{}
	dec := json.NewDecoder(bytes.NewReader(line))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("不是 JSON 对象: %s", line)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		key := tok.(string)
		keys = append(keys, key)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatal(err)
		}
		if len(raw) > 0 && raw[0] == '{' && (key == "auth" || key == "tls") {
			sub, _ := topLevelKeys(t, raw)
			nested[key] = sub
		}
	}
	return keys, nested
}

// 绝对形式的 WebSocket 握手：PROTOCOL.md 说 /ws 才是 WebSocket 的路径。实现里只要带 Upgrade: websocket，
// 任何路径（这里是 /echo）都由代理直接回 101，而且不写 origin_request。
func TestReviewWebSocketAbsoluteAnyPath(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send(wsHandshake("http://a.kaoju.test/echo?k=WSX.s1", "a.kaoju.test"))
	r := c.readResp()
	if r.status == 101 {
		t.Errorf("对 /echo 的 WebSocket 握手得到了 101（隧道里同样的请求由源站按 /echo 处理，回 200）")
	}
	c.finish()
	e.stop()
}

// tunnel_first_bytes.kind 不应取决于 TCP 怎么分段：TLS 记录没到齐时仪器会等（最多 2 秒），
// 明文 HTTP 的请求行分两次到时却不等，按第一次读到的那一点字节归类，结果是 other。
// R06、R115、R116 直接取这个归类（“明文 HTTP”还是“其他”）。
func TestReviewTunnelFirstBytesHTTPSplit(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:80")
	req := getReq("/echo?k=SPLIT.s1", "a.kaoju.test")
	c.send(req[:2])
	time.Sleep(100 * time.Millisecond)
	c.send(req[2:])
	wantEq(t, "隧道里的请求", c.readResp().echo(t).str("k"), "SPLIT.s1")
	c.finish()
	evs := e.stop()
	tf := one(t, evs.of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "n_first_read", tf.num("n_first_read"), 2)
	wantEq(t, "请求行分两次到达时的归类", tf.str("kind"), "http")
}

// 隧道里（或直连上）被 net/http 自己拒掉的请求（这里是 HTTP/1.1 却没有 Host 头，net/http 直接回 400）
// 不经过仪器的处理函数，所以没有 origin_request。这是 EVENTS.md 的 origin_request 一节写明的盲区：
// 仪器不重新实现源站一侧的 HTTP 解析（TLS 之内的更是只有 net/http 看得到）。
// 审查时这个测试断言“有 1 个 origin_request”；改成断言文档写明的识别办法成立：
// 有 origin_conn、隧道两个方向都有字节、没有 origin_request。
func TestReviewTunnelRequestRejectedByNetHTTP(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:80")
	c.send("GET /echo?k=NOHOST.s1 HTTP/1.1\r\nProxy-Authorization: Basic eDp5\r\n\r\n")
	wantEq(t, "net/http 自己回的状态码", c.readResp().status, 400)
	c.finish()
	evs := e.stop()
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 0)
	one(t, evs.of("origin_conn"), "origin_conn")
	tc := one(t, evs.of("tunnel_close"), "tunnel_close")
	if tc.num("bytes_c2s") == 0 || tc.num("bytes_s2c") == 0 {
		t.Errorf("tunnel_close 的字节数应当两个方向都大于 0: c2s=%d s2c=%d", tc.num("bytes_c2s"), tc.num("bytes_s2c"))
	}
	wantEq(t, "tunnel_first_bytes.kind", one(t, evs.of("tunnel_first_bytes"), "tunnel_first_bytes").str("kind"), "http")
}

// ---- 以下是修复审查发现时补的测试 ----

// Connection: close 是标准的“这条连接到此为止”（RFC 9112 第 9.6 节），仪器照关，压过 on407=keepalive；
// http_response.close 如实记 true。与 Proxy-Connection: close（不算，见上面的测试）相对照。
func TestFixConnectionCloseStillHonored(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["u","p"]]}}`)
	c := e.dialProxy()
	c.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\nConnection: close\r\n\r\n")
	r := c.readResp()
	wantEq(t, "状态码", r.status, 407)
	if v, _ := r.get("Connection"); v != "close" {
		t.Errorf("407 的 Connection = %q，应为 close", v)
	}
	c.expectEOF(2 * time.Second)
	c.finish()
	evs := e.stop()
	wantEq(t, "http_response.close", one(t, evs.of("http_response"), "http_response")["close"], any(true))
	wantEq(t, "conn_end.reason", one(t, evs.of("conn_end"), "conn_end").str("reason"), "response_close")
}

// 绝对形式、路径不是 /ws 而带 Upgrade: websocket 的请求照常交给源站的处理函数：有 origin_request，
// Upgrade 作为逐跳头不转交；/ws 仍由代理完成握手。
func TestFixWebSocketAbsoluteOnlyOnWsPath(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send(wsHandshake("http://a.kaoju.test/echo?k=WSX.s1", "a.kaoju.test"))
	r := c.readResp()
	wantEq(t, "/echo 的状态码", r.status, 200)
	wantEq(t, "/echo 的 k", r.echo(t).str("k"), "WSX.s1")
	c.send(wsHandshake("http://a.kaoju.test/ws?k=WSX.s2", "a.kaoju.test"))
	wantEq(t, "/ws 的状态码", c.readResp().status, 101)
	c.finish()
	evs := e.stop()
	or := one(t, evs.of("origin_request"), "origin_request")
	wantEq(t, "origin_request.k", or.str("k"), "WSX.s1")
	for _, h := range or.pairs("headers") {
		if strings.EqualFold(h[0], "Upgrade") || strings.EqualFold(h[0], "Connection") {
			t.Errorf("逐跳头 %s 被转交给了源站", h[0])
		}
	}
}

// 隧道首包的归类要等到够归类为止，但不无限等：只来了两个大写字母就没有下文的，约 500 毫秒后归成 other；
// 一开始就不可能是方法名的（小写字母）不等。
func TestFixTunnelFirstBytesWaitBounds(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:80")
	c.send("GE")
	c2 := e.dialProxy()
	c2.connect("a.kaoju.test:80")
	c2.send("ge")
	time.Sleep(900 * time.Millisecond)
	c.finish()
	c2.finish()
	evs := e.stop()
	tf := one(t, evs.conn(e.connID(c)).of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "只有 GE：kind", tf.str("kind"), "other")
	wantEq(t, "只有 GE：n_buffered", tf.num("n_buffered"), 2)
	open := one(t, evs.conn(e.connID(c)).of("tunnel_open"), "tunnel_open")
	if d := tf["t"].(float64) - open["t"].(float64); d < 400 || d > 850 {
		t.Errorf("只有 GE：tunnel_first_bytes 在 tunnel_open 之后 %.0f 毫秒写出，应在 500 毫秒左右", d)
	}
	tf2 := one(t, evs.conn(e.connID(c2)).of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "小写的 ge：kind", tf2.str("kind"), "other")
	open2 := one(t, evs.conn(e.connID(c2)).of("tunnel_open"), "tunnel_open")
	if d := tf2["t"].(float64) - open2["t"].(float64); d > 200 {
		t.Errorf("小写的 ge：tunnel_first_bytes 等了 %.0f 毫秒，应当不等", d)
	}
}

func TestFirstBytesWait(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
	}{
		{"", 0}, {"G", methodWait}, {"GET", methodWait}, {"GET ", 0}, {"GET /", 0}, {"get", 0}, {"G1", 0},
		{"ABCDEFGHIJKLMNO", methodWait}, {"ABCDEFGHIJKLMNOP", 0},
		{"\x16", helloWait}, {"\x16\x03\x01\x00\x02\x01", helloWait}, {"\x16\x03\x01\x00\x02\x01\x00", 0},
		{"\x05\x01", 0},
	} {
		if got := firstBytesWait([]byte(c.in)); got != c.want {
			t.Errorf("firstBytesWait(%q) = %v，应为 %v", c.in, got, c.want)
		}
	}
}

// 请求行之前的空行超过 8 个：写一个带 error 的 http_request，回 400 后关（以前是不留痕迹地关）。
func TestFixTooManyBlankLines(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send(strings.Repeat("\r\n", 9) + absGet("BL.s1"))
	wantEq(t, "状态码", c.readResp().status, 400)
	c.expectEOF(2 * time.Second)
	c.finish()
	evs := e.stop()
	hr := one(t, evs.of("http_request"), "http_request")
	wantEq(t, "http_request.seq", hr.num("seq"), 1)
	wantEq(t, "http_request.method", hr.str("method"), "")
	if !strings.HasPrefix(hr.str("error"), "bad_head: ") {
		t.Errorf("http_request.error = %q，应以 bad_head: 开头", hr.str("error"))
	}
	wantEq(t, "http_response.cause", one(t, evs.of("http_response"), "http_response").str("cause"), "bad_request")
	wantEq(t, "origin_request 的个数", len(evs.of("origin_request")), 0)
}

// 仪器退出时还在 delay 里的请求（绝对形式、隧道里各一个）不再得到回应：没有迟到的 200。
func TestFixShutdownDoesNotAnswerDelayed(t *testing.T) {
	e := startEnv(t, `{}`)
	fwd := e.dialProxy()
	fwd.send("GET http://a.kaoju.test/echo?k=SDX.fwd&delay=30000 HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n")
	tun := e.dialProxy()
	tun.connect("a.kaoju.test:80")
	tun.send(getReq("/echo?k=SDX.tun&delay=30000", "a.kaoju.test"))
	time.Sleep(300 * time.Millisecond)
	// 不能用 e.stop()：它先让测试这一侧关连接。这里要的是仪器先退出。
	e.stopped = true
	e.srv.Shutdown("test")
	evs := readEvents(t, e.evPath)
	e.evs = evs
	checkInvariants(t, evs)
	for _, c := range []*rawConn{fwd, tun} {
		c.mu.Lock()
		c.done = true
		c.mu.Unlock()
		_ = c.tcp.Close()
		id := e.connID(c)
		one(t, evs.conn(id).of("origin_request"), "origin_request")
		for _, hr := range evs.conn(id).of("http_response") {
			if hr.str("cause") == "forward" {
				t.Errorf("连接 %d：仪器退出时回了延迟中的请求（状态码 %d）", id, hr.num("status"))
			}
		}
		end := one(t, evs.conn(id).of("conn_end"), "conn_end")
		wantEq(t, "conn_end.reason", end.str("reason"), "shutdown")
	}
	// 隧道那条：写给客户端的只有 CONNECT 的 200，没有源站的响应。
	wantEq(t, "隧道里写给客户端的字节数", one(t, evs.conn(e.connID(tun)).of("tunnel_close"), "tunnel_close").num("bytes_s2c"), 0)
}

// Basic 凭据按整串字节比（用例 D11 的依据）。
func TestBasicOK(t *testing.T) {
	p, err := ParseProfile([]byte(`{"auth":{"accept":[["sess:ab12","kaoju-pass-1"],["u2",""]]}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"sess:ab12:kaoju-pass-1", true}, {"u2:", true},
		{"sess:ab12:kaoju-pass-2", false}, {"sess:kaoju-pass-1", false}, {"x:sess:ab12:kaoju-pass-1", false}, {"u2", false},
	} {
		if got := p.basicOK([]byte(c.in)); got != c.want {
			t.Errorf("basicOK(%q) = %v，应为 %v", c.in, got, c.want)
		}
	}
	anyUser, err := ParseProfile([]byte(`{"auth":{"accept":[["sess:ab12","p:a@s"],["x","other"]],"accept_any_user":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"sess:ab12:p:a@s", true}, {"\xff\xfe:p:a@s", true}, {":p:a@s", true},
		{"p:a@s", false}, {"x:other", false}, {"sess:ab12:p:a@", false},
	} {
		if got := anyUser.basicOK([]byte(c.in)); got != c.want {
			t.Errorf("accept_any_user：basicOK(%q) = %v，应为 %v", c.in, got, c.want)
		}
	}
}
