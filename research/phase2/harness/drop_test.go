package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"
)

func absGet(k string) string {
	return "GET http://a.kaoju.test/echo?k=" + k + " HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n"
}

// wantAction 核对一条 action 事件的全部字段。tunnel、oconn 传 0 表示应为 null。
func wantAction(t *testing.T, a event, what, how string, k any, tunnel, oconn int) {
	t.Helper()
	wantEq(t, "action.what", a.str("what"), what)
	wantEq(t, "action.how", a.str("how"), how)
	wantEq(t, "action.k", a["k"], k)
	for name, want := range map[string]int{"tunnel": tunnel, "oconn": oconn} {
		if want == 0 {
			if a[name] != nil {
				t.Errorf("action.%s 应为 null: %v", name, a[name])
			}
			continue
		}
		wantEq(t, "action."+name, a.num(name), want)
	}
}

// connect.drop：读完 CONNECT 请求后什么都不回就关，共生效 times 次；fin 和 rst 在对端看到的现象不同。
func TestConnectDrop(t *testing.T) {
	for _, how := range []string{"fin", "rst"} {
		t.Run(how, func(t *testing.T) {
			e := startEnv(t, fmt.Sprintf(`{"connect":{"drop":{"times":2,"how":%q}}}`, how))
			var dropped []*rawConn
			for i := 0; i < 2; i++ {
				c := e.dialProxy()
				c.send("CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\n\r\n")
				if how == "fin" {
					c.expectEOF(3 * time.Second)
				} else {
					c.expectReset(3 * time.Second)
				}
				wantEq(t, "被丢弃的 CONNECT 收到的字节数", c.received(), int64(0))
				c.finish()
				dropped = append(dropped, c)
			}
			// 第 3 次不再丢弃。
			c3 := e.dialProxy()
			c3.connect("a.kaoju.test:443")
			tc := e.startTLS(c3, "a.kaoju.test", "http/1.1")
			tc.send(getReq("/echo?k=F11.s1", "a.kaoju.test"))
			wantEq(t, "第 3 次 CONNECT 之后隧道里的请求", tc.readResp().echo(t).str("k"), "F11.s1")
			tc.close()

			evs := e.stop()
			acts := evs.of("action")
			wantEq(t, "action 的个数", len(acts), 2)
			for i, c := range dropped {
				ce := evs.conn(e.connID(c))
				wantEq(t, "被丢弃的连接上的事件序列", ce.names(), "accept first_bytes http_request action conn_end")
				wantEq(t, "http_request.form", ce[2].str("form"), "connect")
				wantAction(t, ce[3], "connect_drop", how, nil, 0, 0)
				wantEq(t, "action 所在的连接", acts[i].num("conn"), e.connID(c))
				end := ce[4]
				wantEq(t, "conn_end.by", end.str("by"), "proxy")
				wantEq(t, "conn_end.close", end.str("close"), how)
				wantEq(t, "conn_end.reason", end.str("reason"), "connect_drop")
				wantEq(t, "conn_end.bytes_out", end.num("bytes_out"), 0)
			}
			wantEq(t, "http_response 的个数（只有第 3 次有）", len(evs.of("http_response")), 1)
			wantEq(t, "tunnel_open 的个数", len(evs.of("tunnel_open")), 1)
		})
	}
}

// conn.drop：按 k 匹配；only_if_reused 为真时只有不是连接上第一个请求才生效；整个运行里共生效 times 次。
func TestConnDropOnlyIfReused(t *testing.T) {
	e := startEnv(t, `{"conn":{"drop":{"k":"F03.s2","times":1,"how":"fin","only_if_reused":true}}}`)
	c := e.dialProxy()
	// 连接上的第一个请求带着这个 k：不丢。
	c.send(absGet("F03.s2"))
	wantEq(t, "新连接上第一个请求的状态码", c.readResp().status, 200)
	c.send(absGet("F03.s1"))
	wantEq(t, "别的 k 的状态码", c.readResp().status, 200)
	// 复用的连接上再来：丢。
	c.send(absGet("F03.s2"))
	c.expectEOF(3 * time.Second)
	c.finish()

	// 次数用完了：另一条连接上复用时也不再丢。
	c2 := e.dialProxy()
	c2.send(absGet("F03.s1"))
	wantEq(t, "c2 第 1 个请求", c2.readResp().status, 200)
	c2.send(absGet("F03.s2"))
	wantEq(t, "次数用完以后的 F03.s2", c2.readResp().echo(t).str("k"), "F03.s2")
	c2.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(),
		"accept first_bytes http_request origin_request http_response http_request origin_request http_response http_request action conn_end")
	dropped := ce.of("http_request")[2]
	wantEq(t, "被丢弃的 http_request.k", dropped.str("k"), "F03.s2")
	wantEq(t, "被丢弃的 http_request.seq", dropped.num("seq"), 3)
	act := one(t, evs.of("action"), "action")
	wantAction(t, act, "conn_drop", "fin", "F03.s2", 0, 0)
	wantEq(t, "action.conn", act.num("conn"), e.connID(c))
	end := ce.of("conn_end")[0]
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.close", end.str("close"), "fin")
	wantEq(t, "conn_end.reason", end.str("reason"), "conn_drop")
	// 带 k=F03.s2 的请求一共到达代理 3 次（矩阵 R92 数的就是这个）。
	n := 0
	for _, hr := range evs.of("http_request") {
		if hr.str("k") == "F03.s2" {
			n++
		}
	}
	wantEq(t, "带 k=F03.s2 的 http_request 的个数", n, 3)
	wantEq(t, "到达源站的 F03.s2 的个数", len(evs.of("origin_request"))-2, 2)
}

// conn.drop 丢 POST：必须先把正文读完再关；rst 时对端看到 ECONNRESET。only_if_reused 为假时新连接上也丢。
func TestConnDropPOSTReadsBodyThenRST(t *testing.T) {
	e := startEnv(t, `{"conn":{"drop":{"k":"F04.s2","times":1,"how":"rst"}}}`)
	body := pattern(65536)
	c := e.dialProxy()
	c.send(fmt.Sprintf("POST http://a.kaoju.test/echo?k=F04.s2 HTTP/1.1\r\nHost: a.kaoju.test\r\nContent-Length: %d\r\n\r\n", len(body)))
	// 正文分几次发，中间停一下：仪器不能在正文读完之前就关。
	for off := 0; off < len(body); off += 20000 {
		time.Sleep(30 * time.Millisecond)
		if _, err := c.Write(body[off:min(off+20000, len(body))]); err != nil {
			t.Fatalf("发正文失败（仪器没等正文读完就关了？）: %v", err)
		}
	}
	c.expectReset(3 * time.Second)
	wantEq(t, "收到的字节数", c.received(), int64(0))
	c.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(), "accept first_bytes http_request action conn_end")
	hr := ce[2]
	wantEq(t, "http_request.body_len", hr.num("body_len"), len(body))
	wantEq(t, "http_request.body_sha256", hr.str("body_sha256"), sha256hex(body))
	wantAction(t, ce[3], "conn_drop", "rst", "F04.s2", 0, 0)
	end := ce[4]
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.close", end.str("close"), "rst")
	wantEq(t, "conn_end.reason", end.str("reason"), "conn_drop")
	wantEq(t, "conn_end.bytes_in（请求头加正文，一个字节不少）", int64(end.num("bytes_in")), c.sent())
	wantEq(t, "origin_request 的个数（没有转给源站）", len(evs.of("origin_request")), 0)
}

// conn.drop 的 times 大于 1。
func TestConnDropTimes(t *testing.T) {
	e := startEnv(t, `{"conn":{"drop":{"k":"T.s1","times":2}}}`)
	for i := 0; i < 2; i++ {
		c := e.dialProxy()
		c.send(absGet("T.s1"))
		c.expectEOF(3 * time.Second)
		c.finish()
	}
	c := e.dialProxy()
	c.send(absGet("T.s1"))
	wantEq(t, "第 3 次", c.readResp().status, 200)
	c.finish()
	evs := e.stop()
	wantEq(t, "action 的个数", len(evs.of("action")), 2)
	wantEq(t, "默认的 how", evs.of("action")[0].str("how"), "fin")
}

// tlsReadErr 在隧道里的 TLS 连接上读，直到出错，返回错误。
func tlsReadErr(tc *tlsConn) error {
	_ = tc.tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := tc.br.Read(buf); err != nil {
			return err
		}
	}
}

// origin.drop（HTTP/1.1 的隧道）：请求到达源站、读完以后不回应就切断隧道，关的是最外层的 TCP 连接。
func TestOriginDropH1(t *testing.T) {
	for _, how := range []string{"fin", "rst"} {
		t.Run(how, func(t *testing.T) {
			e := startEnv(t, fmt.Sprintf(`{"origin":{"h2":false,"drop":{"k":"F05.s2","times":1,"how":%q,"only_if_reused":true}}}`, how))
			c := e.dialProxy()
			c.connect("a.kaoju.test:443")
			tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
			// 这条源站连接上的第一个请求：不丢。
			tc.send(getReq("/echo?k=F05.s2", "a.kaoju.test"))
			wantEq(t, "第一个请求", tc.readResp().echo(t).str("k"), "F05.s2")
			// 复用：丢。带正文，正文必须读完。
			body := pattern(70000)
			tc.send(fmt.Sprintf("POST /echo?k=F05.s2 HTTP/1.1\r\nHost: a.kaoju.test\r\nContent-Length: %d\r\n\r\n", len(body)))
			tc.send(string(body))
			err := tlsReadErr(tc)
			if how == "fin" {
				// 仪器没有发 close_notify，直接发的 FIN：crypto/tls 报 unexpected EOF。
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("fin：应当读到 EOF，实际 %v", err)
				}
			} else {
				c.mu.Lock()
				c.lossy = true
				c.mu.Unlock()
				if !errors.Is(err, syscall.ECONNRESET) {
					t.Errorf("rst：应当读到 ECONNRESET，实际 %v", err)
				}
			}
			c.finish()

			evs := e.stop()
			ce := evs.conn(e.connID(c))
			wantEq(t, "事件序列", ce.names(),
				"accept first_bytes http_request http_response tunnel_open tunnel_first_bytes origin_conn origin_request origin_request action tunnel_close conn_end")
			ors := ce.of("origin_request")
			wantEq(t, "第 1 个 origin_request.action", ors[0].str("action"), "respond")
			wantEq(t, "第 1 个 origin_request.status", ors[0].num("status"), 200)
			wantEq(t, "第 2 个 origin_request.action", ors[1].str("action"), "drop")
			if ors[1]["status"] != nil {
				t.Errorf("被丢弃的 origin_request.status 应为 null: %v", ors[1]["status"])
			}
			wantEq(t, "被丢弃的 origin_request.k", ors[1].str("k"), "F05.s2")
			wantEq(t, "被丢弃的 origin_request.seq", ors[1].num("seq"), 2)
			wantEq(t, "被丢弃的 origin_request.body_len", ors[1].num("body_len"), len(body))
			wantEq(t, "被丢弃的 origin_request.body_sha256", ors[1].str("body_sha256"), sha256hex(body))
			wantAction(t, one(t, ce.of("action"), "action"), "origin_drop", how, "F05.s2", 1, 1)
			tcl := ce.of("tunnel_close")[0]
			wantEq(t, "tunnel_close.by", tcl.str("by"), "proxy")
			wantEq(t, "tunnel_close.reason", tcl.str("reason"), "origin_drop")
			end := ce.of("conn_end")[0]
			wantEq(t, "conn_end.by", end.str("by"), "proxy")
			wantEq(t, "conn_end.close", end.str("close"), how)
			wantEq(t, "conn_end.reason", end.str("reason"), "origin_drop")
		})
	}
}

// origin.drop 在新隧道的第一个请求上（only_if_reused 为假）。
func TestOriginDropFirstRequest(t *testing.T) {
	e := startEnv(t, `{"origin":{"drop":{"k":"F08.s1","times":1,"how":"fin"}}}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:443")
	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	tc.send(getReq("/echo?k=F08.s1", "a.kaoju.test"))
	if err := tlsReadErr(tc); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("应当读到 EOF，实际 %v", err)
	}
	c.finish()
	// 次数用完：新隧道里同样的请求得到回应。
	c2 := e.dialProxy()
	c2.connect("a.kaoju.test:443")
	tc2 := e.startTLS(c2, "a.kaoju.test", "http/1.1")
	tc2.send(getReq("/echo?k=F08.s1", "a.kaoju.test"))
	wantEq(t, "重发的请求", tc2.readResp().echo(t).str("k"), "F08.s1")
	tc2.close()
	evs := e.stop()
	ors := evs.of("origin_request")
	wantEq(t, "origin_request 的个数", len(ors), 2)
	wantEq(t, "第 1 个的 action", ors[0].str("action"), "drop")
	wantEq(t, "第 2 个的 action", ors[1].str("action"), "respond")
	wantAction(t, one(t, evs.of("action"), "action"), "origin_drop", "fin", "F08.s1", 1, 1)
}

// origin.drop 在 h2 的隧道里：only_if_reused 按流计数。
func TestOriginDropH2(t *testing.T) {
	e := startEnv(t, `{"origin":{"h2":true,"drop":{"k":"F12.s2","times":1,"how":"fin","only_if_reused":true}}}`)
	client, conns := e.h2Client()
	res, err := client.Get("https://a.kaoju.test/echo?k=F12.s1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	wantEq(t, "s1 的协议", res.Proto, "HTTP/2.0")
	res2, err2 := client.Get("https://a.kaoju.test/echo?k=F12.s2")
	if err2 == nil {
		// 标准库的 h2 客户端如果自己在新连接上重发了，这里会成功；事件里照样看得出来。
		_, _ = io.Copy(io.Discard, res2.Body)
		res2.Body.Close()
	}
	t.Logf("被丢弃的 h2 请求在客户端看到的结果: err=%v", err2)
	client.CloseIdleConnections()
	first := conns()[0]

	evs := e.stop()
	ce := evs.conn(e.connID(first))
	ors := ce.of("origin_request")
	wantEq(t, "第一条隧道里 origin_request 的个数", len(ors), 2)
	wantEq(t, "s1 的 action", ors[0].str("action"), "respond")
	wantEq(t, "s2 的 action", ors[1].str("action"), "drop")
	wantEq(t, "s2 的 seq（h2 按流计数）", ors[1].num("seq"), 2)
	wantEq(t, "s2 的 proto", ors[1].str("proto"), "HTTP/2.0")
	wantAction(t, one(t, evs.of("action"), "action"), "origin_drop", "fin", "F12.s2", 1, 1)
	wantEq(t, "tunnel_close.by", ce.of("tunnel_close")[0].str("by"), "proxy")
	wantEq(t, "conn_end.reason", ce.of("conn_end")[0].str("reason"), "origin_drop")
}

// conn.idle_close_ms：没有隧道的代理连接在两个请求之间空闲这么久就按 fin 关。
func TestConnIdleClose(t *testing.T) {
	e := startEnv(t, `{"conn":{"idle_close_ms":300}}`)
	c := e.dialProxy()
	c.send(absGet("F01.s1"))
	wantEq(t, "第 1 个请求", c.readResp().status, 200)
	// 空闲不到 300 毫秒再发一个：计时重新开始。
	time.Sleep(150 * time.Millisecond)
	c.send(absGet("F01.s1b"))
	wantEq(t, "第 2 个请求", c.readResp().status, 200)
	d := c.expectEOF(3 * time.Second)
	if d < 250*time.Millisecond || d > 1500*time.Millisecond {
		t.Errorf("空闲 300 毫秒后关闭，实际等了 %v", d)
	}
	c.finish()

	// 还没发过请求的连接不算“两个请求之间”：不关。
	c2 := e.dialProxy()
	c2.expectSilence(600 * time.Millisecond)
	c2.send(absGet("F01.s2"))
	wantEq(t, "c2 的请求", c2.readResp().status, 200)
	c2.finish()

	// 已经变成隧道的连接不受这个字段管。
	c3 := e.dialProxy()
	c3.connect("a.kaoju.test:80")
	c3.send(getReq("/echo?k=F01.t", "a.kaoju.test"))
	wantEq(t, "隧道里的请求", c3.readResp().status, 200)
	c3.expectSilence(600 * time.Millisecond)
	c3.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(),
		"accept first_bytes http_request origin_request http_response http_request origin_request http_response action conn_end")
	act := one(t, evs.of("action"), "action")
	wantAction(t, act, "conn_idle_close", "fin", nil, 0, 0)
	wantEq(t, "action.conn", act.num("conn"), e.connID(c))
	end := ce.of("conn_end")[0]
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.close", end.str("close"), "fin")
	wantEq(t, "conn_end.reason", end.str("reason"), "conn_idle")
	gap := act["t"].(float64) - ce.of("http_response")[1]["t"].(float64)
	if gap < 290 || gap > 1500 {
		t.Errorf("最后一个响应到空闲关闭隔了 %.1f 毫秒，应在 300 毫秒左右", gap)
	}
}

// tunnel.idle_close_ms：隧道两个方向都静默这么久就按 fin 关。
func TestTunnelIdleClose(t *testing.T) {
	e := startEnv(t, `{"tunnel":{"idle_close_ms":300}}`)
	c := e.dialProxy()
	c.connect("a.kaoju.test:443")
	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	tc.send(getReq("/echo?k=F02.s1", "a.kaoju.test"))
	wantEq(t, "隧道里的请求", tc.readResp().echo(t).str("k"), "F02.s1")
	// 有流量就不算空闲。
	time.Sleep(200 * time.Millisecond)
	tc.send(getReq("/echo?k=F02.s1b", "a.kaoju.test"))
	wantEq(t, "隧道里的第 2 个请求", tc.readResp().echo(t).str("k"), "F02.s1b")
	start := time.Now()
	err := tlsReadErr(tc)
	d := time.Since(start)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("应当读到 EOF，实际 %v", err)
	}
	if d < 250*time.Millisecond || d > 1500*time.Millisecond {
		t.Errorf("空闲 300 毫秒后关闭，实际等了 %v", d)
	}
	c.finish()

	// 建了隧道以后一个字节都没发：两个方向都静默，同样关。
	c2 := e.dialProxy()
	c2.connect("a.kaoju.test:443")
	c2.expectEOF(3 * time.Second)
	c2.finish()

	// 没有隧道的代理连接不受这个字段管。
	c3 := e.dialProxy()
	c3.send(absGet("F02.plain"))
	wantEq(t, "明文请求", c3.readResp().status, 200)
	c3.expectSilence(600 * time.Millisecond)
	c3.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	if !strings.HasSuffix(ce.names(), "origin_request origin_request action tunnel_close conn_end") {
		t.Errorf("事件序列不对: %s", ce.names())
	}
	acts := evs.of("action")
	wantEq(t, "action 的个数", len(acts), 2)
	wantAction(t, ce.of("action")[0], "tunnel_idle_close", "fin", nil, 1, 0)
	tcl := ce.of("tunnel_close")[0]
	wantEq(t, "tunnel_close.by", tcl.str("by"), "proxy")
	wantEq(t, "tunnel_close.reason", tcl.str("reason"), "tunnel_idle")
	end := ce.of("conn_end")[0]
	wantEq(t, "conn_end.by", end.str("by"), "proxy")
	wantEq(t, "conn_end.close", end.str("close"), "fin")
	wantEq(t, "conn_end.reason", end.str("reason"), "tunnel_idle")

	ce2 := evs.conn(e.connID(c2))
	wantEq(t, "空隧道的事件序列", ce2.names(), "accept first_bytes http_request http_response tunnel_open action tunnel_close conn_end")
	wantEq(t, "空隧道 tunnel_close.bytes_c2s", ce2.of("tunnel_close")[0].num("bytes_c2s"), 0)
	wantEq(t, "空隧道 tunnel_close.bytes_s2c", ce2.of("tunnel_close")[0].num("bytes_s2c"), 0)
}

// fin 与 rst 在对端看到的现象不同：fin 是读到 EOF，而且之后对端还能把话说完（仪器照样读、照样记账）；
// rst 是 ECONNRESET。
func TestFinVersusRst(t *testing.T) {
	t.Run("fin", func(t *testing.T) {
		e := startEnv(t, `{"conn":{"drop":{"k":"X.s1","how":"fin"}}}`)
		c := e.dialProxy()
		c.send(absGet("X.s1"))
		c.expectEOF(3 * time.Second)
		// 仪器已经发了 FIN，但还在读：对端这时再发的字节不会招来 RST，并且算进 bytes_in。
		late := absGet("X.s2")
		c.send(late)
		time.Sleep(100 * time.Millisecond)
		c.send("tail")
		c.finish()
		evs := e.stop()
		end := one(t, evs.of("conn_end"), "conn_end")
		wantEq(t, "conn_end.by", end.str("by"), "proxy")
		wantEq(t, "conn_end.close", end.str("close"), "fin")
		wantEq(t, "conn_end.bytes_drained", end.num("bytes_drained"), len(late)+4)
		wantEq(t, "conn_end.bytes_in", int64(end.num("bytes_in")), c.sent())
		wantEq(t, "http_request 的个数（关闭以后读到的字节不再解析）", len(evs.of("http_request")), 1)
	})
	t.Run("rst", func(t *testing.T) {
		e := startEnv(t, `{"conn":{"drop":{"k":"X.s1","how":"rst"}}}`)
		c := e.dialProxy()
		c.send(absGet("X.s1"))
		c.expectReset(3 * time.Second)
		c.finish()
		evs := e.stop()
		end := one(t, evs.of("conn_end"), "conn_end")
		wantEq(t, "conn_end.by", end.str("by"), "proxy")
		wantEq(t, "conn_end.close", end.str("close"), "rst")
		wantEq(t, "conn_end.bytes_drained", end.num("bytes_drained"), 0)
	})
}

// 对端先关（FIN 或 RST）时，conn_end 记的是 client 和对端的关法。
func TestClientClosesFirst(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.send(absGet("CC.s1"))
	wantEq(t, "状态码", c.readResp().status, 200)
	c.finish()

	c2 := e.dialProxy()
	c2.send(absGet("CC.s2"))
	wantEq(t, "状态码", c2.readResp().status, 200)
	// 对端复位：SO_LINGER 设 0 再关。
	c2.mu.Lock()
	c2.done = true
	c2.mu.Unlock()
	_ = c2.tcp.SetLinger(0)
	_ = c2.tcp.Close()
	time.Sleep(200 * time.Millisecond)

	evs := e.stop()
	end := evs.conn(e.connID(c)).of("conn_end")[0]
	wantEq(t, "FIN：conn_end.by", end.str("by"), "client")
	wantEq(t, "FIN：conn_end.close", end.str("close"), "fin")
	wantEq(t, "FIN：conn_end.reason", end.str("reason"), "client_eof")
	end2 := evs.conn(e.connID(c2)).of("conn_end")[0]
	wantEq(t, "RST：conn_end.by", end2.str("by"), "client")
	wantEq(t, "RST：conn_end.close", end2.str("close"), "rst")
	wantEq(t, "RST：conn_end.reason", end2.str("reason"), "client_reset")
}
