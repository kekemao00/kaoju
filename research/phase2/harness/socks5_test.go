package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// readN 从连接上恰好读 n 个字节。
func (c *rawConn) readN(n int) []byte {
	c.t.Helper()
	_ = c.tcp.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.tcp.SetReadDeadline(time.Time{})
	b := make([]byte, n)
	if _, err := io.ReadFull(c.br, b); err != nil {
		c.t.Fatalf("想读 %d 个字节，失败: %v", n, err)
	}
	return b
}

func (c *rawConn) sendBytes(b []byte) {
	c.t.Helper()
	if _, err := c.Write(b); err != nil {
		c.t.Fatalf("发送失败: %v", err)
	}
}

// socksRequest 按 RFC 1928 第 4 节拼一个请求。
func socksRequest(cmd, atyp byte, addr []byte, port int) []byte {
	b := []byte{0x05, cmd, 0x00, atyp}
	if atyp == 0x03 {
		b = append(b, byte(len(addr)))
	}
	b = append(b, addr...)
	return append(b, byte(port>>8), byte(port))
}

// socksUserPass 按 RFC 1929 第 2 节拼用户名密码子协商。
func socksUserPass(user, pass []byte) []byte {
	b := []byte{0x01, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

var socksOKReply = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

func wantBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s = %x，应为 %x", what, got, want)
	}
}

// S01：无认证，域名交给代理，隧道里走 TLS。逐项核对 SOCKS5 的事件。
func TestSocks5NoAuthDomainTLS(t *testing.T) {
	e := startEnv(t, `{"socks":{"auth":"none"}}`)
	c := e.dialProxy()
	greeting := []byte{0x05, 0x02, 0x00, 0x02}
	c.sendBytes(greeting)
	wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x00})
	req := socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 443)
	c.sendBytes(req)
	wantBytes(t, "应答（绑定地址 0.0.0.0:0，ATYP=1）", c.readN(10), socksOKReply)
	afterReply := c.received()
	tc := e.startTLS(c, "a.kaoju.test", "http/1.1")
	tc.send(getReq("/echo?k=S01.s1", "a.kaoju.test"))
	echo := tc.readResp().echo(t)
	wantEq(t, "echo.k", echo.str("k"), "S01.s1")
	wantEq(t, "echo.via", echo.str("via"), "tunnel")
	tc.close()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(),
		"accept first_bytes socks5_greeting socks5_method socks5_request socks5_reply tunnel_open tunnel_first_bytes origin_conn origin_request tunnel_close conn_end")
	fb := ce[1]
	wantEq(t, "first_bytes.kind", fb.str("kind"), "socks5")
	wantEq(t, "first_bytes.n_first_read", fb.num("n_first_read"), len(greeting))
	wantEq(t, "first_bytes.hex", fb.str("hex"), "05020002")
	g := ce[2]
	wantEq(t, "socks5_greeting.version", g.num("version"), 5)
	wantEq(t, "socks5_greeting.methods", fmt.Sprint(g.ints("methods")), "[0 2]")
	wantEq(t, "socks5_greeting.raw_hex", g.str("raw_hex"), "05020002")
	wantEq(t, "socks5_method.selected", ce[3].num("selected"), 0)
	rq := ce[4]
	wantEq(t, "socks5_request.version", rq.num("version"), 5)
	wantEq(t, "socks5_request.cmd", rq.num("cmd"), 1)
	wantEq(t, "socks5_request.rsv", rq.num("rsv"), 0)
	wantEq(t, "socks5_request.atyp", rq.num("atyp"), 3)
	wantEq(t, "socks5_request.host", rq.str("host"), "a.kaoju.test")
	wantEq(t, "socks5_request.port", rq.num("port"), 443)
	wantEq(t, "socks5_request.raw_hex", rq.str("raw_hex"), hex.EncodeToString(req))
	rp := ce[5]
	wantEq(t, "socks5_reply.rep", rp.num("rep"), 0)
	wantEq(t, "socks5_reply.cause", rp.str("cause"), "ok")
	wantEq(t, "socks5_reply.raw_hex", rp.str("raw_hex"), "05000001000000000000")
	to := ce[6]
	wantEq(t, "tunnel_open.via", to.str("via"), "socks5")
	wantEq(t, "tunnel_open.target_host", to.str("target_host"), "a.kaoju.test")
	wantEq(t, "tunnel_open.target_port", to.num("target_port"), 443)
	wantEq(t, "tunnel_open.mapped", to.str("mapped"), "origin_https")
	if to["req_seq"] != nil {
		t.Errorf("SOCKS5 的 tunnel_open.req_seq 应为 null: %v", to["req_seq"])
	}
	tf := ce[7]
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "tls_client_hello")
	wantEq(t, "tunnel_first_bytes.tls.sni", tf.obj("tls").str("sni"), "a.kaoju.test")
	tcl := ce.of("tunnel_close")[0]
	wantEq(t, "tunnel_close.bytes_c2s", int64(tcl.num("bytes_c2s")), c.sent()-int64(len(greeting)+len(req)))
	wantEq(t, "tunnel_close.bytes_s2c", int64(tcl.num("bytes_s2c")), c.received()-afterReply)
	wantEq(t, "http_request 的个数", len(evs.of("http_request")), 0)
}

// S02：隧道里是明文 HTTP；地址类型是 IPv4、IPv6；目标端口等于源站的实际端口。握手一个字节一个字节地发也行。
func TestSocks5AddressTypesAndPlain(t *testing.T) {
	e := startEnv(t, `{}`)
	cases := []struct {
		name   string
		atyp   byte
		addr   []byte
		port   int
		host   string
		mapped string
	}{
		{"ipv4", 0x01, []byte{127, 0, 0, 1}, 80, "127.0.0.1", "origin_http"},
		{"ipv6", 0x04, append(make([]byte, 15), 1), e.hp, "::1", "origin_http"},
		{"domain", 0x03, []byte("b.kaoju.test"), 80, "b.kaoju.test", "origin_http"},
	}
	var conns []*rawConn
	for _, tcase := range cases {
		c := e.dialProxy()
		conns = append(conns, c)
		all := append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, tcase.atyp, tcase.addr, tcase.port)...)
		if tcase.name == "ipv4" {
			// 一个字节一个字节地发。第一个字节之后多等一会儿，保证仪器的第一次读只读到它。
			for i, b := range all {
				c.sendBytes([]byte{b})
				if i == 0 {
					time.Sleep(150 * time.Millisecond)
				}
				time.Sleep(2 * time.Millisecond)
			}
		} else {
			c.sendBytes(all[:3])
			wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x00})
			c.sendBytes(all[3:])
		}
		if tcase.name == "ipv4" {
			wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x00})
		}
		wantBytes(t, tcase.name+" 的应答", c.readN(10), socksOKReply)
		c.send(getReq("/echo?k=S02."+tcase.name, "a.kaoju.test"))
		echo := c.readResp().echo(t)
		wantEq(t, "echo.k", echo.str("k"), "S02."+tcase.name)
		wantEq(t, "echo.tls", echo["tls"], any(false))
		c.finish()
	}
	evs := e.stop()
	for i, tcase := range cases {
		ce := evs.conn(e.connID(conns[i]))
		rq := one(t, ce.of("socks5_request"), "socks5_request")
		wantEq(t, tcase.name+" socks5_request.atyp", rq.num("atyp"), int(tcase.atyp))
		wantEq(t, tcase.name+" socks5_request.host", rq.str("host"), tcase.host)
		wantEq(t, tcase.name+" socks5_request.port", rq.num("port"), tcase.port)
		wantEq(t, tcase.name+" socks5_request.raw_hex", rq.str("raw_hex"),
			hex.EncodeToString(socksRequest(0x01, tcase.atyp, tcase.addr, tcase.port)))
		to := one(t, ce.of("tunnel_open"), "tunnel_open")
		wantEq(t, tcase.name+" tunnel_open.mapped", to.str("mapped"), tcase.mapped)
		wantEq(t, tcase.name+" tunnel_open.target_host", to.str("target_host"), tcase.host)
		tf := one(t, ce.of("tunnel_first_bytes"), "tunnel_first_bytes")
		wantEq(t, tcase.name+" tunnel_first_bytes.kind", tf.str("kind"), "http")
		if tf["tls"] != nil {
			t.Errorf("明文隧道的 tunnel_first_bytes.tls 应为 null: %v", tf["tls"])
		}
		oc := one(t, ce.of("origin_conn"), "origin_conn")
		wantEq(t, tcase.name+" origin_conn.tls", oc["tls"], any(false))
	}
	wantEq(t, "ipv4 那条连接的 first_bytes.n_first_read（逐字节发）", evs.conn(e.connID(conns[0])).of("first_bytes")[0].num("n_first_read"), 1)
}

// S05、S08：用户名密码认证。凭据对、凭据错（回配置的状态字节后关）、子协商版本不对、accept_any_user、非 UTF-8 的字节。
func TestSocks5UserPass(t *testing.T) {
	e := startEnv(t, `{"socks":{"auth":"userpass","auth_fail_status":85},"auth":{"accept":[["kaoju-user","kaoju-pass-1"],["u2","p2"]]}}`)

	// 凭据正确。
	c := e.dialProxy()
	c.sendBytes([]byte{0x05, 0x02, 0x00, 0x02})
	wantBytes(t, "方法应答（选用户名密码）", c.readN(2), []byte{0x05, 0x02})
	c.sendBytes(socksUserPass([]byte("kaoju-user"), []byte("kaoju-pass-1")))
	wantBytes(t, "认证应答", c.readN(2), []byte{0x01, 0x00})
	c.sendBytes(socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 80))
	wantBytes(t, "应答", c.readN(10), socksOKReply)
	c.send(getReq("/echo?k=S05.s1", "a.kaoju.test"))
	wantEq(t, "隧道里的请求", c.readResp().echo(t).str("k"), "S05.s1")
	c.finish()

	// 第二组凭据也接受。
	cb := e.dialProxy()
	cb.sendBytes(append([]byte{0x05, 0x01, 0x02}, socksUserPass([]byte("u2"), []byte("p2"))...))
	wantBytes(t, "方法应答", cb.readN(2), []byte{0x05, 0x02})
	wantBytes(t, "认证应答", cb.readN(2), []byte{0x01, 0x00})
	cb.finish()

	// 密码错：回 auth_fail_status，然后关。
	c2 := e.dialProxy()
	c2.sendBytes([]byte{0x05, 0x01, 0x02})
	wantBytes(t, "方法应答", c2.readN(2), []byte{0x05, 0x02})
	c2.sendBytes(socksUserPass([]byte("kaoju-user"), []byte("wrong")))
	wantBytes(t, "认证应答（状态是配置的 85）", c2.readN(2), []byte{0x01, 85})
	c2.expectEOF(3 * time.Second)
	c2.finish()

	// 子协商的版本字节不是 1：按 malformed 拒绝，即使凭据本身是对的。
	c3 := e.dialProxy()
	c3.sendBytes([]byte{0x05, 0x01, 0x02})
	c3.readN(2)
	bad := socksUserPass([]byte("kaoju-user"), []byte("kaoju-pass-1"))
	bad[0] = 0x05
	c3.sendBytes(bad)
	wantBytes(t, "认证应答", c3.readN(2), []byte{0x01, 85})
	c3.expectEOF(3 * time.Second)
	c3.finish()

	// 用户名不是合法的 UTF-8，密码为空。
	c4 := e.dialProxy()
	c4.sendBytes([]byte{0x05, 0x01, 0x02})
	c4.readN(2)
	c4.sendBytes(socksUserPass([]byte{0xff, 0xfe, 'x'}, nil))
	wantBytes(t, "认证应答", c4.readN(2), []byte{0x01, 85})
	c4.expectEOF(3 * time.Second)
	c4.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(),
		"accept first_bytes socks5_greeting socks5_method socks5_auth socks5_request socks5_reply tunnel_open tunnel_first_bytes origin_conn origin_request tunnel_close conn_end")
	wantEq(t, "socks5_method.selected", ce.of("socks5_method")[0].num("selected"), 2)
	a := ce.of("socks5_auth")[0]
	wantEq(t, "socks5_auth.version", a.num("version"), 1)
	wantEq(t, "socks5_auth.ulen", a.num("ulen"), 10)
	wantEq(t, "socks5_auth.plen", a.num("plen"), 12)
	wantEq(t, "socks5_auth.user", a.str("user"), "kaoju-user")
	wantEq(t, "socks5_auth.user_hex", a.str("user_hex"), hex.EncodeToString([]byte("kaoju-user")))
	wantEq(t, "socks5_auth.pass", a.str("pass"), "kaoju-pass-1")
	wantEq(t, "socks5_auth.pass_hex", a.str("pass_hex"), hex.EncodeToString([]byte("kaoju-pass-1")))
	wantEq(t, "socks5_auth.status", a.num("status"), 0)
	wantEq(t, "socks5_auth.result", a.str("result"), "ok")

	wantEq(t, "第二组凭据 socks5_auth.result", evs.conn(e.connID(cb)).of("socks5_auth")[0].str("result"), "ok")

	ce2 := evs.conn(e.connID(c2))
	wantEq(t, "密码错的事件序列", ce2.names(), "accept first_bytes socks5_greeting socks5_method socks5_auth conn_end")
	a2 := ce2.of("socks5_auth")[0]
	wantEq(t, "密码错 socks5_auth.status", a2.num("status"), 85)
	wantEq(t, "密码错 socks5_auth.result", a2.str("result"), "bad")
	wantEq(t, "密码错 socks5_auth.pass", a2.str("pass"), "wrong")
	end2 := ce2.of("conn_end")[0]
	wantEq(t, "密码错 conn_end.by", end2.str("by"), "proxy")
	wantEq(t, "密码错 conn_end.close", end2.str("close"), "fin")
	wantEq(t, "密码错 conn_end.reason", end2.str("reason"), "socks_auth_failed")

	a3 := evs.conn(e.connID(c3)).of("socks5_auth")[0]
	wantEq(t, "版本不对 socks5_auth.version", a3.num("version"), 5)
	wantEq(t, "版本不对 socks5_auth.result", a3.str("result"), "malformed")
	wantEq(t, "版本不对 socks5_auth.status", a3.num("status"), 85)

	a4 := evs.conn(e.connID(c4)).of("socks5_auth")[0]
	if a4["user"] != nil {
		t.Errorf("不是合法 UTF-8 的用户名，user 应为 null: %v", a4["user"])
	}
	wantEq(t, "非 UTF-8 socks5_auth.user_hex", a4.str("user_hex"), "fffe78")
	wantEq(t, "非 UTF-8 socks5_auth.ulen", a4.num("ulen"), 3)
	wantEq(t, "空密码 socks5_auth.plen", a4.num("plen"), 0)
	wantEq(t, "空密码 socks5_auth.pass", a4["pass"], any(""))
	wantEq(t, "空密码 socks5_auth.pass_hex", a4["pass_hex"], any(""))
}

// accept_any_user：任何用户名都接受，只比密码；收到的用户名字节照样记录。用户名 255 字节（RFC 1929 的上限）。
func TestSocks5AcceptAnyUser(t *testing.T) {
	e := startEnv(t, `{"socks":{"auth":"userpass"},"auth":{"accept":[["kaoju-user","p:a@s s%2Fw+d"]],"accept_any_user":true}}`)
	user := []byte(strings.Repeat("u", 255))
	c := e.dialProxy()
	c.sendBytes([]byte{0x05, 0x01, 0x02})
	c.readN(2)
	c.sendBytes(socksUserPass(user, []byte("p:a@s s%2Fw+d")))
	wantBytes(t, "认证应答", c.readN(2), []byte{0x01, 0x00})
	c.finish()

	c2 := e.dialProxy()
	c2.sendBytes([]byte{0x05, 0x01, 0x02})
	c2.readN(2)
	c2.sendBytes(socksUserPass([]byte("kaoju-user"), []byte("p:a@s s/w+d")))
	wantBytes(t, "密码不同的认证应答（默认的失败状态是 1）", c2.readN(2), []byte{0x01, 0x01})
	c2.expectEOF(3 * time.Second)
	c2.finish()

	evs := e.stop()
	a := evs.conn(e.connID(c)).of("socks5_auth")[0]
	wantEq(t, "socks5_auth.ulen", a.num("ulen"), 255)
	wantEq(t, "socks5_auth.user", a.str("user"), string(user))
	wantEq(t, "socks5_auth.pass", a.str("pass"), "p:a@s s%2Fw+d")
	wantEq(t, "socks5_auth.result", a.str("result"), "ok")
	wantEq(t, "密码不同 socks5_auth.result", evs.conn(e.connID(c2)).of("socks5_auth")[0].str("result"), "bad")
}

// S07：socks.auth=userpass 而客户端没提供方法 2，回 0xFF 然后关；socks.auth=reject 一律回 0xFF；
// socks.auth=none 而客户端只提供方法 2，同样没有可接受的方法。
func TestSocks5NoAcceptableMethod(t *testing.T) {
	for _, tcase := range []struct {
		name, profile string
		methods       []byte
	}{
		{"userpass 而客户端只有无认证", `{"socks":{"auth":"userpass"},"auth":{"accept":[["u","p"]]}}`, []byte{0x00}},
		{"reject", `{"socks":{"auth":"reject"}}`, []byte{0x00, 0x02}},
		{"none 而客户端只有用户名密码", `{}`, []byte{0x02}},
		{"客户端一个方法都没给", `{}`, nil},
	} {
		t.Run(tcase.name, func(t *testing.T) {
			e := startEnv(t, tcase.profile)
			c := e.dialProxy()
			c.sendBytes(append([]byte{0x05, byte(len(tcase.methods))}, tcase.methods...))
			wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0xff})
			c.expectEOF(3 * time.Second)
			c.finish()
			evs := e.stop()
			ce := evs.conn(e.connID(c))
			wantEq(t, "事件序列", ce.names(), "accept first_bytes socks5_greeting socks5_method conn_end")
			wantEq(t, "socks5_greeting.methods 的个数", len(ce[2].ints("methods")), len(tcase.methods))
			wantEq(t, "socks5_method.selected", ce[3].num("selected"), 255)
			end := ce[4]
			wantEq(t, "conn_end.by", end.str("by"), "proxy")
			wantEq(t, "conn_end.close", end.str("close"), "fin")
			wantEq(t, "conn_end.reason", end.str("reason"), "socks_no_method")
		})
	}
}

// 应答码：不支持的命令回 7、对不上的端口回 5、不认识的地址类型回 8；socks.rep 非 0 时对每个请求都回它。
// 回了非 0 的应答码以后按 fin 关。
func TestSocks5ReplyCodes(t *testing.T) {
	for _, tcase := range []struct {
		name, profile string
		req           []byte
		rep           byte
		cause         string
		host          any
		port          any
	}{
		{"BIND", `{}`, socksRequest(0x02, 0x03, []byte("a.kaoju.test"), 443), 0x07, "unsupported_cmd", "a.kaoju.test", 443.0},
		{"UDP ASSOCIATE", `{}`, socksRequest(0x03, 0x01, []byte{0, 0, 0, 0}, 0), 0x07, "unsupported_cmd", "0.0.0.0", 0.0},
		{"端口对不上", `{}`, socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 8443), 0x05, "unmapped_port", "a.kaoju.test", 8443.0},
		{"不认识的地址类型", `{}`, []byte{0x05, 0x01, 0x00, 0x09}, 0x08, "unsupported_atyp", nil, nil},
		{"socks.rep=2", `{"socks":{"rep":2}}`, socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 443), 0x02, "profile_rep", "a.kaoju.test", 443.0},
		{"socks.rep=4", `{"socks":{"rep":4}}`, socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 443), 0x04, "profile_rep", "a.kaoju.test", 443.0},
		{"socks.rep=5 压过不支持的命令", `{"socks":{"rep":5}}`, socksRequest(0x02, 0x03, []byte("a.kaoju.test"), 443), 0x05, "profile_rep", "a.kaoju.test", 443.0},
	} {
		t.Run(tcase.name, func(t *testing.T) {
			e := startEnv(t, tcase.profile)
			c := e.dialProxy()
			c.sendBytes([]byte{0x05, 0x01, 0x00})
			wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x00})
			c.sendBytes(tcase.req)
			wantBytes(t, "应答", c.readN(10), []byte{0x05, tcase.rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			c.expectEOF(3 * time.Second)
			c.finish()
			evs := e.stop()
			ce := evs.conn(e.connID(c))
			wantEq(t, "事件序列", ce.names(), "accept first_bytes socks5_greeting socks5_method socks5_request socks5_reply conn_end")
			rq := ce[4]
			wantEq(t, "socks5_request.cmd", rq.num("cmd"), int(tcase.req[1]))
			wantEq(t, "socks5_request.atyp", rq.num("atyp"), int(tcase.req[3]))
			wantEq(t, "socks5_request.host", rq["host"], tcase.host)
			wantEq(t, "socks5_request.port", rq["port"], tcase.port)
			wantEq(t, "socks5_request.raw_hex", rq.str("raw_hex"), hex.EncodeToString(tcase.req))
			rp := ce[5]
			wantEq(t, "socks5_reply.rep", rp.num("rep"), int(tcase.rep))
			wantEq(t, "socks5_reply.cause", rp.str("cause"), tcase.cause)
			end := ce[6]
			wantEq(t, "conn_end.by", end.str("by"), "proxy")
			wantEq(t, "conn_end.close", end.str("close"), "fin")
			wantEq(t, "conn_end.reason", end.str("reason"), "socks_reply_failure")
			wantEq(t, "tunnel_open 的个数", len(evs.of("tunnel_open")), 0)
		})
	}
}

// 保留字节不是 0：照实记录，不因此拒绝。握手和隧道的首批字节在同一次写里到达：记在 early_bytes 里。
func TestSocks5ReservedByteAndEarlyData(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	req := socksRequest(0x01, 0x03, []byte("a.kaoju.test"), 80)
	req[2] = 0x7f
	get := getReq("/echo?k=S.early", "a.kaoju.test")
	all := append([]byte{0x05, 0x01, 0x00}, req...)
	all = append(all, get...)
	c.sendBytes(all)
	wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x00})
	wantBytes(t, "应答", c.readN(10), socksOKReply)
	wantEq(t, "隧道里的请求", c.readResp().echo(t).str("k"), "S.early")
	c.finish()
	evs := e.stop()
	wantEq(t, "socks5_request.rsv", one(t, evs.of("socks5_request"), "socks5_request").num("rsv"), 0x7f)
	tf := one(t, evs.of("tunnel_first_bytes"), "tunnel_first_bytes")
	wantEq(t, "tunnel_first_bytes.early_bytes", tf.num("early_bytes"), len(get))
	wantEq(t, "tunnel_first_bytes.n_first_read", tf.num("n_first_read"), len(get))
	wantEq(t, "tunnel_first_bytes.kind", tf.str("kind"), "http")
	wantEq(t, "tunnel_close.bytes_c2s", one(t, evs.of("tunnel_close"), "tunnel_close").num("bytes_c2s"), len(get))
}

// 握手到一半对端就关了：已经收到的部分有事件，conn_end 记的是 client。
func TestSocks5ClientClosesMidHandshake(t *testing.T) {
	e := startEnv(t, `{}`)
	c := e.dialProxy()
	c.sendBytes([]byte{0x05, 0x01, 0x00})
	wantBytes(t, "方法应答", c.readN(2), []byte{0x05, 0x00})
	c.sendBytes([]byte{0x05, 0x01, 0x00, 0x03, 0x0c, 'a'})
	c.finish()
	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(), "accept first_bytes socks5_greeting socks5_method conn_end")
	end := ce[4]
	wantEq(t, "conn_end.by", end.str("by"), "client")
	wantEq(t, "conn_end.reason", end.str("reason"), "client_eof")
}
