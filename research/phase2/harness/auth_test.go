package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

const basicProfile = `{"auth":{"mode":"basic","accept":[["kaoju-user","kaoju-pass-1"],["kaoju-user-2","kaoju-pass-2"]]}}`

// 没带凭据 → 407（带质询、带 Content-Length、连接留着）→ 原连接上带凭据重试 → 200。
func TestAuth407ThenRetryOnSameConn(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["kaoju-user","kaoju-pass-1"]],
		"challenge":["Basic realm=\"kaoju\"","Basic realm=\"other\", charset=\"UTF-8\""]}}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=B01.s1", "a.kaoju.test"))
	r := c.readResp()
	wantEq(t, "状态码", r.status, 407)
	wantEq(t, "原因短语", r.reason, "Proxy Authentication Required")
	wantEq(t, "质询（每项一行，按配置的顺序）", strings.Join(r.all("Proxy-Authenticate"), " | "),
		`Basic realm="kaoju" | Basic realm="other", charset="UTF-8"`)
	if cl, ok := r.get("Content-Length"); !ok || cl != fmt.Sprint(len(r.body)) || len(r.body) == 0 {
		t.Errorf("407 应带 Content-Length 和一小段正文: %q %q", cl, r.body)
	}
	if ct, _ := r.get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("407 的正文应是纯文本: %q", ct)
	}
	if _, ok := r.get("Connection"); ok {
		t.Error("on407=keepalive 时 407 不应带 Connection 头")
	}
	if strings.Contains(string(r.body), "407") {
		t.Errorf("407 的正文里不应出现数字 407（否则分不清调用方看到的是状态码还是正文）: %q", r.body)
	}
	hdr := "Proxy-Authorization: " + basicAuth("kaoju-user", "kaoju-pass-1") + "\r\n"
	c.send(getReq("http://a.kaoju.test/echo?k=B01.s1", "a.kaoju.test", hdr))
	r2 := c.readResp()
	wantEq(t, "带凭据重试", r2.status, 200)
	for _, h := range r2.echo(t).pairs("headers") {
		if strings.HasPrefix(strings.ToLower(h[0]), "proxy-") {
			t.Errorf("Proxy- 开头的头 %s 被交给了源站", h[0])
		}
	}
	c.finish()

	evs := e.stop()
	ce := evs.conn(e.connID(c))
	wantEq(t, "事件序列", ce.names(), "accept first_bytes http_request http_response http_request origin_request http_response conn_end")
	reqs, resps := ce.of("http_request"), ce.of("http_response")
	a1 := reqs[0].obj("auth")
	wantEq(t, "第 1 个请求 auth.present", a1["present"], any(false))
	wantEq(t, "第 1 个请求 auth.result", a1.str("result"), "none")
	for _, k := range []string{"scheme", "raw", "user", "user_hex", "pass", "pass_hex"} {
		if v, ok := a1[k]; !ok || v != nil {
			t.Errorf("没带凭据时 auth.%s 应当存在且为 null: %v（存在=%v）", k, v, ok)
		}
	}
	wantEq(t, "第 1 个响应 status", resps[0].num("status"), 407)
	wantEq(t, "第 1 个响应 cause", resps[0].str("cause"), "auth_required")
	wantEq(t, "第 1 个响应 by", resps[0].str("by"), "proxy")
	wantEq(t, "第 1 个响应 close", resps[0]["close"], any(false))
	a2 := reqs[1].obj("auth")
	wantEq(t, "第 2 个请求 auth.present", a2["present"], any(true))
	wantEq(t, "第 2 个请求 auth.scheme", a2.str("scheme"), "Basic")
	wantEq(t, "第 2 个请求 auth.raw", a2.str("raw"), basicAuth("kaoju-user", "kaoju-pass-1"))
	wantEq(t, "第 2 个请求 auth.user", a2.str("user"), "kaoju-user")
	wantEq(t, "第 2 个请求 auth.user_hex", a2.str("user_hex"), hex.EncodeToString([]byte("kaoju-user")))
	wantEq(t, "第 2 个请求 auth.pass", a2.str("pass"), "kaoju-pass-1")
	wantEq(t, "第 2 个请求 auth.pass_hex", a2.str("pass_hex"), hex.EncodeToString([]byte("kaoju-pass-1")))
	wantEq(t, "第 2 个请求 auth.result", a2.str("result"), "ok")
	wantEq(t, "第 2 个请求 seq", reqs[1].num("seq"), 2)
	wantEq(t, "origin_request.has_proxy_authorization", ce.of("origin_request")[0]["has_proxy_authorization"], any(false))
}

// auth.on407=close：407 带 Connection: close，发完按 fin 关。
func TestAuthOn407Close(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["kaoju-user","kaoju-pass-1"]],"on407":"close"}}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=B03.s1", "a.kaoju.test"))
	r := c.readResp()
	wantEq(t, "状态码", r.status, 407)
	if v, _ := r.get("Connection"); v != "close" {
		t.Errorf("on407=close 时 407 应带 Connection: close，实际 %q", v)
	}
	c.expectEOF(3 * time.Second)
	c.finish()

	// CONNECT 也一样。
	c2 := e.dialProxy()
	c2.send("CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\n\r\n")
	r2 := c2.readResp()
	wantEq(t, "CONNECT 的状态码", r2.status, 407)
	if v, _ := r2.get("Connection"); v != "close" {
		t.Errorf("CONNECT 的 407 应带 Connection: close，实际 %q", v)
	}
	c2.expectEOF(3 * time.Second)
	c2.finish()

	// 带对了凭据的不受影响。
	c3 := e.dialProxy()
	c3.send(getReq("http://a.kaoju.test/echo?k=B03.s1", "a.kaoju.test", "Proxy-Authorization: "+basicAuth("kaoju-user", "kaoju-pass-1")+"\r\n"))
	wantEq(t, "带凭据的请求", c3.readResp().status, 200)
	c3.finish()

	evs := e.stop()
	for _, c := range []*rawConn{c, c2} {
		ce := evs.conn(e.connID(c))
		wantEq(t, "http_response.close", ce.of("http_response")[0]["close"], any(true))
		end := ce.of("conn_end")[0]
		wantEq(t, "conn_end.by", end.str("by"), "proxy")
		wantEq(t, "conn_end.close", end.str("close"), "fin")
		wantEq(t, "conn_end.reason", end.str("reason"), "response_close")
	}
	wantEq(t, "tunnel_open 的个数", len(evs.of("tunnel_open")), 0)
}

// 凭据不对：按 auth.reject_status 回 407 或 403；没带凭据一律 407。
func TestAuthRejectStatus(t *testing.T) {
	for _, status := range []int{407, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			e := startEnv(t, fmt.Sprintf(`{"auth":{"mode":"basic","accept":[["kaoju-user","kaoju-pass-1"]],"reject_status":%d}}`, status))
			c := e.dialProxy()
			bad := "Proxy-Authorization: " + basicAuth("kaoju-user", "wrong-pass") + "\r\n"
			c.send(getReq("http://a.kaoju.test/echo?k=C03.s1", "a.kaoju.test", bad))
			r := c.readResp()
			wantEq(t, "密码错（明文）", r.status, status)
			wantEq(t, "质询的行数", len(r.all("Proxy-Authenticate")), map[int]int{407: 1, 403: 0}[status])
			if strings.Contains(string(r.body), fmt.Sprint(status)) {
				t.Errorf("正文里不应出现状态码数字: %q", r.body)
			}
			c.send("CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\n" + bad + "\r\n")
			wantEq(t, "密码错（CONNECT）", c.readResp().status, status)
			c.send(getReq("http://a.kaoju.test/echo?k=C03.s1", "a.kaoju.test"))
			wantEq(t, "没带凭据", c.readResp().status, 407)
			c.send(getReq("http://a.kaoju.test/echo?k=C03.s1", "a.kaoju.test", "Proxy-Authorization: "+basicAuth("kaoju-user", "kaoju-pass-1")+"\r\n"))
			wantEq(t, "凭据正确（同一条连接上的第 4 个请求）", c.readResp().status, 200)
			c.finish()
			evs := e.stop()
			reqs, resps := evs.of("http_request"), evs.of("http_response")
			wantEq(t, "请求 1 的判定", reqs[0].obj("auth").str("result"), "bad")
			wantEq(t, "请求 1 解出的密码", reqs[0].obj("auth").str("pass"), "wrong-pass")
			wantEq(t, "请求 2 的判定", reqs[1].obj("auth").str("result"), "bad")
			wantEq(t, "请求 3 的判定", reqs[2].obj("auth").str("result"), "none")
			wantEq(t, "请求 4 的判定", reqs[3].obj("auth").str("result"), "ok")
			wantEq(t, "响应 1 的 cause", resps[0].str("cause"), "auth_rejected")
			wantEq(t, "响应 3 的 cause", resps[2].str("cause"), "auth_required")
		})
	}
}

// Proxy-Authorization 的各种写法：宽容地记录，严格地判定。
func TestAuthHeaderVariants(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("kaoju-user:kaoju-pass-1"))
	unpadded := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte("kaoju-user:kaoju-pass-123")), "=") // 需要填充的长度
	if unpadded == base64.StdEncoding.EncodeToString([]byte("kaoju-user:kaoju-pass-123")) {
		t.Fatal("测试数据选错了：这个凭据的 base64 本来就没有填充")
	}
	cases := []struct {
		name, value string
		status      int
		result      string
		scheme      string
		user, pass  any // string 或 nil
		lenient     bool
	}{
		{"标准写法", "Basic " + good, 200, "ok", "Basic", "kaoju-user", "kaoju-pass-1", false},
		{"方案名全小写", "basic " + good, 200, "ok", "basic", "kaoju-user", "kaoju-pass-1", false},
		{"方案名大小写混合", "bAsIc " + good, 200, "ok", "bAsIc", "kaoju-user", "kaoju-pass-1", false},
		{"方案和凭据之间多个空格", "Basic    " + good, 200, "ok", "Basic", "kaoju-user", "kaoju-pass-1", false},
		{"密码里有冒号（按第一个冒号拆）", "Basic " + base64.StdEncoding.EncodeToString([]byte("kaoju-user:a:b:c")), 407, "bad", "Basic", "kaoju-user", "a:b:c", false},
		{"用户名里有冒号（拆出来的用户名只到第一个冒号）", "Basic " + base64.StdEncoding.EncodeToString([]byte("sess:ab12:kaoju-pass-1")), 407, "bad", "Basic", "sess", "ab12:kaoju-pass-1", false},
		{"空密码", "Basic " + base64.StdEncoding.EncodeToString([]byte("kaoju-user:")), 407, "bad", "Basic", "kaoju-user", "", false},
		{"空用户名", "Basic " + base64.StdEncoding.EncodeToString([]byte(":kaoju-pass-1")), 407, "bad", "Basic", "", "kaoju-pass-1", false},
		{"base64 解不开", "Basic !!!not-base64!!!", 407, "malformed", "Basic", nil, nil, false},
		{"base64 缺填充", "Basic " + unpadded, 407, "malformed", "Basic", "kaoju-user", "kaoju-pass-123", true},
		{"解开以后没有冒号", "Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")), 407, "malformed", "Basic", "no-colon-here", nil, false},
		{"只有方案名", "Basic", 407, "malformed", "Basic", nil, nil, false},
		{"凭据是空的", "Basic   ", 407, "malformed", "Basic", nil, nil, false},
		{"不是 Basic", "Bearer abcdef", 407, "bad", "Bearer", nil, nil, false},
		{"Digest", `Digest username="kaoju-user", realm="kaoju"`, 407, "bad", "Digest", nil, nil, false},
	}
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["kaoju-user","kaoju-pass-1"]]}}`)
	c := e.dialProxy()
	for i, tc := range cases {
		c.send(getReq(fmt.Sprintf("http://a.kaoju.test/echo?k=V.s%d", i+1), "a.kaoju.test", "Proxy-Authorization: "+tc.value+"\r\n"))
		wantEq(t, tc.name+"：状态码", c.readResp().status, tc.status)
	}
	c.finish()
	evs := e.stop()
	reqs := evs.of("http_request")
	if len(reqs) != len(cases) {
		t.Fatalf("http_request 应有 %d 个，实际 %d 个", len(cases), len(reqs))
	}
	for i, tc := range cases {
		a := reqs[i].obj("auth")
		wantEq(t, tc.name+"：auth.present", a["present"], any(true))
		wantEq(t, tc.name+"：auth.raw", a.str("raw"), strings.TrimRight(tc.value, " "))
		wantEq(t, tc.name+"：auth.scheme", a.str("scheme"), tc.scheme)
		wantEq(t, tc.name+"：auth.result", a.str("result"), tc.result)
		wantEq(t, tc.name+"：auth.user", a["user"], tc.user)
		wantEq(t, tc.name+"：auth.pass", a["pass"], tc.pass)
		wantEq(t, tc.name+"：auth.lenient", a["lenient"], any(tc.lenient))
		for _, f := range [][2]string{{"user", "user_hex"}, {"pass", "pass_hex"}} {
			if s, ok := a[f[0]].(string); ok {
				wantEq(t, tc.name+"：auth."+f[1], a.str(f[1]), hex.EncodeToString([]byte(s)))
			} else if a[f[1]] != nil {
				t.Errorf("%s：auth.%s 应为 null: %v", tc.name, f[1], a[f[1]])
			}
		}
	}
}

// auth.accept_any_user：任何用户名都接受，只比密码（与 accept[0][1] 比）；收到的用户名字节照样记录。
func TestAuthAcceptAnyUser(t *testing.T) {
	e := startEnv(t, `{"auth":{"mode":"basic","accept":[["placeholder","kaoju-pass-1"],["other","kaoju-pass-2"]],"accept_any_user":true}}`)
	c := e.dialProxy()
	send := func(k string, cred []byte) int {
		c.send(getReq("http://a.kaoju.test/echo?k="+k, "a.kaoju.test", "Proxy-Authorization: Basic "+base64.StdEncoding.EncodeToString(cred)+"\r\n"))
		return c.readResp().status
	}
	utf8User := "用户-séssion-ß"
	wantEq(t, "UTF-8 用户名", send("D.s1", []byte(utf8User+":kaoju-pass-1")), 200)
	binUser := []byte{0xff, 0xfe, 0x00, 0x80, 'x'}
	wantEq(t, "不是 UTF-8 的用户名", send("D.s2", append(append([]byte{}, binUser...), ":kaoju-pass-1"...)), 200)
	long := strings.Repeat("u", 1024)
	wantEq(t, "1024 字节的用户名", send("D.s3", []byte(long+":kaoju-pass-1")), 200)
	wantEq(t, "密码是 accept[1] 的（不认）", send("D.s4", []byte("other:kaoju-pass-2")), 407)
	// Basic 分不出用户名里的冒号：按整串比，以“:密码”结尾就接受（用例 D11）。
	wantEq(t, "用户名里有冒号", send("D.s5", []byte("sess:ab12:kaoju-pass-1")), 200)
	wantEq(t, "用户名里有冒号、密码不对", send("D.s6", []byte("sess:ab12:kaoju-pass-2")), 407)
	c.finish()
	evs := e.stop()
	reqs := evs.of("http_request")
	a := reqs[0].obj("auth")
	wantEq(t, "UTF-8 用户名：auth.user", a.str("user"), utf8User)
	wantEq(t, "UTF-8 用户名：auth.user_hex", a.str("user_hex"), hex.EncodeToString([]byte(utf8User)))
	wantEq(t, "UTF-8 用户名：auth.result", a.str("result"), "ok")
	b := reqs[1].obj("auth")
	if b["user"] != nil {
		t.Errorf("不是 UTF-8 的用户名：auth.user 应为 null: %v", b["user"])
	}
	wantEq(t, "不是 UTF-8 的用户名：auth.user_hex", b.str("user_hex"), hex.EncodeToString(binUser))
	wantEq(t, "不是 UTF-8 的用户名：auth.result", b.str("result"), "ok")
	wantEq(t, "1024 字节的用户名：auth.user", reqs[2].obj("auth").str("user"), long)
	wantEq(t, "密码不对：auth.result", reqs[3].obj("auth").str("result"), "bad")
	wantEq(t, "用户名里有冒号：auth.user", reqs[4].obj("auth").str("user"), "sess")
	wantEq(t, "用户名里有冒号：auth.pass", reqs[4].obj("auth").str("pass"), "ab12:kaoju-pass-1")
	wantEq(t, "用户名里有冒号：auth.result", reqs[4].obj("auth").str("result"), "ok")
	wantEq(t, "用户名里有冒号、密码不对：auth.result", reqs[5].obj("auth").str("result"), "bad")
}

// 要求认证而没带凭据的 POST：先把正文读完再回 407，所以同一条连接上接着重试不会错位。
func TestAuth407ReadsBodyFirst(t *testing.T) {
	e := startEnv(t, basicProfile)
	c := e.dialProxy()
	body := pattern(200000) // 比套接字缓冲区大：代理不读完，客户端就写不完
	head := "POST http://a.kaoju.test/echo?k=B13.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\n" + fmt.Sprintf("Content-Length: %d\r\n", len(body))
	c.send(head + "\r\n" + string(body))
	wantEq(t, "没带凭据", c.readResp().status, 407)
	c.send(head + "Proxy-Authorization: " + basicAuth("kaoju-user-2", "kaoju-pass-2") + "\r\n\r\n" + string(body))
	r := c.readResp()
	wantEq(t, "原连接上带凭据重试", r.status, 200)
	wantEq(t, "echo.body_sha256", r.echo(t).str("body_sha256"), sha256hex(body))
	// chunked 的正文同样先读完。
	c.send("POST http://a.kaoju.test/echo?k=B13.s2 HTTP/1.1\r\nHost: a.kaoju.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	wantEq(t, "没带凭据的 chunked POST", c.readResp().status, 407)
	c.send(getReq("http://a.kaoju.test/echo?k=B13.s3", "a.kaoju.test", "Proxy-Authorization: "+basicAuth("kaoju-user", "kaoju-pass-1")+"\r\n"))
	wantEq(t, "之后的请求", c.readResp().echo(t).str("k"), "B13.s3")
	c.finish()
	evs := e.stop()
	reqs := evs.of("http_request")
	wantEq(t, "http_request 的个数", len(reqs), 4)
	wantEq(t, "第 1 个请求（被 407）的 body_len", reqs[0].num("body_len"), len(body))
	wantEq(t, "第 1 个请求（被 407）的 body_sha256", reqs[0].str("body_sha256"), sha256hex(body))
	wantEq(t, "第 2 个请求解出的用户名", reqs[1].obj("auth").str("user"), "kaoju-user-2")
	wantEq(t, "第 3 个请求（被 407）的 body_len", reqs[2].num("body_len"), 3)
	wantEq(t, "代理连接数", len(evs.of("accept")), 1)
}

// 不要求认证时客户端带了凭据：照样解析、照样判定（与 auth.accept 比），但不据此拒绝。
func TestAuthNotRequiredButSent(t *testing.T) {
	e := startEnv(t, `{"auth":{"accept":[["kaoju-user","kaoju-pass-1"]]}}`)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=C06.s1", "a.kaoju.test", "Proxy-Authorization: "+basicAuth("kaoju-user", "kaoju-pass-1")+"\r\n"))
	wantEq(t, "凭据与 accept 相符", c.readResp().status, 200)
	c.send(getReq("http://a.kaoju.test/echo?k=C06.s2", "a.kaoju.test", "Proxy-Authorization: "+basicAuth("someone", "else")+"\r\n"))
	wantEq(t, "凭据与 accept 不符", c.readResp().status, 200)
	c.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\nProxy-Authorization: " + basicAuth("someone", "else") + "\r\n\r\n")
	wantEq(t, "CONNECT", c.readResp().status, 200)
	c.finish()
	evs := e.stop()
	reqs := evs.of("http_request")
	wantEq(t, "请求 1 的判定", reqs[0].obj("auth").str("result"), "ok")
	wantEq(t, "请求 2 的判定", reqs[1].obj("auth").str("result"), "bad")
	wantEq(t, "请求 3 的判定", reqs[2].obj("auth").str("result"), "bad")
	wantEq(t, "请求 2 解出的用户名", reqs[1].obj("auth").str("user"), "someone")
}

// 有两个 Proxy-Authorization 头时只按第一个判定，两个都留在 headers 里。
func TestAuthTwoHeaders(t *testing.T) {
	e := startEnv(t, basicProfile)
	c := e.dialProxy()
	c.send(getReq("http://a.kaoju.test/echo?k=T.s1", "a.kaoju.test",
		"Proxy-Authorization: "+basicAuth("kaoju-user", "wrong")+"\r\n",
		"proxy-authorization: "+basicAuth("kaoju-user", "kaoju-pass-1")+"\r\n"))
	wantEq(t, "状态码", c.readResp().status, 407)
	c.finish()
	evs := e.stop()
	hr := one(t, evs.of("http_request"), "http_request")
	wantEq(t, "auth.pass", hr.obj("auth").str("pass"), "wrong")
	n := 0
	for _, h := range hr.pairs("headers") {
		if strings.EqualFold(h[0], "Proxy-Authorization") {
			n++
		}
	}
	wantEq(t, "headers 里 Proxy-Authorization 的个数", n, 2)
}

// CONNECT 的认证：407 之后在原连接上带凭据重试，隧道建在第 2 个请求上。
func TestAuthConnect(t *testing.T) {
	e := startEnv(t, basicProfile)
	c := e.dialProxy()
	c.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\n\r\n")
	r := c.readResp()
	wantEq(t, "没带凭据的 CONNECT", r.status, 407)
	wantEq(t, "质询", strings.Join(r.all("Proxy-Authenticate"), "|"), `Basic realm="kaoju"`)
	c.send("CONNECT a.kaoju.test:80 HTTP/1.1\r\nHost: a.kaoju.test:80\r\nProxy-Authorization: " + basicAuth("kaoju-user-2", "kaoju-pass-2") + "\r\n\r\n")
	wantEq(t, "带凭据的 CONNECT", c.readResp().status, 200)
	c.send(getReq("/echo?k=B02.s1", "a.kaoju.test"))
	echo := c.readResp().echo(t)
	wantEq(t, "隧道里的请求", echo.str("k"), "B02.s1")
	c.finish()
	evs := e.stop()
	to := one(t, evs.of("tunnel_open"), "tunnel_open")
	wantEq(t, "tunnel_open.req_seq", to.num("req_seq"), 2)
	connects := evs.of("http_request")
	wantEq(t, "建隧道的 CONNECT 解出的用户名", connects[to.num("req_seq")-1].obj("auth").str("user"), "kaoju-user-2")
	or := one(t, evs.of("origin_request"), "origin_request")
	wantEq(t, "隧道里的请求有没有带 Proxy-Authorization", or["has_proxy_authorization"], any(false))
}
