package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// FuzzHTTPHead：请求头的读取和解析对任何输入都不崩溃，并且守住几条不变的性质。
//
//	go test -run '^$' -fuzz FuzzHTTPHead -fuzztime 10s
func FuzzHTTPHead(f *testing.F) {
	for _, s := range []string{
		"GET http://a.kaoju.test/echo?k=A01.s1 HTTP/1.1\r\nHost: a.kaoju.test\r\n\r\n",
		"CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\nProxy-Authorization: Basic a2FvanUtdXNlcjprYW9qdS1wYXNzLTE=\r\n\r\n",
		"CONNECT a.kaoju.test:443 HTTP/1.0\r\n\r\n",
		"POST http://a.kaoju.test/echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX: y\r\n\r\n",
		"POST http://a.kaoju.test/echo HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET",
		"\r\n\r\nGET / HTTP/1.1\r\n\r\n",
		"GET  /  HTTP/1.1\r\n folded\r\n: novalue\r\nNoColon\r\n\r\n",
		"GET / HTTP/1.1\nHost: x\n\n",
		"GET / HTTP/1.1\r\nProxy-Authorization: basic !!!\r\nProxy-Authorization: Bearer x\r\nContent-Length: 1, 1\r\n\r\nx",
		"GET / HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\nContent-Length: 99999999999999999999\r\n\r\n",
		"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffff\r\n",
		"\x16\x03\x01\x02\x00\x01",
		"",
	} {
		f.Add([]byte(s))
	}
	prof := DefaultProfile()
	prof.Auth.Accept = []Pair{{"u", "p"}}
	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(data), maxHeadBytes+4096)
		// 像 serveHTTP 那样一个接一个地读，直到出错。
		for i := 0; i < 64; i++ {
			raw, err := readHead(br, maxHeadBytes)
			if len(raw) > maxHeadBytes+4096 {
				t.Fatalf("readHead 返回了 %d 字节，超出上限太多", len(raw))
			}
			h, perr := parseHead(raw)
			if h == nil {
				t.Fatal("parseHead 返回了 nil")
			}
			if !bytes.Equal(h.Raw, raw) {
				t.Fatal("Raw 不是原样的字节")
			}
			if err == nil {
				// 完整的请求头：原文里一定以空行结尾，并且是输入里的一段连续的字节。
				if !bytes.HasSuffix(raw, []byte("\n\n")) && !bytes.HasSuffix(raw, []byte("\n\r\n")) {
					t.Fatalf("完整的请求头没有以空行结尾: %q", raw)
				}
				if !bytes.Contains(data, raw) {
					t.Fatalf("请求头的原文不是输入的一部分: %q", raw)
				}
			}
			if perr == nil {
				if !isToken(h.Method) || h.Target == "" || !validVersionSyntax(h.Version) {
					t.Fatalf("解析通过但请求行不合规范: %q %q %q", h.Method, h.Target, h.Version)
				}
				for _, kv := range h.Headers {
					if !isToken(kv[0]) || strings.ContainsAny(kv[1], "\r\n\x00") {
						t.Fatalf("解析通过但头不合规范: %q", kv)
					}
				}
			}
			form := classifyForm(h.Method, h.Target)
			switch form {
			case "absolute", "connect", "origin", "other":
			default:
				t.Fatalf("不认识的形式 %q", form)
			}
			_, _ = queryGet(targetQuery(h.Target), "k")
			a := parseProxyAuth(h.all("Proxy-Authorization"))
			prof.judgeAuth(&a)
			switch a.Result {
			case "none", "ok", "bad", "malformed":
			default:
				t.Fatalf("不认识的认证判定 %q", a.Result)
			}
			if a.Result == "ok" && (string(a.User) != "u" || string(a.Pass) != "p") {
				t.Fatalf("判定为 ok 但凭据不是配置的那组: %q %q", a.User, a.Pass)
			}
			// 事件里的 auth 对象必须能编码成 JSON。
			if _, jerr := json.Marshal(a.fields()); jerr != nil {
				t.Fatalf("auth 编码失败: %v", jerr)
			}
			_ = forwardHeaders(h)
			if err != nil || perr != nil {
				return
			}
			fr, ferr := bodyFraming(h)
			if ferr != nil {
				return
			}
			if fr.kind == "content-length" && fr.length < 0 {
				t.Fatalf("Content-Length 是负数: %d", fr.length)
			}
			n, berr := readBody(br, fr, io.Discard)
			if n < 0 || int(n) > len(data) {
				t.Fatalf("正文长度 %d 不可能（输入只有 %d 字节）", n, len(data))
			}
			if berr != nil {
				return
			}
		}
	})
}

// FuzzSocks5：SOCKS5 握手的解析对任何输入都不崩溃；写给客户端的字节符合 RFC 1928、1929 的格式。
//
//	go test -run '^$' -fuzz FuzzSocks5 -fuzztime 10s
func FuzzSocks5(f *testing.F) {
	f.Add(byte(0), []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x01, 'a', 0x01, 0xbb})
	f.Add(byte(1), append([]byte{0x05, 0x02, 0x00, 0x02, 0x01, 0x01, 'u', 0x01, 'p'}, socksRequest(0x01, 0x01, []byte{127, 0, 0, 1}, 80)...))
	f.Add(byte(1), []byte{0x05, 0x01, 0x02, 0x01, 0x01, 'u', 0x01, 'x'})
	f.Add(byte(2), []byte{0x05, 0x01, 0x00})
	f.Add(byte(3), append([]byte{0x05, 0x01, 0x00}, socksRequest(0x01, 0x04, make([]byte, 16), 443)...))
	f.Add(byte(0), append([]byte{0x05, 0x01, 0x00}, socksRequest(0x02, 0x03, []byte("a.kaoju.test"), 443)...))
	f.Add(byte(0), []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09})
	f.Add(byte(0), []byte{0x04, 0x01, 0x00, 0x50})
	f.Add(byte(0), []byte{})
	profiles := []*Profile{DefaultProfile(), DefaultProfile(), DefaultProfile(), DefaultProfile()}
	profiles[1].Socks.Auth = "userpass"
	profiles[1].Auth.Accept = []Pair{{"u", "p"}}
	profiles[2].Socks.Auth = "reject"
	profiles[3].Socks.Rep = 4
	mapPort := func(port int) string {
		switch port {
		case 80:
			return "origin_http"
		case 443:
			return "origin_https"
		}
		return ""
	}
	f.Fuzz(func(t *testing.T, which byte, data []byte) {
		p := profiles[int(which)%len(profiles)]
		var out bytes.Buffer
		var names []string
		last := map[string][]kv{}
		emit := func(ev string, fields ...kv) {
			names = append(names, ev)
			last[ev] = fields
			if _, err := json.Marshal(obj(fields)); err != nil {
				t.Fatalf("事件 %s 编码失败: %v", ev, err)
			}
		}
		br := bufio.NewReader(bytes.NewReader(data))
		res := socksNegotiate(br, &out, p, mapPort, emit)
		w := out.Bytes()

		field := func(ev, k string) any {
			for _, f := range last[ev] {
				if f.K == k {
					return f.V
				}
			}
			return nil
		}
		// 事件的次序是固定的。
		order := strings.Join(names, " ")
		allowed := []string{
			"",
			"socks5_greeting",
			"socks5_greeting socks5_method",
			"socks5_greeting socks5_method socks5_auth",
			"socks5_greeting socks5_method socks5_request socks5_reply",
			"socks5_greeting socks5_method socks5_auth socks5_request socks5_reply",
		}
		okOrder := false
		for _, a := range allowed {
			okOrder = okOrder || a == order
		}
		if !okOrder {
			t.Fatalf("事件次序不对: %q", order)
		}
		if len(names) < 2 {
			if len(w) != 0 || res.ok {
				t.Fatalf("方法协商还没完成就写了 %x 或者成功了", w)
			}
			return
		}
		// 方法应答：05 加选中的方法；选中的要么是 0xFF，要么是客户端提供过的。
		sel := field("socks5_method", "selected").(int)
		if len(w) < 2 || w[0] != 0x05 || int(w[1]) != sel {
			t.Fatalf("方法应答不对: %x（selected=%d）", w, sel)
		}
		if sel != 0xff {
			offered := false
			for _, m := range field("socks5_greeting", "methods").([]int) {
				offered = offered || m == sel
			}
			if !offered {
				t.Fatalf("选了客户端没提供的方法 %d", sel)
			}
		}
		if p.Socks.Auth == "reject" && sel != 0xff {
			t.Fatalf("socks.auth=reject 却选了 %d", sel)
		}
		rest := w[2:]
		if sel == 0xff {
			if len(rest) != 0 || res.ok {
				t.Fatalf("回了 0xFF 之后还写了 %x 或者成功了", rest)
			}
			return
		}
		if sel == 0x02 && len(last["socks5_auth"]) > 0 {
			st := field("socks5_auth", "status").(int)
			if len(rest) < 2 || rest[0] != 0x01 || int(rest[1]) != st {
				t.Fatalf("认证应答不对: %x（status=%d）", rest, st)
			}
			result := field("socks5_auth", "result").(string)
			if (st == 0) != (result == "ok") {
				t.Fatalf("status=%d 与 result=%q 不一致", st, result)
			}
			if result == "ok" && (field("socks5_auth", "user_hex") != "75" || field("socks5_auth", "pass_hex") != "70") {
				t.Fatal("判定为 ok 但凭据不是配置的那组")
			}
			rest = rest[2:]
			if st != 0 {
				if len(rest) != 0 || res.ok {
					t.Fatal("认证失败之后还写了字节或者成功了")
				}
				return
			}
		}
		if len(last["socks5_reply"]) == 0 {
			if len(rest) != 0 || res.ok {
				t.Fatal("没有应答事件却写了应答或者成功了")
			}
			return
		}
		rep := field("socks5_reply", "rep").(int)
		want := []byte{0x05, byte(rep), 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if !bytes.Equal(rest, want) {
			t.Fatalf("应答 = %x，应为 %x", rest, want)
		}
		if res.ok != (rep == 0) {
			t.Fatalf("rep=%d 而 ok=%v", rep, res.ok)
		}
		if res.ok {
			if res.mapped == "" || p.Socks.Rep != 0 || field("socks5_request", "cmd").(int) != 1 {
				t.Fatalf("不该成功: %+v", res)
			}
		}
	})
}

// FuzzClientHello：隧道首批字节的归类和 ClientHello 的解析对任何输入都不崩溃。
func FuzzClientHello(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		kind, hello := classifyTunnelFirst(data)
		switch kind {
		case "tls_client_hello":
			if hello == nil {
				t.Fatal("归为 ClientHello 却没有解析结果")
			}
			if _, err := json.Marshal(hello.fields()); err != nil {
				t.Fatalf("tls 对象编码失败: %v", err)
			}
			if hello.Complete && hello.RecordLen > len(data)-5 {
				t.Fatal("记录没到齐却标了 complete")
			}
		case "http", "other":
			if hello != nil {
				t.Fatal("不是 ClientHello 却有解析结果")
			}
		default:
			t.Fatalf("不认识的归类 %q", kind)
		}
	})
}
