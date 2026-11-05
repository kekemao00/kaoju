package wire

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSniff(t *testing.T) {
	for in, want := range map[string]string{
		"HTTP/1.1 400 Bad Request\r\n": "http", "SSH-2.0-OpenSSH_9.6": "ssh", "\x16\x03\x01\x02\x00": "tls",
		"220 mail.example.com ESMTP": "smtp_or_ftp", "<!DOCTYPE html><html>": "html", "\x05\xff": "socks5",
		"\x00\x5b\x00\x00": "socks4", "random": "unknown", "": "",
	} {
		if got := Sniff([]byte(in)); got != want {
			t.Errorf("%q: %q，期望 %q", in, got, want)
		}
	}
}

func TestAffixAndSimilarity(t *testing.T) {
	want := []byte("line one\nline two\nline three\nline four\n")
	for _, c := range []struct {
		name     string
		got      string
		pre, suf int
		sim      int
	}{
		{"相同", string(want), len(want), 0, 100},
		{"中间插入", "line one\nline two\nINJECTED\nline three\nline four\n", 18, 21, 100},
		{"一行被改", "line one\nline 2\nline three\nline four\n", 14, 22, 75},
		{"截断", "line one\nline two\n", 18, 0, 50},
		{"整页替换", "<html>error</html>\n", 0, 1, 0},
	} {
		pre, suf := CommonAffix([]byte(c.got), want)
		if pre != c.pre || suf != c.suf {
			t.Errorf("%s: 前缀 %d 后缀 %d，期望 %d %d", c.name, pre, suf, c.pre, c.suf)
		}
		if sim := LineSimilarity([]byte(c.got), want); sim != c.sim {
			t.Errorf("%s: 相似度 %d，期望 %d", c.name, sim, c.sim)
		}
	}
}

func TestBuildRequest(t *testing.T) {
	abs := string(BuildRequest(GetSpec{Absolute: true, Authority: "judge.example:8080", Path: "/p/h/x", Canary: "c0ffee"}))
	want := "GET http://judge.example:8080/p/h/x HTTP/1.1\r\nHost: judge.example:8080\r\nUser-Agent: " + UA + "\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n" +
		"Accept-Encoding: identity\r\nCookie: pc=c0ffee\r\nX-Probe-Canary: c0ffee\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n"
	if abs != want {
		t.Errorf("请求字节变了:\n%q", abs)
	}
	origin := string(BuildRequest(GetSpec{Authority: "judge.example", Path: "/"}))
	if origin != "GET / HTTP/1.1\r\nHost: judge.example\r\nUser-Agent: "+UA+"\r\n"+
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n"+
		"Accept-Encoding: identity\r\nConnection: close\r\n\r\n" {
		t.Errorf("请求字节变了:\n%q", origin)
	}
}

// serve 启动一个只会照本宣科的对端：读掉客户端发来的一切，把 reply 发回去，然后断开。
func serve(reply []byte) net.Conn {
	client, server := net.Pipe()
	go func() {
		go io.Copy(io.Discard, server)
		server.Write(reply)
		time.Sleep(20 * time.Millisecond)
		server.Close()
	}()
	return client
}

// FuzzHandshakes 把任意字节当作对端的回答喂给各个握手函数。对端不可信，这些函数不能崩溃，也不能卡死。
func FuzzHandshakes(f *testing.F) {
	for _, seed := range []string{"\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", "\x05\xff", "\x00\x5a\x00\x00\x00\x00\x00\x00",
		"HTTP/1.1 200 Connection established\r\n\r\n", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"\x05\x00\x05\x00\x00\x03\xff", "SSH-2.0-x\r\n", "", "HTTP/9.9 999\r\n", "\x16\x03\x01\x00\x05hello"} {
		f.Add([]byte(seed))
	}
	ip := netip.MustParseAddr("192.0.2.1")
	const to = 300 * time.Millisecond
	f.Fuzz(func(t *testing.T, reply []byte) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			c := serve(reply)
			Socks5(c, "judge.example", 443, nil, 0, to)
			c.Close()
			c = serve(reply)
			Socks5(c, "judge.example", 443, &Socks5Auth{User: "u", Pass: "p"}, 0, to)
			c.Close()
			c = serve(reply)
			Socks4(c, ip, 443, to)
			c.Close()
			c = serve(reply)
			HTTPConnect(c, "judge.example:443", UA, to)
			c.Close()
			c = serve(reply)
			Get(c, GetSpec{Authority: "judge.example", Path: "/", Timeout: to, MaxBody: 1024})
			c.Close()
			c = serve(reply)
			TLS(c, TLSOpts{ServerName: "judge.example", Timeout: to})
			c.Close()
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("握手函数卡住了")
		}
	})
}
