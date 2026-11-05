// Package wire 实现探测要用到的协议动作：TCP 连接、SOCKS4/SOCKS5/HTTP CONNECT 握手、
// 隧道内的 TLS 握手（完整校验，从不关闭）、一次 HTTP/1.1 请求，以及把各种失败归到固定的类别里。
//
// 这里的每个函数只做一步、只用一条连接，返回值说明这一步成功与否和失败类别。怎样把这些步骤排成一次探访，
// 由 probe 包决定。
package wire

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Step 是一个阶段的结果。
type Step struct {
	OK     bool   `json:"ok"`
	Ms     int64  `json:"ms"`
	Class  string `json:"class,omitempty"`  // 失败类别
	Code   int    `json:"code,omitempty"`   // 协议给出的代码：SOCKS 应答码或 HTTP 状态码
	Detail string `json:"detail,omitempty"` // 错误文本或补充说明
	Banner string `json:"banner,omitempty"` // 对端没按协议回答时，它发来的前几十个字节（十六进制）
	Sniff  string `json:"sniff,omitempty"`  // 根据这些字节猜它实际是什么服务
}

func ms(t0 time.Time) int64 { return time.Since(t0).Milliseconds() }

// NetClass 把网络错误归类。
func NetClass(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNABORTED):
		return "reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTDOWN), errors.Is(err, syscall.ENETDOWN):
		return "unreach"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return "other"
}

func short(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// Dial 建立 TCP 连接。
func Dial(ctx context.Context, addr string, timeout time.Duration, local net.Addr) (net.Conn, Step) {
	t0 := time.Now()
	d := net.Dialer{Timeout: timeout, LocalAddr: local, KeepAlive: -1}
	c, err := d.DialContext(ctx, "tcp4", addr)
	st := Step{Ms: ms(t0)}
	if err != nil {
		st.Class, st.Detail = "tcp_"+NetClass(err), short(err)
		return nil, st
	}
	st.OK = true
	return c, st
}

// Sniff 根据对端发来的前几个字节猜它是什么服务。
func Sniff(b []byte) string {
	s := string(b)
	switch {
	case len(b) == 0:
		return ""
	case strings.HasPrefix(s, "HTTP/"):
		return "http"
	case strings.HasPrefix(s, "SSH-"):
		return "ssh"
	case len(b) >= 2 && (b[0] == 0x16 || b[0] == 0x15) && b[1] == 0x03:
		return "tls"
	case strings.HasPrefix(s, "220 ") || strings.HasPrefix(s, "220-"):
		return "smtp_or_ftp"
	case strings.HasPrefix(s, "+OK"):
		return "pop3"
	case strings.HasPrefix(s, "* OK"):
		return "imap"
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "<!doctype") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "<html"):
		return "html"
	case b[0] == 0x05:
		return "socks5"
	case b[0] == 0x00 && len(b) >= 2 && b[1] >= 0x5a && b[1] <= 0x5d:
		return "socks4"
	}
	return "unknown"
}

func bannerOf(b []byte) (string, string) {
	if len(b) > 48 {
		b = b[:48]
	}
	return hex.EncodeToString(b), Sniff(b)
}

// more 在已经读到 got 的基础上，再等一小会儿多读一些字节，只为把 banner 记全。
func more(conn net.Conn, got []byte) []byte {
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	return append(append([]byte{}, got...), buf[:n]...)
}

func hsFail(st *Step, err error, got []byte) Step {
	st.Class, st.Detail = "hs_"+NetClass(err), short(err)
	if len(got) > 0 {
		st.Class = "hs_not_proto"
		st.Banner, st.Sniff = bannerOf(got)
	}
	return *st
}

// Socks5Auth 是 SOCKS5 的用户名密码（RFC 1929）。探测公开代理时不用；只在连本机旁路进程时用，用户名用来选节点。
type Socks5Auth struct{ User, Pass string }

// Socks5 在已建立的连接上做 SOCKS5 握手并请求连到 host:port。host 是域名时由代理解析。
//
// greet 是等待“方法选择”应答的时限。这一步不需要代理去连上游，一个来回就该有结果，所以可以比 timeout 短；
// HTTP 代理收到 SOCKS 的问候会一直等下去，短时限能省下大半等待。greet 为 0 时与 timeout 相同。
func Socks5(conn net.Conn, host string, port int, auth *Socks5Auth, greet, timeout time.Duration) Step {
	t0 := time.Now()
	if greet <= 0 || greet > timeout {
		greet = timeout
	}
	conn.SetDeadline(t0.Add(greet))
	defer conn.SetDeadline(time.Time{})
	st := Step{}
	fin := func(s Step) Step { s.Ms = ms(t0); return s }

	method := byte(0x00)
	if auth != nil {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		return fin(hsFail(&st, err, nil))
	}
	var r [2]byte
	if n, err := io.ReadFull(conn, r[:]); err != nil {
		return fin(hsFail(&st, err, r[:n]))
	}
	if r[0] != 0x05 {
		return fin(hsFail(&st, errors.New("not socks5"), more(conn, r[:])))
	}
	conn.SetDeadline(t0.Add(timeout))
	switch {
	case r[1] == 0xff:
		st.Class, st.Code, st.Detail = "hs_auth", 0xff, "no acceptable method"
		return fin(st)
	case r[1] != method:
		// 选了我们没提供的方法。常见的是只接受用户名密码的服务器回 0x02
		st.Class, st.Code = "hs_auth", int(r[1])
		if r[1] != 0x02 {
			st.Class = "hs_violation"
		}
		st.Detail = fmt.Sprintf("server chose method 0x%02x", r[1])
		return fin(st)
	}
	if auth != nil {
		req := append([]byte{0x01, byte(len(auth.User))}, auth.User...)
		req = append(append(req, byte(len(auth.Pass))), auth.Pass...)
		if _, err := conn.Write(req); err != nil {
			return fin(hsFail(&st, err, nil))
		}
		if n, err := io.ReadFull(conn, r[:]); err != nil {
			return fin(hsFail(&st, err, r[:n]))
		}
		if r[1] != 0x00 {
			st.Class, st.Code, st.Detail = "hs_auth", int(r[1]), "credentials rejected"
			return fin(st)
		}
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		a := ip.As4()
		req = append(append(req, 0x01), a[:]...)
	} else {
		if len(host) > 255 {
			st.Class, st.Detail = "hs_other", "host name too long"
			return fin(st)
		}
		req = append(append(req, 0x03, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fin(hsFail(&st, err, nil))
	}
	var h [4]byte
	if n, err := io.ReadFull(conn, h[:]); err != nil {
		return fin(hsFail(&st, err, h[:n]))
	}
	if h[0] != 0x05 {
		return fin(hsFail(&st, errors.New("bad reply version"), more(conn, h[:])))
	}
	if h[1] != 0x00 {
		st.Class, st.Code, st.Detail = "hs_refused", int(h[1]), socks5Rep(h[1])
		return fin(st)
	}
	var skip int
	switch h[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return fin(hsFail(&st, err, nil))
		}
		skip = int(l[0]) + 2
	default:
		return fin(hsFail(&st, errors.New("bad address type in reply"), h[:]))
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip)); err != nil {
		return fin(hsFail(&st, err, nil))
	}
	st.OK = true
	return fin(st)
}

func socks5Rep(c byte) string {
	names := []string{"ok", "general failure", "not allowed by ruleset", "network unreachable", "host unreachable",
		"connection refused", "ttl expired", "command not supported", "address type not supported"}
	if int(c) < len(names) {
		return names[c]
	}
	return "unassigned"
}

// Socks4 做 SOCKS4 握手。SOCKS4 只接受 IPv4 地址。
func Socks4(conn net.Conn, ip netip.Addr, port int, timeout time.Duration) Step {
	t0 := time.Now()
	conn.SetDeadline(t0.Add(timeout))
	defer conn.SetDeadline(time.Time{})
	st := Step{}
	fin := func(s Step) Step { s.Ms = ms(t0); return s }
	a := ip.As4()
	req := binary.BigEndian.AppendUint16([]byte{0x04, 0x01}, uint16(port))
	req = append(append(req, a[:]...), 0x00)
	if _, err := conn.Write(req); err != nil {
		return fin(hsFail(&st, err, nil))
	}
	var r [8]byte
	if n, err := io.ReadFull(conn, r[:]); err != nil {
		return fin(hsFail(&st, err, r[:n]))
	}
	// 规范要求应答的第一个字节是 0，有些实现回 4
	if (r[0] != 0x00 && r[0] != 0x04) || r[1] < 0x5a || r[1] > 0x5d {
		return fin(hsFail(&st, errors.New("not socks4"), more(conn, r[:])))
	}
	if r[1] != 0x5a {
		st.Class, st.Code, st.Detail = "hs_refused", int(r[1]), "request rejected"
		return fin(st)
	}
	st.OK = true
	return fin(st)
}

// BufConn 让握手阶段缓冲区里多读到的字节不丢。
type BufConn struct {
	net.Conn
	R *bufio.Reader
}

func (c *BufConn) Read(p []byte) (int, error) { return c.R.Read(p) }

// HTTPConnect 发 CONNECT 请求。成功后返回的连接要继续用（缓冲区里可能已经有隧道里的数据）。
func HTTPConnect(conn net.Conn, authority, ua string, timeout time.Duration) (Step, net.Conn) {
	t0 := time.Now()
	conn.SetDeadline(t0.Add(timeout))
	defer conn.SetDeadline(time.Time{})
	st := Step{}
	fin := func(s Step) Step { s.Ms = ms(t0); return s }
	req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nUser-Agent: " + ua +
		"\r\nProxy-Connection: keep-alive\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return fin(hsFail(&st, err, nil)), nil
	}
	br := bufio.NewReaderSize(conn, 8192)
	code, hdr, got, err := readHead(br)
	if err != nil {
		return fin(hsFail(&st, err, got)), nil
	}
	st.Code = code
	switch {
	case code >= 200 && code < 300:
		st.OK = true
		// 真正的 CONNECT 成功应答没有正文。带正文的多半是随便什么请求都回 200 的网站
		if hdr.Get("Content-Length") != "" && hdr.Get("Content-Length") != "0" || hdr.Get("Transfer-Encoding") != "" {
			st.Detail = "200_with_body"
		}
	case code == 407:
		st.Class, st.Detail = "hs_auth", hdr.Get("Proxy-Authenticate")
	default:
		st.Class = "hs_refused"
		st.Detail = strings.TrimSpace(hdr.Get("Server") + " " + hdr.Get("X-Squid-Error") + " " + hdr.Get("Proxy-Agent"))
	}
	if len(st.Detail) > 120 {
		st.Detail = st.Detail[:120]
	}
	return fin(st), &BufConn{Conn: conn, R: br}
}

// readHead 读一个 HTTP 响应头。返回状态码、头部；不是 HTTP 时返回已读到的字节。
func readHead(br *bufio.Reader) (int, http.Header, []byte, error) {
	var raw []byte
	line, err := readLine(br, &raw)
	if err != nil {
		return 0, nil, raw, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, nil, raw, errors.New("not http")
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 599 {
		return 0, nil, raw, errors.New("bad status code")
	}
	hdr := http.Header{}
	for i := 0; i < 100; i++ {
		line, err := readLine(br, &raw)
		if err != nil {
			return 0, nil, nil, err // 状态行是 HTTP，后面断了：按网络错误归类，不算“不是这个协议”
		}
		if line == "" {
			return code, hdr, nil, nil
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			hdr.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return 0, nil, nil, errors.New("too many header lines")
}

func readLine(br *bufio.Reader, raw *[]byte) (string, error) {
	b, err := br.ReadSlice('\n')
	if len(*raw) < 64 {
		*raw = append(*raw, b[:min(len(b), 64-len(*raw))]...)
	}
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", errors.New("line too long")
		}
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// ---------------------------------------------------------------- TLS

// TLSInfo 是一次 TLS 握手的结果。校验失败时也记下对端给出的证书，那是中间人的证据。
type TLSInfo struct {
	OK         bool   `json:"ok"`
	Ms         int64  `json:"ms"`
	Class      string `json:"class,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Version    string `json:"ver,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	Leaf       string `json:"leaf,omitempty"` // 叶子证书的 SHA-256
	Subject    string `json:"subj,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	SelfSigned bool   `json:"self,omitempty"`
	Banner     string `json:"banner,omitempty"`
	Sniff      string `json:"sniff,omitempty"`
}

type TLSOpts struct {
	ServerName string
	Roots      *x509.CertPool // nil = 系统根证书
	SPKIPin    string         // 非空时，校验通过后还要求叶子证书的公钥哈希等于它
	Timeout    time.Duration
}

var errPin = errors.New("certificate chain is valid but the public key is not the judge's")

// TLS 在连接上做 TLS 握手。证书校验始终开启；失败时握手中止，不会发出任何应用数据。
// 第三个返回值是对端证书链的 DER（仅在校验失败时），供留证。
func TLS(conn net.Conn, o TLSOpts) (*tls.Conn, TLSInfo, []byte) {
	t0 := time.Now()
	info := TLSInfo{}
	describe := func(leaf *x509.Certificate) {
		sum := sha256.Sum256(leaf.Raw)
		info.Leaf = hex.EncodeToString(sum[:])
		info.Subject, info.Issuer = trimStr(leaf.Subject.String(), 120), trimStr(leaf.Issuer.String(), 120)
		info.SelfSigned = bytes.Equal(leaf.RawSubject, leaf.RawIssuer)
	}
	cfg := &tls.Config{
		ServerName: o.ServerName,
		RootCAs:    o.Roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			// 只有标准校验通过后才会走到这里
			leaf := cs.PeerCertificates[0]
			describe(leaf)
			if o.SPKIPin != "" {
				sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				if hex.EncodeToString(sum[:]) != o.SPKIPin {
					return errPin
				}
			}
			return nil
		},
	}
	tc := tls.Client(conn, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	err := tc.HandshakeContext(ctx)
	info.Ms = ms(t0)
	if err == nil {
		cs := tc.ConnectionState()
		info.OK, info.Version, info.Cipher = true, tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite)
		return tc, info, nil
	}
	info.Detail = short(err)
	var chain []byte
	var cve *tls.CertificateVerificationError
	var rhe tls.RecordHeaderError
	switch {
	case errors.Is(err, errPin):
		info.Class = "tls_pin_mismatch"
	case errors.As(err, &cve):
		info.Class = "tls_cert_invalid"
		if len(cve.UnverifiedCertificates) > 0 {
			describe(cve.UnverifiedCertificates[0])
			for _, c := range cve.UnverifiedCertificates {
				chain = append(chain, c.Raw...)
			}
		}
		var ua x509.UnknownAuthorityError
		var he x509.HostnameError
		var ie x509.CertificateInvalidError
		switch {
		case errors.As(err, &ua):
			info.Detail = "unknown_authority"
		case errors.As(err, &he):
			info.Detail = "hostname_mismatch"
		case errors.As(err, &ie):
			info.Detail = "invalid_" + strconv.Itoa(int(ie.Reason))
		}
	case errors.As(err, &rhe):
		info.Class = "tls_not_tls"
		info.Banner, info.Sniff = bannerOf(rhe.RecordHeader[:])
	case strings.Contains(err.Error(), "remote error: tls:"):
		info.Class = "tls_alert"
	default:
		info.Class = "tls_" + NetClass(err)
	}
	return nil, info, chain
}

func trimStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- HTTP

// UA 是探测请求用的 User-Agent。注入广告的代理往往只对浏览器下手，所以用浏览器的写法。
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// GetSpec 描述一次 GET 请求。
type GetSpec struct {
	Absolute  bool   // 请求行写绝对 URI，发给 HTTP 代理时用
	Authority string // host[:port]
	Path      string
	Canary    string // 非空时放进 X-Probe-Canary 头和 Cookie
	Timeout   time.Duration
	MaxBody   int
}

// Resp 是读到的响应。
type Resp struct {
	Status  int
	Header  http.Header
	Body    []byte
	Partial bool // 正文没读完连接就断了，或超过了上限
}

// BuildRequest 返回请求的原始字节。写成一个独立函数，是为了让“探测器到底发了什么”可以被测试和审阅。
func BuildRequest(s GetSpec) []byte {
	var b strings.Builder
	target := s.Path
	if s.Absolute {
		target = "http://" + s.Authority + s.Path
	}
	b.WriteString("GET " + target + " HTTP/1.1\r\n")
	b.WriteString("Host: " + s.Authority + "\r\n")
	b.WriteString("User-Agent: " + UA + "\r\n")
	b.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
	b.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	b.WriteString("Accept-Encoding: identity\r\n")
	if s.Canary != "" {
		b.WriteString("Cookie: pc=" + s.Canary + "\r\n")
		b.WriteString("X-Probe-Canary: " + s.Canary + "\r\n")
	}
	b.WriteString("Connection: close\r\n")
	if s.Absolute {
		b.WriteString("Proxy-Connection: close\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// Get 在连接上发一次 GET 并读完响应。
func Get(conn net.Conn, s GetSpec) (*Resp, Step) {
	t0 := time.Now()
	conn.SetDeadline(t0.Add(s.Timeout))
	defer conn.SetDeadline(time.Time{})
	st := Step{}
	fin := func() Step { st.Ms = ms(t0); return st }
	if _, err := conn.Write(BuildRequest(s)); err != nil {
		st.Class, st.Detail = "http_"+NetClass(err), short(err)
		return nil, fin()
	}
	br := bufio.NewReaderSize(conn, 16<<10)
	first, err := br.Peek(5)
	if err != nil {
		st.Class, st.Detail = "http_"+NetClass(err), short(err)
		if len(first) > 0 {
			st.Class = "http_malformed"
			st.Banner, st.Sniff = bannerOf(first)
		}
		return nil, fin()
	}
	if string(first) != "HTTP/" {
		got, _ := br.Peek(min(48, br.Buffered()))
		st.Class = "http_malformed"
		st.Banner, st.Sniff = bannerOf(got)
		return nil, fin()
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		st.Class, st.Detail = "http_malformed", short(err)
		if c := NetClass(err); c == "timeout" || c == "reset" || c == "eof" {
			st.Class = "http_" + c
		}
		return nil, fin()
	}
	defer resp.Body.Close()
	max := s.MaxBody
	if max <= 0 {
		max = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	r := &Resp{Status: resp.StatusCode, Header: resp.Header, Body: body}
	st.Code = resp.StatusCode
	if len(body) > max {
		r.Body, r.Partial = body[:max], true
	}
	if err != nil {
		// 头已经读到了，正文中途出错：把读到的部分交回去，由调用方按内容不符处理
		r.Partial = true
		st.Detail = "body: " + NetClass(err)
	}
	st.OK = true
	return r, fin()
}

// CommonAffix 返回 got 和 want 的公共前缀、公共后缀长度。
// 注入通常保留原文的头尾；截断只保留前缀；整页替换两者都很短。
func CommonAffix(got, want []byte) (pre, suf int) {
	n := min(len(got), len(want))
	for pre < n && got[pre] == want[pre] {
		pre++
	}
	for suf < n-pre && got[len(got)-1-suf] == want[len(want)-1-suf] {
		suf++
	}
	return pre, suf
}

// LineSimilarity 返回 want 的非空行里有百分之多少原样出现在 got 里。
// 注入脚本、替换广告 ID、把 https 改成 http 这类改动只动少数几行，相似度很高；
// 错误页、门户页这类整页替换几乎为零。
func LineSimilarity(got, want []byte) int {
	have := map[string]struct{}{}
	for _, l := range bytes.Split(got, []byte("\n")) {
		have[string(bytes.TrimSpace(l))] = struct{}{}
	}
	total, hit := 0, 0
	for _, l := range bytes.Split(want, []byte("\n")) {
		t := bytes.TrimSpace(l)
		if len(t) == 0 {
			continue
		}
		total++
		if _, ok := have[string(t)]; ok {
			hit++
		}
	}
	if total == 0 {
		return 0
	}
	return 100 * hit / total
}

// SHA256Hex 返回十六进制的 SHA-256。
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
