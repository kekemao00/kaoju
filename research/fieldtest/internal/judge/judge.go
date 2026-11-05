// Package judge 是测量用的目标站点，也是独立的见证方。
//
// 探测器经由被测代理访问 judge；judge 把自己实际收到的东西记下来：对端地址、TLS 握手参数、
// 原始请求头字节、请求里的 nonce。分析时按 nonce 把“探测器以为发生了什么”和“judge 实际看到了什么”对起来。
package judge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/nonce"
	"fieldtest/internal/payload"
	"fieldtest/internal/rec"
)

// Rec 是 judge 日志里的一条记录。
type Rec struct {
	TS      string      `json:"ts"`
	K       string      `json:"k"` // req：带有效 nonce 的请求；noise：其他请求；tls_fail：握手失败；noise_dropped、req_dropped：限速丢弃计数
	Remote  string      `json:"remote,omitempty"`
	RPort   int         `json:"rport,omitempty"`
	TLS     bool        `json:"tls,omitempty"`
	TLSVer  string      `json:"tls_ver,omitempty"`
	Cipher  string      `json:"cipher,omitempty"`
	SNI     string      `json:"sni,omitempty"`
	ALPN    string      `json:"alpn,omitempty"`
	HelloFP string      `json:"hello_fp,omitempty"`
	Method  string      `json:"method,omitempty"`
	Target  string      `json:"target,omitempty"` // 请求行里的原始 request-target
	Proto   string      `json:"proto,omitempty"`
	Host    string      `json:"host,omitempty"`
	Nonce   string      `json:"nonce,omitempty"`
	AgeS    int64       `json:"age_s,omitempty"`      // 收到请求时 nonce 已签发多少秒
	Kind    string      `json:"kind,omitempty"`       // 载荷种类
	Canary  string      `json:"req_canary,omitempty"` // ok / missing / bad
	Headers [][2]string `json:"headers,omitempty"`
	RawHead string      `json:"raw_head,omitempty"` // 这条连接上读到的原始字节（明文），base64，最多 2048 字节
	Status  int         `json:"status,omitempty"`
	Err     string      `json:"err,omitempty"`
	N       int64       `json:"n,omitempty"`
}

type helloInfo struct {
	sni string
	fp  string
}

type recConn struct {
	net.Conn
	mu    sync.Mutex
	buf   []byte
	tls   *tls.ConnectionState
	hello helloInfo
	once  sync.Once
	onEnd func()
}

const rawCap = 2048

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if room := rawCap - len(c.buf); room > 0 {
			c.buf = append(c.buf, p[:min(n, room)]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *recConn) take() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.buf
	c.buf = nil
	return b
}

func (c *recConn) Close() error {
	c.once.Do(func() {
		if c.onEnd != nil {
			c.onEnd()
		}
	})
	return c.Conn.Close()
}

type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

type connKey struct{}

type Server struct {
	cfg     *cfg.Config
	secret  []byte
	pl      *payload.Set
	log     *rec.Writer
	cert    tls.Certificate
	hello   sync.Map
	open    atomic.Int64
	maxOpen int64

	noiseMu      sync.Mutex
	noiseSec     int64
	noiseCount   int
	noiseDropped int64
	reqSec       int64
	reqCount     int
	reqDropped   int64

	lns  []net.Listener
	srvs []*http.Server
	done chan struct{}

	HTTPAddr, HTTPSAddr string
}

func New(c *cfg.Config, secret []byte, w *rec.Writer) (*Server, error) {
	cert, err := EnsureCert(c)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: c, secret: secret, pl: payload.Build(c.Judge.Host), log: w, cert: cert,
		maxOpen: 4096, done: make(chan struct{})}, nil
}

// Start 开始监听并在后台提供服务。
func (s *Server) Start() error {
	hl, err := net.Listen("tcp", s.cfg.Judge.HTTPListen)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", s.cfg.Judge.HTTPListen, err)
	}
	tl, err := net.Listen("tcp", s.cfg.Judge.HTTPSListen)
	if err != nil {
		hl.Close()
		return fmt.Errorf("监听 %s: %w", s.cfg.Judge.HTTPSListen, err)
	}
	s.HTTPAddr, s.HTTPSAddr = hl.Addr().String(), tl.Addr().String()
	s.lns = []net.Listener{hl, tl}

	plain := &chanListener{ch: make(chan net.Conn), addr: hl.Addr(), done: make(chan struct{})}
	secure := &chanListener{ch: make(chan net.Conn), addr: tl.Addr(), done: make(chan struct{})}
	go s.acceptPlain(hl, plain)
	go s.acceptTLS(tl, secure)

	for _, l := range []*chanListener{plain, secure} {
		srv := &http.Server{
			Handler:           http.HandlerFunc(s.handle),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       5 * time.Second,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          log.New(io.Discard, "", 0),
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connKey{}, c)
			},
		}
		s.srvs = append(s.srvs, srv)
		go srv.Serve(l)
	}
	go s.noiseReporter()
	return nil
}

func (s *Server) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	for _, l := range s.lns {
		l.Close()
	}
	for _, srv := range s.srvs {
		srv.Close()
	}
	s.log.Flush()
}

func (s *Server) admit(c net.Conn) bool {
	if s.open.Add(1) > s.maxOpen {
		s.open.Add(-1)
		c.Close()
		return false
	}
	return true
}

func (s *Server) acceptPlain(ln net.Listener, out *chanListener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			out.Close()
			return
		}
		if !s.admit(c) {
			continue
		}
		rc := &recConn{Conn: c, onEnd: func() { s.open.Add(-1) }}
		select {
		case out.ch <- rc:
		case <-out.done:
			rc.Close()
			return
		}
	}
}

func (s *Server) acceptTLS(ln net.Listener, out *chanListener) {
	tcfg := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			s.hello.Store(chi.Conn, helloInfo{sni: chi.ServerName, fp: helloFP(chi)})
			return nil, nil
		},
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			out.Close()
			return
		}
		if !s.admit(c) {
			continue
		}
		go func() {
			tc := tls.Server(c, tcfg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := tc.HandshakeContext(ctx)
			cancel()
			var hi helloInfo
			if v, ok := s.hello.LoadAndDelete(c); ok {
				hi = v.(helloInfo)
			}
			if err != nil {
				ip, port := splitAddr(c.RemoteAddr())
				s.noise(Rec{TS: rec.TS(time.Now()), K: "tls_fail", Remote: ip, RPort: port, TLS: true,
					SNI: hi.sni, HelloFP: hi.fp, Err: trim(err.Error(), 160)})
				c.Close()
				s.open.Add(-1)
				return
			}
			st := tc.ConnectionState()
			rc := &recConn{Conn: tc, tls: &st, hello: hi, onEnd: func() { s.open.Add(-1) }}
			select {
			case out.ch <- rc:
			case <-out.done:
				rc.Close()
			}
		}()
	}
}

// helloFP 给 ClientHello 取一个指纹。GREASE 值是随机的，先去掉。
// 探测器直连时的指纹是基线；经代理到达而指纹不同，说明 TLS 是代理自己发起的。
func helloFP(chi *tls.ClientHelloInfo) string {
	h := sha256.New()
	fmt.Fprintf(h, "v%v c%v g%v p%v s%v a%v x%v", noGrease(chi.SupportedVersions), noGrease(chi.CipherSuites),
		noGrease(chi.SupportedCurves), chi.SupportedPoints, noGrease(chi.SignatureSchemes), chi.SupportedProtos,
		noGrease(chi.Extensions))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func noGrease[T ~uint16](in []T) []T {
	out := make([]T, 0, len(in))
	for _, v := range in {
		if uint16(v)&0x0f0f == 0x0a0a && uint16(v)>>8 == uint16(v)&0xff {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	rc, _ := r.Context().Value(connKey{}).(*recConn)
	e := Rec{TS: rec.TS(now), Method: r.Method, Target: trim(r.RequestURI, 400), Proto: r.Proto, Host: trim(r.Host, 200)}
	e.Remote, e.RPort = splitAddr(remoteAddr(r, rc))
	var raw []byte
	if rc != nil {
		raw = rc.take()
		if rc.tls != nil {
			e.TLS = true
			e.TLSVer = tls.VersionName(rc.tls.Version)
			e.Cipher = tls.CipherSuiteName(rc.tls.CipherSuite)
			e.ALPN = rc.tls.NegotiatedProtocol
			e.SNI, e.HelloFP = rc.hello.sni, rc.hello.fp
		}
	}
	h := w.Header()
	h.Set("Connection", "close")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Judge-Remote", net.JoinHostPort(e.Remote, strconv.Itoa(e.RPort)))

	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/p/") && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		kind, n, _ := strings.Cut(path[3:], "/")
		issued, ok := nonce.Verify(s.secret, n)
		pl := s.pl.Get(payload.Kind(kind))
		if !ok || pl == nil {
			s.reply(w, &e, http.StatusNotFound, "text/plain; charset=utf-8", []byte("not found\n"), r.Method)
			s.noise(e)
			return
		}
		e.K, e.Nonce, e.Kind = "req", n, kind
		e.AgeS = int64(now.Sub(issued).Seconds())
		e.Canary = canaryState(r.Header.Get("X-Probe-Canary"), nonce.Canary(s.secret, "req", n))
		e.Headers = headerList(r.Header)
		e.RawHead = base64.StdEncoding.EncodeToString(raw)
		resp := nonce.Canary(s.secret, "resp", n)
		h.Set("X-Judge-Canary", resp)
		h.Set("Set-Cookie", "jc="+resp+"; Path=/; HttpOnly")
		if pl.Kind == payload.HTML {
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		}
		s.reply(w, &e, http.StatusOK, pl.ContentType, pl.Body, r.Method)
		s.logReq(e)
	case strings.HasPrefix(path, "/e/") && r.Method == http.MethodGet:
		// 回显：给第三阶段的真实客户端用，返回 judge 看到的对端地址和请求头
		n := path[3:]
		_, ok := nonce.Verify(s.secret, n)
		e.Headers = headerList(r.Header)
		body, _ := json.Marshal(map[string]any{"remote": e.Remote, "rport": e.RPort, "tls": e.TLS, "method": e.Method,
			"target": e.Target, "proto": e.Proto, "host": e.Host, "headers": e.Headers})
		s.reply(w, &e, http.StatusOK, "application/json", append(body, '\n'), r.Method)
		if ok {
			e.K, e.Nonce, e.Kind = "req", n, "e"
			e.RawHead = base64.StdEncoding.EncodeToString(raw)
			s.logReq(e)
		} else {
			s.noise(e)
		}
	case path == "/healthz":
		s.reply(w, &e, http.StatusOK, "text/plain; charset=utf-8", []byte("ok\n"), r.Method)
	case path == "/":
		s.reply(w, &e, http.StatusOK, "text/html; charset=utf-8", []byte(s.infoPage()), r.Method)
		s.noise(e)
	case path == "/robots.txt":
		s.reply(w, &e, http.StatusOK, "text/plain; charset=utf-8", []byte("User-agent: *\nDisallow: /\n"), r.Method)
		s.noise(e)
	case path == "/s/app.js":
		s.reply(w, &e, http.StatusOK, "application/javascript; charset=utf-8", []byte(payload.StaticJS()), r.Method)
		s.noise(e)
	case path == "/s/site.css":
		s.reply(w, &e, http.StatusOK, "text/css; charset=utf-8", []byte(payload.StaticCSS), r.Method)
		s.noise(e)
	case path == "/s/frame.html":
		s.reply(w, &e, http.StatusOK, "text/html; charset=utf-8", []byte(payload.StaticFrame), r.Method)
		s.noise(e)
	default:
		code := http.StatusNotFound
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			code = http.StatusMethodNotAllowed
		}
		s.reply(w, &e, code, "text/plain; charset=utf-8", []byte(http.StatusText(code)+"\n"), r.Method)
		s.noise(e)
	}
}

func (s *Server) reply(w http.ResponseWriter, e *Rec, code int, ctype string, body []byte, method string) {
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	if method != http.MethodHead {
		w.Write(body)
	}
	e.Status = code
}

// logReq 记录一个探测请求。正常情况下每秒只有十来个；有人拿有效的 nonce 大量重放时，每秒最多记 300 条，
// 超出的只计数，免得日志被撑爆。
func (s *Server) logReq(e Rec) {
	sec := time.Now().Unix()
	s.noiseMu.Lock()
	if sec != s.reqSec {
		s.reqSec, s.reqCount = sec, 0
	}
	s.reqCount++
	over := s.reqCount > 300
	if over {
		s.reqDropped++
	}
	s.noiseMu.Unlock()
	if !over {
		s.log.Write(e)
	}
}

// noise 记录与探测无关的流量，每秒最多 20 条；超出的只计数。
func (s *Server) noise(e Rec) {
	if e.K == "" {
		e.K = "noise"
	}
	sec := time.Now().Unix()
	s.noiseMu.Lock()
	if sec != s.noiseSec {
		s.noiseSec, s.noiseCount = sec, 0
	}
	s.noiseCount++
	over := s.noiseCount > 20
	if over {
		s.noiseDropped++
	}
	s.noiseMu.Unlock()
	if !over {
		s.log.Write(e)
	}
}

func (s *Server) noiseReporter() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.noiseMu.Lock()
			n, rq := s.noiseDropped, s.reqDropped
			s.noiseDropped, s.reqDropped = 0, 0
			s.noiseMu.Unlock()
			if n > 0 {
				s.log.Write(Rec{TS: rec.TS(time.Now()), K: "noise_dropped", N: n})
			}
			if rq > 0 {
				s.log.Write(Rec{TS: rec.TS(time.Now()), K: "req_dropped", N: rq})
			}
		}
	}
}

func (s *Server) infoPage() string {
	contact := s.cfg.Judge.Contact
	if contact == "" {
		contact = "the abuse contact of this network"
	}
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Measurement endpoint</title>
<meta name="robots" content="noindex"></head>
<body style="font-family:system-ui,sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem;line-height:1.6">
<h1>Measurement endpoint</h1>
<p>This host is part of a research project that measures the reliability and integrity of
<strong>publicly listed open proxies</strong>. It only answers test requests sent by our own prober.</p>
<ul>
<li>We contact only addresses that appear on public proxy lists. We do not scan the Internet.</li>
<li>We connect at a low rate and send nothing except requests to this host and to two public IP-echo services.</li>
<li>We never try credentials and never send traffic that belongs to anyone else.</li>
</ul>
<p>If your address is on such a list by mistake and you want it excluded from the measurement, contact:
<strong>` + html.EscapeString(contact) + `</strong>. Include the IP address; it will be removed from the probe set.</p>
</body></html>
`
}

func canaryState(got, want string) string {
	switch {
	case got == "":
		return "missing"
	case got == want:
		return "ok"
	default:
		return "bad"
	}
}

func headerList(h http.Header) [][2]string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([][2]string, 0, len(names))
	for _, k := range names {
		for _, v := range h[k] {
			if len(out) >= 60 {
				return out
			}
			out = append(out, [2]string{k, trim(v, 512)})
		}
	}
	return out
}

func remoteAddr(r *http.Request, rc *recConn) net.Addr {
	if rc != nil {
		return rc.RemoteAddr()
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	return nil
}

func splitAddr(a net.Addr) (string, int) {
	if t, ok := a.(*net.TCPAddr); ok {
		ip := t.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return ip.String(), t.Port
	}
	if a == nil {
		return "", 0
	}
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- 证书

// EnsureCert 返回 judge 的证书。配置了 cert_file 就用它；否则在数据目录里生成一张自签证书（首次）并复用。
func EnsureCert(c *cfg.Config) (tls.Certificate, error) {
	certPath, keyPath := c.Judge.CertFile, c.Judge.KeyFile
	if certPath == "" {
		certPath, keyPath = c.Path("judge-cert.pem"), c.Path("judge-key.pem")
		if !selfSignedUsable(c, certPath) {
			if err := generateSelfSigned(c, certPath, keyPath); err != nil {
				return tls.Certificate{}, err
			}
		}
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// selfSignedUsable 判断数据目录里已有的自签证书还能不能用：存在、是给当前主机名签的、离过期还有一个月以上。
// 配置里的主机名改了以后，旧证书就不能用了，要重新生成。
func selfSignedUsable(c *cfg.Config, certPath string) bool {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	return leaf.VerifyHostname(c.Judge.Host) == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour
}

func generateSelfSigned(c *cfg.Config, certPath, keyPath string) error {
	if err := os.MkdirAll(c.DataDir, 0o755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: c.Judge.Host, Organization: []string{"fieldtest judge"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range []string{c.Judge.Host, c.Judge.PublicIP} {
		if ip := net.ParseIP(name); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if name != "" {
			tpl.DNSNames = append(tpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Trust 描述探测器该如何校验 judge 的证书。
type Trust struct {
	Roots   *x509.CertPool // nil 表示用系统根证书
	SPKIPin string         // 叶子证书公钥的 SHA-256（十六进制）；校验通过后还要与它一致
	Self    bool           // judge 用的是自签证书
}

// LoadTrust 读 judge 的证书文件，得出探测器的校验方式。
// 自签证书：只信任这一张。公开证书：按系统根证书校验，并额外要求公钥与文件里的一致。
func LoadTrust(c *cfg.Config) (*Trust, error) {
	certPath := c.Judge.CertFile
	self := certPath == ""
	if self {
		certPath = c.Path("judge-cert.pem")
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("读 judge 证书: %w（judge 是否已经启动过？）", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s 里没有 PEM 证书", certPath)
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	t := &Trust{SPKIPin: hex.EncodeToString(sum[:]), Self: self}
	if self {
		t.Roots = x509.NewCertPool()
		t.Roots.AddCert(leaf)
	}
	return t, nil
}
