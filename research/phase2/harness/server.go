package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// version 是 obsproxy 的版本；eventsVersion 是事件格式（EVENTS.md）的版本，字段有不兼容的改动时加一。
const (
	version       = "1.0.0"
	eventsVersion = 1
)

// firstReadSize 是每条连接第一次读用的缓冲区大小。要比任何客户端一次发来的首批数据都大，
// 这样 n_first_read 反映的是“第一次读到了多少”，不是缓冲区的大小。
const firstReadSize = 64 << 10

// Server 是整个仪器：一个代理端口，加明文、HTTPS 两个内置源站。
// 它从不向外拨号；隧道在进程内直接接到内置源站的 http.Server 上。
type Server struct {
	prof   *Profile
	log    *eventLog
	stderr io.Writer

	lnProxy, lnHTTP, lnHTTPS *net.TCPListener
	proxyPort                int
	httpPort                 int
	httpsPort                int
	maxSeconds               int

	tlsCfg   *tls.Config
	httpSrv  *http.Server
	httpsSrv *http.Server
	chHTTP   *chanListener
	chHTTPS  *chanListener

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	closing bool
	conns   map[int64]*cconn

	connSeq  atomic.Int64
	tunSeq   atomic.Int64
	oconnSeq atomic.Int64

	dropMu          sync.Mutex
	connDropUsed    int
	originDropUsed  int
	connectDropUsed int

	acceptWG sync.WaitGroup
	workWG   sync.WaitGroup
	shutOnce sync.Once
}

// NewServer 建好监听端口和内置源站，但还不开始接受连接。events 是事件的去处（JSONL）。
func NewServer(prof *Profile, caDir string, events io.Writer, stderr io.Writer) (*Server, error) {
	leaf, err := loadCAAndMakeLeaf(caDir)
	if err != nil {
		return nil, err
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	s := &Server{
		prof:   prof,
		log:    newEventLog(events),
		stderr: stderr,
		done:   make(chan struct{}),
		conns:  make(map[int64]*cconn),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())

	protos := []string{"h2", "http/1.1"}
	if !prof.Origin.H2 {
		protos = []string{"http/1.1"}
	}
	s.tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		NextProtos:   protos,
		MinVersion:   tls.VersionTLS12,
	}

	listen := func() (*net.TCPListener, int, error) {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return nil, 0, fmt.Errorf("监听 127.0.0.1 失败: %w", err)
		}
		return ln, ln.Addr().(*net.TCPAddr).Port, nil
	}
	if s.lnProxy, s.proxyPort, err = listen(); err != nil {
		return nil, err
	}
	if s.lnHTTP, s.httpPort, err = listen(); err != nil {
		s.lnProxy.Close()
		return nil, err
	}
	if s.lnHTTPS, s.httpsPort, err = listen(); err != nil {
		s.lnProxy.Close()
		s.lnHTTP.Close()
		return nil, err
	}

	errLog := log.New(stderr, "obsproxy 源站: ", 0)
	s.chHTTP = newChanListener(s.lnHTTP.Addr())
	s.chHTTPS = newChanListener(s.lnHTTPS.Addr())
	s.httpSrv = &http.Server{
		Handler:     http.HandlerFunc(s.originHTTP),
		ConnContext: connContext,
		ErrorLog:    errLog,
	}
	s.httpsSrv = &http.Server{
		Handler:     http.HandlerFunc(s.originHTTP),
		ConnContext: connContext,
		ErrorLog:    errLog,
	}
	if !prof.Origin.H2 {
		// 非 nil 的空表：明确不启用 h2（TLS 配置里也没有提供 h2 这个 ALPN）。
		s.httpsSrv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	return s, nil
}

// Ports 返回三个监听端口。
func (s *Server) Ports() (proxy, originHTTP, originHTTPS int) {
	return s.proxyPort, s.httpPort, s.httpsPort
}

// Start 写出 start 事件并开始接受连接。
func (s *Server) Start() {
	s.log.emit("start",
		kv{"version", version}, kv{"events_version", eventsVersion},
		kv{"go", runtime.Version()}, kv{"pid", os.Getpid()},
		kv{"started_at", s.log.start.UTC().Format(time.RFC3339Nano)},
		kv{"proxy_port", s.proxyPort}, kv{"origin_http_port", s.httpPort}, kv{"origin_https_port", s.httpsPort},
		kv{"max_seconds", s.maxSeconds},
		kv{"profile", s.prof})

	s.workWG.Add(2)
	go func() { defer s.workWG.Done(); _ = s.httpSrv.Serve(s.chHTTP) }()
	go func() { defer s.workWG.Done(); _ = s.httpsSrv.Serve(s.chHTTPS) }()

	s.acceptWG.Add(3)
	go s.acceptLoop(s.lnProxy, "proxy")
	go s.acceptLoop(s.lnHTTP, "origin_http")
	go s.acceptLoop(s.lnHTTPS, "origin_https")
}

func (s *Server) acceptLoop(ln *net.TCPListener, name string) {
	defer s.acceptWG.Done()
	for {
		tc, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-s.done:
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		c, late := s.register(tc, name)
		if late {
			// 正在退出时才接进来的连接：照样记 accept 和 conn_end，然后关掉。
			c.shutdown("proxy", "fin", "shutdown")
			continue
		}
		s.workWG.Add(1)
		go func() {
			defer s.workWG.Done()
			if name == "proxy" {
				s.serveProxy(c)
			} else {
				s.serveDirect(c, name)
			}
		}()
	}
}

// register 给连接编号、登记、写 accept 事件。late 为真表示仪器已经在退出。
func (s *Server) register(tc *net.TCPConn, listener string) (c *cconn, late bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c = newCConn(s, s.connSeq.Add(1), listener, tc)
	c.emit("accept", kv{"listener", listener}, kv{"peer_port", c.peerPort})
	if s.closing {
		return c, true
	}
	s.conns[c.id] = c
	return c, false
}

func (s *Server) unregister(c *cconn) {
	s.mu.Lock()
	delete(s.conns, c.id)
	s.mu.Unlock()
}

// classifyFirst 按代理端口上的第一个字节归类。
func classifyFirst(b byte) string {
	switch {
	case b == 0x05:
		return "socks5"
	case b == 0x04:
		return "socks4"
	case b == 0x16:
		return "tls"
	case (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'):
		return "http"
	}
	return "other"
}

func hexHead(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}

// firstRead 做连接上的第一次读并写 first_bytes。一个字节都没读到（对端直接关了，或仪器在退出）时
// 不写 first_bytes，ok 为假。
func (s *Server) firstRead(c *cconn) (first []byte, kind string, ok bool) {
	buf := make([]byte, firstReadSize)
	n, _ := c.Read(buf)
	if n == 0 {
		return nil, "", false
	}
	first = buf[:n]
	kind = classifyFirst(first[0])
	c.emit("first_bytes",
		kv{"listener", c.listener}, kv{"n_first_read", n},
		kv{"hex", hexHead(first, 16)}, kv{"kind", kind})
	return first, kind, true
}

// serveProxy 处理代理端口上的一条连接：按首字节分流。
func (s *Server) serveProxy(c *cconn) {
	first, kind, ok := s.firstRead(c)
	if !ok {
		c.shutdown("proxy", "fin", "io_error")
		return
	}
	switch kind {
	case "socks4":
		c.shutdown("proxy", "fin", "socks4_unsupported")
		return
	case "tls":
		c.shutdown("proxy", "fin", "tls_on_proxy_port")
		return
	}
	// 之后的解析都经过这个带缓冲的读取器；第一次读到的字节先放回去。
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(first), c), maxHeadBytes+4096)
	if kind == "socks5" {
		s.serveSocks5(c, br)
		return
	}
	s.serveHTTP(c, br)
}

// serveDirect 处理直接连到源站端口上的连接（客户端绕过了代理）。
func (s *Server) serveDirect(c *cconn, listener string) {
	first, _, ok := s.firstRead(c)
	if !ok {
		c.shutdown("proxy", "fin", "io_error")
		return
	}
	s.handoff(c, first, listener, "direct", 0)
}

// mapPort 把目标端口对到内置源站上。主机名不解析、不限制；对不上的端口返回空串（按“连不上”处理）。
func (s *Server) mapPort(port int) string {
	switch {
	case port == 80 || port == s.httpPort:
		return "origin_http"
	case port == 443 || port == s.httpsPort:
		return "origin_https"
	}
	return ""
}

// takeDrop 判断一条丢弃规则这一次是否生效，生效就消耗一次。
func (s *Server) takeDrop(spec *DropSpec, used *int, k string, reused bool) bool {
	if spec == nil {
		return false
	}
	if spec.K != "" && spec.K != k {
		return false
	}
	if spec.OnlyIfReused && !reused {
		return false
	}
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	if *used >= spec.Times {
		return false
	}
	*used++
	return true
}

// sleep 睡一段时间；仪器退出时提前醒来并返回 false（调用方这时不应再回应）。
func (s *Server) sleep(d time.Duration) bool {
	if d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-s.done:
			return false
		}
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// Shutdown 关闭所有连接，为还开着的连接补写 conn_end，最后写 end 事件。可以重复调用。
func (s *Server) Shutdown(reason string) {
	s.shutOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		open := make([]*cconn, 0, len(s.conns))
		for _, c := range s.conns {
			open = append(open, c)
		}
		s.mu.Unlock()
		close(s.done)
		s.cancel()

		s.lnProxy.Close()
		s.lnHTTP.Close()
		s.lnHTTPS.Close()
		s.acceptWG.Wait()

		var wg sync.WaitGroup
		for _, c := range open {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.shutdown("proxy", "fin", "shutdown")
			}()
		}
		wg.Wait()

		s.chHTTP.Close()
		s.chHTTPS.Close()
		s.httpSrv.Close()
		s.httpsSrv.Close()

		// 等各条连接上的处理协程收尾；它们都已经没有连接可用，最多等 3 秒，绝不因此退不出去。
		finished := make(chan struct{})
		go func() { s.workWG.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
		}

		s.log.finish("end",
			kv{"reason", reason}, kv{"version", version},
			kv{"proxy_port", s.proxyPort}, kv{"origin_http_port", s.httpPort}, kv{"origin_https_port", s.httpsPort},
			kv{"conns", s.connSeq.Load()}, kv{"tunnels", s.tunSeq.Load()}, kv{"oconns", s.oconnSeq.Load()})
	})
}
