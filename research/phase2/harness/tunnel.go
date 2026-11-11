package main

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// helloWait 是等一条 TLS 记录到齐的最长时间；methodWait 是等明文请求的方法名到齐的最长时间。
const (
	helloWait  = 2 * time.Second
	methodWait = 500 * time.Millisecond
)

// firstBytesWait 判断隧道的首批字节够不够归类：不够时返回还要等多久（从第一次读到算起），够了返回 0。
// 归类不应取决于 TCP 怎么分段，所以两种情况要接着读：
// 首字节是 0x16 而第一条 TLS 记录没到齐；到手的全是大写字母、不满 16 个、还没见到空格（可能是没到齐的方法名）。
func firstBytesWait(b []byte) time.Duration {
	if len(b) == 0 {
		return 0
	}
	if b[0] == 0x16 {
		need := 5
		if len(b) >= 5 {
			need = 5 + int(b[3])<<8 + int(b[4])
		}
		if len(b) < need {
			return helloWait
		}
		return 0
	}
	if len(b) >= 16 {
		return 0
	}
	for _, c := range b {
		if c < 'A' || c > 'Z' {
			return 0
		}
	}
	return methodWait
}

// startTunnel 在 CONNECT 回了 200（或 SOCKS5 回了成功）之后调用：记 tunnel_open，
// 把隧道里客户端发来的首批字节记下来（tunnel_first_bytes），然后把连接交给内置源站。
// early 是客户端没等应答就发来的、已经读进缓冲区的隧道数据。
func (s *Server) startTunnel(c *cconn, via string, reqSeq int, host string, port int, mapped string, early []byte) {
	tid := s.tunSeq.Add(1)
	c.beginTunnel(tid, len(early))
	var rs any
	if via == "connect" {
		rs = reqSeq
	}
	c.emit("tunnel_open",
		kv{"tunnel", tid}, kv{"via", via}, kv{"req_seq", rs},
		kv{"target_host", host}, kv{"target_port", port}, kv{"mapped", mapped})

	if idle := time.Duration(s.prof.Tunnel.IdleCloseMs) * time.Millisecond; idle > 0 {
		s.workWG.Add(1)
		go func() {
			defer s.workWG.Done()
			s.watchTunnelIdle(c, tid, idle)
		}()
	}

	first := early
	nFirst := len(early)
	if nFirst == 0 {
		buf := make([]byte, firstReadSize)
		n, _ := c.Read(buf)
		if n == 0 {
			// 隧道里一个字节都没来：对端关了，或者仪器按配置关了。不写 tunnel_first_bytes。
			c.shutdown("proxy", "fin", "io_error")
			return
		}
		first = buf[:n:n]
		nFirst = n
	}

	// tunnel_first_bytes 要等下面把 TLS 记录读齐以后才写。万一这期间连接被关（隧道空闲超时、仪器退出），
	// 由 shutdown 在 conn_end 之前把已有的部分写出来。
	var fmu sync.Mutex
	emitFirst := c.beforeEnd(func() {
		fmu.Lock()
		defer fmu.Unlock()
		kind, hello := classifyTunnelFirst(first)
		var tlsField any
		if hello != nil {
			tlsField = hello.fields()
		}
		c.emit("tunnel_first_bytes",
			kv{"tunnel", tid}, kv{"n_first_read", nFirst}, kv{"early_bytes", len(early)},
			kv{"n_buffered", len(first)}, kv{"hex", hexHead(first, 16)}, kv{"kind", kind}, kv{"tls", tlsField})
	})

	// 首批字节还不够归类时多读几次：TLS 记录等到第一条到齐（最多 2 秒，这样才能解析 ClientHello），
	// 明文的方法名等到出现空格（最多 500 毫秒）。多读到的字节同样原样交给源站；
	// 第一次读到多少照实记在 n_first_read 里。
	if firstBytesWait(first) > 0 {
		started := time.Now()
		tmp := make([]byte, 16<<10)
		for {
			wait := firstBytesWait(first)
			if wait == 0 {
				break
			}
			if c.SetReadDeadline(started.Add(wait)) != nil {
				break
			}
			n, err := c.Read(tmp)
			fmu.Lock()
			first = append(first, tmp[:n]...)
			fmu.Unlock()
			if err != nil {
				break
			}
		}
		_ = c.SetReadDeadline(time.Time{})
	}
	emitFirst()

	if c.isClosing() {
		return
	}
	s.handoff(c, first, mapped, "tunnel", tid)
}

// watchTunnelIdle 实现 tunnel.idle_close_ms：隧道两个方向都静默这么久就按 fin 关。
func (s *Server) watchTunnelIdle(c *cconn, tid int64, idle time.Duration) {
	for {
		wait := idle - time.Since(time.Unix(0, c.lastActive.Load()))
		if wait <= 0 {
			if c.isClosing() {
				return
			}
			c.emit("action",
				kv{"what", "tunnel_idle_close"}, kv{"how", "fin"},
				kv{"k", nil}, kv{"tunnel", tid}, kv{"oconn", nil})
			c.shutdown("proxy", "fin", "tunnel_idle")
			return
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-c.done:
			t.Stop()
			return
		}
	}
}

// originConn 是交给内置源站的连接：隧道，或者源站端口上的直连。
// 读的时候先把已经读进来的首批字节原样吐出去，再接着读底下的连接，所以源站看到的字节一个不少。
type originConn struct {
	c        *cconn
	id       int64
	via      string // tunnel、direct
	tunnel   int64  // 直连时为 0
	listener string // origin_http、origin_https

	mu  sync.Mutex
	pre []byte

	reqs atomic.Int64 // 这条源站连接上到过几个请求（h2 按流计数）
}

func (o *originConn) Read(p []byte) (int, error) {
	o.mu.Lock()
	if len(o.pre) > 0 {
		n := copy(p, o.pre)
		o.pre = o.pre[n:]
		o.mu.Unlock()
		return n, nil
	}
	o.mu.Unlock()
	return o.c.Read(p)
}

func (o *originConn) Write(p []byte) (int, error) { return o.c.Write(p) }

// Close 由内置源站（http.Server、tls.Conn）调用：按 fin 关最外层的 TCP 连接。
func (o *originConn) Close() error {
	o.c.shutdown("origin", "fin", "origin_close")
	return nil
}

func (o *originConn) LocalAddr() net.Addr                { return o.c.tcp.LocalAddr() }
func (o *originConn) RemoteAddr() net.Addr               { return o.c.tcp.RemoteAddr() }
func (o *originConn) SetDeadline(t time.Time) error      { return o.c.SetDeadline(t) }
func (o *originConn) SetReadDeadline(t time.Time) error  { return o.c.SetReadDeadline(t) }
func (o *originConn) SetWriteDeadline(t time.Time) error { return o.c.SetWriteDeadline(t) }

type originConnKey struct{}

// connContext 把 originConn 挂到请求的上下文里，处理函数据此知道请求来自哪条隧道。
func connContext(ctx context.Context, nc net.Conn) context.Context {
	if tc, ok := nc.(*tls.Conn); ok {
		nc = tc.NetConn()
	}
	if oc, ok := nc.(*originConn); ok {
		return context.WithValue(ctx, originConnKey{}, oc)
	}
	return ctx
}

// handoff 把连接交给内置源站，不经过额外的 TCP 连接。HTTPS 源站先在这里做 TLS 握手，
// 握手的结果（ALPN、版本、SNI，或失败原因）记进 origin_conn。
func (s *Server) handoff(c *cconn, pre []byte, listener, via string, tid int64) {
	oc := &originConn{c: c, id: s.oconnSeq.Add(1), via: via, tunnel: tid, listener: listener, pre: pre}
	var tunField any
	if via == "tunnel" {
		tunField = tid
	}
	emit := func(isTLS bool, alpn, ver, sni, errText any) {
		c.emit("origin_conn",
			kv{"oconn", oc.id}, kv{"via", via}, kv{"tunnel", tunField}, kv{"listener", listener},
			kv{"tls", isTLS}, kv{"alpn", alpn}, kv{"tls_version", ver}, kv{"sni", sni}, kv{"error", errText})
	}
	if listener != "origin_https" {
		emit(false, nil, nil, nil, nil)
		if !s.chHTTP.push(oc) {
			oc.Close()
		}
		return
	}
	// origin_conn 要等握手有了结果才写。握手到一半连接被关的话，由 shutdown 在 conn_end 之前写出来。
	var hmu sync.Mutex
	var alpn, ver, sni any
	var errText any = "握手完成之前连接已被关闭"
	emitConn := c.beforeEnd(func() {
		hmu.Lock()
		defer hmu.Unlock()
		emit(true, alpn, ver, sni, errText)
	})
	tc := tls.Server(oc, s.tlsCfg)
	err := tc.Handshake()
	hmu.Lock()
	if err != nil {
		errText = err.Error()
	} else {
		st := tc.ConnectionState()
		alpn, ver, sni, errText = st.NegotiatedProtocol, tls.VersionName(st.Version), st.ServerName, nil
	}
	hmu.Unlock()
	emitConn()
	if err != nil {
		c.shutdown("origin", "fin", "tls_handshake_failed")
		return
	}
	if !s.chHTTPS.push(tc) {
		oc.Close()
	}
}

// chanListener 是给 http.Server 用的 net.Listener：连接不是从套接字上接受来的，而是进程内递进来的。
type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
	addr net.Addr
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{ch: make(chan net.Conn), done: make(chan struct{}), addr: addr}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// push 把一条连接递给 http.Server。监听器已经关了就返回 false。
func (l *chanListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
