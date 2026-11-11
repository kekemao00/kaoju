package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// finDrainWait 是 fin 关闭时等对方把话说完的最长时间（PROTOCOL.md：最多 1 秒）。
const finDrainWait = time.Second

// 对端先关闭的方式。
const (
	peerNone int32 = iota
	peerFIN        // 读到 EOF
	peerRST        // 读写时遇到 ECONNRESET / EPIPE
)

// longAgo 是一个早已过去的时刻，用来把阻塞在读写里的协程立刻踢出来。
var longAgo = time.Unix(1, 0)

// tunnelState 记录一条连接上隧道开始时两个方向已有的字节数，关闭时据此算出隧道内的字节数。
type tunnelState struct {
	id       int64
	startIn  int64
	startOut int64
}

// cconn 是一条被接受的 TCP 连接（代理端口上的，或源站端口上的直连）。
//
// 它是这个套接字唯一的主人：所有读写都经过它，所以“从客户端读到的全部字节”和“写给客户端的全部字节”
// 可以在这里各记一份字节数和 SHA-256。隧道里的字节（TLS 记录、源站的响应）同样经过这里，自然算在内。
// 抓包核对（pcap_check.py）拿 conn_end 里的这四个数与包里重建出来的字节流比。
type cconn struct {
	srv      *Server
	id       int64
	listener string // proxy、origin_http、origin_https
	tcp      *net.TCPConn
	peerPort int
	born     time.Time

	// rmu 在“读系统调用 + 记账”期间一直持有：两个协程先后读到的数据，记进哈希的顺序必须与字节流的顺序一致。
	rmu     sync.Mutex
	hin     hash.Hash
	nin     int64
	drained int64 // 其中有多少是代理发起关闭之后、在 fin 的等待期里读到的

	wmu  sync.Mutex
	hout hash.Hash
	nout int64

	// dmu 保护“进入关闭状态”和“设置截止时间”这两件事的先后：
	// 一旦开始关闭，别人就不能再把截止时间改回去，否则被踢出来的读写会重新阻塞。
	dmu     sync.Mutex
	closing atomic.Bool

	peer       atomic.Int32 // 对端是否先关了，怎么关的
	lastActive atomic.Int64 // 最近一次读到或写出字节的时刻（UnixNano），隧道空闲计时用

	tmu sync.Mutex
	tun *tunnelState

	// pending 是“连接结束之前必须写出”的事件，见 beforeEnd。
	pmu     sync.Mutex
	pending []*pendingEvent

	// emu 保证 conn_end 是这条连接的最后一个事件；万一有事件在它之后才写（处理协程与关闭赛跑），
	// 那个事件会带上 late: true。
	emu   sync.Mutex
	ended bool

	once sync.Once
	done chan struct{} // 关闭完成、conn_end 写出之后关闭
}

func newCConn(s *Server, id int64, listener string, tcp *net.TCPConn) *cconn {
	c := &cconn{
		srv:      s,
		id:       id,
		listener: listener,
		tcp:      tcp,
		born:     time.Now(),
		hin:      sha256.New(),
		hout:     sha256.New(),
		done:     make(chan struct{}),
	}
	if a, ok := tcp.RemoteAddr().(*net.TCPAddr); ok {
		c.peerPort = a.Port
	}
	c.lastActive.Store(time.Now().UnixNano())
	return c
}

// Read 从客户端读，并把读到的字节记进入方向的计数和哈希。
func (c *cconn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.tcp.Read(p)
	if n > 0 {
		c.hin.Write(p[:n])
		c.nin += int64(n)
		c.lastActive.Store(time.Now().UnixNano())
	}
	if err != nil {
		c.notePeer(err)
	}
	return n, err
}

// Write 写给客户端，并把实际写出的字节记进出方向的计数和哈希。
func (c *cconn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.tcp.Write(p)
	if n > 0 {
		c.hout.Write(p[:n])
		c.nout += int64(n)
		c.lastActive.Store(time.Now().UnixNano())
	}
	if err != nil {
		c.notePeer(err)
	}
	return n, err
}

// notePeer 记下“对端先关了”。只在代理自己还没开始关的时候才算数。
func (c *cconn) notePeer(err error) {
	if c.closing.Load() {
		return
	}
	switch {
	case err == io.EOF:
		c.peer.CompareAndSwap(peerNone, peerFIN)
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		c.peer.CompareAndSwap(peerNone, peerRST)
	}
}

func (c *cconn) isClosing() bool { return c.closing.Load() }

// emit 写一个属于这条连接的事件；conn 字段自动加在最前面。
func (c *cconn) emit(ev string, fields ...kv) {
	c.emu.Lock()
	defer c.emu.Unlock()
	c.emitLocked(ev, fields...)
}

// pendingEvent 是一个已经登记、还没写出的事件。
type pendingEvent struct {
	once sync.Once
	fn   func()
}

// beforeEnd 登记一个必须在 conn_end 之前写出的事件，返回“现在就写”的函数。
// 正常情况下登记者在事件的内容备齐以后自己调用它；如果连接先一步被关掉（空闲超时、仪器退出），
// shutdown 会在写 conn_end 之前代为调用，写出当时已有的内容。不管谁调用，fn 只执行一次。
func (c *cconn) beforeEnd(fn func()) (run func()) {
	p := &pendingEvent{fn: fn}
	c.pmu.Lock()
	c.pending = append(c.pending, p)
	c.pmu.Unlock()
	return func() { p.once.Do(p.fn) }
}

func (c *cconn) emitLocked(ev string, fields ...kv) {
	all := make([]kv, 0, len(fields)+2)
	all = append(all, kv{"conn", c.id})
	all = append(all, fields...)
	if c.ended {
		all = append(all, kv{"late", true})
	}
	c.srv.log.emit(ev, all...)
}

func (c *cconn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.closing.Load() {
		return net.ErrClosed
	}
	return c.tcp.SetDeadline(t)
}

func (c *cconn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.closing.Load() {
		return net.ErrClosed
	}
	return c.tcp.SetReadDeadline(t)
}

func (c *cconn) SetWriteDeadline(t time.Time) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.closing.Load() {
		return net.ErrClosed
	}
	return c.tcp.SetWriteDeadline(t)
}

// counts 返回当前两个方向的字节数。
func (c *cconn) counts() (in, out int64) {
	c.rmu.Lock()
	in = c.nin
	c.rmu.Unlock()
	c.wmu.Lock()
	out = c.nout
	c.wmu.Unlock()
	return in, out
}

// beginTunnel 标记这条连接从现在起是隧道。early 是随握手一起到达、已经读进来但属于隧道的字节数。
func (c *cconn) beginTunnel(id int64, early int) {
	in, out := c.counts()
	c.tmu.Lock()
	c.tun = &tunnelState{id: id, startIn: in - int64(early), startOut: out}
	c.tmu.Unlock()
	c.lastActive.Store(time.Now().UnixNano())
}

// shutdown 关闭连接并写出 tunnel_close（如果有隧道）和 conn_end。只有第一次调用起作用，
// 其余的调用等它做完再返回。
//
// tunBy 只对隧道有意义：是代理按配置切断的（"proxy"）还是内置源站关的（"origin"）。
// how 是代理一方的关法：fin 或 rst。reason 写进 conn_end。
// 如果对端在此之前已经关了，by 记 client，close 记对端的关法，reason 改成 client_eof 或 client_reset。
func (c *cconn) shutdown(tunBy, how, reason string) {
	c.once.Do(func() {
		c.dmu.Lock()
		c.closing.Store(true)
		_ = c.tcp.SetDeadline(longAgo) // 把还阻塞在读写里的协程踢出来
		c.dmu.Unlock()

		// 对端是不是先关了：读写时已经见到 EOF 或复位的算；没见到的，再看一眼内核的接收队列。
		// 后一种情况很常见：隧道里的客户端先发 TLS 的 close_notify 再发 FIN，源站读到 close_notify
		// 就来关连接了，这时 FIN 已经到了内核，只是还没人去读。
		peer := c.peer.Load()
		if peer == peerNone {
			peer = c.probePeer()
		}

		by, closeKind := "proxy", how
		switch peer {
		case peerFIN:
			by, closeKind, reason = "client", "fin", "client_eof"
		case peerRST:
			by, closeKind, reason = "client", "rst", "client_reset"
		}

		switch {
		case how == "rst":
			// SO_LINGER 设成 0 再关：内核直接发 RST，不发 FIN。配置要求复位时，对端先关了也照做。
			_ = c.tcp.SetLinger(0)
			_ = c.tcp.Close()
		case by == "client":
			_ = c.tcp.Close()
		default:
			closeKind = "fin"
			c.finClose()
		}
		how = closeKind

		c.rmu.Lock()
		in, drained := c.nin, c.drained
		shaIn := hex.EncodeToString(c.hin.Sum(nil))
		c.rmu.Unlock()
		c.wmu.Lock()
		out := c.nout
		shaOut := hex.EncodeToString(c.hout.Sum(nil))
		c.wmu.Unlock()

		// 还没来得及写的事件（握手到一半的 origin_conn、等 ClientHello 到齐的 tunnel_first_bytes）先写出来。
		c.pmu.Lock()
		pend := c.pending
		c.pending = nil
		c.pmu.Unlock()
		for _, p := range pend {
			p.once.Do(p.fn)
		}

		c.tmu.Lock()
		tun := c.tun
		c.tmu.Unlock()
		c.emu.Lock()
		if tun != nil {
			tb := "proxy"
			switch {
			case by == "client":
				tb = "client"
			case tunBy == "origin":
				tb = "origin"
			}
			c.emitLocked("tunnel_close",
				kv{"tunnel", tun.id}, kv{"by", tb}, kv{"reason", reason},
				kv{"bytes_c2s", in - tun.startIn}, kv{"bytes_s2c", out - tun.startOut})
		}
		c.emitLocked("conn_end",
			kv{"listener", c.listener}, kv{"by", by}, kv{"close", how}, kv{"reason", reason},
			kv{"bytes_in", in}, kv{"bytes_out", out}, kv{"bytes_drained", drained},
			kv{"sha256_in", shaIn}, kv{"sha256_out", shaOut},
			kv{"dur_ms", float64(time.Since(c.born).Microseconds()) / 1000})
		c.ended = true
		c.emu.Unlock()
		c.srv.unregister(c)
		close(c.done)
	})
}

// accountDrained 把读到的字节记进入方向的计数和哈希。调用方必须持有 rmu。
// 只用于代理已经决定关闭之后读到的字节，所以同时记进 drained。
func (c *cconn) accountDrained(p []byte) {
	c.hin.Write(p)
	c.nin += int64(len(p))
	c.drained += int64(len(p))
}

// probePeer 在代理动手关闭之前，不阻塞地确认对端是不是已经先关了。
// 接收队列里还有没读的数据时，把它们读进来记账（它们确实是客户端发来的），再看后面是不是 FIN。
func (c *cconn) probePeer() int32 {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	buf := make([]byte, 32<<10)
	for i := 0; i < 64; i++ {
		switch peekSocket(c.tcp) {
		case peekEOF:
			return peerFIN
		case peekReset:
			return peerRST
		case peekData:
		default:
			return peerNone
		}
		_ = c.tcp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := c.tcp.Read(buf)
		if n > 0 {
			c.accountDrained(buf[:n])
		}
		switch {
		case err == io.EOF:
			return peerFIN
		case errors.Is(err, syscall.ECONNRESET):
			return peerRST
		case err != nil:
			return peerNone
		}
	}
	return peerNone
}

// finClose 是 fin 关法：先半关（发 FIN），把对方还在发的读掉（读到 EOF 或满 1 秒），再关。
// 不能带着没读的数据直接 Close：Linux 上那样会发 RST，对方可能连已经发给它的响应都收不到。
// 等待期里读到的字节照样记账。
func (c *cconn) finClose() {
	c.wmu.Lock()
	_ = c.tcp.CloseWrite()
	c.wmu.Unlock()

	c.rmu.Lock()
	_ = c.tcp.SetReadDeadline(time.Now().Add(finDrainWait))
	buf := make([]byte, 32<<10)
	for {
		n, err := c.tcp.Read(buf)
		if n > 0 {
			c.accountDrained(buf[:n])
		}
		if err != nil {
			break
		}
	}
	c.rmu.Unlock()
	_ = c.tcp.Close()
}
