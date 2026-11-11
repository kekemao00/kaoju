//go:build unix

package main

import (
	"net"
	"syscall"
)

// 看一眼套接字的结果。
const (
	peekNothing = iota // 接收队列是空的，对端也没关
	peekData           // 有还没读的数据
	peekEOF            // 没有数据，对端的 FIN 已经到了
	peekReset          // 连接已被对端复位
)

// peekSocket 不阻塞、不消耗地看一眼接收队列（recv 加 MSG_PEEK|MSG_DONTWAIT）。
// 不经过 Go 的截止时间机制，所以连接已经被设了“早已过期”的截止时间时也能用。
func peekSocket(tcp *net.TCPConn) int {
	rc, err := tcp.SyscallConn()
	if err != nil {
		return peekNothing
	}
	var (
		n    int
		rerr error
		b    [1]byte
	)
	if err := rc.Control(func(fd uintptr) {
		for {
			n, _, rerr = syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
			if rerr != syscall.EINTR {
				return
			}
		}
	}); err != nil {
		return peekNothing
	}
	switch {
	case rerr == nil && n > 0:
		return peekData
	case rerr == nil:
		return peekEOF
	case rerr == syscall.ECONNRESET:
		return peekReset
	}
	return peekNothing
}
