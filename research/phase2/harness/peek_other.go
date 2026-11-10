//go:build !unix

package main

import "net"

const (
	peekNothing = iota
	peekData
	peekEOF
	peekReset
)

// peekSocket 在非 Unix 系统上不做探测：仪器只在 Linux 上用于测量，这里只为了能编译。
func peekSocket(*net.TCPConn) int { return peekNothing }
