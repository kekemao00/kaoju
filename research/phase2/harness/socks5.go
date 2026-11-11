package main

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
)

// SOCKS5 服务端，按 RFC 1928（协议本身）和 RFC 1929（用户名密码认证）实现。
// 只支持 CONNECT 命令；应答里的绑定地址固定写 0.0.0.0:0。

// socksOutcome 是一次握手的结果。
type socksOutcome struct {
	ok     bool
	host   string
	port   int
	mapped string
	reason string // 失败时写进 conn_end 的 reason
}

func intsOf(b []byte) []int {
	out := make([]int, len(b))
	for i, v := range b {
		out[i] = int(v)
	}
	return out
}

// socksNegotiate 在一条连接上走完 SOCKS5 的握手：方法协商、（需要时）用户名密码认证、请求和应答。
// 每一步都通过 emit 记事件。它只依赖读写接口，不碰套接字，所以可以直接拿来做模糊测试。
func socksNegotiate(br *bufio.Reader, w io.Writer, p *Profile, mapPort func(int) string, emit func(ev string, fields ...kv)) socksOutcome {
	fail := func(reason string) socksOutcome { return socksOutcome{reason: reason} }

	// 方法协商：VER NMETHODS METHODS
	var gh [2]byte
	if _, err := io.ReadFull(br, gh[:]); err != nil {
		return fail("io_error")
	}
	methods := make([]byte, int(gh[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return fail("io_error")
	}
	emit("socks5_greeting",
		kv{"version", int(gh[0])}, kv{"methods", intsOf(methods)},
		kv{"raw_hex", hex.EncodeToString(append(gh[:], methods...))})
	if gh[0] != 0x05 {
		return fail("socks_malformed")
	}

	has := func(m byte) bool {
		for _, v := range methods {
			if v == m {
				return true
			}
		}
		return false
	}
	sel := byte(0xff)
	switch p.Socks.Auth {
	case "none":
		if has(0x00) {
			sel = 0x00
		}
	case "userpass":
		if has(0x02) {
			sel = 0x02
		}
	}
	_, werr := w.Write([]byte{0x05, sel})
	emit("socks5_method", kv{"selected", int(sel)})
	if werr != nil {
		return fail("io_error")
	}
	if sel == 0xff {
		return fail("socks_no_method")
	}

	// 用户名密码认证：VER ULEN UNAME PLEN PASSWD，VER 必须是 1。
	if sel == 0x02 {
		var ah [2]byte
		if _, err := io.ReadFull(br, ah[:]); err != nil {
			return fail("io_error")
		}
		user := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(br, user); err != nil {
			return fail("io_error")
		}
		var pl [1]byte
		if _, err := io.ReadFull(br, pl[:]); err != nil {
			return fail("io_error")
		}
		pass := make([]byte, int(pl[0]))
		if _, err := io.ReadFull(br, pass); err != nil {
			return fail("io_error")
		}
		result := "bad"
		switch {
		case ah[0] != 0x01:
			result = "malformed"
		case p.credsOK(user, pass):
			result = "ok"
		}
		status := 0
		if result != "ok" {
			status = p.Socks.AuthFailStatus
		}
		_, werr := w.Write([]byte{0x01, byte(status)})
		emit("socks5_auth",
			kv{"version", int(ah[0])}, kv{"ulen", len(user)}, kv{"plen", len(pass)},
			kv{"user", strOrNil(user, true)}, kv{"user_hex", hex.EncodeToString(user)},
			kv{"pass", strOrNil(pass, true)}, kv{"pass_hex", hex.EncodeToString(pass)},
			kv{"status", status}, kv{"result", result})
		if werr != nil {
			return fail("io_error")
		}
		if result != "ok" {
			return fail("socks_auth_failed")
		}
	}

	// 请求：VER CMD RSV ATYP DST.ADDR DST.PORT
	var rh [4]byte
	if _, err := io.ReadFull(br, rh[:]); err != nil {
		return fail("io_error")
	}
	raw := append([]byte{}, rh[:]...)
	var host any
	var port any
	portNum := 0
	hostStr := ""
	atypOK := true
	var addr []byte
	switch rh[3] {
	case 0x01:
		addr = make([]byte, 4)
	case 0x04:
		addr = make([]byte, 16)
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return fail("io_error")
		}
		raw = append(raw, l[0])
		addr = make([]byte, int(l[0]))
	default:
		atypOK = false
	}
	if atypOK {
		if _, err := io.ReadFull(br, addr); err != nil {
			return fail("io_error")
		}
		var pb [2]byte
		if _, err := io.ReadFull(br, pb[:]); err != nil {
			return fail("io_error")
		}
		raw = append(append(raw, addr...), pb[:]...)
		portNum = int(pb[0])<<8 | int(pb[1])
		port = portNum
		if rh[3] == 0x03 {
			host = strOrNil(addr, true)
			hostStr = toValidString(addr)
		} else {
			hostStr = net.IP(addr).String()
			host = hostStr
		}
	}
	emit("socks5_request",
		kv{"version", int(rh[0])}, kv{"cmd", int(rh[1])}, kv{"rsv", int(rh[2])}, kv{"atyp", int(rh[3])},
		kv{"host", host}, kv{"port", port}, kv{"raw_hex", hex.EncodeToString(raw)})

	// 应答码。次序：格式问题在先，然后是配置要求的应答码（对每个请求都回），再是不支持的命令和对不上的端口。
	rep, cause, mapped := byte(0x00), "ok", ""
	switch {
	case rh[0] != 0x05:
		rep, cause = 0x01, "bad_version"
	case !atypOK:
		rep, cause = 0x08, "unsupported_atyp"
	case p.Socks.Rep != 0:
		rep, cause = byte(p.Socks.Rep), "profile_rep"
	case rh[1] != 0x01:
		rep, cause = 0x07, "unsupported_cmd"
	default:
		if mapped = mapPort(portNum); mapped == "" {
			rep, cause = 0x05, "unmapped_port"
		}
	}
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, werr = w.Write(reply)
	emit("socks5_reply", kv{"rep", int(rep)}, kv{"cause", cause}, kv{"raw_hex", hex.EncodeToString(reply)})
	if werr != nil {
		return fail("io_error")
	}
	if rep != 0x00 {
		return fail("socks_reply_failure")
	}
	return socksOutcome{ok: true, host: hostStr, port: portNum, mapped: mapped}
}

// serveSocks5 处理代理端口上首字节是 0x05 的连接。
func (s *Server) serveSocks5(c *cconn, br *bufio.Reader) {
	out := socksNegotiate(br, c, s.prof, s.mapPort, c.emit)
	if !out.ok {
		c.shutdown("proxy", "fin", out.reason)
		return
	}
	var early []byte
	if n := br.Buffered(); n > 0 {
		early = make([]byte, n)
		_, _ = io.ReadFull(br, early)
	}
	s.startTunnel(c, "socks5", 0, out.host, out.port, out.mapped, early)
}
