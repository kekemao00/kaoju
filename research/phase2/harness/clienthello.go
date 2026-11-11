package main

import (
	"unicode/utf8"
)

// helloInfo 是从隧道首批字节里解析出来的 TLS ClientHello。
type helloInfo struct {
	RecordLen     int      // 第一条 TLS 记录的长度（不含 5 个字节的记录头）
	Complete      bool     // 第一条记录是否完整到齐
	RecordVersion int      // 记录头里的版本
	LegacyVersion int      // ClientHello 里的 legacy_version
	HasSNI        bool     //
	SNI           string   //
	ALPN          []string // 没有 ALPN 扩展时为空
	Versions      []int    // supported_versions 扩展（含 GREASE 值）
	Groups        []int    // supported_groups 扩展（含 GREASE 值）
	KeyShares     []int    // key_share 扩展里各份额所属的组
	ParseError    string   // 解析到哪一步出了问题；空串表示完整解析
}

func (h *helloInfo) fields() obj {
	var sni any
	if h.HasSNI {
		sni = h.SNI
	}
	var perr any
	if h.ParseError != "" {
		perr = h.ParseError
	}
	return obj{
		{"record_len", h.RecordLen}, {"complete", h.Complete},
		{"record_version", h.RecordVersion}, {"legacy_version", h.LegacyVersion},
		{"sni", sni}, {"alpn", nonNilStrings(h.ALPN)},
		{"versions", nonNilInts(h.Versions)}, {"groups", nonNilInts(h.Groups)}, {"key_shares", nonNilInts(h.KeyShares)},
		{"parse_error", perr},
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilInts(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

// cursor 是带边界检查的读取位置。越界不崩溃，只把 ok 置假。
type cursor struct {
	b  []byte
	ok bool
}

func (c *cursor) u8() int {
	if !c.ok || len(c.b) < 1 {
		c.ok = false
		return 0
	}
	v := int(c.b[0])
	c.b = c.b[1:]
	return v
}

func (c *cursor) u16() int {
	if !c.ok || len(c.b) < 2 {
		c.ok = false
		return 0
	}
	v := int(c.b[0])<<8 | int(c.b[1])
	c.b = c.b[2:]
	return v
}

func (c *cursor) u24() int {
	if !c.ok || len(c.b) < 3 {
		c.ok = false
		return 0
	}
	v := int(c.b[0])<<16 | int(c.b[1])<<8 | int(c.b[2])
	c.b = c.b[3:]
	return v
}

func (c *cursor) take(n int) []byte {
	if !c.ok || n < 0 || len(c.b) < n {
		c.ok = false
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}

// classifyTunnelFirst 给隧道里的首批字节归类：tls_client_hello、http、other。
// 是 ClientHello 时同时返回解析结果。
func classifyTunnelFirst(b []byte) (string, *helloInfo) {
	if h := parseClientHello(b); h != nil {
		return "tls_client_hello", h
	}
	if looksLikeHTTP(b) {
		return "http", nil
	}
	return "other", nil
}

// looksLikeHTTP：开头是 1 到 15 个大写字母再跟一个空格（GET、POST、PRI 等方法名）。
func looksLikeHTTP(b []byte) bool {
	for i := 0; i < len(b) && i < 16; i++ {
		c := b[i]
		if c == ' ' {
			return i > 0
		}
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return false
}

// parseClientHello 解析以 TLS 记录开头的字节。不是“握手记录里的 ClientHello”时返回 nil。
// 能解析多少算多少；任何输入都不会让它崩溃。
func parseClientHello(b []byte) *helloInfo {
	// 记录头：类型 22（握手）、版本（主版本号 3）、长度；随后握手消息的类型必须是 1（ClientHello）。
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return nil
	}
	h := &helloInfo{
		RecordVersion: int(b[1])<<8 | int(b[2]),
		RecordLen:     int(b[3])<<8 | int(b[4]),
	}
	payload := b[5:]
	if len(payload) >= h.RecordLen {
		payload = payload[:h.RecordLen]
		h.Complete = true
	}
	c := &cursor{b: payload, ok: true}
	fail := func(where string) *helloInfo {
		h.ParseError = where
		return h
	}
	c.u8() // 握手类型，上面已经确认是 1
	msgLen := c.u24()
	if !c.ok {
		return fail("握手消息头不完整")
	}
	truncated := false
	if msgLen > len(c.b) {
		// 握手消息比这条记录长（跨了多条记录），或者记录没到齐：只解析手头有的部分。
		truncated = true
	} else {
		c.b = c.b[:msgLen]
	}
	h.LegacyVersion = c.u16()
	c.take(32)      // random
	c.take(c.u8())  // legacy_session_id
	c.take(c.u16()) // cipher_suites
	c.take(c.u8())  // legacy_compression_methods
	if !c.ok {
		return fail("ClientHello 的固定部分不完整")
	}
	if len(c.b) == 0 {
		if truncated {
			return fail("ClientHello 被截断")
		}
		return h // 没有扩展
	}
	extLen := c.u16()
	if !c.ok {
		return fail("扩展的总长度不完整")
	}
	if extLen < len(c.b) {
		c.b = c.b[:extLen]
	} else if extLen > len(c.b) {
		truncated = true
	}
	for len(c.b) > 0 {
		typ := c.u16()
		data := c.take(c.u16())
		if !c.ok {
			if truncated {
				return fail("ClientHello 被截断")
			}
			return fail("扩展不完整")
		}
		e := &cursor{b: data, ok: true}
		switch typ {
		case 0: // server_name
			list := &cursor{b: e.take(e.u16()), ok: e.ok}
			for list.ok && len(list.b) > 0 {
				nameType := list.u8()
				name := list.take(list.u16())
				if list.ok && nameType == 0 && !h.HasSNI {
					h.HasSNI = true
					h.SNI = toValidString(name)
				}
			}
		case 16: // application_layer_protocol_negotiation
			list := &cursor{b: e.take(e.u16()), ok: e.ok}
			for list.ok && len(list.b) > 0 {
				p := list.take(list.u8())
				if list.ok {
					h.ALPN = append(h.ALPN, toValidString(p))
				}
			}
		case 43: // supported_versions
			list := &cursor{b: e.take(e.u8()), ok: e.ok}
			for list.ok && len(list.b) >= 2 {
				h.Versions = append(h.Versions, list.u16())
			}
		case 10: // supported_groups
			list := &cursor{b: e.take(e.u16()), ok: e.ok}
			for list.ok && len(list.b) >= 2 {
				h.Groups = append(h.Groups, list.u16())
			}
		case 51: // key_share
			list := &cursor{b: e.take(e.u16()), ok: e.ok}
			for list.ok && len(list.b) >= 4 {
				g := list.u16()
				list.take(list.u16())
				if list.ok {
					h.KeyShares = append(h.KeyShares, g)
				}
			}
		}
	}
	if truncated {
		return fail("ClientHello 被截断")
	}
	return h
}

// toValidString 把字节变成字符串；不是合法 UTF-8 的字节换成 U+FFFD（JSON 里本来也只能这样表示）。
func toValidString(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return string([]rune(string(b)))
}
