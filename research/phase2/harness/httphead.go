package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxHeadBytes 是请求头（请求行、各个头、结尾的空行）的上限。
const maxHeadBytes = 64 << 10

var (
	errHeadTooLarge  = errors.New("请求头超过 64 KiB")
	errTooManyBlanks = errors.New("请求行之前的空行太多")
)

// reqHead 是解析后的请求头。Headers 保留原顺序、原大小写；值去掉了首尾的空格和制表符，
// 其余原样。一个字节都不差的原文在 Raw 里。
type reqHead struct {
	Method  string
	Target  string
	Version string
	Headers [][2]string
	Raw     []byte
}

// get 返回第一个同名（不分大小写）头的值。
func (h *reqHead) get(name string) (string, bool) {
	for _, kv := range h.Headers {
		if strings.EqualFold(kv[0], name) {
			return kv[1], true
		}
	}
	return "", false
}

// all 返回所有同名（不分大小写）头的值，按出现顺序。
func (h *reqHead) all(name string) []string {
	var out []string
	for _, kv := range h.Headers {
		if strings.EqualFold(kv[0], name) {
			out = append(out, kv[1])
		}
	}
	return out
}

// hasToken 判断某个头（可以出现多次，每次是逗号分隔的列表）里有没有某个记号，不分大小写。
func (h *reqHead) hasToken(name, token string) bool {
	for _, v := range h.all(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.Trim(t, " \t"), token) {
				return true
			}
		}
	}
	return false
}

// readHead 从连接上读出一个完整的请求头：从请求行到空行（含）。
// 请求行之前的空行跳过（RFC 9112 第 2.2 节），不算进返回的字节里。
// 出错时返回已经读到的部分。
func readHead(br *bufio.Reader, max int) ([]byte, error) {
	var raw []byte
	skipped := 0
	for {
		line, err := br.ReadSlice('\n')
		raw = append(raw, line...)
		if len(raw) > max || err == bufio.ErrBufferFull {
			return raw, errHeadTooLarge
		}
		if err != nil {
			return raw, err
		}
		if len(line) == 1 || (len(line) == 2 && line[0] == '\r') {
			if len(raw) == len(line) {
				// 请求行之前的空行。
				raw = raw[:0]
				skipped++
				if skipped > 8 {
					return raw, errTooManyBlanks
				}
				continue
			}
			return raw, nil
		}
	}
}

// isToken 判断是不是 RFC 9110 的 token（方法名、头的名字）。
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func validVersionSyntax(v string) bool {
	return len(v) == 8 && strings.HasPrefix(v, "HTTP/") &&
		v[5] >= '0' && v[5] <= '9' && v[6] == '.' && v[7] >= '0' && v[7] <= '9'
}

// parseHead 解析请求头。解析是宽容地记录、严格地判定：能认出来的部分都填进返回值，
// 不合规范的地方返回错误（调用方据此回 400）。任何输入都不会让它崩溃。
func parseHead(raw []byte) (*reqHead, error) {
	h := &reqHead{Raw: raw, Headers: [][2]string{}}
	lines := bytes.Split(raw, []byte("\n"))
	// 去掉结尾的空行（以及最后一个 \n 之后的空串）。
	for len(lines) > 0 {
		last := lines[len(lines)-1]
		if len(last) == 0 || (len(last) == 1 && last[0] == '\r') {
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	if len(lines) == 0 {
		return h, errors.New("没有请求行")
	}
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	rl := string(bytes.TrimSuffix(lines[0], []byte("\r")))
	parts := strings.Split(rl, " ")
	if len(parts) != 3 {
		// 规范要求用单个空格分隔；多个空格、制表符分隔的也认出来记下，但判为不合规范。
		parts = strings.Fields(rl)
		if len(parts) == 3 {
			note(errors.New("请求行不是用单个空格分隔的"))
		}
	}
	switch len(parts) {
	case 3:
		h.Method, h.Target, h.Version = parts[0], parts[1], parts[2]
	case 2:
		h.Method, h.Target = parts[0], parts[1]
		note(errors.New("请求行缺少版本"))
	case 1:
		h.Method = parts[0]
		note(errors.New("请求行缺少目标和版本"))
	default:
		note(errors.New("请求行格式不对"))
	}
	if firstErr == nil {
		switch {
		case !isToken(h.Method):
			note(errors.New("方法名不是合法的 token"))
		case h.Target == "":
			note(errors.New("请求目标为空"))
		case !validVersionSyntax(h.Version):
			note(errors.New("版本格式不对"))
		}
	}
	if strings.ContainsAny(rl, "\r\x00") {
		note(errors.New("请求行里有不允许的控制字符"))
	}

	for _, lb := range lines[1:] {
		line := string(bytes.TrimSuffix(lb, []byte("\r")))
		if line == "" {
			note(errors.New("头中间有空行"))
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			note(errors.New("头的折行（obs-fold）不接受"))
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			note(fmt.Errorf("头没有冒号或名字为空"))
			continue
		}
		name, value := line[:i], strings.Trim(line[i+1:], " \t")
		h.Headers = append(h.Headers, [2]string{name, value})
		if !isToken(name) {
			note(errors.New("头的名字不是合法的 token"))
		}
		for j := 0; j < len(value); j++ {
			if c := value[j]; (c < 0x20 && c != '\t') || c == 0x7f {
				note(errors.New("头的值里有不允许的控制字符"))
				break
			}
		}
	}
	return h, firstErr
}

// classifyForm 按方法和请求目标归类：absolute、connect、origin、other。
func classifyForm(method, target string) string {
	switch {
	case method == "CONNECT":
		return "connect"
	case strings.HasPrefix(target, "/"):
		return "origin"
	case hasScheme(target):
		return "absolute"
	}
	return "other"
}

// hasScheme 判断目标是不是以“scheme://”开头。
func hasScheme(target string) bool {
	i := strings.Index(target, "://")
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := target[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// targetQuery 取请求目标里问号之后、井号之前的部分。
func targetQuery(target string) string {
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target = target[:i]
	}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[i+1:]
	}
	return ""
}

// queryGet 从查询串里取第一个同名参数。解不开的百分号转义按原文返回。
func queryGet(rawQuery, key string) (string, bool) {
	if rawQuery == "" {
		return "", false
	}
	for _, part := range strings.Split(rawQuery, "&") {
		name, val, _ := strings.Cut(part, "=")
		if queryUnescape(name) == key {
			return queryUnescape(val), true
		}
	}
	return "", false
}

func queryUnescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// framing 是请求正文的分帧方式。
type framing struct {
	kind   string // none、content-length、chunked
	length int64
}

// bodyFraming 按 RFC 9112 第 6.3 节确定请求正文怎么分帧。
func bodyFraming(h *reqHead) (framing, error) {
	if tes := h.all("Transfer-Encoding"); len(tes) > 0 {
		if h.Version == "HTTP/1.0" {
			return framing{}, errors.New("HTTP/1.0 的请求带了 Transfer-Encoding")
		}
		var codings []string
		for _, v := range tes {
			for _, t := range strings.Split(v, ",") {
				if t = strings.Trim(t, " \t"); t != "" {
					codings = append(codings, strings.ToLower(t))
				}
			}
		}
		if len(codings) != 1 || codings[0] != "chunked" {
			return framing{}, errors.New("Transfer-Encoding 不是单独的 chunked")
		}
		return framing{kind: "chunked"}, nil
	}
	cls := h.all("Content-Length")
	if len(cls) == 0 {
		return framing{kind: "none"}, nil
	}
	var length int64 = -1
	for _, v := range cls {
		for _, t := range strings.Split(v, ",") {
			t = strings.Trim(t, " \t")
			if t == "" || len(t) > 18 {
				return framing{}, errors.New("Content-Length 不是合法的数字")
			}
			for i := 0; i < len(t); i++ {
				if t[i] < '0' || t[i] > '9' {
					return framing{}, errors.New("Content-Length 不是合法的数字")
				}
			}
			n, err := strconv.ParseInt(t, 10, 64)
			if err != nil {
				return framing{}, errors.New("Content-Length 不是合法的数字")
			}
			if length >= 0 && n != length {
				return framing{}, errors.New("多个 Content-Length 的值不一致")
			}
			length = n
		}
	}
	return framing{kind: "content-length", length: length}, nil
}

// errBadChunked 表示 chunked 正文的格式不对（区别于读到一半连接断了）。
type errBadChunked struct{ msg string }

func (e *errBadChunked) Error() string { return "chunked 格式不对: " + e.msg }

// readBody 把请求正文读完，写进 sink（通常是哈希），返回正文的字节数。
// chunked 的正文返回的是解开以后的长度。
func readBody(br *bufio.Reader, f framing, sink io.Writer) (int64, error) {
	switch f.kind {
	case "content-length":
		n, err := io.CopyN(sink, br, f.length)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n, err
	case "chunked":
		return readChunked(br, sink)
	}
	return 0, nil
}

// readCRLFLine 读一行，必须以 CRLF 结尾，返回不含 CRLF 的内容。
func readCRLFLine(br *bufio.Reader, max int) (string, error) {
	var line []byte
	for {
		part, err := br.ReadSlice('\n')
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			if len(line) > max {
				return "", &errBadChunked{"行太长"}
			}
			continue
		}
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return "", err
		}
		break
	}
	if len(line) > max {
		return "", &errBadChunked{"行太长"}
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", &errBadChunked{"行没有以 CRLF 结尾"}
	}
	return string(line[:len(line)-2]), nil
}

func readChunked(br *bufio.Reader, sink io.Writer) (int64, error) {
	var total int64
	for {
		line, err := readCRLFLine(br, 4096)
		if err != nil {
			return total, err
		}
		sizeStr, _, _ := strings.Cut(line, ";") // 块扩展不解释
		sizeStr = strings.TrimRight(sizeStr, " \t")
		if sizeStr == "" || len(sizeStr) > 15 {
			return total, &errBadChunked{"块长度不是合法的十六进制数"}
		}
		var size int64
		for i := 0; i < len(sizeStr); i++ {
			if !isHex(sizeStr[i]) {
				return total, &errBadChunked{"块长度不是合法的十六进制数"}
			}
			size = size<<4 | int64(unhex(sizeStr[i]))
		}
		if size == 0 {
			break
		}
		n, err := io.CopyN(sink, br, size)
		total += n
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return total, err
		}
		var crlf [2]byte
		if _, err := io.ReadFull(br, crlf[:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return total, err
		}
		if crlf != [2]byte{'\r', '\n'} {
			return total, &errBadChunked{"块数据后面不是 CRLF"}
		}
	}
	// 尾部的头（trailer），直到空行。
	for i := 0; ; i++ {
		line, err := readCRLFLine(br, 8192)
		if err != nil {
			return total, err
		}
		if line == "" {
			return total, nil
		}
		if i >= 64 || strings.IndexByte(line, ':') <= 0 {
			return total, &errBadChunked{"尾部的头格式不对"}
		}
	}
}

// authInfo 是对 Proxy-Authorization 的解析和判定。
type authInfo struct {
	Present bool
	Scheme  string
	Raw     string
	User    []byte
	Pass    []byte
	HasUser bool
	HasPass bool
	Lenient bool   // 严格的 base64 解不开，放宽以后（缺填充、URL 字母表）解开了；判定仍是 malformed
	Result  string // none、ok、bad、malformed
}

// parseProxyAuth 解析 Proxy-Authorization 的值（有多个时只看第一个）。
// 记录要宽容：方案名不分大小写，方案和凭据之间可以有多个空格。判定要严格：
// base64 必须是带填充的标准字母表，解开以后必须有冒号，否则是 malformed。
// 判定结果里的 ok、bad 由调用方按配置填。
func parseProxyAuth(values []string) authInfo {
	if len(values) == 0 {
		return authInfo{Result: "none"}
	}
	a := authInfo{Present: true, Raw: values[0]}
	v := strings.Trim(values[0], " \t")
	i := strings.IndexAny(v, " \t")
	if i < 0 {
		a.Scheme = v
		if strings.EqualFold(v, "Basic") {
			a.Result = "malformed"
		} else {
			a.Result = "bad"
		}
		return a
	}
	a.Scheme = v[:i]
	cred := strings.Trim(v[i:], " \t")
	if !strings.EqualFold(a.Scheme, "Basic") {
		a.Result = "bad" // 不是 Basic：格式谈不上错，但不接受
		return a
	}
	dec, err := base64.StdEncoding.Strict().DecodeString(cred)
	if err != nil {
		a.Result = "malformed"
		t := strings.TrimRight(cred, "=")
		if d, err := base64.RawStdEncoding.DecodeString(t); err == nil {
			dec, a.Lenient = d, true
		} else if d, err := base64.RawURLEncoding.DecodeString(t); err == nil {
			dec, a.Lenient = d, true
		} else {
			return a
		}
	}
	j := bytes.IndexByte(dec, ':')
	if j < 0 {
		a.User, a.HasUser = dec, true
		a.Result = "malformed"
		return a
	}
	a.User, a.HasUser = dec[:j], true
	a.Pass, a.HasPass = dec[j+1:], true
	return a
}

// judgeAuth 填上 ok 或 bad。格式有问题的保持 malformed。
// 判定只是把凭据与 auth.accept 比较，与 auth.mode 无关：不要求认证时照样记下判定，但不据此拒绝。
func (p *Profile) judgeAuth(a *authInfo) {
	if !a.Present || a.Result != "" {
		return
	}
	decoded := append(append(append([]byte{}, a.User...), ':'), a.Pass...)
	if p.basicOK(decoded) {
		a.Result = "ok"
	} else {
		a.Result = "bad"
	}
}

// strOrNil 把字节当成字符串给出；不是合法 UTF-8 时给 nil（事件里是 null），原样的字节看十六进制字段。
func strOrNil(b []byte, has bool) any {
	if !has || !utf8.Valid(b) {
		return nil
	}
	return string(b)
}

func hexOrNil(b []byte, has bool) any {
	if !has {
		return nil
	}
	return hex.EncodeToString(b)
}

// fields 把判定结果变成事件里的 auth 对象。各字段总是出现，不适用时为 null。
func (a *authInfo) fields() obj {
	if !a.Present {
		return obj{
			{"present", false}, {"scheme", nil}, {"raw", nil},
			{"user", nil}, {"user_hex", nil}, {"pass", nil}, {"pass_hex", nil},
			{"lenient", false}, {"result", "none"},
		}
	}
	return obj{
		{"present", true}, {"scheme", a.Scheme}, {"raw", a.Raw},
		{"user", strOrNil(a.User, a.HasUser)}, {"user_hex", hexOrNil(a.User, a.HasUser)},
		{"pass", strOrNil(a.Pass, a.HasPass)}, {"pass_hex", hexOrNil(a.Pass, a.HasPass)},
		{"lenient", a.Lenient}, {"result", a.Result},
	}
}
