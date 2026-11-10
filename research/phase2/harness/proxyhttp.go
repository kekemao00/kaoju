package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// proxyReq 是代理端口上收到的一个 HTTP 请求。
type proxyReq struct {
	seq       int
	tHead     float64 // 请求头读完的时刻
	head      *reqHead
	form      string
	k         any // 查询参数 k，没有就是 nil
	auth      authInfo
	bodyLen   int64
	bodySHA   string
	wantClose bool
	errText   any // 解析或读正文出的问题，没有就是 nil
}

// respSpec 是代理要写回去的一个响应。
type respSpec struct {
	status   int
	reason   string
	headers  [][2]string
	body     []byte
	by       string // proxy：代理自己生成的；origin：内置源站的处理函数生成、代理回写的
	cause    string
	close    bool // 发完以后代理关连接
	noLength bool // 不自动加 Content-Length（1xx、101、CONNECT 的 2xx）
	headOnly bool // 响应 HEAD：带 Content-Length 但不发正文
	tail     []byte
}

func textBody(s string) ([][2]string, []byte) {
	return [][2]string{{"Content-Type", "text/plain; charset=utf-8"}}, []byte(s)
}

func hasHeader(hs [][2]string, name string) bool {
	for _, h := range hs {
		if strings.EqualFold(h[0], name) {
			return true
		}
	}
	return false
}

func pairsTo(hs []Pair) [][2]string {
	out := make([][2]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, [2]string(h))
	}
	return out
}

// send 把响应写给客户端并写 http_response 事件。只回 HTTP/1.1。
func (s *Server) send(c *cconn, rq *proxyReq, r respSpec) bool {
	hdrs := append([][2]string{}, r.headers...)
	if !r.noLength && !hasHeader(hdrs, "Content-Length") {
		hdrs = append(hdrs, [2]string{"Content-Length", strconv.Itoa(len(r.body))})
	}
	if r.close && !hasHeader(hdrs, "Connection") {
		hdrs = append(hdrs, [2]string{"Connection", "close"})
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", r.status, r.reason)
	for _, h := range hdrs {
		b.WriteString(h[0])
		b.WriteString(": ")
		b.WriteString(h[1])
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	bodyLen := 0
	if !r.headOnly {
		b.Write(r.body)
		bodyLen = len(r.body)
	}
	b.Write(r.tail)
	_, err := c.Write(b.Bytes())
	var errText any
	if err != nil {
		errText = err.Error()
	}
	c.emit("http_response",
		kv{"seq", rq.seq}, kv{"status", r.status}, kv{"reason", r.reason},
		kv{"headers", hdrs}, kv{"body_len", bodyLen}, kv{"by", r.by}, kv{"cause", r.cause},
		kv{"close", r.close}, kv{"error", errText})
	return err == nil
}

func (s *Server) emitRequest(c *cconn, rq *proxyReq) {
	h := rq.head
	if h == nil {
		h = &reqHead{Headers: [][2]string{}}
	}
	c.emit("http_request",
		kv{"seq", rq.seq}, kv{"t_head", rq.tHead}, kv{"form", rq.form},
		kv{"method", h.Method}, kv{"target", h.Target}, kv{"version", h.Version}, kv{"k", rq.k},
		kv{"headers", h.Headers}, kv{"head_b64", base64.StdEncoding.EncodeToString(h.Raw)},
		kv{"body_len", rq.bodyLen}, kv{"body_sha256", rq.bodySHA},
		kv{"auth", rq.auth.fields()}, kv{"error", rq.errText})
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// serveHTTP 是代理端口上的 HTTP 入口：一条连接上一个接一个地处理请求，直到连接关闭或变成隧道。
func (s *Server) serveHTTP(c *cconn, br *bufio.Reader) {
	idle := time.Duration(s.prof.Conn.IdleCloseMs) * time.Millisecond
	seq := 0
	for {
		// conn.idle_close_ms：两个请求之间空闲太久就按 fin 关。只在已经处理过至少一个请求之后计时。
		if seq > 0 && idle > 0 && br.Buffered() == 0 {
			if err := c.SetReadDeadline(time.Now().Add(idle)); err != nil {
				return // 别处已经在关这条连接
			}
			if _, err := br.Peek(1); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) && !c.isClosing() {
					c.emit("action",
						kv{"what", "conn_idle_close"}, kv{"how", "fin"},
						kv{"k", nil}, kv{"tunnel", nil}, kv{"oconn", nil})
					c.shutdown("proxy", "fin", "conn_idle")
				} else {
					c.shutdown("proxy", "fin", "io_error")
				}
				return
			}
			_ = c.SetReadDeadline(time.Time{})
		}

		raw, err := readHead(br, maxHeadBytes)
		rq := &proxyReq{seq: seq + 1, tHead: s.log.now(), form: "other", bodySHA: emptySHA256, auth: authInfo{Result: "none"}}
		if err != nil {
			if err == errTooManyBlanks {
				// 请求行之前的空行超过 8 个：记一个没有请求行的 http_request，回 400 后关。
				rq.errText = "bad_head: " + err.Error()
				s.emitRequest(c, rq)
				h, b := textBody("obsproxy: bad request\n")
				s.send(c, rq, respSpec{status: 400, reason: "Bad Request", headers: h, body: b,
					by: "proxy", cause: "bad_request", close: true})
				c.shutdown("proxy", "fin", "response_close")
				return
			}
			if len(raw) == 0 && err != errHeadTooLarge {
				// 两个请求之间连接结束了（多数是对端正常关闭）。
				c.shutdown("proxy", "fin", "io_error")
				return
			}
			rq.head, _ = parseHead(raw)
			rq.form = classifyForm(rq.head.Method, rq.head.Target)
			if err == errHeadTooLarge {
				rq.errText = "head_too_large"
				s.emitRequest(c, rq)
				h, b := textBody("obsproxy: request header too large\n")
				s.send(c, rq, respSpec{status: 431, reason: "Request Header Fields Too Large", headers: h, body: b,
					by: "proxy", cause: "head_too_large", close: true})
				c.shutdown("proxy", "fin", "response_close")
				return
			}
			rq.errText = "incomplete_head: " + err.Error()
			s.emitRequest(c, rq)
			c.shutdown("proxy", "fin", "io_error")
			return
		}
		seq++

		head, perr := parseHead(raw)
		rq.head = head
		rq.form = classifyForm(head.Method, head.Target)
		if kval, ok := queryGet(targetQuery(head.Target), "k"); ok && rq.form != "connect" {
			rq.k = kval
		}
		rq.auth = parseProxyAuth(head.all("Proxy-Authorization"))
		s.prof.judgeAuth(&rq.auth)
		// 请求一侧要求关闭时照关（RFC 9112 第 9.6 节）：Connection: close，或不带 keep-alive 的 HTTP/1.0。
		// 这一条压过 auth.on407=keepalive 和 fail 的 close=false。
		// Proxy-Connection 不是标准头：带 close 不算要求关闭（否则“407 之后连接留着”的配置对
		// 默认带 Proxy-Connection: close 的客户端永远不成立）；带 keep-alive 则照老客户端的习惯，
		// 当作 HTTP/1.0 下要求保持连接。
		rq.wantClose = head.hasToken("Connection", "close") ||
			(head.Version == "HTTP/1.0" &&
				!head.hasToken("Connection", "keep-alive") && !head.hasToken("Proxy-Connection", "keep-alive"))

		bad := func(status int, reason, cause, text string) {
			rq.errText = text
			s.emitRequest(c, rq)
			h, b := textBody("obsproxy: bad request\n")
			s.send(c, rq, respSpec{status: status, reason: reason, headers: h, body: b, by: "proxy", cause: cause, close: true})
			c.shutdown("proxy", "fin", "response_close")
		}
		if perr != nil {
			bad(400, "Bad Request", "bad_request", "bad_head: "+perr.Error())
			return
		}
		if head.Version != "HTTP/1.1" && head.Version != "HTTP/1.0" {
			bad(505, "HTTP Version Not Supported", "bad_version", "unsupported_version")
			return
		}
		fr, ferr := bodyFraming(head)
		if rq.form == "connect" {
			// CONNECT 请求没有正文（RFC 9110 第 9.3.6 节）：请求头之后的字节都是隧道里的数据，不按
			// Content-Length、Transfer-Encoding 去读。带了这两个头（Content-Length: 0 除外）记一笔，请求照常处理。
			if ferr != nil || fr.kind == "chunked" || fr.length > 0 {
				rq.errText = "connect_framing_ignored"
			}
			fr, ferr = framing{kind: "none"}, nil
		}
		if ferr != nil {
			bad(400, "Bad Request", "bad_request", "bad_framing: "+ferr.Error())
			return
		}
		if len(head.all("Transfer-Encoding")) > 0 && len(head.all("Content-Length")) > 0 {
			// RFC 9112 第 6.1 节：两个都带的请求按 Transfer-Encoding 处理，回应之后必须关连接。
			rq.wantClose = true
		}

		// Expect: 100-continue：按配置先回 100，再读正文。不管后面认证过不过都先回，
		// 否则“先读完正文再回 407”会和“等 100 再发正文”的客户端互相等。
		if head.Version == "HTTP/1.1" && head.hasToken("Expect", "100-continue") && s.prof.Forward.Send100Continue &&
			(fr.kind == "chunked" || fr.length > 0) && (rq.form == "absolute" || rq.form == "connect") {
			s.send(c, rq, respSpec{status: 100, reason: "Continue", by: "proxy", cause: "continue", noLength: true})
		}

		hsh := sha256.New()
		n, berr := readBody(br, fr, hsh)
		rq.bodyLen = n
		rq.bodySHA = hex.EncodeToString(hsh.Sum(nil))
		if berr != nil {
			var bc *errBadChunked
			if errors.As(berr, &bc) {
				bad(400, "Bad Request", "bad_request", "bad_body: "+berr.Error())
				return
			}
			rq.errText = "incomplete_body: " + berr.Error()
			s.emitRequest(c, rq)
			c.shutdown("proxy", "fin", "io_error")
			return
		}
		s.emitRequest(c, rq)

		var keep bool
		switch rq.form {
		case "connect":
			keep = s.handleConnect(c, br, rq)
		case "absolute":
			keep = s.handleAbsolute(c, rq)
		default:
			h, b := textBody("obsproxy: this port only takes absolute-form requests and CONNECT\n")
			s.send(c, rq, respSpec{status: 400, reason: "Bad Request", headers: h, body: b, by: "proxy", cause: "not_proxy_request", close: true})
			c.shutdown("proxy", "fin", "response_close")
		}
		if !keep {
			return
		}
	}
}

// finish 在响应发出以后决定连接的去留：要关就按 fin 关，返回是否继续在这条连接上读下一个请求。
func (s *Server) finish(c *cconn, closeAfter, sent bool) bool {
	if !sent {
		c.shutdown("proxy", "fin", "io_error")
		return false
	}
	if closeAfter {
		c.shutdown("proxy", "fin", "response_close")
		return false
	}
	return true
}

// checkAuth 按 auth.* 判认证。通过返回 true；否则已经回了 407 或 403，keep 说明连接是否还留着。
// 调用时请求（含正文）已经读完，所以连接留着也不会错位。
func (s *Server) checkAuth(c *cconn, rq *proxyReq) (pass, keep bool) {
	a := &s.prof.Auth
	if a.Mode != "basic" || rq.auth.Result == "ok" {
		return true, true
	}
	closeAfter := a.On407 == "close" || rq.wantClose
	var r respSpec
	if rq.auth.Result == "none" || a.RejectStatus == 407 {
		// 没带凭据一律 407；带了但不对，按 reject_status。
		h, b := textBody("obsproxy: proxy authentication required\n")
		hdrs := make([][2]string, 0, len(a.Challenge)+1)
		for _, ch := range a.Challenge {
			hdrs = append(hdrs, [2]string{"Proxy-Authenticate", ch})
		}
		hdrs = append(hdrs, h...)
		cause := "auth_required"
		if rq.auth.Result != "none" {
			cause = "auth_rejected"
		}
		r = respSpec{status: 407, reason: "Proxy Authentication Required", headers: hdrs, body: b, by: "proxy", cause: cause, close: closeAfter}
	} else {
		h, b := textBody("obsproxy: proxy credentials rejected\n")
		r = respSpec{status: 403, reason: "Forbidden", headers: h, body: b, by: "proxy", cause: "auth_rejected", close: closeAfter}
	}
	sent := s.send(c, rq, r)
	return false, s.finish(c, closeAfter, sent)
}

// sendFail 回 connect.fail 或 forward.fail 配置的响应。
func (s *Server) sendFail(c *cconn, rq *proxyReq, f *FailSpec, cause string) bool {
	closeAfter := f.Close || rq.wantClose
	sent := s.send(c, rq, respSpec{status: f.Status, reason: f.Reason, headers: pairsTo(f.Headers), body: []byte(f.Body),
		by: "proxy", cause: cause, close: closeAfter, headOnly: rq.head.Method == "HEAD"})
	return s.finish(c, closeAfter, sent)
}

// sendSimple 回一个代理自己生成的纯文本响应，连接按请求的意思留或关。
func (s *Server) sendSimple(c *cconn, rq *proxyReq, status int, reason, cause, text string) bool {
	h, b := textBody(text)
	sent := s.send(c, rq, respSpec{status: status, reason: reason, headers: h, body: b, by: "proxy", cause: cause,
		close: rq.wantClose, headOnly: rq.head.Method == "HEAD"})
	return s.finish(c, rq.wantClose, sent)
}

// splitHostPort 解析 CONNECT 的目标（host:port，IPv6 带方括号）。
func splitHostPort(target string) (string, int, bool) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || len(portStr) > 5 {
		return "", 0, false
	}
	return host, port, true
}

// handleConnect 处理 CONNECT：认证、connect.fail、connect.drop、端口映射，然后建隧道。
// 返回 true 表示连接还留在 HTTP 入口上（等下一个请求）；建了隧道或关了连接都返回 false。
func (s *Server) handleConnect(c *cconn, br *bufio.Reader, rq *proxyReq) bool {
	if pass, keep := s.checkAuth(c, rq); !pass {
		return keep
	}
	host, port, ok := splitHostPort(rq.head.Target)
	if !ok {
		return s.sendSimple(c, rq, 400, "Bad Request", "bad_connect_target", "obsproxy: bad CONNECT target\n")
	}
	if f := s.prof.Connect.Fail; f != nil && f.appliesTo(host) {
		return s.sendFail(c, rq, f, "connect_fail")
	}
	if d := s.prof.Connect.Drop; s.takeDrop(d, &s.connectDropUsed, "", true) {
		c.emit("action",
			kv{"what", "connect_drop"}, kv{"how", d.How},
			kv{"k", nil}, kv{"tunnel", nil}, kv{"oconn", nil})
		c.shutdown("proxy", d.How, "connect_drop")
		return false
	}
	mapped := s.mapPort(port)
	if mapped == "" {
		return s.sendSimple(c, rq, 502, "Bad Gateway", "unmapped_port", "obsproxy: destination port is not served\n")
	}
	if !s.send(c, rq, respSpec{status: 200, reason: "Connection established", headers: pairsTo(s.prof.Connect.OKHeaders),
		by: "proxy", cause: "connect_ok", noLength: true}) {
		c.shutdown("proxy", "fin", "io_error")
		return false
	}
	// 客户端可能没等 200 就把隧道里的数据发来了：这些字节已经在缓冲区里，原样交给隧道。
	var early []byte
	if n := br.Buffered(); n > 0 {
		early = make([]byte, n)
		_, _ = io.ReadFull(br, early)
	}
	s.startTunnel(c, "connect", rq.seq, host, port, mapped, early)
	return false
}

// hopHeaders 是不转给源站的逐跳头。Host 由代理按请求目标重新给出，也不照搬。
var hopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true, "host": true,
}

// forwardHeaders 去掉逐跳头、Connection 里点名的头和 Proxy- 开头的头，其余保持原顺序。
func forwardHeaders(h *reqHead) [][2]string {
	named := map[string]bool{}
	for _, v := range h.all("Connection") {
		for _, t := range strings.Split(v, ",") {
			if t = strings.ToLower(strings.Trim(t, " \t")); t != "" {
				named[t] = true
			}
		}
	}
	out := make([][2]string, 0, len(h.Headers))
	for _, kv := range h.Headers {
		ln := strings.ToLower(kv[0])
		if hopHeaders[ln] || named[ln] || strings.HasPrefix(ln, "proxy-") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// handleAbsolute 处理绝对形式的请求：认证、forward.fail、conn.drop，然后交给内置明文源站的处理函数，
// 响应由代理回写。
func (s *Server) handleAbsolute(c *cconn, rq *proxyReq) bool {
	if pass, keep := s.checkAuth(c, rq); !pass {
		return keep
	}
	u, err := url.Parse(rq.head.Target)
	if err != nil || u.Host == "" {
		return s.sendSimple(c, rq, 400, "Bad Request", "bad_target", "obsproxy: bad request target\n")
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if f := s.prof.Forward.Fail; f != nil && f.appliesTo(host) {
		return s.sendFail(c, rq, f, "forward_fail")
	}
	kstr, _ := rq.k.(string)
	if d := s.prof.Conn.Drop; s.takeDrop(d, &s.connDropUsed, kstr, rq.seq > 1) {
		c.emit("action",
			kv{"what", "conn_drop"}, kv{"how", d.How},
			kv{"k", rq.k}, kv{"tunnel", nil}, kv{"oconn", nil})
		c.shutdown("proxy", d.How, "conn_drop")
		return false
	}
	switch scheme {
	case "http", "ws":
	case "https", "wss":
		// 不替客户端发起 TLS。
		return s.sendSimple(c, rq, 502, "Bad Gateway", "https_absolute", "obsproxy: absolute-form https is not forwarded\n")
	default:
		return s.sendSimple(c, rq, 400, "Bad Request", "bad_scheme", "obsproxy: unsupported scheme\n")
	}
	port := 80
	if ps := u.Port(); ps != "" {
		port, err = strconv.Atoi(ps)
		if err != nil {
			return s.sendSimple(c, rq, 400, "Bad Request", "bad_target", "obsproxy: bad request target\n")
		}
	}
	if s.mapPort(port) != "origin_http" {
		return s.sendSimple(c, rq, 502, "Bad Gateway", "unmapped_port", "obsproxy: destination port is not served\n")
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	// /ws 上带 Upgrade: websocket 的：由代理直接完成握手，发一个关闭帧，然后关连接。
	// 其余路径带不带 Upgrade 都照常交给源站的处理函数（Upgrade 是逐跳头，不转交），与隧道里的结果一致。
	if path == "/ws" && rq.head.hasToken("Upgrade", "websocket") {
		accept, status, why := wsCheck(rq.head.Method, rq.head.Version, rq.head)
		if status != 101 {
			return s.sendSimple(c, rq, status, http.StatusText(status), "websocket_rejected", "obsproxy: bad websocket handshake: "+why+"\n")
		}
		sent := s.send(c, rq, respSpec{status: 101, reason: "Switching Protocols",
			headers: [][2]string{{"Upgrade", "websocket"}, {"Connection", "Upgrade"}, {"Sec-WebSocket-Accept", accept}},
			by:      "proxy", cause: "websocket", close: true, noLength: true, tail: wsCloseFrame})
		if !sent {
			c.shutdown("proxy", "fin", "io_error")
			return false
		}
		c.shutdown("proxy", "fin", "websocket_done")
		return false
	}

	q := &originReq{
		via: "forward", c: c, reqSeq: rq.seq,
		method: rq.head.Method, path: path, rawQuery: u.RawQuery, proto: rq.head.Version, host: u.Host,
		headers: forwardHeaders(rq.head), bodyLen: rq.bodyLen, bodySHA: rq.bodySHA,
	}
	resp := s.originRespond(q)
	s.emitOriginRequest(q, "respond", resp.status, nil)
	if !s.sleep(resp.delay) {
		// 仪器在延迟期间开始退出：不再回应，连接由 Shutdown 关。
		return false
	}
	if resp.ws {
		// 走不到：/ws 上带 Upgrade 的请求上面已经处理了，不带的在 originRespond 里得到 400。
		resp = plainResp(400, "obsproxy origin: bad websocket handshake\n")
	}
	hdrs := [][2]string{{"Date", time.Now().UTC().Format(http.TimeFormat)}}
	hdrs = append(hdrs, resp.headers...)
	hdrs = append(hdrs, pairsTo(s.prof.Forward.AddResponseHeaders)...)
	sent := s.send(c, rq, respSpec{status: resp.status, reason: http.StatusText(resp.status), headers: hdrs, body: resp.body,
		by: "origin", cause: "forward", close: rq.wantClose, headOnly: rq.head.Method == "HEAD"})
	return s.finish(c, rq.wantClose, sent)
}
