package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// originReq 是内置源站收到的一个请求。三条来路共用：
// tunnel（隧道里）、direct（源站端口上的直连）由 http.Server 解析后填；
// forward（代理端口上的绝对形式请求）由代理入口填，进程内直接调用。
type originReq struct {
	via      string
	c        *cconn // 最外层的 TCP 连接
	oconn    int64  // 源站连接编号；forward 没有
	tunnel   int64  // 隧道编号；只有 tunnel 有
	seq      int    // 这条源站连接上的第几个请求；forward 没有
	reqSeq   int    // forward：对应代理连接上 http_request 的 seq
	method   string
	path     string
	rawQuery string
	proto    string
	host     string
	headers  [][2]string
	bodyLen  int64
	bodySHA  string
	tls      bool
	hijack   bool // 这条连接能不能接管过来做 WebSocket（HTTP/1.x 的 tunnel、direct 可以）
}

// originResp 是内置源站对一个请求的回应。
type originResp struct {
	status   int
	headers  [][2]string
	body     []byte
	delay    time.Duration // /echo?delay=毫秒：回应之前先等这么久
	ws       bool          // 接管连接：回 101，发一个关闭帧，然后关
	wsAccept string
}

func plainResp(status int, text string) *originResp {
	return &originResp{status: status, headers: [][2]string{{"Content-Type", "text/plain; charset=utf-8"}}, body: []byte(text)}
}

// maxDelay 是 /echo 的 delay 参数的上限。
const maxDelay = 60 * time.Second

func (q *originReq) headerGet(name string) (string, bool) {
	for _, h := range q.headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

func (q *originReq) headerHasToken(name, token string) bool {
	for _, h := range q.headers {
		if !strings.EqualFold(h[0], name) {
			continue
		}
		for _, t := range strings.Split(h[1], ",") {
			if strings.EqualFold(strings.Trim(t, " \t"), token) {
				return true
			}
		}
	}
	return false
}

func (q *originReq) hasProxyAuthorization() bool {
	_, ok := q.headerGet("Proxy-Authorization")
	return ok
}

func (q *originReq) k() any {
	if v, ok := queryGet(q.rawQuery, "k"); ok {
		return v
	}
	return nil
}

// idOrNil：forward 没有源站连接，相应的编号在事件和 /echo 里是 null。
func idOrNil(v int64, has bool) any {
	if !has {
		return nil
	}
	return v
}

// originRespond 是内置源站的处理函数：只看请求，算出回应，不做任何读写。
// 明文和 HTTPS 两个源站的路径完全相同。
func (s *Server) originRespond(q *originReq) *originResp {
	switch q.path {
	case "/echo":
		onConn := q.via != "forward"
		var seq any
		if onConn {
			seq = q.seq
		}
		body, err := marshalPlain(obj{
			{"k", q.k()}, {"method", q.method}, {"proto", q.proto}, {"host", q.host},
			{"headers", q.headers}, {"body_len", q.bodyLen}, {"body_sha256", q.bodySHA},
			{"origin_conn", idOrNil(q.oconn, onConn)}, {"seq", seq}, {"tls", q.tls},
			{"via", q.via}, {"conn", q.c.id},
		})
		if err != nil {
			return plainResp(500, "obsproxy origin: internal error\n")
		}
		resp := &originResp{
			status: 200,
			headers: [][2]string{
				{"Content-Type", "application/json"},
				{"Cache-Control", "no-store"},
				{"Access-Control-Allow-Origin", "*"},
			},
			body: append(body, '\n'),
		}
		if d, ok := queryGet(q.rawQuery, "delay"); ok {
			if ms, err := strconv.Atoi(d); err == nil && ms > 0 {
				resp.delay = min(time.Duration(ms)*time.Millisecond, maxDelay)
			}
		}
		return resp

	case "/redirect":
		to, ok := queryGet(q.rawQuery, "to")
		if !ok || to == "" || !validHeaderValue(to) {
			return plainResp(400, "obsproxy origin: redirect needs a usable to= parameter\n")
		}
		code := 302
		if cs, ok := queryGet(q.rawQuery, "code"); ok {
			switch n, _ := strconv.Atoi(cs); n {
			case 301, 302, 303, 307, 308:
				code = n
			}
		}
		return &originResp{
			status: code,
			headers: [][2]string{
				{"Location", to},
				{"Content-Type", "text/plain; charset=utf-8"},
				{"Cache-Control", "no-store"},
			},
			body: []byte("obsproxy origin: redirect\n"),
		}

	case "/page":
		k, _ := q.k().(string)
		page := "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>kaoju " + html.EscapeString(k) +
			"</title></head><body></body></html>\n"
		return &originResp{
			status: 200,
			headers: [][2]string{
				{"Content-Type", "text/html; charset=utf-8"},
				{"Cache-Control", "no-store"},
			},
			body: []byte(page),
		}

	case "/ws":
		if !q.hijack {
			return plainResp(400, "obsproxy origin: websocket needs an HTTP/1.1 connection of its own\n")
		}
		accept, status, why := wsCheck(q.method, q.proto, q)
		if status != 101 {
			r := plainResp(status, "obsproxy origin: bad websocket handshake: "+why+"\n")
			if status == 426 {
				r.headers = append(r.headers, [2]string{"Sec-WebSocket-Version", "13"})
			}
			return r
		}
		return &originResp{status: 101, ws: true, wsAccept: accept}
	}
	return plainResp(404, "obsproxy origin: not found\n")
}

// headerView 是 wsCheck 需要的读头方法；代理入口的 reqHead 和源站的 originReq 都满足。
type headerView interface {
	headerGet(name string) (string, bool)
	headerHasToken(name, token string) bool
}

func (h *reqHead) headerGet(name string) (string, bool)   { return h.get(name) }
func (h *reqHead) headerHasToken(name, token string) bool { return h.hasToken(name, token) }

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsCloseFrame 是一个没有掩码的关闭帧，状态码 1000（正常关闭）。
var wsCloseFrame = []byte{0x88, 0x02, 0x03, 0xe8}

// wsCheck 按 RFC 6455 第 4.2.1 节校验握手。通过时 status 是 101，并给出 Sec-WebSocket-Accept 的值。
func wsCheck(method, proto string, h headerView) (accept string, status int, why string) {
	if method != "GET" {
		return "", 400, "method is not GET"
	}
	if proto != "HTTP/1.1" {
		return "", 400, "not HTTP/1.1"
	}
	if !h.headerHasToken("Upgrade", "websocket") {
		return "", 400, "no Upgrade: websocket"
	}
	if !h.headerHasToken("Connection", "upgrade") {
		return "", 400, "Connection has no upgrade token"
	}
	key, ok := h.headerGet("Sec-WebSocket-Key")
	if !ok {
		return "", 400, "no Sec-WebSocket-Key"
	}
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		return "", 400, "Sec-WebSocket-Key is not 16 bytes of base64"
	}
	if v, _ := h.headerGet("Sec-WebSocket-Version"); v != "13" {
		return "", 426, "Sec-WebSocket-Version is not 13"
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:]), 101, ""
}

func (s *Server) emitOriginRequest(q *originReq, action string, status int, bodyErr error) {
	onConn := q.via != "forward"
	var seq, reqSeq, st, be any
	if onConn {
		seq = q.seq
	} else {
		reqSeq = q.reqSeq
	}
	if action == "respond" {
		st = status
	}
	if bodyErr != nil {
		be = bodyErr.Error()
	}
	q.c.emit("origin_request",
		kv{"oconn", idOrNil(q.oconn, onConn)}, kv{"tunnel", idOrNil(q.tunnel, q.via == "tunnel")},
		kv{"via", q.via}, kv{"seq", seq}, kv{"req_seq", reqSeq}, kv{"k", q.k()},
		kv{"method", q.method}, kv{"path", q.path}, kv{"query", q.rawQuery}, kv{"proto", q.proto}, kv{"host", q.host},
		kv{"headers", q.headers}, kv{"body_len", q.bodyLen}, kv{"body_sha256", q.bodySHA},
		kv{"has_proxy_authorization", q.hasProxyAuthorization()}, kv{"tls", q.tls},
		kv{"action", action}, kv{"status", st}, kv{"error", be})
}

// sortedHeaders 把 net/http 解析出来的头摊平成 [[名, 值], …]。
// 这一侧拿不到线上的原顺序和原大小写：名字是 net/http 规范化以后的写法，按名字排序，同名的值保持先后。
func sortedHeaders(h http.Header) [][2]string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([][2]string, 0, len(h))
	for _, name := range names {
		for _, v := range h[name] {
			out = append(out, [2]string{name, v})
		}
	}
	return out
}

// originHTTP 是两个内置源站共用的 http.Handler，处理隧道里和直连上的请求。
func (s *Server) originHTTP(w http.ResponseWriter, r *http.Request) {
	oc, _ := r.Context().Value(originConnKey{}).(*originConn)
	if oc == nil {
		http.Error(w, "obsproxy origin: internal error", http.StatusInternalServerError)
		return
	}
	seq := int(oc.reqs.Add(1))

	// 先把正文读完并算哈希；丢弃请求也在读完之后。
	hsh := sha256.New()
	n, bodyErr := io.Copy(hsh, r.Body)
	q := &originReq{
		via: oc.via, c: oc.c, oconn: oc.id, tunnel: oc.tunnel, seq: seq,
		method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery, proto: r.Proto, host: r.Host,
		headers: sortedHeaders(r.Header), bodyLen: n, bodySHA: hex.EncodeToString(hsh.Sum(nil)),
		tls: r.TLS != nil, hijack: r.ProtoMajor == 1,
	}
	if bodyErr != nil {
		// 正文没读完连接就断了：记下来，不回应。
		s.emitOriginRequest(q, "none", 0, bodyErr)
		panic(http.ErrAbortHandler)
	}

	// origin.drop：隧道里带这个 k 的请求读完以后不回应，切断隧道（关最外层的 TCP 连接）。
	if d := s.prof.Origin.Drop; oc.via == "tunnel" {
		kstr, _ := q.k().(string)
		if s.takeDrop(d, &s.originDropUsed, kstr, seq > 1) {
			s.emitOriginRequest(q, "drop", 0, nil)
			oc.c.emit("action",
				kv{"what", "origin_drop"}, kv{"how", d.How},
				kv{"k", kstr}, kv{"tunnel", oc.tunnel}, kv{"oconn", oc.id})
			oc.c.shutdown("proxy", d.How, "origin_drop")
			panic(http.ErrAbortHandler)
		}
	}

	resp := s.originRespond(q)
	s.emitOriginRequest(q, "respond", resp.status, nil)
	s.sleep(resp.delay)

	if resp.ws {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "obsproxy origin: cannot take over this connection", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		// 握手的应答和关闭帧分两次写，像一个真的服务端那样；然后关连接。
		_, _ = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + resp.wsAccept + "\r\n\r\n")
		_ = bufrw.Flush()
		_, _ = bufrw.Write(wsCloseFrame)
		_ = bufrw.Flush()
		_ = conn.Close()
		return
	}

	hdr := w.Header()
	for _, h := range resp.headers {
		hdr.Add(h[0], h[1])
	}
	hdr.Set("Content-Length", strconv.Itoa(len(resp.body)))
	w.WriteHeader(resp.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(resp.body)
	}
}
