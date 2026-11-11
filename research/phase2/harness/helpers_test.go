package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// asMainEnv：测试程序带着这个环境变量被重新执行时，直接充当 obsproxy 本身（见 cli_test.go）。
const asMainEnv = "OBSPROXY_TEST_AS_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(asMainEnv) == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// testCA 给这个测试生成一张测试用的 CA，放在测试自己的临时目录里（测试结束时自动删掉），
// 返回目录和只信任这张 CA 的证书池。
func testCA(t testing.TB) (string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	if _, err := genCA(dir); err != nil {
		t.Fatalf("生成测试 CA 失败: %v", err)
	}
	pem, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("ca.pem 里没有证书")
	}
	return dir, pool
}

// event 是事件文件里的一行。
type event map[string]any

func (e event) str(k string) string {
	s, _ := e[k].(string)
	return s
}

func (e event) num(k string) int {
	f, ok := e[k].(float64)
	if !ok {
		return -1
	}
	return int(f)
}

func (e event) obj(k string) event {
	m, _ := e[k].(map[string]any)
	return event(m)
}

// pairs 把 [[名, 值], …] 取出来。
func (e event) pairs(k string) [][2]string {
	arr, _ := e[k].([]any)
	out := make([][2]string, 0, len(arr))
	for _, it := range arr {
		p, _ := it.([]any)
		if len(p) != 2 {
			out = append(out, [2]string{"?", "?"})
			continue
		}
		a, _ := p[0].(string)
		b, _ := p[1].(string)
		out = append(out, [2]string{a, b})
	}
	return out
}

func (e event) ints(k string) []int {
	arr, _ := e[k].([]any)
	out := make([]int, 0, len(arr))
	for _, it := range arr {
		f, _ := it.(float64)
		out = append(out, int(f))
	}
	return out
}

func (e event) strs(k string) []string {
	arr, _ := e[k].([]any)
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		s, _ := it.(string)
		out = append(out, s)
	}
	return out
}

type events []event

func (es events) of(ev string) events {
	var out events
	for _, e := range es {
		if e.str("ev") == ev {
			out = append(out, e)
		}
	}
	return out
}

func (es events) conn(id int) events {
	var out events
	for _, e := range es {
		if e.num("conn") == id {
			out = append(out, e)
		}
	}
	return out
}

// names 返回事件名的序列，方便整体比较一条连接上发生了什么。
func (es events) names() string {
	var out []string
	for _, e := range es {
		out = append(out, e.str("ev"))
	}
	return strings.Join(out, " ")
}

// env 是一次测试用的仪器实例，跑在测试进程里。
type env struct {
	t       *testing.T
	srv     *Server
	evPath  string
	pool    *x509.CertPool
	pp      int // 代理端口
	hp      int // 明文源站端口
	sp      int // HTTPS 源站端口
	mu      sync.Mutex
	conns   []*rawConn
	stopped bool
	evs     events
}

func startEnv(t *testing.T, profile string) *env {
	t.Helper()
	caDir, pool := testCA(t)
	prof, err := ParseProfile([]byte(profile))
	if err != nil {
		t.Fatalf("配置解析失败: %v", err)
	}
	evPath := filepath.Join(t.TempDir(), "events.jsonl")
	f, err := os.Create(evPath)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(prof, caDir, f, io.Discard)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	srv.Start()
	e := &env{t: t, srv: srv, evPath: evPath, pool: pool}
	e.pp, e.hp, e.sp = srv.Ports()
	t.Cleanup(func() {
		if !e.stopped {
			e.stop()
		}
		f.Close()
	})
	return e
}

func (e *env) dial(port int, listener string) *rawConn {
	e.t.Helper()
	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		e.t.Fatalf("连接 127.0.0.1:%d 失败: %v", port, err)
	}
	rc := &rawConn{t: e.t, tcp: c, listener: listener, sentH: sha256.New(), recvH: sha256.New()}
	rc.localPort = c.LocalAddr().(*net.TCPAddr).Port
	rc.br = bufio.NewReaderSize(countedReader{rc}, 64<<10)
	e.mu.Lock()
	e.conns = append(e.conns, rc)
	e.mu.Unlock()
	return rc
}

func (e *env) dialProxy() *rawConn { return e.dial(e.pp, "proxy") }

// stop 让仪器退出，读回事件，做对所有测试都成立的检查，并逐条连接核对字节数和哈希。
func (e *env) stop() events {
	e.t.Helper()
	if e.stopped {
		return e.evs
	}
	e.stopped = true
	e.mu.Lock()
	conns := append([]*rawConn{}, e.conns...)
	e.mu.Unlock()
	for _, c := range conns {
		c.finish()
	}
	done := make(chan struct{})
	go func() { e.srv.Shutdown("test"); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		e.t.Fatal("Shutdown 10 秒没有返回")
	}
	e.evs = readEvents(e.t, e.evPath)
	dumpEvents(e.t, e.evPath)
	checkInvariants(e.t, e.evs)
	for _, c := range conns {
		e.verifyConn(c)
	}
	return e.evs
}

// dumpEvents：设了 OBSPROXY_TEST_DUMP=目录 时，把这个测试的事件文件留一份在那个目录里。
// EVENTS.md 里的例子就是从这里取的。
func dumpEvents(t testing.TB, evPath string) {
	dir := os.Getenv("OBSPROXY_TEST_DUMP")
	if dir == "" {
		return
	}
	data, _ := os.ReadFile(evPath)
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	_ = os.WriteFile(filepath.Join(dir, name+".jsonl"), data, 0o644)
}

func readEvents(t testing.TB, path string) events {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out events
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var ev event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("事件文件第 %d 行不是合法的 JSON: %v\n%s", i+1, err, line)
		}
		out = append(out, ev)
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		t.Fatal("事件文件的最后一行没有换行")
	}
	return out
}

var knownEvents = map[string]bool{
	"start": true, "end": true, "accept": true, "first_bytes": true, "http_request": true, "http_response": true,
	"tunnel_open": true, "tunnel_first_bytes": true, "tunnel_close": true,
	"socks5_greeting": true, "socks5_method": true, "socks5_auth": true, "socks5_request": true, "socks5_reply": true,
	"origin_conn": true, "origin_request": true, "action": true, "conn_end": true,
}

// eventFields 是每种事件的字段（t、ev、conn 之外的），按出现的顺序。EVENTS.md 写的就是这张表；
// checkInvariants 拿它核对测试里出现的每一个事件，TestEventsDoc 拿它核对 EVENTS.md。
var eventFields = map[string][]string{
	"start": {"version", "events_version", "go", "pid", "started_at", "proxy_port", "origin_http_port", "origin_https_port",
		"max_seconds", "profile"},
	"end":         {"reason", "version", "proxy_port", "origin_http_port", "origin_https_port", "conns", "tunnels", "oconns", "events"},
	"accept":      {"listener", "peer_port"},
	"first_bytes": {"listener", "n_first_read", "hex", "kind"},
	"http_request": {"seq", "t_head", "form", "method", "target", "version", "k", "headers", "head_b64", "body_len", "body_sha256",
		"auth", "error"},
	"http_response":      {"seq", "status", "reason", "headers", "body_len", "by", "cause", "close", "error"},
	"tunnel_open":        {"tunnel", "via", "req_seq", "target_host", "target_port", "mapped"},
	"tunnel_first_bytes": {"tunnel", "n_first_read", "early_bytes", "n_buffered", "hex", "kind", "tls"},
	"tunnel_close":       {"tunnel", "by", "reason", "bytes_c2s", "bytes_s2c"},
	"socks5_greeting":    {"version", "methods", "raw_hex"},
	"socks5_method":      {"selected"},
	"socks5_auth":        {"version", "ulen", "plen", "user", "user_hex", "pass", "pass_hex", "status", "result"},
	"socks5_request":     {"version", "cmd", "rsv", "atyp", "host", "port", "raw_hex"},
	"socks5_reply":       {"rep", "cause", "raw_hex"},
	"origin_conn":        {"oconn", "via", "tunnel", "listener", "tls", "alpn", "tls_version", "sni", "error"},
	"origin_request": {"oconn", "tunnel", "via", "seq", "req_seq", "k", "method", "path", "query", "proto", "host", "headers",
		"body_len", "body_sha256", "has_proxy_authorization", "tls", "action", "status", "error"},
	"action": {"what", "how", "k", "tunnel", "oconn"},
	"conn_end": {"listener", "by", "close", "reason", "bytes_in", "bytes_out", "bytes_drained", "sha256_in", "sha256_out",
		"dur_ms"},
}

// 事件里嵌套对象的字段。
var (
	authFields = []string{"present", "scheme", "raw", "user", "user_hex", "pass", "pass_hex", "lenient", "result"}
	tlsFields  = []string{"record_len", "complete", "record_version", "legacy_version", "sni", "alpn", "versions", "groups",
		"key_shares", "parse_error"}
)

// checkFields 核对一个事件的字段恰好是 eventFields 里列的那些：一个不多，一个不少（不适用的字段是 null，不省略）。
func checkFields(t testing.TB, where string, ev event) {
	t.Helper()
	name := ev.str("ev")
	want, ok := eventFields[name]
	if !ok {
		t.Errorf("%s：不认识的事件 %q", where, name)
		return
	}
	all := map[string]bool{"t": true, "ev": true}
	if name != "start" && name != "end" {
		all["conn"] = true
	}
	for _, k := range want {
		all[k] = true
	}
	for k := range all {
		if _, ok := ev[k]; !ok {
			t.Errorf("%s（%s）：缺少字段 %q", where, name, k)
		}
	}
	for k := range ev {
		if !all[k] && k != "late" {
			t.Errorf("%s（%s）：多出字段 %q", where, name, k)
		}
	}
	sub := func(field string, want []string) {
		o := ev.obj(field)
		if o == nil {
			return
		}
		if len(o) != len(want) {
			t.Errorf("%s（%s）：%s 对象有 %d 个字段，应为 %d 个", where, name, field, len(o), len(want))
		}
		for _, k := range want {
			if _, ok := o[k]; !ok {
				t.Errorf("%s（%s）：%s 对象缺少字段 %q", where, name, field, k)
			}
		}
	}
	switch name {
	case "http_request":
		if ev.obj("auth") == nil {
			t.Errorf("%s：http_request.auth 不是对象", where)
		}
		sub("auth", authFields)
	case "tunnel_first_bytes":
		sub("tls", tlsFields)
	}
}

// checkInvariants 检查任何一次运行都必须成立的事：start 开头、end 结尾、t 不倒退、
// 每个 accept 恰好一个 conn_end、每个 tunnel_open 恰好一个 tunnel_close、连接结束之后不再有它的事件。
func checkInvariants(t testing.TB, evs events) {
	t.Helper()
	if len(evs) < 2 {
		t.Fatalf("事件太少: %d", len(evs))
	}
	if evs[0].str("ev") != "start" {
		t.Errorf("第一个事件是 %q，应为 start", evs[0].str("ev"))
	}
	last := evs[len(evs)-1]
	if last.str("ev") != "end" {
		t.Errorf("最后一个事件是 %q，应为 end", last.str("ev"))
	}
	if last.num("events") != len(evs) {
		t.Errorf("end.events = %d，文件里有 %d 行", last.num("events"), len(evs))
	}
	prev := -1.0
	accepted := map[int]bool{}
	ended := map[int]bool{}
	tunOpen := map[int]bool{}
	tunClosed := map[int]bool{}
	for i, ev := range evs {
		name := ev.str("ev")
		if !knownEvents[name] {
			t.Errorf("第 %d 行：不认识的事件 %q", i+1, name)
		}
		checkFields(t, fmt.Sprintf("第 %d 行", i+1), ev)
		tt, ok := ev["t"].(float64)
		if !ok || tt < prev {
			t.Errorf("第 %d 行：t 不是数字或倒退了（%v，上一个 %v）", i+1, ev["t"], prev)
		}
		prev = tt
		id := ev.num("conn")
		switch name {
		case "start", "end":
			continue
		case "accept":
			if accepted[id] {
				t.Errorf("连接 %d 有两个 accept", id)
			}
			accepted[id] = true
			continue
		}
		if !accepted[id] {
			t.Errorf("第 %d 行（%s）：连接 %d 还没有 accept", i+1, name, id)
		}
		if ended[id] {
			// conn_end 之后才写出来的事件必须带 late: true；测试里不应该出现这种赛跑。
			t.Errorf("第 %d 行（%s，late=%v）：连接 %d 已经 conn_end 了", i+1, name, ev["late"], id)
		}
		switch name {
		case "conn_end":
			ended[id] = true
		case "tunnel_open":
			tunOpen[ev.num("tunnel")] = true
		case "tunnel_close":
			tid := ev.num("tunnel")
			if !tunOpen[tid] || tunClosed[tid] {
				t.Errorf("隧道 %d 的 tunnel_close 没有对应的 tunnel_open，或者重复了", tid)
			}
			tunClosed[tid] = true
		}
	}
	for id := range accepted {
		if !ended[id] {
			t.Errorf("连接 %d 没有 conn_end", id)
		}
	}
	for tid := range tunOpen {
		if !tunClosed[tid] {
			t.Errorf("隧道 %d 没有 tunnel_close", tid)
		}
	}
	if last.num("conns") != len(accepted) {
		t.Errorf("end.conns = %d，accept 有 %d 个", last.num("conns"), len(accepted))
	}
}

// connID 按对端端口找到某条测试连接在事件里的编号。
func (e *env) connID(c *rawConn) int {
	e.t.Helper()
	for _, ev := range e.evs.of("accept") {
		if ev.num("peer_port") == c.localPort && ev.str("listener") == c.listener {
			return ev.num("conn")
		}
	}
	e.t.Fatalf("事件里找不到本地端口 %d 的连接（%s）", c.localPort, c.listener)
	return 0
}

// verifyConn 核对 conn_end 里两个方向的字节数和 SHA-256 与测试自己发收的完全一致。
func (e *env) verifyConn(c *rawConn) {
	e.t.Helper()
	id := e.connID(c)
	ends := e.evs.conn(id).of("conn_end")
	if len(ends) != 1 {
		e.t.Errorf("连接 %d 的 conn_end 有 %d 个", id, len(ends))
		return
	}
	end := ends[0]
	c.mu.Lock()
	defer c.mu.Unlock()
	sentSHA := hex.EncodeToString(c.sentH.Sum(nil))
	recvSHA := hex.EncodeToString(c.recvH.Sum(nil))
	if int64(end.num("bytes_in")) != c.sentN || end.str("sha256_in") != sentSHA {
		e.t.Errorf("连接 %d：测试发了 %d 字节（%s），conn_end 记的是 %d 字节（%s）",
			id, c.sentN, sentSHA, end.num("bytes_in"), end.str("sha256_in"))
	}
	if c.lossy {
		// 仪器复位了连接：还在路上的字节测试这边可能收不到，只要求收到的不比仪器写出的多。
		if int64(end.num("bytes_out")) < c.recvN {
			e.t.Errorf("连接 %d：测试收到 %d 字节，比 conn_end 记的 %d 还多", id, c.recvN, end.num("bytes_out"))
		}
		return
	}
	if int64(end.num("bytes_out")) != c.recvN || end.str("sha256_out") != recvSHA {
		e.t.Errorf("连接 %d：测试收到 %d 字节（%s），conn_end 记的是 %d 字节（%s）",
			id, c.recvN, recvSHA, end.num("bytes_out"), end.str("sha256_out"))
	}
}

// rawConn 是测试用的裸 TCP 连接。发出和收到的每个字节都记数、记哈希，最后与 conn_end 比。
// 它实现 net.Conn，所以 crypto/tls 可以直接跑在它上面（隧道里的 TLS）。
type rawConn struct {
	t         *testing.T
	tcp       *net.TCPConn
	listener  string
	localPort int
	br        *bufio.Reader

	mu     sync.Mutex
	sentN  int64
	recvN  int64
	sentH  hash.Hash
	recvH  hash.Hash
	writes []int // 每次 Write 的长度
	done   bool
	lossy  bool // 这条连接会被仪器复位，收到的字节数不要求相等
}

// countedReader 是 rawConn 底下真正读套接字的地方。
type countedReader struct{ c *rawConn }

func (r countedReader) Read(p []byte) (int, error) {
	n, err := r.c.tcp.Read(p)
	if n > 0 {
		r.c.mu.Lock()
		r.c.recvH.Write(p[:n])
		r.c.recvN += int64(n)
		r.c.mu.Unlock()
	}
	return n, err
}

func (c *rawConn) Read(p []byte) (int, error) { return c.br.Read(p) }

func (c *rawConn) Write(p []byte) (int, error) {
	n, err := c.tcp.Write(p)
	c.mu.Lock()
	if n > 0 {
		c.sentH.Write(p[:n])
		c.sentN += int64(n)
	}
	c.writes = append(c.writes, n)
	c.mu.Unlock()
	return n, err
}

// Close 由 crypto/tls 在关闭时调用（发完 close_notify 之后）。这里做有序的收尾而不是直接关套接字：
// 直接关的话，仪器随后写出的字节（它那一侧的 close_notify）测试收不到，字节数就对不上了。
func (c *rawConn) Close() error {
	c.finish()
	return nil
}

func (c *rawConn) LocalAddr() net.Addr                { return c.tcp.LocalAddr() }
func (c *rawConn) RemoteAddr() net.Addr               { return c.tcp.RemoteAddr() }
func (c *rawConn) SetDeadline(t time.Time) error      { return c.tcp.SetDeadline(t) }
func (c *rawConn) SetReadDeadline(t time.Time) error  { return c.tcp.SetReadDeadline(t) }
func (c *rawConn) SetWriteDeadline(t time.Time) error { return c.tcp.SetWriteDeadline(t) }

func (c *rawConn) sent() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sentN
}

func (c *rawConn) received() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recvN
}

func (c *rawConn) send(s string) {
	c.t.Helper()
	if _, err := c.Write([]byte(s)); err != nil {
		c.t.Fatalf("发送失败: %v", err)
	}
}

// finish 是测试这一侧的收尾：半关，把对方还在发的读完，再关。这样仪器写出的每个字节测试都收到了。
func (c *rawConn) finish() {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	c.done = true
	c.mu.Unlock()
	_ = c.tcp.CloseWrite()
	_ = c.tcp.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, c.br)
	_ = c.tcp.Close()
}

// expectEOF 要求对方在 within 之内正常关闭（FIN），期间不再发任何字节。返回等了多久。
func (c *rawConn) expectEOF(within time.Duration) time.Duration {
	c.t.Helper()
	start := time.Now()
	_ = c.tcp.SetReadDeadline(start.Add(within))
	defer c.tcp.SetReadDeadline(time.Time{})
	var b [1]byte
	n, err := c.br.Read(b[:])
	if n != 0 || err != io.EOF {
		c.t.Fatalf("应当读到 EOF（对方发 FIN），实际 n=%d err=%v", n, err)
	}
	return time.Since(start)
}

// expectReset 要求对方在 within 之内复位连接（RST）。
func (c *rawConn) expectReset(within time.Duration) {
	c.t.Helper()
	c.mu.Lock()
	c.lossy = true
	c.mu.Unlock()
	_ = c.tcp.SetReadDeadline(time.Now().Add(within))
	defer c.tcp.SetReadDeadline(time.Time{})
	var b [1]byte
	n, err := c.br.Read(b[:])
	if n != 0 || !errors.Is(err, syscall.ECONNRESET) {
		c.t.Fatalf("应当读到 ECONNRESET（对方发 RST），实际 n=%d err=%v", n, err)
	}
}

// expectSilence 要求 d 之内对方什么都不发，也不关。
func (c *rawConn) expectSilence(d time.Duration) {
	c.t.Helper()
	_ = c.tcp.SetReadDeadline(time.Now().Add(d))
	defer c.tcp.SetReadDeadline(time.Time{})
	_, err := c.br.Peek(1)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		c.t.Fatalf("应当保持安静 %v，实际 err=%v", d, err)
	}
}

// resp 是测试自己解析出来的一个 HTTP 响应。
type resp struct {
	proto   string
	status  int
	reason  string
	headers [][2]string
	body    []byte
	head    string // 状态行和头的原文
}

func (r *resp) get(name string) (string, bool) {
	for _, h := range r.headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

func (r *resp) all(name string) []string {
	var out []string
	for _, h := range r.headers {
		if strings.EqualFold(h[0], name) {
			out = append(out, h[1])
		}
	}
	return out
}

// echo 把 /echo 的正文解析出来。
func (r *resp) echo(t *testing.T) event {
	t.Helper()
	var ev event
	if err := json.Unmarshal(r.body, &ev); err != nil {
		t.Fatalf("/echo 的正文不是 JSON: %v\n%s", err, r.body)
	}
	return ev
}

// readResp 用测试自己的解析器读一个响应：状态行、头、按 Content-Length 读正文。
// 没有 Content-Length 的（CONNECT 的 200、100、101）正文为空。
func readResp(t *testing.T, br *bufio.Reader, d time.Duration, setDeadline func(time.Time) error) *resp {
	t.Helper()
	_ = setDeadline(time.Now().Add(d))
	defer setDeadline(time.Time{})
	r := &resp{}
	var head strings.Builder
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读状态行失败: %v（已读到 %q）", err, line)
	}
	head.WriteString(line)
	if !strings.HasSuffix(line, "\r\n") {
		t.Fatalf("状态行没有以 CRLF 结尾: %q", line)
	}
	parts := strings.SplitN(strings.TrimSuffix(line, "\r\n"), " ", 3)
	if len(parts) != 3 {
		t.Fatalf("状态行格式不对: %q", line)
	}
	r.proto, r.reason = parts[0], parts[2]
	if r.status, err = strconv.Atoi(parts[1]); err != nil {
		t.Fatalf("状态码不是数字: %q", line)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("读响应头失败: %v", err)
		}
		head.WriteString(line)
		if !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("响应头的行没有以 CRLF 结尾: %q", line)
		}
		line = strings.TrimSuffix(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			t.Fatalf("响应头的行格式不对: %q", line)
		}
		r.headers = append(r.headers, [2]string{name, value})
	}
	r.head = head.String()
	if cl, ok := r.get("Content-Length"); ok {
		n, err := strconv.Atoi(cl)
		if err != nil {
			t.Fatalf("Content-Length 不是数字: %q", cl)
		}
		r.body = make([]byte, n)
		if _, err := io.ReadFull(br, r.body); err != nil {
			t.Fatalf("读正文失败: %v", err)
		}
	}
	return r
}

func (c *rawConn) readResp() *resp {
	c.t.Helper()
	return readResp(c.t, c.br, 5*time.Second, c.tcp.SetReadDeadline)
}

// connect 发一个 CONNECT 并要求得到 200。
func (c *rawConn) connect(target string) *resp {
	c.t.Helper()
	c.send("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
	r := c.readResp()
	if r.status != 200 {
		c.t.Fatalf("CONNECT %s 得到 %d %s", target, r.status, r.reason)
	}
	return r
}

// tlsConn 是隧道里（或直连上）的 TLS 连接，带一个读响应用的缓冲。
type tlsConn struct {
	t  *testing.T
	tc *tls.Conn
	br *bufio.Reader
}

// startTLS 在一条连接上做 TLS 握手。证书由测试 CA 校验（RootCAs），不关闭校验。
func (e *env) startTLS(c net.Conn, serverName string, alpn ...string) *tlsConn {
	e.t.Helper()
	tc := tls.Client(c, &tls.Config{RootCAs: e.pool, ServerName: serverName, NextProtos: alpn})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		e.t.Fatalf("TLS 握手失败: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	return &tlsConn{t: e.t, tc: tc, br: bufio.NewReader(tc)}
}

// close 发 close_notify，然后经 rawConn.Close 有序地收尾。
func (c *tlsConn) close() {
	_ = c.tc.Close()
}

func (c *tlsConn) send(s string) {
	c.t.Helper()
	if _, err := c.tc.Write([]byte(s)); err != nil {
		c.t.Fatalf("隧道里发送失败: %v", err)
	}
}

func (c *tlsConn) readResp() *resp {
	c.t.Helper()
	return readResp(c.t, c.br, 5*time.Second, c.tc.SetReadDeadline)
}

func getReq(path, host string, extra ...string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n" + strings.Join(extra, "") + "\r\n"
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pattern 生成与 cases.json 说明里相同的正文：第 i 个字节是 (i*131+7)%251。
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*131 + 7) % 251)
	}
	return b
}

func wantPairs(t *testing.T, what string, got, want [][2]string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%s 不对\n  实际: %q\n  应为: %q", what, got, want)
	}
}

func wantEq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v，应为 %v", what, got, want)
	}
}

func one(t *testing.T, es events, what string) event {
	t.Helper()
	if len(es) != 1 {
		t.Fatalf("%s 应当恰好有 1 个，实际 %d 个", what, len(es))
	}
	return es[0]
}
