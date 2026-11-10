// go 这一列的驱动：Go 标准库 net/http 默认的 Transport 经代理时的行为。
//
// 用法：
//
//	driver <用例.json> <结果.json>
//	driver --versions
//
// 约定见 research/phase2/PROTOCOL.md 的“驱动”一节，惯用写法的出处见本目录的 NOTES.md。只用标准库。
//
// 做法（同样的话写进结果的 config）：
//
//   - 一个用例一个 Transport、一个 Client，从头用到尾。Transport 是 http.DefaultTransport 的克隆，只改 Proxy
//     （另挂一个只旁听、一定返回 nil 的 OnProxyConnectResponse，用来取 extra_text）。
//   - 凭据写在代理 URL 的 userinfo 里（url.UserPassword）。Proxy 是一个函数，按请求 context 里的用户下标返回对应的 URL；
//     只有一个用户时它每次返回同一个 URL，与 http.ProxyURL 等价。
//   - 信任测试 CA 靠环境变量 SSL_CERT_FILE（由 registry.json 的 env 设好），不设 TLSClientConfig，HTTP/2 保持默认。
//   - POST 的正文读进内存，用 bytes.NewReader 交给 http.NewRequestWithContext。
//   - 重定向用 Client 的默认行为（跟随，最多 10 跳）。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed go.mod
var goMod string

const bodyHead = 4096

const extraHow = "Transport.OnProxyConnectResponse（Go 1.20 起，net/http 的文档写明：收到代理对 CONNECT 的响应时调用，在检查 200 之前）。" +
	"钩子只旁听、一定返回 nil：记下协议版本、状态行、响应头；状态码不是 200 时再读正文的前 4096 字节（最多等 1 秒）。" +
	"记录归到发起这次拨号的那一步；一步里没有发出 CONNECT（复用了隧道、明文请求、SOCKS5）就没有记录"

type userT struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type stepT struct {
	ID       string  `json:"id"`
	Op       string  `json:"op"`
	Method   string  `json:"method"`
	URL      string  `json:"url"`
	User     *int    `json:"user"`
	Follow   bool    `json:"follow"`
	BodyFile string  `json:"body_file"`
	Ms       int     `json:"ms"`
	Steps    []stepT `json:"steps"`
}

type caseT struct {
	ID      string `json:"id"`
	Variant string `json:"variant"`
	Proxy   struct {
		Scheme string `json:"scheme"`
		Host   string `json:"host"`
		Port   int    `json:"port"`
	} `json:"proxy"`
	Users    []userT `json:"users"`
	CAFile   string  `json:"ca_file"`
	TimeoutS float64 `json:"timeout_s"`
	Steps    []stepT `json:"steps"`
}

type stepResult struct {
	ID          string         `json:"id"`
	Op          string         `json:"op"`
	OK          *bool          `json:"ok"`
	Status      *int           `json:"status"`
	BodySHA256  *string        `json:"body_sha256"`
	Ms          *int64         `json:"ms"`
	DefaultText *string        `json:"default_text"`
	ExtraText   *string        `json:"extra_text"`
	ExtraHow    *string        `json:"extra_how"`
	Go          map[string]any `json:"go,omitempty"`
	Steps       []stepResult   `json:"steps,omitempty"`
}

type resultT struct {
	Variant     string         `json:"variant"`
	Versions    map[string]any `json:"versions"`
	Config      *string        `json:"config"`
	Unsupported *string        `json:"unsupported"`
	Steps       []stepResult   `json:"steps"`
	Notes       []string       `json:"notes"`
}

// stepInfo 挂在每个请求的 context 上：Proxy 函数从它取用户下标，OnProxyConnectResponse 往它里面记 CONNECT 的响应。
type stepInfo struct {
	id   string
	user *int

	mu       sync.Mutex
	connects []string
}

type stepKey struct{}

func (s *stepInfo) add(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connects = append(s.connects, text)
}

func (s *stepInfo) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.connects...)
}

func ptr[T any](v T) *T { return &v }

func versions() map[string]any {
	v := map[string]any{
		"go":           runtime.Version(),
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
		"go_mod_go":    nil,
		"GODEBUG":      os.Getenv("GODEBUG"),
		"dependencies": "只用标准库",
	}
	for _, line := range strings.Split(goMod, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "go" {
			v["go_mod_go"] = f[1]
		}
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		settings := map[string]string{}
		for _, s := range bi.Settings {
			settings[s.Key] = s.Value
		}
		v["build_settings"] = settings
	}
	return v
}

// proxyURL 是 NOTES.md 第 1 节的写法：userinfo 用 url.UserPassword 构造，不手拼字符串。
func proxyURL(scheme, host string, port int, u *userT) *url.URL {
	p := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}
	if u != nil {
		p.User = url.UserPassword(u.User, u.Pass)
	}
	return p
}

type runner struct {
	c       *caseT
	tr      *http.Transport
	client  *http.Client
	noUser  *url.URL
	byUser  []*url.URL
	httpPx  bool
	unsupMu sync.Mutex
	unsup   string
}

func newRunner(c *caseT) *runner {
	r := &runner{c: c, httpPx: c.Proxy.Scheme == "http"}
	r.noUser = proxyURL(c.Proxy.Scheme, c.Proxy.Host, c.Proxy.Port, nil)
	for i := range c.Users {
		r.byUser = append(r.byUser, proxyURL(c.Proxy.Scheme, c.Proxy.Host, c.Proxy.Port, &c.Users[i]))
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		si, _ := req.Context().Value(stepKey{}).(*stepInfo)
		if si == nil || si.user == nil {
			return r.noUser, nil
		}
		if *si.user < 0 || *si.user >= len(r.byUser) {
			return nil, fmt.Errorf("驱动：用例里没有下标为 %d 的用户", *si.user)
		}
		return r.byUser[*si.user], nil
	}
	tr.OnProxyConnectResponse = func(ctx context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
		si, _ := ctx.Value(stepKey{}).(*stepInfo)
		if si == nil {
			return nil
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "%s %s\n", res.Proto, res.Status)
		_ = res.Header.Write(&sb)
		if res.StatusCode != 200 && res.Body != nil {
			sb.WriteString("\n")
			sb.WriteString(readBounded(res.Body, bodyHead, time.Second))
		}
		si.add(sb.String())
		return nil
	}
	r.tr = tr
	timeout := c.TimeoutS
	if timeout <= 0 {
		timeout = 15
	}
	r.client = &http.Client{Transport: tr, Timeout: time.Duration(timeout * float64(time.Second))}
	return r
}

// readBounded 读正文的前 limit 字节，最多等 wait：CONNECT 的失败响应没有长度信息时，读会一直等到对端关连接。
func readBounded(body io.Reader, limit int64, wait time.Duration) string {
	type out struct {
		b   []byte
		err error
	}
	ch := make(chan out, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(body, limit))
		ch <- out{b, err}
	}()
	select {
	case o := <-ch:
		s := string(o.b)
		if o.err != nil {
			s += fmt.Sprintf("\n（读正文出错：%v）", o.err)
		}
		return s
	case <-time.After(wait):
		return fmt.Sprintf("（等了 %v 没读到正文的结尾，放弃）", wait)
	}
}

func (r *runner) config() string {
	c := r.c
	var sb strings.Builder
	sb.WriteString("tr := http.DefaultTransport.(*http.Transport).Clone()\n")
	sb.WriteString("tr.Proxy = func(req *http.Request) (*url.URL, error) { /* 按 req.Context() 里的用户下标返回下面的 URL 之一；这一步不配凭据时返回不带 userinfo 的那个 */ }\n")
	fmt.Fprintf(&sb, "//   不配凭据：&url.URL{Scheme: %q, Host: %q}\n", r.noUser.Scheme, r.noUser.Host)
	for i, u := range c.Users {
		fmt.Fprintf(&sb, "//   用户 %d：&url.URL{Scheme: %q, Host: %q, User: url.UserPassword(%q, %q)}\n", i, r.noUser.Scheme, r.noUser.Host, u.User, u.Pass)
	}
	sb.WriteString("tr.OnProxyConnectResponse = func(...) error { /* 只旁听，记进 extra_text；一定返回 nil */ }\n")
	fmt.Fprintf(&sb, "client := &http.Client{Transport: tr, Timeout: %v}\n", r.client.Timeout)
	sb.WriteString("// 每个请求：req, _ := http.NewRequestWithContext(ctx, method, url, body); resp, err := client.Do(req)；响应体读到 EOF 再 Close\n")
	sb.WriteString("// POST：body 是 bytes.NewReader(os.ReadFile(body_file))，另设 Content-Type: application/octet-stream；不设其他请求头\n")
	sb.WriteString("// 重定向：Client 的默认行为（跟随，最多 10 跳），follow 为假的步骤也不改\n")
	sb.WriteString("// 并发：每个请求一个 goroutine，共用同一个 client\n")
	fmt.Fprintf(&sb, "// 信任测试 CA：环境变量 SSL_CERT_FILE=%s（进程启动前由 registry.json 的 env 设好）；不设 TLSClientConfig，不设 GODEBUG（当前值 %q）\n",
		os.Getenv("SSL_CERT_FILE"), os.Getenv("GODEBUG"))
	fmt.Fprintf(&sb, "// go.mod 的 go 行与 Go 版本见 versions；用例结束时 tr.CloseIdleConnections()\n")
	if strings.HasPrefix(c.Proxy.Scheme, "socks5") {
		fmt.Fprintf(&sb, "// 代理 URL 的 scheme 照用例原样写 %q。net/http 的文档写明 socks5 与 socks5h 等价，域名总是交给代理解析，做不到“客户端自己解析”\n", c.Proxy.Scheme)
	}
	return sb.String()
}

// errChain 是失败时调用方拿到的全部文字：error 的类型和消息，再沿 Unwrap 一层层往下。
func errChain(err error) string {
	var sb strings.Builder
	for depth := 0; err != nil && depth < 20; depth++ {
		if depth > 0 {
			sb.WriteString("\n" + strings.Repeat("  ", depth) + "Unwrap -> ")
		}
		fmt.Fprintf(&sb, "%T: %v", err, err)
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, e := range joined.Unwrap() {
				fmt.Fprintf(&sb, "\n%s并列 -> %T: %v", strings.Repeat("  ", depth+1), e, e)
			}
			break
		}
		err = errors.Unwrap(err)
	}
	return sb.String()
}

func (r *runner) request(st stepT) (res stepResult) {
	res = stepResult{ID: st.ID, Op: st.Op, OK: ptr(false), Go: map[string]any{}}
	si := &stepInfo{id: st.ID, user: st.User}
	t0 := time.Now()
	finish := func(text string) {
		res.Ms = ptr(time.Since(t0).Milliseconds())
		res.DefaultText = ptr(text)
		if recs := si.take(); len(recs) > 0 {
			var sb strings.Builder
			for i, rec := range recs {
				fmt.Fprintf(&sb, "CONNECT 的响应（这一步发起的第 %d 次拨号）:\n%s\n", i+1, rec)
			}
			res.ExtraText = ptr(sb.String())
			res.ExtraHow = ptr(extraHow)
		}
	}
	defer func() {
		if p := recover(); p != nil {
			finish(fmt.Sprintf("驱动内部出错（panic）：%v\n%s", p, debug.Stack()))
		}
	}()

	ctx := context.WithValue(context.Background(), stepKey{}, si)
	method := st.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if st.BodyFile != "" {
		b, err := os.ReadFile(st.BodyFile)
		if err != nil {
			finish("驱动读不了正文文件：" + errChain(err))
			return res
		}
		body = bytes.NewReader(b)
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, st.URL, body)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, st.URL, nil)
	}
	if err != nil {
		finish("http.NewRequestWithContext 返回错误：\n" + errChain(err))
		return res
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		finish("client.Do 返回错误：\n" + errChain(err))
		return res
	}
	defer resp.Body.Close()
	// 整个正文读到 EOF：HTTP/1.1 的连接这样才会回到空闲池
	data, rerr := io.ReadAll(resp.Body)
	sum := sha256.Sum256(data)
	*res.OK = true
	res.Status = ptr(resp.StatusCode)
	res.BodySHA256 = ptr(hex.EncodeToString(sum[:]))
	res.Go["proto"] = resp.Proto
	res.Go["body_len"] = len(data)
	res.Go["uncompressed"] = resp.Uncompressed
	if resp.Request != nil && resp.Request.URL != nil {
		res.Go["final_url"] = resp.Request.URL.String()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "resp.Proto、resp.Status: %s %s\n", resp.Proto, resp.Status)
	sb.WriteString("resp.Header:\n")
	_ = resp.Header.Write(&sb)
	if len(resp.Trailer) > 0 {
		sb.WriteString("resp.Trailer:\n")
		_ = resp.Trailer.Write(&sb)
	}
	if rerr != nil {
		fmt.Fprintf(&sb, "读 resp.Body 出错（已读到 %d 字节）：\n%s\n", len(data), errChain(rerr))
	}
	fmt.Fprintf(&sb, "resp.Body 前 %d 字节:\n", bodyHead)
	head := data
	if len(head) > bodyHead {
		head = head[:bodyHead]
	}
	sb.WriteString(strings.ToValidUTF8(string(head), "�"))
	finish(sb.String())
	return res
}

func (r *runner) markUnsupported(why string) {
	r.unsupMu.Lock()
	defer r.unsupMu.Unlock()
	if r.unsup == "" {
		r.unsup = why
	}
}

func (r *runner) step(st stepT) stepResult {
	switch st.Op {
	case "request":
		return r.request(st)
	case "sleep":
		time.Sleep(time.Duration(st.Ms) * time.Millisecond)
		return stepResult{ID: st.ID, Op: st.Op, Ms: ptr(int64(st.Ms))}
	case "parallel":
		out := stepResult{ID: st.ID, Op: st.Op, Steps: make([]stepResult, len(st.Steps))}
		t0 := time.Now()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range st.Steps {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				out.Steps[i] = r.step(st.Steps[i])
			}()
		}
		close(start)
		wg.Wait()
		out.Ms = ptr(time.Since(t0).Milliseconds())
		return out
	case "ws":
		why := "Go 标准库没有 WebSocket 客户端（net/http 只有服务端的 Hijacker；客户端要用第三方包，这一列只用标准库）"
		r.markUnsupported(why)
		return stepResult{ID: st.ID, Op: st.Op, OK: ptr(false), DefaultText: ptr(why)}
	default:
		why := fmt.Sprintf("驱动不认识的步骤类型：%q", st.Op)
		r.markUnsupported(why)
		return stepResult{ID: st.ID, Op: st.Op, OK: ptr(false), DefaultText: ptr(why)}
	}
}

func runCase(c *caseT) (res *resultT) {
	res = &resultT{Variant: c.Variant, Versions: versions(), Steps: []stepResult{}, Notes: []string{}}
	if res.Variant == "" {
		res.Variant = "go"
	}
	defer func() {
		if p := recover(); p != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("驱动内部出错（panic）：%v\n%s", p, debug.Stack()))
		}
	}()
	if got := os.Getenv("SSL_CERT_FILE"); got != c.CAFile {
		res.Notes = append(res.Notes, fmt.Sprintf("环境变量 SSL_CERT_FILE（%q）与用例的 ca_file（%q）不同；驱动没有改它", got, c.CAFile))
	}
	switch c.Proxy.Scheme {
	case "http", "socks5", "socks5h":
	default:
		res.Unsupported = ptr(fmt.Sprintf("驱动不认识的代理类型：%q", c.Proxy.Scheme))
		return res
	}
	r := newRunner(c)
	res.Config = ptr(r.config())
	res.Notes = append(res.Notes,
		"default_text 成功时是 resp.Proto、resp.Status、resp.Header（net/http 已经去掉了 Transfer-Encoding 等逐跳的头，并可能自动解压）和正文前 4096 字节；"+
			"失败时是 client.Do 返回的 error：类型和消息，再沿 errors.Unwrap 逐层列出。",
		"OnProxyConnectResponse 的记录按发起拨号的那一步归档。并发或连接被别的请求抢先用掉时，一个请求实际走的隧道可能是另一步拨出来的。",
	)
	for _, st := range c.Steps {
		res.Steps = append(res.Steps, r.step(st))
	}
	r.tr.CloseIdleConnections()
	if r.unsup != "" {
		res.Unsupported = ptr(r.unsup)
	}
	return res
}

func writeResult(path string, res *resultT) error {
	data, err := json.MarshalIndent(res, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func main() {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--versions" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(versions()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "用法：driver <用例.json> <结果.json>   或   driver --versions")
		os.Exit(2)
	}
	var c caseT
	var res *resultT
	raw, err := os.ReadFile(args[0])
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err != nil {
		res = &resultT{Variant: "go", Versions: versions(), Steps: []stepResult{},
			Notes: []string{"驱动读不了用例文件：" + errChain(err)}}
	} else {
		res = runCase(&c)
	}
	if err := writeResult(args[1], res); err != nil {
		fmt.Fprintln(os.Stderr, "写不了结果文件：", err)
		os.Exit(1)
	}
}
