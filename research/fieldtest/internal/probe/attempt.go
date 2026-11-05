// Package probe 是探测器：把 wire 包里的单步动作排成一次次探访，调度几万个候选地址，
// 并把每一条连接的结果原样记下来。
package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/judge"
	"fieldtest/internal/nonce"
	"fieldtest/internal/payload"
	"fieldtest/internal/rec"
	"fieldtest/internal/wire"
)

// 探测用的协议名。
const (
	Socks5   = "socks5"
	Socks4   = "socks4"
	Connect  = "connect"  // HTTP CONNECT 隧道
	Forward  = "forward"  // HTTP 代理的普通转发（请求行写绝对 URI）
	TLSProxy = "tlsproxy" // 只做一件事：看代理端口本身是不是说 TLS
	Node     = "node"     // 经本机 sing-box 旁路进程访问一个订阅节点
	Direct   = "direct"   // 不经任何代理直接访问目的地：对照组
)

// 目的地。
const (
	DstJudgeTLS  = "judge_tls"
	DstJudgeHTTP = "judge_http"
	DstSelf      = "self"
)

// Attempt 是一条连接的完整记录：每个阶段成功与否、失败在哪一步、归为哪一类。
type Attempt struct {
	TS    string        `json:"ts"`
	K     string        `json:"k"` // att
	Visit string        `json:"visit"`
	Cand  string        `json:"cand"` // 代理的 ip:port，或节点的标识
	Proto string        `json:"proto"`
	Dst   string        `json:"dst"`
	Kind  string        `json:"kind,omitempty"` // 载荷种类 h / j / b
	Arm   string        `json:"arm,omitempty"`  // 节点探测的分组：strict 或 as_linked
	Nonce string        `json:"nonce,omitempty"`
	TCP   *wire.Step    `json:"tcp,omitempty"`
	HS    *wire.Step    `json:"hs,omitempty"`
	TLS   *wire.TLSInfo `json:"tls,omitempty"`
	HTTP  *HTTPResult   `json:"http,omitempty"`
	Class string        `json:"class"`        // ok，或第一个失败阶段的类别
	IP    string        `json:"ip,omitempty"` // 出口地址：judge 在响应头里回显的，或第二观察者报告的
	Ev    string        `json:"ev,omitempty"` // 证书链证据的哈希
	Ms    int64         `json:"ms"`
}

// HTTPResult 是 HTTP 阶段的结果。
type HTTPResult struct {
	wire.Step
	Len    int               `json:"len,omitempty"`
	SHA    string            `json:"sha,omitempty"`    // 正文哈希，只在与期望不符时记录
	Pre    int               `json:"pre,omitempty"`    // 与期望正文的公共前缀长度
	Suf    int               `json:"suf,omitempty"`    // 公共后缀长度
	Sim    int               `json:"sim,omitempty"`    // 与期望正文的相似度（百分比），见 Similarity
	Canary string            `json:"canary,omitempty"` // 响应头里的金丝雀：ok / missing / bad
	Flags  []string          `json:"flags,omitempty"`  // 正文无误但响应头被动过：csp_missing、cookie_missing 等
	Added  []string          `json:"added,omitempty"`  // judge 没发、却出现在响应里的头
	Hdr    map[string]string `json:"hdr,omitempty"`    // 非 200 响应的几个头，用来认代理软件
	Ev     string            `json:"ev,omitempty"`     // 正文证据的哈希
}

// Env 是探测时共用的环境。
type Env struct {
	Cfg      *cfg.Config
	Secret   []byte
	Payload  *payload.Set
	Ev       *rec.Evidence
	Log      *rec.Writer
	Lim      *Limiter
	Sink     func(any) // 可选：每条记录落盘的同时也交给它，自测用
	JudgeIP  netip.Addr
	ObsRoots *x509.CertPool // 校验第二观察者用的根证书；nil 表示系统根证书
	trust    atomic.Pointer[judge.Trust]
	seq      atomic.Uint64
}

func NewEnv(c *cfg.Config, secret []byte, log *rec.Writer, ev *rec.Evidence) (*Env, error) {
	e := &Env{Cfg: c, Secret: secret, Payload: payload.Build(c.Judge.Host), Ev: ev, Log: log}
	e.JudgeIP, _ = netip.ParseAddr(c.Judge.PublicIP)
	if err := e.ReloadTrust(); err != nil {
		return nil, err
	}
	return e, nil
}

// ReloadTrust 重新读 judge 的证书。公开证书会续期，所以要定期重读。
func (e *Env) ReloadTrust() error {
	t, err := judge.LoadTrust(e.Cfg)
	if err != nil {
		return err
	}
	e.trust.Store(t)
	return nil
}

func (e *Env) dialTimeout() time.Duration {
	return time.Duration(e.Cfg.Probe.DialTimeoutSec) * time.Second
}
func (e *Env) ioTimeout() time.Duration { return time.Duration(e.Cfg.Probe.IOTimeoutSec) * time.Second }

// Panic 把一次程序错误连同调用栈记进日志。
func (e *Env) Panic(what string, r any) {
	stack := string(debug.Stack())
	if len(stack) > 3000 {
		stack = stack[:3000]
	}
	e.Log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "error", "what": "程序错误: " + what,
		"err": fmt.Sprint(r), "stack": stack})
	e.Log.Flush()
}

// NewVisitID 返回一个本次运行内唯一的探访编号。
func (e *Env) NewVisitID() string {
	return strconv.FormatInt(time.Now().Unix(), 36) + "-" + strconv.FormatUint(e.seq.Add(1), 36)
}

// Run 执行一次尝试并落盘。addr 是要连接的代理地址；auth 只在连本机旁路进程时使用；
// obs 非空时目的地是第二观察者。
func (e *Env) Run(ctx context.Context, a *Attempt, addr string, auth *wire.Socks5Auth, obs *cfg.Observer) {
	// 先排队领连接配额，再开始计时：排队的时间不算在这次尝试的耗时里
	if e.Lim != nil {
		if err := e.Lim.Wait(ctx); err != nil {
			a.TS, a.K, a.Class = rec.TS(time.Now()), "att", "canceled"
			e.Log.Write(a)
			return
		}
	}
	t0 := time.Now()
	a.TS, a.K = rec.TS(t0), "att"
	e.run(ctx, a, addr, auth, obs)
	if a.Class == "" {
		a.Class = "ok"
	}
	a.Ms = time.Since(t0).Milliseconds()
	e.Log.Write(a)
	if e.Sink != nil {
		e.Sink(a)
	}
}

func (e *Env) run(ctx context.Context, a *Attempt, addr string, auth *wire.Socks5Auth, obs *cfg.Observer) {
	var host string
	var ip netip.Addr
	var port int
	tlsDst := true
	switch {
	case obs != nil:
		host, port = obs.Host, obs.Port
		if port == 0 {
			port = 443
		}
	case a.Dst == DstJudgeHTTP:
		host, ip, port, tlsDst = e.Cfg.Judge.Host, e.JudgeIP, e.Cfg.Judge.HTTPPort, false
	case a.Dst == DstJudgeTLS:
		host, ip, port = e.Cfg.Judge.Host, e.JudgeIP, e.Cfg.Judge.HTTPSPort
	}
	conn, st := wire.Dial(ctx, addr, e.dialTimeout(), nil)
	a.TCP = &st
	if !st.OK {
		a.Class = st.Class
		return
	}
	defer conn.Close()
	iot := e.ioTimeout()
	tun := net.Conn(conn)

	switch a.Proto {
	case Socks5, Node:
		greet := iot
		if a.Proto == Socks5 {
			// 问候只需一个来回：按建连耗时的 6 倍给时限，最少 4 秒
			greet = max(4*time.Second, 6*time.Duration(st.Ms)*time.Millisecond)
		}
		hs := wire.Socks5(conn, host, port, auth, greet, iot)
		a.HS = &hs
	case Socks4:
		if !ip.IsValid() {
			a.Class = "skipped_needs_ip"
			return
		}
		hs := wire.Socks4(conn, ip, port, iot)
		a.HS = &hs
	case Connect:
		hs, c2 := wire.HTTPConnect(conn, net.JoinHostPort(host, strconv.Itoa(port)), wire.UA, iot)
		a.HS = &hs
		if c2 != nil {
			tun = c2
		}
	case Forward, Direct:
		// 没有握手阶段：Forward 把请求直接发给代理，Direct 的 addr 就是目的地本身
	case TLSProxy:
		// 代理端口本身说不说 TLS。列表只给了 IP，所以按 IP 校验证书；几乎一定校验不过，
		// 我们要的只是“它是不是 TLS 服务、给出的是什么证书”，握手到此为止，不发任何数据。
		ipHost, _, _ := net.SplitHostPort(addr)
		_, info, chain := wire.TLS(conn, wire.TLSOpts{ServerName: ipHost, Timeout: iot})
		a.TLS = &info
		a.Ev = e.Ev.Put(a.Cand, "der", chain, 32<<10)
		if !info.OK {
			a.Class = info.Class
		}
		return
	}
	if a.HS != nil && !a.HS.OK {
		a.Class = a.HS.Class
		return
	}
	if a.Proto == Forward {
		e.fetchJudge(a, conn, true)
		return
	}
	if tlsDst {
		opts := wire.TLSOpts{ServerName: host, Timeout: iot, Roots: e.ObsRoots}
		if obs == nil {
			tr := e.trust.Load()
			opts.Roots, opts.SPKIPin = tr.Roots, tr.SPKIPin
		}
		tc, info, chain := wire.TLS(tun, opts)
		a.TLS = &info
		if !info.OK {
			a.Class = info.Class
			a.Ev = e.Ev.Put(a.Cand, "der", chain, 32<<10)
			return
		}
		tun = tc
	}
	if obs != nil {
		e.fetchObserver(a, tun, obs)
		return
	}
	e.fetchJudge(a, tun, false)
}

// 判断响应头是否被动过时，这些是 judge 自己会发的头。
var judgeHeaders = map[string]bool{
	"Connection": true, "Cache-Control": true, "X-Judge-Remote": true, "X-Judge-Canary": true, "Set-Cookie": true,
	"Content-Security-Policy": true, "Content-Type": true, "Content-Length": true, "Date": true,
}

func (e *Env) fetchJudge(a *Attempt, conn net.Conn, absolute bool) {
	kind := payload.Kind(a.Kind)
	if kind == "" {
		kind = payload.HTML
		a.Kind = string(kind)
	}
	pl := e.Payload.Get(kind)
	n := nonce.New(e.Secret, time.Now())
	a.Nonce = n
	resp, st := wire.Get(conn, wire.GetSpec{
		Absolute:  absolute,
		Authority: e.Cfg.JudgeAuthority(a.Dst == DstJudgeTLS),
		Path:      "/p/" + string(kind) + "/" + n,
		Canary:    nonce.Canary(e.Secret, "req", n),
		Timeout:   e.ioTimeout(),
		MaxBody:   256 << 10,
	})
	r := &HTTPResult{Step: st}
	a.HTTP = r
	if !st.OK {
		a.Class = st.Class
		return
	}
	r.Len = len(resp.Body)
	h := resp.Header
	fail := func(class string) {
		r.OK, r.Class = false, class
		a.Class = class
	}
	if resp.Status != 200 {
		fail("http_status")
		r.Hdr = pick(h, "Server", "Via", "X-Squid-Error", "Proxy-Agent", "X-Cache", "Content-Type", "Location",
			"Proxy-Authenticate", "Www-Authenticate")
		r.Ev = e.Ev.Put(a.Cand, "body", resp.Body, 4<<10)
		return
	}
	body := resp.Body
	if strings.EqualFold(h.Get("Content-Encoding"), "gzip") && !resp.Partial {
		// 我们声明了只接受 identity，代理仍然压缩了。解开再比：内容没变就不算篡改，只记一笔
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if dec, err := io.ReadAll(io.LimitReader(zr, 1<<20)); err == nil {
				body = dec
				r.Flags = append(r.Flags, "gzip_added")
			}
		}
	}
	if sha := wire.SHA256Hex(body); sha != pl.SHA256 || resp.Partial {
		fail("http_body_mismatch")
		r.SHA = sha
		r.Pre, r.Suf = wire.CommonAffix(body, pl.Body)
		r.Sim = Similarity(kind, body, pl.Body, r.Pre, r.Suf)
		r.Hdr = pick(h, "Server", "Via", "X-Cache", "Content-Type", "Content-Encoding")
		r.Ev = e.Ev.Put(a.Cand, "body", resp.Body, 256<<10)
		return
	}
	want := nonce.Canary(e.Secret, "resp", n)
	switch got := h.Get("X-Judge-Canary"); {
	case got == want:
		r.Canary = "ok"
	case got == "":
		r.Canary = "missing"
	default:
		r.Canary = "bad"
	}
	if r.Canary != "ok" {
		// 正文对，但这不是 judge 对这次请求的应答：要么是缓存或伪造的，要么头被删了
		fail("http_canary_" + r.Canary)
		return
	}
	if kind == payload.HTML {
		switch csp := h.Get("Content-Security-Policy"); {
		case csp == "":
			r.Flags = append(r.Flags, "csp_missing")
		case csp != "default-src 'self'; script-src 'self'":
			r.Flags = append(r.Flags, "csp_changed")
		}
	}
	switch ck := h.Get("Set-Cookie"); {
	case ck == "":
		r.Flags = append(r.Flags, "cookie_missing")
	case ck != "jc="+want+"; Path=/; HttpOnly":
		r.Flags = append(r.Flags, "cookie_changed")
	}
	for k := range h {
		if !judgeHeaders[k] && len(r.Added) < 12 {
			r.Added = append(r.Added, k)
		}
	}
	sort.Strings(r.Added)
	if rem := h.Get("X-Judge-Remote"); rem != "" {
		if host, _, err := net.SplitHostPort(rem); err == nil {
			a.IP = host
		}
	}
}

func (e *Env) fetchObserver(a *Attempt, conn net.Conn, obs *cfg.Observer) {
	resp, st := wire.Get(conn, wire.GetSpec{Authority: obs.Host, Path: obs.Path, Timeout: e.ioTimeout(), MaxBody: 8 << 10})
	r := &HTTPResult{Step: st}
	a.HTTP = r
	if !st.OK {
		a.Class = st.Class
		return
	}
	r.Len = len(resp.Body)
	if resp.Status != 200 {
		r.OK, r.Class = false, "http_status"
		a.Class = r.Class
		return
	}
	ip := ParseObserver(obs.Parse, resp.Body)
	if !ip.IsValid() {
		r.OK, r.Class = false, "obs_unparsed"
		a.Class = r.Class
		r.Ev = e.Ev.Put(a.Cand, "body", resp.Body, 2<<10)
		return
	}
	a.IP = ip.String()
}

// ParseObserver 从第二观察者的响应里取出它看到的地址。
func ParseObserver(mode string, body []byte) netip.Addr {
	s := strings.TrimSpace(string(body))
	if mode == "kv" {
		for _, line := range strings.Split(s, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
				s = v
				break
			}
		}
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func pick(h map[string][]string, names ...string) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		if v := h[n]; len(v) > 0 {
			s := v[0]
			if len(s) > 120 {
				s = s[:120]
			}
			out[n] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Similarity 衡量收到的正文与期望的正文有多像（0 到 100）。
// 文本载荷看期望正文里有多少行原样出现；二进制载荷没有行，看公共前缀和后缀合计占多少。
func Similarity(kind payload.Kind, got, want []byte, pre, suf int) int {
	if kind == payload.Bin {
		if len(want) == 0 {
			return 0
		}
		return min(100, 100*(pre+suf)/len(want))
	}
	return wire.LineSimilarity(got, want)
}
