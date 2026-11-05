// Package selftest 是探测器的仪器自检。
//
// 它在本机回环地址上启动 judge、两个假的第二观察者和三十来个代理夹具（有规矩的，也有各种作恶的），
// 让探测器按正式流程逐个探访，然后核对：每个夹具做了什么，探测器是否如实报告。
// 正式测量之前先在同一台机器上跑一遍，任何一项不符都说明仪器有问题，数据不可信。
package selftest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/evil"
	"fieldtest/internal/judge"
	"fieldtest/internal/lists"
	"fieldtest/internal/nonce"
	"fieldtest/internal/probe"
	"fieldtest/internal/rec"
	"fieldtest/internal/summary"
)

type want struct {
	att   string // 协议>目的地[:载荷种类]
	class string // 期望的类别；用 | 分隔的几个值任一即可
	check func(a *probe.Attempt, d summary.Derived) string
}

type testCase struct {
	name, label string
	b           evil.Behavior
	closed      bool
	wants       []want
	second      []want // 第二次探访（不做完整识别）时的期望
	state       string
	ok          string // 期望通过校验的协议，空格分隔
	auth        bool
	only        int // 非零时，第一次探访的尝试数必须正好是这个数
}

func w(att, class string) want { return want{att: att, class: class} }
func ok(att string) want       { return want{att: att, class: "ok"} }
func wc(att, class string, f func(a *probe.Attempt, d summary.Derived) string) want {
	return want{att: att, class: class, check: f}
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func cases(httpsPort, obsPort int, resolve map[string]string) []testCase {
	hb := func(b evil.Behavior) evil.Behavior { b.Resolve = resolve; return b }
	const (
		fwd  = "forward>judge_http:h"
		con  = "connect>judge_tls:h"
		s5   = "socks5>judge_tls:h"
		s4   = "socks4>judge_tls:h"
		con8 = "connect>judge_http:h"
	)
	gone := "eof|reset" // 对端直接断开：先收到 FIN 还是 RST 取决于时序
	return []testCase{
		{name: "http-honest", label: "http", b: hb(evil.Behavior{Proto: "http"}), state: "working", ok: "connect forward",
			wants: []want{
				wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
					switch {
					case !d.Seen:
						return "judge 没有记录到这次请求"
					case d.Egress != "127.0.0.1" || a.IP != "127.0.0.1":
						return "出口地址不对: judge=" + d.Egress + " 带内=" + a.IP
					case d.Anonymity != "elite" || len(d.Tamper) > 0 || len(d.AddedReq) > 0:
						return fmt.Sprintf("规矩的代理被判为改动了请求: %v %v %s", d.Tamper, d.AddedReq, d.Anonymity)
					case d.Copies != 1:
						return "judge 收到的份数不是 1"
					case len(a.HTTP.Flags) > 0 || len(a.HTTP.Added) > 0:
						return fmt.Sprintf("规矩的代理被判为改动了响应头: %v %v", a.HTTP.Flags, a.HTTP.Added)
					}
					return ""
				}),
				// HTTP 代理收到 SOCKS 的字节会一直等请求行，所以这两项是超时而不是“协议不符”
				ok(con), w(s5, "hs_timeout"), w(s4, "hs_timeout"),
				ok("connect>obs:kv"), ok("connect>obs:plain"), ok("forward>judge_http:j"), ok("forward>judge_http:b"), ok(con8),
			}},
		{name: "socks5-honest", label: "socks5", b: hb(evil.Behavior{Proto: "socks5"}), state: "working", ok: "socks5",
			wants: []want{ok(s5), w(con, "hs_"+gone), w(fwd, "http_"+gone), w(s4, "hs_"+gone),
				wc("socks5>obs:kv", "ok", func(a *probe.Attempt, d summary.Derived) string {
					if a.IP != "127.0.0.1" {
						return "第二观察者报告的地址不对: " + a.IP
					}
					return ""
				}),
				ok("socks5>obs:plain"), ok("socks5>judge_http:h")}},
		{name: "socks4-honest", label: "socks4", b: hb(evil.Behavior{Proto: "socks4"}), state: "working", ok: "socks4",
			wants: []want{ok(s4), w(s5, "hs_timeout"), w(con, "hs_"+gone), w(fwd, "http_"+gone), ok("socks4>judge_http:h")}},
		{name: "http-forward-only", label: "http", b: hb(evil.Behavior{Proto: "http", NoConnect: true}), state: "working", ok: "forward",
			wants: []want{ok(fwd), wc(con, "hs_refused", func(a *probe.Attempt, d summary.Derived) string {
				if a.HS.Code != 405 {
					return "状态码不是 405"
				}
				return ""
			})}},
		{name: "http-connect-443-only", label: "https", state: "working", ok: "connect forward",
			b: hb(evil.Behavior{Proto: "http", ConnectPorts: map[int]bool{httpsPort: true, obsPort: true}}),
			wants: []want{ok(con), ok(fwd), ok("connect>obs:kv"),
				wc(con8, "hs_refused", func(a *probe.Attempt, d summary.Derived) string {
					if a.HS.Code != 403 {
						return "状态码不是 403"
					}
					return ""
				}),
				w("tlsproxy>self", "tls_not_tls")}},
		{name: "http-inject", label: "http", b: hb(evil.Behavior{Proto: "http", RespHook: evil.InjectScript}), state: "working", ok: "connect",
			wants: []want{wc(fwd, "http_body_mismatch", func(a *probe.Attempt, d summary.Derived) string {
				if a.HTTP.Pre < 1000 || a.HTTP.Suf < 8 || a.HTTP.Ev == "" {
					return fmt.Sprintf("注入的特征没记下来: pre=%d suf=%d ev=%q", a.HTTP.Pre, a.HTTP.Suf, a.HTTP.Ev)
				}
				if got := summary.BodyChange(a.Kind, a.HTTP.Len, a.HTTP.Pre, a.HTTP.Sim, 1<<20); got != "正文被局部改动（注入或改写）" {
					return fmt.Sprintf("注入脚本应判为局部改动，实际 %s（sim=%d%%）", got, a.HTTP.Sim)
				}
				return ""
			}), ok(con), ok("forward>judge_http:j"), ok("forward>judge_http:b")}},
		{name: "http-adswap", label: "http", b: hb(evil.Behavior{Proto: "http", RespHook: evil.SwapAdID}), state: "working", ok: "connect",
			wants: []want{w(fwd, "http_body_mismatch"), ok(con)}},
		{name: "http-sslstrip", label: "http", b: hb(evil.Behavior{Proto: "http", RespHook: evil.StripHTTPS}), state: "working", ok: "connect",
			wants: []want{wc(fwd, "http_body_mismatch", func(a *probe.Attempt, d summary.Derived) string {
				// 改动散布在全页，公共前后缀都很短，但大部分行原样保留：应判为局部改动而不是整页替换
				if got := summary.BodyChange(a.Kind, a.HTTP.Len, a.HTTP.Pre, a.HTTP.Sim, 1<<20); got != "正文被局部改动（注入或改写）" {
					return fmt.Sprintf("https 被改成 http 应判为局部改动，实际 %s（sim=%d%%）", got, a.HTTP.Sim)
				}
				return ""
			}), ok(con)}},
		{name: "http-strip-headers", label: "http", b: hb(evil.Behavior{Proto: "http", RespHook: evil.StripSecurityHeaders}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				if !has(a.HTTP.Flags, "csp_missing") || !has(a.HTTP.Flags, "cookie_missing") {
					return fmt.Sprintf("没发现安全头被删: %v", a.HTTP.Flags)
				}
				return ""
			})}},
		{name: "http-add-headers", label: "http", b: hb(evil.Behavior{Proto: "http", RespHook: evil.AddProxyHeaders}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				if strings.Join(a.HTTP.Added, " ") != "Via X-Cache" {
					return fmt.Sprintf("没发现代理加的响应头: %v", a.HTTP.Added)
				}
				return ""
			})}},
		{name: "http-gzip", label: "http", b: hb(evil.Behavior{Proto: "http", RespHook: evil.GzipBody}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				if !has(a.HTTP.Flags, "gzip_added") {
					return fmt.Sprintf("没记下代理擅自压缩: %v", a.HTTP.Flags)
				}
				return ""
			}), ok("forward>judge_http:b")}},
		{name: "http-transparent", label: "http", b: hb(evil.Behavior{Proto: "http", ReqHook: evil.LeakClientIP}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				if !d.LeakIP || d.Anonymity != "transparent" || !has(d.AddedReq, "X-Forwarded-For") || !has(d.AddedReq, "Via") {
					return fmt.Sprintf("没发现客户端地址泄露: leak=%v anon=%s added=%v", d.LeakIP, d.Anonymity, d.AddedReq)
				}
				return ""
			})}},
		{name: "http-anonymous", label: "http", b: hb(evil.Behavior{Proto: "http", ReqHook: evil.AnonymousVia}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				if d.LeakIP || d.Anonymity != "anonymous" {
					return fmt.Sprintf("匿名级别判错: leak=%v anon=%s", d.LeakIP, d.Anonymity)
				}
				return ""
			})}},
		{name: "http-reqtamper", label: "http", b: hb(evil.Behavior{Proto: "http", ReqHook: evil.TamperRequest}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				for _, t := range []string{"canary_missing", "cookie_missing", "user_agent_changed"} {
					if !has(d.Tamper, t) {
						return fmt.Sprintf("没发现请求被改（%s）: %v", t, d.Tamper)
					}
				}
				return ""
			})}},
		{name: "connect-mitm", label: "https", b: hb(evil.Behavior{Proto: "http", MITM: true}), state: "working", ok: "forward",
			wants: []want{wc(con, "tls_cert_invalid", func(a *probe.Attempt, d summary.Derived) string {
				switch {
				case a.Nonce != "" || a.HTTP != nil:
					return "证书校验失败后仍然发出了请求"
				case !a.TLS.SelfSigned || a.TLS.Leaf == "" || a.Ev == "":
					return "中间人的证书没记下来"
				}
				return ""
			}), ok(fwd), w("tlsproxy>self", "tls_not_tls")}},
		{name: "socks5-mitm", label: "socks5", b: hb(evil.Behavior{Proto: "socks5", MITM: true}), state: "open",
			wants: []want{w(s5, "tls_cert_invalid")}},
		{name: "webserver", label: "http", b: evil.Behavior{Raw: evil.WebServer}, state: "open",
			wants: []want{wc(fwd, "http_body_mismatch", func(a *probe.Attempt, d summary.Derived) string {
				if got := summary.BodyChange(a.Kind, a.HTTP.Len, a.HTTP.Pre, a.HTTP.Sim, 1<<20); got != "正文被整页替换" {
					return fmt.Sprintf("别的网站的页面应判为整页替换，实际 %s（sim=%d%%）", got, a.HTTP.Sim)
				}
				return ""
			}), wc(con, "tls_not_tls", func(a *probe.Attempt, d summary.Derived) string {
				if a.HS.Detail != "200_with_body" {
					return "没记下 CONNECT 的 200 带着正文"
				}
				return ""
			}), w(s5, "hs_timeout"), w(s4, "hs_timeout")}},
		{name: "connect-ok-then-close", label: "https", b: hb(evil.Behavior{Proto: "http", CloseAfterOK: true}), state: "working", ok: "forward",
			wants: []want{w(con, "tls_"+gone), ok(fwd)}},
		{name: "socks5-liar", label: "socks5", state: "open",
			b:     hb(evil.Behavior{Proto: "socks5", AfterOK: []byte("<html><body>blocked</body></html>")}),
			wants: []want{w(s5, "tls_not_tls")}},
		{name: "tarpit", label: "socks5", b: evil.Behavior{Raw: evil.Tarpit}, state: "open",
			wants: []want{w(s5, "hs_timeout"), w(con, "hs_timeout"), w(fwd, "http_timeout"), w(s4, "hs_timeout")}},
		{name: "ssh-banner", label: "socks5", b: evil.Behavior{Raw: evil.Banner("SSH-2.0-OpenSSH_9.6\r\n")}, state: "open",
			wants: []want{wc(s5, "hs_not_proto", func(a *probe.Attempt, d summary.Derived) string {
				if a.HS.Sniff != "ssh" {
					return "没认出 SSH: " + a.HS.Sniff
				}
				return ""
			}), w(con, "hs_not_proto"), w(fwd, "http_malformed"), w(s4, "hs_not_proto")}},
		{name: "garbage", label: "socks4", b: evil.Behavior{Raw: evil.Garbage}, state: "open",
			wants: []want{w(s4, "hs_not_proto"), w(s5, "hs_not_proto"), w(con, "hs_not_proto"), w(fwd, "http_malformed")}},
		{name: "auth-http", label: "http", b: hb(evil.Behavior{Proto: "http", Auth: true}), state: "open", auth: true,
			wants: []want{wc(fwd, "http_status", func(a *probe.Attempt, d summary.Derived) string {
				if a.HTTP.Code != 407 {
					return "状态码不是 407"
				}
				return ""
			}), w(con, "hs_auth")}},
		{name: "auth-socks5", label: "socks5", b: hb(evil.Behavior{Proto: "socks5", Auth: true}), state: "open", auth: true,
			wants: []want{w(s5, "hs_auth")}},
		{name: "closed", label: "socks5", closed: true, state: "dead", only: 1,
			wants: []want{w(s5, "tcp_refused")}},
		{name: "egress-other", label: "http", b: hb(evil.Behavior{Proto: "http", EgressIP: "127.0.0.2"}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				if a.IP != "127.0.0.2" || d.Egress != "127.0.0.2" {
					return "出口地址应为 127.0.0.2: judge=" + d.Egress + " 带内=" + a.IP
				}
				return ""
			}), wc("connect>obs:plain", "ok", func(a *probe.Attempt, d summary.Derived) string {
				if a.IP != "127.0.0.2" {
					return "第二观察者应报告 127.0.0.2: " + a.IP
				}
				return ""
			})}},
		{name: "http-truncate", label: "http", b: hb(evil.Behavior{Proto: "http", Truncate: 1000}), state: "working", ok: "connect",
			wants: []want{wc(fwd, "http_body_mismatch", func(a *probe.Attempt, d summary.Derived) string {
				if a.HTTP.Pre != 1000 || a.HTTP.Len != 1000 {
					return fmt.Sprintf("截断的特征不对: pre=%d len=%d", a.HTTP.Pre, a.HTTP.Len)
				}
				if got := summary.BodyChange(a.Kind, a.HTTP.Len, a.HTTP.Pre, a.HTTP.Sim, 1<<20); got != "正文被截断" {
					return "截断被判成了 " + got
				}
				return ""
			}), ok(con)}},
		{name: "http-cache", label: "http", b: hb(evil.Behavior{Proto: "http", CacheReplay: true}), state: "working", ok: "connect forward",
			wants:  []want{ok(fwd), ok(con), w("forward>judge_http:j", "http_body_mismatch")},
			second: []want{w(fwd, "http_canary_bad"), ok(con)}},
		{name: "http-replay", label: "http", b: hb(evil.Behavior{Proto: "http", Replay: 2}), state: "working", ok: "connect forward",
			wants: []want{wc(fwd, "ok", func(a *probe.Attempt, d summary.Derived) string {
				if d.Copies != 3 {
					return fmt.Sprintf("judge 应收到 3 份请求，实际 %d", d.Copies)
				}
				return ""
			})}},
		{name: "http-302", label: "http", state: "working", ok: "connect",
			b: hb(evil.Behavior{Proto: "http", Status: 302, StatusHeader: map[string]string{"Location": "http://ads.example/landing"}}),
			wants: []want{wc(fwd, "http_status", func(a *probe.Attempt, d summary.Derived) string {
				if a.HTTP.Code != 302 || a.HTTP.Hdr["Location"] == "" {
					return "没记下 302 和跳转地址"
				}
				return ""
			}), ok(con)}},
		{name: "slow", label: "http", b: hb(evil.Behavior{Proto: "http", Delay: 700 * time.Millisecond}), state: "working", ok: "connect forward",
			wants: []want{ok(fwd), ok(con)}},
		{name: "too-slow", label: "http", b: hb(evil.Behavior{Proto: "http", Delay: 4 * time.Second}), state: "open",
			wants: []want{w(fwd, "http_timeout"), w(con, "hs_timeout")}},
		{name: "socks5-labelled-http", label: "http", b: hb(evil.Behavior{Proto: "socks5"}), state: "working", ok: "socks5",
			wants: []want{w(fwd, "http_"+gone), w(con, "hs_"+gone), ok(s5)}},
	}
}

func key(a *probe.Attempt) string {
	k := a.Proto + ">" + a.Dst
	if a.Kind != "" {
		k += ":" + a.Kind
	}
	return k
}

func classOK(got, want string) bool {
	prefix := ""
	if i := strings.Index(want, "_"); i >= 0 && strings.Contains(want, "|") {
		prefix, want = want[:i+1], want[i+1:]
	}
	for _, alt := range strings.Split(want, "|") {
		if got == prefix+alt {
			return true
		}
	}
	return false
}

// Run 执行自检，把结果写到 out。全部通过时返回 true。
// singbox 是 sing-box 可执行文件的路径；为空时跳过节点探测的自检。
func Run(out io.Writer, verbose bool, singbox string) (bool, error) {
	dir, err := os.MkdirTemp("", "fieldtest-selftest-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(dir)

	c := cfg.Default()
	c.DataDir = dir
	c.Judge = cfg.Judge{Host: "judge.test", PublicIP: "127.0.0.1", HTTPListen: "127.0.0.1:0", HTTPSListen: "127.0.0.1:0"}
	c.AllowLocal = true
	c.Probe.DialTimeoutSec, c.Probe.IOTimeoutSec, c.Probe.ConnPerSec = 2, 2, 1000
	secret := nonce.NewSecret()

	jlog, err := rec.NewWriter(dir, "judge")
	if err != nil {
		return false, err
	}
	defer jlog.Close()
	js, err := judge.New(c, secret, jlog)
	if err != nil {
		return false, err
	}
	if err := js.Start(); err != nil {
		return false, err
	}
	defer js.Close()
	c.Judge.HTTPPort, c.Judge.HTTPSPort = portOf(js.HTTPAddr), portOf(js.HTTPSAddr)
	c.Judge.HTTPListen, c.Judge.HTTPSListen = js.HTTPAddr, js.HTTPSAddr

	obsLn, obsRoots, _, err := StartObserver()
	if err != nil {
		return false, err
	}
	defer obsLn.Close()
	obsPort := portOf(obsLn.Addr().String())
	c.Observers = []cfg.Observer{
		{Name: "kv", Host: "obs1.test", Port: obsPort, Path: "/cdn-cgi/trace", Parse: "kv"},
		{Name: "plain", Host: "obs2.test", Port: obsPort, Path: "/", Parse: "plain"},
	}
	resolve := map[string]string{"judge.test": "127.0.0.1", "obs1.test": "127.0.0.1", "obs2.test": "127.0.0.1"}

	plog, err := rec.NewWriter(dir, "probe")
	if err != nil {
		return false, err
	}
	defer plog.Close()
	env, err := probe.NewEnv(c, secret, plog, rec.NewEvidence(dir+"/evidence"))
	if err != nil {
		return false, err
	}
	env.ObsRoots = obsRoots
	var mu sync.Mutex
	atts := map[string][]*probe.Attempt{}
	visits := map[string][]*probe.VisitRec{}
	env.Sink = func(v any) {
		mu.Lock()
		defer mu.Unlock()
		switch r := v.(type) {
		case *probe.Attempt:
			atts[r.Cand] = append(atts[r.Cand], r)
		case *probe.VisitRec:
			cp := *r
			visits[r.Cand] = append(visits[r.Cand], &cp)
		}
	}
	slog, err := rec.NewWriter(dir, "snap")
	if err != nil {
		return false, err
	}
	defer slog.Close()
	pr := probe.NewProber(env, &lists.Sources{}, slog)
	ctx := context.Background()

	// 对照：不经代理直接访问 judge，拿到 TLS 指纹的基线
	base := []*probe.Attempt{
		{Visit: "ctl", Cand: "control", Proto: probe.Direct, Dst: probe.DstJudgeTLS, Kind: "h"},
		{Visit: "ctl", Cand: "control", Proto: probe.Direct, Dst: probe.DstJudgeHTTP, Kind: "h"},
	}
	env.Run(ctx, base[0], js.HTTPSAddr, nil, nil)
	env.Run(ctx, base[1], js.HTTPAddr, nil, nil)

	cs := cases(c.Judge.HTTPSPort, obsPort, resolve)
	fixtures := make([]*evil.Fixture, len(cs))
	firstN := make([]int, len(cs))
	var wg sync.WaitGroup
	for i := range cs {
		tc := &cs[i]
		var f *evil.Fixture
		if tc.closed {
			f, err = evil.Closed(tc.name, tc.label)
		} else {
			f, err = evil.Start(tc.name, tc.label, tc.b)
		}
		if err != nil {
			return false, err
		}
		defer f.Close()
		fixtures[i] = f
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bit := lists.LabelBit(tc.label)
			cand := &probe.Cand{Key: f.Addr, Labels: bit, Srcs: map[uint8]uint8{0: bit}}
			pr.Visit(ctx, cand)
			mu.Lock()
			firstN[i] = len(atts[f.Addr])
			mu.Unlock()
			if tc.second != nil {
				pr.Visit(ctx, cand)
			}
		}(i)
	}
	wg.Wait()
	var nodeCases []nodeCase
	if singbox != "" {
		if nodeCases, err = runNodes(ctx, env, c, slog, dir, singbox); err != nil {
			return false, err
		}
	}
	plog.Flush()
	jlog.Flush()
	slog.Flush()

	// judge 的记录按 nonce 归拢
	byNonce := map[string][]judge.Rec{}
	rec.Each(dir, "judge", func(line []byte) {
		var r judge.Rec
		if json.Unmarshal(line, &r) == nil && r.K == "req" {
			byNonce[r.Nonce] = append(byNonce[r.Nonce], r)
		}
	})
	derive := func(a *probe.Attempt) summary.Derived {
		return summary.Derive(a, byNonce[a.Nonce], secret, []string{"127.0.0.1"})
	}

	pass, total, failed := true, 0, 0
	fail := func(format string, args ...any) {
		pass = false
		failed++
		fmt.Fprintf(out, "  不符: "+format+"\n", args...)
	}
	check := func(name string, got []*probe.Attempt, wants []want) {
		for _, wt := range wants {
			total++
			var a *probe.Attempt
			for _, x := range got {
				if key(x) == wt.att {
					a = x
					break
				}
			}
			switch {
			case a == nil:
				fail("%s 没有做 %s 这项尝试", name, wt.att)
			case !classOK(a.Class, wt.class):
				fail("%s %s 期望 %s，实际 %s", name, wt.att, wt.class, a.Class)
			case wt.check != nil:
				if msg := wt.check(a, derive(a)); msg != "" {
					fail("%s %s: %s", name, wt.att, msg)
				}
			}
		}
	}

	// 对照组
	fmt.Fprintf(out, "对照（不经代理）\n")
	baseFP := ""
	for _, a := range base {
		total++
		d := derive(a)
		if a.Class != "ok" || !d.Seen || len(d.Tamper) > 0 {
			fail("直连 judge 失败: %s %s %v", key(a), a.Class, d.Tamper)
		}
		if a.Dst == probe.DstJudgeTLS {
			baseFP = d.HelloFP
		}
	}

	fmt.Fprintf(out, "夹具\n")
	for i := range cs {
		tc, f := &cs[i], fixtures[i]
		all := atts[f.Addr]
		first, second := all[:firstN[i]], all[firstN[i]:]
		before := failed
		check(tc.name, first, tc.wants)
		if tc.second != nil {
			check(tc.name+"（第二次探访）", second, tc.second)
		}
		total++
		if vs := visits[f.Addr]; len(vs) == 0 {
			fail("%s 没有探访小结", tc.name)
		} else {
			v := vs[0]
			if v.State != tc.state || strings.Join(v.OK, " ") != tc.ok || v.Auth != tc.auth {
				fail("%s 小结期望 状态=%s 可用=[%s] 需认证=%v，实际 状态=%s 可用=%v 需认证=%v",
					tc.name, tc.state, tc.ok, tc.auth, v.State, v.OK, v.Auth)
			}
		}
		if tc.only > 0 && len(first) != tc.only {
			total++
			fail("%s 应只做 %d 次尝试，实际 %d 次", tc.name, tc.only, len(first))
		}
		// 不变量：TLS 校验通过的请求，judge 收到的必须与探测器发出的完全一致，TLS 指纹必须与直连相同
		for _, a := range all {
			if a.Dst != probe.DstJudgeTLS || a.TLS == nil || !a.TLS.OK || a.Nonce == "" {
				continue
			}
			total++
			d := derive(a)
			if a.Class == "ok" && (!d.Seen || len(d.Tamper) > 0 || len(d.AddedReq) > 0 || d.HelloFP != baseFP) {
				fail("%s %s 经 TLS 的请求到达 judge 时与发出时不一致: seen=%v tamper=%v added=%v fp=%s 基线=%s",
					tc.name, key(a), d.Seen, d.Tamper, d.AddedReq, d.HelloFP, baseFP)
			}
		}
		mark := "通过"
		if failed > before {
			mark = "不符"
		}
		if verbose || failed > before {
			var parts []string
			for _, a := range all {
				parts = append(parts, key(a)+"="+a.Class)
			}
			fmt.Fprintf(out, "  %s  %-22s %s\n", mark, tc.name, strings.Join(parts, "  "))
		} else {
			fmt.Fprintf(out, "  %s  %s\n", mark, tc.name)
		}
	}
	if nodeCases != nil {
		fmt.Fprintf(out, "节点（经 sing-box）\n")
		pre, why := map[string]string{}, map[string]string{}
		rec.Each(dir, "probe", func(line []byte) {
			var r struct{ K, Node, Class string }
			if json.Unmarshal(line, &r) == nil && r.K == "npre" {
				pre[r.Node] = r.Class
			}
		})
		rec.Each(dir, "snap", func(line []byte) {
			var r struct{ K, ID, Why string }
			if json.Unmarshal(line, &r) == nil && r.K == "node" {
				why[r.ID] = "known:" + r.Why
			}
		})
		for _, nc := range nodeCases {
			before := failed
			all := atts[nc.id]
			find := func(arm, dst string) *probe.Attempt {
				for _, a := range all {
					if a.Arm == arm && a.Dst == dst {
						return a
					}
				}
				return nil
			}
			total++
			if why[nc.id] != "known:"+nc.why {
				fail("%s 的支持情况期望 %q，实际 %q", nc.name, nc.why, strings.TrimPrefix(why[nc.id], "known:"))
			}
			if nc.why == "" {
				total++
				wantPre := nc.pre
				if wantPre == "" {
					wantPre = "ok"
				}
				if pre[nc.id] != wantPre {
					fail("%s 的预检期望 %s，实际 %q", nc.name, wantPre, pre[nc.id])
				}
			}
			okArm := ""
			for _, x := range []struct{ arm, want string }{{"strict", nc.strict}, {"as_linked", nc.linked}} {
				total++
				a := find(x.arm, probe.DstJudgeTLS)
				switch {
				case x.want == "" && a != nil:
					fail("%s 不应有 %s 这一组的尝试，实际 %s", nc.name, x.arm, a.Class)
				case x.want == "!ok" && (a == nil || a.Class == "ok"):
					fail("%s 的 %s 一组应当失败", nc.name, x.arm)
				case x.want == "ok":
					if a == nil || a.Class != "ok" {
						got := "没有尝试"
						if a != nil {
							got = a.Class
						}
						fail("%s 的 %s 一组应当可用，实际 %s", nc.name, x.arm, got)
						break
					}
					okArm = x.arm
					if d := derive(a); a.IP != NodeEgress || d.Egress != NodeEgress || len(d.Tamper) > 0 || d.HelloFP != baseFP {
						fail("%s 经节点到达 judge 的请求不对: ip=%s seen=%v tamper=%v fp=%s", nc.name, a.IP, d.Seen, d.Tamper, d.HelloFP)
					}
				}
			}
			if nc.extras && okArm != "" {
				for _, dst := range []string{"obs:kv", "obs:plain", probe.DstJudgeHTTP} {
					total++
					if a := find(okArm, dst); a == nil || a.Class != "ok" || a.IP != NodeEgress {
						fail("%s 的附加测试 %s 不对", nc.name, dst)
					}
				}
			}
			mark := "通过"
			if failed > before {
				mark = "不符"
			}
			var parts []string
			for _, a := range all {
				parts = append(parts, a.Arm+">"+a.Dst+"="+a.Class)
			}
			if p := pre[nc.id]; p != "" && p != "ok" {
				parts = append(parts, "预检="+p)
			}
			if nc.why != "" {
				parts = append(parts, "不支持="+nc.why)
			}
			if verbose || failed > before {
				fmt.Fprintf(out, "  %s  %-22s %s\n", mark, nc.name, strings.Join(parts, "  "))
			} else {
				fmt.Fprintf(out, "  %s  %s\n", mark, nc.name)
			}
		}
	} else {
		fmt.Fprintf(out, "节点（经 sing-box）：未指定 sing-box，跳过\n")
	}
	fmt.Fprintf(out, "共核对 %d 项，%d 项不符\n", total, failed)
	return pass, nil
}

func portOf(addr string) int {
	_, ps, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(ps)
	return p
}

// StartObserver 启动一个假的第二观察者：HTTPS，返回它看到的对端地址。证书由临时 CA 签发；
// 第三个返回值是这张 CA 证书的 DER。
func StartObserver() (net.Listener, *x509.CertPool, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "selftest CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "obs1.test"},
		DNSNames: []string{"obs1.test", "obs2.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		return nil, nil, nil, err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if r.URL.Path == "/cdn-cgi/trace" {
			fmt.Fprintf(w, "fl=0f0\nh=%s\nip=%s\nts=%d\nvisit_scheme=https\n", r.Host, ip, time.Now().Unix())
			return
		}
		fmt.Fprintf(w, "%s\n", ip)
	})}
	go srv.Serve(ln)
	return ln, pool, caDER, nil
}

// Names 返回全部夹具的名字，文档用。
func Names() []string {
	var out []string
	for _, c := range cases(0, 0, nil) {
		out = append(out, c.name)
	}
	sort.Strings(out)
	return out
}

// Fixture 是一个已启动的夹具，以及假装列表给它贴的标签。
type Fixture struct {
	Name, Label, Addr string
	close             func()
}

// StartFixtures 启动全部代理夹具，每个占一个 127.0.1.x 地址。端到端测试用。
func StartFixtures(httpsPort, obsPort int, resolve map[string]string) ([]Fixture, func(), error) {
	var out []Fixture
	closeAll := func() {
		for _, f := range out {
			f.close()
		}
	}
	for i, tc := range cases(httpsPort, obsPort, resolve) {
		ip := "127.0.1." + strconv.Itoa(i+1)
		var f *evil.Fixture
		var err error
		if tc.closed {
			f, err = evil.ClosedAt(ip, tc.name, tc.label)
		} else {
			f, err = evil.StartAt(ip, tc.name, tc.label, tc.b)
		}
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		out = append(out, Fixture{Name: tc.name, Label: tc.label, Addr: f.Addr, close: f.Close})
	}
	return out, closeAll, nil
}

// StartNodeServer 启动本机的 sing-box 服务端，返回各测试节点的分享链接。端到端测试用。
func StartNodeServer(bin, dir string, judgeTLSPort int) ([]string, func(), error) {
	cs, stop, err := startNodeServer(bin, dir, judgeTLSPort)
	if err != nil {
		return nil, nil, err
	}
	var links []string
	for _, c := range cs {
		links = append(links, c.link)
	}
	return links, stop, nil
}
