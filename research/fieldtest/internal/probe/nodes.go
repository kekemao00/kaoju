package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fieldtest/internal/lists"
	"fieldtest/internal/nodes"
	"fieldtest/internal/rec"
	"fieldtest/internal/wire"
)

// 节点探测的做法：每一轮先直接对每个节点的地址做 DNS 和 TCP 预检，连得上的再分批交给官方 sing-box。
// 每批生成一份配置，启动一个只听回环的 sing-box 进程，探测器把它当 SOCKS5 代理用，用户名决定走哪个节点；
// 隧道里仍然是对 judge 的 TLS 握手（锁定证书）和带 nonce 的请求。这一批测完就关掉进程。

// NSnapRec 是一次订阅抓取的记录。
type NSnapRec struct {
	TS       string   `json:"ts"`
	K        string   `json:"k"` // nsnap
	Src      string   `json:"src"`
	Status   int      `json:"status"`
	Err      string   `json:"err,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	Bytes    int      `json:"bytes,omitempty"`
	Lines    int      `json:"lines,omitempty"`
	Unparsed int      `json:"unparsed,omitempty"`
	N        int      `json:"n,omitempty"`
	Base     bool     `json:"base,omitempty"`
	Changed  bool     `json:"changed,omitempty"`
	Add      []string `json:"add,omitempty"`
	Del      []string `json:"del,omitempty"`
	Ms       int64    `json:"ms"`
}

// NodeRec 在第一次见到一个节点时写一条。不含凭据。
type NodeRec struct {
	TS  string `json:"ts"`
	K   string `json:"k"` // node
	Src string `json:"src"`
	*nodes.Node
	Why string `json:"why,omitempty"` // sing-box 连不了它的原因；空表示可以探测
}

// NPreRec 是一个节点的预检结果。
type NPreRec struct {
	TS    string     `json:"ts"`
	K     string     `json:"k"` // npre
	Round int        `json:"round"`
	Node  string     `json:"node"`
	DNS   *wire.Step `json:"dns,omitempty"`
	IPs   []string   `json:"ips,omitempty"`
	TCP   *wire.Step `json:"tcp,omitempty"`
	Class string     `json:"class"`
}

// NErrRec 是 sing-box 日志里与某个节点有关的最后一条错误，用来解释探测为什么失败。
type NErrRec struct {
	TS    string `json:"ts"`
	K     string `json:"k"` // nerr
	Round int    `json:"round"`
	Node  string `json:"node"`
	Arm   string `json:"arm"`
	Msg   string `json:"msg"`
}

// NRoundRec 是一轮节点探测的小结。
type NRoundRec struct {
	TS        string `json:"ts"`
	K         string `json:"k"` // nround
	Round     int    `json:"round"`
	Known     int    `json:"known"`      // 见过的节点
	Listed    int    `json:"listed"`     // 当前在榜
	Supported int    `json:"supported"`  // 其中 sing-box 能连的
	Backoff   int    `json:"backoff"`    // 因为连续不可用、这一轮跳过的
	TCPOK     int    `json:"tcp_ok"`     // 预检连得上的
	Probed    int    `json:"probed"`     // 做了隧道探测的
	OKStrict  int    `json:"ok_strict"`  // 严格校验下可用
	OKLinked  int    `json:"ok_linked"`  // 只有照链接要求跳过校验才可用
	BadConfig int    `json:"bad_config"` // 配置被 sing-box 拒绝的
	Batches   int    `json:"batches"`
	Ms        int64  `json:"ms"`
	Err       string `json:"err,omitempty"`
}

type nodeState struct {
	n         *nodes.Node
	why       string
	srcs      map[int]bool
	first     time.Time
	delisted  time.Time
	lastExtra time.Time
	everOK    bool
	fails     int // 连续多少轮不可用
	skipUntil int // 这一轮之前不再探测它
}

// settle 记下一个节点这一轮的结果。可用的每轮都测；不可用的隔 1、2、4、6 轮再测，
// 省下来的时间和连接留给还活着的节点。
func (st *nodeState) settle(ok bool, round int) {
	if ok {
		st.fails, st.skipUntil = 0, 0
		return
	}
	st.fails++
	gap := 1 << min(st.fails-1, 3)
	if gap > 6 {
		gap = 6
	}
	st.skipUntil = round + gap
}

type subFile struct {
	sub     lists.Subscription
	idx     int
	etag    string
	sha     string
	prev    map[string]struct{}
	fetched bool
}

// NodeRun 负责订阅快照和节点探测。
type NodeRun struct {
	Env    *Env
	Fetch  *lists.Fetcher
	Snap   *rec.Writer
	Raw    *rec.Writer // 可选：节点标识到原始链接的对照，只留在本机，方便排查
	Dir    string      // 旁路进程的工作目录
	Static []string    // 自测用：不经订阅直接给出的分享链接

	mu       sync.Mutex
	states   map[string]*nodeState
	files    []*subFile
	round    int
	lastSnap time.Time
}

func NewNodeRun(env *Env, subs []lists.Subscription, snap *rec.Writer, dir string) *NodeRun {
	nr := &NodeRun{Env: env, Fetch: lists.NewFetcher(), Snap: snap, Dir: dir, states: map[string]*nodeState{}}
	for i, s := range subs {
		nr.files = append(nr.files, &subFile{sub: s, idx: i})
	}
	return nr
}

func (nr *NodeRun) learn(n *nodes.Node, link, src string, idx int, now time.Time) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	st := nr.states[n.ID]
	if st == nil {
		st = &nodeState{n: n, why: nodes.Supported(n), srcs: map[int]bool{}, first: now}
		nr.states[n.ID] = st
		nr.Snap.Write(NodeRec{TS: rec.TS(now), K: "node", Src: src, Node: n, Why: st.why})
		if nr.Raw != nil {
			nr.Raw.Write(map[string]string{"id": n.ID, "link": link})
		}
	}
	st.srcs[idx] = true
	st.delisted = time.Time{}
}

func (nr *NodeRun) unlist(id string, idx int, now time.Time) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	if st := nr.states[id]; st != nil {
		delete(st.srcs, idx)
		if len(st.srcs) == 0 && st.delisted.IsZero() {
			st.delisted = now
		}
	}
}

func (nr *NodeRun) snapshot(ctx context.Context) {
	for _, f := range nr.files {
		if ctx.Err() != nil {
			return
		}
		now, t0 := time.Now(), time.Now()
		r := NSnapRec{TS: rec.TS(now), K: "nsnap", Src: f.sub.Name}
		body, status, etag, err := nr.Fetch.Get(ctx, f.sub.URL, f.etag)
		r.Status, r.Ms = status, time.Since(t0).Milliseconds()
		if err != nil {
			r.Err = err.Error()
		}
		if err != nil || status != 200 {
			nr.Snap.Write(r)
			continue
		}
		sum := sha256.Sum256(body)
		sha := hex.EncodeToString(sum[:])
		r.SHA256, r.Bytes = sha, len(body)
		f.etag = etag
		if f.fetched && sha == f.sha {
			nr.Snap.Write(r)
			continue
		}
		set := map[string]struct{}{}
		for _, link := range nodes.Links(nodes.LoadText(body)) {
			r.Lines++
			n := nodes.Parse(link)
			if n == nil {
				r.Unparsed++
				continue
			}
			set[n.ID] = struct{}{}
			nr.learn(n, link, f.sub.Name, f.idx, now)
		}
		for id := range set {
			if _, ok := f.prev[id]; !ok {
				r.Add = append(r.Add, id)
			}
		}
		for id := range f.prev {
			if _, ok := set[id]; !ok {
				r.Del = append(r.Del, id)
				nr.unlist(id, f.idx, now)
			}
		}
		sort.Strings(r.Add)
		sort.Strings(r.Del)
		r.N, r.Changed, r.Base = len(set), true, !f.fetched
		f.prev, f.sha, f.fetched = set, sha, true
		nr.Snap.Write(r)
	}
	nr.lastSnap = time.Now()
	nr.Snap.Flush()
}

// Init 建好工作目录，并登记直接给出的链接。
func (nr *NodeRun) Init() error {
	if err := os.MkdirAll(nr.Dir, 0o700); err != nil {
		return err
	}
	for _, link := range nr.Static {
		if n := nodes.Parse(link); n != nil {
			nr.learn(n, link, "static", -1, time.Now())
		}
	}
	return nil
}

// Run 循环执行：到点就抓订阅，然后做一轮探测。
func (nr *NodeRun) Run(ctx context.Context) {
	nc := nr.Env.Cfg.Nodes
	bin, err := exec.LookPath(nc.SingBox)
	if err != nil {
		nr.Env.Log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "error", "what": "节点探测未启动：找不到 sing-box",
			"err": err.Error()})
		return
	}
	if err := nr.Init(); err != nil {
		nr.Env.Log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "error", "what": "节点探测未启动", "err": err.Error()})
		return
	}
	for ctx.Err() == nil {
		start := time.Now()
		if nr.lastSnap.IsZero() || start.Sub(nr.lastSnap) >= minutes(nc.SnapshotMin) {
			nr.snapshot(ctx)
		}
		nr.Round(ctx, bin)
		wait := time.Until(start.Add(minutes(nc.RoundMin)))
		if next := time.Until(nr.lastSnap.Add(minutes(nc.SnapshotMin))); next < wait {
			wait = next
		}
		if wait < 10*time.Second {
			wait = 10 * time.Second
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
}

// Round 做一轮节点探测。
func (nr *NodeRun) Round(ctx context.Context, bin string) NRoundRec {
	e, nc := nr.Env, nr.Env.Cfg.Nodes
	t0 := time.Now()
	nr.round++
	rr := NRoundRec{TS: rec.TS(t0), K: "nround", Round: nr.round}
	grace := hours(e.Cfg.Probe.DelistedGraceHours)

	nr.mu.Lock()
	var cands []*nodeState
	rr.Known = len(nr.states)
	for _, st := range nr.states {
		listed := len(st.srcs) > 0
		if listed {
			rr.Listed++
		}
		if st.why != "" || (!listed && t0.Sub(st.delisted) > grace) {
			continue
		}
		if listed {
			rr.Supported++
		}
		if nr.round < st.skipUntil {
			rr.Backoff++
			continue
		}
		cands = append(cands, st)
	}
	nr.mu.Unlock()
	sort.Slice(cands, func(i, j int) bool { return cands[i].n.ID < cands[j].n.ID })
	if nc.MaxPerRound > 0 && len(cands) > nc.MaxPerRound {
		rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
		cands = cands[:nc.MaxPerRound]
	}

	// 预检：直接对节点地址做 DNS 和 TCP
	alive := make([]*nodeState, 0, len(cands))
	var amu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, st := range cands {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(st *nodeState) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					e.Panic("节点预检 "+st.n.ID, r)
				}
			}()
			if nr.precheck(ctx, st) {
				amu.Lock()
				alive = append(alive, st)
				amu.Unlock()
			} else if ctx.Err() == nil {
				st.settle(false, nr.round)
			}
		}(st)
	}
	wg.Wait()
	rr.TCPOK = len(alive)
	sort.Slice(alive, func(i, j int) bool { return alive[i].n.ID < alive[j].n.ID })

	for i := 0; i < len(alive) && ctx.Err() == nil; i += nc.Batch {
		rr.Batches++
		if err := nr.batch(ctx, bin, alive[i:min(i+nc.Batch, len(alive))], &rr); err != nil {
			rr.Err = err.Error()
			e.Log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "error", "what": "sing-box 旁路进程", "err": err.Error()})
		}
	}
	rr.Ms = time.Since(t0).Milliseconds()
	e.Log.Write(rr)
	if e.Sink != nil {
		e.Sink(&rr)
	}
	return rr
}

func (nr *NodeRun) precheck(ctx context.Context, st *nodeState) bool {
	e := nr.Env
	r := NPreRec{TS: rec.TS(time.Now()), K: "npre", Round: nr.round, Node: st.n.ID}
	defer func() { e.Log.Write(r) }()
	var ip netip.Addr
	if a, err := netip.ParseAddr(st.n.Host); err == nil {
		ip = a.Unmap()
		r.IPs = []string{ip.String()}
	} else {
		t0 := time.Now()
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip4", st.n.Host)
		cancel()
		d := wire.Step{Ms: time.Since(t0).Milliseconds()}
		r.DNS = &d
		if err != nil || len(addrs) == 0 {
			var de *net.DNSError
			switch {
			case errors.As(err, &de) && de.IsNotFound:
				d.Class = "dns_nxdomain"
			case errors.As(err, &de) && de.IsTimeout:
				d.Class = "dns_timeout"
			default:
				d.Class = "dns_other"
			}
			r.Class = d.Class
			return false
		}
		d.OK = true
		for i, a := range addrs {
			if i < 4 {
				r.IPs = append(r.IPs, a.Unmap().String())
			}
		}
		ip = addrs[0].Unmap()
	}
	switch {
	case !ip.Is4():
		r.Class = "skip_ipv6"
		return false
	case !e.Cfg.AllowLocal && !lists.IsPublicV4(ip):
		r.Class = "skip_not_public" // 指向内网或保留地址的“节点”一律不碰
		return false
	}
	if e.Lim != nil && e.Lim.Wait(ctx) != nil {
		r.Class = "canceled"
		return false
	}
	conn, st2 := wire.Dial(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(st.n.Port)), e.dialTimeout(), nil)
	r.TCP = &st2
	if !st2.OK {
		r.Class = st2.Class
		return false
	}
	conn.Close()
	r.Class = "ok"
	return true
}

func tagOf(id string, linked bool) string {
	if linked {
		return "n" + id + "_i"
	}
	return "n" + id
}

func (nr *NodeRun) batch(ctx context.Context, bin string, sts []*nodeState, rr *NRoundRec) error {
	e, nc := nr.Env, nr.Env.Cfg.Nodes
	var members []nodes.Member
	for _, st := range sts {
		members = append(members, nodes.Member{Tag: tagOf(st.n.ID, false), Outbound: nodes.Outbound(st.n, tagOf(st.n.ID, false), false)})
		if st.n.Insecure && st.n.Sec == "tls" {
			members = append(members, nodes.Member{Tag: tagOf(st.n.ID, true), Outbound: nodes.Outbound(st.n, tagOf(st.n.ID, true), true)})
		}
	}
	cfgPath := filepath.Join(nr.Dir, "config.json")
	valid := nr.validate(bin, cfgPath, members, rr)
	if len(valid) == 0 {
		return nil
	}
	has := map[string]bool{}
	for _, m := range valid {
		has[m.Tag] = true
	}
	if err := os.WriteFile(cfgPath, nodes.Config(nc.ListenPort, valid), 0o600); err != nil {
		return err
	}
	logPath := filepath.Join(nr.Dir, "sing-box.log")
	stop, err := startSidecar(bin, cfgPath, logPath, nr.Dir, nc.ListenPort)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(nc.ListenPort))

	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := map[string]bool{}
	sem := make(chan struct{}, nc.Concurrency)
	for _, st := range sts {
		if ctx.Err() != nil {
			break
		}
		if !has[tagOf(st.n.ID, false)] {
			st.settle(false, nr.round) // 配置被 sing-box 拒绝
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(st *nodeState) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					e.Panic("节点探测 "+st.n.ID, r)
				}
			}()
			vid := e.NewVisitID()
			try := func(linked bool, dst, kind string, obs int) *Attempt {
				arm := "strict"
				if linked {
					arm = "as_linked"
				}
				a := &Attempt{Visit: vid, Cand: st.n.ID, Proto: Node, Dst: dst, Kind: kind, Arm: arm}
				auth := &wire.Socks5Auth{User: tagOf(st.n.ID, linked), Pass: "x"}
				if obs >= 0 {
					e.Run(ctx, a, addr, auth, &e.Cfg.Observers[obs])
				} else {
					e.Run(ctx, a, addr, auth, nil)
				}
				if a.Class != "ok" {
					mu.Lock()
					failed[auth.User] = true
					mu.Unlock()
				}
				return a
			}
			a := try(false, DstJudgeTLS, "h", -1)
			linked := false
			if a.Class != "ok" && has[tagOf(st.n.ID, true)] {
				linked = true
				a = try(true, DstJudgeTLS, "h", -1)
			}
			mu.Lock()
			rr.Probed++
			if a.Class == "ok" {
				if linked {
					rr.OKLinked++
				} else {
					rr.OKStrict++
				}
			}
			mu.Unlock()
			if ctx.Err() == nil {
				st.settle(a.Class == "ok", nr.round)
			}
			if a.Class != "ok" {
				return
			}
			st.everOK = true
			if now := time.Now(); st.lastExtra.IsZero() || now.Sub(st.lastExtra) >= hours(e.Cfg.Probe.ExtraHours) {
				st.lastExtra = now
				for i := range e.Cfg.Observers {
					try(linked, "obs:"+e.Cfg.Observers[i].Name, "", i)
				}
				try(linked, DstJudgeHTTP, "h", -1)
			}
		}(st)
	}
	wg.Wait()
	stop()

	// 从 sing-box 的日志里找出失败节点的错误原因
	if b, err := os.ReadFile(logPath); err == nil {
		last := map[string]string{}
		for _, line := range bytes.Split(b, []byte("\n")) {
			if m := sidecarErrRE.FindSubmatch(line); m != nil {
				last[string(m[1])] = string(m[2])
			}
		}
		for tag, msg := range last {
			if !failed[tag] {
				continue
			}
			id, arm := strings.TrimPrefix(tag, "n"), "strict"
			if s, ok := strings.CutSuffix(id, "_i"); ok {
				id, arm = s, "as_linked"
			}
			if len(msg) > 240 {
				msg = msg[:240]
			}
			e.Log.Write(NErrRec{TS: rec.TS(time.Now()), K: "nerr", Round: nr.round, Node: id, Arm: arm, Msg: msg})
		}
	}
	return nil
}

var sidecarErrRE = regexp.MustCompile(`outbound/[a-z0-9_-]+\[(n[0-9a-f]{12}(?:_i)?)\]: (.+)$`)

// validate 让 sing-box 检查配置。整批不过时对半拆开再查，直到找出被拒的那几个出站。
func (nr *NodeRun) validate(bin, cfgPath string, ms []nodes.Member, rr *NRoundRec) []nodes.Member {
	if len(ms) == 0 {
		return nil
	}
	if err := os.WriteFile(cfgPath, nodes.Config(nr.Env.Cfg.Nodes.ListenPort, ms), 0o600); err != nil {
		return nil
	}
	out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput()
	if err == nil {
		return ms
	}
	if len(ms) == 1 {
		rr.BadConfig++
		msg := strings.TrimSpace(string(out))
		if i := strings.LastIndex(msg, "]: "); i >= 0 {
			msg = msg[i+3:]
		}
		if len(msg) > 240 {
			msg = msg[:240]
		}
		id, arm := strings.TrimPrefix(ms[0].Tag, "n"), "strict"
		if s, ok := strings.CutSuffix(id, "_i"); ok {
			id, arm = s, "as_linked"
		}
		nr.Env.Log.Write(NErrRec{TS: rec.TS(time.Now()), K: "nerr", Round: nr.round, Node: id, Arm: arm, Msg: "config: " + msg})
		return nil
	}
	half := len(ms) / 2
	return append(nr.validate(bin, cfgPath, ms[:half], rr), nr.validate(bin, cfgPath, ms[half:], rr)...)
}

// startSidecar 启动 sing-box 并等它开始监听。返回的函数用来停掉它。
func startSidecar(bin, cfgPath, logPath, dir string, port int) (func(), error) {
	logf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	pidPath := filepath.Join(dir, "sing-box.pid")
	killStale(pidPath, cfgPath)
	cmd := exec.Command(bin, "run", "-c", cfgPath, "-D", dir)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stop := func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-exited
		}
		logf.Close()
		os.Remove(pidPath)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			logf.Close()
			tail, _ := os.ReadFile(logPath)
			if len(tail) > 300 {
				tail = tail[len(tail)-300:]
			}
			return nil, errors.New("sing-box 启动后退出: " + errString(err) + " " + strings.TrimSpace(string(tail)))
		default:
		}
		if c, err := net.DialTimeout("tcp4", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return stop, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	return nil, errors.New("sing-box 没有在 15 秒内开始监听")
}

// killStale 清掉上次异常退出时留下的旁路进程：只杀命令行里带着我们这份配置路径的那个。
func killStale(pidPath, cfgPath string) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return
	}
	defer os.Remove(pidPath)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || !bytes.Contains(cmdline, []byte(cfgPath)) {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		p.Kill()
		time.Sleep(200 * time.Millisecond)
	}
}
