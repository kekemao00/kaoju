package probe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/lists"
	"fieldtest/internal/rec"
	"fieldtest/internal/sysx"
)

// VisitRec 是一次探访的小结。探访 = 对一个候选连续做的一组尝试。
type VisitRec struct {
	TS      string   `json:"ts"`
	K       string   `json:"k"` // visit
	Visit   string   `json:"visit"`
	Cand    string   `json:"cand"`
	Group   uint8    `json:"group,omitempty"`
	N       int      `json:"n"`              // 这个候选的第几次探访
	Prev    string   `json:"prev"`           // 探访前的状态
	State   string   `json:"state"`          // 探访后的状态
	Full    bool     `json:"full,omitempty"` // 是否做了完整的协议识别
	Listed  bool     `json:"listed"`
	Labels  []string `json:"labels,omitempty"`
	Tried   []string `json:"tried,omitempty"`
	OK      []string `json:"ok,omitempty"` // 通过端到端校验的协议
	Auth    bool     `json:"auth,omitempty"`
	Aborted bool     `json:"aborted,omitempty"` // 程序正在退出，这次探访的结果不作数
	NextMin float64  `json:"next_min"`
	Ms      int64    `json:"ms"`
}

// Prober 把快照、调度、探访串起来。
type Prober struct {
	Env     *Env
	Pool    *Pool
	Sources *lists.Sources
	Fetch   *lists.Fetcher
	SnapLog *rec.Writer
	Nodes   NodeRunner // 可以为 nil

	files    []*snapFile
	visits   atomic.Int64
	started  time.Time
	stop     context.CancelFunc
	firstReg chan struct{}
	once     sync.Once
}

// NodeRunner 由节点探测部分实现。
type NodeRunner interface {
	Run(ctx context.Context)
}

type snapFile struct {
	*lists.File
	src   uint8
	label uint8
}

func NewProber(env *Env, src *lists.Sources, snapLog *rec.Writer) *Prober {
	c := env.Cfg
	p := &Prober{Env: env, Sources: src, Fetch: lists.NewFetcher(), SnapLog: snapLog, firstReg: make(chan struct{}),
		Pool: NewPool(env.JudgeIP, c.Probe.SkipPorts, c.Probe.PerPrefixConc, c.AllowLocal)}
	for i, l := range src.Lists {
		labels := make([]string, 0, len(l.Files))
		for label := range l.Files {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		for _, label := range labels {
			p.files = append(p.files, &snapFile{src: uint8(i), label: lists.LabelBit(label),
				File: &lists.File{Src: l.Name, Label: label, URL: l.Files[label], Agg: l.Aggregator}})
		}
	}
	return p
}

// labelProtos 把列表的标签换成“先试哪些协议”。
func labelProtos(mask uint8) []string {
	var out []string
	add := func(ps ...string) {
		for _, p := range ps {
			if !contains(out, p) {
				out = append(out, p)
			}
		}
	}
	if mask&lists.LSocks5 != 0 {
		add(Socks5)
	}
	if mask&lists.LSocks4 != 0 {
		add(Socks4)
	}
	if mask&(lists.LHTTPS|lists.LConnect) != 0 {
		add(Connect, Forward)
	}
	if mask&lists.LHTTP != 0 {
		add(Forward, Connect)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func hours(n int) time.Duration   { return time.Duration(n) * time.Hour }
func minutes(n int) time.Duration { return time.Duration(n) * time.Minute }

// Visit 对一个候选做一次探访，返回下次探访的时间（零值表示不再探访）。
func (p *Prober) Visit(ctx context.Context, c *Cand) time.Time {
	e, pc := p.Env, p.Env.Cfg.Probe
	t0 := time.Now()
	vid := e.NewVisitID()
	// 先在锁里取一份快照，探访期间只看这份快照
	var was Cand
	var listed bool
	p.Pool.With(func() { was, listed = *c, c.Listed() })
	v := VisitRec{TS: rec.TS(t0), K: "visit", Visit: vid, Cand: was.Key, Group: was.Group, N: was.Visits + 1,
		Prev: stateNames[was.State], Listed: listed, Labels: lists.LabelNames(was.Labels)}

	full := was.LastFull.IsZero() || t0.Sub(was.LastFull) >= hours(pc.FullIdentHours)
	var order []string
	switch {
	case full:
		order = labelProtos(was.Labels)
		for _, pb := range protoBits {
			if !contains(order, pb.name) {
				order = append(order, pb.name)
			}
		}
	case was.OKMask != 0:
		order = ProtoNames(was.OKMask)
	default:
		order = labelProtos(was.Labels)
	}
	v.Full = full

	try := func(proto, dst, kind string, obs *cfg.Observer) *Attempt {
		a := &Attempt{Visit: vid, Cand: was.Key, Proto: proto, Dst: dst, Kind: kind}
		e.Run(ctx, a, was.Key, nil, obs)
		return a
	}
	var tcpOK, fwdAnswers bool
	var okMask uint8
	for _, proto := range order {
		dst := DstJudgeTLS
		if proto == Forward {
			dst = DstJudgeHTTP
		}
		a := try(proto, dst, "h", nil)
		v.Tried = append(v.Tried, proto)
		if a.TCP != nil && a.TCP.OK {
			tcpOK = true
		} else if !tcpOK {
			break // 第一条连接就连不上：不再试别的协议
		}
		if a.Class == "ok" {
			okMask |= protoBit(proto)
		}
		if proto == Forward && (a.Class == "ok" || a.Class == "http_body_mismatch") {
			fwdAnswers = true // 转发能拿到 200，哪怕内容被改了：值得再看看它对别的内容类型下不下手
		}
		if a.Class == "hs_auth" || (a.HTTP != nil && a.HTTP.Code == 407) {
			v.Auth = true
		}
	}

	// 附加测试：隔几个小时做一次
	extraDue := was.LastExtra.IsZero() || t0.Sub(was.LastExtra) >= hours(pc.ExtraHours)
	didExtra := false
	tunnel := ""
	for _, pr := range []string{Socks5, Connect, Socks4} {
		if okMask&protoBit(pr) != 0 {
			tunnel = pr
			break
		}
	}
	if extraDue && (okMask != 0 || fwdAnswers) {
		if tunnel != "" && tunnel != Socks4 {
			for i := range e.Cfg.Observers {
				o := &e.Cfg.Observers[i]
				try(tunnel, "obs:"+o.Name, "", o) // 第二观察者看到的出口地址
			}
		}
		if tunnel == Socks5 || tunnel == Socks4 {
			try(tunnel, DstJudgeHTTP, "h", nil) // SOCKS 隧道里走明文：看内容会不会被改
		}
		if fwdAnswers {
			try(Forward, DstJudgeHTTP, "j", nil)
			try(Forward, DstJudgeHTTP, "b", nil)
		}
		didExtra = true
	}
	if full && tcpOK {
		if okMask&PConnect != 0 {
			try(Connect, DstJudgeHTTP, "h", nil) // CONNECT 能不能连 80 端口：看端口策略
		}
		if was.Labels&(lists.LHTTPS|lists.LConnect) != 0 {
			try(TLSProxy, DstSelf, "", nil) // 标成 https 的条目，端口本身是不是 TLS
		}
	}

	if ctx.Err() != nil {
		v.Aborted = true
		v.State = v.Prev
		v.Ms = time.Since(t0).Milliseconds()
		e.Log.Write(v)
		return t0.Add(time.Minute)
	}

	// 把结果写回候选，并算出下次探访的时间
	var next time.Time
	var d time.Duration
	p.Pool.With(func() {
		c.Visits++
		if didExtra {
			c.LastExtra = t0
		}
		retrySoon := false
		switch {
		case okMask != 0:
			c.State, c.OKMask, c.Fails, c.EverOK, c.LastOK = StWorking, okMask, 0, true, t0
		case tcpOK:
			c.State, c.Fails = StOpen, 0
			if full {
				c.OKMask = 0
			} else if c.OKMask != 0 {
				// 以前能用的协议这次都没通过，但端口还开着：尽快做一次完整识别，看它是不是换了协议
				c.LastFull = time.Time{}
				retrySoon = true
			}
		default:
			c.State = StDead
			c.Fails++
		}
		if full && tcpOK {
			c.LastFull = t0
		}
		switch c.State {
		case StWorking:
			d = minutes(pc.AliveIntervalMin)
			if c.Group == 1 {
				d = minutes(pc.AggregatorMin)
			}
		case StOpen:
			d = minutes(pc.OpenIntervalMin)
			if retrySoon {
				d = 2 * time.Minute
			}
		default:
			base := minutes(pc.DeadBaseMin)
			if c.EverOK {
				base = minutes(pc.JustDiedBaseMin)
			} else if c.Group == 1 {
				base = minutes(pc.DeadMaxMin)
			}
			d = base << min(c.Fails-1, 10)
			if top := minutes(pc.DeadMaxMin); d > top || d <= 0 {
				d = top
			}
		}
		d = time.Duration(float64(d) * (0.9 + 0.2*rand.Float64())) // 上下浮动一成，避免扎堆
		next = t0.Add(d)
		if !c.Listed() && !c.DelistedAt.IsZero() && t0.Sub(c.DelistedAt) >= hours(pc.DelistedGraceHours) {
			next, d = time.Time{}, 0
		}
		v.State = stateNames[c.State]
	})
	v.OK, v.NextMin = ProtoNames(okMask), d.Minutes()
	v.Ms = time.Since(t0).Milliseconds()
	e.Log.Write(v)
	if e.Sink != nil {
		e.Sink(&v)
	}
	p.visits.Add(1)
	return next
}

func (p *Prober) dispatch(ctx context.Context) {
	sem := make(chan struct{}, p.Env.Cfg.Probe.Concurrency)
	var wg sync.WaitGroup
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-tick.C:
		}
	fill:
		for {
			select {
			case sem <- struct{}{}:
			default:
				break fill
			}
			c := p.Pool.Take(time.Now())
			if c == nil {
				<-sem
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				next := time.Now().Add(time.Hour)
				// 对端发来的字节不可信。万一哪个候选触发了程序错误，记下来、一小时后再碰它，别让整个探测器停掉
				defer func() {
					if r := recover(); r != nil {
						p.Env.Panic("探访 "+c.Key, r)
					}
					p.Pool.Done(c, next)
				}()
				next = p.Visit(ctx, c)
			}()
		}
	}
}

// ---------------------------------------------------------------- 快照

func (p *Prober) snapshotLoop(ctx context.Context) {
	pc := p.Env.Cfg.Probe
	p.snapRegular(ctx)
	p.once.Do(func() { close(p.firstReg) })
	p.snapAggregators(ctx, false)
	reg := time.NewTicker(minutes(pc.SnapshotMin))
	agg := time.NewTicker(6 * time.Hour)
	defer reg.Stop()
	defer agg.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reg.C:
			p.snapRegular(ctx)
			if pc.AggregatorSample > 0 {
				p.snapAggregators(ctx, true)
			}
		case <-agg.C:
			p.snapAggregators(ctx, false)
		}
	}
}

func (p *Prober) snapRegular(ctx context.Context) {
	for _, f := range p.files {
		if f.Agg || ctx.Err() != nil {
			continue
		}
		now := time.Now()
		r, set := p.Fetch.Snapshot(ctx, f.File, now)
		p.SnapLog.Write(r)
		if set == nil {
			continue
		}
		for _, k := range r.Add {
			p.Pool.Upsert(k, f.src, f.label, 0, now)
		}
		for _, k := range r.Del {
			p.Pool.Delist(k, f.src, f.label, now)
		}
	}
	p.SnapLog.Flush()
}

// AggSampleRec 记录一次聚合器抽样，抽样可以按种子复现。
type AggSampleRec struct {
	TS        string   `json:"ts"`
	K         string   `json:"k"` // agg_sample
	Src       string   `json:"src"`
	Union     int      `json:"union"`     // 聚合器各文件合并后的条目数
	Exclusive int      `json:"exclusive"` // 其中不在任何常规列表里的
	Sample    int      `json:"sample"`    // 抽中的条数
	Seed      string   `json:"seed"`
	Members   []string `json:"members"` // 抽中的条目。聚合器不逐条记快照，所以在这里列出来
}

// snapAggregators 抓取聚合器。聚合器太大，不逐条跟踪；第一次完整抓到时从它的独占条目里随机抽一批来探测，
// 用来估计“聚合器独有的那部分到底有多少能用”。之后的抓取只更新抽样条目是否还在榜上。
// 抽样只做一次：洗牌的种子由共享密钥和聚合器的名字决定，抽过的标记随状态文件保存。
//
// onlyUnsampled 为真时只处理还没抽过样的聚合器：第一次抓取失败的，下一个快照周期再试，不必等六个小时。
func (p *Prober) snapAggregators(ctx context.Context, onlyUnsampled bool) {
	pc := p.Env.Cfg.Probe
	regular := map[string]struct{}{}
	for _, f := range p.files {
		if !f.Agg {
			for k := range f.Prev {
				regular[k] = struct{}{}
			}
		}
	}
	bySrc := map[uint8][]*snapFile{}
	var order []uint8
	for _, f := range p.files {
		if f.Agg {
			if _, ok := bySrc[f.src]; !ok {
				order = append(order, f.src)
			}
			bySrc[f.src] = append(bySrc[f.src], f)
		}
	}
	for _, src := range order {
		if onlyUnsampled && p.Pool.Sampled(bySrc[src][0].Src) {
			continue
		}
		union := map[string]uint8{}
		complete := true
		now := time.Now()
		for _, f := range bySrc[src] {
			if ctx.Err() != nil {
				return
			}
			r, set := p.Fetch.Snapshot(ctx, f.File, now)
			p.SnapLog.Write(r)
			if set == nil {
				complete = false
				continue
			}
			for k := range set {
				union[k] |= f.label
			}
		}
		name := bySrc[src][0].Src
		switch {
		case len(union) == 0 || pc.AggregatorSample <= 0:
			continue
		case p.Pool.Sampled(name):
			// 抽过样了（包括重启之前抽的）：只更新抽样条目是否还在榜上
			if !complete {
				continue
			}
			for k := range p.Pool.Keys(1) {
				if label, ok := union[k]; ok {
					p.Pool.Upsert(k, src, label, 1, now)
				} else {
					p.Pool.Delist(k, src, 0xff, now)
				}
			}
		case complete:
			var excl []string
			for k := range union {
				if _, ok := regular[k]; !ok {
					excl = append(excl, k)
				}
			}
			sort.Strings(excl)
			sum := sha256.Sum256(append(append([]byte{}, p.Env.Secret...), name...))
			seed := binary.BigEndian.Uint64(sum[:8])
			rng := rand.New(rand.NewPCG(seed, 0x6669656c64))
			rng.Shuffle(len(excl), func(i, j int) { excl[i], excl[j] = excl[j], excl[i] })
			// 取洗牌后的前 N 条。同一条目可以同时属于几个聚合器的样本
			members := excl[:min(len(excl), pc.AggregatorSample)]
			for _, k := range members {
				p.Pool.Upsert(k, src, union[k], 1, now)
			}
			p.Pool.MarkSampled(name)
			p.SnapLog.Write(AggSampleRec{TS: rec.TS(now), K: "agg_sample", Src: name, Union: len(union),
				Exclusive: len(excl), Sample: len(members), Seed: hex.EncodeToString(sum[:8]), Members: members})
		}
	}
	p.SnapLog.Flush()
	// 聚合器的文件有几十万行，解析时占的内存用完就还给系统
	debug.FreeOSMemory()
}

// ---------------------------------------------------------------- 对照探测

// controlLoop 不经任何代理，定时直接访问 judge 和第二观察者。
// 这些对照记录用来分辨“代理坏了”和“我们自己这边坏了”：对照失败的时段，代理的失败不作数。
func (p *Prober) controlLoop(ctx context.Context) {
	e := p.Env
	j := e.Cfg.Judge
	port := func(listen string, def int) string {
		if _, ps, err := net.SplitHostPort(listen); err == nil {
			return ps
		}
		return strconv.Itoa(def)
	}
	loHTTP := net.JoinHostPort("127.0.0.1", port(j.HTTPListen, j.HTTPPort))
	loTLS := net.JoinHostPort("127.0.0.1", port(j.HTTPSListen, j.HTTPSPort))
	pubHTTP := net.JoinHostPort(j.PublicIP, strconv.Itoa(j.HTTPPort))
	pubTLS := net.JoinHostPort(j.PublicIP, strconv.Itoa(j.HTTPSPort))
	round := 0
	run := func() {
		vid := e.NewVisitID()
		for _, t := range []struct{ cand, addr, dst string }{
			{"control:loopback", loHTTP, DstJudgeHTTP}, {"control:loopback", loTLS, DstJudgeTLS},
			{"control:public", pubHTTP, DstJudgeHTTP}, {"control:public", pubTLS, DstJudgeTLS},
		} {
			e.Run(ctx, &Attempt{Visit: vid, Cand: t.cand, Proto: Direct, Dst: t.dst, Kind: "h"}, t.addr, nil, nil)
		}
		if round%5 == 0 {
			for i := range e.Cfg.Observers {
				o := &e.Cfg.Observers[i]
				port := o.Port
				if port == 0 {
					port = 443
				}
				e.Run(ctx, &Attempt{Visit: vid, Cand: "control:observer", Proto: Direct, Dst: "obs:" + o.Name},
					net.JoinHostPort(o.Host, strconv.Itoa(port)), nil, o)
			}
		}
		round++
	}
	run()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// StatRec 每隔几分钟记一次运行状况。
type StatRec struct {
	TS     string         `json:"ts"`
	K      string         `json:"k"` // stat
	UpMin  float64        `json:"up_min"`
	Visits int64          `json:"visits"`
	Recs   int64          `json:"records"`
	Pool   map[string]int `json:"pool"`
}

func (p *Prober) housekeeping(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Stat()
			if free := sysx.DiskFreeGB(p.Env.Cfg.DataDir); free >= 0 && free < 1 {
				// 磁盘快满了：再写下去记录会残缺，不如停下来
				p.Env.Log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "error", "what": "磁盘剩余不足 1 GB，停止探测",
					"err": fmt.Sprintf("%.2f GB", free)})
				p.Env.Log.Flush()
				if p.stop != nil {
					p.stop()
				}
				return
			}
			if err := p.Pool.Save(p.Env.Cfg.Path("state.json.gz")); err != nil {
				p.Env.Log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "error", "what": "save state", "err": err.Error()})
			}
			p.Env.ReloadTrust()
			p.loadExclude()
		}
	}
}

// Stat 写一条运行状况记录。
func (p *Prober) Stat() {
	p.Env.Log.Write(StatRec{TS: rec.TS(time.Now()), K: "stat", UpMin: time.Since(p.started).Minutes(),
		Visits: p.visits.Load(), Recs: p.Env.Log.Count(), Pool: p.Pool.Stats()})
}

// loadExclude 读退出名单：每行一个 IP 或 CIDR。文件可以在运行中修改，最多五分钟后生效。
func (p *Prober) loadExclude() {
	path := p.Env.Cfg.Probe.ExcludeFile
	if path == "" {
		path = p.Env.Cfg.Path("exclude.txt")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var out []netip.Prefix
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(line); err == nil {
			out = append(out, pfx)
		} else if a, err := netip.ParseAddr(line); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	p.Pool.SetExclude(out)
}

// Run 运行探测器，直到 ctx 结束或到达配置的时长。
func (p *Prober) Run(ctx context.Context) error {
	c := p.Env.Cfg
	p.started = time.Now()
	if d := c.Probe.DurationHours; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(d*float64(time.Hour)))
		defer cancel()
	}
	ctx, p.stop = context.WithCancel(ctx)
	defer p.stop()
	if p.Env.Lim == nil {
		p.Env.Lim = NewLimiter(c.Probe.ConnPerSec)
		defer p.Env.Lim.Close()
	}
	p.loadExclude()
	n, err := p.Pool.Load(c.Path("state.json.gz"), p.started)
	p.Env.Log.Write(map[string]any{"ts": rec.TS(p.started), "k": "start", "resumed_candidates": n,
		"load_err": errString(err), "judge_host": c.Judge.Host, "judge_ip": c.Judge.PublicIP,
		"http_port": c.Judge.HTTPPort, "https_port": c.Judge.HTTPSPort, "probe": c.Probe,
		"payload_sha256": map[string]string{"h": p.Env.Payload.Get("h").SHA256, "j": p.Env.Payload.Get("j").SHA256,
			"b": p.Env.Payload.Get("b").SHA256}})

	var wg sync.WaitGroup
	start := func(f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 后台循环出了程序错误就重新进入，最多十次；每次都留下记录
			for i := 0; i < 10 && ctx.Err() == nil; i++ {
				if func() (crashed bool) {
					defer func() {
						if r := recover(); r != nil {
							p.Env.Panic("后台循环", r)
							crashed = true
						}
					}()
					f(ctx)
					return false
				}() {
					time.Sleep(5 * time.Second)
					continue
				}
				return
			}
		}()
	}
	start(p.snapshotLoop)
	start(p.dispatch)
	start(p.controlLoop)
	start(p.housekeeping)
	if p.Nodes != nil {
		start(p.Nodes.Run)
	}
	<-ctx.Done()
	wg.Wait()
	p.Stat()
	p.Env.Log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "stop", "visits": p.visits.Load()})
	err = p.Pool.Save(c.Path("state.json.gz"))
	p.Env.Log.Flush()
	p.SnapLog.Flush()
	return err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
