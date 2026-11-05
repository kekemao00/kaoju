package summary

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/judge"
	"fieldtest/internal/lists"
	"fieldtest/internal/payload"
	"fieldtest/internal/probe"
	"fieldtest/internal/rec"
)

// Summary 是一次运行的汇总。它是给人看的速览和给预检用的体检表；寿命分布等正式分析另用脚本做。
type Summary struct {
	Generated string         `json:"generated"`
	First     string         `json:"first_record"`
	Last      string         `json:"last_record"`
	Hours     float64        `json:"hours"`
	Records   map[string]int `json:"records"`
	Warnings  []string       `json:"warnings"`

	Control   map[string]*Ratio `json:"control"`
	Snapshots []SnapRow         `json:"snapshots"`
	AggSample []map[string]any  `json:"aggregator_samples,omitempty"`
	Pool      map[string]int    `json:"pool,omitempty"`

	Funnel   map[string]*Funnel        `json:"funnel"` // regular / aggregator_sample
	BySource []SourceRow               `json:"by_source"`
	Labels   map[string]map[string]int `json:"labels"`   // 标签 → 实测可用的协议组合 → 候选数
	Classes  map[string]map[string]int `json:"classes"`  // 协议>目的地 → 类别 → 尝试数
	Latency  map[string][3]int64       `json:"latency"`  // 协议 → 成功尝试耗时的 p50 / p90 / p99（毫秒）
	Findings map[string]*Finding       `json:"findings"` // 各类异常：尝试数与涉及的候选数
	Anon     map[string]int            `json:"anonymity"`
	Egress   map[string]int            `json:"egress"`
	Extras   map[string]map[string]int `json:"extras"`

	Nodes NodeSummary    `json:"nodes"`
	Judge map[string]int `json:"judge"`
	Rate  map[string]any `json:"rate"`
}

type Ratio struct {
	OK    int `json:"ok"`
	Total int `json:"total"`
}

type SnapRow struct {
	Src      string `json:"src"`
	Fetches  int    `json:"fetches"`
	Failed   int    `json:"failed"`
	Changed  int    `json:"changed"`
	Current  int    `json:"current"` // 最近一次各文件条目数之和
	Agg      bool   `json:"aggregator,omitempty"`
	LastErr  string `json:"last_err,omitempty"`
	LastCode int    `json:"last_status,omitempty"`
}

type Funnel struct {
	Seen       int `json:"seen"`        // 探访过的候选
	TCP        int `json:"tcp"`         // 至少连上过一次
	Responsive int `json:"responsive"`  // 至少按某种代理协议回应过一次（含拒绝、要求认证）
	Working    int `json:"working"`     // 至少有一次通过端到端校验
	WorkingNow int `json:"working_now"` // 最近一次探访时可用
	Auth       int `json:"auth"`        // 要求认证
}

type SourceRow struct {
	Src        string `json:"src"`
	Listed     int    `json:"listed"`      // 当前在榜的条目
	Visited    int    `json:"visited"`     // 其中已探访
	WorkingNow int    `json:"working_now"` // 其中最近一次探访可用
	Working    int    `json:"working"`     // 其中曾经可用
}

type Finding struct {
	Attempts int      `json:"attempts"`
	Cands    int      `json:"candidates"`
	Examples []string `json:"examples,omitempty"`
	set      map[string]struct{}
}

type NodeSummary struct {
	Known       int                       `json:"known"`
	ByScheme    map[string]int            `json:"by_scheme"`
	Unsupported map[string]int            `json:"unsupported"`
	Pre         map[string]int            `json:"precheck"` // 最近一轮预检的结果分布
	Rounds      []probe.NRoundRec         `json:"rounds"`   // 最近几轮
	OK          map[string]map[string]int `json:"ok"`       // 协议 → strict/as_linked → 曾经可用的节点数
	Classes     map[string]int            `json:"classes"`  // 隧道探测的结果分布（尝试数）
	Errors      map[string]int            `json:"errors"`   // sing-box 报的错误，归并后计数
	Egress      map[string]int            `json:"egress"`
	Subs        []SnapRow                 `json:"subscriptions"`
}

type candAgg struct {
	group      uint8
	labels     []string
	visits     int
	tcp        bool
	responsive bool
	everOK     map[string]bool
	lastState  string
	auth       bool
	egress     map[string]struct{}
}

type jdigest struct {
	d       Derived
	tls     bool
	ips     map[string]struct{}
	control bool
}

func (f *Finding) add(cand, example string) {
	f.Attempts++
	if f.set == nil {
		f.set = map[string]struct{}{}
	}
	if _, ok := f.set[cand]; !ok {
		f.set[cand] = struct{}{}
		if len(f.Examples) < 5 && example != "" {
			f.Examples = append(f.Examples, example)
		}
	}
	f.Cands = len(f.set)
}

type builder struct {
	s       *Summary
	c       *cfg.Config
	secret  []byte
	selfIPs []string
	judge   map[string]*jdigest
	cands   map[string]*candAgg
	baseFP  string
	lat     map[string][]int64
	perMin  map[string]int
	srcCur  map[string]map[string]map[string]struct{} // 来源 → 标签 → 条目
	snap    map[string]*SnapRow
	nodeSch map[string]string
	nodeOK  map[string]map[string]bool
	lastPre map[string]string
	nodeIP  map[string][]string
	aggN    map[string]map[string]int // 聚合器：来源 → 标签 → 条目数
	// judge 日志里最后一条记录之前 10 秒。早于它的成功尝试必须能在 judge 日志里找到
	judgeHorizon string
	judgeLast    string
	pl           *payload.Set
}

func (b *builder) finding(name string) *Finding {
	f := b.s.Findings[name]
	if f == nil {
		f = &Finding{}
		b.s.Findings[name] = f
	}
	return f
}

func inc(m map[string]map[string]int, a, k string) {
	if m[a] == nil {
		m[a] = map[string]int{}
	}
	m[a][k]++
}

// Build 读数据目录里的全部记录并汇总。
func Build(c *cfg.Config) (*Summary, error) {
	secret, err := os.ReadFile(c.Path("secret"))
	if err != nil {
		return nil, fmt.Errorf("读共享密钥: %w", err)
	}
	s := &Summary{Generated: rec.TS(time.Now()), Records: map[string]int{}, Control: map[string]*Ratio{},
		Funnel: map[string]*Funnel{"regular": {}, "aggregator_sample": {}}, Labels: map[string]map[string]int{},
		Classes: map[string]map[string]int{}, Latency: map[string][3]int64{}, Findings: map[string]*Finding{},
		Anon: map[string]int{}, Egress: map[string]int{}, Extras: map[string]map[string]int{}, Judge: map[string]int{},
		Rate: map[string]any{}}
	s.Nodes = NodeSummary{ByScheme: map[string]int{}, Unsupported: map[string]int{}, Pre: map[string]int{},
		OK: map[string]map[string]int{}, Classes: map[string]int{}, Errors: map[string]int{}, Egress: map[string]int{}}
	b := &builder{s: s, c: c, secret: secret, selfIPs: []string{c.Judge.PublicIP}, judge: map[string]*jdigest{},
		cands: map[string]*candAgg{}, lat: map[string][]int64{}, perMin: map[string]int{},
		srcCur: map[string]map[string]map[string]struct{}{}, snap: map[string]*SnapRow{},
		nodeSch: map[string]string{}, nodeOK: map[string]map[string]bool{}, lastPre: map[string]string{},
		nodeIP: map[string][]string{}, aggN: map[string]map[string]int{}}

	if err := rec.Each(c.DataDir, "judge", b.judgeLine); err != nil {
		return nil, err
	}
	if t, err := time.Parse(tsLayout, b.judgeLast); err == nil {
		b.judgeHorizon = t.Add(-10 * time.Second).Format(tsLayout)
	}
	if err := rec.Each(c.DataDir, "snap", b.snapLine); err != nil {
		return nil, err
	}
	if err := rec.Each(c.DataDir, "probe", b.probeLine); err != nil {
		return nil, err
	}
	b.finish()
	return s, nil
}

func (b *builder) span(ts string) {
	if ts == "" {
		return
	}
	if b.s.First == "" || ts < b.s.First {
		b.s.First = ts
	}
	if ts > b.s.Last {
		b.s.Last = ts
	}
}

func (b *builder) judgeLine(line []byte) {
	var r judge.Rec
	if json.Unmarshal(line, &r) != nil {
		return
	}
	b.s.Judge[r.K]++
	if r.TS > b.judgeLast {
		b.judgeLast = r.TS
	}
	if r.K == "noise_dropped" {
		b.s.Judge["noise"] += int(r.N)
	}
	if r.K != "req" || r.Nonce == "" {
		return
	}
	j := b.judge[r.Nonce]
	if j == nil {
		j = &jdigest{d: Derive(&probe.Attempt{Nonce: r.Nonce}, []judge.Rec{r}, b.secret, b.selfIPs), tls: r.TLS}
		b.judge[r.Nonce] = j
		return
	}
	if j.ips == nil {
		j.ips = map[string]struct{}{j.d.Egress: {}}
	}
	j.ips[r.Remote] = struct{}{}
	j.d.Copies++
	j.d.CopyIPs = len(j.ips)
	if r.AgeS > j.d.LateS {
		j.d.LateS = r.AgeS
	}
}

func (b *builder) snapLine(line []byte) {
	var k struct {
		K string `json:"k"`
	}
	if json.Unmarshal(line, &k) != nil {
		return
	}
	b.s.Records[k.K]++
	switch k.K {
	case "snap":
		var r lists.SnapRec
		if json.Unmarshal(line, &r) != nil {
			return
		}
		row := b.snap[r.Src]
		if row == nil {
			row = &SnapRow{Src: r.Src, Agg: r.Agg}
			b.snap[r.Src] = row
		}
		row.Fetches++
		row.LastCode = r.Status
		if r.Err != "" || (r.Status != 200 && r.Status != 304) {
			row.Failed++
			row.LastErr = r.Err
			if row.LastErr == "" {
				row.LastErr = fmt.Sprintf("HTTP %d", r.Status)
			}
			return
		}
		if !r.Changed {
			return
		}
		row.Changed++
		if r.Agg {
			if b.aggN[r.Src] == nil {
				b.aggN[r.Src] = map[string]int{}
			}
			b.aggN[r.Src][r.Label] = r.N // 聚合器只记数量
			return
		}
		if b.srcCur[r.Src] == nil {
			b.srcCur[r.Src] = map[string]map[string]struct{}{}
		}
		set := b.srcCur[r.Src][r.Label]
		if set == nil || r.Base {
			set = map[string]struct{}{}
			b.srcCur[r.Src][r.Label] = set
		}
		for _, e := range r.Add {
			set[e] = struct{}{}
		}
		for _, e := range r.Del {
			delete(set, e)
		}
	case "agg_sample":
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			delete(m, "k")
			b.s.AggSample = append(b.s.AggSample, m)
		}
	case "nsnap":
		var r probe.NSnapRec
		if json.Unmarshal(line, &r) != nil {
			return
		}
		var row *SnapRow
		for i := range b.s.Nodes.Subs {
			if b.s.Nodes.Subs[i].Src == r.Src {
				row = &b.s.Nodes.Subs[i]
			}
		}
		if row == nil {
			b.s.Nodes.Subs = append(b.s.Nodes.Subs, SnapRow{Src: r.Src})
			row = &b.s.Nodes.Subs[len(b.s.Nodes.Subs)-1]
		}
		row.Fetches++
		row.LastCode = r.Status
		switch {
		case r.Err != "" || (r.Status != 200 && r.Status != 304):
			row.Failed++
			row.LastErr = r.Err
		case r.Changed:
			row.Changed++
			row.Current = r.N
		}
	case "node":
		var r struct {
			ID, Scheme, Why string
		}
		if json.Unmarshal(line, &r) != nil {
			return
		}
		// 探测器重启后会把还在榜的节点再记一遍，同一个节点只数一次
		if _, seen := b.nodeSch[r.ID]; seen {
			return
		}
		b.s.Nodes.Known++
		b.s.Nodes.ByScheme[r.Scheme]++
		b.nodeSch[r.ID] = r.Scheme
		if r.Why != "" {
			b.s.Nodes.Unsupported[r.Why]++
		}
	}
}

func (b *builder) cand(key string) *candAgg {
	c := b.cands[key]
	if c == nil {
		c = &candAgg{everOK: map[string]bool{}}
		b.cands[key] = c
	}
	return c
}

func (b *builder) probeLine(line []byte) {
	var k struct {
		K  string `json:"k"`
		TS string `json:"ts"`
	}
	if json.Unmarshal(line, &k) != nil {
		return
	}
	b.s.Records[k.K]++
	b.span(k.TS)
	switch k.K {
	case "att":
		var a probe.Attempt
		if json.Unmarshal(line, &a) == nil {
			b.attempt(&a)
		}
	case "visit":
		var v probe.VisitRec
		if json.Unmarshal(line, &v) != nil || v.Aborted {
			return
		}
		c := b.cand(v.Cand)
		c.group, c.labels, c.visits, c.lastState = v.Group, v.Labels, v.N, v.State
		if v.Auth {
			c.auth = true
		}
	case "stat":
		var st probe.StatRec
		if json.Unmarshal(line, &st) == nil {
			b.s.Pool = st.Pool
		}
	case "npre":
		var r probe.NPreRec
		if json.Unmarshal(line, &r) == nil {
			b.lastPre[r.Node] = r.Class
			if len(r.IPs) > 0 {
				b.nodeIP[r.Node] = r.IPs
			}
		}
	case "nround":
		var r probe.NRoundRec
		if json.Unmarshal(line, &r) == nil {
			b.s.Nodes.Rounds = append(b.s.Nodes.Rounds, r)
			if len(b.s.Nodes.Rounds) > 6 {
				b.s.Nodes.Rounds = b.s.Nodes.Rounds[1:]
			}
		}
	case "nerr":
		var r probe.NErrRec
		if json.Unmarshal(line, &r) == nil {
			b.s.Nodes.Errors[normErr(r.Msg)]++
		}
	case "error":
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			b.s.Warnings = append(b.s.Warnings, fmt.Sprintf("运行中的错误：%v %v", m["what"], m["err"]))
		}
	}
}

const tsLayout = "2006-01-02T15:04:05.000Z"

var addrRE = regexp.MustCompile(`^(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::\d+)?[:,]?$`)

// normErr 把 sing-box 的错误信息里因节点而异的部分（地址和端口）去掉，便于归并计数。
func normErr(msg string) string {
	var out []string
	for _, w := range strings.Fields(msg) {
		if addrRE.MatchString(w) && strings.IndexAny(w, "0123456789") >= 0 {
			w = "<addr>"
		}
		out = append(out, w)
	}
	s := strings.Join(out, " ")
	if len(s) > 110 {
		s = s[:110]
	}
	return s
}

func (b *builder) attempt(a *probe.Attempt) {
	s := b.s
	if strings.Contains(a.Class, "canceled") {
		return
	}
	if len(a.TS) >= 16 {
		b.perMin[a.TS[:16]]++
	}
	var d Derived
	var j *jdigest
	if a.Nonce != "" {
		if j = b.judge[a.Nonce]; j != nil {
			d = j.d
		}
	}
	judgeDst := a.Dst == probe.DstJudgeTLS || a.Dst == probe.DstJudgeHTTP

	// 对照组
	if strings.HasPrefix(a.Cand, "control:") {
		name := a.Cand + " " + a.Dst
		r := s.Control[name]
		if r == nil {
			r = &Ratio{}
			s.Control[name] = r
		}
		r.Total++
		if a.Class == "ok" {
			r.OK++
			if j != nil {
				j.control = true
				if a.Dst == probe.DstJudgeTLS && d.HelloFP != "" {
					b.baseFP = d.HelloFP
				}
			}
		}
		return
	}

	// 节点
	if a.Proto == probe.Node {
		if a.Dst == probe.DstJudgeTLS {
			s.Nodes.Classes[a.Arm+" "+a.Class]++
			if a.Class == "ok" {
				if b.nodeOK[a.Cand] == nil {
					b.nodeOK[a.Cand] = map[string]bool{}
				}
				b.nodeOK[a.Cand][a.Arm] = true
				b.nodeEgress(a, d)
			}
		}
		b.integrity(a, d, j, "node "+a.Cand)
		return
	}

	// 代理
	inc(s.Classes, a.Proto+">"+a.Dst, a.Class)
	c := b.cand(a.Cand)
	if a.TCP != nil && a.TCP.OK {
		c.tcp = true
	}
	if (a.HS != nil && (a.HS.OK || a.HS.Code != 0)) || (a.HTTP != nil && a.HTTP.Code != 0) {
		c.responsive = true
	}
	if a.Class == "ok" && judgeDst {
		c.everOK[a.Proto] = true
		b.lat[a.Proto] = append(b.lat[a.Proto], a.Ms)
		if d.Seen {
			if c.egress == nil {
				c.egress = map[string]struct{}{}
			}
			c.egress[d.Egress] = struct{}{}
		}
	}
	switch {
	case strings.HasPrefix(a.Dst, "obs:"):
		inc(s.Extras, "observer "+a.Dst[4:], a.Class)
		if a.Class == "ok" && c.egress != nil {
			if _, same := c.egress[a.IP]; same {
				inc(s.Extras, "observer_vs_judge", "same_ip")
			} else {
				inc(s.Extras, "observer_vs_judge", "different_ip")
				b.finding("第二观察者看到的出口与 judge 不同").add(a.Cand, a.Cand+" judge="+keys(c.egress)+" "+a.Dst+"="+a.IP)
			}
		}
	case a.Proto == probe.Connect && a.Dst == probe.DstJudgeHTTP:
		inc(s.Extras, "connect_to_port_80", a.Class)
	case a.Proto == probe.TLSProxy:
		k := a.Class
		if a.TLS != nil && a.TLS.Detail != "" && a.Class == "tls_cert_invalid" {
			k += " (" + a.TLS.Detail + ")"
		}
		inc(s.Extras, "https_label_port_speaks_tls", k)
	case (a.Proto == probe.Socks5 || a.Proto == probe.Socks4) && a.Dst == probe.DstJudgeHTTP:
		inc(s.Extras, "plain_http_inside_socks", a.Class)
	}
	b.integrity(a, d, j, a.Cand)

	// 匿名程度：只对明文转发有意义
	if a.Proto == probe.Forward && a.Class == "ok" && d.Seen {
		s.Anon[d.Anonymity]++
	}
}

func keys(m map[string]struct{}) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// integrity 汇总各种“内容或请求被动过”的发现。
func (b *builder) integrity(a *probe.Attempt, d Derived, j *jdigest, who string) {
	ex := who + " " + a.Proto + ">" + a.Dst
	if a.TLS != nil {
		switch a.TLS.Class {
		case "tls_cert_invalid":
			if a.Proto != probe.TLSProxy {
				b.finding("隧道里的证书不是 judge 的（中间人）").add(who, ex+" issuer="+a.TLS.Issuer+" "+a.TLS.Detail)
			}
		case "tls_pin_mismatch":
			b.finding("证书链有效但公钥不是 judge 的").add(who, ex+" leaf="+a.TLS.Leaf)
		}
	}
	if h := a.HTTP; h != nil {
		switch {
		case h.Class == "http_body_mismatch":
			kind := BodyChange(a.Kind, h.Len, h.Pre, h.Sim, b.wantLen(a.Kind))
			b.finding(kind).add(who, fmt.Sprintf("%s kind=%s len=%d pre=%d suf=%d sim=%d%% ev=%s", ex, a.Kind, h.Len, h.Pre, h.Suf, h.Sim, short(h.Ev)))
		case strings.HasPrefix(h.Class, "http_canary_"):
			b.finding("正文正确但不是这次请求的应答（缓存或重放）").add(who, ex+" "+h.Class)
		}
		for _, f := range h.Flags {
			b.finding("响应头被动过: "+f).add(who, ex)
		}
		if len(h.Added) > 0 && a.Class == "ok" && (a.Dst == probe.DstJudgeTLS || a.Dst == probe.DstJudgeHTTP) {
			b.finding("响应里多出 judge 没发的头").add(who, ex+" "+strings.Join(h.Added, ","))
		}
	}
	if a.Nonce == "" || a.Class != "ok" || strings.HasPrefix(a.Dst, "obs:") {
		return
	}
	if !d.Seen {
		// judge 的日志每两秒落盘一次。汇总时两个进程可能都还在跑，最后几秒的请求还没写到盘上，不能算作没收到
		if a.TS < b.judgeHorizon {
			b.finding("探测器认为成功，但 judge 没收到请求").add(who, ex+" nonce="+a.Nonce)
		}
		return
	}
	if a.IP != "" && a.IP != d.Egress {
		b.finding("响应头里回显的地址与 judge 日志不一致").add(who, ex+" header="+a.IP+" log="+d.Egress)
	}
	if d.Copies > 1 {
		b.finding("同一请求被 judge 收到多次（重放）").add(who, fmt.Sprintf("%s copies=%d ips=%d late=%ds", ex, d.Copies, d.CopyIPs, d.LateS))
		if d.CopyIPs > 1 {
			b.finding("重放来自别的地址").add(who, fmt.Sprintf("%s copies=%d ips=%d", ex, d.Copies, d.CopyIPs))
		}
	}
	if len(d.Tamper) > 0 {
		b.finding("请求头被改动").add(who, ex+" "+strings.Join(d.Tamper, ","))
	}
	if d.LeakIP {
		b.finding("请求头里带出了探测器的地址").add(who, ex+" "+strings.Join(d.AddedReq, ","))
	}
	if a.TLS != nil && a.TLS.OK && (len(d.Tamper) > 0 || len(d.AddedReq) > 0 || (b.baseFP != "" && d.HelloFP != b.baseFP)) {
		// TLS 校验通过后，请求不可能被改；出现这种情况说明仪器本身有错
		b.finding("仪器异常：TLS 内的请求到达 judge 时与发出时不同").add(who, ex+" fp="+d.HelloFP+" base="+b.baseFP)
	}
	if a.Proto != probe.Node {
		if host, _, err := net.SplitHostPort(a.Cand); err == nil && host != d.Egress {
			b.finding("出口地址与列表里的地址不同").add(who, a.Cand+" egress="+d.Egress)
		}
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// wantLen 返回某种载荷的期望长度。
func (b *builder) wantLen(kind string) int {
	if b.pl == nil {
		b.pl = payload.Build(b.c.Judge.Host)
	}
	if p := b.pl.Get(payload.Kind(kind)); p != nil {
		return len(p.Body)
	}
	return 0
}

func (b *builder) nodeEgress(a *probe.Attempt, d Derived) {
	if !d.Seen {
		return
	}
	for _, self := range b.selfIPs {
		if d.Egress == self {
			b.finding("仪器异常：节点探测的流量从本机直接出去了").add(a.Cand, "node "+a.Cand+" egress="+d.Egress)
			return
		}
	}
	entry := b.nodeIP[a.Cand]
	same := false
	for _, ip := range entry {
		if ip == d.Egress {
			same = true
		}
	}
	switch {
	case same:
		b.s.Nodes.Egress["与入口相同"]++
	case len(entry) == 0:
		b.s.Nodes.Egress["入口地址未知"]++
	default:
		b.s.Nodes.Egress["与入口不同"]++
	}
}

func pct(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
}

func (b *builder) finish() {
	s := b.s
	if t0, err := time.Parse(tsLayout, s.First); err == nil {
		if t1, err := time.Parse(tsLayout, s.Last); err == nil {
			s.Hours = t1.Sub(t0).Hours()
		}
	}
	// 漏斗与标签
	for _, c := range b.cands {
		name := "regular"
		if c.group == 1 {
			name = "aggregator_sample"
		}
		f := s.Funnel[name]
		if c.visits == 0 {
			continue
		}
		f.Seen++
		if c.tcp {
			f.TCP++
		}
		if c.responsive {
			f.Responsive++
		}
		if len(c.everOK) > 0 {
			f.Working++
		}
		if c.lastState == "working" {
			f.WorkingNow++
		}
		if c.auth {
			f.Auth++
		}
		if c.group == 0 && c.tcp {
			var ok []string
			for _, p := range []string{probe.Socks5, probe.Connect, probe.Forward, probe.Socks4} {
				if c.everOK[p] {
					ok = append(ok, p)
				}
			}
			m := "无"
			if len(ok) > 0 {
				m = strings.Join(ok, "+")
			}
			inc(s.Labels, strings.Join(c.labels, "+"), m)
		}
		if n := len(c.egress); n > 0 {
			switch {
			case n == 1:
				s.Egress["1 个出口地址"]++
			case n <= 3:
				s.Egress["2 到 3 个出口地址"]++
			default:
				s.Egress["4 个以上出口地址"]++
			}
		}
	}
	// 来源
	s.Snapshots = s.Snapshots[:0]
	for _, row := range b.snap {
		cur := 0
		union := map[string]struct{}{}
		for _, n := range b.aggN[row.Src] {
			cur += n
		}
		for _, set := range b.srcCur[row.Src] {
			cur += len(set)
			for k := range set {
				union[k] = struct{}{}
			}
		}
		row.Current = cur
		s.Snapshots = append(s.Snapshots, *row)
		if row.Agg {
			continue
		}
		sr := SourceRow{Src: row.Src, Listed: len(union)}
		for k := range union {
			if c := b.cands[k]; c != nil && c.visits > 0 {
				sr.Visited++
				if c.lastState == "working" {
					sr.WorkingNow++
				}
				if len(c.everOK) > 0 {
					sr.Working++
				}
			}
		}
		s.BySource = append(s.BySource, sr)
	}
	sort.Slice(s.Snapshots, func(i, j int) bool { return s.Snapshots[i].Src < s.Snapshots[j].Src })
	sort.Slice(s.BySource, func(i, j int) bool { return s.BySource[i].Listed > s.BySource[j].Listed })
	// 耗时
	for p, v := range b.lat {
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		q := func(f float64) int64 { return v[min(len(v)-1, int(f*float64(len(v))))] }
		s.Latency[p] = [3]int64{q(0.5), q(0.9), q(0.99)}
	}
	// 速率
	peak, total := 0, 0
	for _, n := range b.perMin {
		total += n
		if n > peak {
			peak = n
		}
	}
	if len(b.perMin) > 0 {
		s.Rate["attempts_per_sec_avg"] = fmt.Sprintf("%.1f", float64(total)/float64(len(b.perMin))/60)
		s.Rate["attempts_per_sec_peak_minute"] = fmt.Sprintf("%.1f", float64(peak)/60)
		s.Rate["configured_conn_per_sec"] = b.c.Probe.ConnPerSec
	}
	// 节点
	for _, cls := range b.lastPre {
		s.Nodes.Pre[cls]++
	}
	for id, arms := range b.nodeOK {
		sch := b.nodeSch[id]
		if sch == "" {
			sch = "?"
		}
		if arms["strict"] {
			inc(s.Nodes.OK, sch, "strict")
		} else if arms["as_linked"] {
			inc(s.Nodes.OK, sch, "as_linked_only")
		}
	}
	b.warnings()
}

func (b *builder) warnings() {
	s := b.s
	warn := func(format string, args ...any) { s.Warnings = append(s.Warnings, fmt.Sprintf(format, args...)) }
	ctl := func(name string) (int, int) {
		if r := s.Control[name]; r != nil {
			return r.OK, r.Total
		}
		return 0, 0
	}
	for _, dst := range []string{probe.DstJudgeHTTP, probe.DstJudgeTLS} {
		if ok, n := ctl("control:loopback " + dst); n > 0 && ok*10 < n*9 {
			warn("经回环访问 judge（%s）%d 次里只成功 %d 次：judge 可能没在运行，或端口配置不对", dst, n, ok)
		}
		lo, _ := ctl("control:loopback " + dst)
		if ok, n := ctl("control:public " + dst); n > 0 && ok == 0 && lo > 0 {
			warn("从本机访问自己的公网地址（%s）全部失败。很多云主机不支持这样回访，不一定是问题；"+
				"请从另一台机器执行 curl 确认 judge 能从外面访问", dst)
		}
	}
	obsOK, obsN := 0, 0
	for name, r := range s.Control {
		if strings.HasPrefix(name, "control:observer") {
			obsOK += r.OK
			obsN += r.Total
		}
	}
	if obsN > 0 && obsOK == 0 {
		warn("直连第二观察者全部失败：本机出不了 HTTPS，或系统缺根证书（ca-certificates）")
	}
	viaObs, viaJudge := 0, 0
	for k, m := range s.Extras {
		if strings.HasPrefix(k, "observer ") {
			viaObs += m["ok"]
		}
	}
	for k, m := range s.Classes {
		if strings.HasSuffix(k, probe.DstJudgeTLS) || strings.HasSuffix(k, probe.DstJudgeHTTP) {
			viaJudge += m["ok"]
		}
	}
	f := s.Funnel["regular"]
	if f.Seen > 500 && viaJudge == 0 {
		warn("已探访 %d 个候选，没有一个能经代理到达 judge。若回环对照正常，多半是云厂商的安全组或防火墙没放行 judge 的端口", f.Seen)
	}
	if viaObs > 20 && viaJudge == 0 {
		warn("经代理能到第二观察者（%d 次），却到不了 judge：judge 的端口从外面访问不到", viaObs)
	}
	if f.Seen > 2000 && f.Working > 0 {
		share := 100 * float64(f.Working) / float64(f.Seen)
		if share > 60 {
			warn("曾经可用的候选占 %.0f%%，高得反常，先怀疑探测器把不可用的算成了可用", share)
		}
		if share < 1 {
			warn("曾经可用的候选只占 %.1f%%，低得反常，先检查 judge 是否可达、端口是否是 80 和 443", share)
		}
	}
	for _, row := range s.Snapshots {
		if row.Fetches >= 3 && row.Failed*2 > row.Fetches {
			warn("列表 %s 抓取 %d 次失败 %d 次（%s）", row.Src, row.Fetches, row.Failed, row.LastErr)
		}
	}
	for _, row := range s.Nodes.Subs {
		if row.Fetches >= 2 && row.Failed*2 > row.Fetches {
			warn("订阅 %s 抓取 %d 次失败 %d 次（%s）", row.Src, row.Fetches, row.Failed, row.LastErr)
		}
	}
	for name, fd := range s.Findings {
		if strings.HasPrefix(name, "仪器异常") || name == "探测器认为成功，但 judge 没收到请求" {
			warn("%s：%d 次。这类情况不该出现，数据在查明原因之前不可信", name, fd.Attempts)
		}
	}
	if s.Judge["req"] == 0 {
		warn("judge 的日志里没有任何探测请求")
	}
	if len(s.Nodes.Rounds) > 0 {
		last := s.Nodes.Rounds[len(s.Nodes.Rounds)-1]
		if last.Err != "" {
			warn("最近一轮节点探测出错：%s", last.Err)
		}
		if last.Probed > 200 && last.OKStrict+last.OKLinked == 0 {
			warn("最近一轮探测了 %d 个节点，没有一个可用，先检查 sing-box 是否正常", last.Probed)
		}
	} else if s.Nodes.Known > 0 && s.Hours > 3 {
		// 第一轮要对近两万个节点做预检再分批探测，一两个小时是正常的
		warn("已经见到 %d 个节点，运行了 %.1f 小时还没有完成任何一轮节点探测", s.Nodes.Known, s.Hours)
	}
	sort.Strings(s.Warnings)
}

// Text 把汇总写成给人看的文本。
func (s *Summary) Text(w io.Writer) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }
	p("实测汇总  生成于 %s", s.Generated)
	p("记录时间 %s 至 %s，共 %.2f 小时", s.First, s.Last, s.Hours)
	p("")
	if len(s.Warnings) == 0 {
		p("自动检查：没有发现问题")
	} else {
		p("自动检查发现 %d 个问题：", len(s.Warnings))
		for _, x := range s.Warnings {
			p("  ! %s", x)
		}
	}
	p("")
	p("对照（不经代理）")
	for _, k := range sortedKeys(s.Control) {
		p("  %-40s %d/%d", k, s.Control[k].OK, s.Control[k].Total)
	}
	p("")
	p("列表快照")
	for _, r := range s.Snapshots {
		kind := ""
		if r.Agg {
			kind = "  聚合器"
		}
		p("  %-36s 抓取 %3d 次  失败 %2d  有变化 %3d  当前条目 %7d%s", r.Src, r.Fetches, r.Failed, r.Changed, r.Current, kind)
	}
	for _, m := range s.AggSample {
		p("  抽样 %v: 合计 %v，独占 %v，抽中 %v", m["src"], m["union"], m["exclusive"], m["sample"])
	}
	p("")
	p("候选池 %v", fmtMap(s.Pool))
	for _, name := range []string{"regular", "aggregator_sample"} {
		f := s.Funnel[name]
		label := "常规列表"
		if name == "aggregator_sample" {
			label = "聚合器抽样"
		}
		p("%s：已探访 %d，连得上 %d（%s），有协议回应 %d（%s），曾通过端到端校验 %d（%s），最近一次可用 %d（%s），要求认证 %d",
			label, f.Seen, f.TCP, pct(f.TCP, f.Seen), f.Responsive, pct(f.Responsive, f.Seen), f.Working, pct(f.Working, f.Seen),
			f.WorkingNow, pct(f.WorkingNow, f.Seen), f.Auth)
	}
	p("")
	p("各来源（当前在榜 / 已探访 / 最近一次可用 / 曾经可用）")
	for _, r := range s.BySource {
		p("  %-36s %6d %6d %6d (%s) %6d (%s)", r.Src, r.Listed, r.Visited, r.WorkingNow, pct(r.WorkingNow, r.Visited),
			r.Working, pct(r.Working, r.Visited))
	}
	p("")
	p("标签与实测（连得上的候选：列表标签 → 实测可用的协议 → 个数）")
	for _, l := range sortedKeys(s.Labels) {
		p("  %-24s %s", l, fmtMap(s.Labels[l]))
	}
	p("")
	p("各类尝试的结果（协议>目的地：类别 次数）")
	for _, k := range sortedKeys(s.Classes) {
		p("  %-22s %s", k, fmtMap(s.Classes[k]))
	}
	p("")
	p("成功尝试的耗时 p50/p90/p99（毫秒）")
	for _, k := range sortedKeys(s.Latency) {
		v := s.Latency[k]
		p("  %-10s %d / %d / %d", k, v[0], v[1], v[2])
	}
	p("")
	p("发现（尝试数 / 涉及的候选数）")
	if len(s.Findings) == 0 {
		p("  无")
	}
	for _, k := range sortedKeys(s.Findings) {
		f := s.Findings[k]
		p("  %s: %d / %d", k, f.Attempts, f.Cands)
		for _, e := range f.Examples {
			p("      %s", e)
		}
	}
	p("")
	p("明文转发的匿名程度（成功的请求数）: %s", fmtMap(s.Anon))
	p("每个可用代理的出口地址数: %s", fmtMap(s.Egress))
	for _, k := range sortedKeys(s.Extras) {
		p("  %-32s %s", k, fmtMap(s.Extras[k]))
	}
	p("")
	n := s.Nodes
	p("节点：见过 %d 个  %s", n.Known, fmtMap(n.ByScheme))
	p("  sing-box 连不了的: %s", fmtMap(n.Unsupported))
	for _, r := range n.Subs {
		p("  订阅 %-36s 抓取 %3d 次  失败 %2d  当前节点 %6d", r.Src, r.Fetches, r.Failed, r.Current)
	}
	for _, r := range n.Rounds {
		p("  第 %d 轮 %s: 在榜 %d，可探测 %d，退避跳过 %d，预检连得上 %d，已探测 %d，严格校验可用 %d，仅跳过校验可用 %d，配置被拒 %d，%d 批，%.1f 分钟 %s",
			r.Round, r.TS, r.Listed, r.Supported, r.Backoff, r.TCPOK, r.Probed, r.OKStrict, r.OKLinked, r.BadConfig, r.Batches,
			float64(r.Ms)/60000, r.Err)
	}
	p("  预检结果: %s", fmtMap(n.Pre))
	p("  隧道探测结果: %s", fmtMap(n.Classes))
	for _, k := range sortedKeys(n.OK) {
		p("  曾经可用 %-8s %s", k, fmtMap(n.OK[k]))
	}
	p("  出口: %s", fmtMap(n.Egress))
	if len(n.Errors) > 0 {
		p("  sing-box 报的错误（前 12 种）:")
		type kv struct {
			k string
			v int
		}
		var es []kv
		for k, v := range n.Errors {
			es = append(es, kv{k, v})
		}
		sort.Slice(es, func(i, j int) bool { return es[i].v > es[j].v })
		for i, e := range es {
			if i >= 12 {
				break
			}
			p("    %6d  %s", e.v, e.k)
		}
	}
	p("")
	p("judge 日志: %s", fmtMap(s.Judge))
	p("记录数: %s", fmtMap(s.Records))
	p("连接速率: %v", s.Rate)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fmtMap(m map[string]int) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, "  ")
}

// BodyChange 给“正文与期望不符”分类。只有局部改动算篡改；截断多半是传输问题，整页替换多半是错误页或门户页。
// 文本载荷：期望正文里不少于一半的行原样出现在收到的正文里，算局部改动。
// 二进制载荷：公共前缀和后缀合计不少于九成，算局部改动。
func BodyChange(kind string, gotLen, pre, sim, wantLen int) string {
	switch {
	case pre == gotLen && gotLen < wantLen:
		return "正文被截断"
	case kind == "b" && sim >= 90, kind != "b" && sim >= 50:
		return "正文被局部改动（注入或改写）"
	}
	return "正文被整页替换"
}
