package probe

import (
	"compress/gzip"
	"container/heap"
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"os"
	"sync"
	"time"

	"fieldtest/internal/lists"
)

// Limiter 限制每秒新建连接的数量（令牌桶）。
type Limiter struct {
	ch   chan struct{}
	stop chan struct{}
}

func NewLimiter(perSec float64) *Limiter {
	burst := int(perSec)
	if burst < 1 {
		burst = 1
	}
	l := &Limiter{ch: make(chan struct{}, burst), stop: make(chan struct{})}
	interval := time.Duration(float64(time.Second) / perSec)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case l.ch <- struct{}{}:
				default:
				}
			case <-l.stop:
				return
			}
		}
	}()
	return l
}

func (l *Limiter) Wait(ctx context.Context) error {
	select {
	case <-l.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Limiter) Close() { close(l.stop) }

// 协议位。
const (
	PSocks5 uint8 = 1 << iota
	PSocks4
	PConnect
	PForward
)

var protoBits = []struct {
	bit  uint8
	name string
}{{PSocks5, Socks5}, {PConnect, Connect}, {PForward, Forward}, {PSocks4, Socks4}}

func protoBit(name string) uint8 {
	for _, p := range protoBits {
		if p.name == name {
			return p.bit
		}
	}
	return 0
}

// ProtoNames 把协议位展开成名字。
func ProtoNames(mask uint8) []string {
	var out []string
	for _, p := range protoBits {
		if mask&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

// 候选的状态。
const (
	StNew     uint8 = iota
	StWorking       // 上次探访至少有一种协议通过了端到端校验
	StOpen          // 端口连得上，但没有任何协议通过校验
	StDead          // 连不上
)

var stateNames = []string{"new", "working", "open", "dead"}

// Cand 是一个候选代理。
type Cand struct {
	Key        string          `json:"key"`
	Group      uint8           `json:"group,omitempty"` // 0 常规列表；1 聚合器抽样
	Srcs       map[uint8]uint8 `json:"srcs,omitempty"`  // 来源编号 → 该来源给它贴的标签；只含当前还列着它的来源
	Labels     uint8           `json:"labels"`          // 历史上出现过的全部标签
	FirstSeen  time.Time       `json:"first_seen"`
	DelistedAt time.Time       `json:"delisted_at,omitzero"`
	Next       time.Time       `json:"next"`
	Visits     int             `json:"visits,omitempty"`
	Fails      int             `json:"fails,omitempty"`
	State      uint8           `json:"state,omitempty"`
	OKMask     uint8           `json:"ok_mask,omitempty"`
	EverOK     bool            `json:"ever_ok,omitempty"`
	LastOK     time.Time       `json:"last_ok,omitzero"`
	LastFull   time.Time       `json:"last_full,omitzero"`
	LastExtra  time.Time       `json:"last_extra,omitzero"`
	addr       netip.AddrPort
	busy       bool
	idx        int
}

func (c *Cand) Listed() bool { return len(c.Srcs) > 0 }

type candHeap []*Cand

func (h candHeap) Len() int           { return len(h) }
func (h candHeap) Less(i, j int) bool { return h[i].Next.Before(h[j].Next) }
func (h candHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].idx = i; h[j].idx = j }
func (h *candHeap) Push(x any)        { c := x.(*Cand); c.idx = len(*h); *h = append(*h, c) }
func (h *candHeap) Pop() any {
	old := *h
	n := len(old)
	c := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	c.idx = -1
	return c
}

// Pool 保存全部候选并决定下一个该探访谁。
type Pool struct {
	mu       sync.Mutex
	cands    map[string]*Cand
	due      candHeap
	busyIP   map[netip.Addr]int
	busyPfx  map[netip.Prefix]int
	skipPort map[uint16]bool
	exclude  []netip.Prefix
	selfIP   netip.Addr
	allowLo  bool
	perPfx   int
	Skipped  map[string]int // 因各种原因没有纳入探测的条目数
	Dropped  int
	sampled  map[string]bool // 已经抽过样的聚合器
}

// Sampled 返回某个聚合器是否已经抽过样。
func (p *Pool) Sampled(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sampled[name]
}

// MarkSampled 记下某个聚合器已经抽过样；这个标记随状态文件保存，重启后不会重抽。
func (p *Pool) MarkSampled(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sampled == nil {
		p.sampled = map[string]bool{}
	}
	p.sampled[name] = true
}

type poolState struct {
	Cands   []Cand   `json:"cands"`
	Sampled []string `json:"sampled,omitempty"`
}

func NewPool(selfIP netip.Addr, skipPorts []int, perPrefix int, allowLocal bool) *Pool {
	p := &Pool{cands: map[string]*Cand{}, busyIP: map[netip.Addr]int{}, busyPfx: map[netip.Prefix]int{},
		skipPort: map[uint16]bool{}, selfIP: selfIP, allowLo: allowLocal, perPfx: perPrefix, Skipped: map[string]int{}}
	for _, v := range skipPorts {
		p.skipPort[uint16(v)] = true
	}
	return p
}

// With 在持有锁的情况下执行 f。探访开始时读候选的字段、结束时写回，都要经过它：
// 快照采集器和状态保存会在别的协程里读写同一个候选。
func (p *Pool) With(f func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f()
}

// SetExclude 设置不探测的地址段。
func (p *Pool) SetExclude(pfx []netip.Prefix) {
	p.mu.Lock()
	p.exclude = pfx
	p.mu.Unlock()
}

// ineligible 返回不探测这个地址的原因；可以探测时返回空串。
func (p *Pool) ineligible(ap netip.AddrPort) string {
	a := ap.Addr()
	switch {
	case !a.Is4():
		return "not_ipv4"
	case a == p.selfIP:
		return "self"
	case !p.allowLo && !lists.IsPublicV4(a):
		return "not_public"
	case p.skipPort[ap.Port()]:
		return "skip_port"
	}
	for _, x := range p.exclude {
		if x.Contains(a) {
			return "excluded"
		}
	}
	return ""
}

// Upsert 记下“来源 src 以标签 label 列出了 key”。新候选会尽快被探访。返回是否是新候选。
func (p *Pool) Upsert(key string, src, label, group uint8, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.cands[key]
	if c == nil {
		ap, err := netip.ParseAddrPort(key)
		if err != nil {
			p.Skipped["unparsable"]++
			return false
		}
		if why := p.ineligible(ap); why != "" {
			p.Skipped[why]++
			return false
		}
		c = &Cand{Key: key, Group: group, Srcs: map[uint8]uint8{}, FirstSeen: now, addr: ap, idx: -1,
			// 新到的条目在一分钟内随机错开，避免一次快照带来的几千个条目同时发起连接
			Next: now.Add(time.Duration(rand.Int64N(int64(60 * time.Second))))}
		p.cands[key] = c
		heap.Push(&p.due, c)
		c.Srcs[src] |= label
		c.Labels |= label
		return true
	}
	if group < c.Group {
		c.Group = group // 聚合器抽样里的条目后来也出现在常规列表里
	}
	if c.Srcs == nil {
		c.Srcs = map[uint8]uint8{}
	}
	c.Srcs[src] |= label
	c.Labels |= label
	c.DelistedAt = time.Time{}
	return false
}

// Delist 记下“来源 src 不再以标签 label 列出 key”。
func (p *Pool) Delist(key string, src, label uint8, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.cands[key]
	if c == nil {
		return
	}
	if m := c.Srcs[src] &^ label; m == 0 {
		delete(c.Srcs, src)
	} else {
		c.Srcs[src] = m
	}
	if len(c.Srcs) == 0 && c.DelistedAt.IsZero() {
		c.DelistedAt = now
	}
}

// Take 取出一个到期且可以探访的候选；没有则返回 nil。
// 同一个 IP 同时只探访一个端口，同一个 /24 同时探访的数量有上限。
func (p *Pool) Take(now time.Time) *Cand {
	p.mu.Lock()
	defer p.mu.Unlock()
	var held []*Cand
	var got *Cand
	for len(p.due) > 0 && !p.due[0].Next.After(now) && len(held) < 64 {
		c := heap.Pop(&p.due).(*Cand)
		pfx, _ := c.addr.Addr().Prefix(24)
		if p.busyIP[c.addr.Addr()] > 0 || p.busyPfx[pfx] >= p.perPfx {
			held = append(held, c)
			continue
		}
		p.busyIP[c.addr.Addr()]++
		p.busyPfx[pfx]++
		c.busy = true
		got = c
		break
	}
	for _, c := range held {
		c.Next = now.Add(5*time.Second + time.Duration(rand.Int64N(int64(5*time.Second))))
		heap.Push(&p.due, c)
	}
	return got
}

// Done 归还一个候选。next 为零值表示不再探访它。
func (p *Pool) Done(c *Cand, next time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pfx, _ := c.addr.Addr().Prefix(24)
	if p.busyIP[c.addr.Addr()]--; p.busyIP[c.addr.Addr()] <= 0 {
		delete(p.busyIP, c.addr.Addr())
	}
	if p.busyPfx[pfx]--; p.busyPfx[pfx] <= 0 {
		delete(p.busyPfx, pfx)
	}
	c.busy = false
	if next.IsZero() {
		delete(p.cands, c.Key)
		p.Dropped++
		return
	}
	c.Next = next
	heap.Push(&p.due, c)
}

// Stats 返回各状态的候选数。
func (p *Pool) Stats() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]int{"total": len(p.cands), "dropped": p.Dropped}
	for _, c := range p.cands {
		out[stateNames[c.State]]++
		if c.Listed() {
			out["listed"]++
		}
		if c.Group == 1 {
			out["aggregator_sample"]++
		}
	}
	for k, v := range p.Skipped {
		out["skipped_"+k] = v
	}
	return out
}

// Keys 返回某一组里全部候选的键。
func (p *Pool) Keys(group uint8) map[string]struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]struct{}, len(p.cands))
	for k, c := range p.cands {
		if c.Group == group {
			out[k] = struct{}{}
		}
	}
	return out
}

// Save 把候选的状态写到文件，重启后可以接着跑。
func (p *Pool) Save(path string) error {
	p.mu.Lock()
	list := make([]Cand, 0, len(p.cands))
	for _, c := range p.cands {
		cp := *c
		cp.Srcs = make(map[uint8]uint8, len(c.Srcs))
		for k, v := range c.Srcs {
			cp.Srcs[k] = v
		}
		list = append(list, cp)
	}
	st := poolState{Cands: list}
	for name := range p.sampled {
		st.Sampled = append(st.Sampled, name)
	}
	p.mu.Unlock()
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	err = json.NewEncoder(zw).Encode(st)
	if e := zw.Close(); err == nil {
		err = e
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Load 读回上次保存的状态。来源的在榜信息不恢复，由重启后的第一次快照重建。
func (p *Pool) Load(path string, now time.Time) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	var st poolState
	if err := json.NewDecoder(zr).Decode(&st); err != nil {
		return 0, err
	}
	list := st.Cands
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, name := range st.Sampled {
		if p.sampled == nil {
			p.sampled = map[string]bool{}
		}
		p.sampled[name] = true
	}
	n := 0
	for i := range list {
		c := &list[i]
		ap, err := netip.ParseAddrPort(c.Key)
		if err != nil || p.cands[c.Key] != nil {
			continue
		}
		c.addr, c.idx, c.busy = ap, -1, false
		if len(c.Srcs) > 0 {
			c.DelistedAt = now // 保存时还在榜上：先当作刚下榜，若其实还在，第一次快照会把这个时间清掉
		}
		c.Srcs = map[uint8]uint8{}
		if c.Next.Before(now) {
			c.Next = now.Add(time.Duration(rand.Int64N(int64(2 * time.Minute))))
		}
		p.cands[c.Key] = c
		heap.Push(&p.due, c)
		n++
	}
	return n, nil
}
