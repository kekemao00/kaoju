// Package lists 解析公开代理列表，并定时给它们拍快照。
//
// 解析规则与普查脚本 research/census/census.py 的 parse_blob 相同，两边的数字才能对得上。
package lists

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed sources.json
var defaultSources []byte

// Label 是列表给条目贴的协议标签，用位表示，一个条目可以有多个。
const (
	LHTTP uint8 = 1 << iota
	LHTTPS
	LConnect
	LSocks4
	LSocks5
)

var labelNames = []struct {
	bit  uint8
	name string
}{{LHTTP, "http"}, {LHTTPS, "https"}, {LConnect, "connect"}, {LSocks4, "socks4"}, {LSocks5, "socks5"}}

func LabelBit(name string) uint8 {
	for _, l := range labelNames {
		if l.name == name {
			return l.bit
		}
	}
	return 0
}

func LabelNames(mask uint8) []string {
	var out []string
	for _, l := range labelNames {
		if mask&l.bit != 0 {
			out = append(out, l.name)
		}
	}
	return out
}

type List struct {
	Name       string            `json:"name"`
	Aggregator bool              `json:"aggregator,omitempty"`
	Files      map[string]string `json:"files"` // 标签 → URL
}

type Subscription struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Sources struct {
	Lists         []List         `json:"lists"`
	Subscriptions []Subscription `json:"subscriptions"`
}

// LoadSources 读来源清单；path 为空时用编译进程序的那一份。
func LoadSources(path string) (*Sources, error) {
	b := defaultSources
	if path != "" {
		var err error
		if b, err = os.ReadFile(path); err != nil {
			return nil, err
		}
	}
	var s Sources
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("来源清单: %w", err)
	}
	if len(s.Lists) > 250 {
		return nil, fmt.Errorf("来源清单里的列表太多（%d）", len(s.Lists))
	}
	for _, l := range s.Lists {
		for label := range l.Files {
			if LabelBit(label) == 0 {
				return nil, fmt.Errorf("来源 %s: 不认识的标签 %q", l.Name, label)
			}
		}
	}
	return &s, nil
}

// ---------------------------------------------------------------- 解析

var (
	lineRE = regexp.MustCompile(`^\s*(?:([a-zA-Z0-9+.-]+)://)?(?:([^@/\s]+)@)?` +
		`(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?(.*)$`)
	hostRE = regexp.MustCompile(`^\s*(?:[a-zA-Z0-9+.-]+://)?(?:[^@/\s]+@)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}:\d{1,5}`)
)

// Quality 统计一个文件里各种不合格的行。
type Quality struct {
	Lines     int `json:"lines,omitempty"`
	Garbage   int `json:"garbage,omitempty"`
	Hostname  int `json:"hostname,omitempty"`
	NoPort    int `json:"no_port,omitempty"`
	BadRange  int `json:"bad_range,omitempty"`
	Duplicate int `json:"duplicate,omitempty"`
	WithCreds int `json:"with_credentials,omitempty"`
}

// Parse 解析一个列表文件，返回规范化的 "ip:port" 集合。
func Parse(text []byte) (map[string]struct{}, Quality) {
	entries := make(map[string]struct{}, 1024)
	var q Quality
	for len(text) > 0 {
		var raw []byte
		if i := indexNewline(text); i >= 0 {
			raw, text = text[:i], text[i+1:]
		} else {
			raw, text = text, nil
		}
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		q.Lines++
		key, why, creds := parseLine(line)
		if creds {
			q.WithCreds++
		}
		switch why {
		case "":
			if _, dup := entries[key]; dup {
				q.Duplicate++
			} else {
				entries[key] = struct{}{}
			}
		case "garbage":
			q.Garbage++
		case "hostname":
			q.Hostname++
		case "no_port":
			q.NoPort++
		case "bad_range":
			q.BadRange++
		}
	}
	return entries, q
}

func indexNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' || c == '\r' {
			return i
		}
	}
	return -1
}

// ParseLine 解析一行。成功时返回规范化的 "ip:port"；否则返回不合格的原因。
func ParseLine(line string) (key, why string) {
	key, why, _ = parseLine(line)
	return key, why
}

// parseLine 另外返回这一行是否带着用户名密码（user:pass@ip:port 的写法）。
func parseLine(line string) (key, why string, creds bool) {
	if k, ok, bad := fastIPPort(line); ok {
		if bad {
			return "", "bad_range", false
		}
		return k, "", false
	}
	m := lineRE.FindStringSubmatch(line)
	if m == nil {
		if hostRE.MatchString(line) {
			return "", "hostname", false
		}
		return "", "garbage", false
	}
	creds = m[2] != ""
	port, rest := m[7], m[8]
	// 普查脚本的正则要求端口后面不能紧跟数字（1.2.3.4:123456 不算有端口）
	if port != "" && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		port = ""
	}
	if port == "" {
		return "", "no_port", creds
	}
	var o [4]int
	for i := 0; i < 4; i++ {
		o[i] = atoi(m[3+i])
	}
	p := atoi(port)
	if o[0] > 255 || o[1] > 255 || o[2] > 255 || o[3] > 255 || p < 1 || p > 65535 {
		return "", "bad_range", creds
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", o[0], o[1], o[2], o[3], p), "", creds
}

// fastIPPort 处理最常见的形式：整行就是 a.b.c.d:port。
func fastIPPort(s string) (key string, ok, bad bool) {
	var nums [5]int
	var digits [5]int
	part := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			nums[part] = nums[part]*10 + int(c-'0')
			digits[part]++
			if (part < 4 && digits[part] > 3) || digits[part] > 5 {
				return "", false, false
			}
		case c == '.' && part < 3 && digits[part] > 0:
			part++
		case c == ':' && part == 3 && digits[part] > 0:
			part++
		default:
			return "", false, false
		}
	}
	if part != 4 || digits[4] == 0 {
		return "", false, false
	}
	if nums[0] > 255 || nums[1] > 255 || nums[2] > 255 || nums[3] > 255 || nums[4] < 1 || nums[4] > 65535 {
		return "", true, true
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", nums[0], nums[1], nums[2], nums[3], nums[4]), true, false
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// ---------------------------------------------------------------- 探测资格

var reserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsPublicV4 判断地址是不是公网上可路由的 IPv4 单播地址。
func IsPublicV4(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- 快照

// SnapRec 是一次抓取的记录。内容有变化时带上增减的条目；第一次（base）带上全部条目。
type SnapRec struct {
	TS      string   `json:"ts"`
	K       string   `json:"k"` // snap
	Src     string   `json:"src"`
	Label   string   `json:"label"`
	Status  int      `json:"status"`
	Err     string   `json:"err,omitempty"`
	ETag    string   `json:"etag,omitempty"`
	SHA256  string   `json:"sha256,omitempty"`
	Bytes   int      `json:"bytes,omitempty"`
	N       int      `json:"n,omitempty"` // 有效条目数
	Q       *Quality `json:"q,omitempty"`
	Base    bool     `json:"base,omitempty"`
	Agg     bool     `json:"agg,omitempty"` // 聚合器：只记数量，不记条目
	Add     []string `json:"add,omitempty"`
	Del     []string `json:"del,omitempty"`
	Ms      int64    `json:"ms"`
	Changed bool     `json:"changed,omitempty"`
}

// File 记住一个列表文件上一次的状态。
type File struct {
	Src, Label, URL string
	Agg             bool
	ETag            string
	SHA             string
	Prev            map[string]struct{}
	Fetched         bool
}

// Fetcher 抓取列表文件。
type Fetcher struct {
	Client *http.Client
	MaxLen int64
}

func NewFetcher() *Fetcher {
	return &Fetcher{Client: &http.Client{Timeout: 90 * time.Second}, MaxLen: 64 << 20}
}

// Get 做一次条件请求。内容没变时返回 (nil, 304)。网络错误和 5xx 会隔一秒重试一次。
func (f *Fetcher) Get(ctx context.Context, url, etag string) (body []byte, status int, newETag string, err error) {
	body, status, newETag, err = f.get(ctx, url, etag)
	if (err != nil || status >= 500) && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			body, status, newETag, err = f.get(ctx, url, etag)
		}
	}
	return body, status, newETag, err
}

func (f *Fetcher) get(ctx context.Context, url, etag string) (body []byte, status int, newETag string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("User-Agent", "fieldtest-snapshot/1 (list measurement)")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, resp.StatusCode, "", nil
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, f.MaxLen))
	return body, resp.StatusCode, resp.Header.Get("ETag"), err
}

// Snapshot 抓取一个文件并与上次比较。返回记录，以及这次的完整集合（内容没变时为 nil）。
func (f *Fetcher) Snapshot(ctx context.Context, file *File, now time.Time) (SnapRec, map[string]struct{}) {
	t0 := time.Now()
	r := SnapRec{TS: now.UTC().Format("2006-01-02T15:04:05.000Z"), K: "snap", Src: file.Src, Label: file.Label, Agg: file.Agg}
	body, status, etag, err := f.Get(ctx, file.URL, file.ETag)
	r.Status, r.Ms = status, time.Since(t0).Milliseconds()
	if err != nil {
		r.Err = trim(err.Error(), 200)
		return r, nil
	}
	if status != http.StatusOK {
		return r, nil
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	r.ETag, r.SHA256, r.Bytes = etag, sha, len(body)
	file.ETag = etag
	if file.Fetched && sha == file.SHA {
		return r, nil // ETag 变了但内容没变
	}
	set, q := Parse(body)
	r.N, r.Q, r.Changed = len(set), &q, true
	if !file.Agg {
		if !file.Fetched {
			r.Base = true
			r.Add = sortedKeys(set)
		} else {
			for k := range set {
				if _, ok := file.Prev[k]; !ok {
					r.Add = append(r.Add, k)
				}
			}
			for k := range file.Prev {
				if _, ok := set[k]; !ok {
					r.Del = append(r.Del, k)
				}
			}
			sort.Strings(r.Add)
			sort.Strings(r.Del)
		}
		file.Prev = set
	}
	file.SHA, file.Fetched = sha, true
	return r, set
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
