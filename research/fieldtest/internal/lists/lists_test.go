package lists

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	cases := []struct{ line, key, why string }{
		{"1.2.3.4:8080", "1.2.3.4:8080", ""},
		{"001.002.003.004:0080", "1.2.3.4:80", ""},
		{"http://1.2.3.4:8080", "1.2.3.4:8080", ""},
		{"socks5://user:pass@1.2.3.4:1080", "1.2.3.4:1080", ""},
		{"1.2.3.4:8080:user:pass", "1.2.3.4:8080", ""},
		{"1.2.3.4:8080 US anonymous", "1.2.3.4:8080", ""},
		{"1.2.3.4", "", "no_port"},
		{"1.2.3.4:123456", "", "no_port"}, // 端口后面紧跟数字：普查脚本算作没有端口
		{"1.2.3.4:0", "", "bad_range"},
		{"1.2.3.4:65536", "", "bad_range"},
		{"256.1.1.1:80", "", "bad_range"},
		{"999.1.1.1:80", "", "bad_range"},
		{"example.com:8080", "", "hostname"},
		{"not a proxy", "", "garbage"},
		{"# comment", "", "garbage"},
		{"", "", "garbage"},
	}
	for _, c := range cases {
		key, why := ParseLine(c.line)
		if key != c.key || why != c.why {
			t.Errorf("%q: 得到 (%q, %q)，期望 (%q, %q)", c.line, key, why, c.key, c.why)
		}
	}
}

func TestParseQuality(t *testing.T) {
	set, q := Parse([]byte("1.1.1.1:80\r\n1.1.1.1:80\n\nfoo\nexample.org:3128\nu:p@2.2.2.2:1080\n3.3.3.3\n4.4.4.4:99999\n"))
	if len(set) != 2 || q.Lines != 7 || q.Duplicate != 1 || q.Garbage != 1 || q.Hostname != 1 || q.NoPort != 1 ||
		q.BadRange != 1 || q.WithCreds != 1 {
		t.Errorf("集合 %v，计数 %+v", set, q)
	}
}

func TestIsPublicV4(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "93.184.216.34": true, "10.1.2.3": false, "127.0.0.1": false, "169.254.169.254": false,
		"172.16.0.1": false, "172.32.0.1": true, "192.168.1.1": false, "100.64.0.1": false, "224.0.0.1": false,
		"240.0.0.1": false, "0.1.2.3": false, "198.18.0.1": false, "192.0.2.1": false,
	} {
		if got := IsPublicV4(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v，期望 %v", addr, got, want)
		}
	}
}

func TestEmbeddedSources(t *testing.T) {
	s, err := LoadSources("")
	if err != nil {
		t.Fatal(err)
	}
	agg := 0
	for _, l := range s.Lists {
		if l.Aggregator {
			agg++
		}
		for _, u := range l.Files {
			if !strings.HasPrefix(u, "https://raw.githubusercontent.com/") {
				t.Errorf("%s: 不是 raw.githubusercontent.com 的地址: %s", l.Name, u)
			}
		}
	}
	if len(s.Lists) != 18 || agg != 4 || len(s.Subscriptions) != 11 {
		t.Errorf("来源清单应有 18 个列表（其中 4 个聚合器）和 11 个订阅，实际 %d / %d / %d", len(s.Lists), agg, len(s.Subscriptions))
	}
}

func FuzzParse(f *testing.F) {
	f.Add("1.2.3.4:80\nhttp://u:p@5.6.7.8:3128 extra\n")
	f.Add("\x00\xff:::\n999.999.999.999:99999\n")
	f.Fuzz(func(t *testing.T, s string) {
		set, _ := Parse([]byte(s))
		for k := range set {
			ap, err := netip.ParseAddrPort(k)
			if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
				t.Fatalf("解析出了不合法的条目 %q", k)
			}
		}
	})
}

// TestCensusEquivalence 逐个文件核对：Go 解析器与普查脚本对同一份列表文件得出完全相同的条目集合和质量计数。
// 需要 FIELDTEST_HIST_DIR 指向普查时克隆的列表仓库目录，并且能运行 python3。
func TestCensusEquivalence(t *testing.T) {
	hist := os.Getenv("FIELDTEST_HIST_DIR")
	if hist == "" {
		t.Skip("未设置 FIELDTEST_HIST_DIR")
	}
	out, err := exec.Command("python3", "../../../census/parse_check.py", "--hist-dir", hist).Output()
	if err != nil {
		t.Fatalf("运行普查脚本: %v", err)
	}
	var want map[string]struct {
		N      int            `json:"n"`
		SHA256 string         `json:"sha256"`
		Q      map[string]int `json:"q"`
	}
	if err := json.Unmarshal(out, &want); err != nil {
		t.Fatal(err)
	}
	total := 0
	for name, w := range want {
		raw, err := os.ReadFile(filepath.Join(hist, name))
		if err != nil {
			t.Fatal(err)
		}
		set, q := Parse([]byte(strings.ToValidUTF8(string(raw), "�")))
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
		got := map[string]int{"lines": q.Lines, "garbage": q.Garbage, "hostname": q.Hostname, "no_port": q.NoPort,
			"bad_range": q.BadRange, "duplicate": q.Duplicate, "with_credentials": q.WithCreds}
		if len(set) != w.N || hex.EncodeToString(sum[:]) != w.SHA256 {
			t.Errorf("%s: 条目集合不同（Go %d 条，普查 %d 条）", name, len(set), w.N)
		}
		for k, v := range got {
			if v != w.Q[k] {
				t.Errorf("%s: %s 计数不同（Go %d，普查 %d）", name, k, v, w.Q[k])
			}
		}
		total += len(set)
	}
	t.Logf("核对了 %d 个文件，共 %d 个条目", len(want), total)
}
