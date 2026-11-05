package nodes

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// 与 research/census/nodes_census.py 的 SOURCES 相同：订阅仓库的克隆目录和文件。
var censusFiles = [][2]string{
	{"barry-far__V2ray-config", "All_Configs_Sub.txt"},
	{"MatinGhanbari__v2ray-configs", "subscriptions/base64/all_sub.txt"},
	{"mahdibland__V2RayAggregator", "sub/sub_merge.txt"},
	{"mheidari98__.proxy", "all"},
	{"peasoft__NoMoreWalls", "list_raw.txt"},
	{"chengaopan__AutoMergePublicNodes", "list_raw.txt"},
	{"mfuu__v2ray", "sub"},
	{"aiboboxx__v2rayfree", "sub"},
	{"Pawdroid__Free-servers", "sub"},
	{"snakem982__proxypool", "source/v2ray-2.txt"},
	{"roosterkid__openproxylist", "V2RAY_RAW.txt"},
}

// TestCensusEquivalence 用普查时克隆下来的订阅文件核对两件事：
// Go 解析器的去重结果与 Python 普查脚本一致；全部可映射的节点都能通过 sing-box 的配置检查。
// 需要 FIELDTEST_NODES_DIR（克隆目录）；设置了 FIELDTEST_SINGBOX 时才做配置检查。
func TestCensusEquivalence(t *testing.T) {
	dir := os.Getenv("FIELDTEST_NODES_DIR")
	if dir == "" {
		t.Skip("未设置 FIELDTEST_NODES_DIR")
	}
	uniq := map[string]*Node{}
	lines, unparsed := 0, 0
	for _, f := range censusFiles {
		raw, err := os.ReadFile(filepath.Join(dir, f[0], f[1]))
		if err != nil {
			t.Fatalf("读 %s: %v", f[0], err)
		}
		for _, ln := range Links(LoadText(raw)) {
			lines++
			n := Parse(ln)
			if n == nil {
				unparsed++
				continue
			}
			if _, ok := uniq[n.ID]; !ok {
				uniq[n.ID] = n
			}
		}
	}
	byScheme, reasons := map[string]int{}, map[string]int{}
	var members []Member
	strict, linked := 0, 0
	for _, n := range uniq {
		byScheme[n.Scheme]++
		why := Supported(n)
		if why != "" {
			reasons[why]++
			continue
		}
		strict++
		members = append(members, Member{Tag: "n" + n.ID, Outbound: Outbound(n, "n"+n.ID, false)})
		if n.Insecure && (n.Sec == "tls") {
			linked++
			members = append(members, Member{Tag: "n" + n.ID + "_i", Outbound: Outbound(n, "n"+n.ID+"_i", true)})
		}
	}
	t.Logf("链接 %d 行，解析不了 %d 行，去重后 %d 个节点", lines, unparsed, len(uniq))
	t.Logf("按协议: %s", fmtCounts(byScheme))

	// 与普查脚本的输出核对：去重后的节点数和各协议的节点数必须完全相同
	if b, err := os.ReadFile("../../../census/out/nodes_summary.json"); err != nil {
		t.Errorf("读普查结果: %v", err)
	} else {
		var census struct {
			Pool struct {
				Unique   int            `json:"unique_nodes"`
				ByScheme map[string]int `json:"by_scheme"`
			} `json:"pool"`
		}
		if err := json.Unmarshal(b, &census); err != nil {
			t.Fatal(err)
		}
		if len(uniq) != census.Pool.Unique {
			t.Errorf("去重后的节点数 %d，普查是 %d", len(uniq), census.Pool.Unique)
		}
		for sch, n := range census.Pool.ByScheme {
			if byScheme[sch] != n {
				t.Errorf("%s 节点数 %d，普查是 %d", sch, byScheme[sch], n)
			}
		}
	}
	t.Logf("可映射 %d 个（另有 %d 个照链接要求跳过校验的对照出站）；不可映射的原因: %s", strict, linked, fmtCounts(reasons))

	bin := os.Getenv("FIELDTEST_SINGBOX")
	if bin == "" {
		return
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Tag < members[j].Tag })
	bad := map[string]string{}
	t0 := time.Now()
	checks := 0
	var check func(ms []Member)
	check = func(ms []Member) {
		if len(ms) == 0 {
			return
		}
		path := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(path, Config(17998, ms), 0o600)
		checks++
		out, err := exec.Command(bin, "check", "-c", path).CombinedOutput()
		if err == nil {
			return
		}
		if len(ms) == 1 {
			msg := strings.TrimSpace(string(out))
			if i := strings.LastIndex(msg, "FATAL"); i >= 0 {
				msg = msg[i:]
			}
			bad[ms[0].Tag] = msg
			return
		}
		check(ms[:len(ms)/2])
		check(ms[len(ms)/2:])
	}
	for i := 0; i < len(members); i += 400 {
		check(members[i:min(i+400, len(members))])
	}
	kinds := map[string]int{}
	examples := map[string]string{}
	for tag, msg := range bad {
		k := msg
		if i := strings.Index(k, "]: "); i >= 0 {
			k = k[i+3:]
		}
		if len(k) > 70 {
			k = k[:70]
		}
		kinds[k]++
		examples[k] = tag + ": " + msg
	}
	t.Logf("sing-box check: %d 个出站，%d 个被拒（%d 次检查，%.1f 秒）", len(members), len(bad), checks, time.Since(t0).Seconds())
	for k, v := range kinds {
		t.Logf("  %5d  %s\n         例: %s", v, k, trimTo(examples[k], 260))
	}
}

func trimTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func fmtCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] })
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, "、")
}
