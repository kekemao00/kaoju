package summary

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fieldtest/internal/cfg"
	"fieldtest/internal/nodes"
	"fieldtest/internal/probe"
)

// writeSnap 把记录按探测器的格式（每行一个 JSON）写进数据目录。gz 为真时写成压缩过的小时文件。
func writeSnap(t *testing.T, dir, name string, gz bool, recs ...any) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var w interface {
		Write([]byte) (int, error)
	} = f
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(f)
		w = zw
	}
	enc := json.NewEncoder(w)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func nodeRec(ts, src string, n *nodes.Node, why string) probe.NodeRec {
	return probe.NodeRec{TS: ts, K: "node", Src: src, Node: n, Why: why}
}

// 探测器重启后会把还在榜的节点再记一遍（probe.NodeRun.learn 的状态只在进程内）。
// 汇总必须按节点 ID 只数一次，否则节点数、各协议的节点数、不支持的原因都会翻倍。
// 0.1.1 修的就是这个问题；之前只有端到端测试的“节点只数一次”一项兜底。
func TestNodesCountedOnceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	c := cfg.Default()
	c.DataDir = dir
	c.Judge.Host = "judge.test"
	c.Judge.PublicIP = "192.0.2.1"
	if err := os.WriteFile(c.Path("secret"), []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &nodes.Node{ID: "aaaaaaaaaaaa", Scheme: "vless", Host: "198.51.100.1", Port: 443}
	b := &nodes.Node{ID: "bbbbbbbbbbbb", Scheme: "vmess", Host: "198.51.100.2", Port: 443}
	cc := &nodes.Node{ID: "cccccccccccc", Scheme: "ss", Host: "198.51.100.3", Port: 8388}
	d := &nodes.Node{ID: "dddddddddddd", Scheme: "trojan", Host: "198.51.100.4", Port: 443}

	// 第一次运行：已经切过小时、压缩过的文件
	writeSnap(t, dir, "snap-20261105-10.jsonl.gz", true,
		nodeRec("2026-11-05T10:00:00.000Z", "sub1", a, ""),
		nodeRec("2026-11-05T10:00:00.000Z", "sub1", b, "transport_xhttp"),
		nodeRec("2026-11-05T10:00:00.000Z", "sub2", cc, ""),
	)
	// 重启后：A、B 又被记了一遍（B 这次来自另一个订阅），另有一个新节点 D
	writeSnap(t, dir, "snap-20261105-11.jsonl", false,
		nodeRec("2026-11-05T11:00:00.000Z", "sub1", a, ""),
		nodeRec("2026-11-05T11:00:00.000Z", "sub2", b, "transport_xhttp"),
		nodeRec("2026-11-05T11:00:00.000Z", "sub2", d, ""),
	)

	s, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Records["node"]; got != 6 {
		t.Errorf("node 记录数 = %d，应为 6（原始行数，不去重）", got)
	}
	if s.Nodes.Known != 4 {
		t.Errorf("节点数 = %d，应为 4", s.Nodes.Known)
	}
	want := map[string]int{"vless": 1, "vmess": 1, "ss": 1, "trojan": 1}
	if len(s.Nodes.ByScheme) != len(want) {
		t.Errorf("各协议的节点数 = %v，应为 %v", s.Nodes.ByScheme, want)
	}
	for k, v := range want {
		if s.Nodes.ByScheme[k] != v {
			t.Errorf("各协议的节点数 = %v，应为 %v", s.Nodes.ByScheme, want)
			break
		}
	}
	if len(s.Nodes.Unsupported) != 1 || s.Nodes.Unsupported["transport_xhttp"] != 1 {
		t.Errorf("不支持的原因 = %v，应为 map[transport_xhttp:1]", s.Nodes.Unsupported)
	}
}
