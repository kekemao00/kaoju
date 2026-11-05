package payload

import (
	"bytes"
	"strings"
	"testing"
)

// 载荷必须是确定的：同一个主机名每次生成的内容和哈希都一样，第三方才能自己算出期望值。
func TestDeterministic(t *testing.T) {
	a, b := Build("judge.example"), Build("judge.example")
	for _, k := range Kinds() {
		if a.Get(k).SHA256 != b.Get(k).SHA256 || !bytes.Equal(a.Get(k).Body, b.Get(k).Body) {
			t.Errorf("载荷 %s 两次生成的结果不同", k)
		}
	}
	if Build("other.example").Get(HTML).SHA256 == a.Get(HTML).SHA256 {
		t.Error("HTML 载荷应随主机名变化")
	}
	// 二进制载荷不含主机名，哈希是一个常数。它变了说明生成方式被改了，旧数据就对不上了
	if got := a.Get(Bin).SHA256; got != "a20ee43d7ab3d6cb03e2c9f95bd5b7c75094fb4afabca5afa6fe615a42fdf968" {
		t.Errorf("二进制载荷的哈希变了: %s", got)
	}
}

func TestDecoyShape(t *testing.T) {
	h := string(Build("judge.example").Get(HTML).Body)
	for _, must := range []string{"</head>", "</body>", "ca-pub-0000000000000000", "<form ", "<iframe ", "type=\"password\""} {
		if !strings.Contains(h, must) {
			t.Errorf("诱饵页面里缺少 %q", must)
		}
	}
	if n := strings.Count(h, "https://judge.example/"); n < 6 {
		t.Errorf("诱饵页面里指向 judge 的 https 链接只有 %d 个", n)
	}
	if strings.Contains(h, "{{HOST}}") {
		t.Error("模板里的占位符没有替换干净")
	}
	if len(Build("judge.example").Get(Bin).Body) != 32*1024 {
		t.Error("二进制载荷应为 32 KB")
	}
}
