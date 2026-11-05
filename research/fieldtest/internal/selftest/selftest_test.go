package selftest

import (
	"bytes"
	"os"
	"testing"
)

// TestSelfTest 跑一遍完整的仪器自检：每个夹具的判定都必须与预期一致。
// 设置 FIELDTEST_SINGBOX 指向 sing-box 可执行文件时，同时自检节点探测。
func TestSelfTest(t *testing.T) {
	var buf bytes.Buffer
	pass, err := Run(&buf, true, os.Getenv("FIELDTEST_SINGBOX"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + buf.String())
	if !pass {
		t.Fatal("自检有不符项")
	}
}
