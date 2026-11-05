package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"fieldtest/internal/cfg"
)

// 自签证书：同一个主机名重复启动时复用同一张；主机名变了就重新生成。
func TestCertReuseAndRegenerate(t *testing.T) {
	c := cfg.Default()
	c.DataDir = t.TempDir()
	c.Judge.Host, c.Judge.PublicIP = "judge.example", "192.0.2.10"
	fp := func() string {
		cert, err := EnsureCert(c)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(cert.Certificate[0])
		return hex.EncodeToString(sum[:])
	}
	a, b := fp(), fp()
	if a != b {
		t.Error("主机名没变，证书却换了")
	}
	tr, err := LoadTrust(c)
	if err != nil || !tr.Self || tr.Roots == nil || len(tr.SPKIPin) != 64 {
		t.Errorf("LoadTrust: %+v %v", tr, err)
	}
	c.Judge.Host = "other.example"
	if fp() == a {
		t.Error("主机名变了，证书应当重新生成")
	}
	c.Judge.Host = "192.0.2.10"
	ip := fp()
	if ip != fp() {
		t.Error("主机名是 IP 时也应复用证书")
	}
}
