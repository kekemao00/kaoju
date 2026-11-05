package nonce

import (
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1794000000, 0)
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		n := New(secret, now)
		if len(n) != Len || seen[n] {
			t.Fatalf("nonce 长度不对或重复: %q", n)
		}
		seen[n] = true
		issued, ok := Verify(secret, n)
		if !ok || !issued.Equal(now) {
			t.Fatalf("校验失败: %q %v %v", n, issued, ok)
		}
	}
}

func TestRejects(t *testing.T) {
	secret, other := NewSecret(), NewSecret()
	n := New(secret, time.Now())
	if _, ok := Verify(other, n); ok {
		t.Error("别的密钥签发的 nonce 不应通过")
	}
	flipped := []byte(n)
	if flipped[3] == 'a' {
		flipped[3] = 'b'
	} else {
		flipped[3] = 'a'
	}
	if _, ok := Verify(secret, string(flipped)); ok {
		t.Error("被改过的 nonce 不应通过")
	}
	for _, bad := range []string{"", "short", n + "x", "!!!!!!!!!!!!!!!!!!!!", "healthz"} {
		if _, ok := Verify(secret, bad); ok {
			t.Errorf("%q 不应通过", bad)
		}
	}
	if Canary(secret, "req", n) == Canary(secret, "resp", n) || Canary(secret, "req", n) == Canary(other, "req", n) {
		t.Error("金丝雀应随方向和密钥而不同")
	}
}
