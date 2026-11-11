package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// PROTOCOL.md 里写明的默认配置，原样抄在这里。空配置解析出来必须与它逐字段相同。
const protocolDefaults = `{
  "auth":    {"mode": "none", "accept": [], "accept_any_user": false,
              "challenge": ["Basic realm=\"kaoju\""], "on407": "keepalive", "reject_status": 407},
  "connect": {"ok_headers": [], "fail": null, "drop": null},
  "forward": {"fail": null, "add_response_headers": [], "send_100_continue": true},
  "conn":    {"idle_close_ms": 0, "drop": null},
  "tunnel":  {"idle_close_ms": 0},
  "origin":  {"h2": true, "drop": null},
  "socks":   {"auth": "none", "auth_fail_status": 1, "rep": 0}
}`

func asGeneric(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProfileDefaultsMatchProtocol(t *testing.T) {
	var want any
	if err := json.Unmarshal([]byte(protocolDefaults), &want); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{`{}`, protocolDefaults, `{"auth":{},"connect":{},"forward":{},"conn":{},"tunnel":{},"origin":{},"socks":{}}`} {
		p, err := ParseProfile([]byte(in))
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", in, err)
		}
		if got := asGeneric(t, p); !reflect.DeepEqual(got, want) {
			t.Errorf("默认值与 PROTOCOL.md 不一致\n  输入: %s\n  实际: %v\n  应为: %v", in, got, want)
		}
	}
}

// PROTOCOL.md 的文本里那段默认配置必须与测试里抄的这份相同，防止两边各改各的。
func TestProfileDefaultsCopiedFromProtocolFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "PROTOCOL.md"))
	if err != nil {
		t.Skipf("读不到 PROTOCOL.md: %v", err)
	}
	if !strings.Contains(string(data), protocolDefaults) {
		t.Error("PROTOCOL.md 里的默认配置与 profile_test.go 里抄的不一样")
	}
}

func TestProfilePartialOverride(t *testing.T) {
	p, err := ParseProfile([]byte(`{"auth":{"mode":"basic","accept":[["u","p"]]},"origin":{"h2":false},
		"conn":{"drop":{"k":"F03.s2"}},"connect":{"fail":{"status":503}},"forward":{"send_100_continue":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	wantEq(t, "auth.mode", p.Auth.Mode, "basic")
	wantEq(t, "auth.on407（没写，取默认）", p.Auth.On407, "keepalive")
	wantEq(t, "auth.reject_status（没写，取默认）", p.Auth.RejectStatus, 407)
	wantEq(t, "auth.challenge（没写，取默认）", strings.Join(p.Auth.Challenge, "|"), `Basic realm="kaoju"`)
	wantEq(t, "origin.h2", p.Origin.H2, false)
	wantEq(t, "forward.send_100_continue", p.Forward.Send100Continue, false)
	wantEq(t, "socks.auth_fail_status（没写，取默认）", p.Socks.AuthFailStatus, 1)
	if d := p.Conn.Drop; d == nil || d.K != "F03.s2" || d.Times != 1 || d.How != "fin" || d.OnlyIfReused {
		t.Errorf("conn.drop 的默认值不对: %+v", d)
	}
	if f := p.Connect.Fail; f == nil || f.Status != 503 || f.Reason != "Service Unavailable" || f.Close || len(f.Headers) != 0 || len(f.Hosts) != 0 || f.Body != "" {
		t.Errorf("connect.fail 的默认值不对: %+v", f)
	}
}

func TestProfileRejectsUnknownFields(t *testing.T) {
	bad := map[string]string{
		"顶层":                   `{"auht":{"mode":"basic"}}`,
		"auth 里":               `{"auth":{"mode":"basic","acept":[]}}`,
		"connect 里":            `{"connect":{"okheaders":[]}}`,
		"connect.fail 里":       `{"connect":{"fail":{"status":502,"reson":"x"}}}`,
		"connect.drop 里":       `{"connect":{"drop":{"times":1,"hwo":"fin"}}}`,
		"forward 里":            `{"forward":{"send_100":true}}`,
		"forward.fail 里":       `{"forward":{"fail":{"status":403,"host":["a"]}}}`,
		"conn 里":               `{"conn":{"idle_close":5}}`,
		"conn.drop 里":          `{"conn":{"drop":{"k":"x","only_reused":true}}}`,
		"tunnel 里":             `{"tunnel":{"idle":5}}`,
		"origin 里":             `{"origin":{"http2":true}}`,
		"origin.drop 里":        `{"origin":{"drop":{"k":"x","time":1}}}`,
		"socks 里":              `{"socks":{"auth":"none","reply":1}}`,
		"JSON 之后有多余内容":         `{} {}`,
		"不是对象":                 `[]`,
		"null":                 `null`,
		"空文件":                  ``,
		"头不是两项":                `{"connect":{"ok_headers":[["A","b","c"]]}}`,
		"accept 不是两项":          `{"auth":{"accept":[["only-user"]]}}`,
		"类型不对":                 `{"conn":{"idle_close_ms":"1500"}}`,
		"connect.drop 带了 k":    `{"connect":{"drop":{"k":"x"}}}`,
		"connect.drop 带了 only": `{"connect":{"drop":{"only_if_reused":true}}}`,
	}
	for name, in := range bad {
		if p, err := ParseProfile([]byte(in)); err == nil {
			t.Errorf("%s：应当报错，却解析成了 %+v", name, p)
		}
	}
}

func TestProfileRejectsBadValues(t *testing.T) {
	bad := map[string]string{
		"auth.mode":                 `{"auth":{"mode":"digest"}}`,
		"auth.on407":                `{"auth":{"on407":"reset"}}`,
		"auth.reject_status":        `{"auth":{"reject_status":401}}`,
		"accept_any_user 没有 accept": `{"auth":{"accept_any_user":true}}`,
		"challenge 里有换行":            `{"auth":{"challenge":["Basic\r\nX: y"]}}`,
		"头名字不合法":                    `{"connect":{"ok_headers":[["Bad Name","v"]]}}`,
		"头值里有换行":                    `{"forward":{"add_response_headers":[["X","a\r\nB: c"]]}}`,
		"fail 没有 status":            `{"connect":{"fail":{"reason":"x"}}}`,
		"fail.status 越界":            `{"forward":{"fail":{"status":99}}}`,
		"fail.reason 里有换行":          `{"forward":{"fail":{"status":403,"reason":"a\nb"}}}`,
		"drop.how":                  `{"conn":{"drop":{"k":"x","how":"timeout"}}}`,
		"drop.times 为负":             `{"conn":{"drop":{"k":"x","times":-1}}}`,
		"conn.drop 没有 k":            `{"conn":{"drop":{"times":1}}}`,
		"origin.drop 没有 k":          `{"origin":{"drop":{"how":"rst"}}}`,
		"idle 为负":                   `{"tunnel":{"idle_close_ms":-5}}`,
		"socks.auth":                `{"socks":{"auth":"gssapi"}}`,
		"socks.auth_fail_status=0":  `{"socks":{"auth_fail_status":0}}`,
		"socks.rep 越界":              `{"socks":{"rep":256}}`,
	}
	for name, in := range bad {
		if p, err := ParseProfile([]byte(in)); err == nil {
			t.Errorf("%s：应当报错，却解析成了 %+v", name, p)
		}
	}
}

// cases.json 里每个用例的 profile 都必须能被解析（字段名、取值都认得）。
func TestProfileAcceptsAllCases(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "cases.json"))
	if err != nil {
		t.Skipf("读不到 cases.json: %v", err)
	}
	var doc struct {
		Cases []struct {
			ID      string          `json:"id"`
			Profile json.RawMessage `json:"profile"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("cases.json 里没有用例")
	}
	for _, c := range doc.Cases {
		if _, err := ParseProfile(c.Profile); err != nil {
			t.Errorf("用例 %s 的 profile 解析失败: %v", c.ID, err)
		}
	}
	t.Logf("解析了 %d 个用例的 profile", len(doc.Cases))
}

func TestCredsOK(t *testing.T) {
	p, err := ParseProfile([]byte(`{"auth":{"accept":[["kaoju-user","kaoju-pass-1"],["u2",""]]}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		u, pw string
		want  bool
	}{
		{"kaoju-user", "kaoju-pass-1", true},
		{"u2", "", true},
		{"kaoju-user", "kaoju-pass-2", false},
		{"Kaoju-User", "kaoju-pass-1", false}, // 按字节比较，大小写敏感
		{"kaoju-user", "", false},
		{"", "", false},
	} {
		if got := p.credsOK([]byte(c.u), []byte(c.pw)); got != c.want {
			t.Errorf("credsOK(%q, %q) = %v，应为 %v", c.u, c.pw, got, c.want)
		}
	}
	any, err := ParseProfile([]byte(`{"auth":{"accept":[["whoever","secret"],["x","other"]],"accept_any_user":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !any.credsOK([]byte{0xff, 0xfe}, []byte("secret")) {
		t.Error("accept_any_user：任何用户名加 accept[0][1] 应当通过")
	}
	if any.credsOK([]byte("x"), []byte("other")) {
		t.Error("accept_any_user：只认 accept[0][1]，别的密码不应通过")
	}
}
