package nodes

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testUUID = "bf000d23-0752-40b4-affe-68f7707a9661"
	testPBK  = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
)

func vmessLink(json string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(json))
}

var sampleLinks = []struct {
	name, link  string
	scheme, net string
	sec         string
	port        int
	support     string
	insecure    bool
}{
	{"vless ws tls", "vless://" + testUUID + "@cdn.example.com:443?type=ws&security=tls&sni=a.example.com&host=a.example.com&path=%2Fws%3Fed%3D2048&fp=chrome&alpn=h2%2Chttp%2F1.1#name%20one",
		"vless", "ws", "tls", 443, "", false},
	{"vless reality vision", "vless://" + testUUID + "@203.0.113.5:8443?type=tcp&security=reality&sni=www.example.org&fp=chrome&pbk=" + testPBK + "&sid=0123abcd&flow=xtls-rprx-vision#r",
		"vless", "tcp", "reality", 8443, "", false},
	{"vless raw reality", "vless://" + testUUID + "@203.0.113.6:443?type=raw&security=reality&sni=www.example.org&pbk=" + testPBK + "&flow=xtls-rprx-vision-udp443",
		"vless", "tcp", "reality", 443, "", false},
	{"vless grpc reality", "vless://" + testUUID + "@203.0.113.7:443?type=grpc&security=reality&serviceName=grpc&sni=www.example.org&pbk=" + testPBK + "&sid=ab",
		"vless", "grpc", "reality", 443, "", false},
	{"vless xhttp", "vless://" + testUUID + "@example.net:443?type=xhttp&security=tls&path=%2Fx",
		"vless", "xhttp", "tls", 443, "transport_xhttp", false},
	{"vless httpupgrade", "vless://" + testUUID + "@example.net:80?type=httpupgrade&host=h.example.net&path=%2Fup&security=none",
		"vless", "httpupgrade", "none", 80, "", false},
	{"vless tcp http header", "vless://" + testUUID + "@198.51.100.9:8080?type=tcp&headerType=http&host=speedtest.net&security=none",
		"vless", "tcp", "none", 8080, "", false},
	{"vless insecure", "vless://" + testUUID + "@example.net:2053?type=ws&security=tls&allowInsecure=1&sni=x.example.net&path=%2F",
		"vless", "ws", "tls", 2053, "", true},
	{"vless reality without key", "vless://" + testUUID + "@example.net:443?security=reality&sni=x.example.net",
		"vless", "tcp", "reality", 443, "reality_no_key", false},
	{"vless new encryption", "vless://" + testUUID + "@example.net:443?security=none&encryption=mlkem768x25519plus.native.0rtt.abc",
		"vless", "tcp", "none", 443, "vless_encryption", false},
	{"vmess ws tls", vmessLink(`{"v":"2","ps":"n","add":"V.Example.com","port":"443","id":"` + testUUID + `","aid":"0","scy":"auto","net":"ws","type":"none","host":"v.example.com","path":"/vm","tls":"tls","sni":"v.example.com"}`),
		"vmess", "ws", "tls", 443, "", false},
	{"vmess tcp numeric port", vmessLink(`{"v":"2","add":"198.51.100.1","port":8080,"id":"` + testUUID + `","aid":0,"net":"tcp","type":"none","tls":""}`),
		"vmess", "tcp", "none", 8080, "", false},
	{"vmess tcp http header", vmessLink(`{"v":"2","add":"198.51.100.2","port":"80","id":"` + testUUID + `","aid":"0","net":"tcp","type":"http","host":"a.example.com,b.example.com","path":"/","tls":"none"}`),
		"vmess", "tcp", "none", 80, "", false},
	{"vmess h2", vmessLink(`{"v":"2","add":"h2.example.com","port":"443","id":"` + testUUID + `","net":"h2","host":"h2.example.com","path":"/h2","tls":"tls"}`),
		"vmess", "h2", "tls", 443, "", false},
	{"vmess kcp", vmessLink(`{"v":"2","add":"198.51.100.3","port":"443","id":"` + testUUID + `","net":"kcp","type":"wechat-video"}`),
		"vmess", "kcp", "none", 443, "transport_kcp", false},
	{"trojan tcp", "trojan://pass%40word@t.example.com:443?sni=t.example.com#x", "trojan", "tcp", "tls", 443, "", false},
	{"trojan ws insecure", "trojan://secret@198.51.100.4:8443?type=ws&host=w.example.com&path=%2Ftr&allowInsecure=1&sni=w.example.com",
		"trojan", "ws", "tls", 8443, "", true},
	{"ss sip002", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa:ss")) + "@198.51.100.5:8388#tag",
		"ss", "", "", 8388, "", false},
	{"ss legacy", "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:secret@198.51.100.6:443")) + "#tag",
		"ss", "", "", 443, "", false},
	{"ss alias", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-poly1305:secret")) + "@198.51.100.7:443",
		"ss", "", "", 443, "", false},
	{"ss legacy cipher", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:secret")) + "@198.51.100.8:443",
		"ss", "", "", 443, "", false},
	{"ss unknown method", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("bf-cfb:secret")) + "@198.51.100.8:444",
		"ss", "", "", 444, "ss_method", false},
	{"ss 2022", "ss://2022-blake3-aes-128-gcm:" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")) + "@198.51.100.10:443",
		"ss", "", "", 443, "", false},
	{"hysteria2", "hy2://pw@h.example.com:443?sni=h.example.com&insecure=1", "hysteria2", "tcp", "", 443, "scheme_hysteria2", true},
}

func TestParseAndSupport(t *testing.T) {
	for _, c := range sampleLinks {
		n := Parse(c.link)
		if n == nil {
			t.Errorf("%s: 解析失败", c.name)
			continue
		}
		if n.Scheme != c.scheme || n.Port != c.port || n.Insecure != c.insecure {
			t.Errorf("%s: scheme=%s port=%d insecure=%v", c.name, n.Scheme, n.Port, n.Insecure)
		}
		if c.net != "" && n.Net != c.net {
			t.Errorf("%s: net=%s 期望 %s", c.name, n.Net, c.net)
		}
		if c.sec != "" && n.Sec != c.sec {
			t.Errorf("%s: sec=%s 期望 %s", c.name, n.Sec, c.sec)
		}
		if got := Supported(n); got != c.support {
			t.Errorf("%s: Supported=%q 期望 %q", c.name, got, c.support)
		}
	}
}

func TestIdentity(t *testing.T) {
	a := Parse("vless://" + testUUID + "@example.net:443?type=ws&security=tls&path=%2Fa#one")
	b := Parse("vless://" + testUUID + "@EXAMPLE.net:443?security=tls&type=ws&path=%2Fa#two")
	c := Parse("vless://" + testUUID + "@example.net:443?type=ws&security=tls&path=%2Fb#one")
	if a == nil || b == nil || c == nil {
		t.Fatal("解析失败")
	}
	if a.ID != b.ID {
		t.Error("只有名称、参数顺序、主机名大小写不同的链接应是同一个节点")
	}
	if a.ID == c.ID {
		t.Error("路径不同的链接应是不同节点")
	}
}

func TestMapping(t *testing.T) {
	n := Parse(sampleLinks[0].link)
	o := Outbound(n, "t", false)
	tr := o["transport"].(map[string]any)
	if tr["path"] != "/ws" || tr["max_early_data"] != 2048 || tr["early_data_header_name"] != "Sec-WebSocket-Protocol" {
		t.Errorf("ws 的 early data 没映射对: %v", tr)
	}
	tl := o["tls"].(map[string]any)
	if tl["server_name"] != "a.example.com" || tl["insecure"] != nil {
		t.Errorf("tls 映射不对: %v", tl)
	}
	n = Parse(sampleLinks[7].link)
	if Outbound(n, "t", false)["tls"].(map[string]any)["insecure"] != nil {
		t.Error("严格模式下不应带 insecure")
	}
	if Outbound(n, "t", true)["tls"].(map[string]any)["insecure"] != true {
		t.Error("照链接要求时应带 insecure")
	}
	n = Parse(sampleLinks[2].link)
	if Outbound(n, "t", false)["flow"] != "xtls-rprx-vision" {
		t.Error("flow 的 -udp443 后缀应去掉")
	}
}

// TestConfigAccepted 用真正的 sing-box 检查生成的配置。设置 FIELDTEST_SINGBOX 指向可执行文件才会运行。
func TestConfigAccepted(t *testing.T) {
	bin := os.Getenv("FIELDTEST_SINGBOX")
	if bin == "" {
		t.Skip("未设置 FIELDTEST_SINGBOX")
	}
	var members []Member
	for i, c := range sampleLinks {
		n := Parse(c.link)
		if n == nil || Supported(n) != "" {
			continue
		}
		members = append(members, Member{Tag: "n" + n.ID, Outbound: Outbound(n, "n"+n.ID, false)})
		if n.Insecure {
			members = append(members, Member{Tag: "n" + n.ID + "_i", Outbound: Outbound(n, "n"+n.ID+"_i", true)})
		}
		_ = i
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, Config(17999, members), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check 失败: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		t.Logf("sing-box check 输出:\n%s", s)
	}
	t.Logf("%d 个出站通过检查", len(members))
}

// FuzzParse 把任意字符串当作分享链接。订阅内容来自不可信的来源，解析和映射都不能崩溃。
func FuzzParse(f *testing.F) {
	for _, c := range sampleLinks {
		f.Add(c.link)
	}
	f.Add("vmess://e30=")
	f.Add("ss://@:0")
	f.Add("vless://@[::1]:443?type=ws&path=%zz&ed=x")
	f.Fuzz(func(t *testing.T, s string) {
		for _, link := range Links(LoadText([]byte(s))) {
			n := Parse(link)
			if n == nil {
				continue
			}
			if n.Port < 1 || n.Port > 65535 || n.Host == "" || len(n.ID) != 12 {
				t.Fatalf("解析出了不合法的节点: %+v", n)
			}
			if Supported(n) == "" {
				Config(1080, []Member{{Tag: "n" + n.ID, Outbound: Outbound(n, "n"+n.ID, true)}})
			}
		}
	})
}
