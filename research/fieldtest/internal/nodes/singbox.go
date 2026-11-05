package nodes

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// sing-box 支持的 Shadowsocks 加密方式（docs/configuration/outbound/shadowsocks.md）。
var ssMethods = map[string]bool{
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
	"none": true, "aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
}

var ssAlias = map[string]string{
	"chacha20-poly1305":  "chacha20-ietf-poly1305",
	"xchacha20-poly1305": "xchacha20-ietf-poly1305",
}

var vmessCiphers = map[string]bool{"auto": true, "none": true, "zero": true, "aes-128-gcm": true,
	"chacha20-poly1305": true, "aes-128-ctr": true}

var utlsFP = map[string]bool{"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true,
	"qq": true, "ios": true, "android": true, "random": true, "randomized": true}

// Supported 判断 sing-box 能不能连这个节点。不能时返回原因，能时返回空串。
// 原因是固定的几类，汇总时按它统计“因为什么用不了”。
func Supported(n *Node) string {
	switch n.Scheme {
	case "ss":
		m := n.Method
		if a, ok := ssAlias[m]; ok {
			m = a
		}
		switch {
		case !ssMethods[m]:
			return "ss_method"
		case n.Password == "" && m != "none":
			return "no_credential"
		case n.Plugin != "" && n.Plugin != "obfs-local" && n.Plugin != "simple-obfs" && n.Plugin != "v2ray-plugin":
			return "ss_plugin"
		}
		return ""
	case "vmess", "vless":
		if n.UUID == "" {
			return "no_credential"
		}
	case "trojan":
		if n.Password == "" {
			return "no_credential"
		}
	default:
		return "scheme_" + n.Scheme
	}
	switch n.Net {
	case "tcp", "ws", "grpc", "http", "h2", "httpupgrade":
	default:
		return "transport_" + n.Net
	}
	if n.Net == "tcp" && n.HeaderType != "" && n.HeaderType != "none" && n.HeaderType != "http" {
		return "tcp_header_" + n.HeaderType
	}
	switch n.Sec {
	case "none", "tls", "":
	case "reality":
		if n.PBK == "" {
			return "reality_no_key"
		}
	default:
		return "security_" + n.Sec
	}
	if n.Scheme == "vless" {
		if n.Enc != "" && n.Enc != "none" {
			return "vless_encryption"
		}
		if f := strings.TrimSuffix(n.Flow, "-udp443"); f != "" && f != "xtls-rprx-vision" {
			return "vless_flow"
		}
	}
	return ""
}

// Outbound 把节点映射成 sing-box 的出站配置。调用前先用 Supported 确认可以映射。
//
// insecure 决定 TLS 是否跳过证书校验：false 是严格校验（不管链接怎么写）；
// true 是照链接的要求跳过。后者只用于测量“有多少节点只有跳过校验才连得上”。
func Outbound(n *Node, tag string, insecure bool) map[string]any {
	o := map[string]any{"tag": tag, "server": n.Host, "server_port": n.Port}
	switch n.Scheme {
	case "ss":
		m := n.Method
		if a, ok := ssAlias[m]; ok {
			m = a
		}
		o["type"], o["method"], o["password"] = "shadowsocks", m, n.Password
		if n.Plugin != "" {
			pl := n.Plugin
			if pl == "simple-obfs" {
				pl = "obfs-local"
			}
			o["plugin"], o["plugin_opts"] = pl, n.PluginOpts
		}
		return o
	case "vmess":
		o["type"], o["uuid"] = "vmess", n.UUID
		c := n.Cipher
		if !vmessCiphers[c] {
			c = "auto"
		}
		o["security"] = c
		if n.AlterID > 0 {
			o["alter_id"] = n.AlterID
		}
	case "vless":
		o["type"], o["uuid"] = "vless", n.UUID
		if f := strings.TrimSuffix(n.Flow, "-udp443"); f != "" {
			o["flow"] = f
		}
	case "trojan":
		o["type"], o["password"] = "trojan", n.Password
	}

	if n.Sec == "tls" || n.Sec == "reality" {
		t := map[string]any{"enabled": true}
		sni := n.SNI
		if sni == "" && (n.Net == "ws" || n.Net == "httpupgrade" || n.Net == "http" || n.Net == "h2") {
			sni = firstHost(n.HostHeader)
		}
		if sni == "" {
			if _, err := netip.ParseAddr(n.Host); err != nil {
				sni = n.Host
			}
		}
		if sni != "" {
			t["server_name"] = sni
		}
		if insecure {
			t["insecure"] = true
		}
		if len(n.ALPN) > 0 {
			t["alpn"] = n.ALPN
		}
		fp := n.FP
		if !utlsFP[fp] {
			fp = ""
		}
		if n.Sec == "reality" {
			if fp == "" {
				fp = "chrome" // REALITY 必须配合 uTLS
			}
			t["reality"] = map[string]any{"enabled": true, "public_key": n.PBK, "short_id": n.SID}
		}
		if fp != "" {
			t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		o["tls"] = t
	}

	switch n.Net {
	case "ws":
		path, ed := splitEarlyData(n.Path)
		tr := map[string]any{"type": "ws", "path": path}
		if h := firstHost(n.HostHeader); h != "" {
			tr["headers"] = map[string]any{"Host": h}
		}
		if ed > 0 {
			// 路径里的 ?ed=N 是 Xray 的写法：前 N 字节放进 Sec-WebSocket-Protocol 头
			tr["max_early_data"], tr["early_data_header_name"] = ed, "Sec-WebSocket-Protocol"
		}
		o["transport"] = tr
	case "grpc":
		o["transport"] = map[string]any{"type": "grpc", "service_name": n.ServiceName}
	case "http", "h2":
		tr := map[string]any{"type": "http", "path": n.Path}
		if hs := splitList(n.HostHeader); len(hs) > 0 {
			tr["host"] = hs
		}
		o["transport"] = tr
	case "httpupgrade":
		tr := map[string]any{"type": "httpupgrade", "path": n.Path}
		if h := firstHost(n.HostHeader); h != "" {
			tr["host"] = h
		}
		o["transport"] = tr
	case "tcp":
		if n.HeaderType == "http" {
			// v2ray 的“TCP + HTTP 伪装头”，在 sing-box 里归到 HTTP 传输
			tr := map[string]any{"type": "http", "path": n.Path}
			if hs := splitList(n.HostHeader); len(hs) > 0 {
				tr["host"] = hs
			}
			o["transport"] = tr
		}
	}
	return o
}

func firstHost(s string) string {
	if l := splitList(s); len(l) > 0 {
		return l[0]
	}
	return ""
}

func splitEarlyData(path string) (string, int) {
	i := strings.Index(path, "?")
	if i < 0 {
		return path, 0
	}
	q, err := url.ParseQuery(path[i+1:])
	if err != nil {
		return path, 0
	}
	ed, err := strconv.Atoi(q.Get("ed"))
	if err != nil || ed <= 0 {
		return path, 0
	}
	q.Del("ed")
	if rest := q.Encode(); rest != "" {
		return path[:i] + "?" + rest, ed
	}
	return path[:i], ed
}

// Member 是一批里的一个出站：标签同时用作旁路进程的 SOCKS 用户名。
type Member struct {
	Tag      string
	Outbound map[string]any
}

// Config 生成旁路进程的配置：一个只听回环的入站，每个出站对应一个用户名，按用户名路由。
func Config(port int, members []Member) []byte {
	users := make([]map[string]string, 0, len(members))
	outs := make([]any, 0, len(members)+1)
	rules := make([]any, 0, len(members)+1)
	for _, m := range members {
		users = append(users, map[string]string{"username": m.Tag, "password": "x"})
		outs = append(outs, m.Outbound)
		rules = append(rules, map[string]any{"auth_user": []string{m.Tag}, "outbound": m.Tag})
	}
	// 兜底有两层：没匹配到用户名的连接被规则拒绝；万一规则没生效，默认出站是一个必然连不上的地址。
	// 配置里故意不放直连出站：探测流量一旦从本机直接出去，看上去就像节点可用，那是最糟的一种错。
	outs = append(outs, map[string]any{"type": "socks", "tag": "dead-end", "server": "127.0.0.1", "server_port": 1})
	rules = append(rules, map[string]any{"inbound": []string{"in"}, "action": "reject"})
	cfg := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
		"inbounds": []any{map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
			"listen_port": port, "users": users}},
		"outbounds": outs,
		"route":     map[string]any{"rules": rules, "final": "dead-end", "default_domain_resolver": "local"},
	}
	b, _ := json.MarshalIndent(cfg, "", " ")
	return b
}
