// Package nodes 处理节点订阅：解析分享链接，并把节点映射成 sing-box 的出站配置。
//
// 节点的去重口径与普查脚本 research/census/nodes_census.py 相同：
// (协议, 主机, 端口, 凭据, 传输参数) 相同的算同一个节点，只有名称不同的不算两个。
package nodes

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Node 是从一条分享链接里解析出来的节点。
type Node struct {
	ID     string `json:"id"` // 去重键的 SHA-256 前 12 位
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`

	UUID     string `json:"-"`
	Password string `json:"-"`
	Method   string `json:"method,omitempty"` // ss 的加密方式
	AlterID  int    `json:"aid,omitempty"`
	Cipher   string `json:"-"` // vmess 的 scy
	Flow     string `json:"flow,omitempty"`
	Enc      string `json:"-"` // vless 的 encryption

	Net         string   `json:"net,omitempty"` // tcp ws grpc http h2 httpupgrade xhttp ...
	Path        string   `json:"-"`
	HostHeader  string   `json:"-"`
	ServiceName string   `json:"-"`
	HeaderType  string   `json:"hdr,omitempty"`
	Sec         string   `json:"sec,omitempty"` // none tls reality
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"-"`
	FP          string   `json:"-"`
	PBK         string   `json:"-"`
	SID         string   `json:"-"`
	Insecure    bool     `json:"insecure,omitempty"` // 链接要求跳过证书校验
	Plugin      string   `json:"plugin,omitempty"`
	PluginOpts  string   `json:"-"`
}

func b64Loose(s string) []byte {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-':
			b.WriteByte('+')
		case c == '_':
			b.WriteByte('/')
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			b.WriteByte(c)
		}
	}
	t := b.String()
	if len(t)%4 == 1 {
		return nil
	}
	out, err := base64.RawStdEncoding.DecodeString(t)
	if err != nil {
		return nil
	}
	return out
}

// LoadText 把订阅内容变成一行一条链接的文本：整个文件是 base64 的先解开。
func LoadText(raw []byte) string {
	s := string(raw)
	head := s
	if len(head) > 4000 {
		head = head[:4000]
	}
	if strings.Contains(head, "://") {
		return s
	}
	if dec := b64Loose(strings.Join(strings.Fields(s), "")); dec != nil {
		return strings.ToValidUTF8(string(dec), "�")
	}
	return s
}

// Links 取出文本里所有看起来像分享链接的行。
func Links(text string) []string {
	var out []string
	for _, ln := range strings.Split(strings.ReplaceAll(text, "\r", "\n"), "\n") {
		if strings.Contains(ln, "://") && !strings.HasPrefix(strings.TrimLeft(ln, " \t"), "#") {
			out = append(out, strings.TrimSpace(ln))
		}
	}
	return out
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None" // 与普查脚本里 Python 的 str(None) 保持一致，去重键才相同
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		if x {
			return "True"
		}
		return "False"
	}
	return fmt.Sprint(v)
}

func get(j map[string]any, k string) string {
	v, ok := j[k]
	if !ok {
		return ""
	}
	return str(v)
}

var truthy = map[string]bool{"1": true, "true": true, "yes": true}

// Parse 解析一条分享链接。解析不了时返回 nil。
func Parse(line string) *Node {
	line = strings.TrimSpace(line)
	i := strings.Index(line, "://")
	if i <= 0 {
		return nil
	}
	scheme, rest := strings.ToLower(line[:i]), line[i+3:]
	for _, c := range scheme {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return nil
		}
	}
	if scheme == "hy2" {
		scheme = "hysteria2"
	}
	var n *Node
	var key []any
	switch scheme {
	case "vmess":
		n, key = parseVmess(rest)
	case "ssr":
		n, key = parseSSR(rest)
	case "ss":
		n, key = parseSS(rest)
	default:
		n, key = parseGeneric(scheme, rest)
	}
	if n == nil || n.Host == "" || n.Port < 1 || n.Port > 65535 {
		return nil
	}
	n.Scheme = scheme
	kb, _ := json.Marshal(key)
	sum := sha256.Sum256(kb)
	n.ID = hex.EncodeToString(sum[:6])
	return n
}

func parseVmess(rest string) (*Node, []any) {
	body := strings.SplitN(strings.SplitN(rest, "#", 2)[0], "?", 2)[0]
	dec := b64Loose(body)
	if dec == nil {
		return nil, nil
	}
	var j map[string]any
	d := json.NewDecoder(strings.NewReader(strings.ToValidUTF8(string(dec), "�")))
	d.UseNumber()
	if err := d.Decode(&j); err != nil || j == nil {
		return nil, nil
	}
	// JSON 后面还跟着别的内容的不算数（与普查脚本一致：Python 的 json.loads 会拒绝）
	if _, err := d.Token(); err != io.EOF {
		return nil, nil
	}
	low := func(k string) string { return strings.ToLower(strings.TrimSpace(get(j, k))) }
	port, err := strconv.Atoi(strings.TrimSpace(get(j, "port")))
	if err != nil {
		return nil, nil
	}
	n := &Node{Host: low("add"), Port: port, UUID: get(j, "id"), Cipher: low("scy"), Net: normNet(low("net")),
		HeaderType: low("type"), HostHeader: strings.TrimSpace(get(j, "host")), Path: strings.TrimSpace(get(j, "path")),
		SNI: strings.TrimSpace(get(j, "sni")), FP: low("fp")}
	n.AlterID, _ = strconv.Atoi(strings.TrimSpace(get(j, "aid")))
	if a := strings.TrimSpace(get(j, "alpn")); a != "" && a != "None" {
		n.ALPN = splitList(a)
	}
	switch tls := low("tls"); tls {
	case "tls", "reality", "xtls":
		n.Sec = tls
	default:
		n.Sec = "none"
	}
	for _, k := range []string{"allowInsecure", "skip-cert-verify", "insecure"} {
		if truthy[strings.ToLower(get(j, k))] {
			n.Insecure = true
		}
	}
	if v, ok := j["verify_cert"].(bool); ok && !v {
		n.Insecure = true
	}
	if n.Net == "grpc" {
		n.ServiceName = n.Path
	}
	for _, f := range []*string{&n.SNI, &n.HostHeader, &n.Path} {
		if *f == "None" {
			*f = ""
		}
	}
	key := []any{"vmess", n.Host, n.Port, get(j, "id"), []string{low("net"), low("host"), low("path"), low("sni"), low("tls")}}
	return n, key
}

func parseSSR(rest string) (*Node, []any) {
	dec := b64Loose(rest)
	if dec == nil {
		return nil, nil
	}
	main := strings.SplitN(string(dec), "/?", 2)[0]
	parts := strings.Split(main, ":")
	if len(parts) < 6 {
		return nil, nil
	}
	port, err := strconv.Atoi(parts[len(parts)-5])
	if err != nil {
		return nil, nil
	}
	host := strings.ToLower(strings.Join(parts[:len(parts)-5], ":"))
	cred := strings.Join(parts[len(parts)-4:], ":")
	return &Node{Host: host, Port: port}, []any{"ssr", host, port, cred, []string{}}
}

func parseSS(rest string) (*Node, []any) {
	body := strings.SplitN(rest, "#", 2)[0]
	var cred, hp string
	if !strings.Contains(body, "@") {
		dec := b64Loose(strings.SplitN(body, "?", 2)[0])
		if dec == nil {
			return nil, nil
		}
		body = strings.ToValidUTF8(string(dec), "�")
		if i := strings.LastIndex(body, "@"); i >= 0 {
			cred, hp = body[:i], body[i+1:]
		} else {
			hp = body
		}
	} else {
		i := strings.LastIndex(body, "@")
		cred, hp = body[:i], body[i+1:]
		un, err := url.PathUnescape(cred)
		if err != nil {
			un = cred
		}
		if dec := b64Loose(un); dec != nil && strings.Contains(string(dec), ":") {
			cred = strings.ToValidUTF8(string(dec), "�")
		}
	}
	query := ""
	if i := strings.Index(hp, "?"); i >= 0 {
		query, hp = hp[i+1:], hp[:i]
	}
	hp = strings.SplitN(hp, "/", 2)[0]
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		return nil, nil
	}
	port, err := strconv.Atoi(hp[i+1:])
	if err != nil {
		return nil, nil
	}
	host := strings.ToLower(strings.Trim(hp[:i], "[]"))
	n := &Node{Host: host, Port: port}
	if m, p, ok := strings.Cut(cred, ":"); ok {
		n.Method, n.Password = strings.ToLower(m), p
	}
	if q, err := url.ParseQuery(query); err == nil {
		if pl := q.Get("plugin"); pl != "" {
			name, opts, _ := strings.Cut(pl, ";")
			n.Plugin, n.PluginOpts = name, opts
		}
	} else if query != "" {
		n.Plugin = "?"
	}
	return n, []any{"ss", host, port, cred, []string{strings.ToLower(query)}}
}

// parseGeneric 处理 scheme://凭据@主机:端口?参数#名称 这种形式（vless、trojan 等）。
func parseGeneric(scheme, rest string) (*Node, []any) {
	rest = strings.SplitN(rest, "#", 2)[0]
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	netloc := strings.SplitN(rest, "/", 2)[0]
	userinfo, hostport := "", netloc
	if i := strings.LastIndex(netloc, "@"); i >= 0 {
		userinfo, hostport = netloc[:i], netloc[i+1:]
	}
	var host, portS string
	if strings.HasPrefix(hostport, "[") {
		j := strings.Index(hostport, "]")
		if j < 0 {
			return nil, nil
		}
		host = hostport[1:j]
		portS = strings.TrimPrefix(hostport[j+1:], ":")
	} else if i := strings.Index(hostport, ":"); i >= 0 {
		// 第一个冒号之后都算端口：没加方括号的 IPv6 地址因此解析不了（与普查脚本一致）
		host, portS = hostport[:i], hostport[i+1:]
	} else {
		return nil, nil
	}
	port, err := strconv.Atoi(portS)
	if err != nil || host == "" {
		return nil, nil
	}
	host = strings.ToLower(host)
	user, pass, _ := strings.Cut(userinfo, ":")
	unq := func(s string) string {
		if u, err := url.PathUnescape(s); err == nil {
			return u
		}
		return s
	}
	user, pass = unq(user), unq(pass)

	// 参数名和值都转小写后用于去重；映射成配置时用原值（路径、公钥等区分大小写）
	q := map[string]string{}
	orig := map[string]string{}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		ku, err1 := url.QueryUnescape(k)
		vu, err2 := url.QueryUnescape(v)
		if err1 != nil {
			ku = k
		}
		if err2 != nil {
			vu = v
		}
		if vu == "" {
			continue
		}
		lk := strings.ToLower(ku)
		if _, dup := q[lk]; !dup {
			q[lk], orig[lk] = strings.ToLower(vu), vu
		}
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	extra := make([][2]string, 0, len(keys))
	for _, k := range keys {
		extra = append(extra, [2]string{k, q[k]})
	}

	n := &Node{Host: host, Port: port, Net: normNet(q["type"]), HeaderType: q["headertype"], Flow: q["flow"],
		Path: orig["path"], HostHeader: orig["host"], ServiceName: orig["servicename"], SNI: orig["sni"],
		FP: q["fp"], PBK: orig["pbk"], SID: orig["sid"], Enc: q["encryption"]}
	if n.SNI == "" {
		n.SNI = orig["peer"]
	}
	if a := orig["alpn"]; a != "" {
		n.ALPN = splitList(a)
	}
	for _, k := range []string{"allowinsecure", "insecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify"} {
		if truthy[q[k]] {
			n.Insecure = true
		}
	}
	sec := q["security"]
	switch scheme {
	case "vless":
		n.UUID = user
		n.Sec = "none"
		if sec == "tls" || sec == "reality" || sec == "xtls" {
			n.Sec = sec
		}
	case "trojan":
		n.Password = user
		n.Sec = "tls"
		if sec == "none" || sec == "reality" || sec == "xtls" {
			n.Sec = sec
		}
	default:
		n.Password = user
		n.Sec = sec
	}
	return n, []any{scheme, host, port, user + ":" + pass, extra}
}

func normNet(v string) string {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "", "raw":
		return "tcp"
	case "splithttp":
		return "xhttp"
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return "other"
		}
	}
	return v
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
