package selftest

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/evil"
	"fieldtest/internal/nodes"
	"fieldtest/internal/probe"
	"fieldtest/internal/rec"
)

// 节点探测的自检：在本机用官方 sing-box 起一个服务端（ss、vmess、vless、trojan、REALITY 各一个入站），
// 再让探测器按正式流程经另一个 sing-box 进程去连它们。

type nodeCase struct {
	name, link string
	id         string
	strict     string // 严格校验这一组的期望：ok、!ok，或空（不应有这次尝试）
	linked     string // 照链接要求跳过校验这一组的期望
	why        string // 期望的“不支持”原因
	pre        string // 期望的预检结果，空表示 ok
	extras     bool   // 期望做了附加测试（第二观察者和明文对照）
}

const nodeUUID = "bf000d23-0752-40b4-affe-68f7707a9661"

// NodeEgress 是自检用的 sing-box 服务端连上游时使用的源地址。
const NodeEgress = "127.0.3.1"

func freePort() int {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startNodeServer 启动服务端，返回各个测试节点的分享链接。
func startNodeServer(bin, dir string, judgeTLSPort int) ([]nodeCase, func(), error) {
	out, err := exec.Command(bin, "generate", "reality-keypair").Output()
	if err != nil {
		return nil, nil, fmt.Errorf("生成 REALITY 密钥: %w", err)
	}
	var priv, pub string
	for _, ln := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(ln, "PrivateKey: "); ok {
			priv = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(ln, "PublicKey: "); ok {
			pub = strings.TrimSpace(v)
		}
	}
	if priv == "" || pub == "" {
		return nil, nil, fmt.Errorf("看不懂 sing-box generate 的输出: %q", out)
	}
	cert, err := evil.SelfSigned("trojan.test")
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, nil, err
	}
	certPath, keyPath := filepath.Join(dir, "trojan-cert.pem"), filepath.Join(dir, "trojan-key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)

	pSS, pVM, pVL, pTR, pRE, pClosed := freePort(), freePort(), freePort(), freePort(), freePort(), freePort()
	in := func(typ, tag string, port int, extra map[string]any) map[string]any {
		m := map[string]any{"type": typ, "tag": tag, "listen": "127.0.0.1", "listen_port": port}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	server := map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{"servers": []any{map[string]any{"type": "hosts", "tag": "hosts",
			"predefined": map[string]any{"judge.test": "127.0.0.1", "obs1.test": "127.0.0.1", "obs2.test": "127.0.0.1"}}}},
		"inbounds": []any{
			in("shadowsocks", "ss", pSS, map[string]any{"method": "aes-256-gcm", "password": "sspass"}),
			in("vmess", "vmess", pVM, map[string]any{"users": []any{map[string]any{"uuid": nodeUUID, "alterId": 0}},
				"transport": map[string]any{"type": "ws", "path": "/vm"}}),
			in("vless", "vless", pVL, map[string]any{"users": []any{map[string]any{"uuid": nodeUUID}}}),
			in("trojan", "trojan", pTR, map[string]any{"users": []any{map[string]any{"password": "trpass"}},
				"tls": map[string]any{"enabled": true, "server_name": "trojan.test", "certificate_path": certPath, "key_path": keyPath}}),
			in("vless", "reality", pRE, map[string]any{"users": []any{map[string]any{"uuid": nodeUUID, "flow": "xtls-rprx-vision"}},
				"tls": map[string]any{"enabled": true, "server_name": "judge.test", "reality": map[string]any{"enabled": true,
					"handshake":   map[string]any{"server": "127.0.0.1", "server_port": judgeTLSPort},
					"private_key": priv, "short_id": []string{"0123abcd"}}}}),
		},
		// 服务端从 127.0.3.1 出去：judge 看到的地址若是它，说明流量确实经过了节点；
		// 若是 127.0.0.1，就是探测流量从本机直接出去了
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct", "inet4_bind_address": NodeEgress}},
		"route":     map[string]any{"default_domain_resolver": "hosts"},
	}
	b, _ := json.MarshalIndent(server, "", " ")
	cfgPath := filepath.Join(dir, "node-server.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		return nil, nil, err
	}
	logf, _ := os.Create(filepath.Join(dir, "node-server.log"))
	cmd := exec.Command(bin, "run", "-c", cfgPath, "-D", dir)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	stop := func() { cmd.Process.Kill(); cmd.Wait(); logf.Close() }
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(pRE)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			stop()
			tail, _ := os.ReadFile(filepath.Join(dir, "node-server.log"))
			return nil, nil, fmt.Errorf("sing-box 服务端没有起来: %s", strings.TrimSpace(string(tail)))
		}
		time.Sleep(50 * time.Millisecond)
	}

	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "t", "add": "127.0.0.1", "port": strconv.Itoa(pVM), "id": nodeUUID,
		"aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "", "path": "/vm", "tls": ""})
	hp := func(p int) string { return "127.0.0.1:" + strconv.Itoa(p) }
	cases := []nodeCase{
		{name: "ss", strict: "ok", extras: true,
			link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:sspass")) + "@" + hp(pSS) + "#ss"},
		{name: "vmess-ws", strict: "ok", extras: true, link: "vmess://" + base64.StdEncoding.EncodeToString(vm)},
		{name: "vless-tcp", strict: "ok", extras: true, link: "vless://" + nodeUUID + "@" + hp(pVL) + "?type=tcp&security=none#v"},
		{name: "trojan-insecure", strict: "!ok", linked: "ok", extras: true,
			link: "trojan://trpass@" + hp(pTR) + "?sni=trojan.test&allowInsecure=1#t"},
		{name: "trojan-strict-only", strict: "!ok", link: "trojan://trpass@" + hp(pTR) + "?sni=trojan.test&type=tcp#t2"},
		{name: "vless-reality-vision", strict: "ok", extras: true,
			link: "vless://" + nodeUUID + "@" + hp(pRE) + "?type=tcp&security=reality&sni=judge.test&fp=chrome&pbk=" + pub +
				"&sid=0123abcd&flow=xtls-rprx-vision#r"},
		{name: "vless-wrong-uuid", strict: "!ok", link: "vless://11111111-2222-4333-8444-555555555555@" + hp(pVL) + "?security=none"},
		{name: "trojan-wrong-password", strict: "!ok", linked: "!ok",
			link: "trojan://nope@" + hp(pTR) + "?sni=trojan.test&allowInsecure=1&path=x"},
		{name: "vless-closed-port", pre: "tcp_refused", link: "vless://" + nodeUUID + "@" + hp(pClosed) + "?security=none"},
		{name: "vless-xhttp", why: "transport_xhttp", link: "vless://" + nodeUUID + "@" + hp(pVL) + "?type=xhttp&security=none&path=%2Fx"},
	}
	for i := range cases {
		n := nodes.Parse(cases[i].link)
		if n == nil {
			stop()
			return nil, nil, fmt.Errorf("自检链接 %s 解析失败", cases[i].name)
		}
		cases[i].id = n.ID
	}
	return cases, stop, nil
}

// runNodes 让探测器对测试节点做一轮探测。
func runNodes(ctx context.Context, env *probe.Env, c *cfg.Config, snap *rec.Writer, dir, bin string) ([]nodeCase, error) {
	cases, stop, err := startNodeServer(bin, dir, c.Judge.HTTPSPort)
	if err != nil {
		return nil, err
	}
	defer stop()
	c.Nodes.SingBox, c.Nodes.ListenPort, c.Nodes.Concurrency = bin, freePort(), 8
	nr := probe.NewNodeRun(env, nil, snap, filepath.Join(dir, "sidecar"))
	for _, nc := range cases {
		nr.Static = append(nr.Static, nc.link)
	}
	if err := nr.Init(); err != nil {
		return nil, err
	}
	if rr := nr.Round(ctx, bin); rr.Err != "" {
		tail, _ := os.ReadFile(filepath.Join(dir, "sidecar", "sing-box.log"))
		return nil, fmt.Errorf("节点探测这一轮出错: %s\n%s", rr.Err, tail)
	}
	return cases, nil
}
