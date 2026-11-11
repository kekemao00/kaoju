package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// obsproxyCmd 把测试程序自己当作 obsproxy 重新执行（见 TestMain）。环境是干净的：只有那一个开关变量。
func obsproxyCmd(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = []string{asMainEnv + "=1"}
	return cmd
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := obsproxyCmd(args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("运行失败: %v", err)
		}
		code = ee.ExitCode()
	}
	return so.String(), se.String(), code
}

func TestCLIVersionAndUsage(t *testing.T) {
	out, _, code := runCLI(t, "version")
	wantEq(t, "version 的退出码", code, 0)
	if !strings.HasPrefix(out, "obsproxy "+version) {
		t.Errorf("version 的输出: %q", out)
	}
	_, errOut, code := runCLI(t)
	wantEq(t, "不带参数的退出码", code, 2)
	if !strings.Contains(errOut, "obsproxy serve -profile") {
		t.Errorf("不带参数应当打印用法: %q", errOut)
	}
	_, errOut, code = runCLI(t, "nope")
	wantEq(t, "不认识的子命令的退出码", code, 2)
	if !strings.Contains(errOut, "nope") {
		t.Errorf("应当指出不认识的子命令: %q", errOut)
	}
	_, _, code = runCLI(t, "serve", "-profile", "x.json")
	wantEq(t, "serve 缺参数的退出码", code, 2)
}

// gen-ca：ECDSA P-256，7 天有效，私钥文件只有属主可读。
func TestCLIGenCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, errOut, code := runCLI(t, "gen-ca", "-dir", dir)
	if code != 0 {
		t.Fatalf("gen-ca 退出码 %d: %s", code, errOut)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, rest := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("ca.pem 应当恰好是一张 PEM 证书")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Errorf("CA 的公钥应当是 ECDSA P-256: %T", cert.PublicKey)
	}
	if !cert.IsCA {
		t.Error("证书不是 CA")
	}
	life := cert.NotAfter.Sub(time.Now())
	if life < 7*24*time.Hour-time.Hour || life > 7*24*time.Hour+time.Minute {
		t.Errorf("CA 的有效期应为 7 天，实际还剩 %v", life)
	}
	st, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	wantEq(t, "ca.key 的权限", st.Mode().Perm(), os.FileMode(0o600))
	_, _, code = runCLI(t, "gen-ca")
	wantEq(t, "gen-ca 缺 -dir 的退出码", code, 2)
}

// serveProc 是一个真的 obsproxy serve 进程。
type serveProc struct {
	t          *testing.T
	cmd        *exec.Cmd
	stdout     *bufio.Reader
	stderr     *bytes.Buffer
	evPath     string
	ports      map[string]int
	readyLine  string
	pool       *x509.CertPool
	waitResult chan error
}

func startServe(t *testing.T, profile string, extra ...string) *serveProc {
	t.Helper()
	caDir, pool := testCA(t)
	dir := t.TempDir()
	profPath := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profPath, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &serveProc{t: t, evPath: filepath.Join(dir, "events.jsonl"), stderr: &bytes.Buffer{}, pool: pool, waitResult: make(chan error, 1)}
	args := append([]string{"serve", "-profile", profPath, "-ca-dir", caDir, "-events", p.evPath}, extra...)
	p.cmd = obsproxyCmd(args...)
	p.cmd.Stderr = p.stderr
	out, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if p.cmd.ProcessState == nil {
			_ = p.cmd.Process.Kill()
		}
	})
	p.stdout = bufio.NewReader(out)
	lineCh := make(chan string, 1)
	go func() {
		line, _ := p.stdout.ReadString('\n')
		lineCh <- line
		// 就绪行之后标准输出不应再有内容；读到 EOF 再 Wait，免得管道还没读完就被关。
		rest, _ := p.stdout.ReadString(0)
		if rest != "" {
			t.Errorf("就绪行之后标准输出还有内容: %q", rest)
		}
		p.waitResult <- p.cmd.Wait()
	}()
	select {
	case p.readyLine = <-lineCh:
	case <-time.After(10 * time.Second):
		t.Fatalf("10 秒没有等到就绪行；标准错误: %s", p.stderr)
	}
	if p.readyLine == "" {
		return p // 启动失败：调用方看退出码
	}
	if err := json.Unmarshal([]byte(p.readyLine), &p.ports); err != nil {
		t.Fatalf("就绪行不是 JSON: %q", p.readyLine)
	}
	return p
}

// wait 等进程退出，返回退出码。
func (p *serveProc) wait(within time.Duration) int {
	p.t.Helper()
	select {
	case err := <-p.waitResult:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		p.t.Fatalf("等进程退出失败: %v", err)
	case <-time.After(within):
		_ = p.cmd.Process.Kill()
		p.t.Fatalf("进程 %v 之内没有退出；标准错误: %s", within, p.stderr)
	}
	return -1
}

func dialLocal(t *testing.T, port int) *net.TCPConn {
	t.Helper()
	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("连接 127.0.0.1:%d 失败: %v", port, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// 配置里有不认识的字段：报错退出，不打印就绪行，不留下监听端口。
func TestCLIServeRejectsUnknownField(t *testing.T) {
	for _, prof := range []string{
		`{"auht":{"mode":"basic"}}`,
		`{"auth":{"mod":"basic"}}`,
		`{"conn":{"drop":{"k":"x","time":1}}}`,
		`{"connect":{"fail":{"status":502,"reson":"x"}}}`,
		`[]`,
	} {
		p := startServe(t, prof)
		wantEq(t, "就绪行（应当没有）: "+prof, p.readyLine, "")
		wantEq(t, "退出码: "+prof, p.wait(5*time.Second), 2)
		if !strings.Contains(p.stderr.String(), "配置") {
			t.Errorf("标准错误应当说明是配置的问题: %q", p.stderr.String())
		}
		if _, err := os.Stat(p.evPath); err == nil {
			t.Errorf("配置不对时不应创建事件文件")
		}
	}
}

// serve 的整个生命周期：就绪行、只监听 127.0.0.1、事件边写边落盘、SIGTERM 时关掉所有连接、
// 为还开着的连接补写 conn_end、最后写 end。
func TestCLIServeLifecycleSIGTERM(t *testing.T) {
	p := startServe(t, `{"auth":{"mode":"none"}}`)
	// 就绪行恰好是这三个字段，按这个顺序。
	var keys []string
	dec := json.NewDecoder(strings.NewReader(p.readyLine))
	for dec.More() || len(keys) == 0 {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if s, ok := tok.(string); ok {
			keys = append(keys, s)
		}
	}
	wantEq(t, "就绪行的字段", strings.Join(keys, ","), "proxy_port,origin_http_port,origin_https_port")
	if !strings.HasSuffix(p.readyLine, "}\n") {
		t.Errorf("就绪行应当是一行 JSON: %q", p.readyLine)
	}
	pp, hp, sp := p.ports["proxy_port"], p.ports["origin_http_port"], p.ports["origin_https_port"]
	if pp == 0 || hp == 0 || sp == 0 || pp == hp || hp == sp || pp == sp {
		t.Fatalf("三个端口应当各不相同且非 0: %v", p.ports)
	}

	// 一个完整的请求：事件应当在进程还活着的时候就已经在文件里了（每个事件写完就落盘）。
	c1 := dialLocal(t, pp)
	_, _ = c1.Write([]byte(absGet("LIFE.s1")))
	br1 := bufio.NewReader(c1)
	r := readResp(t, br1, 5*time.Second, c1.SetReadDeadline)
	wantEq(t, "状态码", r.status, 200)
	// http_response 是在响应写出之后才记的，所以稍等一下；但绝不能等到进程退出才出现。
	var live []byte
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var err error
		if live, err = os.ReadFile(p.evPath); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(live, []byte(`"ev":"http_response"`)) {
			break
		}
	}
	if !bytes.Contains(live, []byte(`"ev":"http_response"`)) || !bytes.HasSuffix(live, []byte("\n")) {
		t.Errorf("进程还在运行时，事件文件里应当已经有 http_response，且以换行结尾:\n%s", live)
	}
	// c1 留着不关（空闲的保持连接）。
	// c2：请求头只发了一半。
	c2 := dialLocal(t, pp)
	_, _ = c2.Write([]byte("GET http://a.kaoju.test/echo?k=LIFE.half HTTP/1.1\r\nHost: a.kao"))
	// c3：建好隧道，隧道里一个字节都还没发。
	c3 := dialLocal(t, pp)
	_, _ = c3.Write([]byte("CONNECT a.kaoju.test:443 HTTP/1.1\r\nHost: a.kaoju.test:443\r\n\r\n"))
	br3 := bufio.NewReader(c3)
	wantEq(t, "CONNECT 的状态码", readResp(t, br3, 5*time.Second, c3.SetReadDeadline).status, 200)
	// c4：连上以后一个字节都不发。
	c4 := dialLocal(t, pp)
	// c5：直连明文源站，发过一个请求。
	c5 := dialLocal(t, hp)
	_, _ = c5.Write([]byte(getReq("/echo?k=LIFE.direct", "localhost")))
	wantEq(t, "直连的状态码", readResp(t, bufio.NewReader(c5), 5*time.Second, c5.SetReadDeadline).status, 200)
	// c6：直连 HTTPS 源站，一个字节都不发。
	c6 := dialLocal(t, sp)
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// 每条连接都应当看到对方正常关闭（FIN），不是复位。
	for i, c := range []*net.TCPConn{c1, c2, c3, c4, c5, c6} {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1)
		if n, err := c.Read(buf); n != 0 || err == nil || err.Error() != "EOF" {
			t.Errorf("第 %d 条连接应当读到 EOF，实际 n=%d err=%v", i+1, n, err)
		}
		_ = c.Close()
	}
	wantEq(t, "退出码", p.wait(8*time.Second), 0)
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("收到 SIGTERM 后 %v 才退出", d)
	}

	evs := readEvents(t, p.evPath)
	dumpEvents(t, p.evPath)
	checkInvariants(t, evs)
	st := evs[0]
	wantEq(t, "start.proxy_port", st.num("proxy_port"), pp)
	wantEq(t, "start.origin_http_port", st.num("origin_http_port"), hp)
	wantEq(t, "start.origin_https_port", st.num("origin_https_port"), sp)
	wantEq(t, "start.version", st.str("version"), version)
	wantEq(t, "start.max_seconds", st.num("max_seconds"), 120)
	wantEq(t, "start.profile.auth.mode", st.obj("profile").obj("auth").str("mode"), "none")
	wantEq(t, "start.profile.forward.send_100_continue（默认值也写出来）", st.obj("profile").obj("forward")["send_100_continue"], any(true))
	end := evs[len(evs)-1]
	wantEq(t, "end.reason", end.str("reason"), "signal:SIGTERM")
	wantEq(t, "end.conns", end.num("conns"), 6)
	wantEq(t, "end.tunnels", end.num("tunnels"), 1)
	ends := evs.of("conn_end")
	wantEq(t, "conn_end 的个数", len(ends), 6)
	for _, ce := range ends {
		wantEq(t, "conn_end.by", ce.str("by"), "proxy")
		wantEq(t, "conn_end.close", ce.str("close"), "fin")
		wantEq(t, "conn_end.reason", ce.str("reason"), "shutdown")
	}
	// 发了一半的请求头也留下了记录。
	var half event
	for _, hr := range evs.of("http_request") {
		if strings.HasPrefix(hr.str("error"), "incomplete_head") {
			half = hr
		}
	}
	if half == nil {
		t.Error("发了一半的请求头应当有一条带 error 的 http_request")
	} else {
		wantEq(t, "半个请求头的 http_request.target", half.str("target"), "http://a.kaoju.test/echo?k=LIFE.half")
	}
	wantEq(t, "tunnel_close.reason", one(t, evs.of("tunnel_close"), "tunnel_close").str("reason"), "shutdown")
	if s := p.stderr.String(); s != "" {
		t.Errorf("正常运行时标准错误应当是空的: %q", s)
	}

	// 端口已经放掉。
	if c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", itoa(pp)), time.Second); err == nil {
		c.Close()
		t.Error("退出以后代理端口还能连上")
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// SIGINT 同样有序退出；-max-seconds 到点自己退出。
func TestCLIServeSIGINTAndMaxSeconds(t *testing.T) {
	p := startServe(t, `{}`)
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	wantEq(t, "SIGINT 的退出码", p.wait(5*time.Second), 0)
	evs := readEvents(t, p.evPath)
	checkInvariants(t, evs)
	wantEq(t, "end.reason", evs[len(evs)-1].str("reason"), "signal:SIGINT")

	start := time.Now()
	p2 := startServe(t, `{}`, "-max-seconds", "1")
	c := dialLocal(t, p2.ports["proxy_port"])
	wantEq(t, "到点的退出码", p2.wait(6*time.Second), 0)
	if d := time.Since(start); d < 900*time.Millisecond || d > 5*time.Second {
		t.Errorf("-max-seconds 1 实际运行了 %v", d)
	}
	_ = c.Close()
	evs2 := readEvents(t, p2.evPath)
	checkInvariants(t, evs2)
	wantEq(t, "end.reason", evs2[len(evs2)-1].str("reason"), "max_seconds")
	wantEq(t, "start.max_seconds", evs2[0].num("max_seconds"), 1)
	wantEq(t, "conn_end.reason", one(t, evs2.of("conn_end"), "conn_end").str("reason"), "shutdown")
}

// 只监听 127.0.0.1：本机别的地址上连不到这些端口。
func TestListensOnLoopbackOnly(t *testing.T) {
	e := startEnv(t, `{}`)
	for _, ln := range []*net.TCPListener{e.srv.lnProxy, e.srv.lnHTTP, e.srv.lnHTTPS} {
		a := ln.Addr().(*net.TCPAddr)
		if !a.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("监听地址应为 127.0.0.1，实际 %v", a)
		}
	}
	e.stop()
}
