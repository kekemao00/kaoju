//go:build unix

// Package preflight 在正式测量前检查这台机器是否具备条件，并把结果写成一份可以直接发回来的清单。
package preflight

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/judge"
	"fieldtest/internal/lists"
	"fieldtest/internal/nodes"
	"fieldtest/internal/probe"
	"fieldtest/internal/selftest"
	"fieldtest/internal/sysx"
	"fieldtest/internal/wire"
)

type report struct {
	w           io.Writer
	fail, warns int
}

func (r *report) pass(format string, args ...any) {
	fmt.Fprintf(r.w, "  通过  "+format+"\n", args...)
}
func (r *report) warn(format string, args ...any) {
	r.warns++
	fmt.Fprintf(r.w, "  注意  "+format+"\n", args...)
}
func (r *report) bad(format string, args ...any) {
	r.fail++
	fmt.Fprintf(r.w, "  失败  "+format+"\n", args...)
}

// Run 执行预检。返回是否没有“失败”项。
func Run(c *cfg.Config, out io.Writer, withSelftest bool) bool {
	r := &report{w: out}
	fmt.Fprintf(out, "预检  %s\n", time.Now().UTC().Format(time.RFC3339))
	j := c.Judge

	fmt.Fprintln(out, "配置")
	r.pass("judge 主机名 %s，公网地址 %s，HTTP 端口 %d，HTTPS 端口 %d", j.Host, j.PublicIP, j.HTTPPort, j.HTTPSPort)
	if j.HTTPPort != 80 || j.HTTPSPort != 443 {
		r.warn("judge 没有用 80 和 443。不少 HTTP 代理只允许 CONNECT 到 443，用别的端口会低估它们的可用率")
	}
	if j.Contact == "" {
		r.warn("没有填写 judge.contact。judge 首页会告诉访客如何退出测量，需要一个联系方式")
	}

	fmt.Fprintln(out, "本机")
	if err := os.MkdirAll(c.DataDir, 0o755); err != nil {
		r.bad("数据目录 %s 建不出来: %v", c.DataDir, err)
	} else if f, err := os.CreateTemp(c.DataDir, "preflight-*"); err != nil {
		r.bad("数据目录 %s 不可写: %v", c.DataDir, err)
	} else {
		f.Close()
		os.Remove(f.Name())
		free := sysx.DiskFreeGB(c.DataDir)
		switch {
		case free < 0:
			r.pass("数据目录 %s 可写", c.DataDir)
		case free < 5:
			r.bad("数据目录所在磁盘只剩 %.1f GB，72 小时的记录需要 5 GB 左右", free)
		default:
			r.pass("数据目录 %s 可写，磁盘剩余 %.0f GB", c.DataDir, free)
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var kb int64
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fmt.Sscan(strings.TrimPrefix(line, "MemTotal:"), &kb)
			}
		}
		switch {
		case kb > 0 && kb < 900*1024:
			r.warn("内存只有 %d MB。解析聚合器的大文件时探测器会短暂用到三四百 MB，偏紧；可以在配置里把 probe.aggregator_sample 设为 0 关掉聚合器抽样", kb/1024)
		case kb > 0:
			r.pass("内存 %d MB", kb/1024)
		}
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		if lim.Cur < 4096 {
			r.warn("可打开的文件数上限是 %d，偏低；用安装脚本装的服务会把它提到 65536", lim.Cur)
		} else {
			r.pass("可打开的文件数上限 %d", lim.Cur)
		}
	}

	fmt.Fprintln(out, "出站与时钟")
	for i := range c.Observers {
		o := &c.Observers[i]
		ip, skew, err := directObserver(o)
		switch {
		case err != nil:
			r.bad("直连第二观察者 %s 失败: %v", o.Host, err)
		case ip.String() != j.PublicIP:
			r.warn("%s 看到本机的出口地址是 %s，与配置的 public_ip %s 不同。如果本机出站和入站用的不是同一个地址，这是正常的",
				o.Host, ip, j.PublicIP)
		default:
			r.pass("%s 看到的出口地址与 public_ip 一致", o.Host)
		}
		if err == nil && skew != 0 {
			if skew > 5*time.Second || skew < -5*time.Second {
				r.warn("本机时钟与 %s 相差 %s，建议开启时间同步", o.Host, skew.Round(time.Second))
			} else {
				r.pass("本机时钟与 %s 相差不到 5 秒", o.Host)
			}
		}
	}
	if _, err := netip.ParseAddr(j.Host); err != nil {
		addrs, err := net.DefaultResolver.LookupHost(context.Background(), j.Host)
		switch {
		case err != nil:
			r.bad("judge 主机名 %s 解析失败: %v", j.Host, err)
		case !contains(addrs, j.PublicIP):
			r.bad("judge 主机名 %s 解析到 %v，不含 public_ip %s", j.Host, addrs, j.PublicIP)
		default:
			r.pass("judge 主机名 %s 解析到 %s", j.Host, j.PublicIP)
		}
	}
	src, err := lists.LoadSources(c.SourcesFile)
	if err != nil {
		r.bad("来源清单读不出来: %v", err)
	} else {
		f := lists.NewFetcher()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		n, failed := 0, 0
		for _, l := range src.Lists {
			if l.Aggregator {
				continue
			}
			for _, url := range l.Files {
				n++
				if _, status, _, err := f.Get(ctx, url, ""); err != nil || status != 200 {
					failed++
				}
				break // 每个来源试一个文件
			}
		}
		for _, s := range src.Subscriptions {
			n++
			if _, status, _, err := f.Get(ctx, s.URL, ""); err != nil || status != 200 {
				failed++
			}
		}
		cancel()
		switch {
		case failed == 0:
			r.pass("列表和订阅都抓得到（试了 %d 个地址）", n)
		case failed*2 > n:
			r.bad("%d 个列表和订阅地址里有 %d 个抓不到，先检查本机能否访问 raw.githubusercontent.com", n, failed)
		default:
			r.warn("%d 个列表和订阅地址里有 %d 个抓不到", n, failed)
		}
	}

	fmt.Fprintln(out, "judge")
	running := judgeRunning(c)
	loHTTP, loTLS := loopback(j.HTTPListen), loopback(j.HTTPSListen)
	if running == nil {
		r.pass("judge 正在运行（回环访问 %s 和 %s 正常，证书与数据目录里的一致）", loHTTP, loTLS)
		for _, t := range []struct {
			name string
			port int
			tls  bool
		}{{"HTTP", j.HTTPPort, false}, {"HTTPS", j.HTTPSPort, true}} {
			if err := health(net.JoinHostPort(j.PublicIP, strconv.Itoa(t.port)), t.tls, c); err != nil {
				r.warn("从本机访问自己的公网地址（%s）不通: %v。很多云主机不支持这样回访，不一定是问题", t.name, short(err))
			} else {
				r.pass("从本机访问自己的公网地址（%s）正常", t.name)
			}
		}
	} else {
		// 用“连不连得上”判断端口是否被占：这样不依赖当前用户有没有绑定低端口的权限
		busy := false
		for _, l := range []string{j.HTTPListen, j.HTTPSListen} {
			if c, err := net.DialTimeout("tcp", loopback(l), 2*time.Second); err == nil {
				c.Close()
				busy = true
				r.bad("端口 %s 上有程序在监听，但不是按当前配置运行的 judge（%s）。"+
					"刚改过配置的话重启 judge；否则用 ss -ltnp 看是谁占着，腾不出来就换端口重装（见 README）", l, short(running))
			}
		}
		if !busy {
			r.bad("judge 没在运行（%s），两个端口都是空的。看日志: journalctl -u fieldtest-judge -n 20", short(running))
		}
	}
	fmt.Fprintf(out, "  请在另一台机器上执行下面两条命令，都应输出 ok（预检无法从外面检查自己）：\n")
	fmt.Fprintf(out, "      curl -s  http://%s/healthz\n", c.JudgeAuthority(false))
	fmt.Fprintf(out, "      curl -sk https://%s/healthz\n", c.JudgeAuthority(true))

	fmt.Fprintln(out, "sing-box")
	bin := ""
	if !c.Nodes.Enabled {
		r.warn("配置里关闭了节点探测")
	} else if p, err := exec.LookPath(c.Nodes.SingBox); err != nil {
		r.bad("找不到 sing-box（%s）。节点探测需要它", c.Nodes.SingBox)
	} else {
		bin = p
		ver, _ := exec.Command(bin, "version").Output()
		first := strings.SplitN(strings.TrimSpace(string(ver)), "\n", 2)[0]
		dir, _ := os.MkdirTemp("", "fieldtest-preflight-")
		defer os.RemoveAll(dir)
		n := nodes.Parse("ss://YWVzLTI1Ni1nY206cHJlZmxpZ2h0@192.0.2.1:8388")
		path := filepath.Join(dir, "c.json")
		os.WriteFile(path, nodes.Config(c.Nodes.ListenPort, []nodes.Member{{Tag: "n" + n.ID, Outbound: nodes.Outbound(n, "n"+n.ID, false)}}), 0o600)
		if msg, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
			r.bad("%s 不接受探测器生成的配置: %s", first, strings.TrimSpace(string(msg)))
		} else {
			r.pass("%s，接受探测器生成的配置", first)
		}
		if ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Nodes.ListenPort))); err != nil {
			r.warn("回环端口 %d 被占用，节点探测的旁路进程要用它（可在配置的 nodes.listen_port 里换一个）", c.Nodes.ListenPort)
		} else {
			ln.Close()
		}
	}

	if withSelftest {
		fmt.Fprintln(out, "仪器自检")
		var buf bytes.Buffer
		ok, err := selftest.Run(&buf, false, bin)
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		switch {
		case err != nil:
			r.bad("自检没跑起来: %v", err)
		case !ok:
			r.bad("自检有不符项，探测器在这台机器上的判定不可信：")
			for _, l := range lines {
				if strings.Contains(l, "不符") {
					fmt.Fprintln(out, "    "+strings.TrimSpace(l))
				}
			}
		default:
			r.pass("%s", lines[len(lines)-1])
		}
	}

	fmt.Fprintf(out, "结论：%d 项失败，%d 项注意\n", r.fail, r.warns)
	return r.fail == 0
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func short(err error) string {
	s := err.Error()
	if len(s) > 140 {
		s = s[:140]
	}
	return s
}

func loopback(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// directObserver 不经代理访问第二观察者，返回它看到的地址，以及本机时钟与它的差。
func directObserver(o *cfg.Observer) (netip.Addr, time.Duration, error) {
	port := o.Port
	if port == 0 {
		port = 443
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(o.Host, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	defer conn.Close()
	tc, info, _ := wire.TLS(conn, wire.TLSOpts{ServerName: o.Host, Timeout: 10 * time.Second})
	if !info.OK {
		return netip.Addr{}, 0, fmt.Errorf("TLS: %s %s", info.Class, info.Detail)
	}
	resp, st := wire.Get(tc, wire.GetSpec{Authority: o.Host, Path: o.Path, Timeout: 10 * time.Second, MaxBody: 8 << 10})
	if !st.OK {
		return netip.Addr{}, 0, fmt.Errorf("HTTP: %s %s", st.Class, st.Detail)
	}
	var skew time.Duration
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		skew = time.Since(d).Round(time.Second)
	}
	ip := probe.ParseObserver(o.Parse, resp.Body)
	if !ip.IsValid() {
		return netip.Addr{}, skew, fmt.Errorf("看不懂响应（状态 %d）", resp.Status)
	}
	return ip, skew, nil
}

// judgeRunning 检查 judge 是否在本机运行：回环访问两个端口，并核对 HTTPS 用的是数据目录里那张证书。
func judgeRunning(c *cfg.Config) error {
	if err := health(loopback(c.Judge.HTTPListen), false, c); err != nil {
		return err
	}
	return health(loopback(c.Judge.HTTPSListen), true, c)
}

func health(addr string, useTLS bool, c *cfg.Config) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if useTLS {
		tr, err := judge.LoadTrust(c)
		if err != nil {
			return err
		}
		tc, info, _ := wire.TLS(conn, wire.TLSOpts{ServerName: c.Judge.Host, Roots: tr.Roots, SPKIPin: tr.SPKIPin, Timeout: 5 * time.Second})
		if !info.OK {
			return fmt.Errorf("TLS: %s %s", info.Class, info.Detail)
		}
		conn = tc
	}
	resp, st := wire.Get(conn, wire.GetSpec{Authority: c.JudgeAuthority(useTLS), Path: "/healthz", Timeout: 5 * time.Second})
	if !st.OK {
		return fmt.Errorf("HTTP: %s %s", st.Class, st.Detail)
	}
	if resp.Status != 200 || strings.TrimSpace(string(resp.Body)) != "ok" {
		return fmt.Errorf("端口上的不是 judge（状态 %d）", resp.Status)
	}
	return nil
}
