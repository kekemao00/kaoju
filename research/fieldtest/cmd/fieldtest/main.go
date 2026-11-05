//go:build unix

// fieldtest 是第一阶段 1B 的实测工具：judge 端点、列表快照采集器、分阶段探测器，以及预检、自检和汇总。
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"fieldtest/internal/cfg"
	"fieldtest/internal/judge"
	"fieldtest/internal/lists"
	"fieldtest/internal/nodes"
	"fieldtest/internal/nonce"
	"fieldtest/internal/preflight"
	"fieldtest/internal/probe"
	"fieldtest/internal/rec"
	"fieldtest/internal/selftest"
	"fieldtest/internal/summary"
)

// version 在构建时用 -ldflags 写入。
var version = "dev"

const usage = `fieldtest %s

用法: fieldtest <命令> [选项]

  init       生成配置文件
  preflight  预检：这台机器能不能跑测量（含仪器自检）
  judge      运行 judge 端点
  probe      运行快照采集器和探测器
  sources    把全部列表和订阅抓一遍，报告条目数（不探测）
  summary    汇总已有的记录
  pack       把汇总和记录打成一个包，便于发回分析
  selftest   只跑仪器自检
  version    打印版本

每个命令加 -h 可以看它的选项。
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "preflight":
		err = cmdPreflight(args)
	case "judge":
		err = cmdJudge(args)
	case "probe":
		err = cmdProbe(args)
	case "sources":
		err = cmdSources(args)
	case "summary":
		err = cmdSummary(args)
	case "pack":
		err = cmdPack(args)
	case "selftest":
		err = cmdSelftest(args)
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Printf(usage, version)
	default:
		fmt.Fprintf(os.Stderr, "不认识的命令 %q\n\n", cmd)
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	c := fs.String("c", "/etc/fieldtest/fieldtest.json", "配置文件")
	return fs, c
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func cmdInit(args []string) error {
	fs, path := flags("init")
	host := fs.String("host", "", "judge 的主机名（探测请求里用它），没有域名就填公网 IP")
	ip := fs.String("ip", "", "这台机器的公网 IPv4 地址")
	data := fs.String("data", "/var/lib/fieldtest", "数据目录")
	contact := fs.String("contact", "", "写在 judge 首页上的联系方式（邮箱或网址），供想退出测量的人使用")
	httpL := fs.String("http", ":80", "judge 的 HTTP 监听地址")
	httpsL := fs.String("https", ":443", "judge 的 HTTPS 监听地址")
	singbox := fs.String("sing-box", "sing-box", "sing-box 可执行文件")
	hours := fs.Float64("hours", 0, "探测运行多少小时后自动停止，0 表示一直运行")
	force := fs.Bool("force", false, "覆盖已有的配置文件")
	fs.Parse(args)
	if *host == "" {
		*host = *ip
	}
	c := cfg.Default()
	c.DataDir = *data
	c.Judge.Host, c.Judge.PublicIP, c.Judge.Contact = *host, *ip, *contact
	c.Judge.HTTPListen, c.Judge.HTTPSListen = *httpL, *httpsL
	c.Nodes.SingBox = *singbox
	c.Probe.DurationHours = *hours
	if err := c.Finish(); err != nil {
		return err
	}
	if _, err := os.Stat(*path); err == nil && !*force {
		return fmt.Errorf("%s 已存在；要覆盖请加 -force", *path)
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(*path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println("已写入", *path)
	return nil
}

func cmdPreflight(args []string) error {
	fs, path := flags("preflight")
	noSelf := fs.Bool("no-selftest", false, "跳过仪器自检")
	fs.Parse(args)
	c, err := cfg.Load(*path)
	if err != nil {
		return err
	}
	var out io.Writer = os.Stdout
	if f, err := os.Create(c.Path("preflight.txt")); err == nil {
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
	}
	if !preflight.Run(c, out, !*noSelf) {
		return fmt.Errorf("预检有失败项")
	}
	return nil
}

func cmdJudge(args []string) error {
	fs, path := flags("judge")
	fs.Parse(args)
	c, err := cfg.Load(*path)
	if err != nil {
		return err
	}
	secret, err := c.LoadSecret(nonce.NewSecret)
	if err != nil {
		return err
	}
	log, err := rec.NewWriter(c.DataDir, "judge")
	if err != nil {
		return err
	}
	defer log.Close()
	s, err := judge.New(c, secret, log)
	if err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	fmt.Printf("judge %s 已启动: http %s  https %s  主机名 %s\n", version, s.HTTPAddr, s.HTTPSAddr, c.Judge.Host)
	ctx, cancel := signalContext()
	defer cancel()
	<-ctx.Done()
	s.Close()
	return nil
}

func cmdProbe(args []string) error {
	fs, path := flags("probe")
	hours := fs.Float64("hours", -1, "运行多少小时后自动停止（覆盖配置里的 probe.duration_hours）")
	fs.Parse(args)
	c, err := cfg.Load(*path)
	if err != nil {
		return err
	}
	if *hours >= 0 {
		c.Probe.DurationHours = *hours
	}
	// 只给端到端测试用：允许探测回环地址上的夹具。正式测量时绝不设置。
	c.AllowLocal = os.Getenv("FIELDTEST_ALLOW_LOCAL") == "1"
	secret, err := c.LoadSecret(nonce.NewSecret)
	if err != nil {
		return err
	}
	src, err := lists.LoadSources(c.SourcesFile)
	if err != nil {
		return err
	}
	log, err := rec.NewWriter(c.DataDir, "probe")
	if err != nil {
		return err
	}
	defer log.Close()
	snap, err := rec.NewWriter(c.DataDir, "snap")
	if err != nil {
		return err
	}
	defer snap.Close()
	env, err := probe.NewEnv(c, secret, log, rec.NewEvidence(c.Path("evidence")))
	if err != nil {
		return err
	}
	p := probe.NewProber(env, src, snap)
	if c.Nodes.Enabled {
		raw, err := rec.NewWriter(c.Path("local"), "noderaw")
		if err != nil {
			return err
		}
		defer raw.Close()
		nr := probe.NewNodeRun(env, src.Subscriptions, snap, c.Path("sidecar"))
		nr.Raw = raw
		p.Nodes = nr
	}
	log.Write(map[string]any{"ts": rec.TS(time.Now()), "k": "version", "version": version})
	fmt.Printf("探测器 %s 已启动: %d 个列表来源，%d 个订阅，每秒最多新建 %.0f 条连接\n",
		version, len(src.Lists), len(src.Subscriptions), c.Probe.ConnPerSec)
	ctx, cancel := signalContext()
	defer cancel()
	return p.Run(ctx)
}

func cmdSummary(args []string) error {
	fs, path := flags("summary")
	asJSON := fs.Bool("json", false, "输出 JSON")
	quiet := fs.Bool("quiet", false, "只写 summary.txt 和 summary.json，不打印")
	fs.Parse(args)
	c, err := cfg.Load(*path)
	if err != nil {
		return err
	}
	s, err := summary.Build(c)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", " ")
	os.WriteFile(c.Path("summary.json"), b, 0o644)
	if f, err := os.Create(c.Path("summary.txt")); err == nil {
		s.Text(f)
		f.Close()
	}
	switch {
	case *quiet:
	case *asJSON:
		os.Stdout.Write(append(b, '\n'))
	default:
		s.Text(os.Stdout)
	}
	return nil
}

func cmdSelftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	singbox := fs.String("sing-box", "", "sing-box 可执行文件；给出后同时自检节点探测")
	verbose := fs.Bool("v", false, "列出每个夹具的每一次尝试")
	fs.Parse(args)
	ok, err := selftest.Run(os.Stdout, *verbose, *singbox)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("自检有不符项")
	}
	return nil
}

// cmdPack 把汇总和原始记录打包。密钥、私钥和节点的原始链接不进包。
func cmdPack(args []string) error {
	fs, path := flags("pack")
	out := fs.String("o", "", "输出文件，默认是数据目录下的 fieldtest-pack-<时间>.tar.gz")
	noRaw := fs.Bool("no-raw", false, "只打包汇总，不带原始记录")
	fs.Parse(args)
	c, err := cfg.Load(*path)
	if err != nil {
		return err
	}
	if err := cmdSummary([]string{"-c", *path, "-quiet"}); err != nil {
		fmt.Fprintln(os.Stderr, "汇总失败，仍然继续打包:", err)
	}
	if *out == "" {
		*out = c.Path("fieldtest-pack-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz")
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	add := func(p string) error {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(c.DataDir, p)
		h, _ := tar.FileInfoHeader(st, "")
		h.Name = "fieldtest/" + filepath.ToSlash(rel)
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		// 正在写入的文件可能变长，只取打包开始时的长度
		_, err = io.CopyN(tw, in, st.Size())
		return err
	}
	names := []string{"summary.txt", "summary.json", "preflight.txt", "judge-cert.pem"}
	for _, n := range names {
		if err := add(c.Path(n)); err != nil {
			return err
		}
	}
	if !*noRaw {
		for _, prefix := range []string{"probe", "judge", "snap"} {
			for _, p := range rec.Files(c.DataDir, prefix) {
				if err := add(p); err != nil {
					return err
				}
			}
		}
		filepath.Walk(c.Path("evidence"), func(p string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() {
				return add(p)
			}
			return nil
		})
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	st, _ := f.Stat()
	fmt.Fprintf(os.Stderr, "已打包: %s（%.1f MB）\n", *out, float64(st.Size())/(1<<20))
	if strings.Contains(*out, c.DataDir) {
		fmt.Fprintln(os.Stderr, "包里不含密钥、私钥和节点的原始链接")
	}
	return nil
}

// cmdSources 把来源清单里的每个地址抓一遍并解析，不做任何探测。用来确认来源都还在、解析结果合理。
func cmdSources(args []string) error {
	fs := flag.NewFlagSet("sources", flag.ExitOnError)
	file := fs.String("f", "", "来源清单文件；不给则用程序自带的那份")
	fs.Parse(args)
	src, err := lists.LoadSources(*file)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	f := lists.NewFetcher()
	regular := map[string]struct{}{}
	fmt.Printf("%-38s %-8s %6s %8s %8s  %s\n", "来源", "标签", "状态", "条目", "毫秒", "不合格的行")
	type agg struct {
		name string
		set  map[string]struct{}
	}
	var aggs []agg
	for _, l := range src.Lists {
		union := map[string]struct{}{}
		labels := make([]string, 0, len(l.Files))
		for label := range l.Files {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		for _, label := range labels {
			r, set := f.Snapshot(ctx, &lists.File{Src: l.Name, Label: label, URL: l.Files[label], Agg: l.Aggregator}, time.Now())
			bad := ""
			if r.Q != nil {
				q := *r.Q
				q.Lines = 0
				if b, _ := json.Marshal(q); string(b) != "{}" {
					bad = string(b)
				}
			}
			if r.Err != "" {
				bad = r.Err
			}
			fmt.Printf("%-38s %-8s %6d %8d %8d  %s\n", l.Name, label, r.Status, r.N, r.Ms, bad)
			for k := range set {
				union[k] = struct{}{}
			}
		}
		if l.Aggregator {
			aggs = append(aggs, agg{l.Name, union})
		} else {
			for k := range union {
				regular[k] = struct{}{}
			}
		}
	}
	fmt.Printf("\n常规列表去重后 %d 条\n", len(regular))
	for _, a := range aggs {
		excl := 0
		for k := range a.set {
			if _, ok := regular[k]; !ok {
				excl++
			}
		}
		fmt.Printf("聚合器 %s: 去重后 %d 条，其中不在常规列表里的 %d 条\n", a.name, len(a.set), excl)
	}
	if len(src.Subscriptions) == 0 {
		return nil
	}
	fmt.Printf("\n%-38s %6s %8s %8s %8s\n", "订阅", "状态", "链接行", "解析不了", "节点")
	uniq := map[string]*nodes.Node{}
	for _, sub := range src.Subscriptions {
		body, status, _, err := f.Get(ctx, sub.URL, "")
		if err != nil {
			fmt.Printf("%-38s %v\n", sub.Name, err)
			continue
		}
		lines, bad := 0, 0
		own := map[string]struct{}{}
		for _, link := range nodes.Links(nodes.LoadText(body)) {
			lines++
			n := nodes.Parse(link)
			if n == nil {
				bad++
				continue
			}
			own[n.ID] = struct{}{}
			if _, ok := uniq[n.ID]; !ok {
				uniq[n.ID] = n
			}
		}
		fmt.Printf("%-38s %6d %8d %8d %8d\n", sub.Name, status, lines, bad, len(own))
	}
	byScheme, why := map[string]int{}, map[string]int{}
	ok := 0
	for _, n := range uniq {
		byScheme[n.Scheme]++
		if w := nodes.Supported(n); w != "" {
			why[w]++
		} else {
			ok++
		}
	}
	fmt.Printf("\n节点去重后 %d 个: %v\n", len(uniq), byScheme)
	fmt.Printf("sing-box 能连的 %d 个；不能连的原因: %v\n", ok, why)
	return nil
}
