// obsproxy 是第 2 阶段（客户端行为矩阵）的测量仪器：一个只做观察的代理，自带明文和 HTTPS 两个源站。
// 规格见 ../PROTOCOL.md 的“仪器 / obsproxy”一节，事件格式见 EVENTS.md。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const usage = `用法：
  obsproxy gen-ca -dir DIR
      生成测试用 CA（ECDSA P-256，7 天有效）：DIR/ca.pem、DIR/ca.key
  obsproxy serve -profile P.json -ca-dir DIR -events E.jsonl [-max-seconds 120]
      在 127.0.0.1 上监听三个随机端口，就绪后在标准输出打印一行 JSON
      {"proxy_port":…,"origin_http_port":…,"origin_https_port":…}
      收到 SIGTERM、SIGINT 或超过 -max-seconds 后关闭所有连接，写完事件再退出
  obsproxy version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "gen-ca":
		return cmdGenCA(args[1:], stdout, stderr)
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "obsproxy %s（事件格式第 %d 版）\n", version, eventsVersion)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "obsproxy: 不认识的子命令 %q\n\n%s", args[0], usage)
	return 2
}

func cmdGenCA(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gen-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "放 ca.pem 和 ca.key 的目录")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "obsproxy gen-ca: 需要 -dir DIR，且没有别的参数")
		return 2
	}
	fp, err := genCA(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "obsproxy gen-ca: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "已生成测试用 CA：%s/ca.pem（证书的 SHA-256：%s），私钥在 %s/ca.key\n", *dir, fp, *dir)
	return 0
}

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profilePath := fs.String("profile", "", "配置文件（JSON，字段见 PROTOCOL.md）")
	caDir := fs.String("ca-dir", "", "gen-ca 生成的目录")
	eventsPath := fs.String("events", "", "事件文件（JSONL，格式见 EVENTS.md）")
	maxSeconds := fs.Int("max-seconds", 120, "最长运行多少秒，到点自己退出；0 表示不限")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profilePath == "" || *caDir == "" || *eventsPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "obsproxy serve: 需要 -profile、-ca-dir、-events 三个参数，且没有别的参数")
		return 2
	}
	prof, err := LoadProfile(*profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "obsproxy serve: %v\n", err)
		return 2
	}
	ef, err := os.OpenFile(*eventsPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(stderr, "obsproxy serve: 打不开事件文件: %v\n", err)
		return 1
	}
	defer ef.Close()

	srv, err := NewServer(prof, *caDir, ef, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "obsproxy serve: %v\n", err)
		return 1
	}
	srv.maxSeconds = *maxSeconds

	// 先接管信号再宣布就绪，这样调用方一看到就绪行就可以放心发信号。
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	srv.Start()

	pp, hp, sp := srv.Ports()
	ready, _ := json.Marshal(obj{{"proxy_port", pp}, {"origin_http_port", hp}, {"origin_https_port", sp}})
	fmt.Fprintf(stdout, "%s\n", ready)
	if f, ok := stdout.(*os.File); ok {
		_ = f.Sync() // 标准输出是管道或终端时没有可刷的缓冲，出错可以不管
	}

	var timeout <-chan time.Time
	if *maxSeconds > 0 {
		t := time.NewTimer(time.Duration(*maxSeconds) * time.Second)
		defer t.Stop()
		timeout = t.C
	}
	reason := ""
	select {
	case sig := <-sigc:
		reason = "signal:" + sigName(sig)
	case <-timeout:
		reason = "max_seconds"
	}
	srv.Shutdown(reason)
	if err := srv.log.writeErr(); err != nil {
		fmt.Fprintf(stderr, "obsproxy serve: 写事件文件出错: %v\n", err)
		return 1
	}
	return 0
}

func sigName(sig os.Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGINT:
		return "SIGINT"
	}
	return sig.String()
}
