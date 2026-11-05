//go:build unix

// fixtures 是端到端测试的布景：在本机启动全部代理夹具、两个假的第二观察者、一个 sing-box 服务端，
// 并用一个小 HTTP 服务把它们的地址当作“公开列表”和“订阅”提供出来，再写好 fieldtest 的配置文件。
// 之后照正式流程运行 fieldtest judge 和 fieldtest probe，就是一次不出本机的完整测量。
// 这个程序只用于测试，不随测量工具部署。
package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"fieldtest/internal/cfg"
	"fieldtest/internal/lists"
	"fieldtest/internal/selftest"
)

func main() {
	dir := flag.String("dir", "", "工作目录")
	httpPort := flag.Int("http", 18080, "judge 的 HTTP 端口")
	httpsPort := flag.Int("https", 18443, "judge 的 HTTPS 端口")
	singbox := flag.String("sing-box", "", "sing-box 可执行文件")
	dead := flag.Int("dead", 0, "往常规列表里加这么多个没人监听的地址，用来测调度在大规模下的表现")
	rate := flag.Float64("rate", 40, "写进配置的每秒新建连接上限")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "需要 -dir")
		os.Exit(2)
	}
	must := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "错误:", err)
			os.Exit(1)
		}
	}
	must(os.MkdirAll(*dir, 0o755))

	obsLn, _, caDER, err := selftest.StartObserver()
	must(err)
	obsPort := obsLn.Addr().(*net.TCPAddr).Port
	must(os.WriteFile(filepath.Join(*dir, "obs-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644))

	resolve := map[string]string{"judge.test": "127.0.0.1", "obs1.test": "127.0.0.1", "obs2.test": "127.0.0.1"}
	fx, closeFx, err := selftest.StartFixtures(*httpsPort, obsPort, resolve)
	must(err)
	defer closeFx()

	var links []string
	if *singbox != "" {
		var stop func()
		links, stop, err = selftest.StartNodeServer(*singbox, *dir, *httpsPort)
		must(err)
		defer stop()
	}

	// 列表：每种标签一个文件。聚合器的文件里除了常规条目，还有一批没人监听的地址。
	var mu sync.Mutex
	byLabel := map[string][]string{}
	for _, f := range fx {
		byLabel[f.Label] = append(byLabel[f.Label], f.Addr)
	}
	for i := 0; i < *dead; i++ {
		byLabel["http"] = append(byLabel["http"], fmt.Sprintf("127.%d.%d.%d:8080", 16+i/65536, (i/256)%256, i%256))
	}
	extra := []string{"not a proxy line", "example.com:8080", "10.0.0.1", "999.1.1.1:80", "127.0.9.9:22"}
	var agg []string
	for i := 0; i < 40; i++ {
		agg = append(agg, fmt.Sprintf("127.0.2.%d:%d", i+1, 20000+rand.IntN(20000)))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/lists/", func(w http.ResponseWriter, r *http.Request) {
		label := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/lists/"), ".txt")
		mu.Lock()
		body := strings.Join(append(append([]string{}, byLabel[label]...), extra...), "\n") + "\n"
		mu.Unlock()
		fmt.Fprint(w, body)
	})
	mux.HandleFunc("/agg/", func(w http.ResponseWriter, r *http.Request) {
		label := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/agg/"), ".txt")
		mu.Lock()
		all := append([]string{}, byLabel[label]...)
		mu.Unlock()
		if label == "http" {
			all = append(all, agg...)
		}
		fmt.Fprint(w, strings.Join(all, "\n")+"\n")
	})
	mux.HandleFunc("/sub.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Join(links, "\n")+"\nnot-a-link\n")
	})
	// 模拟下榜：访问 /drop?label=http&n=2 会从列表里去掉 n 个条目
	mux.HandleFunc("/drop", func(w http.ResponseWriter, r *http.Request) {
		label := r.URL.Query().Get("label")
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		mu.Lock()
		if n > len(byLabel[label]) {
			n = len(byLabel[label])
		}
		dropped := byLabel[label][len(byLabel[label])-n:]
		byLabel[label] = byLabel[label][:len(byLabel[label])-n]
		mu.Unlock()
		fmt.Fprintln(w, "dropped", dropped)
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	go http.Serve(ln, mux)
	base := "http://" + ln.Addr().String()

	src := lists.Sources{
		Lists: []lists.List{
			{Name: "local/regular", Files: map[string]string{}},
			{Name: "local/aggregator", Aggregator: true, Files: map[string]string{}},
		},
	}
	for label := range byLabel {
		src.Lists[0].Files[label] = base + "/lists/" + label + ".txt"
		src.Lists[1].Files[label] = base + "/agg/" + label + ".txt"
	}
	if len(links) > 0 {
		src.Subscriptions = []lists.Subscription{{Name: "local/sub", URL: base + "/sub.txt"}}
	}
	sb, _ := json.MarshalIndent(src, "", " ")
	must(os.WriteFile(filepath.Join(*dir, "sources.json"), sb, 0o644))

	c := cfg.Default()
	c.DataDir = filepath.Join(*dir, "data")
	c.SourcesFile = filepath.Join(*dir, "sources.json")
	c.Judge = cfg.Judge{Host: "judge.test", PublicIP: "127.0.0.1", Contact: "e2e@example.invalid",
		HTTPListen: "127.0.0.1:" + strconv.Itoa(*httpPort), HTTPSListen: "127.0.0.1:" + strconv.Itoa(*httpsPort)}
	c.Probe.DialTimeoutSec, c.Probe.IOTimeoutSec, c.Probe.ConnPerSec = 2, 2, *rate
	c.Probe.SnapshotMin, c.Probe.AliveIntervalMin, c.Probe.OpenIntervalMin = 1, 1, 1
	c.Probe.DeadBaseMin, c.Probe.JustDiedBaseMin, c.Probe.DeadMaxMin = 1, 1, 2
	c.Probe.AggregatorSample, c.Probe.AggregatorMin = 25, 1
	c.Probe.SkipPorts = []int{22}
	c.Nodes.Enabled = *singbox != ""
	c.Nodes.SingBox, c.Nodes.RoundMin, c.Nodes.SnapshotMin, c.Nodes.Concurrency = *singbox, 1, 1, 8
	c.Observers = []cfg.Observer{
		{Name: "kv", Host: "obs1.test", Port: obsPort, Path: "/cdn-cgi/trace", Parse: "kv"},
		{Name: "plain", Host: "obs2.test", Port: obsPort, Path: "/", Parse: "plain"},
	}
	must(c.Finish())
	cb, _ := json.MarshalIndent(c, "", " ")
	must(os.WriteFile(filepath.Join(*dir, "fieldtest.json"), cb, 0o644))
	fmt.Printf("ready base=%s fixtures=%d nodes=%d obs_port=%d\n", base, len(fx), len(links), obsPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
