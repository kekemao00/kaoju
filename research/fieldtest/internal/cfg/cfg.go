// Package cfg 读取和校验配置。配置文件是 JSON；没写的字段用这里的默认值。
package cfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir     string     `json:"data_dir"`
	SourcesFile string     `json:"sources_file"`
	Judge       Judge      `json:"judge"`
	Probe       Probe      `json:"probe"`
	Nodes       Nodes      `json:"nodes"`
	Observers   []Observer `json:"observers"`

	// 只给自测用：允许探测回环和私网地址。配置文件里不出现。
	AllowLocal bool `json:"-"`
	// 只给自测用：把主机名解析到固定地址（"judge.test" → "127.0.0.1"）。
	StaticHosts map[string]string `json:"-"`
}

type Judge struct {
	Host        string `json:"host"`         // 探测请求里用的主机名（Host 头和 SNI），也可以是 IP
	PublicIP    string `json:"public_ip"`    // 公网 IPv4：SOCKS4 要用，也用来把自己排除在探测目标之外
	HTTPListen  string `json:"http_listen"`  // 默认 ":80"
	HTTPSListen string `json:"https_listen"` // 默认 ":443"
	HTTPPort    int    `json:"http_port"`    // 外部看到的端口，默认取监听端口
	HTTPSPort   int    `json:"https_port"`
	CertFile    string `json:"cert_file"` // 可选：公开签发的证书。留空则自动生成自签证书并在探测时锁定它
	KeyFile     string `json:"key_file"`
	Contact     string `json:"contact"` // 写在 judge 首页上的联系方式，供想退出测量的人使用
}

type Probe struct {
	ConnPerSec         float64 `json:"conn_per_sec"`         // 每秒新建连接数上限
	Concurrency        int     `json:"concurrency"`          // 同时进行的探访数上限
	PerPrefixConc      int     `json:"per_prefix_conc"`      // 同一个 /24 里同时进行的探访数上限
	DialTimeoutSec     int     `json:"dial_timeout_sec"`     //
	IOTimeoutSec       int     `json:"io_timeout_sec"`       // 握手、TLS、HTTP 各阶段的超时
	AliveIntervalMin   int     `json:"alive_interval_min"`   // 可用的代理多久复测一次
	OpenIntervalMin    int     `json:"open_interval_min"`    // 端口开着但不是可用代理的，多久复测一次
	DeadBaseMin        int     `json:"dead_base_min"`        // 连不上的，退避的起点
	JustDiedBaseMin    int     `json:"just_died_base_min"`   // 曾经可用、刚连不上的，退避的起点
	DeadMaxMin         int     `json:"dead_max_min"`         // 退避的上限
	FullIdentHours     int     `json:"full_ident_hours"`     // 多久重新做一次完整的协议识别
	ExtraHours         int     `json:"extra_hours"`          // 第二观察者、明文对照等附加测试的间隔
	DelistedGraceHours int     `json:"delisted_grace_hours"` // 从列表消失后继续探测多久
	SnapshotMin        int     `json:"snapshot_min"`         // 列表快照间隔
	AggregatorSample   int     `json:"aggregator_sample"`    // 从每个聚合器的独占条目里抽多少条
	AggregatorMin      int     `json:"aggregator_min"`       // 聚合器抽样条目的复测间隔（可用的）
	SkipPorts          []int   `json:"skip_ports"`           // 不探测的端口
	ExcludeFile        string  `json:"exclude_file"`         // 不探测的地址段，每行一个 CIDR 或 IP
	DurationHours      float64 `json:"duration_hours"`       // 运行多久后自动停止探测，0 表示不停
}

type Nodes struct {
	Enabled     bool   `json:"enabled"`
	SingBox     string `json:"sing_box"`      // sing-box 可执行文件路径
	ListenPort  int    `json:"listen_port"`   // 旁路进程在回环上监听的端口
	Batch       int    `json:"batch"`         // 每批加载多少个节点
	Concurrency int    `json:"concurrency"`   // 每批内同时探测多少个节点
	RoundMin    int    `json:"round_min"`     // 两轮之间的最小间隔
	SnapshotMin int    `json:"snapshot_min"`  // 订阅快照间隔
	MaxPerRound int    `json:"max_per_round"` // 每轮最多探测多少个节点，0 表示不限
}

type Observer struct {
	Name  string `json:"name"`
	Host  string `json:"host"`
	Port  int    `json:"port,omitempty"` // 默认 443
	Path  string `json:"path"`
	Parse string `json:"parse"` // "plain"：响应体就是 IP；"kv"：每行 key=value，取 ip
}

func Default() *Config {
	return &Config{
		DataDir:     "/var/lib/fieldtest",
		SourcesFile: "",
		Judge:       Judge{HTTPListen: ":80", HTTPSListen: ":443"},
		Probe: Probe{
			ConnPerSec: 40, Concurrency: 300, PerPrefixConc: 4,
			DialTimeoutSec: 10, IOTimeoutSec: 15,
			AliveIntervalMin: 20, OpenIntervalMin: 120, DeadBaseMin: 30, JustDiedBaseMin: 5, DeadMaxMin: 360,
			FullIdentHours: 24, ExtraHours: 6, DelistedGraceHours: 24,
			SnapshotMin: 10, AggregatorSample: 5000, AggregatorMin: 60,
			// 这些端口上不会有代理；往上面发代理握手只会招来滥用投诉
			SkipPorts: []int{21, 22, 23, 25, 53, 110, 111, 135, 137, 138, 139, 143, 161, 389, 445, 465, 587,
				993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017},
		},
		Nodes: Nodes{Enabled: true, SingBox: "sing-box", ListenPort: 17890, Batch: 400, Concurrency: 40,
			RoundMin: 60, SnapshotMin: 30},
		Observers: []Observer{
			{Name: "cloudflare", Host: "www.cloudflare.com", Path: "/cdn-cgi/trace", Parse: "kv"},
			{Name: "aws", Host: "checkip.amazonaws.com", Path: "/", Parse: "plain"},
		},
	}
}

// Load 读配置文件并填默认值。path 为空时只用默认值。
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("配置文件 %s: %w", path, err)
		}
	}
	if err := c.Finish(); err != nil {
		return nil, err
	}
	return c, nil
}

// Finish 推导端口并校验。
func (c *Config) Finish() error {
	var errs []string
	j := &c.Judge
	if j.Host == "" {
		errs = append(errs, "judge.host 不能为空")
	}
	if j.PublicIP == "" {
		errs = append(errs, "judge.public_ip 不能为空")
	} else if a, err := netip.ParseAddr(j.PublicIP); err != nil || !a.Is4() {
		errs = append(errs, "judge.public_ip 必须是 IPv4 地址")
	}
	for _, p := range []struct {
		listen string
		port   *int
		name   string
	}{{j.HTTPListen, &j.HTTPPort, "http"}, {j.HTTPSListen, &j.HTTPSPort, "https"}} {
		if *p.port == 0 {
			_, ps, err := net.SplitHostPort(p.listen)
			if err != nil {
				errs = append(errs, fmt.Sprintf("judge.%s_listen 无法解析: %v", p.name, err))
				continue
			}
			n, err := strconv.Atoi(ps)
			if err != nil {
				errs = append(errs, fmt.Sprintf("judge.%s_listen 的端口不是数字", p.name))
				continue
			}
			*p.port = n
		}
	}
	if (j.CertFile == "") != (j.KeyFile == "") {
		errs = append(errs, "judge.cert_file 和 judge.key_file 要么都写，要么都不写")
	}
	if c.Probe.ConnPerSec <= 0 || c.Probe.Concurrency <= 0 {
		errs = append(errs, "probe.conn_per_sec 和 probe.concurrency 必须大于 0")
	}
	if c.DataDir == "" {
		errs = append(errs, "data_dir 不能为空")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "；"))
	}
	return nil
}

// JudgeAuthority 返回 URL 里的 host[:port] 部分。
func (c *Config) JudgeAuthority(tls bool) string {
	port, def := c.Judge.HTTPPort, 80
	if tls {
		port, def = c.Judge.HTTPSPort, 443
	}
	if port == def {
		return c.Judge.Host
	}
	return net.JoinHostPort(c.Judge.Host, strconv.Itoa(port))
}

func (c *Config) Path(name string) string { return filepath.Join(c.DataDir, name) }

// LoadSecret 读共享密钥；不存在时生成。judge 和探测器用它签发、校验 nonce。
func (c *Config) LoadSecret(create func() []byte) ([]byte, error) {
	p := c.Path("secret")
	b, err := os.ReadFile(p)
	if err == nil && len(b) >= 16 {
		return b, nil
	}
	if err := os.MkdirAll(c.DataDir, 0o755); err != nil {
		return nil, err
	}
	b = create()
	// O_EXCL：judge 和探测器同时启动时，只有一个能创建成功，另一个回头读它
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		for i := 0; i < 40; i++ {
			if b2, err2 := os.ReadFile(p); err2 == nil && len(b2) >= 16 {
				return b2, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}
