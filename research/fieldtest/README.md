# fieldtest：72 小时实测工具

第一阶段 1B 用的测量工具。一个程序，包含四样东西：

- judge：目标站点兼独立见证方，记下自己实际收到的每个探测请求
- 快照采集器：定时抓取公开代理列表和节点订阅，记下增减
- 探测器：对每个条目分阶段探测（TCP、协议握手、隧道内 TLS、回显、载荷完整性）
- 预检、仪器自检和汇总

测什么、怎么判定、指标怎么定义，都事先写在 [PROTOCOL.md](PROTOCOL.md) 里。

## 部署前要知道的

- judge 要占用这台机器的 80 和 443 端口。
- 探测器会向公开列表里的几万个地址发起连接，每秒不超过 40 条，持续 72 小时。
- 这台机器的 IP 和域名会出现在这些代理的日志里。上面如果还有别的重要服务，换一台机器。
- 云厂商有可能把大量对外连接当成扫描来提醒你。工具做了限速，只连公开列表里的地址，judge 首页写明了用途和联系方式，
  但不能保证不被提醒。
- 数据写在 `/var/lib/fieldtest`，72 小时预计占几个 GB；磁盘剩余不足 1 GB 时探测会自动停止。

## 部署

需要一台 Linux 服务器（x86-64 或 arm64）、root 权限、公网 IPv4。有 systemd 最省事。

```sh
tar -xzf fieldtest-bundle.tar.gz && cd fieldtest-bundle
./deploy/install.sh --host <judge 的域名> --ip <公网 IPv4> --contact <邮箱或网址>
```

安装脚本会：把程序装到 `/usr/local/bin/fieldtest`；下载官方 sing-box 1.14.4 并核对 SHA-256；
新建没有登录权限的用户 `fieldtest`；写配置 `/etc/fieldtest/fieldtest.json`；启动 judge；运行预检。
探测不会自动开始。

接下来三步：

1. 看预检的输出。有“失败”先解决，再执行 `fieldtest preflight`。
2. 在另一台机器（比如你自己的电脑）上确认 judge 从外面能访问，两条命令都应输出 `ok`：

   ```sh
   curl -s  http://<域名>/healthz
   curl -sk https://<域名>/healthz
   ```

   不通的话，检查云厂商的安全组和本机防火墙是否放行了 80 和 443 的入站。
3. 开始探测，30 分钟后看汇总：

   ```sh
   systemctl enable --now fieldtest-probe
   fieldtest summary
   ```

汇总开头的“自动检查”没有报问题，就让它继续跑满 72 小时。

### 80 或 443 被占用

最好在测量期间把占用它们的服务停掉或挪走。做不到时改用别的端口：

```sh
./deploy/install.sh --host <域名> --ip <IP> --contact <联系方式> --http :8080 --https :8443 --reconfigure
```

安全组也要放行这两个端口。代价是：不少 HTTP 代理只允许 CONNECT 到 443，换了端口会把它们算成不可用。报告里会注明这一点。

### 服务器访问不了 GitHub

安装脚本要从 GitHub 下载 sing-box。下载不了时，先在别处下载
`sing-box-1.14.4-linux-amd64.tar.gz`（arm64 机器对应 arm64 的包），放到解开的目录里，再运行安装脚本。
脚本照样核对 SHA-256。

## 取回数据

```sh
fieldtest pack            # 汇总 + 全部原始记录 + 证据
fieldtest pack -no-raw    # 只要汇总
```

包生成在 `/var/lib/fieldtest/` 下。里面没有密钥、judge 的私钥和节点的原始链接。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `fieldtest preflight` | 预检。结果同时写到数据目录的 `preflight.txt` |
| `fieldtest summary` | 汇总目前的记录，开头是自动检查的结论 |
| `fieldtest sources` | 把全部列表和订阅抓一遍，报告条目数。不做任何探测 |
| `fieldtest selftest -sing-box /opt/fieldtest/sing-box/sing-box -v` | 只跑仪器自检，列出每个夹具的每次尝试 |
| `systemctl status fieldtest-judge fieldtest-probe` | 两个服务的状态 |
| `journalctl -u fieldtest-probe -n 50` | 探测器最近的输出 |
| `systemctl stop fieldtest-probe` | 停止探测。再启动时接着上次的状态跑 |
| `./deploy/uninstall.sh` | 卸载，保留数据；加 `--purge` 连数据一起删 |

有人要求把某个地址排除在测量之外时，把 IP 或网段写进 `/var/lib/fieldtest/exclude.txt`，一行一个，五分钟内生效。

## 配置

配置文件是 `/etc/fieldtest/fieldtest.json`，由 `fieldtest init` 生成，里面是全部字段和当前取值。常要动的只有这几个：

| 字段 | 含义 | 默认 |
| --- | --- | --- |
| `judge.host` | 探测请求里用的主机名 | 安装时给的域名 |
| `judge.public_ip` | 本机的公网 IPv4 | 安装时给的地址 |
| `judge.http_listen`、`judge.https_listen` | judge 的监听地址 | `:80`、`:443` |
| `judge.cert_file`、`judge.key_file` | 公开签发的证书。留空时自动生成自签证书，探测器只认这一张 | 空 |
| `judge.contact` | 写在 judge 首页上的联系方式 | 安装时给的 |
| `probe.conn_per_sec` | 每秒新建连接的上限 | 40 |
| `probe.duration_hours` | 运行多久后自动停止，0 表示不停 | 0 |
| `nodes.enabled` | 是否探测节点订阅 | true |

改完配置后重启对应的服务。

## 数据目录

| 路径 | 内容 |
| --- | --- |
| `probe-*.jsonl` | 探测器的记录：每条连接、每次探访、节点探测、运行状况 |
| `judge-*.jsonl` | judge 的记录：收到的每个请求和它的原始请求头 |
| `snap-*.jsonl` | 列表和订阅的快照 |
| `evidence/` | 被改动的响应正文、不属于 judge 的证书链，按内容哈希存放 |
| `summary.txt`、`summary.json`、`preflight.txt` | 最近一次汇总和预检的结果 |
| `state.json.gz` | 探测器的调度状态，重启后接着跑用 |
| `secret`、`judge-key.pem` | 签发 nonce 的密钥和 judge 的私钥。不要外传 |
| `local/` | 节点标识与原始分享链接的对照，只留在本机 |

记录按小时切分，过去的小时会压缩成 `.gz`。各种记录的字段见 PROTOCOL.md 和源码里的类型定义。

## 源码与测试

工具只用 Go 标准库，没有第三方依赖。

```sh
go build ./cmd/fieldtest
go test ./...                                     # 含仪器自检
FIELDTEST_SINGBOX=/path/to/sing-box go test ./... # 加上节点探测的自检和配置检查
./deploy/build-bundle.sh                          # 构建部署包
SINGBOX=/path/to/sing-box ./test/e2e.sh           # 端到端测试，约 5 分钟，只连 127.0.0.0/8
```

端到端测试把夹具当作“公开列表”，让 judge 和探测器照正式流程跑两轮（中间重启一次），
再由 `test/e2e_check.py` 核对汇总。每次提交都在 GitHub Actions 上跑这些检查，见 `.github/workflows/fieldtest.yml`。

另有三项要用到普查数据的核对，设置对应的环境变量才会运行：

| 环境变量 | 核对什么 |
| --- | --- |
| `FIELDTEST_HIST_DIR` | 列表解析器与普查脚本对每个列表文件得出相同的条目集合和质量计数 |
| `FIELDTEST_NODES_DIR` | 分享链接解析器的去重结果与普查脚本一致 |
| 再加上 `FIELDTEST_SINGBOX` | 全部可映射的节点都能通过 sing-box 的配置检查 |

模糊测试：

```sh
go test ./internal/wire  -run '^$' -fuzz '^FuzzHandshakes$' -fuzztime 1m
go test ./internal/lists -run '^$' -fuzz '^FuzzParse$' -fuzztime 1m
go test ./internal/nodes -run '^$' -fuzz '^FuzzParse$' -fuzztime 1m
```

| 目录 | 内容 |
| --- | --- |
| `internal/wire` | 单步的协议动作：SOCKS4、SOCKS5、HTTP CONNECT、隧道内 TLS、一次 HTTP 请求，以及失败的归类 |
| `internal/probe` | 探访的编排、调度与限速、列表快照、节点探测、对照探测 |
| `internal/judge` | judge 端点 |
| `internal/lists` | 列表解析（规则与普查脚本相同）和来源清单 `sources.json` |
| `internal/nodes` | 分享链接解析，映射成 sing-box 的出站配置 |
| `internal/evil` | 自检用的代理夹具，有规矩的也有作恶的 |
| `internal/selftest` | 仪器自检：每个夹具的已知行为和探测器应给出的判定 |
| `internal/summary` | 把探测器和 judge 的记录对起来并汇总 |
| `cmd/fixtures` | 端到端测试的布景：把夹具当作“公开列表”提供出来，让 judge 和探测器照正式流程在本机跑一遍 |
