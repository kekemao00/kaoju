# 配置、管理 API、指标

## 配置文件

**DD-40** 一个声明式的 YAML 文件，结构由 [config.schema.json](config.schema.json) 约束，例子见 [config.example.yaml](config.example.yaml)。
`research/design/check_config.py` 核对例子符合 Schema，并且 Schema 确实拒绝 13 种写错的配置。

| 段 | 内容 | 出处 |
| --- | --- | --- |
| `listen` | 监听地址；可以把一个端口绑成“端口即会话” | [02-gateway.md](02-gateway.md) 的 DD-10、DD-14 |
| `admin` | 只读管理 API 和指标的地址 | 本文 |
| `accounts` | 账号、口令的来源、并发上限 | [01-threat-model.md](01-threat-model.md) 的 DD-5 |
| `defaults` | 用户名里没写时的 `tier`、`onfail`、`ttl`、`life` | [02-gateway.md](02-gateway.md) 的 DD-11 |
| `policy` | 隧道端口白名单、直连规则、额外禁止的目标 | [02-gateway.md](02-gateway.md) 的 DD-12 |
| `trusted` | 自有或付费的代理 | [01-threat-model.md](01-threat-model.md) 的 DD-1 |
| `sources` | 出厂来源的开关、聚合器的抽样、自己加的列表和订阅 | [05-routing.md](05-routing.md) 的 DD-36 到 DD-39 |
| `probe` | 探测的限速、目标池大小、验证有效期 | [05-routing.md](05-routing.md) 的 DD-33 |
| `observers` | 公共回显服务的开关和限速、自建 judge | [05-routing.md](05-routing.md) 的 DD-34、DD-35 |
| `routing` | 选路策略、单上游并发、重试次数和时限 | [05-routing.md](05-routing.md) 的 DD-31、DD-32，[04-failures.md](04-failures.md) 的 DD-20 |
| `session` | 出口观察的间隔和期限、稳定的判定、绑定时要求的存活时长 | [03-sticky.md](03-sticky.md) |
| `storage`、`log` | 数据库文件、日志级别 | |

几条不在 Schema 里、由 `kaoju check` 另外检查的规则（Schema 表达不了跨字段的约束）：

- 任何一个 `listen` 的地址不是回环地址时，每个账号都必须有口令来源，而且不带凭据的“端口即会话”不许出现在这个地址上。不满足就拒绝启动。
- `admin` 的地址不是回环地址时必须配 `token_env` 或 `token_file`。
- `listen` 里 `session.account` 引用的账号必须存在。
- `tier` 的默认值是 `trusted` 或 `auto` 而 `trusted` 段是空的：`auto` 允许（等同于 `verified`），`trusted` 拒绝。

**DD-41** 秘密不进配置文件。口令、可信上游带凭据的地址、管理 API 的令牌只能经环境变量（`*_env`）或文件（`*_file`）给出，Schema 里没有明文字段。
理由：配置文件会被贴进 issue、提交进仓库；管理 API 和日志里也永远不输出这些值。

**DD-42** 上限写死在 Schema 里的几项：探测速率不超过每秒 40（1B 用过的上限）、同一个 /24 的并发不超过 4、聚合器抽样不超过 5,000、公共回显服务每秒不超过 2 次。
理由：这几项关系到对第三方的打扰，超出 1B 测过的范围就没有依据，不留“自己改大”的口子。想改的人要改代码，并且自己负责。

### 环境变量、校验、热重载

- **环境变量覆盖**：`KAOJU__` 加上用双下划线连接的路径，例如 `KAOJU__PROBE__RATE=10`、`KAOJU__ROUTING__STRATEGY=p2c`。只覆盖标量；数组不能用环境变量改。
  覆盖之后的结果同样要过 Schema。
- **校验子命令**：`kaoju check 配置文件`。只读文件、过 Schema 和上面的跨字段规则、打印生效的配置（秘密显示为来源名），不监听、不联网。退出码 0 合格，1 不合格。
- **热重载**：收到 `SIGHUP` 或文件变化时重读。新配置不合格就整个拒绝、继续用旧的，并在日志、指标（`kaoju_config_reload_total{result}`）和管理 API 里报告；不做“合格的部分先生效”。
  能热重载的：`accounts`、`defaults`、`policy`、`trusted`、`sources`、`probe`、`observers`、`routing`、`session`、`log`。
  改了 `listen`、`admin`、`storage` 要重启，重载时发现这几段变了就报告“需要重启”，其余的照常生效。
  重载不动已有的会话：会话的参数在创建时固定（INV-6）；账号被删掉时，它的会话在下一条隧道请求时因为认证失败而自然结束，已经打开的隧道不切断。

## 存储

内嵌 SQLite（决策 D5），一个文件。两类写入：

- **先落盘再继续**：会话的绑定和换绑事件（INV-3、INV-7）、上游进出 `mitm` 隔离、来源状态的变化。
- **定期落盘**：选路的统计、探测的结果、来源的统计。丢了最近几十秒的不影响正确性，只影响选路的质量。

管理 API 和事件里出现的上游地址是公开列表里的地址；可信上游只显示名字，不显示地址和凭据。

## 管理 API

只读，全部是 `GET`，返回 JSON。没有任何能改变网关状态的接口；改状态只有改配置这一条路。

| 路径 | 内容 |
| --- | --- |
| `/healthz` | 进程活着、存储可写、至少一个观察者可达 |
| `/v1/status` | 版本、启动时刻、生效配置的摘要、`verified` 的出口组数和目标数、探测速率 |
| `/v1/upstreams` | 上游：协议、层、状态、出处、最近一次验证、出口、存活时长、在途连接数 |
| `/v1/egress` | 出口组：成员、是否稳定、绑着几个会话、最近一次观察的时刻和观察者 |
| `/v1/sessions` | 当前的会话实例 |
| `/v1/sessions/{账号}/{会话}` | 这个会话的状态、当前的出口和代数、参数、全部事件（绑定、换绑、出口用不了、过期） |
| `/v1/sources` | 来源：状态、最近一次抓取、产出率、中位寿命、独占贡献、各种拒收的计数、许可和条款字段 |
| `/v1/events?since=` | 事件流：会话、上游隔离、来源状态、配置重载 |
| `/metrics` | Prometheus 指标 |

`/v1/sessions/{账号}/{会话}` 是“换绑并明确告知”里那个一定看得到的通道（[03-sticky.md](03-sticky.md)）。

## 指标

名字是契约的一部分，验收标准按它们取数。

| 指标 | 标签 | 含义 |
| --- | --- | --- |
| `kaoju_requests_total` | `entry`、`tier`、`result` | 客户端的隧道请求和明文请求，按最终结果 |
| `kaoju_attempts_total` | `tier`、`class` | 每一次向上游的尝试，按失败分类法的类别 |
| `kaoju_retries_total` | `reason` | 重试 |
| `kaoju_fallback_total` | | 回落到可信层 |
| `kaoju_session_rebinds_total` | `reason` | 换绑 |
| `kaoju_session_egress_unavailable_total` | | `onfail-error` 的会话因出口用不了而失败的请求 |
| `kaoju_sessions` | `state` | 当前的会话实例数 |
| `kaoju_upstreams` | `tier`、`state` | 上游数，按层和状态（含 `mitm`、`dead`、`unsupported`） |
| `kaoju_egress_groups` | `stable` | 出口组数 |
| `kaoju_egress_observation_age_seconds` | | 建隧道时所用上游的出口观察有多旧（直方图） |
| `kaoju_probe_connections_total` | `result` | 探测发起的连接 |
| `kaoju_probe_rate_limited_seconds_total` | | 探测因为限速而等待的时间 |
| `kaoju_tunnel_first_byte_seconds` | `tier` | 从转发 ClientHello 到对面第一条记录（直方图） |
| `kaoju_source_candidates` | `source`、`state` | 各来源的候选数 |
| `kaoju_source_rejected_total` | `source`、`reason` | 输入校验拒收的行 |
| `kaoju_source_state` | `source`、`state` | 来源的状态 |
| `kaoju_nodes_unsupported_total` | `reason` | 用不了的节点，按原因（不支持的传输、要求跳过证书校验等） |
| `kaoju_config_reload_total` | `result` | 配置重载 |

标签里不放上游的地址和会话标识（基数会失控，也不该进监控系统）；要查单个上游或会话，用管理 API。
