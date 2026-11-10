# phase1b 分析库：表结构说明

`ingest.py` 把 fieldtest 的原始记录灌进一个 SQLite 库，后面的指标脚本只看这个库和本文件。
本文件写的是：每张表从哪种记录来、每列对应哪个 JSON 字段、时间怎么换算、已知的坑。
记录格式的权威来源是 Go 源码的结构体和 json 标签（`research/fieldtest/internal/…`），
下面每张表都标了对应的结构体；本文件与源码不一致时以源码为准，并请修正本文件。

```sh
python3 ingest.py --data <数据目录> --db <sqlite 路径> [--state <state.json.gz>] [--sources <sources.json>] [--force]
```

- `--data`：`fieldtest pack` 解开后的 `fieldtest/` 目录，或测量机上的原始数据目录，布局相同。
  给的是解包根目录（里面只有 `fieldtest/` 子目录）时自动进入子目录。
- `--state`：候选池的状态文件，默认取数据目录下的 `state.json.gz`，没有就不建 `cands`。
  `fieldtest pack` 不打包它，真实数据里它是单独传来的。
- `--sources`：来源清单（最好是部署时那份 `sources.json`），默认用仓库里的 `research/fieldtest/internal/lists/sources.json`。
  state 里的来源编号 → 来源名**先从快照数据多数票推出**，`--sources` 只用来比对和补缺（见 `cand_src`、`meta.cand_src_names`）；
  数据包里的文件与仓库 HEAD 不一致时以数据为准。
- `--force`：目标库已存在时先删再建。不加则拒绝覆盖并以状态码 2 退出（幂等：二选一里选了“拒绝”，
  免得手滑把花十几分钟建好的库删掉）。
- 进度打到 stderr：每个文件一行（文件名、条数、秒数、已处理字节的百分比）。

**库和原始数据都不进仓库**（公开仓库，含第三方地址）。指标脚本的输出只写到 `research/phase1b/out/`，
并且不许出现：judge 的主机名或公网 IP、单个代理的 ip:port、节点凭据、用户邮箱。
**库里不清洗**：judge 的身份明文散布在很多列里（所有表的 `raw`；`start.raw`；`att` 的 `tls_subj`/`tls_issuer`/`ip`/`*_detail`；
`req` 的 `host`/`sni`/`target`/`remote`/`headers`/`raw_head`；`tls_fail` 的 `sni`/`remote`；`node` 的 `host`/`sni`……
逐列清单见“可输出列白名单”），候选和节点的地址更是到处都是。`self_ips`、`self_names`、`self_leaf` 三张表只是把 judge 的身份
各取一份方便判等。因此**指标脚本输出前按白名单取列，不按黑名单删词**：白名单在 `ingest.OUTPUT_WHITELIST`
（也写进 `meta.output_whitelist`），`ingest.check_output_columns(表, 列)` 在写出前做检查；白名单外的列一律不输出。
`/24` 前缀（`prefix24` 列）可以出现在输出里，单个 ip:port 只能做聚合。

## 通用约定

- **每种记录一张表**，表名就是记录的 `k`。列名与 JSON 字段一致；嵌套对象拍平成 `前缀_字段`
  （`tcp_ok`、`tls_class`、`http_len`、`q_lines` 等）；数组和对象字段存成 JSON 文本（`labels`、`tried`、`ok`、
  `http_flags`、`http_added`、`http_hdr`、`add`、`del`、`members`、`headers`、`pool`、`probe`、`payload_sha256`、`srcs`）。
- 每张记录表都有：`rid`（本表内的行号，整数主键，子表用它关联）、`file_id`（来自哪个文件，见 `files`）、
  `ts`（记录里的时间文本，原样）、`ts_epoch`（UTC 浮点秒）、`raw`（原始 JSON 文本，一行原样）。
  派生列（不是 JSON 字段，由 ingest 算出）在各表里单独标出。
- **缺省字段就是 NULL。** Go 侧多数字段带 `omitempty`：值为 false、0、空串、空数组时 JSON 里根本没有这个字段，
  库里就是 NULL。所以 `visit.full IS NULL` 的意思是 false，`att.tls_self IS NULL` 是 false，`req.age_s IS NULL` 是 0。
  统计时用 `COALESCE(col, 0)`。只有 `cands` 表把这些规范化成了 0/1（它不是记录表）。
- 布尔值存成 0/1。
- 列名是 SQL 保留字的要加双引号：`visit."group"`、`cands."group"`、`agg_sample."union"`。
  `key`、`n`、`ok`、`class`、`state`、`next`、`add`、`del` 在 SQLite 里可以不加引号。
- 子表都带父表的 `xxx_rid`，没有外键约束（载入速度优先）。

### 时间

- 记录里的 `ts` 由 `rec.TS` 生成：UTC，毫秒，固定 24 个字符，形如 `2026-11-05T17:30:04.795Z`。`ts` 列原样保留。
- `ts_epoch` 是 UTC 的浮点秒（Unix 时间），所有表统一，做差、分桶都用它。
- `state.json.gz` 里的时间由 Go 的 `time.Time` 直接序列化：RFC 3339，小数位 0 到 9 位（末尾的零被去掉），
  **带服务器本地时区**（真实数据是 `+08:00`，夹具是 `Z`）。ingest 保留偏移再换算成 UTC；
  `cands` 表为每个时间给三列：`*_raw`（原文）、`*`（换算后的 UTC 文本，保留原有的小数位数，末尾 `Z`）、`*_epoch`。
  看到的偏移记在 `meta.state_tz_offsets`，真实数据应该只有 `+08:00` 一种。
- Go 的零时间 `0001-01-01T00:00:00Z` 换算成 NULL（不过这些字段都带 `omitzero`，一般不会出现）。
- `files.first_ts`/`last_ts` 和 `meta.first_ts`/`last_ts` 是记录 `ts` 的最小最大值（文本比较，同一格式所以可靠）。

### `cand` 字段的三种写法

`att.cand`、`visit.cand` 里的 `cand` 有三种东西，派生列 `att.cand_kind` 区分它们：

| `cand_kind` | 写法 | 说明 |
| --- | --- | --- |
| `proxy` | `ip:port` | 代理候选。派生列 `cand_ip`、`cand_port`、`prefix24`（形如 `192.0.2.0/24`）可用 |
| `node` | 12 位十六进制 | 节点标识（`nodes.Node.ID`，去重键的 SHA-256 前 12 位），`proto='node'`。不是地址，对应 `node.id`。节点的入口地址看 `node.host`/`node.port`，解析出的 IP 看 `npre_ip` |
| `control` | `control:loopback`、`control:public`、`control:observer` | 对照组：探测器不经代理直接访问 judge（回环地址、公网地址）或第二观察者，`proto='direct'`。**`cand` 里没有地址**，连的地址来自配置。judge 的公网 IP 由此取不到，见“judge 的身份从哪里取” |

`visit` 只有代理有，派生列同 `att`。节点没有 `visit` 记录，一个节点一轮里的几次尝试共用一个 `att.visit` 编号。

## 表清单

### 来自 `probe-*.jsonl`（探测器）

#### `att` —— 一次尝试（一条连接）。`probe.Attempt`（`internal/probe/attempt.go`）

| 列 | 来源 | 含义 |
| --- | --- | --- |
| `visit` | `visit` | 探访编号，与 `visit.visit` 对应；对照组和节点也有，但没有 `visit` 记录 |
| `cand` | `cand` | 见上节 |
| `proto` | `proto` | `socks5` / `socks4` / `connect`（HTTP CONNECT）/ `forward`（HTTP 转发）/ `tlsproxy`（只看代理端口说不说 TLS）/ `node` / `direct` |
| `dst` | `dst` | `judge_tls`、`judge_http`、`self`（tlsproxy）、`obs:<观察者名>` |
| `kind` | `kind` | 载荷：`h` HTML、`j` JavaScript、`b` 二进制；访问观察者和 tlsproxy 时为 NULL |
| `arm` | `arm` | 节点探测的分组：`strict`（完整证书校验）/ `as_linked`（照链接要求跳过校验）。只有 `proto='node'` 有 |
| `nonce` | `nonce` | 本次请求的 nonce，用它与 `req.nonce` 对账。没走到 HTTP 阶段的尝试没有 nonce；访问观察者的也没有 |
| `tcp_ok` `tcp_ms` `tcp_class` `tcp_code` `tcp_detail` `tcp_banner` `tcp_sniff` | `tcp.*` | TCP 阶段，`wire.Step`。`class` 是失败类别（`tcp_timeout` 等） |
| `hs_*`（同上七列） | `hs.*` | 握手阶段。`hs_code`：SOCKS 应答码或 CONNECT 的 HTTP 状态码；`hs_detail`：如 `200_with_body`、`Basic realm=...`；`hs_banner`/`hs_sniff`：对方不说这个协议时发来的前几十个字节（十六进制）和猜测的服务。`forward`、`direct`、`tlsproxy` 没有握手阶段 |
| `tls_ok` `tls_ms` `tls_class` `tls_detail` `tls_ver` `tls_cipher` `tls_leaf` `tls_subj` `tls_issuer` `tls_self` `tls_banner` `tls_sniff` | `tls.*` | 隧道里对 judge 的 TLS 握手，`wire.TLSInfo`。`tls_detail` 在 `tls_cert_invalid` 时是 `unknown_authority` / `hostname_mismatch` / `invalid_<n>`（PROTOCOL 第 1.2 版“中间人”细分用），**其他类别时是 Go 错误原文（带代理的 ip:port），整列不可输出，用派生列 `tls_detail_enum`**；`tls_leaf` 是叶子证书 DER 的 SHA-256；`tls_subj`/`tls_issuer` 是 Subject/Issuer 的字符串（最多 120 字符）；`tls_self` 自签。`tlsproxy` 的 `tls_*` 是对代理端口自己的握手，不是隧道 |
| `http_ok` `http_ms` `http_class` `http_code` `http_detail` `http_banner` `http_sniff` | `http.*` | HTTP 阶段，`wire.Step` 部分。`http_code` 是状态码 |
| `http_len` `http_sha` `http_pre` `http_suf` `http_sim` `http_canary` `http_flags` `http_added` `http_hdr` `http_ev` | `http.*` | `probe.HTTPResult`：正文长度；正文哈希（只在不符时记）；与期望正文的公共前缀/后缀长度；相似度百分比（`probe.Similarity`，HTML/JS 按行，二进制按前后缀）；响应头金丝雀 `ok`/`missing`/`bad`；正文无误但响应头被动过的标记（JSON 数组：`gzip_added`、`csp_missing`、`csp_changed`、`cookie_missing`、`cookie_changed`）；judge 没发却出现的响应头名（JSON 数组，最多 12 个）；非 200 或正文不符时记下的几个响应头（JSON 对象）；正文证据的哈希（`evidence/<前两位>/<哈希>.body`） |
| `class` | `class` | `ok`，或第一个失败阶段的类别；`canceled` 见“坑” |
| `ip` | `ip` | 出口地址：judge 在响应头 `X-Judge-Remote` 里回显的对端地址，或第二观察者报告的。**只用来和 judge 日志互相核对**，出口地址以 `req.remote` 为准（PROTOCOL） |
| `ev` | `ev` | 证书链证据的哈希（`evidence/<前两位>/<哈希>.der`，DER 串接）；只在 TLS 校验失败时有。注意与 `http_ev`（正文证据）不同 |
| `ms` | `ms` | 整次尝试的毫秒数，不含排队等连接配额的时间 |
| `cand_kind` `cand_ip` `cand_port` `prefix24` | 派生 | 见上节 |
| `tls_detail_enum` | 派生 | `tls_detail` 里可输出的枚举部分（`ingest.tls_detail_enum()`）：`tls_class='tls_cert_invalid'` 且 `tls_detail` 是 `unknown_authority` / `hostname_mismatch` / `invalid_<n>` 时取原值；`tls_cert_invalid` 但不是这三种（x509 的其他错误类型，`tls_detail` 仍是错误原文）记 `other`；其他类别 NULL（失败原因已在 `tls_class` 里）。“中间人”细分按这一列分组 |

子表：

- `att_http_flag(rid, att_rid, flag)`：`http.flags` 拆成一行一个。
- `att_http_added(rid, att_rid, header)`：`http.added` 拆成一行一个。

#### `visit` —— 一次探访的小结。`probe.VisitRec`（`prober.go`）

| 列 | 来源 | 含义 |
| --- | --- | --- |
| `visit` | `visit` | 探访编号 |
| `cand` | `cand` | 代理 `ip:port` |
| `"group"` | `group` | 0 常规列表（JSON 里省略 → NULL），1 聚合器抽样 |
| `n` | `n` | 这个候选的第几次探访（累计，跨重启；状态文件被清空才归零） |
| `prev` `state` | `prev` `state` | 探访前后的状态：`new` / `working` / `open` / `dead` |
| `full` | `full` | 是否做了完整的协议识别（四种协议都试） |
| `listed` | `listed` | 探访开始时是否还在榜上（没有 omitempty，总有值） |
| `labels` | `labels` | 列表给的协议标签，JSON 数组 |
| `tried` | `tried` | 试过的协议，JSON 数组，按顺序 |
| `ok` | `ok` | 通过端到端校验的协议，JSON 数组 |
| `auth` | `auth` | 遇到要求认证（`hs_auth` 或 407） |
| `aborted` | `aborted` | 程序正在退出，这次探访的结果不作数（`state` 等于 `prev`）；汇总程序会跳过它们 |
| `next_min` | `next_min` | 到下次探访的分钟数；0 表示不再探访（下榜超过 24 小时） |
| `ms` | `ms` | 探访耗时 |
| `cand_ip` `cand_port` `prefix24` `n_ok` | 派生 | 地址拆分；`ok` 数组的长度（NULL 的 ok 记 0） |

子表：

- `visit_ok(rid, visit_rid, visit, cand, ts, ts_epoch, proto)`：`ok` 数组拆成一行一个协议——“协议通过”子表。
- `visit_tried(rid, visit_rid, visit, cand, seq, proto)`：`tried` 数组，`seq` 是顺序。

#### `npre` —— 节点预检。`probe.NPreRec`（`nodes.go`）

| 列 | 来源 | 含义 |
| --- | --- | --- |
| `round` `node` | 同名 | 轮次；节点标识 |
| `dns_ok` `dns_ms` `dns_class` …（Step 七列） | `dns.*` | 节点主机名的 DNS 解析；主机本来就是 IP 时没有这个对象（全 NULL） |
| `ips` | `ips` | 解析出的 IPv4，JSON 数组，最多 4 个；主机是 IP 时就是它自己 |
| `tcp_*`（Step 七列） | `tcp.*` | 对节点地址的 TCP 预检。**没有 `tcp` 对象的记录没有发起连接**（见“坑”） |
| `class` | `class` | `ok`、`dns_nxdomain`、`dns_timeout`、`dns_other`、`skip_ipv6`、`skip_not_public`、`canceled`、`tcp_*` |
| `n_ips` | 派生 | `ips` 的长度 |

子表 `npre_ip(rid, npre_rid, node, round, seq, ip)`：`ips` 拆开。节点“出口地址是否与入口相同”的判断用它（`summary.go` 的 `nodeEgress`）。

#### `nerr` —— sing-box 日志里与某节点有关的最后一条错误。`probe.NErrRec`

`round`、`node`、`arm`、`msg`（最多 240 字符；`config: ` 开头的是配置被 sing-box 拒绝）。

#### `nround` —— 一轮节点探测的小结。`probe.NRoundRec`

`round`、`known`（见过的节点）、`listed`（在榜）、`supported`（sing-box 能连）、`backoff`（因连续不可用跳过）、
`tcp_ok`（预检连得上）、`probed`、`ok_strict`、`ok_linked`（只有照链接跳过校验才可用）、`bad_config`、`batches`、`ms`、`err`。

#### `stat` —— 运行状况，每 5 分钟一条。`probe.StatRec`

`up_min`、`visits`（累计探访数）、`records`（本进程写的记录数）、`pool`（JSON：各状态候选数、`listed`、`aggregator_sample`、`dropped`、`skipped_<原因>`）。
子表 `stat_pool(rid, stat_rid, ts, ts_epoch, key, value)` 把 `pool` 拆开，画时间序列用。

#### `start` / `stop` / `version` / `error` —— 运行事件（`prober.Run`、`attempt.go` 的 `Panic`、`nodes.go`）

- `start`：`resumed_candidates`（从状态文件恢复的候选数，0 表示状态被清空或首次启动）、`load_err`、`http_port`、`https_port`、
  `probe`（JSON，探测器配置 `cfg.Probe`）、`payload_sha256`（JSON，三种载荷的期望哈希。**不可输出**：h 载荷的正文是公开模板
  `htmlTemplate` 填入 judge 主机名（`internal/payload/payload.go` `Build()`），拿到哈希的人把猜测的主机名填进模板算一次 sha256 就能验证猜测；
  核对载荷一致性只输出 `COUNT(DISTINCT payload_sha256)`）、
  **`judge_host_sha8`、`judge_ip_sha8`**（派生：`judge_host`、`judge_ip` 的 sha256 前 8 位，只用来看多条 `start` 的值是否相同；
  明文在 `raw` 和 `self_*` 表里。sha256 前 8 位对 IPv4 可穷举还原、对主机名可查字典，**同样不可输出**）。
  正式测量的起点以第一条 `start` 为准（PROTOCOL“正式测量的起止”）；多条 `start` 说明重启过，`stop` 与下一条 `start` 之间是中断时段。
- `stop`：`visits`。
- `version`：`version`（探测器版本字符串，这次实测的是 `0.1.1-…`）。
- `error`：`what`、`err`、`stack`（程序错误的调用栈，最多 3000 字符）。

### 来自 `judge-*.jsonl`（见证方）

五种记录共用 `judge.Rec`（`internal/judge/judge.go`），所以五张表列相同：

| 列 | 含义 |
| --- | --- |
| `remote` `rport` | judge 看到的对端地址和端口。**出口地址以这里为准** |
| `tls` `tls_ver` `cipher` `sni` `alpn` `hello_fp` | 是否经 TLS 端口；协商的版本和密码套件；ClientHello 里的 SNI；ALPN；ClientHello 指纹（去掉 GREASE 后的哈希前 8 字节）。直连时的指纹是基线：经隧道到达而指纹不同，说明 TLS 是代理自己发起的 |
| `method` `target` `proto` `host` | 请求行里的方法、原始 request-target（经转发代理到达时可能仍是绝对 URI）、HTTP 版本、Host 头 |
| `nonce` `age_s` `kind` | nonce；收到时 nonce 已签发多少秒（0 省略 → NULL）；载荷种类 |
| `req_canary` | 请求头 `X-Probe-Canary` 的核对：`ok` / `missing` / `bad` |
| `headers` | 收到的全部请求头，JSON 数组 `[[名, 值], …]`，按名排序，最多 60 条，值最多 512 字符 |
| `raw_head` | 这条连接上读到的原始字节（明文；TLS 连接是解密后的），base64，最多 2048 字节 |
| `status` | judge 回的状态码 |
| `err` | `tls_fail` 的握手错误 |
| `n` | `noise_dropped` / `req_dropped` 的丢弃条数 |

- `req`：带有效 nonce 的探测请求。子表 **`req_header(rid, req_rid, nonce, seq, name, value)`** 把 `headers` 拆开，
  匿名程度和“请求头被改”的判断用它（照 `summary/derive.go` 的 `Derive`：探测器自己发的头是 User-Agent、Accept、
  Accept-Language、Accept-Encoding、Connection、Cookie、X-Probe-Canary、Host；多出来的都是代理加的；
  值里含探测器自己的地址算透明，只多了 Via/X-Forwarded-For 之类算匿名，都没有算高匿）。
  `host`、`sni`、`target`、`remote`、`headers`、`raw_head`（base64，解码后含 Host 头和 X-Forwarded-For 之类）都含 judge 或探测器的地址，
  `req_header.value` 同理；它们都不在可输出列白名单里。
- `noise`：无关流量（扫描、浏览器、错误路径），每秒最多记 20 条。
- `tls_fail`：TLS 握手失败的连接（含探测器自己的 `tls_eof` 等）。
- `noise_dropped` / `req_dropped`：限速丢弃计数，每分钟一条，`n` 是丢弃数。`req` 每秒最多记 300 条。

### 来自 `snap-*.jsonl`（快照采集器）

#### `snap` —— 一次列表文件抓取。`lists.SnapRec`（`internal/lists/lists.go`）

`src`（来源名）、`label`（文件的协议标签：http/https/connect/socks4/socks5）、`status`（HTTP 状态；304 是没变）、`err`、`etag`、
`sha256`、`bytes`、`n`（有效条目数）、`q_lines` `q_garbage` `q_hostname` `q_no_port` `q_bad_range` `q_duplicate` `q_with_credentials`
（`lists.Quality`，解析质量）、`base`（第一次抓到：`add` 是全部条目）、`agg`（聚合器：只记数量，不记条目）、
`add` `del`（JSON 数组）、`ms`、`changed`（内容有变化才解析）。派生 `n_add`、`n_del`。

子表 **`list_event(rid, snap_rid, ts, ts_epoch, src, label, cand, event, base, cand_ip, cand_port, prefix24)`**：
上榜/下榜事件表，`event` 是 `add` 或 `del`，`base=1` 表示这是该文件的首次快照（探测器每次启动都会重新来一遍首次快照，
所以 `base=1` 的 add **不是真正的新上榜**；真正的新上榜是 `base=0` 的 add）。聚合器文件没有事件。

#### `agg_sample` —— 聚合器抽样，每个聚合器只做一次。`probe.AggSampleRec`

`src`、`"union"`（各文件合并后的条目数）、`exclusive`（不在任何常规列表里的）、`sample`、`seed`、`members`（JSON）。
子表 **`agg_member(rid, agg_sample_rid, ts, ts_epoch, src, seq, cand, cand_ip, cand_port, prefix24)`**。
抽样条目之后是否还在榜，看 `cands.srcs` / `cands.delisted_at`，快照里不逐条记。

#### `nsnap` —— 一次订阅抓取。`probe.NSnapRec`

`src`、`status`、`err`、`sha256`、`bytes`、`lines`、`unparsed`、`n`、`base`、`changed`、`add` `del`（节点标识的 JSON 数组）、`ms`。
派生 `n_add`、`n_del`。子表 **`node_event(rid, nsnap_rid, ts, ts_epoch, src, node, event, base)`**。

#### `node` —— 第一次见到一个节点时写一条。`probe.NodeRec` + `nodes.Node`（`internal/nodes/link.go`）

`src`、`id`、`scheme`（ss/vmess/vless/trojan）、`host`、`port`、`method`（ss 加密）、`aid`、`flow`、`net`（传输：tcp/ws/grpc/http/h2/httpupgrade/xhttp…）、
`hdr`、`sec`（none/tls/reality）、`sni`、`insecure`（链接要求跳过证书校验）、`plugin`、`why`（sing-box 连不了的原因，如 `transport_xhttp`；NULL 表示可探测）。
**不含凭据**（Go 侧 `json:"-"`）。探测器重启后会把还在榜的节点再记一遍，同一个 `id` 可能有多行，按 `id` 去重（`summary.go` 也是这样）。

### 来自 `state.json.gz`（候选池状态）

#### `cands` —— 每个候选一行。`probe.Cand`（`internal/probe/sched.go`）

| 列 | 来源 | 含义 |
| --- | --- | --- |
| `key` `ip` `port` `prefix24` | `key` + 拆分 | 代理地址 |
| `"group"` | `group` | 0 常规列表，1 聚合器抽样（后来也出现在常规列表里的会被改成 0） |
| `srcs` `n_srcs` `listed` | `srcs` | 保存时还列着它的来源：JSON 对象 `{"来源编号": 标签位}`；来源数；是否还在榜（`n_srcs>0`） |
| `labels` `label_names` | `labels` | 历史上出现过的全部标签位，和解码后的名字（JSON 数组）。位：http=1 https=2 connect=4 socks4=8 socks5=16（`lists.go`） |
| `ts` `ts_epoch` | = `first_seen` | 为了与其他表统一 |
| `first_seen_raw` `first_seen` `first_seen_epoch` | `first_seen` | 第一次出现在快照里（原文 / UTC / 浮点秒） |
| `delisted_at_*` | `delisted_at` | 从所有来源消失的时刻；在榜时 NULL |
| `next_*` | `next` | 下次探访时刻（保存时的计划） |
| `visits` `fails` | 同名 | 探访次数；连续连不上的次数 |
| `state` `state_name` | `state` | 0 new / 1 working / 2 open / 3 dead |
| `ok_mask` `ok_protos` | `ok_mask` | 上次探访通过校验的协议位和名字。位：socks5=1 socks4=2 connect=4 forward=8（`sched.go` `protoBits`） |
| `ever_ok` | `ever_ok` | 曾经可用 |
| `last_ok_*` `last_full_*` `last_extra_*` | 同名 | 最后一次可用、最后一次完整识别、最后一次附加测试 |
| `raw` | 整条 | 原始 JSON |

状态文件每 5 分钟保存一次、停止时再保存一次，所以它是**结束时刻的快照**，不是历史。
历史（每次探访的状态变化）在 `visit` 表里。`Pool.Load` 的细节：重启时 `srcs` 清空、在榜候选先当作刚下榜，
由第一次快照重建，所以 `delisted_at` 可能是重启时刻——只在它与 `list_event` 的 `del` 对不上时需要留意。

子表 **`cand_src(rid, key, src_idx, src_name, labels, label_names)`**：`srcs` 拆开。`src_idx` 是来源在**部署时那份** sources.json 里的下标
（`prober.go` `NewProber`：`snapFile.src = uint8(i)`，`i` 是 `src.Lists` 的下标；快照记录的 `src` 字段是同一个 `l.Name`）。
数据包里的 sources.json 未必等于仓库 HEAD 的那份（夹具就不是：来源叫 `local/regular`、`local/aggregator`），所以
`src_name` **不按 `--sources` 抄，而由 `ingest.resolve_src_names` 从数据推**：持有编号 `i` 的候选，其上榜事件（`list_event`，`event='add'`，
含 `base=1` 的首次快照——重启后 `srcs` 正是由它重建）或聚合器抽样（`agg_member`）出现在哪个来源名下，按候选数投票，最高票就是编号 `i` 的名字
（真实来源的票数应等于持有者数；只有“该来源是另一来源的子集”时才可能打平，打平或没有事件判为未定）。
然后与 `--sources` 比对：推出的编号全部一致才信任 `--sources`，用它补未定的编号；不一致则以数据为准、未定的留 NULL。
推导过程记在 `meta.cand_src_names`，最终名字再用快照记录逐条核对记在 `meta.cand_src_check`（`matched_by_snapshot` 应等于 `checked`）。

### 元数据

- **`files`**：数据目录里每个文件一行。`name`、`prefix`（probe/judge/snap）、`hour`（`YYYYMMDD-HH`）、`compressed`、`bytes`、
  `status`、`records`（读到的记录数；重复文件是它的行数）、`bad_lines`、`first_ts`、`last_ts`、`note`。
  `status`：`read` 已读入；`duplicate_skipped` 同一小时另有一份已读，这份跳过；`skipped_tmp` 压缩中途的临时文件；
  `skipped_sensitive` 不读（`secret`、`judge-key.pem`、`local/`、`sidecar/`）；`not_ingested` 已知但不入库的文件
  （`summary.json`、`preflight.txt`、`judge-cert.pem`、`state.json.gz` 等）；`ignored`/`ignored_dir` 不认识的东西。
- **`file_kind(file_id, k, n)`**：每个文件里各种 `k` 的条数。与 `summary.json` 的 `records` 一节逐项比对用。
- **`meta(key, value)`**：全是文本。主要键：

  | 键 | 含义 |
  | --- | --- |
  | `data_dir` `ingested_at_utc` `ingest_version` `python` `sqlite` `ingest_seconds` | 入库环境 |
  | `files_read` `records_total` `records_by_kind`（JSON） | 读了多少 |
  | `first_ts` `last_ts` | 全部记录的时间范围 |
  | `duplicate_hour_files`（JSON） | 同一小时两份的情况：跳过的文件名、它的行数、读入那份的记录数（两者应相等） |
  | `unknown_fields`（JSON） | 记录里出现、本脚本没列进表的字段及次数。非空说明记录格式变了，字段只在 `raw` 里 |
  | `misplaced_kinds`（JSON） | 出现在不该出现的文件里的记录种类 |
  | `judge_host_sha8` `judge_ip_sha8`（JSON 数组） | judge 身份的 sha256 前 8 位（`hashlib.sha256(s.encode()).hexdigest()[:8]`）。多于一个值说明中途改过配置。**不可输出**（可穷举） |
  | `judge_leaf_observed`（JSON 数组） | judge 的叶子证书，**从数据推导**：对照组直连 `judge_tls` 且 `class='ok'` 的尝试里 `DISTINCT tls_leaf`，每个带次数和首末时间。应恰好 1 个；多于 1 个说明中途换过证书（公开证书续期），按时间段分开用。**哈希不可输出**（见白名单规则） |
  | `judge_leaf_observed_count` | 上面的个数，可输出，应为 1 |
  | `judge_leaf_pem_sha256` `judge_leaf_pem_present` `judge_leaf_pem_matches_observed` | 数据目录里 `judge-cert.pem` 第一张证书 DER 的 SHA-256（不可输出）；有没有这个文件；它是否等于观测到的叶子之一（0/1，没有文件或没有观测值时 NULL）。这张文件只在配置 `judge.cert_file` 为空时才是 judge 实际用的证书（`judge.go` 的 `EnsureCert`、`LoadTrust`），配置了公开证书时可能是旧的自签证书或根本没打包，所以不以它为准 |
  | `judge_leaf_tls_ok_extra` `judge_leaf_tls_ok_extra_count` | 交叉核对：所有对 `judge_tls` 的尝试（经代理、节点、对照组，不含 `tlsproxy`）里 TLS 校验通过（`tls_ok=1`，含 SPKI 锁定）却不在 `judge_leaf_observed` 里的叶子。应为空；不为空说明换证书的时刻没有对照组尝试覆盖 |
  | `output_whitelist` `output_rules`（JSON） | 可输出列白名单和附加规则，与 `ingest.OUTPUT_WHITELIST`/`OUTPUT_RULES` 相同，供不导入 ingest 的脚本从库里读 |
  | `payload_len`（JSON） | 各载荷的期望长度（`BodyChange` 需要）：成功到达 judge、响应头没有标记的尝试里最常见的 `http_len`；`distinct_lens` 应为 1 |
  | `state_file` `state_cands` `state_tz_offsets` `state_sampled` `state_mtime_utc` | 状态文件的信息 |
  | `sources_file` `sources_sha256` `sources_names` | `--sources` 文件的路径（不可输出）、哈希和其中的来源名顺序 |
  | `cand_src_names`（JSON） | 来源编号 → 来源名的推导结果（`resolve_src_names`）：`sources_trusted`（0/1）、`mismatch`（数据与 `--sources` 不一致的编号）、`unresolved`（留 NULL 的编号），`by_idx` 里每个编号的 `holders`（持有它的候选数）、`votes`（各来源名的票数）、`top_share`（最高票 / holders，应为 1.0）、`data_name`、`why_unresolved`（`tie` / `no_snapshot_events`）、`cfg_name`（`--sources` 给的名字）、`agrees_with_sources`、`name`（最终）、`by`（`data` / `sources`）。只含来源名和计数，可输出 |
  | `cand_src_check`（JSON） | 最终名字与快照记录逐条核对：`checked`（有名字的候选-来源对）、`matched_by_snapshot`（在 `list_event` 的 add 或 `agg_member` 里找到同名来源的）；两者应相等 |
  | `evidence_files` `evidence_bytes` | 证据库规模 |
  | `summary_json`（JSON） | 自带汇总的 `generated`、`first_record`、`last_record`、`records`、`judge`，交叉核对用 |

- **`evidence(hash, ext, bytes, path)`**：`evidence/` 下的文件清单。`ext` 是 `body`（被改的正文）或 `der`（证书链，DER 串接）。
  `att.ev`、`att.http_ev` 里的哈希在这里找不到的，说明证据库超限没存（每个来源最多 12 份，总共 1 GB），只能用 `tls_subj` 判名字。
- **`misc(rid, file_id, k, ts, ts_epoch, raw)`**：`k` 不认识的记录。应为空。
- **`bad_line(rid, file_id, lineno, why, raw)`**：解析不了的行。应为空；文件末尾没写完的一行会落在这里。
- **`self_ips(ip, source, n)`、`self_names(name, source, n)`、`self_leaf(leaf, source, n, first_ts, last_ts)`**：judge 的身份
  （公网 IP、主机名、叶子证书 SHA-256），见下节。**不许输出。**

## judge 的身份从哪里取

指标脚本要用 judge 的公网 IP 做两种判等：请求头里是否带出了探测器的地址（探测器与 judge 同机，所以探测器的出口地址就是 judge 的公网 IP）、
出口地址是否与入口相同（节点探测的流量不能从本机直接出去）；还要用 judge 的主机名判断“冒充 judge”（`tls_subj` 的 CN、证书 SAN）。
候选来源比较：

| 来源 | 可靠性 |
| --- | --- |
| `probe-` 里 `start` 记录的 `judge_ip`、`judge_host` | **选它。** 这是探测器实际使用的配置值：SOCKS4 握手把这个 IP 交给代理，`control:public` 连的就是它，判断“自己的地址不探测”也用它；`summary.go` 的 `selfIPs` 也只用 `c.Judge.PublicIP`。每次启动写一条，中途改配置会留下不同的值 |
| `judge-` 里 `req.host`、`req.sni` | 是主机名不是 IP（配置里 `host` 也可以写成 IP，但真实数据写的是域名）。取对照组请求的 Host/SNI 作为主机名的第二来源 |
| `att` 里 `control:public` 的 `cand` | `cand` 字段只是字符串 `control:public`，**不含地址**。它的 `ip` 列是 judge 回显的对端地址：探测器连自己的公网地址时 judge 看到的源地址。云主机做 NAT 时这可能是内网地址而不是公网 IP，所以只作参考 |
| `summary.json` | 没有专门的字段，但 `findings.*.examples` 的自由文本里有候选 `ip:port` 和中间人证书的 issuer/subject（夹具里 CN 就是夹具 judge 的主机名）；`meta.summary_json` 只抄 `generated`、`first_record`、`last_record`、`records`、`judge`（后者只是计数） |
| `preflight.txt` | 中文散文里有（“公网地址 x.x.x.x”），格式不保证，且是预检时刻的值 |

因此 `self_ips` 的行按 `source` 区分：`start.judge_ip`（推荐）、`judge_remote:control:loopback`、`judge_remote:control:public`
（judge 日志里对照请求的对端地址）、`echo:control:*`（响应头回显）。`self_names`：`start.judge_host`（推荐）、
`judge_host_header:control`、`judge_sni:control`。指标脚本按 `summary.go` 的口径只用 `start.*`，其他行用来发现异常
（例如 `judge_remote:control:public` 不等于 `start.judge_ip`，就说明本机访问公网地址经过了 NAT）。

judge 的**叶子证书**在 `self_leaf`，按 `source` 区分：`control_ok`（**定义**：对照组直连 `judge_tls`、`class='ok'` 的尝试看到的 `tls_leaf`，
应恰好一行）、`tls_ok_any`（所有对 `judge_tls` 的尝试里 `tls_ok=1` 的叶子，不含 `tlsproxy`；交叉核对，应与 `control_ok` 同一集合）、
`pem`（数据目录里 `judge-cert.pem` 的哈希；只在 judge 用自签证书时才一定是实际用的那张）。
“隧道里的证书是不是 judge 的”用 `att.tls_leaf IN (SELECT leaf FROM self_leaf WHERE source = 'control_ok')` 判断；
换过证书时按 `first_ts`/`last_ts` 分时间段。叶子哈希本身不输出：公开证书的 SHA-256 指纹可以在 CT 日志（crt.sh）里查到证书，
从而得到 judge 主机名；真实部署用的是不是公开证书未验证，代码两种都允许（`internal/cfg` 的 `judge.cert_file`）。

## 可输出列白名单

写进 `research/phase1b/out/` 的每个数字和每个维度值都只能来自下面的列。**权威版本是 `ingest.OUTPUT_WHITELIST`
（入库时也写进 `meta.output_whitelist`）**，下表由它生成（`python3 -c 'import ingest; …'`，改了常量就重新生成），不要手改。
指标脚本在写出任何表格之前调用 `ingest.check_output_columns(表, 列)`，列不在白名单里就抛错。
不在白名单里的列就是不可输出；要放开一列，先在这里写明理由，再改常量。

原则：**枚举值**（`class`、`*_class`、`*_sniff`、`proto`、`dst`、`state`、`event`、`label`、`src` 等）、**计数与聚合值**、
**毫秒数**、**时间（分桶后）**、**`/24` 前缀**、**来源名**、**头名（不含值）** 可以输出；
**地址、主机名、哈希、自由文本（Go 错误原文、banner、日志）、原始 JSON** 一律不行。

| 表 | 可输出列 |
| --- | --- |
| `att` | `proto` `dst` `kind` `arm` `tcp_ok` `tcp_ms` `tcp_class` `tcp_code` `tcp_sniff` `hs_ok` `hs_ms` `hs_class` `hs_code` `hs_sniff` `tls_ok` `tls_ms` `tls_class` `tls_detail_enum` `tls_ver` `tls_cipher` `tls_self` `tls_sniff` `http_ok` `http_ms` `http_class` `http_code` `http_sniff` `http_len` `http_pre` `http_suf` `http_sim` `http_canary` `http_flags` `class` `ms` `cand_kind` `cand_port` `prefix24` `ts` `ts_epoch` |
| `att_http_flag` | `flag` |
| `att_http_added` | `header` |
| `visit` | `group` `n` `prev` `state` `full` `listed` `labels` `tried` `ok` `auth` `aborted` `next_min` `ms` `n_ok` `cand_port` `prefix24` `ts` `ts_epoch` |
| `visit_ok` | `proto` `ts` `ts_epoch` |
| `visit_tried` | `seq` `proto` |
| `npre` | `round` `node` `dns_ok` `dns_ms` `dns_class` `dns_code` `dns_sniff` `tcp_ok` `tcp_ms` `tcp_class` `tcp_code` `tcp_sniff` `class` `n_ips` `ts` `ts_epoch` |
| `npre_ip` | `round` `node` `seq` |
| `nerr` | `round` `node` `arm` `ts` `ts_epoch` |
| `nround` | `round` `known` `listed` `supported` `backoff` `tcp_ok` `probed` `ok_strict` `ok_linked` `bad_config` `batches` `ms` `ts` `ts_epoch` |
| `stat` | `up_min` `visits` `records` `pool` `ts` `ts_epoch` |
| `stat_pool` | `key` `value` `ts` `ts_epoch` |
| `start` | `resumed_candidates` `ts` `ts_epoch` |
| `stop` | `visits` `ts` `ts_epoch` |
| `version` | `version` `ts` `ts_epoch` |
| `error` | `what` `ts` `ts_epoch` |
| `req` | `tls` `tls_ver` `cipher` `alpn` `hello_fp` `method` `proto` `kind` `age_s` `req_canary` `status` `ts` `ts_epoch` |
| `req_header` | `seq` `name` |
| `noise` | `tls` `tls_ver` `cipher` `alpn` `hello_fp` `method` `proto` `status` `ts` `ts_epoch` |
| `tls_fail` | `tls` `tls_ver` `cipher` `alpn` `hello_fp` `ts` `ts_epoch` |
| `noise_dropped` | `n` `ts` `ts_epoch` |
| `req_dropped` | `n` `ts` `ts_epoch` |
| `snap` | `src` `label` `status` `bytes` `n` `q_lines` `q_garbage` `q_hostname` `q_no_port` `q_bad_range` `q_duplicate` `q_with_credentials` `base` `agg` `ms` `changed` `n_add` `n_del` `ts` `ts_epoch` |
| `list_event` | `src` `label` `event` `base` `cand_port` `prefix24` `ts` `ts_epoch` |
| `agg_sample` | `src` `union` `exclusive` `sample` `seed` `ts` `ts_epoch` |
| `agg_member` | `src` `seq` `cand_port` `prefix24` `ts` `ts_epoch` |
| `nsnap` | `src` `status` `bytes` `lines` `unparsed` `n` `base` `changed` `ms` `n_add` `n_del` `ts` `ts_epoch` |
| `node_event` | `src` `node` `event` `base` `ts` `ts_epoch` |
| `node` | `src` `id` `scheme` `method` `aid` `flow` `net` `sec` `insecure` `why` `ts` `ts_epoch` |
| `cands` | `prefix24` `port` `group` `n_srcs` `listed` `labels` `label_names` `visits` `fails` `state` `state_name` `ok_mask` `ok_protos` `ever_ok` `first_seen` `first_seen_epoch` `delisted_at` `delisted_at_epoch` `next` `next_epoch` `last_ok` `last_ok_epoch` `last_full` `last_full_epoch` `last_extra` `last_extra_epoch` `ts` `ts_epoch` |
| `cand_src` | `src_idx` `src_name` `labels` `label_names` |
| `files` | `name` `prefix` `hour` `compressed` `bytes` `status` `records` `bad_lines` `first_ts` `last_ts` `note` |
| `file_kind` | `file_id` `k` `n` |
| `evidence` | `ext` `bytes` |
| `misc` | `k` `ts` `ts_epoch` |
| `bad_line` | `lineno` `why` |
| `meta` | `ingest_version` `ingested_at_utc` `python` `sqlite` `ingest_seconds` `files_read` `records_total` `records_by_kind` `first_ts` `last_ts` `duplicate_hour_files` `unknown_fields` `misplaced_kinds` `judge_leaf_observed_count` `judge_leaf_pem_present` `judge_leaf_pem_matches_observed` `judge_leaf_tls_ok_extra_count` `payload_len` `state_cands` `state_tz_offsets` `state_sampled` `state_mtime_utc` `sources_sha256` `sources_names` `cand_src_names` `cand_src_check` `evidence_files` `evidence_bytes` `summary_json` `output_whitelist` `output_rules` |
| `self_ips` | （无） |
| `self_names` | （无） |
| `self_leaf` | （无） |

附加规则（`ingest.OUTPUT_RULES`）：

- **att.tls_detail**：整列不输出：tls_class 不是 tls_cert_invalid 时它是 Go 错误原文，带代理的 ip:port。用派生列 tls_detail_enum（tls_cert_invalid 时的 unknown_authority / hostname_mismatch / invalid_<n>，其他 tls_cert_invalid 归并成 other，别的类别 NULL；wire.go TLS()）
- **start.payload_sha256**：载荷哈希不输出：h 载荷是公开模板填入 judge 主机名后的正文（payload.go Build()），哈希可用来验证对主机名的猜测；核对载荷一致性只输出 COUNT(DISTINCT payload_sha256)
- ***.cand_port / cands.port**：只能单独作为维度（端口分布），不能与 prefix24 或任何别的地址信息同行出现
- **att.tls_leaf / meta.judge_leaf_***：叶子证书哈希不输出（公开证书的指纹可在 CT 日志查到主机名）；只输出“等于 judge 叶子”的计数，判等用 self_leaf 表
- **att.ev / att.http_ev / att.http_sha**：证据哈希不输出，只输出 COUNT(DISTINCT …)
- **start.probe**：整列不输出（exclude_file 是本机路径）；需要的数值字段用 json_extract 单独取
- **att.dst**：obs:<名> 里的名字是配置里的观察者名，输出前核对它不是主机名
- **时间列**：ts / *_epoch 只在分桶（小时、分钟）或做差之后输出，不输出逐行时间
- **行**：输出的永远是聚合结果，不是行；每个数字都要带分子、分母和口径说明

**不可输出列的逐表清单**（夹具库上用夹具 judge 的主机名和回环地址逐列扫过，带 ✱ 的是实际扫到 judge 身份明文的列）：

- 所有表：`raw` ✱、`rid`、`file_id`、各种 `*_rid`（内部编号，输出没有意义）。
- `att`：`visit`、`cand`、`nonce`、`tcp_detail`、`tcp_banner`、`hs_detail` ✱、`hs_banner`、`tls_detail`（整列；枚举部分见派生列 `tls_detail_enum`）、`tls_leaf`、
  `tls_subj` ✱、`tls_issuer` ✱、`tls_banner`、`http_detail` ✱、`http_banner`、`http_sha`、`http_added`（用子表的头名）、`http_hdr`、
  `http_ev`、`ip` ✱、`ev`、`cand_ip`。`*_detail` 是 `wire.go` `short(err)` 的 Go 错误原文（`read tcp4 本机:端口->代理:端口: i/o timeout`），
  `hs_detail` 还可能是对方的 `Proxy-Authenticate`/`Server` 头；`tls_subj`/`tls_issuer` 来自 `wire.go` `TLS()` 的 `describe()`。
- `visit`：`visit`、`cand`、`cand_ip`。`visit_ok`/`visit_tried`：`visit`、`cand`。
- `npre`：`ips`、`dns_detail`、`dns_banner`、`tcp_detail` ✱、`tcp_banner`。`npre_ip`：`ip` ✱。
- `nerr`：`msg`（sing-box 日志原文）。`nround`：`err`。`error`：`err`、`stack`。
- `start`：`judge_host_sha8`、`judge_ip_sha8`（可穷举）、`payload_sha256`（h 载荷是公开模板填入 judge 主机名，哈希可验证对主机名的猜测）、
  `load_err`、`http_port`、`https_port`、`probe`（含 `exclude_file` 路径）。
- `req`/`noise`/`tls_fail`/`*_dropped`：`remote` ✱、`rport`、`sni` ✱、`target`、`host` ✱、`nonce`、`headers` ✱、`raw_head` ✱（base64）、`err`。
  `req_header`：`value` ✱（`X-Forwarded-For`、`Via` 等带地址）、`nonce`。
- `snap`：`err`、`etag`、`sha256`、`add`、`del`。`list_event`/`agg_member`：`cand`、`cand_ip`。`agg_sample`：`members`。
  `nsnap`：`err`、`sha256`、`add`、`del`。
- `node`：`host` ✱、`port`、`hdr`、`sni` ✱、`plugin`。
- `cands`：`key`、`ip`、`srcs`、所有 `*_raw`。`cand_src`：`key`。
- `evidence`：`hash`、`path`。`misc`/`bad_line`：`raw`。`meta`：`data_dir`、`state_file`、`sources_file`（本机路径）、
  `judge_host_sha8`、`judge_ip_sha8`、`judge_leaf_observed`、`judge_leaf_pem_sha256`、`judge_leaf_tls_ok_extra`。
- `self_ips` ✱、`self_names` ✱、`self_leaf`：整表。

## 已知的坑

1. **时区。** 记录的 `ts` 全是 UTC（`Z`）；`state.json.gz` 带本地时区（真实数据 `+08:00`），已换算，`*_raw` 列保留原文。
   不要拿 `cands.first_seen_raw` 和 `ts` 直接比较文本。
2. **同一小时两份文件。** 探测器把过去的小时压成 `.gz`，当前小时是 `.jsonl`；两者并存说明压缩刚完成、原文件还没删，内容相同。
   ingest 只读 `.jsonl` 那份（与 `rec.Files` 一致），`.gz` 记为 `duplicate_skipped` 并数行数；`meta.duplicate_hour_files` 里两边的数应相等。
   `.gz.tmp` 是压缩中途的半成品，不读。
3. **`att.cand` 在 `proto='node'` 时是节点标识，不是 ip:port**；`control:*` 时不含地址。用 `cand_kind` 过滤，代理的比例分母只算 `cand_kind='proxy'`。
4. **`class='canceled'` 的 att 没有发起连接**：它在排队等连接配额时程序开始退出。`tcp`、`hs`、`tls`、`http` 全 NULL，`ms` 为 0，
   `ts` 是放弃排队的时刻。汇总程序把含 `canceled` 的 class 全部跳过，指标脚本也应如此。
5. **`npre` 没有 `tcp` 对象的记录没有发起连接**：DNS 失败（`dns_*`）、`skip_ipv6`、`skip_not_public`、`canceled`。
   “预检连得上”的分母应是 `tcp_ok IS NOT NULL` 的记录。
6. **omitempty → NULL。** 见“通用约定”。尤其 `visit."group"`（NULL 即常规列表）、`visit.full`、`visit.auth`、`visit.aborted`、`snap.base`、`snap.changed`、`att.tls_self`。
7. **judge 日志滞后。** judge 每 2 秒落盘一次，`summary.json` 生成时最后几秒的 `req` 可能还没写出，所以它的 `judge.req` 可能比库里少几条
   （夹具：300 对 301）。`summary.go` 为此只对早于“judge 最后一条记录前 10 秒”的成功尝试做“judge 没收到”的核对，指标脚本照做。
8. **文件末尾没写完的一行。** Go 的读法直接丢弃最后一行没有换行符的内容；ingest 能解析就入库、不能就进 `bad_line`，
   因此与 `summary.json` 可能差一条。
9. **重启的痕迹。** 多条 `start`/`version`；每个列表文件重新出现 `base=1` 的 `snap`（`list_event` 里一大批 `base=1` 的 add，不是新上榜）；
   `node` 表同一 `id` 多行；`nsnap` 的 `base=1` 再来一遍；`cands.srcs` 由重启后第一次快照重建。
   `resumed_candidates=0` 的 `start` 意味着状态被清空，PROTOCOL 规定从那一刻重新算 72 小时。
10. **`visit.aborted=1` 的探访结果不作数**（程序退出时被打断），`state` 等于 `prev`。
11. **`att.ip` 不是出口地址的依据**，只是回显；出口地址用 `req.remote`（按 `nonce` 连接，取最早到达的那条）。同一 `nonce` 多条 `req` 就是重放。
12. **匿名程度和请求被改的判断需要期望的金丝雀值**（`derive.go` 里的 `nonce.Canary(secret, "req", nonce)`），而 `secret` 不在数据包里。
    judge 已经替我们比过 `X-Probe-Canary`（`req.req_canary`）；Cookie 的期望值 `pc=<金丝雀>` 可以在 `req_canary='ok'` 时取 `X-Probe-Canary` 头的值来比，
    `req_canary` 不是 ok 时 Cookie 的改动无法单独判定，只能并入“金丝雀被改”。
13. **被排除的条目**（judge 自己的地址、私网地址、28 个知名端口、退出名单）会出现在 `list_event` 里，但永远不进 `cands`/`visit`；
    数量在 `stat_pool` 的 `skipped_*` 里。算“在榜条目里可用的比例”时分母用 `cands`/`visit` 的口径，并单独报告被排除的数。
14. **聚合器条目**只在 `agg_member` 和 `cands`（`group=1`）里，`list_event` 没有它们；`snap` 里 `agg=1` 的记录只有数量。
15. **`http_hdr` 只在非 200 或正文不符时有**；`csp_*`、`cookie_*` 标记和 `http_added` 只在正文正确且金丝雀 ok 时有；
    `gzip_added` 在解压、比对正文之前就记下，所以可能与 `http_body_mismatch` 同时出现（解开后内容仍不符）。
16. **`tlsproxy` 的 `tls_*`** 是对代理端口自己的 TLS 握手（按 IP 校验证书，几乎一定 `tls_cert_invalid`），
    不能算进“中间人”；`summary.go` 的 `integrity` 也排除了它。
17. **输出按白名单取列**，见“可输出列白名单”。`prefix24` 的写法是 `a.b.c.0/24`，可以出现在输出里；
    地址（`cand_ip`/`cand`/`key`/`ip`/`remote`/`node.host`/`npre.ips`）、主机名（`host`/`sni`/`target`/`tls_subj`/`tls_issuer`）、
    哈希（`tls_leaf`/`ev`/`http_ev`/`http_sha`/`*_sha8`）、自由文本（`*_detail`/`*_banner`/`err`/`msg`/`headers`/`value`/`raw_head`/`http_hdr`）、
    `raw` 都不许出现在输出里，也不要靠“删掉敏感词”来放行——`raw_head` 是 base64，grep 明文查不到。
18. **来源编号的名字从数据推，不从 `--sources` 抄。** `cand_src.src_name` 由 `resolve_src_names` 按快照事件多数票得出，
    `--sources` 只用来比对和补缺；`meta.cand_src_names.sources_trusted=0` 说明部署时的 sources.json 与给的文件顺序不同，
    这时 `sources_names` 的顺序不能用来解释编号。`list_event`/`agg_member` 里的 `src` 始终是权威的来源名。
19. **库很大。** 夹具 1,264 条记录 2.5 MB；合成 208 万条 2.4 GB（约 1.2 KB/条，judge 的 `req` 最占地方）。
    一千多万条 att 加几百万条 judge 记录，库会有 10 GB 以上，放在有足够空间的磁盘上。入库约 4 万条/秒，加建索引大约十几分钟；
    内存由 SQLite 的 256 MB 页缓存主导，不随记录数增长（实测 208 万条峰值 643 MB）。
    真实数据（72.88 小时，数据包 525 MB）：220 个文件、982 万条记录，入库 330 秒，库 12.2 GB（att 507 万行）。
20. **跨整点生成的 `summary.json` 会漏掉刚轮转的 judge 文件。** `rec.Each`（rec.go eachFile）遇到读的过程中消失的文件直接跳过
    （`os.ErrNotExist`，本意是“读取期间文件被压缩改名”）。真实数据的 `summary.json` 生成于 08:59:58，读到 judge 当时那一小时的文件时
    judge 正好整点把它压缩改名，整个小时的 judge 记录都没算进去：`judge.req` 少 12,033、`tls_fail` 少 373、`noise` 少 565，重放少 4 次，
    与汇总生成之后才读得到的记录（那一小时的文件，加上停机后 judge 在下一小时文件里零星写下的几条）逐项相等
    （`m_instrument` 的 `crosscheck.judge_rotation` 逐项核对；`req` 全在那一小时的文件里）。分析脚本读数据包里的全部文件，不受影响；
    以后打包前先停探测器、过了整点再生成 summary 可以避开。
21. **`group` 只降不升。** `sched.go` 的 `Upsert` 只把 `group` 从 1 改成 0：先在常规列表上过榜、之后只剩聚合器还列着的候选，
    状态文件里仍是 `group=0`、`listed=1`，但常规列表的在榜重建（`list_event`）里已经没有它。真实数据结束时有 1,192 个这样的候选，
    `cand_src` 里的来源全是聚合器（`m_availability` 的 `checks` 分类计数）。按“结束时常规列表在榜”算的指标用 `list_event` 重建，不受影响；
    直接用 `cands."group"` 分组时要知道这一点。

## 索引

`att(cand, ts_epoch)`、`att(visit)`、`att(nonce)`（部分）、`att(ts_epoch)`、`att(proto, dst, class)`、`att(prefix24)`（部分）、`att(tls_leaf)`（部分）、
`visit(cand, ts_epoch)`、`visit(visit)`、`visit(ts_epoch)`、`visit(prefix24)`、`visit_ok(visit)`、`visit_ok(cand)`、`visit_tried(visit)`、
`npre(node, round)`、`npre(ts_epoch)`、`npre_ip(node)`、`nerr(node, round)`、`nround(round)`、`stat(ts_epoch)`、`stat_pool(key)`、
`req(nonce)`、`req(remote)`、`req(ts_epoch)`、`req_header(req_rid)`、`req_header(name)`、`noise(ts_epoch)`、`tls_fail(ts_epoch)`、`tls_fail(remote)`、
`snap(src, label, ts_epoch)`、`list_event(cand, ts_epoch)`、`list_event(src, label, ts_epoch)`、`list_event(ts_epoch)`、`agg_member(cand)`、
`nsnap(src, ts_epoch)`、`node_event(node, ts_epoch)`、`node(id)`、`cands(prefix24)`、`cands("group", state)`、`cand_src(key)`、`misc(k)`。

## 几个查询示例

```sql
-- 探测器与 judge 对账：探测器认为成功、judge 却没收到（应为 0；judge 最后 10 秒除外）
SELECT COUNT(*) FROM att a
WHERE a.class = 'ok' AND a.nonce IS NOT NULL AND a.dst IN ('judge_http', 'judge_tls')
  AND a.ts_epoch < (SELECT MAX(ts_epoch) - 10 FROM req)
  AND NOT EXISTS (SELECT 1 FROM req r WHERE r.nonce = a.nonce);

-- 重放：同一 nonce 被 judge 收到不止一次
SELECT nonce, COUNT(*) copies, COUNT(DISTINCT remote) ips FROM req GROUP BY nonce HAVING copies > 1;

-- “中间人”细分的输入：隧道里证书校验失败的尝试（排除 tlsproxy），按 tls_detail_enum 和“叶子是否 judge 的”汇总。
-- 不用 tls_detail（Go 错误原文，带地址）；不输出 tls_leaf 本身，只输出不同叶子的个数（白名单规则）
SELECT tls_detail_enum detail,
       tls_leaf IN (SELECT leaf FROM self_leaf WHERE source = 'control_ok') leaf_is_judge,
       COUNT(*) attempts, COUNT(DISTINCT cand) cands, COUNT(DISTINCT tls_leaf) leaves, SUM(ev IS NOT NULL) with_chain
FROM att WHERE tls_class = 'tls_cert_invalid' AND proto != 'tlsproxy' AND cand_kind = 'proxy'
GROUP BY 1, 2 ORDER BY attempts DESC;

-- 候选密集的 /24：每个前缀多少候选、多少探访过
SELECT c.prefix24, COUNT(*) cands, SUM(c.visits > 0) visited FROM cands c GROUP BY 1 HAVING cands > 100 ORDER BY cands DESC;
```
