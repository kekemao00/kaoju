# 网关：架构、入口、控制通道、报错通道

## 架构

一个进程，一个静态二进制（决策 D5），节点协议由进程内嵌入的出站实现承担（决策 D6）。

```
客户端 ──► 入口（同端口：HTTP 代理 / SOCKS5，按首字节分流）
             │  认证、解析用户名参数
             ▼
           策略（层、端口、目标地址）──► 拒绝：状态码 + 原因短语
             │
             ▼
           会话表 ◄──────────────┐
             │                    │ 出口变了、上游失效
             ▼                    │
           选路（按“上游 × 目标注册域”）
             │                    │
             ▼                    │
           拨号（http-connect / socks5 / socks4 / 节点出站 / 直连）
             │                    │
             ▼                    │
           转发（隧道：先验首条记录；明文：只走 trusted 和 direct）
                                  │
来源抓取 ─► 候选池 ─► 探测器 ─► 观察者（两个公共回显服务 + 可选的自建 judge）
                         │
                         ▼
                   存储（内嵌 SQLite）：上游、统计、来源、会话绑定、事件
                         ▲
              只读管理 API、Prometheus 指标
```

| 部件 | 职责 | 状态放在哪 |
| --- | --- | --- |
| 入口 | 首字节分流，HTTP/1.1 代理和 SOCKS5 的解析，认证 | 无 |
| 策略 | 层、端口白名单、目标地址检查、并发上限 | 配置 |
| 会话表 | 粘性会话的状态机（[03-sticky.md](03-sticky.md)） | 内存，绑定和事件同步写进 SQLite |
| 选路 | 三种策略之一（[05-routing.md](05-routing.md)） | 内存，统计定期落盘 |
| 拨号与转发 | 经选中的上游建隧道，转发字节，记录被动信号 | 无 |
| 探测器、观察者 | 验证上游、观察出口（[05-routing.md](05-routing.md)） | SQLite |
| 来源抓取 | 条件请求、校验、去重、来源健康 | SQLite |
| 管理 API、指标 | 只读（[06-config.md](06-config.md)） | 无 |

## 入口

**DD-10** 一个端口同时接 HTTP 代理和 SOCKS5，按第一个字节分流：`0x05` 是 SOCKS5，大写 ASCII 字母是 HTTP，其余直接关连接。
实测的第一个字节：明文请求是方法首字母，CONNECT 是 `C`，SOCKS5 是 `0x05`（矩阵 R23；有 SOCKS5 的 8 列都是 `G / C / 05`，
`R23[node-fetch-env]=C / C / 不支持`，因为它的明文请求也走 CONNECT）。
不接 SOCKS4 入口、不接“到代理本身的 TLS”（`https://` 代理）、不接 HTTP/2：这三样第 2 阶段都没有测，不作承诺。

### HTTP 代理

- **明文请求**（绝对形式）：只走 `trusted` 和 `direct`。解析从严：`Content-Length` 与 `Transfer-Encoding` 同时出现、重复且不一致的 `Content-Length`、
  请求行或头里的裸 LF、不合法的分块，一律回 400，不猜测着转发。转发前删掉 `Proxy-Authorization`（9110-11.7.2-2）、`Proxy-Connection`
  （非标准头，`R02[curl,curl-anyauth]=Proxy-Connection: Keep-Alive`）和 `Connection` 里点名的头（9110-7.6.1-2）。
  带 `Upgrade` 的明文请求回 501；`ws://` 要走 CONNECT（`R21[chromium-pw]=CONNECT 到 80 端口，隧道里明文升级`，浏览器本来就这么做）。
- **CONNECT**：目标以请求行为准（9112-3.2.3-2），不拿 `Host` 头去比对（`R05[node-fetch-env,node-undici,node-axios]=不同`）。
- **`Expect: 100-continue`**（`R20[curl,curl-anyauth]=发`）：要拒绝就立刻给最终状态码；要转发就先把请求头发给上游，不等正文收齐（9110-10.1.1-10）。
- **认证**：带了合法凭据就直接处理，不先回 407（9110-11.3-3 允许；`R30[curl,requests,go,node-fetch-env,node-http-env,node-undici,node-agents,node-axios]=先带`）。
  没带就回 407，带 `Proxy-Authenticate: Basic realm="kaoju"`（9110-11.7.1-1），响应自带长度、保持连接（9112-9.3-8；
  `R30[curl-anyauth,chromium-pw,firefox-pw]=等 407 再带`，这三列都在原连接上重试）。凭据错误也回 407；凭据对、但请求被策略拒绝回 403（9110-15.5.4-1）。
  407 的正文是一行纯文本，一眼能看出是代理说的话（`R45[curl,requests,go,chromium-pw]=拿到 407 响应`：调用方不查状态码就会把它当页面）。
- **连接管理**：CONNECT 回了非 2xx 就带 `Connection: close` 关掉（矩阵 R88：没有一列会复用这条连接）。
  网关只关空闲的连接；明文请求已经转给上游之后出了错，回 502，不直接关客户端连接。
  理由：连接被关，客户端会自己把请求再发一遍，POST 也发（`R93[curl,curl-anyauth,chromium-pw,firefox-pw]=2 次，成功`），
  Firefox 连新连接上的第一个请求也重发（`R96[firefox-pw]=2 次，成功`）。

### SOCKS5

- **方法协商**：客户端提供了 `02`（用户名密码）就选 `02`。配了凭据的客户端同时提供“无认证”（`R111[requests,go,node-agents]=00,02`），
  选 `00` 的话凭据根本不会发出来。只提供 `00` 的客户端，只在“端口即会话”的回环端口上接受，其余回 `FF`。
- **命令**：只做 CONNECT。BIND 和 UDP ASSOCIATE 回 `07`（不支持的命令）。
- **地址类型**：域名、IPv4、IPv6 都接（1928-4-4）。`socks5://` 不保证客户端自己解析（`R114[go,node-undici,chromium-pw]=把域名交给了代理`），
  所以域名和 IP 两种目标走同一套目标检查。
- **认证失败**：回失败状态后立即关连接（1929-2-5）。
- **应答码**：如实填。策略拒绝填 `02`，上游报告目标不可达填 `04`，目标拒绝填 `05`，其余失败填 `01`
  （`R121[curl,requests,go,node-undici,node-agents]=能区分`：非浏览器的客户端分得清 2、4、5）。
- **不合规之处**：不做 GSSAPI。RFC 1928 说合规的实现必须支持 GSSAPI（1928-3-10），所以本项目的 SOCKS5 入口按字面**不是**合规实现。
  README 只能写“支持 SOCKS5 的 CONNECT，认证支持无认证和用户名密码”，不能写“符合 RFC 1928”。

## 控制通道：用户名参数

**DD-11** 会话和选路的参数写在代理用户名里，HTTP 代理和 SOCKS5 共用一套语法。

```
username = account *( "-" key "-" value )
account  = 1*32( ALPHA / DIGIT / "_" / "." )
key      = "session" / "ttl" / "life" / "every" / "tier" / "onfail" / "proto"
value    = 1*64( ALPHA / DIGIT / "_" / "." )
```

整个用户名不超过 127 字节，键小写，值区分大小写，同一个键出现两次算错。口令是账号的口令，不能为空。

| 键 | 值 | 默认 | 含义 |
| --- | --- | --- | --- |
| `session` | 任意合法的值 | 无 | 粘性会话的标识，不需要预先登记。命名空间是“账号 + 这个值”。不写就是每条隧道（明文是每个请求）各自选路 |
| `ttl` | 时长，如 `90s`、`5m` | `5m` | 空闲多久以后会话过期。上限 60 分钟 |
| `life` | 时长 | `10m` | 会话最长活多久，到点过期；同一个标识再来就是一个新会话、重新绑定（“按时间轮换”就用它）。上限 60 分钟 |
| `every` | 正整数 | 无 | 这个会话每建成这么多条隧道就换一次出口（“按请求数轮换”）。数的是建成的隧道，不是隧道里的请求 |
| `tier` | `verified`、`trusted`、`auto` | 配置里的 `default_tier`，出厂是 `auto` | `auto`：先用 `verified`，没有可用的才回落到 `trusted` |
| `onfail` | `error`、`rebind` | `error` | 会话的出口不再成立时怎么办，见 [03-sticky.md](03-sticky.md) |
| `proto` | `socks5`、`http`、`socks4`、`ss`、`vmess`、`vless`、`trojan`，多个用 `.` 连接 | 不限 | 只用这些协议的上游 |

例子：`alice-session-job42-ttl-2m-onfail-rebind`。

字符集为什么这么窄，每一条都有实测依据：

- 百分号不能用：`R62[curl,curl-anyauth]=变了`（curl 把转义解开），`R126[node-undici]=变了`（undici 走 SOCKS5 时反而把转义后的样子发出来）。
- 冒号不能用：HTTP 下服务端按第一个冒号拆（7617-2-9），SOCKS5 下 `R132[curl,curl-anyauth]=变了`。
- 非 ASCII 不能用：`R63[requests]=客户端报错`。
- 长度：`R128[requests]=变了`（SOCKS5 下 255 字节的用户名到达时已经不是原样）；128 到 254 字节之间没有测，所以上限定在 127。
- 只含字母、数字、连字符、下划线、点的用户名，HTTP 入口上 11 列原样到达（矩阵 R60、R61），SOCKS5 入口上能配凭据的 6 列原样到达（R125）。
- 连字符留给分隔符，所以值里不能有连字符。这是与题目“会话 ID 是任意字符串”的偏离，见 [08-open.md](08-open.md)。

出错的用户名：口令对、但参数不合法（不认识的键、值不合法、超长、键重复）回 403，原因短语 `kaoju-bad-username`，不回 407。
理由：407 会让浏览器弹窗或让客户端以为口令错了；全部 11 列带着凭据都只试一次（矩阵 R47），回哪个都不会引来重试风暴，403 更准确。

### 端口即会话

给配不了凭据的客户端用。首先是经 SOCKS5 的浏览器：`R117[chromium-pw,firefox-pw]=不支持`（Playwright 拒绝给 SOCKS5 代理配凭据）；
Node 的两种环境变量写法和 axios 没有 SOCKS5（`R110[node-fetch-env,node-http-env,node-axios]=不支持`），它们用 HTTP 代理加用户名就行。

**DD-14** 配置里把一个端口绑到一组参数上（账号、会话标识和其余的键）。这个端口上：

- 监听回环地址时不要求凭据；监听其他地址时仍然要求口令（用户名只写账号）。不要求凭据又对外监听，等于开放代理，配置校验直接拒绝。
- 客户端照样会把配好的凭据发过来（`R53[curl,requests,go,node-undici,node-agents,node-axios]=带`）。用户名只有账号时接受；
  **用户名里带任何参数就拒绝**，回 403 `kaoju-session-conflict`（SOCKS5 回 `02`）。不采用“忽略”：两处都写了会话参数，
  忽略哪一处都可能让人以为自己在用另一个会话，报错才看得见。这回答了第 2 阶段留下的问题。

## 策略

**DD-12** 隧道放行的端口按层给白名单：

| 层 | 默认放行 | 理由 |
| --- | --- | --- |
| `verified` | 443 | 这一层只承载 TLS。80 端口的隧道在选路之前就拒绝（403 `kaoju-plaintext-denied`），不等到看首条记录：这样被拒的客户端看得到状态码 |
| `trusted`、`direct` | 80、443 | Node 内置 `fetch` 的明文请求走 80 端口的隧道（`R01[node-fetch-env]=CONNECT 到 80 端口`），只放 443 它会全部失败 |

白名单可以在配置里加端口；规范建议代理限制 CONNECT 的端口（9110-9.3.6-9）。`auto` 遇到 80 端口的隧道或明文请求，直接用 `trusted`；没有配 `trusted` 就拒绝。

**DD-13** 每个账号的并发连接上限默认 256，配置里不许低于 6。依据：6 个并发在源站只说 HTTP/1.1 时，11 列全部开 6 条隧道（矩阵 R15）；
主要负载是 200 并发以内（决策 D2）。超出回 429 `kaoju-busy`。

**DD-15** 隧道首条记录的检查（只对 `verified` 层的隧道）。顺序是：

1. 选路、拨号、经上游建成到目标的隧道。这一步失败可以换上游重试（[04-failures.md](04-failures.md)），最终失败能用状态码告诉客户端。
2. 向客户端回 200（SOCKS5 回 `00`）。
3. 读客户端的第一条记录，**在确认它是 TLS ClientHello 之前，不向上游转发任何一个字节**：先读 5 字节记录头（类型 `0x16`、主版本 `0x03`、
   长度不超过 16,384 加上限定的余量），再把这条记录攒齐，确认握手类型是 `0x01`。等待有超时（设计参数，10 秒）。
4. 不是 ClientHello：关掉两边的连接，记一次 `not_tls`。这时已经没有办法用状态码告诉客户端了，所以 80 端口要在第 1 步之前拒绝。

为什么不能只看第一次读到的数据：`R07[requests,go,node-undici,chromium-pw,firefox-pw]=超过 1460 字节`，ClientHello 多半装不进一个 TCP 包。
攒齐以后顺便取出 SNI，只用来给“目标注册域”归类（目标是 IP 时没有别的办法知道域名），**不拿它和 CONNECT 的目标比对、不因此拒绝**。

为什么不先回 200、看到 ClientHello 再拨号：那样上游建不起来时只能关连接，而关连接是客户端最看不懂的报错
（`R80[chromium-pw,firefox-pw]=都看不到`），还会引来客户端自己重发。代价是给不说 TLS 的客户端白建了一条上游隧道，但没有向它发过任何客户端字节。

## 报错通道

**DD-16** 一个错误写三处，按“谁看得到”排优先级：

1. **状态码**。CONNECT 失败时 11 列里 8 列看得到状态码（`R80[curl,curl-anyauth,node-fetch-env,node-undici]=状态码` 等）。
2. **原因短语写成机器可读的短词**。规范说客户端应当忽略原因短语（9112-4-1），但 Go 偏偏只给它（`R80[go]=原因短语`）。
3. **`Proxy-Status` 头**（9209-2-1）和一行纯文本正文。照发，给愿意开调试的人看，不指望有人看到。

两个浏览器什么都看不到（`R80[chromium-pw,firefox-pw]=都看不到`），隧道建成时 200 上附加的头 11 列默认都看不到（矩阵 R84），
`Retry-After` 没有客户端理会（矩阵 R83）。所以凡是需要客户端知道的状态（会话换绑了、会话丢了），**另有管理 API 可查**（[06-config.md](06-config.md)），
不能只靠响应。

| 情形 | 状态码和原因短语 | SOCKS5 应答 | `Proxy-Status` 的 error |
| --- | --- | --- | --- |
| 没带凭据或凭据错 | `407 Proxy Authentication Required` | 认证失败，关连接 | 无 |
| 请求解析不了、有歧义 | `400 kaoju-bad-request` | 关连接 | `http_protocol_error` |
| 用户名参数不合法 | `403 kaoju-bad-username` | `02` | `http_request_denied` |
| 会话端口上用户名带了参数 | `403 kaoju-session-conflict` | `02` | `http_request_denied` |
| 明文请求或 80 端口隧道，没有可信层可用 | `403 kaoju-plaintext-denied` | `02` | `http_request_denied` |
| 端口不在白名单 | `403 kaoju-port-denied` | `02` | `destination_ip_prohibited` |
| 目标是私网、回环、云元数据地址 | `403 kaoju-target-denied` | `02` | `destination_ip_prohibited` |
| 账号并发超限 | `429 kaoju-busy` | `01` | `connection_limit_reached` |
| 没有符合条件的上游 | `503 kaoju-no-upstream` | `01` | `destination_unavailable` |
| 粘性会话的出口此刻用不了（`onfail-error`） | `503 kaoju-egress-unavailable` | `01` | `destination_unavailable` |
| 重试用完，上游都没建成隧道 | `502 kaoju-upstream-failed` | `01`；上游明确报告时 `04` 或 `05` | `connection_refused` 等 |
| 建隧道超过总时限 | `504 kaoju-upstream-timeout` | `01` | `connection_timeout` |
| 明文请求已转给上游后出错 | `502 kaoju-upstream-broken` | 不适用 | `http_protocol_error` |
| 隧道首条记录不是 TLS | 已经回过 200，只能关连接 | 已经回过 `00`，只能关连接 | 无 |

成功的 CONNECT 在 200 上带 `Kaoju-Session`、`Kaoju-Gen`、`Kaoju-Tier` 三个头（会话标识、绑定的代数、实际用的层），明文响应也带。看得到的客户端可以用，但契约不依赖它。

## 对客户端的承诺

按第 2 阶段测过的 11 列写。“能用”的意思是：按这一列的写法，不改客户端，经网关访问 HTTPS 目标成功；第 4 阶段在 CI 里逐列跑（AC-30）。

| 客户端（矩阵的列） | HTTP 代理 + 用户名参数 | SOCKS5 + 用户名参数 | 要知道的事 |
| --- | --- | --- | --- |
| `curl` | 能用 | 能用 | `-U` 里不要写百分号 |
| `curl-anyauth` | 能用 | 能用 | 每个请求多一次 407 往返（`R36[curl-anyauth]=6/3`），不算认证失败 |
| `requests` | 能用 | 能用 | 连接被关不重发，报错如实抛出 |
| `go` | 能用 | 能用 | 多会话时每个会话用独立的 `Transport`，否则会共用隧道（`R42[go]=用了别人的隧道`）。独立 `Transport` 的写法第 2 阶段**没有测**，第 4 阶段补测 |
| `node-fetch-env` | 能用 | 没有 SOCKS5 | 明文请求走 80 端口的隧道，只有 `trusted` 层能承载 |
| `node-http-env` | 能用 | 没有 SOCKS5 | |
| `node-undici` | 能用 | 能用 | SOCKS5 下用户名只用安全字符 |
| `node-agents` | 能用 | 能用 | 每个请求一条隧道（`R10[node-agents,node-axios]=3`），`every` 按隧道数 |
| `node-axios` | 能用 | 没有 SOCKS5 | 同上 |
| `chromium-pw` | 能用 | 只能用“端口即会话” | 报错看不到，查管理 API |
| `firefox-pw` | 能用 | 只能用“端口即会话” | 同上；新连接被关也会重发 |

题目第三阶段点名的 httpx 和 Scrapy 第 2 阶段没有测，这里不作承诺，**未验证**；第 4 阶段加进 CI 的兼容性矩阵以后再写。
