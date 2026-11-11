# 代理池网关：第 2 阶段报告（规范与客户端行为矩阵）

2026-11-11

`docs/brief.md` 1B 第 5 条要的两样东西：规范上代理必须、应当、可以做什么；真实的客户端经代理时到底怎么做。
测量方案事先写在 [`research/phase2/PROTOCOL.md`](../../research/phase2/PROTOCOL.md)，用例、矩阵的取值规则和各客户端的预期都先于正式实测提交。

读这份报告要知道的三条规矩：

- 正文里说到矩阵的格子，一律写成 `R10[node-agents]=3` 这种形式：行号、列名、取值。
  `research/phase2/tools/report_tables.py --check` 把每一处都对着 `out/matrix.json` 核对，写错一个字就不通过。
- 说到 RFC 条款一律写条款号（如 9110-9.2.2-5），原文在 [`research/phase2/out/spec_clauses.md`](../../research/phase2/out/spec_clauses.md)，
  引文由 `spec/check_quotes.py` 逐字对着 RFC 文本核对。条款后面“对网关的含义”是我们的解读，不是 RFC 的原话。
- 没有验证过的写“未验证”。实测之后才补的说明都标了出来（PROTOCOL 1.1、`caveats.json`）。

## 结论摘要

一句话：会话不能绑在连接上，错误不能只写在响应头和正文里，用户名参数只能用一小撮安全字符。这三条是数据直接给出的。

1. **凭据什么时候发，分两派。** 大多数客户端第一个请求就带凭据（`R30[curl,requests,go,node-fetch-env,node-http-env,node-undici,node-agents,node-axios]=先带`），
   Chromium 和加了 `--proxy-anyauth` 的 curl 等 407（`R30[curl-anyauth,chromium-pw]=等 407 再带`）。
   等 407 的两个都在原连接上重试（`R32[curl-anyauth,chromium-pw]=原连接`、`R33[curl-anyauth,chromium-pw]=原连接`），
   407 带 `Connection: close` 也能走通（`R34[curl-anyauth,chromium-pw]=成功`、`R35[curl-anyauth,chromium-pw]=成功`）。
   代理不要求认证时，先带的那一派照样把凭据发出来（`R52[curl,requests,go,node-undici,node-agents,node-axios]=带`）。
2. **密码错了没有客户端会反复试。** 全部 10 列都只带着凭据试一次（`R47[curl,curl-anyauth,requests,go,node-fetch-env,node-http-env,node-undici,node-agents,node-axios,chromium-pw]=1`）。
3. **用户名的字节不一定原样到达。** 只含字母、数字、连字符、下划线、点的用户名，HTTP 入口上 10 列都原样（R60、R61），SOCKS5 入口上能配凭据的 6 列也都原样（R125）。
   出了这个范围就各有各的坑：curl 把 `-U` 里的百分号转义解开；requests 遇到非 Latin-1 的用户名直接抛异常；
   SOCKS5 下 requests 的用户名到 255 字节就坏了，undici 把百分号转义原样发出去；空密码在三个客户端上不能用。见“已知坑清单”第 3 组。
4. **CONNECT 被拒时，调用方能看到的很少。** 响应头和正文在默认用法下大多看不到：
   `R80[curl,curl-anyauth,node-fetch-env,node-undici]=状态码`、`R80[go]=原因短语`、`R80[chromium-pw]=都看不到`。
   隧道建成时 200 里附加的头，10 列默认都看不到（R84）。503 带 `Retry-After` 没有一个客户端自动重试（R83）。
5. **连接复用差别很大，会话不能按连接算。** 同一个源连续 3 个 HTTPS 请求，有的开 1 条隧道，有的开 3 条
   （`R10[curl,requests,go,chromium-pw]=1`、`R10[node-agents,node-axios]=3`）；6 个并发在源站只说 HTTP/1.1 时全部开 6 条（R15）。
6. **连接被关以后，有的客户端会自己把请求再发一遍，POST 也发。** 复用的连接在请求发出后被代理关掉：
   `R92[curl,go,chromium-pw]=2 次，成功`，POST 也一样的有 `R93[curl,curl-anyauth,chromium-pw]=2 次，成功`。
   Go 只重发 GET（`R93[go]=1 次，失败`）。requests 都不重发（`R92[requests]=1 次，失败`）。
7. **Node 内置的 `fetch` 把明文请求也放进 CONNECT 隧道**（`R01[node-fetch-env]=CONNECT 到 80 端口`），其余 9 列的明文请求都是绝对形式。
8. **隧道首包都是 TLS ClientHello，但多数超过一个 TCP 包**（R06 全部是 TLS ClientHello；`R07[curl]=不超过 1460 字节`，
   `R07[requests,go,node-undici,chromium-pw]=超过 1460 字节`）。
9. **Go 的一种常见写法会让两个用户共用一条隧道**（`R42[go]=用了别人的隧道`、`R124[go]=用了别人的连接`），前提见“已知坑清单”第 13 条。
10. **SOCKS5 的认证不是人人都能配。** Playwright 拒绝给 SOCKS5 代理配凭据（`R117[chromium-pw]=不支持`），Node 的两种环境变量写法和 axios 根本没有 SOCKS5（`R110[node-fetch-env,node-http-env,node-axios]=不支持`）。

仪器和数据的可信度，以及 Firefox 一列的状态，见“数据与仪器”。

<!-- BEGIN report_tables：由 research/phase2/tools/report_tables.py 生成，不要手改 -->

**规模。** 用例 90 个（A 组 16、B 组 14、C 组 8、D 组 11、E 组 7、F 组 12、S 组 22），每个 3 遍；矩阵 104 行 × 11 列，其中有数据的 10 列，没有数据的列：`firefox-pw`。

**仪器自检。** 参照客户端 `rawref` 一列与手写答案比较 104 行，不一致 0 行，结论：通过。

**各列的版本和正式运行的时刻**（`out/versions.json`）

| 列 | 版本 | 运行时刻（UTC） | 系统 |
| --- | --- | --- | --- |
| `curl` | curl 8.5.0；distro_packages curl 8.5.0-2ubuntu10.16、libcurl4t64 8.5.0-2ubuntu10.16；openssl 3.0.13；nghttp2 1.59.0 | 2026-11-10T23:42:22Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `curl-anyauth` | curl 8.5.0；distro_packages curl 8.5.0-2ubuntu10.16、libcurl4t64 8.5.0-2ubuntu10.16 | 2026-11-10T23:48:35Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `requests` | requests 2.34.2；urllib3 2.8.0；PySocks 1.7.1；python 3.13.18；openssl OpenSSL 3.5.9 29 Sep 2026 | 2026-11-10T19:41:44Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `go` | go go1.24.7 | 2026-11-10T19:44:38Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-fetch-env` | node 22.23.4；node 内置的 undici 6.29.1；openssl 3.5.9 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-http-env` | node 22.23.4 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-undici` | node 22.23.4；undici 8.12.4 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-agents` | node 22.23.4；http-proxy-agent 9.1.0；https-proxy-agent 9.1.0；socks-proxy-agent 10.1.0；socks 2.8.10 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-axios` | node 22.23.4；axios 1.21.1；axios 自带的 https-proxy-agent 5.0.1；follow-redirects 1.16.3 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `chromium-pw` | playwright 1.63.0；browser_version 153.0.8010.12；node v22.23.4 | 2026-11-10T23:35:08Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `firefox-pw` | （没有数据） | | |
| `rawref` | rawref 1 | 2026-11-10T23:35:22Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |

**运行次数和抓包核对**（`out/pcap_check.json`）

| 列 | 运行 | 按用例的 only 跳过 | 逐字节相同 | prefix | 不一致 | tcpdump 丢包 | 运行器出错 | 驱动超时 | 驱动非零退出 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `chromium-pw` | 270 | 0 | 270 | 0 | 0 | 0 | 0 | 0 | 0 |
| `curl` | 264 | 6 | 261 | 3 | 0 | 0 | 0 | 0 | 0 |
| `curl-anyauth` | 264 | 6 | 261 | 3 | 0 | 0 | 0 | 0 | 0 |
| `go` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-agents` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-axios` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-fetch-env` | 270 | 0 | 270 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-http-env` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-undici` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `rawref` | 270 | 0 | 264 | 6 | 0 | 0 | 0 | 0 | 0 |
| `requests` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| 合计 | 2922 | 48 | 2910 | 12 | 0 | 0 | 0 | 0 | 0 |

**实测与预期**（`out/expectation_diff.md`；预期写于实测之前）

| 列 | 比较的格子 | 相符 | 不符 | 预期是“不知道” | 不符的行 |
| --- | --- | --- | --- | --- | --- |
| `curl` | 104 | 104 | 0 | 0 |  |
| `curl-anyauth` | 104 | 104 | 0 | 0 |  |
| `requests` | 103 | 103 | 0 | 1 |  |
| `go` | 104 | 104 | 0 | 0 |  |
| `node-fetch-env` | 104 | 96 | 8 | 0 | R10、R11、R36、R38、R94、R95、R99、R101 |
| `node-http-env` | 102 | 102 | 0 | 2 |  |
| `node-undici` | 104 | 96 | 8 | 0 | R11、R92、R93、R94、R95、R98、R99、R122 |
| `node-agents` | 104 | 104 | 0 | 0 |  |
| `node-axios` | 104 | 104 | 0 | 0 |  |
| `chromium-pw` | 104 | 103 | 1 | 0 | R89 |
| `firefox-pw` | 0 | | | | （没有实测数据） |
| 合计 | 1037 | 1020 | 17 | | |

**矩阵里的格子。** 各遍取值不同（不稳定）的 0 格；落到“其他：”的 3 格；“不支持”的 86 格；挂了读数须知的 79 格（`caveats.json` 共 18 条）。

**规范条款**（`spec/clauses/`，引文由 `spec/check_quotes.py` 逐字核对）

| RFC | 条款数 | 其中标了矩阵行的 |
| --- | --- | --- |
| RFC 1928 | 29 | 20 |
| RFC 1929 | 8 | 8 |
| RFC 6455 | 6 | 5 |
| RFC 7617 | 23 | 17 |
| RFC 9110 | 147 | 116 |
| RFC 9112 | 113 | 69 |
| RFC 9113 | 4 | 0 |
| RFC 9209 | 42 | 26 |
| 合计 | 372 | 261 |

<!-- END report_tables -->

## 对设计的含义

PROTOCOL 的每个问题对应一项设计决定。第 3 阶段的设计文档以这张表为输入。

| 问题 | 设计决定 | 数据给出的回答 |
| --- | --- | --- |
| 凭据什么时候发，407 之后怎么重试 | 407 响应怎么写 | 两种客户端都要照顾：第一个请求就带凭据的要直接放行（9110-11.3-3 允许），不带的要回 407 并带 `Proxy-Authenticate`（9110-11.7.1-1 是 MUST）。407 要自带长度并保持连接（9112-9.3-8），等 407 的两列都在原连接上重试；带 `Connection: close` 也能用，但白白多一次握手。凭据错回 407，被策略拒绝回 403（9110-15.5.4-1），客户端都只试一次 |
| 哪些客户端没法配凭据 | “端口即会话”照顾谁 | HTTP 代理的凭据，测过的 10 列都能配。SOCKS5 的凭据：Playwright 的 Chromium 配不了，Node 的环境变量写法和 axios 没有 SOCKS5。“端口即会话”首先是给浏览器走 SOCKS5 准备的 |
| 用户名的字节是不是原样 | 用户名参数的语法 | 只用字母、数字、连字符、下划线、点；不用冒号、百分号、加号、斜杠、@、空格和非 ASCII 字符；总长控制在 127 字节以内（requests 在 SOCKS5 下 255 字节已经出错，128 到 254 之间没有测，按它的缺陷推断同样会错，未验证）；不能要求空密码 |
| 换用户名会不会串 | 会话绑定在哪一层 | 绑在每个请求（HTTP 明文）和每条隧道（CONNECT、SOCKS5）带来的凭据上，不绑在 TCP 连接上（9110-3.3-3 是 MUST NOT）。隧道建成以后里面走谁的流量网关看不见：Go 的一种写法会把第二个用户的请求放进第一个用户的隧道，网关防不了，只能写进文档 |
| 请求经代理时长什么样 | 首字节分流；“隧道首包必须是 TLS” | 首字节分流成立：三种入口的第一个字节分别是 `G`（或别的方法首字母）、`C`、`0x05`（R23）。“隧道首包必须是 TLS”不能只看第一个 TCP 包能不能解析出完整的 ClientHello：8 列的 ClientHello 超过 1460 字节，要么只看记录头的 5 个字节，要么攒够一条记录再判。会误伤两类：Node 内置 `fetch` 的明文请求（CONNECT 到 80 端口）和 `ws://`（`R21[chromium-pw]=CONNECT 到 80 端口，隧道里明文升级`） |
| 连接怎么复用 | 并发上限、空闲超时、会话计数 | 一个“会话”对应的连接数从 1 条到每请求 1 条都有，并发时普遍 6 条。单用户的并发连接上限不能低于 6；粘性会话按用户名里的会话 ID 计，不按连接计。空闲连接由代理先关，10 列都能换新连接继续（R90、R91，`node-fetch-env` 的 R90 没测到） |
| 出错时调用方看得到什么 | 报错通道 | 状态码是唯一几乎都看得到的通道：CONNECT 失败时 8 列能看到状态码，Go 只给原因短语，Chromium 什么都不给。所以三样都要写：状态码选对，原因短语写成机器可读的短词（9112-4-1 说客户端应当忽略它，Go 偏偏只给它），`Proxy-Status`（RFC 9209）照发但不能指望有人看到。隧道建成时的 200 上附加的头默认没人看得到：“换绑并明确告知”不能靠它，要另给查询接口 |
| 连接被关以后会不会重发 | 重放与空闲超时 | 网关自己不重放（9110-9.2.2-5 是 MUST NOT）还不够：curl 和 Chromium 会在复用连接被关时把 POST 再发一遍。网关关连接的时机因此要守两条：只关空闲的连接；请求已经转给上游以后出了错，回一个 502，而不是直接关掉客户端连接 |
| 代理凭据会不会被带到源站 | 威胁模型 | 没有一列把代理凭据带进隧道或带到重定向后的源站（R39，两列有读数须知）。明文转发时网关自己要删掉 `Proxy-Authorization`（9110-11.7.2-2、9110-11.7.2-3）和 `Proxy-Connection`（明文请求里 5 列还在发这个非标准头，R02；CONNECT 里见 R04） |
| SOCKS5 入口 | 控制通道和报错 | 配了凭据的客户端都同时提供“无认证”（`R111[requests,go,node-agents]=00,02`），入口必须自己选 02 才拿得到用户名。`socks5://` 不等于客户端自己解析：`R114[go,node-undici,chromium-pw]=把域名交给了代理`。应答码 2、4、5 多数客户端能区分（R121），值得如实填 |

## 规范条款

372 条，来自 RFC 9110、9112、1928、1929（题目点名的四份）和 7617、9209、6455、9113（前四份不够回答的地方）。
每条有原文、级别、约束谁、对网关哪一侧，以及它对应矩阵的哪几行。全表在 `research/phase2/out/spec_clauses.md`。
下面只列对设计起决定作用、而且容易想当然的几条。

- **网关不得自动重发非幂等请求**（9110-9.2.2-5，MUST NOT）。CONNECT 不在幂等方法里；向上游发 CONNECT 失败后换一个上游再发算不算“重试”，
  条款没有单独说，**未验证**，设计文档要写明取哪种读法。
- **每个 407 都必须带 `Proxy-Authenticate`**（9110-11.7.1-1、9110-15.5.8-1，MUST）；客户端收到后“可以”重发（9110-15.5.8-2，MAY），
  走哪条连接、试几次条款都没规定，所以才要测。
- **非 2xx 的 CONNECT 响应表示隧道没建成**（9110-9.3.6-6）；2xx 响应不得带 `Content-Length` 或 `Transfer-Encoding`（9110-9.3.6-10，MUST NOT），别的头没有禁止。
- **`Proxy-Authorization` 由第一个要它的代理消费**（9110-11.7.2-2）；只有协同认证的代理之间才可以转交（9110-11.7.2-3，MAY），网关和不可信上游不是这种关系。
- **同一条连接上的两个请求不能假定来自同一个用户**（9110-3.3-3，MUST NOT）。
- **Basic 凭据按第一个冒号拆**，用户名不能含冒号（7617-2-9）；很多客户端不检查（7617-2-10）。
- **SOCKS5 用户名和密码各 1 到 255 字节**（1929-2-1）；认证失败后服务端必须关连接（1929-2-5，MUST）；
  失败应答之后 10 秒内必须关连接（1928-6-9，MUST）。
- **RFC 1928 说合规实现必须支持 GSSAPI**（1928-3-10，MUST）。网关只做“无认证”和“用户名密码”，按字面不算合规实现，文档里要如实写，不能声称完全符合 RFC 1928。
- **代理应当把 CONNECT 限制在一组已知端口**（9110-9.3.6-9，SHOULD）。这一条和第 7 点结论冲突：只放行 443 会让 Node 内置 `fetch` 的明文请求全部失败。
- **客户端应当忽略原因短语**（9112-4-1，SHOULD）。和第 4 点结论冲突：Go 默认只把原因短语给调用方。

## 兼容性矩阵

全表在 [`research/phase2/out/matrix.md`](../../research/phase2/out/matrix.md)（104 行，带脚注和读数须知），机器可读的在 `out/matrix.json`。
列的含义和每列用的写法见 PROTOCOL“被测客户端”一节。下面是与设计直接有关的行的节选，取值照抄不了的地方请看全表。

| 行 | 多数客户端 | 不一样的 |
| --- | --- | --- |
| R30、R31 第一个请求带不带凭据 | 先带 | `curl-anyauth`、`chromium-pw` 等 407 |
| R45 没配凭据，明文 | 调用方拿到 407 响应 | `R45[node-fetch-env,node-undici]=报错，提到 407` |
| R46 没配凭据，HTTPS | 报错，提到 407 | `R46[go,chromium-pw]=报错，没提 407`；`R46[node-agents,node-axios]=拿到 407 响应` |
| R10 同源连续 3 次 HTTPS 的隧道数 | 1 | `R10[node-fetch-env]=2`；`R10[node-agents,node-axios]=3` |
| R14 6 个并发，源站支持 h2 | 6 条隧道 | `R14[curl,node-undici,chromium-pw]=1`（隧道里用 HTTP/2 多路复用） |
| R05 CONNECT 的 Host 头 | 同目标 | `R05[node-fetch-env,node-undici,node-axios]=不同`（Host 里没有端口） |
| R20 2 MiB 的 POST 先发 `Expect: 100-continue` | 不发 | `R20[curl,curl-anyauth]=发` |
| R43 带正文的 POST 遇到认证，正文发几遍 | 1 | `R43[curl-anyauth]=2` |
| R44 6 个并发遇到认证，收到几个 407 | 0 | `R44[curl-anyauth]=6`；`R44[chromium-pw]=1`（有读数须知） |
| R88 CONNECT 失败但代理没关连接 | 全部换新连接 | 无 |
| R100 CONNECT 发出后代理不回应就关连接 | 1 次，失败 | `R100[node-fetch-env]=2 次，成功` |
| R110 SOCKS5 没配凭据时提供的方法 | 00 | `R110[curl,curl-anyauth]=00,01`（多报一个 GSSAPI） |
| R113 `socks5://` 目标是 localhost 时的地址类型 | 各不相同 | `R113[curl]=IPv6`、`R113[requests,node-agents]=IPv4`、`R113[go,node-undici,chromium-pw]=域名`（取决于本机解析） |

## 已知坑清单

每一条写：现象、证据（矩阵的行）、规范怎么说（条款号）、网关该怎么办。“该怎么办”是给第 3 阶段的建议，还不是决定。

### 第 1 组：认证

1. **有的客户端不等 407 就发凭据，有的一定要等。** `R30[curl]=先带`、`R30[chromium-pw]=等 407 再带`。
   规范两种都允许（9110-11.3-3）。网关两条路都要对：带了凭据就直接处理，没带就回 407。
2. **加了 `--proxy-anyauth` 的 curl 每个请求都先不带凭据问一遍。** `R36[curl-anyauth]=6/3`（3 个请求，代理收到 6 个，其中 3 个没带凭据）；
   6 个并发收到 6 个 407（`R44[curl-anyauth]=6`）；带正文的 POST 把正文发了两遍（`R43[curl-anyauth]=2`）。
   Chromium 只问一次，之后都先带（`R36[chromium-pw]=4/1`、`R37[chromium-pw]=先带`）。
   407 不算失败，不能计入“认证失败”的限速或封禁；网关回 407 之前不要读完整个正文再说（9110-10.1.1-9、9110-10.1.1-10）。
3. **代理没要求认证时，凭据照样发过来。** `R53[curl,requests,go,node-undici,node-agents,node-axios]=带`。
   “端口即会话”的端口上也会收到用户名：要么忽略，要么报错，设计文档要定一种并写明。
4. **没配凭据时，调用方看到的东西因客户端而异。** 明文请求多数直接把 407 当成普通响应交给调用方（`R45[curl,requests,go,chromium-pw]=拿到 407 响应`），
   调用方不检查状态码就会把 407 的正文当成页面内容。HTTPS 时 Go 和 Chromium 的报错里连 407 都没有（`R46[go,chromium-pw]=报错，没提 407`）。
   407 的正文要短、是纯文本、一眼能看出是代理说的话（9110-11.4-2）。

### 第 2 组：连接和会话

5. **“一个会话一条连接”不成立。** 每个请求新开连接的有 `R11[node-agents]=3`、`R10[node-axios]=3`；一个源开两条的有 `R11[node-undici]=2`。
   规范不限制连接数（9112-9.4-1）。粘性会话只能按用户名里的会话 ID 认，不能按 TCP 连接认。
6. **并发 6 个请求就是 6 条隧道**（R15，10 列相同），除非隧道里谈成了 HTTP/2（`R14[curl,node-undici,chromium-pw]=1`）。
   网关对单个用户的并发连接上限低于 6 会直接让浏览器类的负载失败；“按请求数轮换”在 HTTP/2 隧道上数不了请求，只能数隧道。
7. **CONNECT 失败以后，没有客户端复用那条连接**（R88 全部是“新连接”），尽管规范说连接还是 HTTP 连接（9110-9.3.6-6）。
   网关对 CONNECT 回非 2xx 之后保留连接没有收益，可以直接带 `Connection: close`。
8. **连接被关，客户端会自己重发，POST 也发。** `R93[curl,curl-anyauth,chromium-pw]=2 次，成功`、`R95[curl,curl-anyauth,chromium-pw]=2 次，成功`；
   复位（RST）也一样（`R98[curl,go,chromium-pw]=2 次，成功`）。规范说客户端不应自动重发非幂等请求（9110-9.2.2-3，SHOULD NOT）。
   后果：网关在转发了一个 POST 之后关掉客户端连接，源站可能收到两次。网关只在连接空闲时关；转发之后出错回 502。
   新连接上的第一个请求被关则没有一列重发（`R96[curl,requests,go,chromium-pw]=1 次，失败`、R97）。
9. **Node 内置 `fetch` 在 CONNECT 没有回应就被关时会再发一次 CONNECT**（`R100[node-fetch-env]=2 次，成功`），其余 9 列不会。
   CONNECT 本身没有副作用，但网关要是按“收到 CONNECT”计数或轮换，这里会多算一次。

### 第 3 组：用户名和密码的字节

10. **curl 把 `-U` 里的百分号转义解开。** `R62[curl,curl-anyauth]=变了`：用户名里的 `%41` 到达代理时是 `A`（字节在全表的脚注里）；
    密码里的 `%2F` 到达时是 `/`（`R68[curl,curl-anyauth]=变了`）。SOCKS5 也一样（`R126[curl,curl-anyauth]=变了`）。
    用户名参数里不能出现百分号，也不能指望用百分号转义来传特殊字符：有的客户端解，有的不解。
11. **undici 走 SOCKS5 时反过来，把转义后的样子原样发出去。** `R126[node-undici]=变了`、`R127[node-undici]=变了`、`R132[node-undici]=变了`：
    用户名里的 `@` 到达时是 `%40`，冒号是 `%3A`，非 ASCII 字符是一串 `%XX`。
12. **requests 的坑最多。** 非 Latin-1 的用户名在发出任何字节之前就抛 `UnicodeEncodeError`，质询带不带 `charset="UTF-8"` 都一样
    （`R63[requests]=客户端报错`、`R64[requests]=客户端报错`；规范见 7617-2.1-3、7617-2-2）。
    SOCKS5（PySocks）下 255 字节的用户名到达时已经不是原样（`R128[requests]=变了`），256 字节的也照发不误（`R129[requests]=变了`，
    别的客户端是 `R129[curl,go,node-undici,node-agents]=客户端报错`）；规范的上限是 255 字节（1929-2-1）。
    SOCKS5 的空密码直接不提供用户名密码这种方法（`R131[requests]=客户端报错`）。
13. **空密码不通用。** `R69[node-fetch-env]=客户端报错`、`R131[requests,node-undici]=客户端报错`。“密码留空”的用法不能出现在文档里。
14. **冒号。** HTTP 代理下 10 列都原样拼接（R70），服务端按第一个冒号拆，冒号后面的部分进了密码（7617-2-9、7617-2-10）。
    SOCKS5 下 curl 自己先按第一个冒号拆了（`R132[curl,curl-anyauth]=变了`）。用户名参数的分隔符不能用冒号。

### 第 4 组：请求的形状

15. **Node 内置 `fetch` 的明文请求走 CONNECT 到 80 端口**（`R01[node-fetch-env]=CONNECT 到 80 端口`；同一个 Node 的 `http.get` 是绝对形式，`R01[node-http-env]=绝对形式`）。
    对网关的三个后果：只放行 443 端口的 CONNECT 会让它全部失败（9110-9.3.6-9 建议限制端口）；
    不可信层“隧道首包必须是 TLS”会拒绝它，这是想要的结果，但报错要让人看得懂；
    明文请求的任何策略（改头、缓存、按请求计数）对它都不生效，网关看到的只是一条隧道。
16. **ClientHello 常常超过一个 TCP 包。** `R07[requests,go,node-fetch-env,node-http-env,node-undici,node-agents,node-axios,chromium-pw]=超过 1460 字节`
    （各列的字节数在全表脚注里）。判“首包是不是 TLS”时，第一次读到的数据里很可能没有完整的 ClientHello。
    本次都在回环网卡上，是否真的分成多个包是按长度推断的，**未在真实链路上验证**。
17. **CONNECT 的 Host 头不一定等于请求目标。** `R05[node-fetch-env,node-undici,node-axios]=不同`（axios 的 Host 不带端口，见全表脚注）。
    入口以请求行里的目标为准（9112-3.2.3-2），不要拿 Host 去比对然后拒绝。
18. **`Proxy-Connection` 还活着。** `R02[curl,curl-anyauth]=Proxy-Connection: Keep-Alive`、`R02[node-agents]=Proxy-Connection: close; Connection: close`。
    它不是标准头（9112-C.2.2-1）。网关转发明文请求时要把它和 `Connection` 里列出的头一起删掉（9110-7.6.1-2）。
19. **curl 发大 POST 之前先问 `Expect: 100-continue`**（`R20[curl,curl-anyauth]=发`）。网关要么立刻给最终状态码，要么把请求头先转给上游，
    不能等正文收齐（9110-10.1.1-10，MUST）。

### 第 5 组：报错看不看得见

20. **CONNECT 失败时的响应头和正文，默认几乎没人看得到。** 只有 `R80[node-agents,node-axios]=状态码、原因短语、响应头、正文`；
    `R80[requests,node-http-env]=状态码、原因短语`；`R80[go]=原因短语`；`R80[chromium-pw]=都看不到`。403 也一样（R82）。
    主动打开调试手段以后多数能看到响应头（R81，三列有读数须知）。
    `Proxy-Status`（9209-2-1、9209-2.1.1-3）照发，给愿意开调试的人看；给程序看的信息放在状态码和原因短语里。
21. **隧道建成时附加的响应头默认没人看得到**（R84，10 列都是“看不到”）。“这条隧道换绑到了哪个出口”这类信息不能只放在 CONNECT 的 200 上。
22. **`Retry-After` 没人理**（R83，10 列都只发 1 次 CONNECT；9110-10.2.3-1 也没有要求客户端重试）。“稍后再试”不能当成自动恢复的手段。
23. **明文请求被拒时，Node 内置 `fetch` 什么都看不到，curl 默认只看到正文。** `R86[requests,go,chromium-pw]=状态码、原因短语、响应头、正文`；
    curl 那一格的“状态码”是驱动加的 `-w` 打出来的（读数须知）。

### 第 6 组：多用户和 SOCKS5

24. **Go：同一个 `Transport`、按请求换代理用户时，第二个用户的 HTTPS 请求走了第一个用户的隧道。** `R42[go]=用了别人的隧道`、`R124[go]=用了别人的连接`；
    别的列都是各开各的（`R42[curl,requests,node-undici,chromium-pw]=各开各的隧道`）。明文请求不受影响（`R41[go]=各用各的凭据`）。
    前提是驱动的写法（一个 `Transport`，`Proxy` 函数按请求返回不同的用户）；每个用户一个 `Transport` 的写法**没有测**。
    网关看不见隧道里的内容，防不了。文档里要写明：用 Go 做多会话时每个会话用独立的 `Transport`。
25. **配了凭据的 SOCKS5 客户端同时提供“无认证”。** `R111[requests,go,node-agents]=00,02`、`R111[curl,curl-anyauth]=00,01,02`。
    代理选了“无认证”它们也照常工作（`R118[curl,requests,go,node-undici,node-agents]=成功`），凭据就没发出来。
    入口要拿到用户名参数，必须在客户端提供 02 时选 02。
26. **`socks5://` 不保证客户端自己解析。** `R114[go,node-undici,chromium-pw]=把域名交给了代理`；`R114[node-agents]=没连代理就报错`；
    curl 和 requests 是先连上代理、协商完认证，然后才在本机解析（`R114[curl,requests]=其他`，读数须知）。
    入口必须同时支持域名和 IP 两种地址类型（1928-4-4、1928-5-2），并对域名做与 HTTP 入口相同的目标检查。
27. **SOCKS5 的报错多数说得清。** `R121[curl,requests,go,node-undici,node-agents]=能区分`（应答码 2、4、5），`R121[chromium-pw]=不能区分`。
    认证失败后入口必须关连接（1929-2-5）。应答码值得如实填，对非浏览器的客户端有用。

## 与预期不符

预期是每列实测之前只凭文档和源码写的（`research/phase2/expectations/`），实测之后不改。不符的 17 格归为三件事。

1. **undici 的连续请求不复用连接**（`node-fetch-env` 的 R10、R11、R36、R38，`node-undici` 的 R11、R122）。预期是 1 条，实测是 2 条。
   请求 1 的响应读完后，undici 要等一轮事件循环才把连接标成可用，紧接着发出的请求 2 于是新开一条，请求 3 回到第一条。
   依据：npm 的 undici 8.12.4 `lib/dispatcher/client-h1.js` 里的 `setImmediate` 和它的注释；驱动的审查者另写了不经驱动、不经代理的对照脚本，
   内置的 6.29.1 和 npm 的 8.12.4 都是 2 条连接。对照脚本不在仓库里，这一条的源码行号**未在本报告里复核**。
2. **因此没测到的“会不会重发”**（`node-undici` 的 R92、R93、R94、R95、R98、R99，`node-fetch-env` 的 R94、R95、R99、R101）。预期是“1 次，失败”，
   实测是“未触发”：第二个请求落在新连接上，仪器“只在复用的连接上断开”的条件没满足。**这不是“不重发”，是没测到。**
   要测到需要三步以上的用例，属于改用例表，留给后续（见“已知局限”）。
3. **Chromium 的 R89**（`R89[chromium-pw]=失败`，预期“成功”）。失败的是 Playwright 的 `page.goto`：上一步 CONNECT 失败后浏览器还在提交错误页，
   紧跟着的导航被它打断。事件里第二个源的 CONNECT 得到了 200，源站也收到了请求。这一格说明不了“代理有没有被标坏”，预期没有被证伪，也没有被证实。

## 数据与仪器

- **仪器。** `research/phase2/harness/` 的 `obsproxy`（Go 标准库）在一个端口上同时当 HTTP 代理和 SOCKS5 代理，自带 HTTP、HTTPS 源站，从不向外拨号。
  全部连接都在 127.0.0.1 上。HTTPS 源站的证书由现建的测试 CA 签发，CA 带名字约束；每个客户端按自己文档里的办法信任这张 CA，没有任何一处关闭证书校验。
- **抓包核对。** 每次运行同时用 tcpdump 抓包，`pcap_check.py` 用独立的解析器把每条连接两个方向的字节重建出来，与仪器记录的字节数和 SHA-256 比，
  再把请求行、`Proxy-Authorization`、SOCKS5 的各个字段重新解析一遍与事件比。结果见上面生成的表：没有不一致，没有丢包。
  12 次 `prefix`（抓包比仪器的记录多出一段）是方案里写明的正常情况：仪器主动关连接以后，对方还在路上的字节仪器读不到。
- **仪器自检。** 参照客户端 `rawref` 用裸套接字按写死的字节说话，它那一列与手写答案逐格相同（见生成的表）。
  自检有“牙齿”测试：故意改错答案或事件时自检会失败（`runner/test_selfcheck.py`）。
- **稳定性。** 每个用例 3 遍，没有一个格子各遍取值不同。
- **驱动审查。** 10 列的驱动由另一位审查者对着事件逐列抽查，没有发现驱动造成的取值；查出的“写法或口径两边都说得通”的地方全部写进了读数须知。
- **Firefox。** `firefox-pw` 一列本机没有数据：本机下载不了 Playwright 的 Firefox。驱动和 CI 工作流（`.github/workflows/phase2.yml`）已经写好，
  CI 的结果取回后另行提交；在那之前，本报告关于“浏览器”的结论只指 Playwright 驱动的 Chromium。Firefox 的代码路径**未验证**。
- **第二个环境。** CI 上重跑全部列并与仓库里的矩阵逐格比较（`runner/compare_env.py`）。截至本报告，CI 的比较结果还没有取回，**未验证**。

### 实测之后才补的东西

按规矩单列，免得和事先定的口径混在一起。

- PROTOCOL 1.1 只加说明，没有改任何判定规则、用例或行表（见 PROTOCOL 文末）。
- `caveats.json` 的 18 条读数须知：哪些格子的取值依赖驱动的写法，哪些行对某一列其实没有测到。只加说明，不改取值。
- 行表的三处不足没有修，原样保留：R114 少一个取值；R119、R120 的关键词表没收 curl 的说法，
  所以 `R120[curl,curl-anyauth]=只说失败` 其实是 curl 说了“User was rejected by the SOCKS5 server”；R89 对浏览器不适用。
- curl 两列在仪器集成阶段试跑过，早于 curl 的预期写成；写预期的人没有看到试跑结果。其余各列的预期都先于该列的任何运行。
- `go` 列首轮有 1 次运行被抓包核对判为不一致，原因是运行器并行时的端口竞争（已修，`runner/run.py` 的 `PortWindow`），那个用例重跑了 3 遍。
- curl 两列的发行版包版本是正式运行之后在同一台机器上补记的。

## 已知局限

- 只测了 Linux x86-64 上的这些版本（见生成的表）。curl 是 Ubuntu 打过安全补丁的 8.5.0，行为不一定等于上游的 8.5.0，更不等于新版。
- 每个客户端只测了一种写法。Go 的“每个用户一个 `Transport`”、requests 换 `HTTPAdapter`、Node 的其他代理库都没测。
- 全在回环网卡上，没有丢包、延迟和 MTU。
- 代理认证只测了 Basic；到代理本身的 TLS（`https://` 代理）、SOCKS4、HTTP/2 和 HTTP/3 的 CONNECT 没测。
- 浏览器由 Playwright 驱动。人手操作的浏览器遇到 407 会弹窗，这里测不到。
- “已发出的请求所在的复用连接被关以后会不会重发”对 `node-undici` 和 `node-fetch-env` 没有测到（见“与预期不符”第 2 条）。
- `node-fetch-env` 的明文请求走隧道，10 行对它没有测到（读数须知）。
- 各驱动为了不挂死都设了限时，Node 的内层进程装了异常处理函数，Chromium 加了 `--log-net-log`。这些有没有改变线上的字节，没有做对照运行，**未验证**。
- SOCKS5 入口上的断连与重发没有测。
- `spec/fetch_rfcs.sh --from rfc-editor` 这条取 RFC 文本的路径本机走不通（出口策略不允许），只在 CI 上用，**本机未验证**；本机核对用的是 Ubuntu 软件包里的 RFC 文本，SHA-256 记在 `spec/rfc_sha256.txt`。

## 下一步

1. 取回 CI 上 Firefox 一列和两个环境的比较结果，提交并更新本报告。
2. 第 3 阶段：设计文档。输入是本报告和 1B 报告各自的“对设计的含义”一表。
3. 值得补测的（要先在 PROTOCOL 里记新版本）：三步以上的断连用例，补上 undici 的“会不会重发”；Go 每个用户一个 `Transport`。

## 复现

```sh
cd research/phase2
./run_all.sh                                  # 构建仪器、跑测试、取数、生成矩阵、自检（全部列各 3 遍，总用时没有单独计）
python3 spec/check_quotes.py                  # 逐字核对 372 条引文（要先按 spec/README.md 取 RFC 文本）
python3 tools/report_tables.py --check ../../docs/research/phase2-report.md   # 核对本报告里引用的格子、条款号和生成的表
```

只想从仓库里的原始记录重新生成矩阵，不重新取数：

```sh
python3 runner/derive.py --raw out/raw --out out/observations
python3 runner/matrix.py --observations out/observations --out out
python3 runner/collect.py && python3 runner/selfcheck.py --out out
```

各驱动要装的东西见 `research/phase2/drivers/*/NOTES.md` 和 `.github/workflows/phase2.yml`。
