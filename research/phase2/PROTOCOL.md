# 测量方案：客户端经代理时的真实行为

第 2 阶段（`docs/brief.md` 1B 第 5 条）。版本 1.1，2026-11-11（1.0 于 2026-11-10 在取数之前写定；1.1 只加说明，见文末）。

这份方案在取数之前写定。用例（`cases.json`）、矩阵每一行的取值规则（`rows.json`）和各客户端的预期（`expectations/`）
都先于第一次正式运行提交；数据出来以后不改口径，确实要改时记在文末的变更记录里，并说明原因。

规范部分（RFC 9110、9112、1928、1929 的条款）不是测量，放在 `spec/`，条款原文由脚本逐字对着 RFC 文本核对。

## 要回答的问题

每个问题都对应网关的一项设计决定。回答不了设计问题的行为不测。

| 问题 | 对应的设计决定 |
| --- | --- |
| 客户端什么时候发代理凭据：一上来就发，还是等 407；407 之后在原连接上重试还是另开连接；407 带 `Connection: close` 行不行 | 网关的 407 响应怎么写（要不要保持连接、带哪些头） |
| 哪些客户端根本没法给 HTTP 代理或 SOCKS5 代理配凭据 | “端口即会话”要照顾谁 |
| 用户名里的字节到达代理时还是不是原样：分隔符、要转义的字符、UTF-8、长度 | 用户名参数的语法（哪些分隔符安全、长度上限） |
| 同一个客户端进程里换用户名，连接和隧道会不会串 | 会话绑定在哪一层（请求、隧道还是连接） |
| 请求经代理时长什么样：明文是不是绝对形式，HTTPS 是不是 CONNECT，隧道首包是不是 TLS，ClientHello 多大 | 同端口按首字节分流；“隧道首包必须是 TLS 握手”怎么判，会误伤谁 |
| 连接怎么复用：连续请求、多个源、并发时各开几条连接和隧道 | 单上游并发上限、空闲超时、粘性会话按什么计数 |
| 代理拒绝或出错时（CONNECT 非 2xx、明文 403、SOCKS5 应答码），调用方到底能看到状态码、原因短语、响应头、正文里的哪些 | “报错”和“换绑并明确告知”通过哪个通道告知才看得见 |
| 连接被关掉以后客户端会不会自己重发请求，对 POST 也重发吗 | “已向上游写出请求字节后不重放”之外，网关还要防客户端自己的重发；空闲连接多久关 |
| 代理凭据会不会被带到源站（隧道里、重定向后） | 威胁模型：网关和上游各自能看到什么 |
| SOCKS5 入口：客户端提供哪些认证方法，域名交给谁解析，失败时报什么 | SOCKS5 入口的控制通道和报错方式 |

## 被测客户端

| 列名 | 客户端 | 代理怎么配 |
| --- | --- | --- |
| `curl` | curl 命令行 | `-x`，凭据用 `-U` |
| `curl-anyauth` | 同上，加 `--proxy-anyauth` | 同上 |
| `requests` | Python requests（SOCKS 用 PySocks） | `proxies=` 参数，凭据写在代理 URL 里 |
| `go` | Go `net/http` 默认的 Transport | `Transport.Proxy`，凭据写在代理 URL 里 |
| `node-fetch-env` | Node 内置 `fetch` | 环境变量加 `NODE_USE_ENV_PROXY=1` |
| `node-http-env` | Node 内置 `http`、`https` 模块 | 同上 |
| `node-undici` | npm 的 undici，`ProxyAgent` | 构造参数 |
| `node-agents` | Node 内置 `http`、`https` 加 `http-proxy-agent`、`https-proxy-agent`、`socks-proxy-agent` | Agent 的构造参数 |
| `node-axios` | axios 自带的 `proxy` 选项 | 请求配置 |
| `chromium-pw` | Playwright 驱动的 Chromium | Playwright 的 `proxy` 选项 |
| `firefox-pw` | Playwright 驱动的 Firefox（Playwright 打过补丁的构建，不是 Mozilla 发布的原版） | 同上 |

Node 没有统一的代理实现，所以按实际在用的五种做法分列。版本号在运行时读出来写进 `out/versions.json`；
依赖的版本固定在 `drivers/*/requirements.txt` 和 `drivers/*/package-lock.json` 里。

每个客户端都按它的文档里最常见的写法使用，不为了测试改默认值。为了让测试能跑而做的设置只有两项，都不影响代理行为：
信任测试用的 CA；把环境里已有的代理变量清掉。驱动把自己实际用的写法原样记在结果里。

## 仪器

三样东西互相核对，任何一样单独说的都不算数。

| 部件 | 作用 |
| --- | --- |
| `obsproxy` | 观察用的代理，同时内置源站。只用 Go 标准库。把收到的每一个字节记下来（解析后的事件，加上每条连接两个方向的字节数和 SHA-256） |
| tcpdump | 独立的见证方。每次运行在回环网卡上抓包，`pcap_check.py` 用自己的解析器从包里重建每条连接，与 `obsproxy` 的记录比对 |
| 驱动 | 每个客户端一个。按用例操作客户端，把调用方实际看到的东西（状态码、报错文字、响应头、正文）记下来 |

所有连接都在 127.0.0.1 上。`obsproxy` 从不向外拨号：目标端口是 80 的都交给内置的明文源站，443 的交给内置的 HTTPS 源站，
其余端口按“连不上”处理。测试用的主机名是 `a.kaoju.test`、`b.kaoju.test`（`.test` 是保留域名，本机解析不了，只有代理认得）。

### obsproxy

```
obsproxy gen-ca -dir DIR                       # 生成测试用 CA（ECDSA P-256，7 天有效）：DIR/ca.pem、DIR/ca.key
obsproxy serve -profile P.json -ca-dir DIR -events E.jsonl [-max-seconds 120]
```

`serve` 在 127.0.0.1 上监听三个随机端口，就绪后在标准输出打印一行 JSON：
`{"proxy_port":…,"origin_http_port":…,"origin_https_port":…}`。收到 SIGTERM 或 SIGINT 后关闭所有连接，写完事件再退出。

- 代理端口按首字节分流：`0x05` 是 SOCKS5；`0x04`（SOCKS4）和 `0x16`（TLS）只记录然后关闭；其余按 HTTP 解析。
- HTTP 入口自己解析请求头（保留头的顺序和大小写，留下原始字节）。绝对形式的请求交给内置源站处理后回写；
  CONNECT 成功后进入隧道。只回 HTTP/1.1。
- 隧道（CONNECT 或 SOCKS5）在进程内直接接到内置源站，不经过额外的 TCP 连接。隧道的首批字节先记下来再交给源站；
  是 TLS ClientHello 的话解析出记录长度、SNI、ALPN、支持的版本和密钥交换组。
- 内置源站：明文一个、HTTPS 一个（证书由测试 CA 签发，名字是 `*.kaoju.test`、`localhost`、`127.0.0.1`；默认支持 h2）。
  两个端口也接受直连，用来发现客户端绕过代理的情况。
- 源站的路径：`/echo` 回一段 JSON，写明源站看到的方法、协议、头、正文长度和哈希，可带 `delay=毫秒`；
  `/redirect?to=URL&code=302` 重定向；`/page` 一个空白网页（浏览器从它发起 `fetch` 和 WebSocket）；
  `/ws` 完成 WebSocket 握手后发一个关闭帧。每个请求都带 `k=用例.步骤`，源站据此把收到的请求对回到步骤上。
- “关闭”有两种：`fin` 是先半关（发 FIN）、把对方还在发的读掉（最多 1 秒）再关；`rst` 是直接复位。

配置（profile）是一个 JSON 对象，下面是全部字段和默认值：

```json
{
  "auth":    {"mode": "none", "accept": [], "accept_any_user": false,
              "challenge": ["Basic realm=\"kaoju\""], "on407": "keepalive", "reject_status": 407},
  "connect": {"ok_headers": [], "fail": null, "drop": null},
  "forward": {"fail": null, "add_response_headers": [], "send_100_continue": true},
  "conn":    {"idle_close_ms": 0, "drop": null},
  "tunnel":  {"idle_close_ms": 0},
  "origin":  {"h2": true, "drop": null},
  "socks":   {"auth": "none", "auth_fail_status": 1, "rep": 0}
}
```

| 字段 | 含义 |
| --- | --- |
| `auth.mode` | `none` 不要求认证；`basic` 要求 `Proxy-Authorization: Basic`（CONNECT 和每个绝对形式的请求都要） |
| `auth.accept` | 接受的 `[用户名, 密码]`，按字节比较 |
| `auth.accept_any_user` | 为真时任何用户名都接受，只要密码等于 `accept[0][1]`；收到的用户名字节照样记录 |
| `auth.challenge` | 407 里的 `Proxy-Authenticate`，每项一行 |
| `auth.on407` | `keepalive`：407 带 `Content-Length`，连接留着；`close`：407 带 `Connection: close`，发完按 `fin` 关 |
| `auth.reject_status` | 凭据不对时回 407 还是 403（没带凭据一律回 407） |
| `connect.ok_headers` | CONNECT 成功时在 200 里多带的头 |
| `connect.fail` | 非空时 CONNECT 不建隧道，回 `{"status","reason","headers","body","close","hosts"}`；`hosts` 非空时只对这些主机生效 |
| `connect.drop` | `{"times":1,"how":"fin"}`：读完 CONNECT 请求后什么都不回就关，共生效 `times` 次 |
| `forward.fail` | 同 `connect.fail`，用于绝对形式的请求 |
| `forward.add_response_headers` | 转发成功时代理在响应里多加的头 |
| `forward.send_100_continue` | 请求带 `Expect: 100-continue` 时是否先回 100 |
| `conn.idle_close_ms` | 大于 0 时，没有隧道的代理连接在两个请求之间空闲这么久就按 `fin` 关 |
| `conn.drop` | `{"k":"F03.s2","times":1,"how":"fin","only_if_reused":true}`：带这个 `k` 的绝对形式请求读完以后不回响应就关连接；整个运行里共生效 `times` 次。`only_if_reused` 为真时，只有它不是所在连接上的第一个请求才生效 |
| `tunnel.idle_close_ms` | 大于 0 时，隧道两个方向都静默这么久就按 `fin` 关 |
| `origin.h2` | 内置 HTTPS 源站是否支持 h2 |
| `origin.drop` | 字段同 `conn.drop`：隧道里带这个 `k` 的请求到达源站、读完以后不回响应就切断隧道。`only_if_reused` 为真时，只有它不是所在源站连接上的第一个请求（h2 按流计数）才生效 |
| `socks.auth` | `none` 选“无认证”；`userpass` 选用户名密码（接受谁同 `auth.accept`、`auth.accept_any_user`），客户端没提供这种方法时回 `0xFF`；`reject` 一律回 `0xFF` |
| `socks.auth_fail_status` | 用户名密码不对时回的状态字节 |
| `socks.rep` | 非 0 时对每个请求都回这个应答码然后关 |

事件每行一个 JSON 对象，`t` 是启动以来的毫秒数，`conn` 是连接编号：

| 事件 | 内容 |
| --- | --- |
| `start`、`end` | 配置、端口、版本 |
| `accept` | 哪个监听端口、对端端口 |
| `first_bytes` | 连接上第一次读到的字节数、前 16 个字节、归类（`http`、`socks5`、`socks4`、`tls`、`other`） |
| `http_request` | 这条连接上的第几个请求、形式（`absolute`、`connect`、`origin`、`other`）、方法、目标、版本、全部头（原顺序、原大小写）、请求头的原始字节（base64）、正文长度；带 `Proxy-Authorization` 时另记方案、原值、解出的用户名和密码（字节以十六进制另存一份）和判定（`ok`、`bad`、`malformed`），不带记 `none` |
| `http_response` | 代理回写的状态码、原因短语、头、正文长度、是代理自己生成的还是源站的、之后是否关闭 |
| `tunnel_open` | 隧道编号、经由（`connect`、`socks5`）、目标主机和端口、接到了哪个源站 |
| `tunnel_first_bytes` | 隧道里客户端发来的首批字节：第一次读到多少、前 16 个字节、归类（`tls_client_hello`、`http`、`other`）；ClientHello 的记录长度、SNI、ALPN、版本、密钥交换组 |
| `tunnel_close` | 谁关的（`client`、`proxy`、`origin`）、两个方向的字节数 |
| `socks5_greeting`、`socks5_method` | 客户端提供的方法、服务端选的方法 |
| `socks5_auth` | 用户名和密码的长度与字节、回的状态 |
| `socks5_request`、`socks5_reply` | 命令、地址类型、主机、端口；应答码 |
| `origin_conn` | 源站连接：来自哪条隧道，或是直连；是否 TLS，协商出的 ALPN |
| `origin_request` | 源站收到的请求：`k`、方法、路径、协议、Host、全部头、正文长度和哈希、是否带着 `Proxy-Authorization`、是照常回应还是按配置丢弃 |
| `action` | 仪器按配置做的动作（空闲关闭、丢弃请求、切断隧道） |
| `conn_end` | 谁关的、怎么关的、两个方向的字节数和 SHA-256、持续时间 |

### 抓包核对

`run.py` 在 `obsproxy` 就绪以后、驱动启动以前开始抓包（`tcpdump -i lo`，只抓三个端口），驱动结束、`obsproxy` 退出以后停。
`pcap_check.py` 只用 Python 标准库，从包里按序号重建每条 TCP 连接，然后做两件事：

1. 每条连接两个方向的字节数和 SHA-256 与 `conn_end` 比。完全相同记 `exact`；一方是另一方的前缀记 `prefix`
   （仪器主动关连接时，对方还在路上的字节仪器读不到，属于正常）；其余记 `mismatch`。
2. 用自己的解析器（不复用 `obsproxy` 的代码）从字节流里再解析一遍：每个 HTTP 请求行和 `Proxy-Authorization` 的原值，
   SOCKS5 的方法、用户名、密码、命令、地址类型、主机、端口，隧道的前 5 个字节。与事件逐项比。

有 `mismatch`、有字段不一致、或者 tcpdump 报告丢包的运行不进入矩阵，要查明原因重跑。抓包文件不进仓库（体积大），
CI 把它们作为构件保存；比对结果（`out/pcap_check.json`）进仓库。

### 仪器自检

`drivers/rawref/` 是一个参照客户端：用裸套接字按写死的字节序列说话（先带凭据的 Basic、CONNECT、SOCKS5 各种分支），
它发了什么是已知的。对它跑全部用例，矩阵里它那一列必须与 `selfcheck_expected.json` 里手写的答案逐格相同。
这一步验证的是整条链（`obsproxy`、抓包核对、事实提取、矩阵）；不通过就不采信其他客户端的数据。
`obsproxy` 自己另有单元测试，用裸套接字验证配置里的每一个字段。

### 驱动

```
<驱动命令> <用例.json> <结果.json>
```

驱动在一个干净的环境里启动（不继承代理相关的环境变量，`HOME` 指向这次运行专用的目录）。一个用例从头到尾用同一个客户端实例
（同一个进程、同一个会话或连接池），这样才看得到连接复用。运行时的用例文件在 `cases.json` 的基础上填好了实际的值：

```json
{
  "id": "B02", "variant": "curl",
  "proxy": {"scheme": "http", "host": "127.0.0.1", "port": 40123},
  "users": [{"user": "kaoju-user", "pass": "kaoju-pass-1"}],
  "ca_file": "/…/ca.pem", "home_dir": "/…/home", "work_dir": "/…/work",
  "origin_http_port": 40124, "origin_https_port": 40125, "timeout_s": 15,
  "steps": [
    {"id": "s1", "op": "request", "method": "GET", "url": "https://a.kaoju.test/echo?k=B02.s1", "user": 0, "follow": false},
    {"id": "z1", "op": "sleep", "ms": 3000},
    {"id": "p", "op": "parallel", "steps": [{"id": "p.1", "op": "request", "method": "GET", "url": "…", "user": 0}]},
    {"id": "s2", "op": "request", "method": "POST", "url": "…", "user": 0, "body_file": "/…/body.bin"},
    {"id": "w1", "op": "ws", "url": "ws://a.kaoju.test/ws?k=A15.w1", "page": "http://a.kaoju.test/page?k=A15.pre"}
  ]
}
```

- `proxy.scheme` 是 `http`、`socks5`（客户端自己解析域名）或 `socks5h`（域名交给代理）。客户端不区分这两种写法时，驱动用它唯一支持的写法并在结果里说明。
- `user` 是 `users` 的下标，`null` 表示这一步不配凭据。一个用例里出现两个用户时，驱动用这个客户端在同一个进程里换凭据的常规做法；
  做不到就把整个用例报成 `unsupported`，并写明依据。
- `follow` 为真时要跟随重定向（客户端默认不跟随的，驱动打开它）。
- `parallel` 里的请求要同时发出。
- 浏览器：GET 是顶层导航（`page.goto`）；POST、`parallel` 和 `ws` 从同源的 `/page` 页面里用 `fetch` 或 `WebSocket` 发起，
  驱动先导航到那个页面（这次导航的 `k` 是 `用例.pre`）。两个用户用两个浏览器上下文。

结果文件：

```json
{
  "variant": "curl", "versions": {"curl": "8.5.0"},
  "config": "实际使用的命令行或代码写法，原样",
  "unsupported": null,
  "steps": [
    {"id": "s1", "ok": true, "status": 200, "body_sha256": "…", "ms": 12,
     "default_text": "调用方按默认用法能拿到的全部文字", "extra_text": null, "extra_how": null}
  ]
}
```

- `ok`：这一步拿到了一个 HTTP 响应（不论状态码）。`status`：调用方看到的最终状态码，没有就是 `null`。
- `default_text`：按默认用法调用方能拿到的全部文字。成功时是状态码、原因短语（接口给的话）、响应头、正文的前 4 KiB；
  失败时是异常的类型和消息（连同 cause 链），命令行工具是默认详细程度下的标准错误和退出码。
- `extra_text`、`extra_how`：通过文档里写明的、需要主动打开的手段（比如 curl 的 `-v`、Go 的 `OnProxyConnectResponse`）还能多看到什么，以及用的是哪个手段。没有这样的手段就留空。
- `unsupported`：客户端做不到这个用例时写原因。能试的都要试，把试出来的报错记下来；只有连配置都写不出来时才不试。

## 用例

`cases.json` 是唯一的用例表（90 个）。每个用例对每个客户端跑 3 遍。分组：

| 组 | 数量 | 内容 | 代理配置 |
| --- | --- | --- | --- |
| A | 16 | 基线：请求的形式、隧道首包、连接复用、并发、目标是 localhost、POST、WebSocket | 不要求认证 |
| B | 14 | 凭据正确时的认证流程：先带还是等 407、407 后怎么重试、之后每次带不带、重定向、同进程两个用户、POST、并发 | Basic |
| C | 8 | 认证失败：没配凭据、密码错（代理回 407 或 403）；配了凭据但代理不要求 | Basic 或不要求 |
| D | 11 | 用户名和密码的字节：常见的参数写法、标点、要转义的字符、UTF-8、长度 255/256/1024、冒号、空密码 | Basic，任何用户名都接受 |
| E | 7 | 报错可见性：CONNECT 回 502/403/503、CONNECT 200 带附加头、明文 403、明文响应里附加的头、失败后连接是否复用 | 不要求认证 |
| F | 12 | 断连与重发：空闲连接和隧道被关、已发出的 GET 和 POST 所在连接被关（新连接上、复用的连接上，FIN 和 RST）、CONNECT 没有回应 | 不要求认证 |
| S | 22 | SOCKS5 入口：提供的方法、域名谁解析、认证成功与失败、应答码、复用、并发、两个用户、用户名的字节 | SOCKS5 |

报错可见性的用例里，代理的响应带四个记号，分别放在原因短语、响应头（`X-Kaoju-Note` 和 `Proxy-Status`）和正文里；
哪个记号出现在驱动记下的文字里，就算调用方看得见哪一样。状态码按数字出现与否判断。

## 矩阵

`rows.json` 是矩阵的行表（104 行）：每行写明看哪个用例、取值规则和可能的取值。`derive.py` 先把一次运行的事件和驱动结果提炼成事实
（连接数、每个请求在哪条连接上、带没带凭据、源站各步骤收到几次请求、记号出现在哪里等），`matrix.py` 再按行表从事实里取值。
两步都是纯函数，同样的输入得到同样的输出。

- 一个格子 3 遍的取值相同，就写这个值；不同，就把出现过的值都列出来并标“不稳定”。
- 有任何一遍没通过抓包核对的格子标“未通过核对”，不给值。
- 驱动报 `unsupported` 的格子写“不支持”，原因在脚注里。
- 矩阵的每个格子都能指回具体的用例和运行；报告里的“已知坑清单”是人写的，每一条都要指到矩阵的行和 RFC 条款。

## 预期

`expectations/<列名>.json` 在该客户端第一次正式运行之前写好并提交：对行表里有把握的行写出预期取值和依据
（客户端文档的章节或源码路径），没把握的写“不知道”。实测与预期不符的格子逐个查：
先怀疑仪器和驱动（“偏差大时先怀疑自己的探测器”），确认仪器没错以后，把它记进报告的“与预期不符”一节。
预期写错了不改预期文件，改的是报告里的结论。

## 两个环境

本机（云端工作区）是正式结果的来源。GitHub Actions 上每次提交重跑全部用例，与仓库里提交的矩阵逐格比较，
不一致的格子在 CI 日志和构件里列出。`firefox-pw` 只能在 CI 上跑（本机下载不了 Playwright 的 Firefox），
它的事件和结果从 CI 取回后提交，并注明来自哪次运行、哪个提交。

## 已知局限

- 只测 Linux（x86-64）上的这些版本。同一客户端在别的系统或别的版本上可能不同。
- 只测 `http://` 和 `socks5://` 两种代理入口。到代理本身的 TLS（`https://` 代理）、SOCKS4、HTTP/2 和 HTTP/3 的 CONNECT 不测：网关第一版不提供这些入口。
- 代理认证只测 Basic。网关只会发 Basic 质询，Digest、NTLM、Negotiate 不测。
- 全部在回环网卡上，没有丢包、延迟和 MTU 限制。ClientHello 是否跨多个包只能按长度推断，不是在真实链路上观察到的。
- 每个客户端只测一种配置写法（表里列的那种）。除 `node-fetch-env`、`node-http-env` 外不测环境变量的写法。
- 浏览器由 Playwright 驱动，启动参数是 Playwright 的默认值；Firefox 是 Playwright 的补丁构建。人手操作的浏览器遇到 407 会弹窗，这里测不到。
- SOCKS5 入口上的断连与重发没有单独测，只测了 HTTP 代理入口。
- 仪器是代理也是源站，同一个进程。抓包能核对代理端口上的字节，隧道里 TLS 之内的内容只有源站一方的记录。

## 变更记录

- 1.0（2026-11-10）：初版。
- 1.1（2026-11-11）：全部列的本机实测做完之后的补充。**判定规则、用例、行表、限时都没有改**，1.0 的数据不用重跑；
  下面每一条都是“实测之后才写的”，读矩阵时要知道。
  - 新增“读数须知”（`caveats.json`）：实测以后发现有些格子的取值依赖前提，或者那一行要问的事对某一列其实没有测到。
    这些说明由 `matrix.py` 挂到格子的脚注上（`matrix.json` 里是 `caveats` 字段），不改取值。
    没有改行表去“修”这些格子：行表是实测前定的，事后改规则等于看着答案改题。
  - 行表的三处不足，保留原样，用读数须知说明：R114 缺一个取值（先连上代理、协商完方法，然后才在本机解析失败；现在落在“其他”）；
    R119、R120 的关键词表没有收 curl 的说法；R89 对浏览器分不出“代理被标坏”和“导航被错误页打断”。
  - “未触发”的含义：F 组的断连只在复用的连接上触发。客户端的第二个请求不复用连接时，这一行要问的“会不会重发”就没有测到，
    不能读成“不重发”。`node-undici`、`node-fetch-env` 的若干格是这种情况。
  - `node-fetch-env` 的明文请求走 CONNECT 到 80 端口，仪器里只对绝对形式请求生效的配置（`forward.*`、`conn.drop`、
    `conn.idle_close_ms`）对它不起作用，相关的行没有测到。
  - 澄清“抓包核对”一节：`prefix` 指抓包里比仪器的记录多出一段，多出来的是仪器关闭连接之后客户端才发出的字节。
    `out/pcap_check.json` 由新加的 `runner/collect.py` 从 `out/raw/` 数出来（1.0 写了这个文件但没有脚本生成它）。
  - 澄清“obsproxy”一节：仪器不向外拨号，但目标端口等于它自己的两个源站端口时，会接到自己的源站上
    （A10、A11、S03 这些以 localhost 为目标的用例靠这一点）。
  - 澄清“驱动”一节：curl 两列的“默认用法”含 `-w '%{http_code}'`（每次传输打印状态码）；各驱动都给请求设了用例里的限时；
    Node 的内层进程装了 uncaughtException 处理函数，否则个别用例会让进程直接退出、留不下结果；
    `chromium-pw` 为了拿到额外信息加了启动参数 `--log-net-log`；`node-http-env`、`node-agents` 的重定向由驱动循环跟随。
    这些都没有做“去掉以后线上字节是否相同”的对照运行。
  - 各列不是一次跑完的：每列正式运行的时刻和环境记在 `out/versions.d/<列>.json`，合并在 `out/versions.json`。
    curl 是 Ubuntu 的补丁构建，包的版本一并记下。`go` 列首轮有 1 次运行因运行器的端口竞争被抓包核对判为不一致
    （已修，见 `runner/run.py` 的 `PortWindow`），按“查明原因重跑”重跑了那个用例的 3 遍。
  - “两个环境”一节说 `firefox-pw` 的数据“从 CI 取回后提交”。取回的办法：CI 把全部输出存成构件 `phase2-out`，
    日志末尾由 `runner/ci_summary.py` 打出这一列每一行的取值和原始记录的 SHA-256。本机的出口策略下载不了构件，
    原始记录要由人从运行页面下载构件后交回，放进 `out/raw/` 时用日志里的哈希核对。
    实际入库的是 GitHub Actions 运行 42937077529 的 `raw/firefox-pw.jsonl.gz`（构件 zip 和这个文件的 SHA-256 都与日志一致），
    只取这一个文件，其余列仍用本机的数据；来源记在 `out/versions.d/firefox-pw.json` 的 `provenance`。
  - `out/observations/` 不进仓库（约 26 MB，可由 `derive.py` 从 `out/raw/` 重新生成）。
