# 客户端行为矩阵

由 `runner/matrix.py` 从 `out/observations/` 生成，不要手改。行的取值规则见 `rows.json`，口径见 `PROTOCOL.md`。
格子里的“（不稳定）”表示各遍取值不同；方括号里的数字指向表后的脚注。

## 基线

| 行 | `curl` | `curl-anyauth` | `requests` | `go` | `node-fetch-env` | `node-http-env` | `node-undici` | `node-agents` | `node-axios` | `chromium-pw` | `firefox-pw` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R01 明文请求到达代理的形式 | 绝对形式 | 绝对形式 | 绝对形式 | 绝对形式 | CONNECT 到 80 端口 | 绝对形式 | 绝对形式 | 绝对形式 | 绝对形式 | 绝对形式 | 绝对形式 |
| R02 明文请求里与连接有关的头 | Proxy-Connection: Keep-Alive | Proxy-Connection: Keep-Alive | Connection: keep-alive | 无 | Connection: keep-alive [1] | proxy-connection: keep-alive; Connection: keep-alive | connection: keep-alive | Proxy-Connection: close; Connection: close | Connection: keep-alive | Proxy-Connection: keep-alive | Connection: keep-alive |
| R03 CONNECT 请求行 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 | a.kaoju.test:443 HTTP/1.1 |
| R04 CONNECT 带的头 | Host, User-Agent, Proxy-Connection | Host, User-Agent, Proxy-Connection | Host | Host, User-Agent | host, connection | proxy-connection, host | host, connection, proxy-connection | Host, Proxy-Connection | Host, Connection | Host, Proxy-Connection, User-Agent | User-Agent, Proxy-Connection, Connection, Host |
| R05 CONNECT 的 Host 头 | 同目标 | 同目标 | 同目标 | 同目标 | 不同 [2] | 同目标 | 不同 [3] | 同目标 | 不同 [4] | 同目标 | 同目标 |
| R06 隧道里客户端发的首包 | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello |
| R07 ClientHello 的长度 | 不超过 1460 字节 [5] | 不超过 1460 字节 [6] | 超过 1460 字节 [7] | 超过 1460 字节 [8] | 超过 1460 字节 [9] | 超过 1460 字节 [10] | 超过 1460 字节 [11] | 超过 1460 字节 [12] | 超过 1460 字节 [13] | 超过 1460 字节 [14] | 超过 1460 字节 [15] |
| R08 隧道里提供的 ALPN | h2,http/1.1 | h2,http/1.1 | http/1.1 | h2,http/1.1 | http/1.1 | 无 | http/1.1,h2 | 无 | 无 | h2,http/1.1 | h2,http/1.1 |
| R09 源站支持 h2 时实际用的协议 | HTTP/2.0 | HTTP/2.0 | HTTP/1.1 | HTTP/2.0 | HTTP/1.1 | HTTP/1.1 | HTTP/2.0 | HTTP/1.1 | HTTP/1.1 | HTTP/2.0 | HTTP/2.0 |
| R10 HTTPS 同一个源连续 3 次：隧道数 | 1 | 1 | 1 | 1 | 2 | 1 | 1 | 3 | 3 | 1 | 1 |
| R11 明文同一个源连续 3 次：代理连接数 | 1 | 1 | 1 | 1 | 2 | 1 | 2 | 3 | 1 | 1 | 1 / 2（不稳定） |
| R12 HTTPS 两个源交替各 2 次：隧道数 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 4 | 4 | 2 | 2 |
| R13 明文两个源交替各 2 次：代理连接数 | 1 | 1 | 1 | 1 | 2 | 2 | 2 | 4 | 1 | 2 | 1 / 2（不稳定） |
| R14 HTTPS 6 个并发（源站支持 h2）：隧道数 | 1 | 1 | 6 | 6 | 6 | 6 | 1 | 6 | 6 | 1 | 1 |
| R15 HTTPS 6 个并发（源站只说 HTTP/1.1）：隧道数 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 [16] | 6 |
| R16 明文 6 个并发：代理连接数 | 5 | 5 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 [17] | 6 |
| R17 目标是 localhost 的明文请求 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 [18] | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 |
| R18 目标是 localhost 的 HTTPS 请求 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 | 经代理 |
| R19 明文 POST 的正文怎么分帧 | Content-Length | Content-Length | Content-Length | Content-Length | 其他：代理端口上没有带 k=A12.s1 的请求 [19] | Content-Length | Content-Length | Content-Length | Content-Length | Content-Length | Content-Length |
| R20 2 MiB 的明文 POST 先不先发 Expect: 100-continue | 发 | 发 | 不发 | 不发 | 其他：代理端口上没有带 k=A14.s1 的请求 [20] | 不发 | 不发 | 不发 | 不发 | 不发 | 不发 |
| R21 ws:// 经代理的方式 | 不适用 | 不适用 | 不适用 | 不适用 | CONNECT 到 80 端口，隧道里明文升级 | 不适用 | 不适用 | 不适用 | 不适用 | CONNECT 到 80 端口，隧道里明文升级 | CONNECT 到 80 端口，隧道里明文升级 |
| R22 wss:// 经代理的方式 | 不适用 | 不适用 | 不适用 | 不适用 | CONNECT 到 443 端口，隧道里 TLS | 不适用 | 不适用 | 不适用 | 不适用 | CONNECT 到 443 端口，隧道里 TLS | CONNECT 到 443 端口，隧道里 TLS |
| R23 代理连接上客户端发的第一个字节 | G / C / 05 | G / C / 05 | G / C / 05 | G / C / 05 | C / C / 不支持 [21] | G / C / 不支持 [22] | G / C / 05 | G / C / 05 | G / C / 不支持 [23] | G / C / 05 | G / C / 05 |
| R24 POST 的正文是否完整到达源站 | 完整 | 完整 | 完整 | 完整 | 完整 | 完整 | 完整 | 完整 | 完整 | 完整 | 完整 |

- [1] R02，`node-fetch-env`：请求不在代理端口上（tunnel），头由源站解析：名字是规范化以后的写法，按名字排序，不是线上的原样；读数须知：请求在 CONNECT 隧道里，头是源站一侧记下的，经过 Go net/http 的规整（名字的大小写不是线上的原样）。
- [2] R05，`node-fetch-env`：Host 头是 'a.kaoju.test'，请求目标是 'a.kaoju.test:443'
- [3] R05，`node-undici`：Host 头是 'a.kaoju.test'，请求目标是 'a.kaoju.test:443'
- [4] R05，`node-axios`：Host 头是 'a.kaoju.test'，请求目标是 'a.kaoju.test:443'
- [5] R07，`curl`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 517、最大 517 字节
- [6] R07，`curl-anyauth`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 517、最大 517 字节
- [7] R07，`requests`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1534、最大 1534 字节
- [8] R07，`go`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1492、最大 1492 字节
- [9] R07，`node-fetch-env`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1604、最大 1604 字节
- [10] R07，`node-http-env`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1589、最大 1589 字节
- [11] R07，`node-undici`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1607、最大 1607 字节
- [12] R07，`node-agents`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1589、最大 1589 字节
- [13] R07，`node-axios`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1589、最大 1589 字节
- [14] R07，`chromium-pw`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1730、最大 1826 字节
- [15] R07，`firefox-pw`：ClientHello 长度（TLS 记录长度加 5 字节记录头）：3 遍里最小 1894、最大 1894 字节
- [16] R15，`chromium-pw`：读数须知：浏览器的 POST 和并发要先导航到同源的 /page 再从页面里发（PROTOCOL.md 的驱动一节）。这次预导航先收下 407 并留下一条空闲连接，这一格的数里含它的影响。
- [17] R16，`chromium-pw`：读数须知：浏览器的 POST 和并发要先导航到同源的 /page 再从页面里发（PROTOCOL.md 的驱动一节）。这次预导航先收下 407 并留下一条空闲连接，这一格的数里含它的影响。
- [18] R17，`node-fetch-env`：请求经 CONNECT 隧道到达，不是绝对形式
- [19] R19，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [20] R20，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [21] R23，`node-fetch-env`：S01：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [22] R23，`node-http-env`：S01：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [23] R23，`node-axios`：S01：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。

## 认证

| 行 | `curl` | `curl-anyauth` | `requests` | `go` | `node-fetch-env` | `node-http-env` | `node-undici` | `node-agents` | `node-axios` | `chromium-pw` | `firefox-pw` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R30 明文：第一个请求带不带凭据 | 先带 | 等 407 再带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 | 等 407 再带 | 等 407 再带 |
| R31 CONNECT：第一个 CONNECT 带不带凭据 | 先带 | 等 407 再带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 | 等 407 再带 | 等 407 再带 |
| R32 明文：407 之后的重试走哪条连接 | 不适用 | 原连接 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 原连接 | 原连接 |
| R33 CONNECT：407 之后的重试走哪条连接 | 不适用 | 原连接 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 原连接 | 原连接 |
| R34 明文：407 带 Connection: close | 不适用 | 成功 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 成功 | 成功 |
| R35 CONNECT：407 带 Connection: close | 不适用 | 成功 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 不适用 | 成功 | 成功 |
| R36 明文连续 3 次：代理收到的请求数 / 其中没带凭据的 | 3/0 | 6/3 | 3/0 | 3/0 | 2/0 | 3/0 | 3/0 | 3/0 | 3/0 | 4/1 | 5/1 / 6/1（不稳定） |
| R37 访问第二个源时 CONNECT 带不带凭据 | 先带 | 等 407 再带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 | 先带 |
| R38 HTTPS 同一个源连续 3 次（要认证）：隧道数 | 1 | 1 | 1 | 1 | 2 | 1 | 1 | 3 | 3 | 1 | 1 |
| R39 代理凭据有没有被带到源站 | 没有 | 没有 | 没有 | 没有 | 没有（不含 B12：不支持） [1] | 没有（不含 B12：不支持） [2] | 没有 | 没有 [3] | 没有 | 没有 | 没有 |
| R40 三种重定向是否都走通 | 都成功 | 都成功 | 都成功 | 都成功 | 都成功 | 都成功 [4] | 都成功 | 都成功 [5] | 都成功 | 都成功 | 都成功 |
| R41 明文，同一个进程两个用户交替 | 各用各的凭据 | 各用各的凭据 | 各用各的凭据 | 各用各的凭据 | 不支持 [6] | 不支持 [7] | 各用各的凭据 | 各用各的凭据 | 各用各的凭据 | 各用各的凭据 | 各用各的凭据 |
| R42 HTTPS，同一个进程两个用户交替 | 各开各的隧道 | 各开各的隧道 | 各开各的隧道 | 用了别人的隧道 [8] | 不支持 [9] | 不支持 [10] | 各开各的隧道 | 各开各的隧道 | 各开各的隧道 | 各开各的隧道 | 各开各的隧道 |
| R43 带正文的明文 POST 遇到认证：完整的正文发了几遍 | 1 | 2 | 1 | 1 | 0 [11] | 1 | 1 | 1 | 1 | 1 [12] | 1 |
| R44 HTTPS 6 个并发（要认证）：收到几个 407 | 0 | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 [13] | 1 |
| R45 没配凭据，明文：调用方看到什么 | 拿到 407 响应 | 拿到 407 响应 | 拿到 407 响应 | 拿到 407 响应 | 报错，提到 407 | 拿到 407 响应 | 报错，提到 407 | 拿到 407 响应 | 拿到 407 响应 | 拿到 407 响应 | 报错，没提 407 |
| R46 没配凭据，HTTPS：调用方看到什么 | 报错，提到 407 | 报错，提到 407 | 报错，提到 407 | 报错，没提 407 | 报错，提到 407 | 报错，提到 407 | 报错，提到 407 | 拿到 407 响应 | 拿到 407 响应 | 报错，没提 407 | 报错，没提 407 |
| R47 密码错，明文：带着凭据试了几次 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| R48 密码错，HTTPS：带着凭据试了几次 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| R49 密码错，HTTPS，代理一直回 407：调用方看到什么 | 报错，提到 407 | 报错，提到 407 | 报错，提到 407 | 报错，没提 407 | 报错，提到 407 | 报错，提到 407 | 报错，提到 407 | 拿到 407 响应 | 拿到 407 响应 | 报错，没提 407 | 报错，没提 407 |
| R50 密码错，HTTPS，代理回 403：调用方看到什么 | 报错，提到 403 | 报错，提到 403 | 报错，提到 403 | 报错，没提 403 | 报错，提到 403 | 报错，提到 403 | 报错，提到 403 | 拿到 403 响应 | 拿到 403 响应 | 报错，没提 403 | 报错，没提 403 |
| R51 密码错，明文，代理回 403：调用方看到什么 | 拿到 403 响应 | 拿到 403 响应 | 拿到 403 响应 | 拿到 403 响应 | 报错，提到 403 | 拿到 403 响应 | 拿到 403 响应 | 拿到 403 响应 | 拿到 403 响应 | 拿到 403 响应 | 拿到 403 响应 |
| R52 代理没要求认证，明文请求带不带凭据 | 带 | 不带 | 带 | 带 | 带 | 带 | 带 | 带 | 带 | 不带 | 不带 |
| R53 代理没要求认证，CONNECT 带不带凭据 | 带 | 不带 | 带 | 带 | 带 | 带 | 带 | 带 | 带 | 不带 | 不带 |

- [1] R39，`node-fetch-env`：B12：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。
- [2] R39，`node-http-env`：B12：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。；读数须知：http、https 模块不会自己跟随重定向，这里跟随的是驱动写的循环（drivers/node/common.mjs 的 followLoop），测到的不是客户端自己的行为。
- [3] R39，`node-agents`：读数须知：http、https 模块不会自己跟随重定向，这里跟随的是驱动写的循环（drivers/node/common.mjs 的 followLoop），测到的不是客户端自己的行为。
- [4] R40，`node-http-env`：读数须知：http、https 模块不会自己跟随重定向，这里跟随的是驱动写的循环（drivers/node/common.mjs 的 followLoop），测到的不是客户端自己的行为。
- [5] R40，`node-agents`：读数须知：http、https 模块不会自己跟随重定向，这里跟随的是驱动写的循环（drivers/node/common.mjs 的 followLoop），测到的不是客户端自己的行为。
- [6] R41，`node-fetch-env`：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。
- [7] R41，`node-http-env`：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。
- [8] R42，`go`：s2 走的隧道是 'kaoju-user' 建的；读数须知：前提是驱动的写法：同一个 http.Transport，Proxy 函数按请求返回不同用户的代理 URL（drivers/go/NOTES.md 第 3 节写法 a）。每个用户一个 Transport 的写法没有测。
- [9] R42，`node-fetch-env`：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。
- [10] R42，`node-http-env`：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。
- [11] R43，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [12] R43，`chromium-pw`：读数须知：浏览器的 POST 和并发要先导航到同源的 /page 再从页面里发（PROTOCOL.md 的驱动一节）。这次预导航先收下 407 并留下一条空闲连接，这一格的数里含它的影响。
- [13] R44，`chromium-pw`：读数须知：浏览器的 POST 和并发要先导航到同源的 /page 再从页面里发（PROTOCOL.md 的驱动一节）。这次预导航先收下 407 并留下一条空闲连接，这一格的数里含它的影响。

## 用户名和密码的字节（HTTP 代理）

| 行 | `curl` | `curl-anyauth` | `requests` | `go` | `node-fetch-env` | `node-http-env` | `node-undici` | `node-agents` | `node-axios` | `chromium-pw` | `firefox-pw` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R60 常见的参数写法（连字符） | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 [1] | 原样 | 原样 | 原样 | 原样 |
| R61 下划线、点、波浪号、等号、分号、逗号 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 [2] | 原样 | 原样 | 原样 | 原样 |
| R62 要转义的字符：@ % + / 和空格 | 变了 [3] | 变了 [4] | 原样 | 原样 | 原样 | 原样 | 原样 [5] | 原样 | 原样 | 原样 | 原样 |
| R63 UTF-8 用户名，质询不带 charset | 原样 | 原样 | 客户端报错 | 原样 | 原样 | 原样 | 原样 [6] | 原样 | 原样 | 原样 | 原样 |
| R64 UTF-8 用户名，质询带 charset="UTF-8" | 原样 | 原样 | 客户端报错 | 原样 | 原样 | 原样 | 原样 [7] | 原样 | 原样 | 原样 | 原样 |
| R65 用户名 255 字节 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 [8] | 原样 | 原样 | 原样 | 原样 |
| R66 用户名 256 字节 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 [9] | 原样 | 原样 | 原样 | 原样 |
| R67 用户名 1024 字节 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 [10] | 原样 | 原样 | 原样 | 原样 |
| R68 密码里有冒号、@、空格、%2F、加号 | 变了 [11] | 变了 [12] | 原样 | 原样 | 原样 | 原样 | 原样 [13] | 原样 | 原样 | 原样 | 原样 |
| R69 空密码 | 原样 | 原样 | 原样 | 原样 | 客户端报错 | 原样 | 原样 [14] | 原样 | 原样 | 原样 | 原样 |
| R70 用户名里有冒号（“原样”指原样拼接，服务端只能按第一个冒号拆） | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 [15] | 原样 | 原样 | 原样 | 原样 |

- [1] R60，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [2] R61，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [3] R62，`curl`：实际收到 27 字节，十六进制 73657373406162412b632f6420653a6b616f6a752d706173732d31，按 UTF-8 读是 'sess@abA+c/d e:kaoju-pass-1'；用例里的是 29 字节
- [4] R62，`curl-anyauth`：实际收到 27 字节，十六进制 73657373406162412b632f6420653a6b616f6a752d706173732d31，按 UTF-8 读是 'sess@abA+c/d e:kaoju-pass-1'；用例里的是 29 字节
- [5] R62，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [6] R63，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [7] R64，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [8] R65，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [9] R66，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [10] R67，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [11] R68，`curl`：实际收到 22 字节，十六进制 6b616f6a752d757365723a703a61407320732f772b64，按 UTF-8 读是 'kaoju-user:p:a@s s/w+d'；用例里的是 24 字节
- [12] R68，`curl-anyauth`：实际收到 22 字节，十六进制 6b616f6a752d757365723a703a61407320732f772b64，按 UTF-8 读是 'kaoju-user:p:a@s s/w+d'；用例里的是 24 字节
- [13] R68，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [14] R69，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。
- [15] R70，`node-undici`：读数须知：ProxyAgent 的凭据用 token 选项传（undici 文档的写法），Basic 后面的 base64 是调用方自己拼的，“原样”说明不了 undici 怎么处理用户名的字节。

## 代理报错时调用方能看到什么

| 行 | `curl` | `curl-anyauth` | `requests` | `go` | `node-fetch-env` | `node-http-env` | `node-undici` | `node-agents` | `node-axios` | `chromium-pw` | `firefox-pw` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R80 CONNECT 回 502：默认用法 | 状态码 | 状态码 | 状态码、原因短语 | 原因短语 | 状态码 | 状态码、原因短语 | 状态码 | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 | 都看不到 | 都看不到 |
| R81 CONNECT 回 502：加上需要主动打开的手段 | 状态码、原因短语、响应头 [1] | 状态码、原因短语、响应头 [2] | 状态码、原因短语、响应头 [3] | 状态码、原因短语、响应头、正文 [4] | 状态码、原因短语、响应头 [5] | 状态码、原因短语、响应头、正文 [6] | 状态码、原因短语、响应头 [7] | 状态码、原因短语、响应头、正文 [8] | 没有这样的手段 | 状态码、原因短语、响应头 [9] | 都看不到 [10] |
| R82 CONNECT 回 403：默认用法 | 状态码 | 状态码 | 状态码、原因短语 | 原因短语 | 状态码 | 状态码、原因短语 | 状态码 | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 | 都看不到 | 都看不到 |
| R83 CONNECT 回 503 带 Retry-After: 1：发了几次 CONNECT | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| R84 CONNECT 成功时 200 里附加的头：默认用法 | 看不到 | 看不到 | 看不到 | 看不到 | 看不到 | 看不到 | 看不到 | 看不到 | 看不到 | 看不到 | 看不到 |
| R85 CONNECT 成功时 200 里附加的头：加上需要主动打开的手段 | 看得到 [11] | 看得到 [12] | 看得到 [13] | 看得到 [14] | 看得到 [15] | 看得到 [16] | 看得到 [17] | 看得到 [18] | 没有这样的手段 | 看得到 [19] | 看不到 [20] |
| R86 明文请求被代理回 403：默认用法 | 状态码、正文 [21] | 状态码、正文 [22] | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 | 都看不到 [23] | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 | 状态码、原因短语、响应头、正文 |
| R87 明文请求成功时代理附加的响应头：默认用法 | 看不到 | 看不到 | 看得到 | 看得到 | 看不到 [24] | 看得到 | 看得到 | 看得到 | 看得到 | 看得到 | 看得到 |
| R88 CONNECT 失败但代理没关连接：下一个 CONNECT 走哪条连接 | 新连接 | 新连接 | 新连接 | 新连接 | 新连接 [25] | 新连接 | 新连接 [26] | 新连接 | 新连接 [27] | 新连接 | 新连接 |
| R89 CONNECT 失败之后，对另一个源的请求 | 成功 | 成功 | 成功 | 成功 | 成功 | 成功 | 成功 | 成功 | 成功 | 失败 [28] | 成功 |

- [1] R81，`curl`：手段：-v（加 --trace-ids 以便按传输切分）与 -D：同一个 curl 进程里打开详细输出，并把响应头另存到文件
- [2] R81，`curl-anyauth`：手段：-v（加 --trace-ids 以便按传输切分）与 -D：同一个 curl 进程里打开详细输出，并把响应头另存到文件
- [3] R81，`requests`：手段：http.client.HTTPConnection.debuglevel = 1（requests 文档 docs/api.rst“Migrating to 1.x”一节给出的调试写法）：标准库把发出的请求头和收到的响应头打印到标准输出，驱动用 contextlib.redirect_stdout 接下来
- [4] R81，`go`：手段：Transport.OnProxyConnectResponse（Go 1.20 起，net/http 的文档写明：收到代理对 CONNECT 的响应时调用，在检查 200 之前）。钩子只旁听、一定返回 nil：记下协议版本、状态行、响应头；状态码不是 200 时再读正文的前 4096 字节（最多等 1 秒）。记录归到发起这次拨号的那一步；一步里没有发出 CONNECT（复用了隧道、明文请求、SOCKS5）就没有记录
- [5] R81，`node-fetch-env`：手段：node:diagnostics_channel 订阅 'undici:request:headers' 频道，只记 CONNECT 请求的响应（状态码、原因短语、响应头；拿不到正文）。依据是 undici 自己的文档 docs/docs/api/DiagnosticsChannel.md；Node 的文档没有提到内置 fetch 也往这个频道发布，这里是实测能收到。；读数须知：用的手段是 diagnostics_channel 的 undici:request:headers 频道，写在 undici 的文档里；Node 自己的文档有没有写没有核对。
- [6] R81，`node-http-env`：手段：环境变量 NODE_DEBUG=https（doc/api/cli.md 的 NODE_DEBUG）：https 模块把调试信息打到标准错误，其中 onProxyData 一段是代理对 CONNECT 回的整块数据（状态行、响应头，以及同一块里的正文）。这是调试输出，格式不保证。驱动只摘出 onProxyData 开头的段落，其余的调试输出（请求选项的转储等）不记。
- [7] R81，`node-undici`：手段：node:diagnostics_channel 订阅 'undici:request:headers' 频道（undici 文档 docs/docs/api/DiagnosticsChannel.md），只记 CONNECT 请求的响应：状态码、原因短语、响应头；拿不到正文。
- [8] R81，`node-agents`：手段：req.on('proxyConnect', (connect) => …)：https-proxy-agent 在读完代理对 CONNECT 的响应以后，在请求对象（和 Agent 实例）上发这个事件，参数是 { statusCode, statusText, headers }，拿不到正文。依据是上游仓库的变更记录（6.1.0：Emit "proxyConnect" event on HTTP request object）和 dist/index.js；随包发布的 README 和类型声明里都没有提到它。只有经 HTTP 代理访问 https:// 目标的步骤有这个手段。；读数须知：用的手段是 https-proxy-agent 的 proxyConnect 事件：9.1.0 的 README 和类型声明里都没有写它，只在 dist/index.js 里有。按“文档写明的手段”从严算，这一格应是“没有这样的手段”。
- [9] R81，`chromium-pw`：手段：两样，都要主动打开：(1) Playwright 的 page.on('requestfailed') 事件里的 request.failure().errorText；(2) Chromium 的 NetLog：启动参数 --log-net-log=<文件>（经 Playwright 的 launch({args}) 传入，出处是 Chromium 的 net/docs/net-log.md，不在 Playwright 的文档里），浏览器关闭后读文件，取 CONNECT 的请求行、CONNECT 响应的状态行和响应头、SOCKS 的事件。两样都按发生时刻落在哪一步的时间窗里归属（并发的子步骤共用同一个时间窗）。；读数须知：用的手段是 NetLog（启动参数 --log-net-log），写在 Chromium 的文档里，不是 Playwright 的；它也是这一列唯一一处不是 Playwright 默认值的启动参数。
- [10] R81，`firefox-pw`：手段：Playwright 的 page.on('requestfailed') 事件里的 request.failure().errorText，按发生时刻落在哪一步的时间窗里归属（并发的子步骤共用同一个时间窗）。Firefox 的 MOZ_LOG 不在 Playwright 的文档里，没有采用。；读数须知：用的手段是 Playwright 的 page.on('requestfailed') 事件，它只给出一个错误名，没有响应的任何内容；Firefox 的 MOZ_LOG 不在 Playwright 的文档里，没有采用。这一格的“看不到”与“没有这样的手段”实质相同。
- [11] R85，`curl`：手段：-v（加 --trace-ids 以便按传输切分）与 -D：同一个 curl 进程里打开详细输出，并把响应头另存到文件
- [12] R85，`curl-anyauth`：手段：-v（加 --trace-ids 以便按传输切分）与 -D：同一个 curl 进程里打开详细输出，并把响应头另存到文件
- [13] R85，`requests`：手段：http.client.HTTPConnection.debuglevel = 1（requests 文档 docs/api.rst“Migrating to 1.x”一节给出的调试写法）：标准库把发出的请求头和收到的响应头打印到标准输出，驱动用 contextlib.redirect_stdout 接下来
- [14] R85，`go`：手段：Transport.OnProxyConnectResponse（Go 1.20 起，net/http 的文档写明：收到代理对 CONNECT 的响应时调用，在检查 200 之前）。钩子只旁听、一定返回 nil：记下协议版本、状态行、响应头；状态码不是 200 时再读正文的前 4096 字节（最多等 1 秒）。记录归到发起这次拨号的那一步；一步里没有发出 CONNECT（复用了隧道、明文请求、SOCKS5）就没有记录
- [15] R85，`node-fetch-env`：手段：node:diagnostics_channel 订阅 'undici:request:headers' 频道，只记 CONNECT 请求的响应（状态码、原因短语、响应头；拿不到正文）。依据是 undici 自己的文档 docs/docs/api/DiagnosticsChannel.md；Node 的文档没有提到内置 fetch 也往这个频道发布，这里是实测能收到。；读数须知：用的手段是 diagnostics_channel 的 undici:request:headers 频道，写在 undici 的文档里；Node 自己的文档有没有写没有核对。
- [16] R85，`node-http-env`：手段：环境变量 NODE_DEBUG=https（doc/api/cli.md 的 NODE_DEBUG）：https 模块把调试信息打到标准错误，其中 onProxyData 一段是代理对 CONNECT 回的整块数据（状态行、响应头，以及同一块里的正文）。这是调试输出，格式不保证。驱动只摘出 onProxyData 开头的段落，其余的调试输出（请求选项的转储等）不记。
- [17] R85，`node-undici`：手段：node:diagnostics_channel 订阅 'undici:request:headers' 频道（undici 文档 docs/docs/api/DiagnosticsChannel.md），只记 CONNECT 请求的响应：状态码、原因短语、响应头；拿不到正文。
- [18] R85，`node-agents`：手段：req.on('proxyConnect', (connect) => …)：https-proxy-agent 在读完代理对 CONNECT 的响应以后，在请求对象（和 Agent 实例）上发这个事件，参数是 { statusCode, statusText, headers }，拿不到正文。依据是上游仓库的变更记录（6.1.0：Emit "proxyConnect" event on HTTP request object）和 dist/index.js；随包发布的 README 和类型声明里都没有提到它。只有经 HTTP 代理访问 https:// 目标的步骤有这个手段。；读数须知：用的手段是 https-proxy-agent 的 proxyConnect 事件：9.1.0 的 README 和类型声明里都没有写它，只在 dist/index.js 里有。按“文档写明的手段”从严算，这一格应是“没有这样的手段”。
- [19] R85，`chromium-pw`：手段：两样，都要主动打开：(1) Playwright 的 page.on('requestfailed') 事件里的 request.failure().errorText；(2) Chromium 的 NetLog：启动参数 --log-net-log=<文件>（经 Playwright 的 launch({args}) 传入，出处是 Chromium 的 net/docs/net-log.md，不在 Playwright 的文档里），浏览器关闭后读文件，取 CONNECT 的请求行、CONNECT 响应的状态行和响应头、SOCKS 的事件。两样都按发生时刻落在哪一步的时间窗里归属（并发的子步骤共用同一个时间窗）。；读数须知：用的手段是 NetLog（启动参数 --log-net-log），写在 Chromium 的文档里，不是 Playwright 的；它也是这一列唯一一处不是 Playwright 默认值的启动参数。
- [20] R85，`firefox-pw`：手段：Playwright 的 page.on('requestfailed') 事件里的 request.failure().errorText，按发生时刻落在哪一步的时间窗里归属（并发的子步骤共用同一个时间窗）。Firefox 的 MOZ_LOG 不在 Playwright 的文档里，没有采用。；读数须知：用的手段是 Playwright 的 page.on('requestfailed') 事件，它只给出一个错误名，没有响应的任何内容；Firefox 的 MOZ_LOG 不在 Playwright 的文档里，没有采用。这一格的“看不到”与“没有这样的手段”实质相同。
- [21] R86，`curl`：读数须知：“状态码”来自驱动加的 -w '%{http_code}'。不加 -w 时 curl 对明文 403 的退出码是 0、标准错误为空，调用方只拿到正文（drivers/curl/NOTES.md“口径上的疑问”第 1 条；不加 -w 的对照没有进正式数据）。
- [22] R86，`curl-anyauth`：读数须知：“状态码”来自驱动加的 -w '%{http_code}'。不加 -w 时 curl 对明文 403 的退出码是 0、标准错误为空，调用方只拿到正文（drivers/curl/NOTES.md“口径上的疑问”第 1 条；不加 -w 的对照没有进正式数据）。
- [23] R86，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [24] R87，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [25] R88，`node-fetch-env`：失败响应的 close 为真而配置没有要求关连接（请求自带 Connection: close 或是 HTTP/1.0），之后换连接不是客户端在“代理留着连接”的前提下做的选择
- [26] R88，`node-undici`：失败响应的 close 为真而配置没有要求关连接（请求自带 Connection: close 或是 HTTP/1.0），之后换连接不是客户端在“代理留着连接”的前提下做的选择
- [27] R88，`node-axios`：失败响应的 close 为真而配置没有要求关连接（请求自带 Connection: close 或是 HTTP/1.0），之后换连接不是客户端在“代理留着连接”的前提下做的选择
- [28] R89，`chromium-pw`：读数须知：失败的是 page.goto：它被上一步失败后的错误页导航打断（Navigation … is interrupted by another navigation to chrome-error://chromewebdata/）。事件里第二个源的 CONNECT 得到了 200，源站也收到了请求。这一格说明不了代理有没有被标坏。

## 连接被关以后

| 行 | `curl` | `curl-anyauth` | `requests` | `go` | `node-fetch-env` | `node-http-env` | `node-undici` | `node-agents` | `node-axios` | `chromium-pw` | `firefox-pw` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R90 明文：空闲连接被代理关掉后再请求 | 换新连接，成功 | 换新连接，成功 | 换新连接，成功 | 换新连接，成功 | 其他：s2 成功，但代理端口上找不到 s1 或 s2 的请求 [1] | 换新连接，成功 | 换新连接，成功 | 换新连接，成功 [2] | 换新连接，成功 | 换新连接，成功 | 换新连接，成功 |
| R91 HTTPS：空闲隧道被代理关掉后再请求 | 换新隧道，成功 | 换新隧道，成功 | 换新隧道，成功 | 换新隧道，成功 | 换新隧道，成功 | 换新隧道，成功 | 换新隧道，成功 | 换新隧道，成功 [3] | 换新隧道，成功 [4] | 换新隧道，成功 | 换新隧道，成功 |
| R92 明文，复用的连接，GET，连接被关（FIN）：请求到达几次，结果 | 2 次，成功 | 2 次，成功 | 1 次，失败 | 2 次，成功 | 未触发 [5] | 1 次，失败 | 未触发 [6] | 未触发 [7] | 1 次，失败 | 2 次，成功 | 未触发 / 2 次，成功（不稳定） |
| R93 明文，复用的连接，POST，连接被关（FIN）：请求到达几次，结果 | 2 次，成功 | 2 次，成功 | 1 次，失败 | 1 次，失败 | 未触发 [8] | 1 次，失败 | 未触发 [9] | 未触发 [10] | 1 次，失败 | 2 次，成功 | 2 次，成功 |
| R94 HTTPS，复用的隧道，GET，隧道被切断（FIN）：请求到达几次，结果 | 2 次，成功 | 2 次，成功 | 1 次，失败 | 2 次，成功 | 未触发 [11] | 1 次，失败 | 未触发 [12] | 未触发 [13] | 未触发 [14] | 2 次，成功 | 2 次，成功 |
| R95 HTTPS，复用的隧道，POST，隧道被切断（FIN）：请求到达几次，结果 | 2 次，成功 | 2 次，成功 | 1 次，失败 | 1 次，失败 | 未触发 [15] | 1 次，失败 | 未触发 [16] | 未触发 [17] | 未触发 [18] | 2 次，成功 | 2 次，成功 |
| R96 明文，新连接上的第一个 GET，连接被关：请求到达几次，结果 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 未触发 [19] | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 2 次，成功 |
| R97 HTTPS，新隧道里的第一个 GET，隧道被切断：请求到达几次，结果 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 2 次，成功 |
| R98 明文，复用的连接，GET，连接被复位（RST）：请求到达几次，结果 | 2 次，成功 | 2 次，成功 | 1 次，失败 | 2 次，成功 | 未触发 [20] | 1 次，失败 | 未触发 [21] | 未触发 [22] | 1 次，失败 | 2 次，成功 | 未触发 / 2 次，成功（不稳定） |
| R99 HTTPS，复用的隧道，GET，隧道被复位（RST）：请求到达几次，结果 | 2 次，成功 | 2 次，成功 | 1 次，失败 | 2 次，成功 | 未触发 [23] | 1 次，失败 | 未触发 [24] | 未触发 [25] | 未触发 [26] | 2 次，成功 | 2 次，成功 |
| R100 CONNECT 发出后代理不回应就关连接：发了几次 CONNECT，结果 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 2 次，成功 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 1 次，失败 | 2 次，成功 |
| R101 HTTPS（源站支持 h2），复用的隧道，GET，隧道被切断：请求到达几次，结果 | 2 次，成功 | 2 次，成功 | 1 次，失败 | 1 次，失败 | 未触发 [27] | 1 次，失败 | 1 次，失败 | 未触发 [28] | 未触发 [29] | 2 次，成功 | 1 次，失败 |

- [1] R90，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [2] R90，`node-agents`：仪器的空闲关闭没有发生：新连接不是因为旧连接被代理关掉
- [3] R91，`node-agents`：仪器的空闲关闭没有发生：新隧道不是因为旧隧道被代理关掉
- [4] R91，`node-axios`：仪器的空闲关闭没有发生：新隧道不是因为旧隧道被代理关掉
- [5] R92，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [6] R92，`node-undici`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的连接上（见 R11、R122），仪器“只在复用的连接上断开”的条件没有满足，这一行要问的事对这一列没有测到。
- [7] R92，`node-agents`：读数须知：这一列每个请求都新开连接（R10、R11 是 3），没有复用的连接可断，所以是“未触发”。
- [8] R93，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [9] R93，`node-undici`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的连接上（见 R11、R122），仪器“只在复用的连接上断开”的条件没有满足，这一行要问的事对这一列没有测到。
- [10] R93，`node-agents`：读数须知：这一列每个请求都新开连接（R10、R11 是 3），没有复用的连接可断，所以是“未触发”。
- [11] R94，`node-fetch-env`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的隧道里（见 R10），仪器的条件没有满足，这一行要问的事对这一列没有测到。
- [12] R94，`node-undici`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的连接上（见 R11、R122），仪器“只在复用的连接上断开”的条件没有满足，这一行要问的事对这一列没有测到。
- [13] R94，`node-agents`：读数须知：这一列每个请求都新开连接（R10、R11 是 3），没有复用的连接可断，所以是“未触发”。
- [14] R94，`node-axios`：读数须知：这一列 HTTPS 每个请求都新开隧道（R10 是 3），没有复用的隧道可断，所以是“未触发”。
- [15] R95，`node-fetch-env`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的隧道里（见 R10），仪器的条件没有满足，这一行要问的事对这一列没有测到。
- [16] R95，`node-undici`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的连接上（见 R11、R122），仪器“只在复用的连接上断开”的条件没有满足，这一行要问的事对这一列没有测到。
- [17] R95，`node-agents`：读数须知：这一列每个请求都新开连接（R10、R11 是 3），没有复用的连接可断，所以是“未触发”。
- [18] R95，`node-axios`：读数须知：这一列 HTTPS 每个请求都新开隧道（R10 是 3），没有复用的隧道可断，所以是“未触发”。
- [19] R96，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [20] R98，`node-fetch-env`：读数须知：这一列的明文请求也走 CONNECT 到 80 端口（R01），仪器里只对绝对形式请求生效的配置（转发时回 403、附加响应头、断开连接、空闲关闭）不会触发，这一行要问的事对这一列没有测到。
- [21] R98，`node-undici`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的连接上（见 R11、R122），仪器“只在复用的连接上断开”的条件没有满足，这一行要问的事对这一列没有测到。
- [22] R98，`node-agents`：读数须知：这一列每个请求都新开连接（R10、R11 是 3），没有复用的连接可断，所以是“未触发”。
- [23] R99，`node-fetch-env`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的隧道里（见 R10），仪器的条件没有满足，这一行要问的事对这一列没有测到。
- [24] R99，`node-undici`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的连接上（见 R11、R122），仪器“只在复用的连接上断开”的条件没有满足，这一行要问的事对这一列没有测到。
- [25] R99，`node-agents`：读数须知：这一列每个请求都新开连接（R10、R11 是 3），没有复用的连接可断，所以是“未触发”。
- [26] R99，`node-axios`：读数须知：这一列 HTTPS 每个请求都新开隧道（R10 是 3），没有复用的隧道可断，所以是“未触发”。
- [27] R101，`node-fetch-env`：读数须知：“未触发”不是“不重发”：第二个请求落在了新开的隧道里（见 R10），仪器的条件没有满足，这一行要问的事对这一列没有测到。
- [28] R101，`node-agents`：读数须知：这一列每个请求都新开连接（R10、R11 是 3），没有复用的连接可断，所以是“未触发”。
- [29] R101，`node-axios`：读数须知：这一列 HTTPS 每个请求都新开隧道（R10 是 3），没有复用的隧道可断，所以是“未触发”。

## SOCKS5 入口

| 行 | `curl` | `curl-anyauth` | `requests` | `go` | `node-fetch-env` | `node-http-env` | `node-undici` | `node-agents` | `node-axios` | `chromium-pw` | `firefox-pw` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R110 没配凭据时提供的认证方法 | 00,01 | 00,01 | 00 | 00 | 不支持 [1] | 不支持 [2] | 00 | 00 | 不支持 [3] | 00 | 00 |
| R111 配了凭据时提供的认证方法 | 00,01,02 | 00,01,02 | 00,02 | 00,02 | 不支持 [4] | 不支持 [5] | 02,00 | 00,02 | 不支持 [6] | 不支持 [7] | 不支持 [8] |
| R112 socks5h：请求里的地址类型 | 域名 | 域名 | 域名 | 域名 | 不支持 [9] | 不支持 [10] | 域名 | 域名 | 不支持 [11] | 域名 | 域名 |
| R113 socks5（客户端自己解析），目标是 localhost：请求里的地址类型 | IPv6 [12] | IPv6 [13] | IPv4 [14] | 域名 [15] | 不支持 [16] | 不支持 [17] | 域名 [18] | IPv4 [19] | 不支持 [20] | 域名 [21] | 域名 [22] |
| R114 socks5（客户端自己解析），域名本机解析不了 | 其他 [23] | 其他 [24] | 其他 [25] | 把域名交给了代理 | 不支持 [26] | 不支持 [27] | 把域名交给了代理 | 没连代理就报错 | 不支持 [28] | 把域名交给了代理 | 把域名交给了代理 |
| R115 SOCKS5 建好以后的首包（HTTPS） | TLS ClientHello | TLS ClientHello | TLS ClientHello | TLS ClientHello | 不支持 [29] | 不支持 [30] | TLS ClientHello | TLS ClientHello | 不支持 [31] | TLS ClientHello | TLS ClientHello |
| R116 SOCKS5 建好以后的首包（明文） | 明文 HTTP | 明文 HTTP | 明文 HTTP | 明文 HTTP | 不支持 [32] | 不支持 [33] | 明文 HTTP | 明文 HTTP | 不支持 [34] | 明文 HTTP | 明文 HTTP |
| R117 用户名密码认证，凭据正确 | 成功 | 成功 | 成功 | 成功 | 不支持 [35] | 不支持 [36] | 成功 | 成功 | 不支持 [37] | 不支持 [38] | 不支持 [39] |
| R118 配了凭据而代理选了无认证 | 成功 | 成功 | 成功 | 成功 | 不支持 [40] | 不支持 [41] | 成功 | 成功 | 不支持 [42] | 不支持 [43] | 不支持 [44] |
| R119 代理回 0xFF（没有可接受的方法）时的报错 | 提到认证或方法 [45] | 提到认证或方法 [46] | 提到认证或方法 | 提到认证或方法 | 不支持 [47] | 不支持 [48] | 提到认证或方法 | 提到认证或方法 | 不支持 [49] | 只说失败 | 只说失败 |
| R120 用户名密码不对时的报错 | 只说失败 [50] | 只说失败 [51] | 提到认证或方法 | 提到认证或方法 | 不支持 [52] | 不支持 [53] | 提到认证或方法 | 提到认证或方法 | 不支持 [54] | 不支持 [55] | 不支持 [56] |
| R121 应答码 2、4、5 的报错能否区分 | 能区分 | 能区分 | 能区分 | 能区分 | 不支持 [57] | 不支持 [58] | 能区分 | 能区分 | 不支持 [59] | 不能区分 | 不能区分 |
| R122 HTTPS 同一个源连续 3 次：SOCKS5 连接数 | 1 | 1 | 1 | 1 | 不支持 [60] | 不支持 [61] | 2 | 3 | 不支持 [62] | 1 | 1 / 2（不稳定） |
| R123 HTTPS 6 个并发（源站只说 HTTP/1.1）：SOCKS5 连接数 | 6 | 6 | 6 | 6 | 不支持 [63] | 不支持 [64] | 6 | 6 | 不支持 [65] | 6 | 6 |
| R124 同一个进程两个用户交替 | 各开各的连接 | 各开各的连接 | 各开各的连接 | 用了别人的连接 [66] | 不支持 [67] | 不支持 [68] | 各开各的连接 | 各开各的连接 | 不支持 [69] | 不支持 [70] | 不支持 [71] |
| R125 SOCKS5 用户名密码：常见的参数写法（连字符） | 原样 | 原样 | 原样 | 原样 | 不支持 [72] | 不支持 [73] | 原样 | 原样 | 不支持 [74] | 不支持 [75] | 不支持 [76] |
| R126 SOCKS5 用户名密码：要转义的字符：@ % + / 和空格 | 变了 [77] | 变了 [78] | 原样 | 原样 | 不支持 [79] | 不支持 [80] | 变了 [81] | 原样 | 不支持 [82] | 不支持 [83] | 不支持 [84] |
| R127 SOCKS5 用户名密码：UTF-8 用户名 | 原样 | 原样 | 原样 | 原样 | 不支持 [85] | 不支持 [86] | 变了 [87] | 原样 | 不支持 [88] | 不支持 [89] | 不支持 [90] |
| R128 SOCKS5 用户名密码：用户名 255 字节 | 原样 | 原样 | 变了 [91] | 原样 | 不支持 [92] | 不支持 [93] | 原样 | 原样 | 不支持 [94] | 不支持 [95] | 不支持 [96] |
| R129 SOCKS5 用户名密码：用户名 256 字节（超出 RFC 1929 的上限） | 客户端报错 | 客户端报错 | 变了 [97] | 客户端报错 | 不支持 [98] | 不支持 [99] | 客户端报错 | 客户端报错 | 不支持 [100] | 不支持 [101] | 不支持 [102] |
| R130 SOCKS5 用户名密码：密码里有冒号、@、空格、%2F、加号 | 变了 [103] | 变了 [104] | 原样 | 原样 | 不支持 [105] | 不支持 [106] | 变了 [107] | 原样 | 不支持 [108] | 不支持 [109] | 不支持 [110] |
| R131 SOCKS5 用户名密码：空密码 | 原样 | 原样 | 客户端报错 | 原样 | 不支持 [111] | 不支持 [112] | 客户端报错 | 原样 | 不支持 [113] | 不支持 [114] | 不支持 [115] |
| R132 SOCKS5 用户名密码：用户名里有冒号 | 变了 [116] | 变了 [117] | 原样 | 原样 | 不支持 [118] | 不支持 [119] | 变了 [120] | 原样 | 不支持 [121] | 不支持 [122] | 不支持 [123] |

- [1] R110，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [2] R110，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [3] R110，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [4] R111，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [5] R111，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [6] R111，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [7] R111，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [8] R111，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [9] R112，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [10] R112，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [11] R112，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [12] R113，`curl`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [13] R113，`curl-anyauth`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [14] R113，`requests`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [15] R113，`go`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [16] R113，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)；读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [17] R113，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)；读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [18] R113，`node-undici`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [19] R113，`node-agents`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [20] R113，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。；读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [21] R113，`chromium-pw`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [22] R113，`firefox-pw`：读数须知：取值取决于本机 localhost 解析出来的第一个地址，换一台机器可能不同。
- [23] R114，`curl`：代理端口上有 1 条连接，没有 socks5_request；驱动 ok=False；读数须知：“其他”指的是行表没有列出的一种情况：先连上代理、协商完认证方法，然后才在本机解析目标域名，解析失败就报错，没有发出 SOCKS5 请求。
- [24] R114，`curl-anyauth`：代理端口上有 1 条连接，没有 socks5_request；驱动 ok=False；读数须知：“其他”指的是行表没有列出的一种情况：先连上代理、协商完认证方法，然后才在本机解析目标域名，解析失败就报错，没有发出 SOCKS5 请求。
- [25] R114，`requests`：代理端口上有 1 条连接，没有 socks5_request；驱动 ok=False；读数须知：“其他”指的是行表没有列出的一种情况：先连上代理、协商完认证方法，然后才在本机解析目标域名，解析失败就报错，没有发出 SOCKS5 请求。
- [26] R114，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [27] R114，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [28] R114，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [29] R115，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [30] R115，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [31] R115，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [32] R116，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [33] R116，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [34] R116，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [35] R117，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [36] R117，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [37] R117，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [38] R117，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [39] R117，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [40] R118，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [41] R118，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [42] R118，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [43] R118，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [44] R118，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [45] R119，`curl`：读数须知：关键词表是实测前定的，没有收 curl 的说法：curl 在用户名密码被拒时报的是 User was rejected by the SOCKS5 server，说的是认证，但不含表里的词，R120 因此记成“只说失败”。原文在 default_text 里。
- [46] R119，`curl-anyauth`：读数须知：关键词表是实测前定的，没有收 curl 的说法：curl 在用户名密码被拒时报的是 User was rejected by the SOCKS5 server，说的是认证，但不含表里的词，R120 因此记成“只说失败”。原文在 default_text 里。
- [47] R119，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [48] R119，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [49] R119，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [50] R120，`curl`：读数须知：关键词表是实测前定的，没有收 curl 的说法：curl 在用户名密码被拒时报的是 User was rejected by the SOCKS5 server，说的是认证，但不含表里的词，R120 因此记成“只说失败”。原文在 default_text 里。
- [51] R120，`curl-anyauth`：读数须知：关键词表是实测前定的，没有收 curl 的说法：curl 在用户名密码被拒时报的是 User was rejected by the SOCKS5 server，说的是认证，但不含表里的词，R120 因此记成“只说失败”。原文在 default_text 里。
- [52] R120，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [53] R120，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [54] R120，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [55] R120，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [56] R120，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [57] R121，`node-fetch-env`：S09：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)；S10：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)；S11：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [58] R121，`node-http-env`：S09：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)；S10：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)；S11：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [59] R121，`node-axios`：S09：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。；S10：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。；S11：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [60] R122，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [61] R122，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [62] R122，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [63] R123，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [64] R123，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [65] R123，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [66] R124，`go`：s2 走的隧道是 'kaoju-user' 建的；读数须知：前提是驱动的写法：同一个 http.Transport，Proxy 函数按请求返回不同用户的代理 URL（drivers/go/NOTES.md 第 3 节写法 a）。每个用户一个 Transport 的写法没有测。
- [67] R124，`node-fetch-env`：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。
- [68] R124，`node-http-env`：不支持的原因：环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。
- [69] R124，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [70] R124，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browser.newContext: Browser does not support socks5 proxy authentication"
- [71] R124，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browser.newContext: Browser does not support socks5 proxy authentication"
- [72] R125，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [73] R125，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [74] R125，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [75] R125，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [76] R125，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [77] R126，`curl`：用户名实际收到 14 字节，十六进制 73657373406162412b632f642065，按 UTF-8 读是 'sess@abA+c/d e'；用例里的是 16 字节
- [78] R126，`curl-anyauth`：用户名实际收到 14 字节，十六进制 73657373406162412b632f642065，按 UTF-8 读是 'sess@abA+c/d e'；用例里的是 16 字节
- [79] R126，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [80] R126，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [81] R126，`node-undici`：用户名实际收到 26 字节，十六进制 7365737325343061622532353431253242632532466425323065，按 UTF-8 读是 'sess%40ab%2541%2Bc%2Fd%20e'；用例里的是 16 字节
- [82] R126，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [83] R126，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [84] R126，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [85] R127，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [86] R127，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [87] R127，`node-undici`：用户名实际收到 38 字节，十六进制 2545372539342541382545362538382542372d732543332541397373696f6e2d254333253946，按 UTF-8 读是 '%E7%94%A8%E6%88%B7-s%C3%A9ssion-%C3%9F'；用例里的是 18 字节
- [88] R127，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [89] R127，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [90] R127，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [91] R128，`requests`：用户名实际收到 195 字节，十六进制开头 bf6b616f6a752d73657373696f6e2d303132333435363738396162636465663031323334353637383961626364656630…结尾 34353637383961626364656630313233，SHA-256 b68bddb5a79e77d13b0c2dfb87e2567aa61c9bf77b21fe48d1737e2978b70f88；用例里的是 255 字节；密码实际收到 52 字节，十六进制 35363738396162636465663031323334353637383961626364656630313233343536373839616263646566303132333435363738，按 UTF-8 读是 '56789abcdef0123456789abcdef0123456789abcdef012345678'；用例里的是 12 字节
- [92] R128，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [93] R128，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [94] R128，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [95] R128，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [96] R128，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [97] R129，`requests`：用户名实际收到 196 字节，十六进制开头 806b616f6a752d73657373696f6e2d303132333435363738396162636465663031323334353637383961626364656630…结尾 35363738396162636465663031323334，SHA-256 3757e0513dd1419b19b7c9343f2bef31f4c83b9bdebdbff18c890bf5540660e2；用例里的是 256 字节；密码实际收到 53 字节，十六进制 3637383961626364656630313233343536373839616263646566303132333435363738396162636465663031323334353637383961，按 UTF-8 读是 '6789abcdef0123456789abcdef0123456789abcdef0123456789a'；用例里的是 12 字节
- [98] R129，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [99] R129，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [100] R129，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [101] R129，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [102] R129，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [103] R130，`curl`：密码实际收到 11 字节，十六进制 703a61407320732f772b64，按 UTF-8 读是 'p:a@s s/w+d'；用例里的是 13 字节
- [104] R130，`curl-anyauth`：密码实际收到 11 字节，十六进制 703a61407320732f772b64，按 UTF-8 读是 'p:a@s s/w+d'；用例里的是 13 字节
- [105] R130，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [106] R130，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [107] R130，`node-undici`：密码实际收到 23 字节，十六进制 7025334161253430732532307325323532467725324264，按 UTF-8 读是 'p%3Aa%40s%20s%252Fw%2Bd'；用例里的是 13 字节
- [108] R130，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [109] R130，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [110] R130，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [111] R131，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [112] R131，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [113] R131，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [114] R131，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [115] R131，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
- [116] R132，`curl`：用户名实际收到 4 字节，十六进制 73657373，按 UTF-8 读是 'sess'；用例里的是 9 字节；密码实际收到 17 字节，十六进制 616231323a6b616f6a752d706173732d31，按 UTF-8 读是 'ab12:kaoju-pass-1'；用例里的是 12 字节
- [117] R132，`curl-anyauth`：用户名实际收到 4 字节，十六进制 73657373，按 UTF-8 读是 'sess'；用例里的是 9 字节；密码实际收到 17 字节，十六进制 616231323a6b616f6a752d706173732d31，按 UTF-8 读是 'ab12:kaoju-pass-1'；用例里的是 12 字节
- [118] R132，`node-fetch-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [119] R132，`node-http-env`：不支持的原因：这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。仍然把 socks5h:// 的地址照样写进这两个变量试了一次。 试了一次：内层 node 进程的退出码是 1，标准错误的头一段：node:internal/deps/undici/undici:1406 \|         throw new InvalidArgumentError("Invalid URL protocol: the URL must start with `http:` or `https:`."); \|         ^ \|  \| InvalidArgumentError: Invalid URL protocol: the URL must start with `http:` or `https:`. \|     at parseURL (node:internal/deps/undici/undici:1406:15)
- [120] R132，`node-undici`：用户名实际收到 11 字节，十六进制 7365737325334161623132，按 UTF-8 读是 'sess%3Aab12'；用例里的是 9 字节
- [121] R132，`node-axios`：不支持的原因：axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。仍然把 protocol 写成 "socks5h" 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。
- [122] R132，`chromium-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launch: Browser does not support socks5 proxy authentication"
- [123] R132，`firefox-pw`：不支持的原因：Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 "Error: browserType.launchPersistentContext: Browser does not support socks5 proxy authentication"
