# node 驱动笔记

这个文件分两部分，各由一个人写：“内置与 undici”（`node-fetch-env`、`node-http-env`、`node-undici` 三列）和“第三方 Agent 与 axios”（`node-agents`、`node-axios` 两列）。

## 内置与 undici

写给实现 `node-fetch-env`、`node-http-env`、`node-undici` 三列驱动的人。2026-11-10 写成，
**只读了文档和源码，没有让这些客户端连过任何代理**（运行过的只有 `node --help`、`node -p process.versions` 和 `node -p tls.DEFAULT_ECDH_CURVE`）。
这里的每一条都还没有被实测证实；实测对不上的以实测为准，并记进报告的“与预期不符”。
逐行预期在 `research/phase2/expectations/node-fetch-env.json`、`node-http-env.json`、`node-undici.json`。

### 读的是哪个版本

| 部件 | 版本 | 来源 |
| --- | --- | --- |
| Node.js | v22.23.4（本机；OpenSSL 3.5.9，随 Node 一起编译） | `nodejs/node` 标签 `v22.23.4` 的 `lib/`、`doc/api/` |
| 内置 undici | 6.29.1（`process.versions.undici`） | 同一标签的 `deps/undici/src/lib/` |
| npm 的 undici | 8.12.4（`dist-tags.latest`，2026-11-05 发布，要求 Node ≥ 22.19.0） | `npm pack undici` 解包 |
| 对比用的旧版 undici | 6.21.3、6.22.0、7.4.0 到 7.30.2 里的几个、8.0.0 到 8.12.0 的各个 x.y.0 | `npm pack undici@版本`，只看 `proxy-agent.js`、`connect.js`、`pool.js` |

下文的出处：`node:` 是 Node 标签 v22.23.4 里的路径，`u6:` 是内置 undici 6.29.1 的 `deps/undici/src/lib/`，
`u8:` 是 npm 包 8.12.4 的 `lib/`，行号是这些版本的。

### 0. 先看这几个会改变结果的选择

预期文件是按下面“建议”的写法填的。换一种写法，括号里的格子会变。

| 选择 | 建议 | 换一种写法会怎样 |
| --- | --- | --- |
| `node-undici` 的版本 | `package-lock.json` 固定 8.12.4 | 8.7.0 之前明文请求也先 CONNECT 到 80 端口（R01 等二十来行跟着变）；8.11.0 之前没有协议探测（R14）；8.6.0 之前代理掐断 CONNECT 会不停重连（R100）；8.2.0 之前 URL 里的空密码不发凭据（R69）；8.0.0 之前不谈 h2（R08、R09） |
| `node-undici` 的 HTTP 代理凭据 | 文档的写法：`token: 'Basic ' + base64(用户名:密码)` | 写在 `uri` 的 userinfo 里也行，但两段都要先 `encodeURIComponent`；结果相同 |
| `node-undici` 的 SOCKS5 凭据 | 写在 `socks5://` URL 的 userinfo 里（`ProxyAgent` 没有别的入口） | 直接用 `Socks5ProxyAgent` 加 `username`、`password` 选项时字节原样到达，R126、R127、R130、R132 从“变了”变成“原样”，R131 仍然报错（见第 2 节） |
| 环境变量里的凭据 | 用户名、密码各自 `encodeURIComponent` | 不转义：`@`、`/`、空格、`:` 会让 URL 拆错或解析失败；`%41` 会被还原成 `A` |
| POST 的正文 | 读成一整块 `Buffer` 再给 | 给流：`http` 模块和 undici 都改用 chunked（R19），undici 的流正文也不能在连接上排队 |
| 信任测试 CA | 环境变量 `NODE_EXTRA_CA_CERTS=ca.pem` | 用 `ca` 选项会替换掉默认的根证书，undici 还要分别传 `requestTls`、`connect`，容易漏掉某条路径 |
| 报错怎么记 | 把 `err.name`、`err.code`、`err.message` 连同整条 `cause` 链都写进 `default_text` | `fetch` 的顶层消息永远是 `fetch failed`，状态码只在 `cause` 里；只记顶层的话 R46、R49、R50、R80、R82、R119 到 R121 全变成“没提”“都看不到”“不能区分” |

### 1. 代理怎么配

#### `node-fetch-env` 和 `node-http-env`：环境变量

文档：`doc/api/http.md` 的“Built-in Proxy Support”（v22.21.0 加入，稳定性 1.1）、`doc/api/cli.md` 的 `NODE_USE_ENV_PROXY=1` 和 `--use-env-proxy`。

```sh
NODE_USE_ENV_PROXY=1 \
HTTP_PROXY=http://<用户名>:<密码>@127.0.0.1:<端口> \
HTTPS_PROXY=http://<用户名>:<密码>@127.0.0.1:<端口> \
NODE_EXTRA_CA_CERTS=<ca.pem> \
node driver.mjs 用例.json 结果.json
```

- 两个变量都要设：`HTTP_PROXY` 管 `http://` 的目标，`HTTPS_PROXY` 管 `https://` 的目标。
  `http` 模块没设 `HTTPS_PROXY` 时 HTTPS 请求直连（`node:lib/internal/http.js:204-209`）；
  `fetch` 没设 `HTTPS_PROXY` 时退回用 `HTTP_PROXY`（`u6:dispatcher/env-http-proxy-agent.js:42-47`）。两者不一样，所以都设上。
  小写的 `http_proxy`、`https_proxy`、`no_proxy` 优先于大写，驱动启动前要把继承来的大小写两套都清掉。
- 变量是进程启动时读的：`fetch` 的全局 dispatcher 在启动阶段建好（`node:lib/internal/process/pre_execution.js:194-206`），
  `http`、`https` 的全局 Agent 在创建时取 `process.env` 的快照（`node:lib/_http_agent.js:720-722`、`node:lib/https.js:636-638`）。
  **在进程里改 `process.env` 不会改变已经建好的代理配置**。用例是从文件里读的，所以驱动得分两层：
  外层读用例、拼好环境变量，再启动一个子进程跑整个用例（一个用例一个进程，满足“同一个客户端实例”的要求）。
- 凭据：写在 URL 的 userinfo 里，两段各自 `encodeURIComponent`。两种实现都是 `new URL()` 之后对 `username`、`password`
  分别 `decodeURIComponent`，拼成 `用户名:密码`，按 UTF-8 做 base64
  （`http` 模块：`node:lib/internal/http.js:114-137`；`fetch`：`u6:dispatcher/proxy-agent.js:108-109、:127-128`）。
  - `http` 模块的条件是 `username || password`：空密码发 `用户名:`。
  - 内置 `fetch` 的条件是 `username && password`：**空密码时什么凭据都不发**（D10 会拿到 407 而报错）。
  - `+` 是字面量，不会被当成空格。
- `NO_PROXY` 没设时没有任何例外，`localhost` 和 `127.0.0.1` 也经代理
  （`node:lib/internal/http.js:138-142、:151-155`；`u6:dispatcher/env-http-proxy-agent.js:99-101`）。不要设 `NO_PROXY`。
- 内置 `fetch` 启动时会打一条 `EnvHttpProxyAgent is experimental` 的警告到标准错误（`u6:dispatcher/env-http-proxy-agent.js:24-29`），不影响行为。
- **这两列不支持 SOCKS5**，S 组报 `unsupported`。`http.md` 的“Proxy URL Format”只列了 `http://`、`https://`；
  `http` 模块对别的协议直接忽略（`node:lib/internal/http.js:218-220`，请求会直连）；内置 undici 6.29.1 没有 SOCKS 的代码，
  `ProxyAgent` 拿到 `socks5://` 时抛 `InvalidArgumentError: Invalid URL protocol`（`u6:core/util.js:138-139、:205-206`），
  而它是启动阶段建的。也就是说把 `socks5://` 写进这两个变量再加 `NODE_USE_ENV_PROXY=1`，进程多半在跑到驱动代码之前就退出
  （两列都一样，因为启动阶段总会建 `fetch` 的 dispatcher）。按方案“能试的都要试”，可以让外层试一次，把子进程的标准错误记进 `unsupported` 的说明里。

#### `node-undici`：显式的 `ProxyAgent`

文档：npm 包里的 `docs/docs/api/ProxyAgent.md`、`Socks5ProxyAgent.md`。

```js
import { ProxyAgent, fetch, request } from 'undici'   // fetch 也要从 undici 引入，不要用全局的

// HTTP 代理，凭据用 token（文档的“proxy request with authentication”）
const agent = new ProxyAgent({
  uri: 'http://127.0.0.1:' + port,
  token: 'Basic ' + Buffer.from(user + ':' + pass).toString('base64'),
})
const res = await fetch(url, { dispatcher: agent })

// SOCKS5 代理（7.23.0 起，标为 Experimental，第一次构造时打一条 ExperimentalWarning）
const socks = new ProxyAgent('socks5://' + encodeURIComponent(user) + ':' + encodeURIComponent(pass) + '@127.0.0.1:' + port)
```

- **全局的 `fetch` 是内置 undici 6.29.1 实现的，把 npm 的 `ProxyAgent`（8.12.4）传给它是跨版本混用**：
  两个版本的 handler 接口不同（8.x 用 `onResponseStart`、`onRequestUpgrade`，6.x 用 `onHeaders`、`onUpgrade`），
  测到的也不再是 npm 这一份的行为。这一列一律用从 `undici` 引入的 `fetch` 或 `request`。
- `token` 原样当作 `proxy-authorization` 的值；`auth`（只给 base64 部分）已标为废弃；
  URL 里的 userinfo 会被 `decodeURIComponent` 后做 base64（`u8:dispatcher/proxy-agent.js:134-145`）。三者里 `token` 优先。
- 请求自己的头里不能出现 `Proxy-Authorization`，`dispatch` 会抛 `InvalidArgumentError: Proxy-Authorization should be sent in ProxyAgent constructor`
  （`u8:dispatcher/proxy-agent.js:278-279、:389-395`）。
- SOCKS5 只认 `socks5:` 和 `socks:` 两种写法（`u8:dispatcher/proxy-agent.js:157、:194`、`socks5-proxy-agent.js:61`）。
  没有 `socks5h`，也没有“客户端自己解析”的模式：域名一律交给代理（`Socks5ProxyAgent.md`：“DNS resolution is delegated to the proxy”，
  `u8:core/socks5-utils.js:12-40`）。用例里 `socks5` 和 `socks5h` 两种都写成 `socks5://`，在结果里说明。
  写成 `socks5h://` 的话它会被当成 HTTP 代理的地址，构造时就抛 `Invalid URL protocol`。

### 2. 同一个进程里对不同请求用不同的代理凭据

- `node-fetch-env`、`node-http-env`：**没有**。环境变量一个进程只有一份，启动时读一次（见第 1 节）。B11、B12、S14 报 `unsupported`。
  文档里有不靠环境变量的办法：`new http.Agent({ proxyEnv: { HTTP_PROXY: … } })`（`http.md`“Built-in Proxy Support”）、
  `new EnvHttpProxyAgent({ httpProxy, httpsProxy })` 或 `ProxyAgent` 作 `fetch` 的 `dispatcher`，但那已经不是“环境变量”这两列测的写法。
- `node-undici`：每个用户一个 `ProxyAgent`，按请求传 `dispatcher`。凭据是构造参数，没有按请求改的入口；
  每个 `ProxyAgent` 有自己的连接池，隧道不会串。整个用例里同一个用户始终用同一个实例，否则看不到复用。

  ```js
  const agents = users.map(u => new ProxyAgent({ uri, token: 'Basic ' + Buffer.from(u.user + ':' + u.pass).toString('base64') }))
  await fetch(url, { dispatcher: agents[step.user] })
  ```

- SOCKS5 的凭据有一个坑：经 `ProxyAgent` 配置时，URL 里的用户名、密码**不解码**就发给代理。
  `u8:dispatcher/proxy-agent.js:126、:162-163` 把 `URL` 对象上还带着百分号的 `username`、`password` 当作选项传下去，
  而 `u8:dispatcher/socks5-proxy-agent.js:84-87` 里选项优先于它自己解码出来的值。结果：只含字母、数字、`-`、`_`、`.`、`~` 的凭据原样到达，
  含 `@`、`%`、`+`、`/`、空格、冒号或非 ASCII 字符的，到达代理的是百分号转义后的字符串。
  直接用 `new Socks5ProxyAgent(url, { username, password })` 没有这个问题，但那不是这一列的写法。
  另外两处限制：用户名或密码超过 255 字节时抛 `InvalidArgumentError: Username or password too long`（`u8:core/socks5-client.js:229-234`）；
  密码为空时只提供“无认证”这一种方法（`:84-87`），代理要求认证就失败。

### 3. 信任测试用的 CA

三列都用环境变量 `NODE_EXTRA_CA_CERTS=<ca.pem>`（`cli.md`：把文件里的证书加进默认的根证书；进程启动时读，之后改 `process.env` 无效）。
它只扩充默认的信任根，不碰代理、ALPN、连接池。外层启动子进程时一起设上。

不要用的写法：

- `NODE_TLS_REJECT_UNAUTHORIZED=0`、`rejectUnauthorized: false`：关闭校验，项目规矩不允许。
- `ca` 选项：`cli.md` 写明显式给了 `ca` 就不再用默认的和附加的根证书；undici 里它得写在 `requestTls`（隧道里到源站的 TLS）上，
  不经隧道的路径又是另一个选项，SOCKS5 路径再是一处（`u8:dispatcher/socks5-proxy-agent.js:256-260`），容易漏，而且等于为测试改了客户端的构造参数。
- `--use-system-ca`、`--use-openssl-ca`：改变整个信任库的来源。

### 4. 并发、重定向、POST

```js
// 并发 6 个：三列都是 Promise.all，同一轮里发出
await Promise.all(steps.map(s => one(s)))
```

| | `node-fetch-env`（全局 `fetch`） | `node-http-env`（`http.get`、`https.request`） | `node-undici` |
| --- | --- | --- | --- |
| 发请求 | `await fetch(url)` | `http.get(url, cb)` 或 `https.get(url, cb)`，按 URL 的协议选模块；包成 Promise，监听 `response` 和 `error` | `await fetch(url, { dispatcher })`，或 `await request(url, { dispatcher })` |
| 重定向 | 默认跟随（`redirect: 'follow'`）；`follow` 为假的步骤写 `redirect: 'manual'` | 不跟随，没有开关。驱动自己读 3xx 的 `Location`，用 `new URL(location, 当前URL)` 解析后再发；注意把上一个响应的正文读完或 `res.resume()`，否则连接回不到空闲池 | `fetch` 默认跟随；`request` 默认不跟随，要 `agent.compose(interceptors.redirect({ maxRedirections: 5 }))`（`Interceptors.md`；`request` 的 `maxRedirections` 选项已经不支持，`u8:core/request.js:162-163`） |
| POST | `fetch(url, { method: 'POST', body: buf, headers: { 'content-type': 'application/octet-stream' } })` | `const req = http.request(url, { method: 'POST', headers: { 'Content-Type': …, 'Content-Length': buf.length } }, cb); req.end(buf)` | 同左列的 `fetch`，或 `request(url, { method: 'POST', body: buf, headers })` |
| 正文读完 | `await res.arrayBuffer()` | 累积 `data` 事件直到 `end` | `fetch` 同左；`request` 是 `await body.arrayBuffer()` |

- 每个响应都要把正文读完再发下一步。不读完的话 `http` 模块的套接字不会回到空闲池，undici 的连接也一直算忙，连接复用的行就测歪了。
- 连续的步骤之间不要插入等待：undici 的空闲连接默认 4 秒后自己关（`keepAliveTimeout`，`u6:dispatcher/client.js:231`、`u8` 同），
  `http` 的全局 Agent 是 `keepAlive: true`、`timeout: 5000`（`node:lib/_http_agent.js:720`；Node 19 起全局 Agent 默认保持连接）。F01、F02 的 3 秒等待在这两个时限之内。
- 并发上限：`http.Agent` 的 `maxSockets` 默认无限（`node:lib/_http_agent.js:308`）；undici 的 `Pool` 默认不限连接数、每条连接 `pipelining` 为 1
  （`u6:dispatcher/pool.js:69`、`client.js:229`）。都不要改。
- `node-undici` 建议统一用 `fetch`（默认跟随重定向，`Response` 上有 `statusText`）。`request` 也可以，矩阵里的取值应当相同，
  区别只在 R02 之外看不到的那些头（`fetch` 会多发 `accept`、`accept-language`、`sec-fetch-mode`、`user-agent`、`accept-encoding`）。
- 超时：`fetch` 用 `signal: AbortSignal.timeout(毫秒)`；`http` 模块用 `req.setTimeout` 或 `signal`。超时时限按用例的 `timeout_s`。
- WebSocket（A15、A16，只有 `node-fetch-env` 跑）：用全局的 `new WebSocket(url)`。它的握手走内置 undici 的 `fetch` 通道，
  没另给 dispatcher 时用全局的（`u6:web/websocket/connection.js:105`、`u6:web/fetch/index.js:370`），也就是环境变量建的那个，所以会经代理。
  `ws` 步骤里的 `page` 字段是给浏览器用的，Node 不用管。记下 `open`、`close`（`code`、`reason`）、`error` 事件。

### 5. 请求经代理时的样子（写驱动时对照用）

| | `node-fetch-env`（6.29.1） | `node-http-env` | `node-undici`（8.12.4） |
| --- | --- | --- | --- |
| `http://` 目标 | **先 `CONNECT 主机:80`，再在隧道里发普通请求**（`proxyTunnel` 默认 `true`，`u6:dispatcher/proxy-agent.js:106、:137-143`） | 绝对形式：`GET http://主机/路径`，头是 `Host`、[`proxy-authorization`、]`proxy-connection: keep-alive`、`Connection: keep-alive`（`node:lib/_http_client.js:149-189`） | 绝对形式，头是 `host`、`connection: keep-alive`、[`proxy-authorization`、]其余（`u8:dispatcher/proxy-agent.js:41-43、:78-89`） |
| `https://` 目标 | `CONNECT 主机:443 HTTP/1.1`，头：`host: 主机`（不带端口）、`connection: close`、[`proxy-authorization`] | `CONNECT 主机:443 HTTP/1.1`，头：[`proxy-authorization`、]`proxy-connection: keep-alive`、`host: 主机:443`（`node:lib/https.js:188-198`） | 同第一列，多一个 `proxy-connection: keep-alive`（`u8:dispatcher/proxy-agent.js:221-225`） |
| 凭据 | 只在 CONNECT 上，先带 | 每个明文请求和每个 CONNECT 上，先带 | 每个明文请求和每个 CONNECT 上，先带 |
| 隧道里的 ALPN | `http/1.1`（`allowH2` 默认 `false`，`u6:core/connect.js:87、:110`） | 不发 ALPN | `http/1.1`、`h2`（`allowH2` 自 8.0.0 起默认 `true`，`u8:core/connect.js:76、:98`）；SOCKS5 路径不发 ALPN |
| 407 | 没有任何重试；CONNECT 的 407 直接报错 | 明文的 407 是普通响应；CONNECT 的 407 报错 | 明文的 407 被改成错误（`u8:dispatcher/proxy-agent.js:66-75`）；CONNECT 的 407 报错 |

第一列对很多行有连带影响：明文请求在隧道里，代理端口上只看得到 CONNECT。仪器里只对“绝对形式的请求”生效的配置
（`forward.fail`、`forward.add_response_headers`、`conn.drop`、`conn.idle_close_ms`）在这一列都不会触发，
预期文件里相应的行写的是“未触发”“都看不到”或 `matrix.py` 找不到请求时的“其他：…”。这不是驱动的毛病。

### 6. 代理出错时调用方能拿到什么

默认用法（记进 `default_text`）：

| 情形 | `node-fetch-env` | `node-http-env` | `node-undici` |
| --- | --- | --- | --- |
| CONNECT 非 200（含 407） | `TypeError: fetch failed`，`cause` 是 `RequestAbortedError`（`name` 是 `AbortError`，`code` 是 `UND_ERR_ABORTED`）：`Proxy response (502) !== 200 when HTTP Tunneling`。只有状态码（`u6:dispatcher/proxy-agent.js:167-170`） | `error` 事件，`code` 是 `ERR_PROXY_TUNNEL`：`Failed to establish tunnel to 主机:443 via http://127.0.0.1:端口/: HTTP/1.1 502 原因短语`。有状态码和原因短语，凭据已从 URL 里去掉（`node:lib/https.js:249-258`、`node:lib/internal/http.js:125-131`） | 同第一列（`u8:dispatcher/proxy-agent.js:229-232`）；用 `request` 时没有外面那层 `TypeError` |
| 明文请求被代理回 407 | 明文走 CONNECT，同上一行 | 普通响应，`res.statusCode` 是 407，头和正文都在 | `InvalidArgumentError: Proxy Authentication Required (407)`（`fetch` 时在 `cause` 里） |
| 明文请求被代理回 403 等 | 这一列遇不到（明文在隧道里） | 普通响应：`statusCode`、`statusMessage`、`headers`、正文 | 普通响应：`status`、`statusText`、`headers`、正文 |
| CONNECT 发出后代理直接断开 | 预期会自动再连一次（6.29.1 对建隧道时的 `UND_ERR_SOCKET` 不清队列，`u6:dispatcher/client.js:371-390、:523`）；一直断就一直重连，直到超时 | `ERR_PROXY_TUNNEL`：`Connection to establish proxy tunnel ended unexpectedly`（`node:lib/https.js:294-298`） | `ProxyConnectionError`（`code` 是 `UND_ERR_PRX_CONN`，`cause` 是原来的 `SocketError`；8.6.0 起） |
| 等响应时连接被关 | `cause` 是 `SocketError: other side closed`（`UND_ERR_SOCKET`）或 `ECONNRESET`，不重发 | `Error: socket hang up`（`ECONNRESET`），不重发；`req.reusedSocket` 告诉调用方这条连接是不是复用的（`http.md`） | 同第一列 |
| SOCKS5 失败 | 不支持 | 不支持 | `Socks5ProxyError`，`code` 分别是 `UND_ERR_SOCKS5_AUTH_REJECTED`（`No acceptable authentication method`）、`UND_ERR_SOCKS5_AUTH_FAILED`（`Authentication failed`）、`UND_ERR_SOCKS5_REPLY_<应答码>`（`SOCKS5 connection failed: Connection not allowed by ruleset` 等，`u8:core/socks5-client.js:194-196、:261-263、:350-353、:391-411`） |

驱动记错误时用一个递归函数把 `name`、`code`、`message` 沿 `cause` 一路写下来，不要只记 `String(err)`。
`http` 模块的错误对象上还有一个 `statusCode` 属性（`node:lib/https.js:257`），文档没写，不算进 `default_text`。

需要主动打开的额外手段（`extra_text`）：

- `node-fetch-env`、`node-undici`：`node:diagnostics_channel` 的 `undici:request:headers` 频道。
  npm 包的 `docs/docs/api/DiagnosticsChannel.md` 写明它“包含成功的 CONNECT 或协议升级的响应”；从源码看非 200 的 CONNECT 响应也会发布
  （`u6:core/request.js:272-281、:327-331`；`u8:core/request.js:381-389`）。消息是 `{ request, response: { statusCode, statusText, headers } }`，
  `headers` 在 HTTP/1.1 下是 `Buffer` 的数组（名、值交替），要自己转成文字。拿得到状态码、原因短语、响应头，拿不到正文。
  内置的那份 undici 也发布到同一个频道名，订阅写法相同；不过 Node 自己的文档没有提这个频道，`node-fetch-env` 用它时在 `extra_how` 里注明依据的是 undici 的文档。

  ```js
  import dc from 'node:diagnostics_channel'
  dc.subscribe('undici:request:headers', ({ request, response }) => {
    if (request.method === 'CONNECT') seen.push({ status: response.statusCode, text: response.statusText,
      headers: response.headers.map(b => b.toString('latin1')) })
  })
  ```

  并发的步骤要能把消息对回到步骤上：`request.path` 是 `主机:端口`，同一个源的并发 CONNECT 分不开，报错可见性的用例（E01 到 E04）都是单个请求，够用。
- `node-undici` 另有 `undici:proxy:connected` 频道（隧道建成时发布 `socket` 和 `connectParams`，`u8:dispatcher/proxy-agent.js:235-240`），不含响应头，用处不大。
- `node-http-env`：文档里没有读取 CONNECT 响应的接口。`NODE_DEBUG=https`（`cli.md` 的 `NODE_DEBUG`）会让 `node:lib/https.js:245`
  把代理回的整块数据打到标准错误，里面有状态行、头和同一块里的正文；它是调试输出，格式不保证。
  用不用由驱动作者定：用了就把外层收到的子进程标准错误里这一步的部分记进 `extra_text`，`extra_how` 写 `NODE_DEBUG=https`；
  不用就留空（矩阵写“没有这样的手段”）。预期文件里这两行（R81、R85）写的是“不知道”。
- 重试不是“看得见”的手段，不要为了测试打开：undici 的 `RetryAgent`、`interceptors.retry` 都不是默认。

### 7. 版本相关的坑

| 版本 | 改了什么 | 出处 |
| --- | --- | --- |
| Node 19.0.0 | `http`、`https` 的全局 Agent 默认 `keepAlive: true`、`timeout: 5000`（“19.0.0”这个版本号是凭记忆写的，没有对着发行说明核对；v22.23.4 的源码里确实是这两个值） | `node:lib/_http_agent.js:720`、`node:lib/https.js:636` |
| Node 22.21.0 | 加入 `NODE_USE_ENV_PROXY`、`--use-env-proxy` 和 `Agent` 的 `proxyEnv`。更早的 22.x 设了变量也不走代理 | `http.md`、`cli.md` 的 YAML 注记 |
| Node 22 的 OpenSSL | 本机是 3.5.9。ClientHello 的大小取决于它默认发不发混合后量子的 key share；这一点没有对着 OpenSSL 源码核对（未验证） | `process.versions.openssl` |
| undici 6.22.0、7.10.0 | `ProxyAgent` 加入 `proxyTunnel` 选项，默认 `true`（明文目标也 CONNECT）。之前没有这个选项，行为相同 | 对比 6.21.3 与 6.22.0、7.9.0 与 7.10.0 的 `proxy-agent.js` |
| undici 7.x（7.10.0 之后、7.22.0 之前的某一版） | CONNECT 加上 `proxy-connection: keep-alive`；CONNECT 非 200 时补上了 `return`（之前报错后还会继续往下走） | 对比 7.10.0 与 7.22.0 的 `proxy-agent.js` |
| undici 7.23.0 | 加入 `Socks5ProxyAgent`，`ProxyAgent` 接受 `socks5://`（Experimental） | `Socks5ProxyAgent.md` |
| undici 8.0.0 | `allowH2` 默认从 `false` 变 `true`：隧道里的 ALPN 多了 `h2` | 对比 7.30.2 与 8.0.0 的 `core/connect.js` |
| undici 8.2.0 | URL 里只有用户名、密码为空时也发 `用户名:`。之前（含内置的 6.29.1）不发凭据 | 对比 8.1.0 与 8.2.0 的 `proxy-agent.js` |
| undici 8.6.0 | 建隧道时的套接字错误包成 `ProxyConnectionError`，不再无限重连（注释里的 #3897）。内置的 6.29.1 没有这个修正 | 对比 8.5.0 与 8.6.0；`u8:dispatcher/proxy-agent.js:261-268` |
| undici 8.7.0 | `proxyTunnel` 不设时按目标协议决定：`http://` 目标改发绝对形式，不再 CONNECT 到 80 | 对比 8.6.0 与 8.7.0；`ProxyAgent.md` 的 `proxyTunnel` |
| undici 8.11.0 | `Pool` 对 HTTPS 目标先用一条连接探测协议，h2 时并发请求合到这一条上 | 对比 8.10.0 与 8.11.0 的 `pool.js` |

上表里“对比某两版”的结论只看了这几个文件有没有对应的代码，没有读发行说明；具体是哪个补丁版本引入的没有再细分。

内置的 undici 跟着 Node 的小版本走（22.23.4 带的是 6.29.1），`node-fetch-env` 的行为会随 Node 升级而变；
其中最显眼的一条是明文请求走 CONNECT：npm 那边 8.7.0 已经改了默认值，6.x 这条线到 6.29.1 还没有。

## 第三方 Agent 与 axios

写给实现 `node-agents`、`node-axios` 两列驱动的人。2026-11-10 写成，
**只读了文档和源码，没有让这些客户端连过任何代理**（运行过的只有 `npm pack`、`node -p process.versions` 和 `node -p tls.DEFAULT_ECDH_CURVE`；下载的包只解包阅读，没有执行）。
这里的每一条都还没有被实测证实；实测对不上的以实测为准，并记进报告的“与预期不符”。
逐行预期在 `research/phase2/expectations/node-agents.json`、`node-axios.json`。

### 读的是哪个版本

| 部件 | 版本 | 来源 |
| --- | --- | --- |
| Node.js | v22.23.4（本机；OpenSSL 3.5.9） | `nodejs/node` 的 `v22.x` 分支 `lib/`（2026-11-10 取，`src/node_version.h` 写 22.23.5，与 22.23.4 的差别没有逐行比对） |
| http-proxy-agent | 9.1.0 | `npm pack`，`dist/index.js`、`README.md` |
| https-proxy-agent | 9.1.0 | 同上，另有 `dist/parse-proxy-response.js` |
| socks-proxy-agent | 10.1.0 | 同上 |
| agent-base | 9.0.0（上面三个包固定依赖这一版） | `dist/index.js` |
| socks | 2.8.10（socks-proxy-agent 依赖 `^2.8.3`） | `build/client/socksclient.js`、`build/common/constants.js` |
| axios | 1.21.1 | `lib/adapters/http.js`、`README.md`、`CHANGELOG.md` |
| axios 带进来的 https-proxy-agent | 5.0.1（axios 依赖 `^5.0.1`），连同 agent-base 6.0.2 | `dist/agent.js`、`dist/parse-proxy-response.js` |
| follow-redirects | 1.16.3（axios 依赖 `^1.16.2`） | `index.js` |
| 三个 Agent 包的变更记录 | main 分支 | `TooTallNate/proxy-agents` 仓库 `packages/*/CHANGELOG.md`（2026-11-10 取） |

下文的出处写成“缩写:行号”：`hpa` = http-proxy-agent 9.1.0 的 `dist/index.js`，`hspa` = https-proxy-agent 9.1.0 的 `dist/index.js`，
`ppr` = 同包的 `dist/parse-proxy-response.js`，`spa` = socks-proxy-agent 10.1.0 的 `dist/index.js`，`ab9` = agent-base 9.0.0 的 `dist/index.js`，
`socks` = socks 2.8.10 的 `build/client/socksclient.js`，`ax` = axios 1.21.1 的 `lib/adapters/http.js`，
`hspa5` = https-proxy-agent 5.0.1 的 `dist/agent.js`，`ppr5` = 同包的 `dist/parse-proxy-response.js`，`ab6` = agent-base 6.0.2 的 `dist/src/index.js`，
`fr` = follow-redirects 1.16.3 的 `index.js`，`node:` = Node `v22.x` 分支 `lib/` 下的文件。

两列的定义：

- `node-agents`：`http.request` / `https.request`，`agent` 选项传一个代理 Agent。明文目标用 `HttpProxyAgent`，HTTPS 目标用 `HttpsProxyAgent`，
  SOCKS5 两种目标都用 `SocksProxyAgent`。Agent 的构造只传代理 URL，不传选项。
- `node-axios`：`axios.request({…, proxy: {protocol, host, port, auth}})`，不传 `httpAgent`、`httpsAgent`。

**先说最容易想错的一点：axios 1.21.1 对 `https://` 目标发的是 CONNECT，不是把绝对形式的 https URL 明文发给代理。**
`ax:440-489`：目标是 https 时装一个 https-proxy-agent 5.x 的隧道 Agent；目标是 http 时才把请求改写成绝对形式（`ax:490-521`）。
README 的 `proxy` 一节原话：“For `https://` targets, axios establishes a CONNECT tunnel through the proxy and performs TLS end-to-end with the origin”。
这是 1.16.1（2026-05-13）改的，变更记录叫它“Proxy Cleartext Leak”（#10858）；更早的版本这里是什么样没有读旧源码核对（未验证）。
所以 `node-axios` 的隧道行为其实是 **https-proxy-agent 5.0.1** 的行为，和 `node-agents` 用的 9.1.0 有几处不同（见第 5、7 节）。

### 0. 先看这几个会改变结果的选择

预期文件是按下面“建议”的写法填的。

| 选择 | 建议 | 换一种写法会怎样 |
| --- | --- | --- |
| 凭据怎么进代理 URL（`node-agents`） | 用户名、密码各自 `encodeURIComponent` 后用模板字符串拼 | 用 `url.username = …` 赋值时，URL 的 setter 不转义 `%`，Agent 再 `decodeURIComponent` 一次，`%41` 变成 `A`、`%2F` 变成 `/`：R62、R68、R126、R130 变成“变了” |
| Agent 的选项（`node-agents`） | 不传（README 的例子都只传 URL） | 传 `keepAlive: true` 会复用连接和隧道，R10 到 R13、R38、R88、R90 到 R99、R122 全部跟着变，R02、R04 里的 `close` 也变成 `Keep-Alive` |
| 两个用户（B11、B12、S14） | `node-agents`：每个凭据一个 Agent 实例；`node-axios`：每个请求传自己的 `proxy.auth` | 没有别的常规写法 |
| POST 的正文 | `node-agents`：读进 Buffer，`req.end(buf)`；`node-axios`：`axios.post(url, buf, …)` | `node-agents` 不设 `Content-Length` 就 `req.write(buf); req.end()`，或用流 `pipe`，R19 变成 chunked |
| axios 的其他配置 | 只给 `proxy`、`headers`（Content-Type）和 `signal`。不设 `maxRedirects`、`validateStatus`、`httpAgent`、`httpsAgent`、`timeout` | `maxRedirects: 0` 会换成原生 transport（`ax:1171-1173`）；传 `httpsAgent` 会改变隧道 Agent 的缓存和 TLS 选项（`ax:235-247`） |
| axios 的非 2xx | 捕获 `AxiosError`，`error.response` 存在就记 `ok: true`、`status: error.response.status` | 把它一律记成失败的话，R45、R46、R49、R50、R51 从“拿到 … 响应”变成“报错，提到 …”，R80、R82、R86 只剩“状态码” |
| 超时 | 自己计时：`signal: AbortSignal.timeout(毫秒)`，并保证进程里有一个活着的定时器 | 见第 6 节：有两个用例请求会永远挂住，`timeout` 选项和 `req.setTimeout` 都救不了 |
| 信任测试 CA | 环境变量 `NODE_EXTRA_CA_CERTS` | 见第 3 节 |
| `node-axios` 的 S 组 | 整组报 `unsupported`，不要把 `protocol` 写成 `socks5` 去试 | 见第 1 节末尾：https 目标会对着 SOCKS 端口发 HTTP 的 CONNECT，而 obsproxy 按首字节分流，会把它当 HTTP 代理请求处理掉 |

### 1. 代理怎么配

#### `node-agents`：HTTP 代理

三个包从 8.0.0 起是纯 ESM（`package.json` 的 `"type": "module"`，变更记录 8.0.0），要求 Node ≥ 20（9.0.0）。驱动写成 `.mjs` 用 `import` 最省事；
Node 22 里对 ESM 包 `require()` 是否可用没有核对（未验证）。

```js
import http from 'node:http';
import https from 'node:https';
import { HttpProxyAgent } from 'http-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';

function proxyUrl(scheme, host, port, user, pass) {
  const cred = user == null ? '' : `${encodeURIComponent(user)}:${encodeURIComponent(pass)}@`;
  return `${scheme}://${cred}${host}:${port}`;
}

const url = proxyUrl('http', '127.0.0.1', port, user, pass);
const httpAgent = new HttpProxyAgent(url);    // 给 http:// 目标
const httpsAgent = new HttpsProxyAgent(url);  // 给 https:// 目标

const target = new URL(step.url);
const mod = target.protocol === 'https:' ? https : http;
const agent = target.protocol === 'https:' ? httpsAgent : httpAgent;
const req = mod.request(target, { method: 'GET', agent, signal }, (res) => { /* … */ });
req.on('error', onError);
req.end();
```

- 两个包的分工写在各自 README 的第一段：http-proxy-agent 给 `http` 模块用（改写成绝对形式），https-proxy-agent 给 `https` 模块用（CONNECT）。
  不要拿 `HttpsProxyAgent` 发明文请求：它对明文目标也会 CONNECT（到 80 端口），然后把裸套接字交回去（`hspa:107-118`）。
- 凭据写在代理 URL 的 userinfo 里。两个包都是 `decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password)`，
  按 UTF-8 转 base64，**每个请求（每个 CONNECT）都先带，不等 407**（`hpa:62-65`、`hspa:88-91`）。URL 里用户名和密码有一个非空就带；
  空密码 `http://user:@host` 发出去是 `user:`。
- 另一种给凭据的办法是构造时的 `headers` 选项（README 里有，对象或返回对象的函数），自己写 `Proxy-Authorization`。不是常见写法，驱动不用。
- 没有 no_proxy、没有回环地址的例外，也不读环境变量：传了这个 Agent 的请求一律走代理。

#### `node-agents`：SOCKS5 代理

```js
import { SocksProxyAgent } from 'socks-proxy-agent';
const agent = new SocksProxyAgent(proxyUrl(run.proxy.scheme, '127.0.0.1', port, user, pass)); // socks5:// 或 socks5h://
mod.request(target, { agent, signal }, …);   // http 和 https 都用它
```

- 协议名决定谁解析域名（`spa:29-51`）：`socks5://` 由客户端先 `dns.lookup` 再把 IP 交给代理；`socks5h://` 和不带版本的 `socks://` 把域名交给代理；
  `socks4://`、`socks4a://` 是 SOCKS4。用例里的 `socks5` 和 `socks5h` 两种写法它都区分，照用例给的写。
- 凭据同样写在 URL 的 userinfo 里并做 `decodeURIComponent`（`spa:57-68`；README 的例子里用户名中的 @ 写成 `%40`）。
  有用户名或密码时问候里提供 `00,02`，否则只提供 `00`（`socks:480-484`）。
- `socks5://` 加一个解析不了的域名：在本机 `dns.lookup` 那一步就失败（ENOTFOUND），不会连代理（`spa:93-107`）。
  目标是 `localhost` 时发给代理的是解析出的第一个地址，是 IPv4 还是 IPv6 取决于机器的 hosts 文件。

#### `node-axios`

```js
import axios from 'axios';
const res = await axios.request({
  method: 'GET', url: step.url,
  proxy: { protocol: 'http', host: '127.0.0.1', port,
           auth: user == null ? undefined : { username: user, password: pass } },
  signal: AbortSignal.timeout(timeoutMs),
});
```

- `proxy.auth` 是两个原始字符串，不经过 URL，不用转义；axios 拼成 `用户名:密码` 后按 UTF-8 转 base64（`ax:426-434`、`ax:494-497`、`hspa5:101-103`）。
  `username`、`password` 至少一个非空，否则抛“Invalid proxy authorization”（`ax:431-437`）。**先带，不等 407。**
- 明文目标：请求行是绝对形式，`Proxy-Authorization` 写在请求头上，连接走 `http.globalAgent`（keep-alive 的连接池，按代理地址取名）。
- HTTPS 目标：CONNECT，凭据只在 CONNECT 上（`ax:442-452`）。隧道 Agent 按“代理地址加凭据”缓存（`ax:226-262`），但隧道本身不复用。
- **环境变量**：没给 `proxy` 配置时 axios 会读 `http_proxy`、`https_proxy`、`no_proxy`（经 proxy-from-env，`ax:366-375`，README 同一节）；
  给了显式的 `proxy` 就不读，也不看 `no_proxy`。`proxy: false` 是完全不走代理。驱动的环境里本来就清掉了这些变量。
- **不支持 SOCKS**（依据）：`setProxy` 只有两条路（`ax:440-521`），README 的 `proxy` 一节只说 http 和 https（“If the proxy server uses HTTPS, then you must set the protocol to `https`”）。
  要走 SOCKS 得自己传 `httpAgent` / `httpsAgent`（比如 socks-proxy-agent），那就不是这一列了。
  如果硬把 `protocol` 写成 `'socks5'`：https 目标照样装隧道 Agent，而 https-proxy-agent 5.x 只在协议是 https 时用 TLS，其余一律明文连上去发 `CONNECT`（`hspa5:54`、`hspa5:89-96`）；
  http 目标则由 follow-redirects 抛 `Unsupported protocol socks5:`（`fr:347-350`）。所以 S 组整组报 `unsupported`，原因写这一条。

### 2. 同一个进程里对不同请求用不同的代理凭据

- `node-agents`：**每个凭据一个 Agent 实例**。凭据在构造时固定在 `agent.proxy` 上（一个 `URL` 对象），没有按请求覆盖的接口。
  驱动里按“用户下标 → {HttpProxyAgent, HttpsProxyAgent}”（SOCKS 是一个 SocksProxyAgent）建一张表，整个用例期间复用这些实例。
  （`headers` 选项可以是函数，但它拿不到当前请求，做不了按请求换凭据。）
- `node-axios`：**每个请求传不同的 `proxy.auth`**，同一个 axios 实例即可。明文目标时两个用户的请求会共用 `http.globalAgent` 里到代理的同一条 TCP 连接，
  凭据是逐请求的头，不会串；HTTPS 目标时隧道 Agent 的缓存键里带着凭据（`ax:227-234`）。

### 3. 信任测试用的 CA

两列都用环境变量 **`NODE_EXTRA_CA_CERTS=<ca.pem 的路径>`**，在启动 node 进程时给（进程启动后再设无效）。它只是往默认的根证书里追加，
不碰 Agent、不碰代理配置；Node 的 `https` 模块本来就只说 HTTP/1.1，谈不上影响 HTTP/2。

不建议的写法和原因：

- `node-agents` 也可以在请求选项里传 `ca`（请求选项会原样进到隧道里的 `tls.connect`，`hspa:113-116`、`spa:139-142`）。能用，但 `ca` 给了以后是替换而不是追加默认根证书，
  而且每个请求都得带，不如环境变量干净。
- `node-axios` 传 `httpsAgent: new https.Agent({ ca })` 也行（README：axios 会把 `httpsAgent` 的 TLS 选项转给隧道 Agent），但这一列的约定是不加 Agent，
  而且传了以后隧道 Agent 换一套缓存（`ax:235-238`）。
- 不许用 `rejectUnauthorized: false`、`NODE_TLS_REJECT_UNAUTHORIZED=0`。

### 4. 并发、重定向、POST

- **并发 6 个**：两列都是把 6 个请求同步发起后 `await Promise.all(…)`。Agent 的 `maxSockets` 默认无限，6 个请求各开一条到代理的连接。
- **重定向**：
  - `node-agents`：Node 的 `http` / `https` 不跟随重定向，没有可以打开的开关。驱动得自己写循环：状态码是 301、302、303、307、308 且有 `Location` 时，
    用 `new URL(location, 当前 URL)` 算出下一跳，**按下一跳的协议重新选 Agent**（明文用 `HttpProxyAgent`，HTTPS 用 `HttpsProxyAgent`），新建一个请求。
    这样 B08 到 B10 测到的主要是驱动自己的循环，结果里要写明。
  - `node-axios`：默认就跟随（README：`maxRedirects` 默认 21，底层是 follow-redirects）。每一跳 axios 在 `beforeRedirect` 里重新跑一遍 `setProxy`（`ax:524-536`）：
    先删掉头里遗留的 `Proxy-Authorization`（`ax:380-386`），摘掉上一跳装的隧道 Agent（`ax:391-401`），再按新目标的协议决定 CONNECT 还是绝对形式。`follow: false` 的步骤不用改配置（那些 URL 不重定向）。
- **POST**：
  - `node-agents`：`const req = mod.request(target, { method: 'POST', agent, headers: { 'Content-Type': 'application/octet-stream' } }, cb); req.end(buf);`
    `end(buf)` 时 Node 自己算出 `Content-Length`（`node:_http_outgoing.js:990`）。http-proxy-agent 会在连上代理以后重新生成一遍请求头并替换缓冲区里的头（`hpa:79-96`），正文不动。
  - `node-axios`：`axios.post(url, buf, { headers: { 'Content-Type': 'application/octet-stream' }, proxy, signal })`。Buffer 正文自动带 `Content-Length`（`ax:975`），默认不限正文大小。
  - 两列都不会自己发 `Expect: 100-continue`。

### 5. 请求经代理时的样子（写驱动时对照用）

| | `node-agents` | `node-axios` |
| --- | --- | --- |
| 明文请求行 | `GET http://a.kaoju.test/echo?… HTTP/1.1`（`hpa:46-57`） | 同左（`ax:516`） |
| 明文请求上与代理有关的头 | `Proxy-Authorization`（有凭据时）、`Proxy-Connection: close`、末尾 `Connection: close`（`hpa:62-70`；`node:_http_client.js:338-340`） | `Proxy-Authorization`（有凭据时）、末尾 `Connection: keep-alive`；另有 axios 自己的 `Accept`、`User-Agent: axios/1.21.1`、`Accept-Encoding`、小写的 `host`（`ax:509`、`ax:915`） |
| CONNECT | `CONNECT a.kaoju.test:443 HTTP/1.1`，头依次是 `Proxy-Authorization`（有凭据时）、`Host: a.kaoju.test:443`、`Proxy-Connection: close`（`hspa:86-100`） | `CONNECT a.kaoju.test:443 HTTP/1.1`，头依次是 `Proxy-Authorization`（有凭据时）、`Host: a.kaoju.test`（默认端口不写）、`Connection: close`（`hspa5:98-114`） |
| 隧道里 | TLS，SNI 是目标主机名，不带 ALPN，HTTP/1.1 | 同左 |
| 连接复用 | 都不复用：Agent 的 `keepAlive` 默认 `false`（`node:_http_agent.js:185`），每个请求一条新连接、一个新 CONNECT | 明文复用（`http.globalAgent` 是 keep-alive 的）；HTTPS 不复用（agent-base 6 没有连接池，`ab6:109-110`、`ab6:190-193`） |
| 407 之后 | 不重试（除非配了 `onProxyAuth`，驱动不配） | 不重试 |
| 自动重发 | 没有 | 没有 |

### 6. 代理出错时调用方能拿到什么

#### CONNECT 回的不是 200（包括 407、403、502、503）

两个版本的 https-proxy-agent 都是同一个做法：关掉到代理的连接，交给 Node 一个只读的假套接字，等请求挂好解析器以后把代理的响应字节原样“回放”进去（`hspa:135-158`、`hspa5:130-153`）。
**于是调用方看到的不是错误，而是一个普通的 HTTP 响应**，状态码、原因短语、头、正文都是代理的那一份（正文只包含和响应头在同一批读到的部分；obsproxy 是一次写出的）。
请求本身（可能带着 `Authorization`）不会被发给代理。

- `node-agents`：`response` 事件照常触发，`res.statusCode`、`res.statusMessage`、`res.rawHeaders`、正文都有。`default_text` 照成功的格式记。
- `node-axios`：状态码不在 2xx 内，按默认的 `validateStatus` 抛 `AxiosError`：`error.message` 是 `Request failed with status code 502`，`error.code` 是 `ERR_BAD_RESPONSE`（4xx 是 `ERR_BAD_REQUEST`），
  `error.response` 里有 `status`、`statusText`、`headers`、`data`（`lib/core/settle.js`）。`default_text` 要把 `error.message` 和 `error.response` 的这四样都记上。
  调用方分不清这个 502 是代理回的还是源站回的。

#### 明文请求被代理拒绝（407、403）

就是这个请求的响应，两列都和上面一样拿到（axios 仍然是带 `error.response` 的 `AxiosError`）。

#### CONNECT 成功时 200 里附加的头

默认用法看不到：响应被 Agent 自己读掉了。

#### 需要主动打开的额外手段（`extra_text`）

- `node-agents` / https-proxy-agent 9.1.0：**`proxyConnect` 事件**，请求对象和 Agent 实例上都会发（`hspa:104-105`），参数是 `{ statusCode, statusText, headers }`，
  200 和非 200 都发，头是 CONNECT 响应的全部头（`ppr:56-86`）。写法：`req.on('proxyConnect', (c) => …)` 或 `agent.on('proxyConnect', (c, req) => …)`。
  它记在变更记录里（6.1.0：“Emit "proxyConnect" event on HTTP `request` object”“…on Agent instance”）和类型声明里，**README 没有提**；算不算 PROTOCOL 说的“文档里写明的手段”需要定一下，
  预期文件按“算”填（R81、R85）。`extra_how` 写 `req.on('proxyConnect')`。
- http-proxy-agent 9.1.0 也发 `proxyConnect`，但内容只有 `{ socket }`（`hpa:113-116`），没有可记的信息。
- 9.1.0 新加的 `onProxyAuth` 回调（变更记录 9.1.0）只在 407 时被调用，而且会带着回调返回的头重发一次 CONNECT（`hspa:121-134`、`hspa:163-211`），用了就改变了行为，驱动不用。
- 三个包都用 `debug` 包打日志（环境变量 `DEBUG=https-proxy-agent*` 等），README 没写，不算。
- SOCKS：没有钩子。
- `node-axios`：没有。axios 不暴露内部的隧道 Agent，5.x 也没有 `proxyConnect` 事件。`extra_text` 留空。

#### 网络层的失败

| 情况 | `node-agents` | `node-axios` |
| --- | --- | --- |
| 明文请求发出后连接被关，没有响应 | `error` 事件：`Error: socket hang up`，`code: 'ECONNRESET'`（RST 时是 `read ECONNRESET`）。不重发 | `AxiosError`，`message` 和 `code` 同左，`cause` 是原始错误。**复用的连接上也不重发** |
| 隧道在响应之前被切断 | 同上 | 同上 |
| CONNECT 发出后代理不回应就关连接 | `Error: Proxy connection ended before receiving CONNECT response`（`ppr:23-27`） | **请求永远挂住**：5.x 在连接结束时只打调试日志，不 reject（`ppr5:29-34`）。见下 |
| SOCKS5 代理回 0xFF | `Received invalid Socks5 initial handshake (no accepted authentication type)` | 不支持 |
| SOCKS5 用户名密码不对 | `Socks5 Authentication failed` | |
| SOCKS5 应答码非 0 | `Socks5 proxy rejected connection - NotAllowed`（2）、`HostUnreachable`（4）、`ConnectionRefused`（5）等（`socks:638`、`constants.js:76-84`） | |
| `socks5://` 加解析不了的域名 | `getaddrinfo ENOTFOUND …`，没连过代理 | |

SOCKS 的错误对象是 `SocksClientError`（`name` 仍是 `Error`），带一个 `options` 属性（代理地址和目标）；`AxiosError` 带 `config`（里面有 `proxy.auth`）。
记 `default_text` 时只取类型、`message`、`code` 和 cause 链，不要把这两个属性整个序列化进结果。

#### 两个会挂住或炸掉进程的地方

1. **F11 在 `node-axios` 上**：隧道 Agent 的 Promise 永远不结束，请求拿不到套接字。axios 的 `timeout` 配置和 Node 的 `req.setTimeout` 都要等到 `socket` 事件才开始计时
   （`ax:1538`；follow-redirects 的 `setTimeout` 同样等 `socket`），所以不会触发。只能靠 `signal: AbortSignal.timeout(毫秒)`（README 的“Handling Timeouts”也这么建议）。
   另外，挂住的 Promise 不会让事件循环保持存活：如果此时进程里没有别的定时器，node 会直接退出而不写结果，所以驱动要有一个总的看门狗定时器。
2. **S19（256 字节的用户名）在 `node-agents` 上**：socks 库写用户名长度时 `writeUInt8(256)` 抛 `RangeError`（`socks:544`），而这一句在套接字的 `data` 事件处理函数里（`socks:300` 起），
   外面没有 `try`。异常成为进程级的 `uncaughtException`，请求本身既不成功也不报错。驱动要装 `process.on('uncaughtException', …)`，把异常文字记进这一步的 `default_text`，
   并靠自己的超时结束这一步；不装的话整个驱动进程退出，这个用例没有结果。认证包没有发出去，代理那边看不到 `socks5_auth`。

### 7. 版本相关的坑

| 版本 | 变了什么 | 依据 |
| --- | --- | --- |
| axios 1.16.1（2026-05-13） | `https://` 目标经 `proxy` 选项改成 CONNECT 隧道（装一个 https-proxy-agent）。变更记录的说法是修复“HTTPS 请求数据可能明文发给 HTTP 代理” | axios `CHANGELOG.md` v1.16.1（#10858）；更早版本的行为没有读源码（未验证） |
| axios 1.17.0、1.21.0 | 隧道里的 TLS 选项：先是保留用户 `httpsAgent` 的（#10957），再是没给 `httpsAgent` 时取 `https.globalAgent` 的（#11178） | 同上 |
| axios 1.16.0 | 目标 URL 里内嵌的 Basic 凭据改为先做 URL 解码（#10825）。这是源站凭据，不是 `proxy.auth`；`proxy.auth` 从来不解码 | 同上；`ax:1035-1036` |
| axios 依赖的 https-proxy-agent 停在 5.x | 和 9.x 的差别：`Host` 头不写默认端口、发 `Connection: close` 而不是 `Proxy-Connection`、没有 `proxyConnect` 事件、代理不回应就断开时挂住 | `hspa5`、`ppr5` 对比 `hspa`、`ppr` |
| https-proxy-agent 6.0.0 | 构造函数拆成 `(代理 URL, 选项)` 两个参数；凭据从 URL 的 `username`、`password` 取并解码（5.x 是 `auth` 字符串原样用） | 变更记录 6.0.0；`hspa5:101-103` |
| https-proxy-agent 6.1.0 | 加入 `proxyConnect` 事件 | 变更记录 |
| https-proxy-agent 6.2.1、7.0.1 | “Properly reject errors during proxy CONNECT response”；修正 CONNECT 响应头的解析范围。5.0.1 里没有“连接结束就 reject”，9.1.0 里有，具体是哪一版加的没有查 | 变更记录；`ppr:23-27` |
| http-proxy-agent 6.1.1 | “Fix `keepAlive: true`”：之前传 `keepAlive` 不起作用 | 变更记录 |
| 三个包 8.0.0（socks-proxy-agent 9.0.0） | 改成纯 ESM | 变更记录 |
| 三个包 9.0.0（socks-proxy-agent 10.0.0） | 要求 Node ≥ 20 | 变更记录 |
| http/https-proxy-agent 9.1.0 | 加入 `onProxyAuth`、`negotiate` 选项（407 后重试）；请求上多一个 `proxy` 事件；http-proxy-agent 也发 `proxyConnect` | 变更记录 |
| socks-proxy-agent 8.0.0 | 支持 `keepAlive: true`；构造函数同样拆成两个参数 | 变更记录 |
| Node 19 起 | `http.globalAgent`、`https.globalAgent` 默认 `keepAlive: true`。`node-axios` 的明文连接复用靠的是它；自己 `new` 出来的 Agent（包括这三个代理 Agent）默认仍是 `false` | `node:_http_agent.js:185`、`:720`；“19 起”是凭印象写的，没有查发行说明（未验证） |
| Node 22.21 起 | 内置了环境变量代理（`proxyEnv`）。axios 在这种 Agent 上把环境代理交给 Node 处理（`ax:103-141`）；显式的 `proxy` 配置不受影响 | axios README 的 `proxy` 一节 |

两列装在同一个 `node_modules` 里时，顶层的 https-proxy-agent 是 9.1.0，axios 自己嵌套一份 5.0.1。`package-lock.json` 里两份都要固定住，
并在结果的 `versions` 里把 axios 实际解析到的那一份也读出来（`node_modules/axios/node_modules/https-proxy-agent/package.json`），因为 `node-axios` 的隧道行为取决于它。
