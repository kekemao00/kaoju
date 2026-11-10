# 浏览器驱动（Playwright）：写驱动之前要知道的事

这个文件分两节，各由读过对应源码的人写：“Chromium”和“Firefox”。只管自己的小节。

## Firefox

给写 `firefox-pw` 驱动的人看的惯用写法清单。写于 2026-11-10，只读了文档和源码，没有运行过浏览器，每一条都要在第一次实测时核对。

版本：Playwright 1.63.0，捆绑的 Firefox 是 155.0（`playwright-core/browsers.json` 里 firefox 的 revision 1543）。
浏览器一侧读的是 Playwright 标签 `v1.63.0` 下的 `browser_patches/firefox/`，网络栈读的是 `mozilla-firefox/firefox` 的修订
`d065a04bc5610f496762935dee56604a78b91b51`（`browser_patches/firefox/UPSTREAM_CONFIG.sh` 写明的基线，`browser/config/version.txt` 是 155.0，与捆绑版本一致）。
下文的出处里，“PW 文档”指 `docs/src/`，“PW 源码”指 `packages/playwright-core/src/`，“juggler”指 `browser_patches/firefox/juggler/`，“necko”指 Firefox 源码树里的路径。

本机的 `playwright-core` 1.63.0 把服务端代码打包进了 `lib/coreBundle.js`，没有 `lib/server/firefox/` 目录；要读代码请看同一标签的 TypeScript 源码。

### 代理怎么配

- HTTP 代理（PW 文档 `network.md` 的“HTTP Proxy”一节；`api/params.md` 的 `browser-option-proxy`）：

  ```js
  const browser = await firefox.launch({
    proxy: { server: 'http://127.0.0.1:40123', username: 'kaoju-user', password: 'kaoju-pass-1' },
  });
  ```

  凭据只能通过 `username`、`password` 两个字段给。写在 `server` 的 URL 里会被丢掉：`normalizeProxySettings` 只保留协议和主机端口
  （PW 源码 `server/browserContext.ts:816-837`）。
- SOCKS5 代理：`proxy: { server: 'socks5://127.0.0.1:40123' }`。
  - 只认 `socks5:` 这个写法。`socks5h://` 不报错，但会被当成 HTTP 代理（PW 源码 `server/firefox/ffBrowser.ts:413-422`，不是 `socks5:`、`socks4:`、`https:` 的一律是 `http`）。
    所以用例里 `socks5` 和 `socks5h` 两种都要写成 `socks5://`，并在结果的 `config` 里说明。
  - 域名总是交给代理解析：juggler 建 `proxyInfo` 时固定带 `TRANSPARENT_PROXY_RESOLVES_HOST`（juggler `NetworkObserver.js:631-640`），没有开关。
  - 不能配凭据：给了 `username` 或 `password` 就抛 `Browser does not support socks5 proxy authentication`
    （PW 源码 `server/browserContext.ts:831-832`，`launch` 和 `newContext` 都先过这一步）。Firefox 本身支持 SOCKS5 用户名密码
    （necko `netwerk/socket/nsSOCKSIOLayer.cpp:708-724`），是 Playwright 不放行。S05、S06、S08、S14 到 S22 应报 `unsupported`，
    把这句报错原文记下来（PROTOCOL 要求“能试的都要试”）。
- 也可以在上下文上配：`browser.newContext({ proxy })`（PW 文档 `network.md` 同一节；`api/params.md` 的 `context-option-proxy`）。
  Firefox 不要求先在 `launch` 上配一个全局代理。上下文的代理优先于浏览器级的（juggler `TargetRegistry.js:310-318`）。
- Playwright 不给 Firefox 加默认的 `bypass`。而且 Playwright 的构建把 `network.proxy.allow_hijacking_localhost` 改成了 `true`
  （`browser_patches/firefox/preferences/playwright.cfg:113-115`；Firefox 自己的默认值是 `false`，`modules/libpref/init/StaticPrefList.yaml:14961-14964`）。
  所以 `localhost` 的请求也经代理，和 Mozilla 发布的 Firefox 不一样。驱动不要为了“让 localhost 走代理”再去改设置。

### 同一个进程里换凭据

常规做法是每个用户一个浏览器上下文，各自带代理设置：

```js
const ctx0 = await browser.newContext({ proxy: { server, username: u0, password: p0 } });
const ctx1 = await browser.newContext({ proxy: { server, username: u1, password: p1 } });
```

- 连接按上下文隔离：连接的散列键末尾是来源属性后缀，每个上下文有自己的 `userContextId`（necko `netwerk/protocol/http/nsHttpConnectionInfo.cpp:297-299`）。
- 认证缓存不隔离（necko `netwerk/protocol/http/nsHttpChannelAuthProvider.cpp:794` 的注释：proxy credentials are not OA-isolated）。
  juggler 的补救办法是：只要有两个上下文（或上下文与浏览器级）对同一个代理配了不同凭据，每个请求解析代理之前都清空整个认证缓存
  （juggler `TargetRegistry.js:264-298`、`NetworkObserver.js:629-630`）。后果是这种情况下每个请求都先不带凭据、吃一个 407 再重试；
  单用户的用例没有这个现象。B11、B12 的 407 个数会比单用户多，属于预期之内。
- 没有“同一个上下文里按请求换代理凭据”的做法。

### 信任测试用的 CA

不要用 `ignoreHTTPSErrors`（那是关闭校验）。可行的办法是 Firefox 的企业策略文件，Playwright 文档里有这个入口
（PW 文档 `api/params.md` 的 `firefoxUserPrefs` 条目末尾：`PLAYWRIGHT_FIREFOX_POLICIES_JSON` 环境变量；
对应 `playwright.cfg:13-14` 的 `browser.policies.alternatePath`）：

```js
// policies.json: {"policies": {"Certificates": {"Install": ["/绝对路径/ca.pem"]}}}
const browser = await firefox.launch({
  env: { ...process.env, PLAYWRIGHT_FIREFOX_POLICIES_JSON: '/绝对路径/policies.json' },
  proxy: { server },
});
```

- `Certificates.Install` 在 Linux 上接受绝对路径（necko 之外：`browser/components/enterprisepolicies/Policies.sys.mjs:561-600`）。
  证书是异步装进去的（同一段代码是一个不等待的 `async` 函数），浏览器刚启动就导航有可能赶在装完之前。
  驱动应先确认 CA 已生效再开始用例（例如对源站端口直连探一次，失败就稍等重试），这次探测不要经过被测代理。未验证。
- `security.enterprise_roots.enabled` 已被 Playwright 设成 `true`（`playwright.cfg:129-131`），但 Linux 上没有系统证书库可导入，帮不上忙。未验证。
- 这个办法不改代理和 HTTP/2 的行为；不要顺手用 `firefoxUserPrefs` 改 `network.*` 的设置。
- `env` 传给 `launch` 时要自己带上原有的环境变量；同时记得驱动应在干净的环境里启动（不继承代理变量）。
  Firefox 的 `network.proxy.type` 默认是 5（跟随系统设置，`StaticPrefList.yaml:15696-15699`），环境里的 `http_proxy` 之类有可能被它读到；是否真的会读未验证。

### 并发、重定向、POST

- GET 是顶层导航：`const resp = await page.goto(url)`。`goto` 自动跟随重定向，返回最后一个响应；`resp.status()`、`resp.statusText()`、
  `await resp.allHeaders()`、`await resp.body()` 是默认用法能拿到的全部内容。
- POST 和并发从同源的 `/page` 里用 `fetch` 发（先 `page.goto` 到 `/page`）：

  ```js
  // 6 个并发
  await page.evaluate(urls => Promise.all(urls.map(async u => {
    const r = await fetch(u); return { status: r.status, text: await r.text() };
  })), urls);
  // POST：正文在 Node 一侧读出来，以数组或 base64 传进页面，再还原成 Uint8Array
  await page.evaluate(async ({ url, b64 }) => {
    const body = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body });
    return { status: r.status, text: await r.text() };
  }, { url, b64 });
  ```

  同源请求不触发预检。`fetch` 失败时页面里抛的是 `TypeError: NetworkError when attempting to fetch resource.`，不带原因；
  想要错误名得另外监听 `page.on('requestfailed')`。
- WebSocket：`page.evaluate` 里 `new WebSocket(url)`，等 `open` 或 `close` 事件。
- `/echo` 回的是 `application/json`。Playwright 关掉了 JSON 查看器（`playwright.cfg:200-203`），页面按纯文本显示，不会变成下载。未验证。

### 代理出错时调用方能拿到什么

默认用法（`page.goto` 抛出的 `Error.message`）是 Firefox 的错误名加调用日志，形如
`page.goto: NS_ERROR_PROXY_BAD_GATEWAY` 换行 `Call log:` 换行 `- navigating to "…", waiting until "load"`。
错误名由 juggler 从状态码反查（juggler `content/FrameTree.js:304`、`Helper.js:109-161`）。里面没有 HTTP 状态码的数字、原因短语、响应头和正文。

| 情况 | 错误名 | 出处 |
| --- | --- | --- |
| CONNECT 回 502 | `NS_ERROR_PROXY_BAD_GATEWAY` | necko `netwerk/protocol/http/nsHttp.cpp:946-948` |
| CONNECT 回 403 | `NS_ERROR_PROXY_FORBIDDEN` | 同上 `:880-882` |
| CONNECT 回 503 | `NS_ERROR_CONNECTION_REFUSED`（注意不是 PROXY 开头的） | 同上 `:949-957` |
| CONNECT 回 400、404、500 | `NS_ERROR_UNKNOWN_HOST` | 同上 `:866-873` |
| 407，没配凭据或凭据不对（明文和 CONNECT 都一样） | `NS_ERROR_PROXY_CONNECTION_REFUSED` | necko `netwerk/protocol/http/nsHttpChannel.cpp:7179-7191` |
| SOCKS5 方法被拒（0xFF）、用户名密码被拒、应答码 1、2、5、7 | `NS_ERROR_CONNECTION_REFUSED` | necko `netwerk/socket/nsSOCKSIOLayer.cpp:742-753、:916-961`；`netwerk/base/nsSocketTransport2.cpp:1674-1677、:180-193` |
| SOCKS5 应答码 4、8 | `NS_ERROR_UNKNOWN_HOST` | 同上；`nsSocketTransport2.cpp:235-237` |
| SOCKS5 应答码 6 | `NS_ERROR_NET_TIMEOUT` | 同上 |

- CONNECT 失败时代理的响应正文不展示，这是有意的（necko `nsHttpChannel.cpp:2745-2775` 的注释）。
- 明文请求被代理拒绝（比如 403）不是错误：`page.goto` 正常返回，状态码、原因短语、响应头、正文都在 Response 上。
  例外是 407：Firefox 不把代理的 407 正文交给页面，而是报上表里的错误。
- 没配凭据也遇到 407 时，juggler 仍会“给出凭据”（`NetworkObserver.js:300-311` 只看有没有代理对象），Firefox 会带一份无效的凭据再试一次才放弃。
  C01、C02 里代理会看到第二个带 `Proxy-Authorization` 的请求，不要当成仪器故障。无效凭据的具体字节未验证。
- 需要主动打开的额外手段（PROTOCOL 里的 `extra_text`）：Playwright 文档里没有能看到 CONNECT 响应的接口。
  `page.on('requestfailed', r => r.failure().errorText)` 给的还是同一个错误名。
  Firefox 自己有 `MOZ_LOG=nsHttp:5`（配 `MOZ_LOG_FILE`，通过 `launch({ env })` 传入），日志里有 CONNECT 响应的状态行和头，没有正文；
  这是 Mozilla 文档里的调试手段，不在 Playwright 文档里。算不算“文档里写明的手段”需要先定（预期文件按“不算”写的 R81、R85）。未验证。

### 会干扰计数的东西

- **favicon**：Firefox 的界面层在每个顶层 http(s) 页面显示之后会自己取一次 `/favicon.ico`
  （`browser/actors/LinkHandlerChild.sys.mjs:26-39`，`browser/modules/FaviconLoader.sys.mjs:155-190`）。`playwright.cfg` 里没有关它；
  Playwright 在自己的事件里把它藏起来了（PW 源码 `server/network.ts:218` 的 `_isFavicon`），但字节照样上线。
  它不带 `k`，会计入“代理端口上的请求总数”（R36），也可能在下一个请求发出时还占着连接，使明文的连接数多 1（R11、R13、R16），
  或者让仪器的 `only_if_reused` 条件落空（F03、F09）。驱动不要用 `page.route` 去拦它（那会改变被测行为），在结果里如实记录即可；
  要不要在矩阵里排除不带 `k` 的请求由方案决定。
- **浏览器自己的后台请求**：代理配在 `launch` 上时，没有上下文的通道也走这个代理（juggler `TargetRegistry.js:310-318`）。
  `playwright.cfg` 关掉了已知的后台请求，但如果有漏网的，代理上会多出不相干的 CONNECT。配在 `newContext` 上就只管页面自己的请求。
- **每个用例用新的浏览器实例**（或至少新的上下文加确认连接已关）：认证缓存、空闲连接、HTTP 缓存都是进程级的，会把上一个用例的状态带过来。
  同一个用例之内必须是同一个上下文，否则看不到连接复用。

### 版本相关的坑

- `network.proxy.allow_hijacking_localhost=true` 是 Playwright 的设置（见上），换成 Mozilla 发布的 Firefox 结论相反。哪个 Playwright 版本开始这样设未验证。
- Playwright 强制 `network.auth.use_redirect_for_retries=false`（`playwright.cfg:32-33`，注释 This preference breaks our authentication flow），
  407 之后的重试走老路径（在原通道上重发）。Mozilla 发布的 Firefox 这个设置的默认值没有查，行为可能不同。
- 后量子密钥交换（`security.tls.enable_kyber`）在 155.0 默认开（`StaticPrefList.yaml:19051-19055`），ClientHello 超过一个 TCP 包；
  从哪个版本开始默认开未验证。
- CONNECT 非 2xx 的 `NS_ERROR_PROXY_*` 细分错误码是 155.0 源码里的现状（`nsHttp.cpp:845-975`）；更早的版本只有少数几个。从哪个版本开始未验证。
- Playwright 的 Firefox 是打过补丁的构建：`patches/bootstrap.diff` 对 `netwerk/` 的改动只涉及离线判断和 `LoadInfo`，
  不动代理、认证和连接管理；与原版的差别主要来自 `playwright.cfg` 的设置和 juggler 的代理过滤器、认证应答。

## Chromium

写给实现 `chromium-pw` 这一列驱动的人。2026-11-10 写成，**只读了文档和源码，没有让浏览器连过任何代理，也没有启动过浏览器**。
这里的每一条都还没有被实测证实；实测对不上的以实测为准，并记进报告的“与预期不符”。
逐行预期在 `research/phase2/expectations/chromium-pw.json`。

### 读的是哪个版本

| 部件 | 版本 | 来源 |
| --- | --- | --- |
| Playwright | 1.63.0 | 本机 `/opt/node-tools/node_modules/playwright-core/lib/coreBundle.js`（打包后的单文件；任务里写的 `lib/server/chromium/*.js` 在这个版本里已经不单独存在） |
| Chromium | 153.0.8010.12，Playwright 修订号 1243 | `playwright-core/browsers.json`；源码取自 `raw.githubusercontent.com/chromium/chromium/` 的标签 `153.0.8010.12` |
| Playwright 的文档和测试 | 标签 `v1.63.0` | `docs/src/network.md`、`docs/src/release-notes-js.md`、`tests/library/proxy.spec.ts`、`tests/library/browsercontext-proxy.spec.ts` |

下文的出处：`pw:行号` 是 `coreBundle.js` 的行号（括号里写原始文件名），`cr:路径:行号` 是 Chromium 标签 153.0.8010.12 里的路径。
任务里提到的 `net/proxy_resolution/proxy_bypass_rules.cc` 在这个标签下已经不存在，回环规则在 `net/proxy_resolution/proxy_host_matching_rules.cc`。

### 0. 先看这几个会改变结果的选择

预期文件是按“建议”一栏填的。换一种做法，括号里的格子会变。

| 选择 | 建议 | 换一种做法会怎样 |
| --- | --- | --- |
| 启动哪个可执行文件 | `chromium.launch()` 的默认值。默认 `headless: true`，实际启动的是 `chromium_headless_shell-1243` 里的 `chrome-headless-shell`，不是 `chromium-1243`（pw:43370-43376 `getExecutableName`；发布说明 1.49、1.57）。把实际路径和 `browser.version()` 写进结果的 `versions` | 用 `channel: 'chromium'`（新 headless）或 `headless: false` 启动的是完整的 Chrome：没配凭据遇到 407 时会建登录框，`page.goto` 等到超时（R45 变成“报错，没提 407”）；会请求 `/favicon.ico`（R36 以及 R11、R13、R16 这类连接数可能变）；错误页可能自动重新加载（R96、R97、R100 的次数可能变）。这几条都是按源码和印象推断，未验证 |
| 一个用例里建几个上下文 | 一个浏览器、一个 `browser.newContext()`、一个 `context.newPage()`，整个用例都用这一个页面 | `browser.newPage()` 每调用一次就新建一个上下文。Chromium 的每个上下文有自己的连接池和认证缓存（见第 2 节），连接复用、407 次数全都看不到了（R10 到 R16、R36、R38、R44、R90 到 R101 都会变） |
| GET 以外的请求从哪里发 | 按 PROTOCOL：先 `page.goto` 到同源的 `/page?k=用例.pre`，再在页面里 `fetch` 或 `new WebSocket` | 这次预先的导航会吃掉唯一的 407，并留下一条空闲连接。所以 R43、R44 对浏览器测不到“带正文的请求遇到 407”和“并发时的 407”，R15、R16、R123 的 6 条里有 1 条是预先导航留下的 |
| POST 的正文怎么给 | 在 Node 里读文件，base64 传进页面，解成 `Uint8Array` 作 `fetch` 的 `body` | 给 `ReadableStream` 是流式上传：改成 chunked、需要 HTTP/2 或 `duplex: 'half'`，遇到 407 直接失败（cr:services/network/url_loader.cc:1049-1053）。不要这样写 |
| 失败时 `default_text` 记什么 | 只记异常的 `name` 和 `message`（Playwright 的消息里带 Call log） | 把错误页的文字或 NetLog 也写进去，R80、R82、R119 到 R121 的判定会被污染 |
| 额外手段（`extra_text`） | Chromium 的 NetLog：`args: ['--log-net-log=<work_dir>/netlog.json']`，浏览器关闭后读文件，见第 5 节 | 不用的话 R81、R85 是“没有这样的手段” |

### 1. 代理怎么配

文档：`docs/src/network.md` 的“HTTP Proxy”；`types.d.ts` 里 `launch` 和 `newContext` 的 `proxy` 选项（`server`、`bypass`、`username`、`password`）。

HTTP 代理，凭据写在选项里：

```js
const browser = await chromium.launch({
  proxy: { server: 'http://127.0.0.1:40123', username: 'kaoju-user', password: 'kaoju-pass-1' },
});
const context = await browser.newContext();
const page = await context.newPage();
```

SOCKS5 代理：

```js
const browser = await chromium.launch({ proxy: { server: 'socks5://127.0.0.1:40123' } });
```

要点：

- `server` 只留协议、主机、端口（pw:51489-51507 `normalizeProxySettings` 把它重写成 `protocol//host`）。**凭据写在 `server` 的 URL 里会被丢掉**，
  Chromium 自己也不用代理设置里嵌的凭据（`net/docs/proxy.md`“Proxy credentials in manual proxy settings”）。凭据只能用 `username`、`password` 两个字段。
- Playwright 把它变成启动参数 `--proxy-server=<server>` 和 `--proxy-bypass-list=<-loopback>`（pw:43344-43365，`chromium.ts` 的 `_innerDefaultArgs`）。
  凭据不进启动参数，也不进请求头，见下面“凭据经哪条路回答 407”。
- **localhost 和 127.0.0.1 默认也走代理。** Chromium 自己默认绕过回环和链路本地地址（`net/docs/proxy.md`“Implicit bypass rules”，M72 起对手工配置的代理生效），
  但 Playwright 默认加 `<-loopback>` 把这条隐式规则减掉（pw:38302-38308 `shouldProxyLoopback`；`cr:net/proxy_resolution/proxy_host_matching_rules.cc:25`、`:99`）。
  只有在 `bypass` 里写了 `localhost`、`127.0.0.1`、`::1`、`<loopback>` 之一，或设了环境变量 `PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK`，才恢复 Chromium 的默认。
  Playwright 自带测试 `tests/library/proxy.spec.ts:74-121` 断言 localhost 的请求到了代理。驱动不要设 `bypass`，也要把这个环境变量从环境里清掉。
- SOCKS5 只有 `socks5://` 一种写法，含义是“域名交给代理解析”：Chromium 的 SOCKS5 请求里地址类型写死为域名
  （`cr:net/socket/socks5_client_socket.cc:337-358`），IP 字面量也按域名类型发。用例的 `proxy.scheme` 不论是 `socks5` 还是 `socks5h`，驱动都写 `socks5://`，并在结果里说明。
  不要写 `socks5h://`：Playwright 会原样传下去，而 Chromium 不认识这个方案（`cr:net/base/proxy_string_util.cc:242-256` 只认 http、socks4、socks、socks5、https、quic），之后会怎样未验证。
- **SOCKS5 不能配凭据。** `server` 是 `socks5:` 而又给了 `username` 或 `password`，`launch` 和 `newContext` 直接抛
  `Browser does not support socks5 proxy authentication`（pw:51501-51502；测试 `tests/library/browsercontext-proxy.spec.ts:249-254`）。
  S05、S06、S08、S14 到 S22 这些用例：照样调用一次 `launch`，把抛出的消息记下来，然后把整个用例报成 `unsupported`。
- SOCKS5 代理时 Playwright 还会加 `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE <代理主机>"`（pw:43352-43354），本意是禁止本机解析。
  参数里的引号是字面量（进程不是经 shell 启动的），按 `cr:net/base/host_mapping_rules.cc:108-135` 的解析规则，带引号的 `"MAP` 不会被认作 MAP 规则，这个参数很可能不起作用；未验证。它对用例结果没有影响。
- Playwright 默认还关掉了 `HttpsUpgrades`（pw:34829，`chromiumSwitches.ts`），所以 `http://` 的导航不会先试 `https://`。
- 浏览器进程会继承环境变量。启动参数里有 `--proxy-server` 时它压过环境里的代理变量；只用上下文级代理（第 2 节）时浏览器级的请求会读系统代理设置，所以环境里的代理变量仍然要清（PROTOCOL 已经规定）。

**凭据经哪条路回答 407**（R30、R31、R47、R48 的依据）：

1. Chromium 的上下文在构造时把代理的 `username`、`password` 放进上下文的 `httpCredentials`，不带 `origin`
   （pw:38576 调 pw:51852-51859 `authenticateProxyViaCredentials`；Firefox 和 WebKit 走的是另一个函数 `authenticateProxyViaHeader`，直接加 `Proxy-Authorization` 请求头）。
2. 有凭据时，每个页面会话启用 `Fetch.enable {handleAuthRequests: true, patterns: [{urlPattern: '*', requestStage: 'Request'}]}`，同时 `Network.setCacheDisabled(true)`（pw:36102-36118）。
   也就是说：配了代理凭据，浏览器的 HTTP 缓存就被关掉，每个请求还会多带 `Pragma: no-cache` 和 `Cache-Control: no-cache`（`cr:net/http/http_network_transaction.cc:1415-1417`）。
3. 第一个请求不带凭据。代理回 407 后 Chromium 把认证请求交给 DevTools（`cr:content/browser/storage_partition_impl.cc:516-519`），Playwright 收到 `Fetch.authRequired`，
   回 `Fetch.continueWithAuth {response: 'ProvideCredentials'}`；同一个请求再收到质询就回 `CancelAuth`（pw:36167-36181）。所以密码错时只带着凭据试 1 次。
4. Chromium 在带凭据重试之前就把凭据写进认证缓存（`cr:net/http/http_auth_controller.cc:318-361`），之后这个上下文里的每个请求、每个新 CONNECT 都预先带上（`:145-180`）。

### 2. 同一个进程里对不同请求用不同的代理凭据

常规做法是每个用户一个浏览器上下文，各自带 `proxy` 选项（`docs/src/network.md` 的 “should use custom proxy on a new context” 例子）：

```js
const browser = await chromium.launch({ proxy: { server: 'http://127.0.0.1:40123' } });   // 不带凭据
const ctxA = await browser.newContext({ proxy: { server: 'http://127.0.0.1:40123', username: 'kaoju-user', password: 'kaoju-pass-1' } });
const ctxB = await browser.newContext({ proxy: { server: 'http://127.0.0.1:40123', username: 'kaoju-user-2', password: 'kaoju-pass-2' } });
```

- 每个 `newContext({proxy})` 对应一次 `Target.createBrowserContext {proxyServer, proxyBypassList}`（pw:38379-38392），是一个独立的 Chromium BrowserContext，
  有自己的网络会话，连接池和认证缓存都不共享（认证缓存是 `HttpNetworkSession` 的成员，`cr:net/http/http_network_session.h:335`）。
  Playwright 自带测试：`tests/library/browsercontext-proxy.spec.ts:298-326`、`:423-455`（issue 31525）。
- 上下文没有自己的 `proxy` 时用启动时的那个，凭据也取启动时的（pw:51853）。
- Linux 上不需要先用一个占位的全局代理启动（`tests/library/browsercontext-proxy.spec.ts:25-43` 测的就是只在上下文上配）。
- 同一个上下文里没有按请求换代理凭据的办法：凭据进了缓存就一直用。
- SOCKS5 没有凭据可换，S14 是“不支持”。

### 3. 信任测试用的 CA

不要用 `ignoreHTTPSErrors: true`，那是关闭校验。Linux 上的 Chromium 读用户的 NSS 共享数据库（`cr:docs/linux/cert_management.md`），把测试 CA 加进去即可，不改变代理和 HTTP/2 行为：

```sh
mkdir -p "$HOME/.pki/nssdb"
certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n kaoju-test-ca -i "$CA_FILE"
```

- 驱动的 `HOME` 是这次运行专用的目录（PROTOCOL），浏览器继承它，所以数据库也是这次运行专用的。本机有 `certutil`（`libnss3-tools`）；CI 上要装这个包。
- **路径的坑**：M146 起默认位置改成 `${XDG_DATA_HOME:-$HOME/.local/share}/pki/nssdb`，但 `$HOME/.pki/nssdb` 已经存在时仍然用它（`cr:crypto/nss_util.cc:43-66`，文档同上）。
  上面的写法先建好旧位置，两种版本都能用；同时确认环境里没有 `XDG_DATA_HOME` 指到别处。
- 文档写的是 Chromium；`chrome-headless-shell` 是否同样读这个数据库没有找到单独的说明，未验证。如果实测证书报错（`net::ERR_CERT_AUTHORITY_INVALID`），先查这里。
- 用例里的 CA 是 ECDSA P-256，没有需要额外处理的地方。

### 4. 并发、重定向、POST、WebSocket 的写法

PROTOCOL 规定：GET 是顶层导航；POST、`parallel`、`ws` 从同源的 `/page` 页面里发。

```js
// GET：顶层导航。自动跟随重定向，没有不跟随的开关；follow 为 false 的步骤里目标本来就不重定向。
const resp = await page.goto(url, { waitUntil: 'load', timeout: timeoutMs });
// resp.status()、resp.statusText()、await resp.allHeaders()、await resp.text()
// 跟随过重定向时：resp.request().redirectedFrom() 是上一跳的请求

// POST 和并发：先到同源的 /page，再在页面里 fetch
await page.goto(origin + '/page?k=' + caseId + '.pre', { timeout: timeoutMs });
const results = await page.evaluate(async (reqs) => Promise.all(reqs.map(async (q) => {
  const init = { method: q.method };
  if (q.b64) {
    init.body = Uint8Array.from(atob(q.b64), (c) => c.charCodeAt(0));
    init.headers = { 'Content-Type': 'application/octet-stream' };
  }
  try {
    const r = await fetch(q.url, init);
    return { ok: true, status: r.status, statusText: r.statusText, headers: [...r.headers], body: await r.text() };
  } catch (e) {
    return { ok: false, error: e.name + ': ' + e.message };
  }
})), reqs);

// WebSocket：同样先到 /page
const ws = await page.evaluate((u) => new Promise((res) => {
  const s = new WebSocket(u);
  s.onopen = () => res('open'); s.onclose = (e) => res('close ' + e.code); s.onerror = () => res('error');
}), wsUrl);
```

- 6 个并发就是一个 `Promise.all`。同一个源、HTTP/1.1 时每个目标最多 6 条连接，每个代理最多 128 条
  （`cr:net/socket/client_socket_pool_manager.cc:54-66`；连接按目标分组而不是按代理分组，`:99-101`）；源站支持 h2 时全部走一条隧道上的一个会话。
- `fetch` 的正文是内存里的字节时带 `Content-Length`（`cr:net/http/http_network_transaction.cc:1395-1403`），Chromium 不发 `Expect: 100-continue`。
- 2 MiB 的正文经 base64 传进 `page.evaluate` 没有问题，但要算进这一步的耗时。
- 页面里 `fetch` 失败时只有 `TypeError: Failed to fetch`，没有错误码。错误码在 Node 一侧：`page.on('requestfailed', r => r.failure().errorText)`。
  这是文档里的常规事件，驱动可以把它记进 `default_text`，但要在结果的 `config` 里写明。
- `ws://` 经 HTTP 代理时也用 CONNECT（目标端口 80），隧道里是明文的升级请求；WebSocket 用单独的连接池，只提供 `http/1.1` 这一个 ALPN
  （`cr:net/socket/client_socket_pool.cc:240-255`；`net/docs/proxy.md`“Mapping WebSockets URLs to a proxy”）。
- `/echo` 返回的是 JSON，顶层导航会把它当文本显示，`load` 事件照常触发；`resp.text()` 就是正文。
- 状态码是 4xx、5xx 的导航不抛异常，`page.goto` 照常返回 Response。完整的 Chrome 对“错误状态且正文为空”的主框架响应会改成报 `net::ERR_HTTP_RESPONSE_CODE_FAILURE`
  （`cr:content/browser/renderer_host/http_error_navigation_throttle.cc`，取决于嵌入方有没有错误页）；obsproxy 的 407、403 都有正文，碰不到。

### 5. 代理出错时调用方能拿到什么

默认用法（`page.goto` 的返回值或异常）：

| 情况 | 调用方看到的 | 出处 |
| --- | --- | --- |
| CONNECT 回非 2xx（407 除外） | 异常 `page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at <URL>`，后面是 Call log。状态码、原因短语、响应头、正文都没有；不重试，也不读 `Retry-After` | `cr:net/http/http_proxy_client_socket.cc:523-530`（注释：为了不让代理冒充目标站，响应被丢弃）；pw:37696-37702 |
| 明文请求被代理回 403 等 | 普通的 Response：状态码、原因短语、响应头、正文都在 | 代理的响应就是页面的响应 |
| 明文，没配凭据，代理回 407 | headless shell：普通的 Response，状态码 407（没有登录框，认证被取消，407 当页面显示） | `cr:content/browser/storage_partition_impl.cc:530-567`、`cr:content/public/browser/content_browser_client.cc:1302-1315`、`cr:net/url_request/url_request_http_job.cc:1688-1708` |
| HTTPS，没配凭据或密码错，代理回 407 | 预期是异常，消息里没有 407（`net::ERR_TUNNEL_CONNECTION_FAILED`，或者等 `load` 到超时）。这一条没有把握，见“没弄清的地方” | `cr:net/http/http_network_transaction.cc:645-665` |
| 明文，密码错，代理一直回 407 | 带凭据试 1 次后 Playwright 取消认证，得到状态码 407 的 Response | pw:36167-36181 |
| 407 带 `Connection: close` | 换一条连接带凭据重发，成功（明文和 CONNECT 都是） | `cr:net/http/http_network_transaction.cc:605-626`；`cr:net/http/http_proxy_connect_job.cc:844-870`；测试 `tests/library/proxy.spec.ts:165-201`（issue 40768） |
| CONNECT 发出后代理直接关连接 | 异常 `net::ERR_EMPTY_RESPONSE`，不重试 | `cr:net/http/http_stream_parser.cc:853-868` |
| SOCKS5：代理选了 0xFF，或应答码非 0 | 都是 `net::ERR_SOCKS_CONNECTION_FAILED`，分不出是哪一种 | `cr:net/socket/socks5_client_socket.cc:326-330`、`:428-432` |
| CONNECT 成功时 200 里附加的头 | 看不到；`resp.allHeaders()` 是源站的响应头 | 同第一行 |

需要主动打开的额外手段：

- Playwright 的 API 里没有读 CONNECT 响应的入口。`request.failure()`、`page.on('requestfailed')` 给的还是同一个错误码；CDP 的 `Network.loadingFailed` 也一样。
- Chromium 的 NetLog 可以：`chromium.launch({ args: ['--log-net-log=' + path] })`（`cr:net/docs/net-log.md`；开关在 content 层处理，
  `cr:content/browser/network_service_instance_impl.cc:701`，headless shell 也有效）。每个 CONNECT 响应都会记一条
  `HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS`，内容是状态行和全部响应头（`cr:net/http/http_proxy_client_socket.cc:469-471`、
  `cr:net/http/http_response_headers.cc:1614-1629`）；默认的捕获级别只抹掉 Cookie 和认证头的值（`cr:net/http/http_log_util.cc:48-63`）。正文不记。
  SOCKS5 的应答码也在里面（`SOCKS_SERVER_ERROR` 事件的 `error_code`）。
  文件在浏览器正常关闭（`browser.close()`）后才写完整，所以驱动要先关浏览器再读，并按 URL 里的 `k` 把事件对回步骤。
  这是 Chromium 文档里的手段，不是 Playwright 文档里的；算不算 PROTOCOL 说的“文档里写明的手段”要由驱动作者定，定了以后写进 `extra_how`。预期文件按“采用”填。

### 6. 特别查过的几件事

| 问题 | 结论 | 出处 |
| --- | --- | --- |
| 第一次请求带不带代理凭据 | 不带，等 407；之后同一个上下文里预先带 | 第 1 节 |
| 407 之后复用连接吗 | 407 保持连接、找得到响应结尾时，读完正文在原连接上重发；否则换连接 | `cr:net/http/http_network_transaction.cc:572-638`；`cr:net/http/http_proxy_client_socket.cc:207-241` |
| CONNECT 带哪些头 | `Host`、`Proxy-Connection: keep-alive`、`User-Agent`，有凭据时加 `Proxy-Authorization`。`Host` 与请求目标相同。`User-Agent` 是浏览器的，不受上下文的 `userAgent` 选项影响 | `cr:net/http/proxy_client_socket.cc:25-45`；测试 `tests/library/proxy.spec.ts:339-340` |
| 明文请求的形式 | 绝对形式，`Host` 之后是 `Proxy-Connection: keep-alive`，没有 `Connection` | `cr:net/http/http_util.cc:98-106`；`cr:net/http/http_network_transaction.cc:1381-1392` |
| HTTP/2 | 隧道里提供 `h2,http/1.1`，源站支持就用 h2；经代理时不同主机名不会合并到一条 h2 连接上 | `cr:net/http/http_network_session.cc:210-218`；`cr:net/socket/client_socket_pool.cc:223-225` |
| ClientHello 的大小 | 默认带 X25519MLKEM768 的密钥份额（1216 字节），整个 ClientHello 超过 1460 字节，在真实链路上会跨两个 TCP 包 | `cr:net/ssl/ssl_config_service.cc:29-34` |
| 连接失效后自动重发 | 条件只有两个：连接是复用的、还没收到响应头。不看方法，**POST 也重发**。新连接上的第一个请求失败不重发 | `cr:net/http/http_network_transaction.cc:2057-2154`、`:2319-2327` |
| CONNECT 失败后换代理或重试吗 | 不。`ERR_TUNNEL_CONNECTION_FAILED` 不触发换代理，列表里也只有一个代理 | `cr:net/http/proxy_fallback.cc:103-110` |
| 用户名的字符和长度 | 没有限制也不转义：令牌是 `base64(UTF-8(用户名) + ":" + UTF-8(密码))`，不看质询里的 `charset`；用户名里的冒号原样拼进去 | `cr:net/http/http_auth_handler_basic.cc:85-97`；`cr:content/browser/devtools/protocol/fetch_handler.cc:481-484` |
| 空密码 | 发 `用户名:`。用户名为空时 Playwright 根本不设凭据 | pw:51857-51858；测试 `tests/library/browsercontext-proxy.spec.ts:281` |

**一处矩阵没有覆盖的泄露面**：上下文的 `httpCredentials` 被设成了代理的凭据，而且不带 `origin`；`_onAuthRequired` 不区分质询来自代理还是源站
（pw:36167-36181、pw:51457-51460）。按源码，源站回 `401` 加 `WWW-Authenticate: Basic` 时，Playwright 会把代理的用户名和密码答给源站
（以 `Authorization` 头的形式，所以 R39 查的 `Proxy-Authorization` 看不到它）；用户自己在上下文上配的 `httpCredentials` 也会被代理凭据覆盖。未验证。

### 7. 版本相关的坑

- Playwright 1.49 起默认的 headless 是单独的 `chrome-headless-shell`，`channel: 'chromium'` 才是完整浏览器的新 headless；1.57 起用的是 Chrome for Testing 的构建（`docs/src/release-notes-js.md`）。两者在 407、favicon、错误页上的行为不同，见第 0 节。
- 回环地址：Chromium M72 起对手工配置的代理默认绕过 localhost（`net/docs/proxy.md`）；Playwright 反过来强制走代理，开关是环境变量 `PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK`。这个行为是哪个 Playwright 版本加的没有核对。
- CONNECT 的 407 关连接后重连：测试注明 issue 40768，是近期修过的路径；旧版本的行为没有核对。
- 上下文之间隔离代理凭据：测试注明 issue 31525。
- NSS 数据库的默认位置在 M146 变了（第 3 节）。
- 每个代理的连接上限在这个标签里是 128（`cr:net/socket/client_socket_pool_manager.cc:62-66`）；常见的说法是 32，哪个版本改的没有核对。
- 后量子密钥交换在这个标签里是写死的默认值，没有特性开关；从哪个版本开始默认开启没有核对。
- Playwright 1.63 的服务端代码打成了一个 `coreBundle.js`，行号只对这一个版本有效。

### 8. 没弄清的地方

- **HTTPS 目标、认证被取消（C02、C04，对应 R46、R49）。** 读正文一定失败（`ERR_TUNNEL_CONNECTION_FAILED`），但 `cr:services/network/url_loader.cc` 会先把 407 的响应头交给导航再报失败，
  `cr:content/browser/loader/navigation_url_loader_impl.cc` 收到响应头就把后续消息的管道交出去了。`page.goto` 最后是抛错、超时，还是返回一个 407 的 Response，从源码没能确定。预期填的是“报错，没提 407”，置信度低。
- headless shell 是否读 NSS 数据库（第 3 节）。
- `fetch` 的请求会不会被网络服务的调度器延后（影响 R15、R16、R123 是不是正好 6 条）：没有逐行核对 `resource_scheduler.cc`。
- 明文经代理的空闲连接是否只在同一个目标分组里复用（R13 填的是 2）：没有找到跨分组复用的代码，按没有处理。
