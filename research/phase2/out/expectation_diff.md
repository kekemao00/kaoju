# 实测与预期不符的格子

由 `runner/matrix.py` 生成。预期在 `expectations/<列>.json`，写于第一次正式运行之前；预期是“不知道”或没写的行不比。
不符的格子先怀疑仪器和驱动，确认以后记进报告；预期文件不改。

## `chromium-pw`

比较了 104 格，相符 103 格，不符 1 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

| 行 | 预期 | 实测 | 把握 | 依据 |
| --- | --- | --- | --- | --- |
| R89 CONNECT 失败之后，对另一个源的请求 | 成功 | 失败 | high | 上一步的失败不影响别的源：ERR_TUNNEL_CONNECTION_FAILED 不会把代理标成坏的（cr:net/http/proxy_fallback.cc:103-110 返回 false，不进入 ProxyList::Fallback）。 |

## `curl-anyauth`

比较了 104 格，相符 104 格，不符 0 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

## `curl`

比较了 104 格，相符 104 格，不符 0 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

## `firefox-pw`

比较了 0 格，相符 0 格，不符 0 格；预期为“不知道”或没写 1 行；有预期但没有实测 103 行。

## `go`

比较了 104 格，相符 104 格，不符 0 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

## `node-agents`

比较了 104 格，相符 104 格，不符 0 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

## `node-axios`

比较了 104 格，相符 104 格，不符 0 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

## `node-fetch-env`

比较了 104 格，相符 96 格，不符 8 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

| 行 | 预期 | 实测 | 把握 | 依据 |
| --- | --- | --- | --- | --- |
| R10 HTTPS 同一个源连续 3 次：隧道数 | 1 | 2 | high | 每个源一个 Pool（u6:dispatcher/agent.js），连接保持（keepAliveTimeout 默认 4 秒，u6:dispatcher/client.js:231），三个请求依次发，复用同一条隧道。 |
| R11 明文同一个源连续 3 次：代理连接数 | 1 | 2 | high | 明文也走隧道（R01），同一个源复用同一条；代理端口上只有一次 accept。 |
| R36 明文连续 3 次：代理收到的请求数 / 其中没带凭据的 | 1/0 | 2/0 | medium | 明文三个请求都在同一条 CONNECT 到 80 的隧道里（R01、R11），代理端口上只有 1 个 http_request（带凭据的 CONNECT）。 |
| R38 HTTPS 同一个源连续 3 次（要认证）：隧道数 | 1 | 2 | high | 同 R10。 |
| R94 HTTPS，复用的隧道，GET，隧道被切断（FIN）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：连接在等响应时被关，队首的请求直接报错（u6:dispatcher/client-h1.js:765、:797 一带，FIN 是 SocketError: other side closed，RST 是 ECONNRESET）；fetch 只在 421 时重试（u6:web/fetch/index.js），RetryAgent 不是默认。 |
| R95 HTTPS，复用的隧道，POST，隧道被切断（FIN）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：连接在等响应时被关，队首的请求直接报错（u6:dispatcher/client-h1.js:765、:797 一带，FIN 是 SocketError: other side closed，RST 是 ECONNRESET）；fetch 只在 421 时重试（u6:web/fetch/index.js），RetryAgent 不是默认。 |
| R99 HTTPS，复用的隧道，GET，隧道被复位（RST）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：连接在等响应时被关，队首的请求直接报错（u6:dispatcher/client-h1.js:765、:797 一带，FIN 是 SocketError: other side closed，RST 是 ECONNRESET）；fetch 只在 421 时重试（u6:web/fetch/index.js），RetryAgent 不是默认。 |
| R101 HTTPS（源站支持 h2），复用的隧道，GET，隧道被切断：请求到达几次，结果 | 1 次，失败 | 未触发 | high | 这一列不谈 h2（R08），源站支持 h2 与否无关；其余同 R94。 |

## `node-http-env`

比较了 102 格，相符 102 格，不符 0 格；预期为“不知道”或没写 2 行；有预期但没有实测 0 行。

## `node-undici`

比较了 104 格，相符 96 格，不符 8 格；预期为“不知道”或没写 0 行；有预期但没有实测 0 行。

| 行 | 预期 | 实测 | 把握 | 依据 |
| --- | --- | --- | --- | --- |
| R11 明文同一个源连续 3 次：代理连接数 | 1 | 2 | high | Http1ProxyWrapper 里是一个到代理的 Pool（u8:dispatcher/proxy-agent.js:58-62），连接保持（keepAliveTimeout 默认 4 秒），连续请求复用。 |
| R92 明文，复用的连接，GET，连接被关（FIN）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：等响应时连接被关，队首请求报错（u8:dispatcher/client-h1.js:1015-1027、:1059-1065）；fetch 只在 421 时重试，RetryAgent 和 interceptors.retry 都不是默认。 |
| R93 明文，复用的连接，POST，连接被关（FIN）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：等响应时连接被关，队首请求报错（u8:dispatcher/client-h1.js:1015-1027、:1059-1065）；fetch 只在 421 时重试，RetryAgent 和 interceptors.retry 都不是默认。 |
| R94 HTTPS，复用的隧道，GET，隧道被切断（FIN）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：等响应时连接被关，队首请求报错（u8:dispatcher/client-h1.js:1015-1027、:1059-1065）；fetch 只在 421 时重试，RetryAgent 和 interceptors.retry 都不是默认。（F05、F06、F08、F10 的源站只说 HTTP/1.1。） |
| R95 HTTPS，复用的隧道，POST，隧道被切断（FIN）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：等响应时连接被关，队首请求报错（u8:dispatcher/client-h1.js:1015-1027、:1059-1065）；fetch 只在 421 时重试，RetryAgent 和 interceptors.retry 都不是默认。（F05、F06、F08、F10 的源站只说 HTTP/1.1。） |
| R98 明文，复用的连接，GET，连接被复位（RST）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：等响应时连接被关，队首请求报错（u8:dispatcher/client-h1.js:1015-1027、:1059-1065）；fetch 只在 421 时重试，RetryAgent 和 interceptors.retry 都不是默认。 |
| R99 HTTPS，复用的隧道，GET，隧道被复位（RST）：请求到达几次，结果 | 1 次，失败 | 未触发 | high | undici 的 HTTP/1.1 客户端不重发已经写出的请求：等响应时连接被关，队首请求报错（u8:dispatcher/client-h1.js:1015-1027、:1059-1065）；fetch 只在 421 时重试，RetryAgent 和 interceptors.retry 都不是默认。（F05、F06、F08、F10 的源站只说 HTTP/1.1。） |
| R122 HTTPS 同一个源连续 3 次：SOCKS5 连接数 | 1 | 2 | medium | 每个源一个 Pool（u8:dispatcher/socks5-proxy-agent.js:231-298），连接保持，三个请求依次复用。SOCKS5 这条路径上的 tls.connect 没给 ALPNProtocols（:256-260），是 HTTP/1.1。 |

## `requests`

比较了 103 格，相符 103 格，不符 0 格；预期为“不知道”或没写 1 行；有预期但没有实测 0 行。
