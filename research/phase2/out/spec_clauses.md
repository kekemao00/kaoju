# 规范条款表

<!-- 由 research/phase2/spec/spec_tables.py 生成，不要手改；改了条款文件就重新生成 -->

本表由 `research/phase2/spec/spec_tables.py` 从 `research/phase2/spec/clauses/*.json` 生成，不要手改。

- “原文”是 RFC 的原话，逐字引用，只把换行和连续空白折成了一个空格，在每个主题的表后面，点开就能对照。
- “对网关的含义”是我们的解读，不是 RFC 的原话；写“背景”的是推不出具体要求的条款。
- 级别是原文里的规范性关键词；statement 指没有规范性关键词的事实陈述或定义。
- “约束谁”是条款约束的角色；“哪一侧”是对网关而言：入口（网关作为代理或 SOCKS5 服务端）、上游（网关作为上游代理的客户端）、两侧、客户端（只约束连到网关的客户端，网关据此判断客户端的行为是否合规）。
- 矩阵行是 `research/phase2/rows.json` 里的行号。
- 本表只是渲染，不代表核对过。引文是不是原文、在不在所标的章节里、级别与关键词是否一致，由 `spec/check_quotes.py` 对着 RFC 文本逐条核对；文本怎么取、怎么核对见 `spec/README.md`。

## 概览

| RFC | 标题 | 条款数 | 条款文件 | 所用文本的 SHA-256 |
| --- | --- | --- | --- | --- |
| RFC 9110 | HTTP Semantics | 147 | `clauses/rfc9110.json` | `21c1cdce6ab0e5509b04d84a28000836c7a087cf786efe6f04877ebfff47232a` |
| RFC 9112 | HTTP/1.1 | 113 | `clauses/rfc9112.json` | `e4f426bac6206b67fdf9e0da826154f70588db2133a0a86b15cde4ff725d8937` |
| RFC 1928 | SOCKS Protocol Version 5 | 29 | `clauses/rfc1928.json` | `ddc2916419a52bedae0fc7d0c051ea513e88c2b930dda27128982fb0c1d6fe2a` |
| RFC 1929 | Username/Password Authentication for SOCKS V5 | 8 | `clauses/rfc1929.json` | `b023357f33b42ba1f3ae10b45ebfcc6dd7b6b13eba0743052b08ae3f7ae3581b` |
| RFC 6455 | The WebSocket Protocol | 6 | `clauses/rfc6455.json` | `765775326aee0ecca9b04bde3fd1f52932d498e33e34e428bd61b8a24da0fa3b` |
| RFC 7617 | The 'Basic' HTTP Authentication Scheme | 23 | `clauses/rfc7617.json` | `bc941321da9912fbb1bc92ad1820848ddfd3283dbfbc30f26ea2800bdaf541db` |
| RFC 9113 | HTTP/2 | 4 | `clauses/rfc9113.json` | `a00ef91b64e111a282e77ec66980f5242e77c0bb5e33e0927e3b6757080506de` |
| RFC 9209 | The Proxy-Status HTTP Response Header Field | 42 | `clauses/rfc9209.json` | `f8fad90cdc25954dd7419bd8b5f67620252706dade2f5e08a63f4083406f9da1` |
| 合计 | | 372 | | |

按级别：

| RFC | MUST | MUST NOT | SHOULD | SHOULD NOT | MAY | REQUIRED | RECOMMENDED | OPTIONAL | statement | 合计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RFC 9110 | 31 | 21 | 15 | 5 | 13 | 0 | 0 | 0 | 62 | 147 |
| RFC 9112 | 43 | 14 | 15 | 1 | 8 | 0 | 1 | 0 | 31 | 113 |
| RFC 1928 | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 25 | 29 |
| RFC 1929 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7 | 8 |
| RFC 6455 | 2 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 2 | 6 |
| RFC 7617 | 2 | 1 | 0 | 1 | 1 | 1 | 0 | 1 | 16 | 23 |
| RFC 9113 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 4 |
| RFC 9209 | 3 | 2 | 3 | 1 | 1 | 0 | 0 | 1 | 31 | 42 |
| 合计 | 88 | 38 | 34 | 8 | 23 | 1 | 1 | 3 | 176 | 372 |

按主题：

| 主题 | 条款数 | 入口 | 上游 | 两侧 | 客户端 |
| --- | --- | --- | --- | --- | --- |
| request-target：请求目标的形式 | 30 | 15 | 1 | 9 | 5 |
| connect：CONNECT 方法 | 19 | 9 | 0 | 10 | 0 |
| tunnel：隧道 | 7 | 3 | 0 | 1 | 3 |
| proxy-auth：代理认证（407、Proxy-Authenticate、Proxy-Authorization） | 28 | 13 | 0 | 11 | 4 |
| hop-by-hop：逐跳的头字段 | 22 | 12 | 0 | 7 | 3 |
| via：Via | 8 | 8 | 0 | 0 | 0 |
| framing：消息定界 | 29 | 6 | 3 | 17 | 3 |
| smuggling：请求走私 | 38 | 15 | 3 | 20 | 0 |
| connection：连接管理 | 31 | 12 | 3 | 16 | 0 |
| retry：重试 | 11 | 2 | 0 | 7 | 2 |
| expect：Expect 与 100-continue | 15 | 8 | 1 | 2 | 4 |
| status：状态码 | 19 | 13 | 1 | 3 | 2 |
| socks-negotiation：SOCKS5 方法协商 | 8 | 1 | 0 | 7 | 0 |
| socks-auth：SOCKS5 用户名密码认证 | 11 | 0 | 0 | 11 | 0 |
| socks-request：SOCKS5 请求 | 12 | 4 | 0 | 8 | 0 |
| socks-reply：SOCKS5 应答 | 6 | 0 | 0 | 6 | 0 |
| basic：Basic 认证方案 | 23 | 6 | 0 | 14 | 3 |
| proxy-status：Proxy-Status | 42 | 38 | 2 | 2 | 0 |
| h2：HTTP/2 | 4 | 3 | 0 | 0 | 1 |
| websocket：WebSocket | 9 | 1 | 0 | 1 | 7 |

## 按主题

### request-target：请求目标的形式

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-3.7-3 | RFC 9110 §3.7 Intermediaries | statement | proxy | 入口 | 背景：proxy 的定义。代理是客户端自己选的（通常靠本地配置），接收的是绝对 URI 的请求。 | R01 |
| 9110-4.2.1-1 | RFC 9110 §4.2.1 http URI Scheme | MUST | recipient | 入口 | 入口解析绝对形式的请求目标时，主机为空的 http URI（如 http:///path）必须当作无效拒绝（absolute-form 的请求本来也不取 Host，见 9112-3.2.2-3）。重建目标 URI 之后 authority 为空是另一种情形，见 9112-3.3-3。用哪个状态码拒绝，这两句没有说。4.2.2 节对 https URI 有一句相同的话（没有另摘）。 | R01 |
| 9110-4.2.3-1 | RFC 9110 §4.2.3 http(s) Normalization and Comparison | statement | any | 客户端 | 背景：规范形式是省略默认端口，所以绝对形式的 http 请求目标通常不带 :80；入口解析时端口缺省要按方案补默认值。CONNECT 的请求目标不适用（见 9110-9.3.6-2）。 | R01 |
| 9110-4.2.3-2 | RFC 9110 §4.2.3 http(s) Normalization and Comparison | MAY | any | 两侧 | 任何 HTTP 组件都可以对 http(s) URI 做规范化，网关不能指望请求目标逐字节保持客户端写的样子；但代理转发时对路径和查询串的改动另有限制（9110-7.7-2）。 | R01 |
| 9110-4.2.4-1 | RFC 9110 §4.2.4 Deprecation of userinfo in http(s) URIs | MUST NOT | sender | 两侧 | 合规的客户端发来的绝对形式请求目标里不会有 user:pass@；网关向上游发绝对形式的请求目标时也不能生成 userinfo。代理凭据走 Proxy-Authorization，不走 URI。 | R01 |
| 9110-4.2.4-2 | RFC 9110 §4.2.4 Deprecation of userinfo in http(s) URIs | SHOULD | recipient | 入口 | 入口收到的绝对形式请求目标来自不可信的客户端，应当检查 userinfo，出现就按错误处理（例如回 400），不要带着它去连目标或转给上游。 | R01 |
| 9110-7.1-1 | RFC 9110 §7.1 Determining the Target Resource | statement | client | 两侧 | CONNECT 的请求目标是“主机名:端口”这一种形式；入口按这个形式解析，网关向上游发 CONNECT 也用这个形式。 | R03 |
| 9110-7.1-2 | RFC 9110 §7.1 Determining the Target Resource | MUST NOT | client | 客户端 | “These forms”指上文列的两种特殊形式：CONNECT 的“主机:端口”和 OPTIONS 的“*”。别的方法用了这两种形式的请求目标是客户端违规，入口可以据此拒绝。 | R01、R03 |
| 9110-7.1-3 | RFC 9110 §7.1 Determining the Target Resource | statement | recipient | 入口 | 背景：入口要从收到的各部分（请求行、Host）重建目标 URI，具体做法由各版本规定（HTTP/1.1 的在 RFC 9112 第 3.3 节，不在本文件）。 | R01、R05 |
| 9110-7.2-1 | RFC 9110 §7.2 Host and :authority | statement | client | 客户端 | 背景：Host 带的是目标 URI 的主机和端口。入口可以拿它与请求目标对照，判断客户端的行为。 | R01、R05 |
| 9110-7.2-2 | RFC 9110 §7.2 Host and :authority | MUST | client | 客户端 | 约束的是 user agent：合规的客户端发来的 HTTP/1.1 请求（包括 CONNECT）都带 Host。这一条的字面不约束作为中间人的网关；网关向上游发请求时带不带 Host 由 RFC 9112 的条款管。 | R04、R05 |
| 9110-7.2-3 | RFC 9110 §7.2 Host and :authority | SHOULD | client | 客户端 | 背景：客户端应当把 Host 放在头部分的第一个。只用于解释客户端的行为，入口不能依赖这个顺序。 | R04、R05 |
| 9110-7.3.2-1 | RFC 9110 §7.3.2 To a Proxy | statement | client | 两侧 | 背景：客户端用代理的方式是与代理建立或复用一条连接，再发请求目标与其目标 URI 相符的请求。条款允许复用连接，所以入口的一条连接上会先后出现不同目标的请求。 | R01、R11、R13 |
| 9110-7.6-3 | RFC 9110 §7.6 Message Forwarding | MUST NOT | intermediary | 入口 | 网关不得把消息转发给自己，除非有防止无限循环的保护。实现上要认得出指向网关自己（各个名字、别名、IP 字面量）的请求目标并直接应答；目标是 localhost 的请求是否算“指向自己”取决于由谁来解析这个名字，条款没有说。 | R17、R18 |
| 9110-7.7-1 | RFC 9110 §7.7 Message Transformations | MUST NOT | proxy | 入口 | 目标 URI 里是完全限定域名时，网关转发时不得改主机名。不是完全限定域名时可以（MAY）补上自己的域，不是必须。 | R01、R17 |
| 9110-7.7-2 | RFC 9110 §7.7 Message Transformations | MUST NOT | proxy | 入口 | 转发时不得改动目标 URI 的路径和查询串，转发协议本身要求的除外（原文举的例子：经 HTTP/1.1 转给源站时把空路径换成“/”或“*”）。网关不能对路径做解码再编码之类的“整理”。 | R01 |
| 9110-17.9-1 | RFC 9110 §17.9 Disclosure of Sensitive Information in URIs | statement | any | 两侧 | 背景：服务器和代理常把目标 URI 记进日志。明文请求的完整 URI、CONNECT 的目标主机和端口，上游代理都看得到；网关自己记日志时也要考虑其中的敏感信息。 | — |
| 9112-3-3 | RFC 9112 §3 Request Line | RECOMMENDED | any | 两侧 | 网关给请求行设的上限建议不低于 8000 字节。 | — |
| 9112-3.2-1 | RFC 9112 §3.2 Request Target | SHOULD NOT | recipient | 入口 | 入口收到不合法的请求行（例如请求目标里有空白）应当回 400（或带正确编码的 301），不应当自己修好之后继续转发。 | R01、R03 |
| 9112-3.2-2 | RFC 9112 §3.2 Request Target | MUST | client | 两侧 | 约束客户端：每个 HTTP/1.1 请求都要带 Host，值与目标 URI 的 authority 相同、不含 userinfo。网关向上游发请求时自己要遵守；也用来判断连到网关的客户端发的 Host 是否合规。 | R01、R05 |
| 9112-3.2-3 | RFC 9112 §3.2 Request Target | MUST | recipient | 入口 | 原文主语是 server。入口收到的 HTTP/1.1 请求（原文不分方法，CONNECT 也在内）没有 Host、有多行 Host 或 Host 值不合法时，回 400。这里的 server 是连接上收请求的一方，网关在入口一侧就是这个角色。 | R01、R05 |
| 9112-3.2.1-1 | RFC 9112 §3.2.1 origin-form | MUST | client | 上游 | 网关自己直接对源站发明文请求时（上游是 SOCKS5 代理，网关与源站之间没有 HTTP 代理），请求目标要从收到的 absolute-form 改成 origin-form，空路径写成 "/"。 | R01 |
| 9112-3.2.2-1 | RFC 9112 §3.2.2 absolute-form | MUST | client | 两侧 | 约束客户端：发给代理的非 CONNECT 请求用 absolute-form。入口据此判断客户端的明文请求是否合规；网关把明文请求发给上游 HTTP 代理时自己也要用 absolute-form。 | R01、R17、R21 |
| 9112-3.2.2-2 | RFC 9112 §3.2.2 absolute-form | MUST | client | 两侧 | absolute-form 的请求也必须带 Host。网关向上游 HTTP 代理发请求时照做；也用来判断客户端的明文请求是否合规。 | R01 |
| 9112-3.2.2-3 | RFC 9112 §3.2.2 absolute-form | MUST | proxy | 入口 | 入口收到 absolute-form 的请求时，目标主机只取自请求目标，忽略收到的 Host；转发时按请求目标重新生成 Host，不转发客户端给的 Host 值。Host 与请求目标不一致时按请求目标走；这种不一致能不能作为拒绝的理由，原文没有说（没有 Host、多行 Host 或 Host 值不合法仍按 9112-3.2-3 回 400）。 | R01 |
| 9112-3.2.2-4 | RFC 9112 §3.2.2 absolute-form | MUST | recipient | 入口 | 原文主语是 server。收请求的一方必须接受 absolute-form；对入口来说这本来就是明文代理请求的正常形式。 | R01 |
| 9112-3.2.4-1 | RFC 9112 §3.2.4 asterisk-form | MUST | proxy | 入口 | 网关是请求链上最后一个代理（经 SOCKS5 上游直接对源站说话）时，收到路径为空、没有查询的 absolute-form OPTIONS，转发时请求目标写 "*"，不能写成 "/"。上游是 HTTP 代理时网关不是最后一个代理，这条不适用。 | — |
| 9112-3.3-1 | RFC 9112 §3.3 Reconstructing the Target URI | statement | recipient | 入口 | 原文主语是 server。背景：absolute-form 的请求，目标 URI 就是请求目标本身，不需要用 Host 重建。 | R01 |
| 9112-3.3-2 | RFC 9112 §3.3 Reconstructing the Target URI | statement | recipient | 入口 | 原文主语是 server。CONNECT 的隧道目标取自请求目标，不取自 Host；只有 origin-form、asterisk-form 的请求才用 Host 确定 authority。 | R03、R05 |
| 9112-3.3-3 | RFC 9112 §3.3 Reconstructing the Target URI | statement | recipient | 入口 | 原文主语是 server。背景：重建出的目标 URI 没有 authority 时（例如发到代理端口的 origin-form 请求又没有可用的 Host），原文允许拒绝；没有规定状态码。 | — |

<details>
<summary>原文（30 条）</summary>

**9110-3.7-3**　RFC 9110 §3.7

> A "proxy" is a message-forwarding agent that is chosen by the client, usually via local configuration rules, to receive requests for some type(s) of absolute URI and attempt to satisfy those requests via translation through the HTTP interface.

**9110-4.2.1-1**　RFC 9110 §4.2.1

> A sender MUST NOT generate an "http" URI with an empty host identifier. A recipient that processes such a URI reference MUST reject it as invalid.

**9110-4.2.3-1**　RFC 9110 §4.2.3

> If the port is equal to the default port for a scheme, the normal form is to omit the port subcomponent.

**9110-4.2.3-2**　RFC 9110 §4.2.3

> Two HTTP URIs that are equivalent after normalization (using any method) can be assumed to identify the same resource, and any HTTP component MAY perform normalization.

**9110-4.2.4-1**　RFC 9110 §4.2.4

> A sender MUST NOT generate the userinfo subcomponent (and its "@" delimiter) when an "http" or "https" URI reference is generated within a message as a target URI or field value.

**9110-4.2.4-2**　RFC 9110 §4.2.4

> Before making use of an "http" or "https" URI reference received from an untrusted source, a recipient SHOULD parse for userinfo and treat its presence as an error; it is likely being used to obscure the authority for the sake of phishing attacks.

**9110-7.1-1**　RFC 9110 §7.1

> For CONNECT (Section 9.3.6), the request target is the host name and port number of the tunnel destination, separated by a colon.

**9110-7.1-2**　RFC 9110 §7.1

> See the respective method definitions for details. These forms MUST NOT be used with other methods.

**9110-7.1-3**　RFC 9110 §7.1

> Upon receipt of a client's request, a server reconstructs the target URI from the received components in accordance with their local configuration and incoming connection context. This reconstruction is specific to each major protocol version.

**9110-7.2-1**　RFC 9110 §7.2

> The "Host" header field in a request provides the host and port information from the target URI, enabling the origin server to distinguish among resources while servicing requests for multiple host names.

**9110-7.2-2**　RFC 9110 §7.2

> A user agent MUST generate a Host header field in a request unless it sends that information as an ":authority" pseudo-header field.

**9110-7.2-3**　RFC 9110 §7.2

> A user agent that sends Host SHOULD send it as the first field in the header section of a request.

**9110-7.3.2-1**　RFC 9110 §7.3.2

> If an "http" or "https" proxy is applicable, the client connects inbound by establishing (or reusing) a connection to that proxy and then sending it an HTTP request message containing a request target that matches the client's target URI.

**9110-7.6-3**　RFC 9110 §7.6

> An intermediary MUST NOT forward a message to itself unless it is protected from an infinite request loop. In general, an intermediary ought to recognize its own server names, including any aliases, local variations, or literal IP addresses, and respond to such requests directly.

**9110-7.7-1**　RFC 9110 §7.7

> If a proxy receives a target URI with a host name that is not a fully qualified domain name, it MAY add its own domain to the host name it received when forwarding the request. A proxy MUST NOT change the host name if the target URI contains a fully qualified domain name.

**9110-7.7-2**　RFC 9110 §7.7

> A proxy MUST NOT modify the "absolute-path" and "query" parts of the received target URI when forwarding it to the next inbound server except as required by that forwarding protocol. For example, a proxy forwarding a request to an origin server via HTTP/1.1 will replace an empty path with "/" (Section 3.2.1 of \[HTTP/1.1\]) or "\*" (Section 3.2.4 of \[HTTP/1.1\]), depending on the request method.

**9110-17.9-1**　RFC 9110 §17.9

> Many servers, proxies, and user agents log or display the target URI in places where it might be visible to third parties.

**9112-3-3**　RFC 9112 §3

> It is RECOMMENDED that all HTTP senders and recipients support, at a minimum, request-line lengths of 8000 octets.

**9112-3.2-1**　RFC 9112 §3.2

> Recipients of an invalid request-line SHOULD respond with either a 400 (Bad Request) error or a 301 (Moved Permanently) redirect with the request-target properly encoded. A recipient SHOULD NOT attempt to autocorrect and then process the request without a redirect, since the invalid request-line might be deliberately crafted to bypass security filters along the request chain.

**9112-3.2-2**　RFC 9112 §3.2

> A client MUST send a Host header field (Section 7.2 of \[HTTP\]) in all HTTP/1.1 request messages. If the target URI includes an authority component, then a client MUST send a field value for Host that is identical to that authority component, excluding any userinfo subcomponent and its "@" delimiter (Section 4.2 of \[HTTP\]).

**9112-3.2-3**　RFC 9112 §3.2

> A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value.

**9112-3.2.1-1**　RFC 9112 §3.2.1

> When making a request directly to an origin server, other than a CONNECT or server-wide OPTIONS request (as detailed below), a client MUST send only the absolute path and query components of the target URI as the request-target. If the target URI's path component is empty, the client MUST send "/" as the path within the origin-form of request-target.

**9112-3.2.2-1**　RFC 9112 §3.2.2

> When making a request to a proxy, other than a CONNECT or server-wide OPTIONS request (as detailed below), a client MUST send the target URI in "absolute-form" as the request-target.

**9112-3.2.2-2**　RFC 9112 §3.2.2

> A client MUST send a Host header field in an HTTP/1.1 request even if the request-target is in the absolute-form, since this allows the Host information to be forwarded through ancient HTTP/1.0 proxies that might not have implemented Host.

**9112-3.2.2-3**　RFC 9112 §3.2.2

> When a proxy receives a request with an absolute-form of request- target, the proxy MUST ignore the received Host header field (if any) and instead replace it with the host information of the request- target. A proxy that forwards such a request MUST generate a new Host field value based on the received request-target rather than forward the received Host field value.

**9112-3.2.2-4**　RFC 9112 §3.2.2

> A server MUST accept the absolute-form in requests even though most HTTP/1.1 clients will only send the absolute-form to a proxy.

**9112-3.2.4-1**　RFC 9112 §3.2.4

> If a proxy receives an OPTIONS request with an absolute-form of request-target in which the URI has an empty path and no query component, then the last proxy on the request chain MUST send a request-target of "\*" when it forwards the request to the indicated origin server.

**9112-3.3-1**　RFC 9112 §3.3

> The target URI is the request-target when the request-target is in absolute-form.

**9112-3.3-2**　RFC 9112 §3.3

> If the request-target is in authority-form, the target URI's authority component is the request-target. Otherwise, the target URI's authority component is the field value of the Host header field.

**9112-3.3-3**　RFC 9112 §3.3

> If the target URI's authority component is empty and its URI scheme requires a non-empty authority (as is the case for "http" and "https"), the server can reject the request or determine whether a configured default applies that is consistent with the incoming connection's context.

</details>

### connect：CONNECT 方法

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-3.3-2 | RFC 9110 §3.3 Connections, Clients, and Servers | statement | any | 入口 | 入口不能假定 CONNECT 只出现在连接的第一个请求里：同一条连接上先有别的请求（例如被 407 拒绝的那个）之后再来 CONNECT 是合规的。 | R33、R88 |
| 9110-6.4.1-1 | RFC 9110 §6.4.1 Content Semantics | statement | any | 两侧 | CONNECT 的 2xx 响应没有内容，头部分之后连接就是隧道：入口回 2xx 时不发正文，上游回 2xx 后网关也不能按 Content-Length 或分块去读正文。 | R84、R85 |
| 9110-8.6-2 | RFC 9110 §8.6 Content-Length | MUST NOT | sender | 入口 | 原文主语是 server。入口对 CONNECT 回 2xx 时不得带 Content-Length（与 9110-9.3.6-10 同一要求）。 | R84、R85 |
| 9110-9.3.6-1 | RFC 9110 §9.3.6 CONNECT | statement | recipient | 入口 | 入口收到 CONNECT：建立到请求目标的隧道；成功之后只做两个方向的盲转发，直到隧道关闭，不解析也不改动其中的字节。 | R03、R06 |
| 9110-9.3.6-2 | RFC 9110 §9.3.6 CONNECT | MUST | client | 两侧 | CONNECT 的请求目标只有“主机:端口”，没有默认端口，客户端必须写端口。入口不替客户端补 443；网关向上游代理发 CONNECT 时也必须写出端口。 | R03 |
| 9110-9.3.6-3 | RFC 9110 §9.3.6 CONNECT | MUST | recipient | 入口 | 原文主语是 server。入口遇到端口为空或无效的 CONNECT 必须拒绝，通常回 400。 | R03 |
| 9110-9.3.6-4 | RFC 9110 §9.3.6 CONNECT | statement | proxy | 两侧 | 建隧道有两条路：直接连请求目标指的服务器，或者在配置了另一个代理时把 CONNECT 转给下一个 inbound 代理。网关走上游 HTTP 代理属于后一种；走上游 SOCKS5 代理不在这句话说的两种方式里。 | R03 |
| 9110-9.3.6-5 | RFC 9110 §9.3.6 CONNECT | statement | sender | 两侧 | 入口回 2xx 就是声明：自己和后面所有 inbound 代理在响应头部分之后立即进入隧道模式，头部分之后的数据都来自请求目标指的服务器。所以入口要等上游的隧道建好才回 2xx，头部分之后不能有网关自己加的字节。上游回 2xx 之后的字节按条款应当来自目标，但上游不可信，这只是它的声明。 | R06、R84、R85 |
| 9110-9.3.6-6 | RFC 9110 §9.3.6 CONNECT | statement | sender | 两侧 | 非 2xx 的响应表示隧道没有建成。入口对 CONNECT 回 407、403、502、503 之后，这条连接仍按 HTTP 连接处理（除非另外声明关闭）；上游对网关的 CONNECT 回非 2xx，网关不能把这条连接当隧道用。 | R33、R35、R80、R82、R83、R88、R89 |
| 9110-9.3.6-9 | RFC 9110 §9.3.6 CONNECT | SHOULD | proxy | 入口 | 入口应当把 CONNECT 限制在一组已知端口，或者一份可配置的安全目标清单之内；不限制要有写明的理由（原文举的风险是连到 25 端口被用来转发垃圾邮件）。 | R18 |
| 9110-9.3.6-10 | RFC 9110 §9.3.6 CONNECT | MUST NOT | sender | 入口 | 原文主语是 server。入口对 CONNECT 回 2xx 时不得带 Transfer-Encoding 或 Content-Length。条款没有禁止别的头字段。 | R84、R85 |
| 9110-9.3.6-11 | RFC 9110 §9.3.6 CONNECT | MUST | client | 两侧 | 上游对网关的 CONNECT 回 2xx 时若带了 Content-Length 或 Transfer-Encoding，网关必须忽略，头部分之后直接当隧道数据。连到入口的客户端也受同一约束。 | R84、R85 |
| 9110-9.3.6-12 | RFC 9110 §9.3.6 CONNECT | statement | any | 两侧 | CONNECT 请求在语义上没有内容；请求头部分之后的数据怎么解释，由所用的 HTTP 版本规定。HTTP/1.1 下请求的分帧仍按 RFC 9112 第 6 节，与方法无关（9112-6-1、9112-6.3-11）：带 Content-Length 或 Transfer-Encoding 的 CONNECT 请求，原文没有单独规定怎么办，入口是拒绝还是按分帧把正文读掉，要在设计决定里写明。 | R04、R06 |
| 9110-15.3.1-1 | RFC 9110 §15.3.1 200 OK | statement | any | 两侧 | CONNECT 成功的结果是隧道，紧接在 200 的响应头部分之后开始：入口发完空行之后的每个字节都是隧道数据；上游的 200 头部分之后的字节，网关直接当隧道数据交给客户端。 | R06、R84、R85 |
| 9112-3.1-1 | RFC 9112 §3.1 Method | statement | any | 入口 | 方法名区分大小写。入口按方法分流（CONNECT 建隧道，其余按明文转发）时按大小写敏感比较：connect、Connect 不是 CONNECT。 | R03 |
| 9112-3.2.3-1 | RFC 9112 §3.2.3 authority-form | statement | any | 入口 | 背景：CONNECT 的请求目标是“主机:端口”，端口不可省；入口按这个语法解析 CONNECT 的目标，别的方法不用这种形式。 | R03 |
| 9112-3.2.3-2 | RFC 9112 §3.2.3 authority-form | MUST | client | 两侧 | 约束客户端：CONNECT 的请求目标只有主机和端口，URI 省略端口时填方案的默认端口。入口据此判断客户端的 CONNECT 请求行；网关向上游 HTTP 代理发 CONNECT 时自己也这样写。 | R03、R18、R22 |
| 9112-6.1-4 | RFC 9112 §6.1 Transfer-Encoding | MUST NOT | sender | 入口 | 原文主语是 server。网关对 CONNECT 回的 2xx，以及它生成的 1xx、204 响应，都不能带 Transfer-Encoding。上游代理对网关的 CONNECT 回 2xx 时带了这个头属于上游违规。 | R84、R85 |
| 9112-6.3-2 | RFC 9112 §6.3 Message Body Length | MUST | client | 两侧 | 判定规则第 2 项：网关向上游 HTTP 代理发 CONNECT、收到 2xx 后，空行之后的字节全部是隧道数据，必须忽略其中的 Content-Length 和 Transfer-Encoding。客户端对网关回的 2xx 也应当这样处理。 | R84、R85 |

<details>
<summary>原文（19 条）</summary>

**9110-3.3-2**　RFC 9110 §3.3

> For example, a CONNECT request (Section 9.3.6) or a request with the Upgrade header field (Section 7.8) can occur at any time, not just in the first message on a connection.

**9110-6.4.1-1**　RFC 9110 §6.4.1

> 2xx (Successful) responses to a CONNECT request method (Section 9.3.6) switch the connection to tunnel mode instead of having content.

**9110-8.6-2**　RFC 9110 §8.6

> A server MUST NOT send a Content-Length header field in any 2xx (Successful) response to a CONNECT request (Section 9.3.6).

**9110-9.3.6-1**　RFC 9110 §9.3.6

> The CONNECT method requests that the recipient establish a tunnel to the destination origin server identified by the request target and, if successful, thereafter restrict its behavior to blind forwarding of data, in both directions, until the tunnel is closed.

**9110-9.3.6-2**　RFC 9110 §9.3.6

> CONNECT uses a special form of request target, unique to this method, consisting of only the host and port number of the tunnel destination, separated by a colon. There is no default port; a client MUST send the port number even if the CONNECT request is based on a URI reference that contains an authority component with an elided port (Section 4.1).

**9110-9.3.6-3**　RFC 9110 §9.3.6

> A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code.

**9110-9.3.6-4**　RFC 9110 §9.3.6

> CONNECT is intended for use in requests to a proxy. The recipient can establish a tunnel either by directly connecting to the server identified by the request target or, if configured to use another proxy, by forwarding the CONNECT request to the next inbound proxy.

**9110-9.3.6-5**　RFC 9110 §9.3.6

> Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch to tunnel mode immediately after the response header section; data received after that header section is from the server identified by the request target.

**9110-9.3.6-6**　RFC 9110 §9.3.6

> Any response other than a successful response indicates that the tunnel has not yet been formed.

**9110-9.3.6-9**　RFC 9110 §9.3.6

> Proxies that support CONNECT SHOULD restrict its use to a limited set of known ports or a configurable list of safe request targets.

**9110-9.3.6-10**　RFC 9110 §9.3.6

> A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx (Successful) response to CONNECT.

**9110-9.3.6-11**　RFC 9110 §9.3.6

> A client MUST ignore any Content-Length or Transfer-Encoding header fields received in a successful response to CONNECT.

**9110-9.3.6-12**　RFC 9110 §9.3.6

> A CONNECT request message does not have content. The interpretation of data sent after the header section of the CONNECT request message is specific to the version of HTTP in use.

**9110-15.3.1-1**　RFC 9110 §15.3.1

> For CONNECT, there is no content because the successful result is a tunnel, which begins immediately after the 200 response header section.

**9112-3.1-1**　RFC 9112 §3.1

> The request method is case-sensitive.

**9112-3.2.3-1**　RFC 9112 §3.2.3

> The "authority-form" of request-target is only used for CONNECT requests (Section 9.3.6 of \[HTTP\]). It consists of only the uri-host and port number of the tunnel destination, separated by a colon (":").

**9112-3.2.3-2**　RFC 9112 §3.2.3

> When making a CONNECT request to establish a tunnel through one or more proxies, a client MUST send only the host and port of the tunnel destination as the request-target. The client obtains the host and port from the target URI's authority component, except that it sends the scheme's default port if the target URI elides the port.

**9112-6.1-4**　RFC 9112 §6.1

> A server MUST NOT send a Transfer-Encoding header field in any response with a status code of 1xx (Informational) or 204 (No Content). A server MUST NOT send a Transfer-Encoding header field in any 2xx (Successful) response to a CONNECT request (Section 9.3.6 of \[HTTP\]).

**9112-6.3-2**　RFC 9112 §6.3

> Any 2xx (Successful) response to a CONNECT request implies that the connection will become a tunnel immediately after the empty line that concludes the header fields. A client MUST ignore any Content-Length or Transfer-Encoding header fields received in such a message.

</details>

### tunnel：隧道

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-3.7-4 | RFC 9110 §3.7 Intermediaries | statement | tunnel | 入口 | 隧道生效之后，网关不改动两个方向的字节，也不再是 HTTP 通信的一方：针对 proxy 的条款（Via、逐跳头处理等）不适用于隧道里的数据。 | R06 |
| 9110-3.7-5 | RFC 9110 §3.7 Intermediaries | statement | tunnel | 入口 | 背景：隧道的生命期到被中继的连接两端都关闭为止。关闭时网关要做的事见 9110-9.3.6-7。 | R91 |
| 9110-9.3.6-7 | RFC 9110 §9.3.6 CONNECT | MUST | tunnel | 入口 | 隧道任一侧关了连接：网关必须尽力把来自已关那一侧、还没转出去的数据发给另一侧，然后关掉两条连接，剩下送不出去的数据丢弃。条款写的是任一侧关闭就两条都关，没有规定保持半关闭。 | R91、R94、R95、R97、R99、R101 |
| 9112-9.7-1 | RFC 9112 §9.7 TLS Connection Initiation | statement | client | 客户端 | 背景：HTTPS 由 HTTP 客户端发起 TLS 握手，先发 ClientHello。这一节没有提到代理和隧道；CONNECT 隧道建好之后的首包见 RFC 9110 的 CONNECT 一节。 | R06 |
| 9112-9.8-1 | RFC 9112 §9.8 TLS Connection Closure | statement | any | 客户端 | 背景：TLS 之上，没有长度信息的响应只有收到合法的关闭告警才算完整。隧道被网关或上游直接切断（只有 TCP 的 FIN，没有 TLS 关闭告警）时，客户端看到的是不完整关闭；网关不终结隧道里的 TLS，补不出这个告警。 | R94、R95、R97 |
| 9112-9.8-2 | RFC 9112 §9.8 TLS Connection Closure | SHOULD | client | 客户端 | 约束客户端：遇到不完整关闭应当平稳恢复。原文没有说恢复是指重试还是报错。 | R94、R95、R97 |
| 9112-11.3-1 | RFC 9112 §11.3 Message Integrity | statement | any | 两侧 | 背景：https 防得住篡改，但要另外防止靠关闭连接来截断消息。隧道里的内容上游改不了，却可以随时切断隧道。 | R94、R95 |

<details>
<summary>原文（7 条）</summary>

**9110-3.7-4**　RFC 9110 §3.7

> A "tunnel" acts as a blind relay between two connections without changing the messages. Once active, a tunnel is not considered a party to the HTTP communication, though the tunnel might have been initiated by an HTTP request.

**9110-3.7-5**　RFC 9110 §3.7

> A tunnel ceases to exist when both ends of the relayed connection are closed.

**9110-9.3.6-7**　RFC 9110 §9.3.6

> A tunnel is closed when a tunnel intermediary detects that either side has closed its connection: the intermediary MUST attempt to send any outstanding data that came from the closed side to the other side, close both connections, and then discard any remaining data left undelivered.

**9112-9.7-1**　RFC 9112 §9.7

> The HTTP client also acts as the TLS client. It initiates a connection to the server on the appropriate port and sends the TLS ClientHello to begin the TLS handshake.

**9112-9.8-1**　RFC 9112 §9.8

> A response that has neither chunked transfer coding nor Content- Length is complete only if a valid closure alert has been received. Treating an incomplete message as complete could expose implementations to attack.

**9112-9.8-2**　RFC 9112 §9.8

> A client detecting an incomplete close SHOULD recover gracefully.

**9112-11.3-1**　RFC 9112 §11.3

> The mechanisms provided with the "https" scheme, such as authenticated encryption, provide protection against modification of messages. Care is needed, however, to ensure that connection closure cannot be used to truncate messages (see Section 9.8).

</details>

### proxy-auth：代理认证（407、Proxy-Authenticate、Proxy-Authorization）

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-9.3.6-8 | RFC 9110 §9.3.6 CONNECT | statement | proxy | 入口 | 背景：可以用代理认证决定谁有权建隧道。入口对 CONNECT 要求 Proxy-Authorization 是条款预见的用法。 | R31、R33、R35 |
| 9110-9.3.8-1 | RFC 9110 §9.3.8 TRACE | SHOULD | recipient | 入口 | 与 9110-7.6.2-1 连着用：TRACE 带 Max-Forwards: 0 时网关就是最终接收方，而 TRACE 的应答是把收到的请求回显出去。回显时应当去掉可能含敏感数据的请求字段；对入口来说首先是 Proxy-Authorization。哪些字段算敏感，原文没有列。 | — |
| 9110-11.1-1 | RFC 9110 §11.1 Authentication Scheme | statement | any | 两侧 | 认证方案名是大小写不敏感的 token。入口解析 Proxy-Authorization 时，“Basic”“basic”“BASIC”要当成同一个方案；上游回的质询也按此比较。 | R30、R31 |
| 9110-11.2-1 | RFC 9110 §11.2 Authentication Parameters | statement | any | 两侧 | 背景：凭据里承载 base64 的 token68 的字符集，不含空白。入口解析 Proxy-Authorization 的 token68 部分按这个字符集；用户名、密码本身的字节怎么编码由 Basic 方案（RFC 7617）规定，不在本文件。 | R60、R61、R62、R68 |
| 9110-11.2-2 | RFC 9110 §11.2 Authentication Parameters | MUST | sender | 入口 | 入口生成质询时，每个参数名（realm、charset 等）在一个质询里只能出现一次；参数名比较不分大小写。解析上游的质询时也按不分大小写比较。 | R63、R64 |
| 9110-11.2-3 | RFC 9110 §11.2 Authentication Parameters | statement | any | 两侧 | 背景：认证参数的值有 token 和 quoted-string 两种写法。网关解析上游的质询时两种都要认。 | — |
| 9110-11.3-1 | RFC 9110 §11.3 Challenge and Response | statement | proxy | 两侧 | 背景：代理用 407 加 Proxy-Authenticate 质询客户端。入口用它要凭据；上游也这样质询网关。强制性的要求见 9110-11.7.1-1。 | R32、R33、R45、R46 |
| 9110-11.3-2 | RFC 9110 §11.3 Challenge and Response | statement | sender | 入口 | 入口发多个质询时，把支持面广的方案（如 basic）放在前面：很多客户端遇到不认识的方案就解析失败。这是原文的 Note，不是规范性要求。 | R45、R46 |
| 9110-11.3-3 | RFC 9110 §11.3 Challenge and Response | statement | client | 两侧 | 客户端带 Proxy-Authorization“通常但不一定”在收到 407 之后：不等质询、第一个请求就带凭据是条款允许的。入口不能假定有凭据的请求之前一定有过 407；网关对上游也可以直接带凭据。 | R30、R31、R36、R37、R52、R53 |
| 9110-11.4-1 | RFC 9110 §11.4 Credentials | statement | client | 客户端 | 背景：凭据依据的质询可以是过去某次收到的。客户端在后续请求里沿用先前质询得到的凭据是条款预期的行为。 | R36、R37、R38 |
| 9110-11.4-2 | RFC 9110 §11.4 Credentials | SHOULD | proxy | 入口 | 入口要求认证时，请求没带代理凭据、凭据无效或不完整，都应当回 407 并带至少一个质询。密码错与没带凭据在这一条里是同一种应答，质询可以是新的。 | R30、R31、R45、R46、R47、R48、R49 |
| 9110-11.4-3 | RFC 9110 §11.4 Credentials | statement | sender | 入口 | 原文主语是 server，用的是 ought to，不是规范性关键词。凭据有效但权限不够时回 403，不回 407：入口上“用户名密码对，但会话参数不被允许”属于这种情况。 | R50、R51、R82、R86 |
| 9110-11.5-1 | RFC 9110 §11.5 Establishing a Protection Space (Realm) | MAY | client | 客户端 | 背景：一次请求被授权之后，user agent 可以在同一个保护空间里对其他请求自动沿用同一份凭据。条款按源站的 origin 定义保护空间，没有单独说代理的保护空间是什么；用来解释客户端后续请求直接带凭据的行为。 | R36、R37、R38 |
| 9110-11.5-2 | RFC 9110 §11.5 Establishing a Protection Space (Realm) | MUST | sender | 入口 | 入口生成质询里的 realm 参数时，值必须用 quoted-string 写法（realm="…"），不能写成裸 token。解析上游的质询时两种写法都要认。 | R45、R46 |
| 9110-11.6.1-2 | RFC 9110 §11.6.1 WWW-Authenticate | statement | sender | 入口 | “this form”指一个字段行里放多个质询。有的 user agent 不认这种写法；11.7.1 说这些解析上的考虑同样适用于 Proxy-Authenticate（9110-11.7.1-3），所以入口发多个质询时每个质询单独一行更稳妥。 | R45、R46 |
| 9110-11.7.1-1 | RFC 9110 §11.7.1 Proxy-Authenticate | MUST | proxy | 入口 | 入口自己生成的每个 407 都必须带至少一个 Proxy-Authenticate 头字段。 | R32、R33、R34、R35、R45、R46、R49 |
| 9110-11.7.1-2 | RFC 9110 §11.7.1 Proxy-Authenticate | statement | proxy | 两侧 | Proxy-Authenticate 只对响应链上的下一个 outbound 客户端有效。上游回给网关的 407 质询的是网关（选了这个上游的是网关），连到入口的客户端没有上游的凭据；条款没有用规范性关键词禁止转发，但把上游的 407 原样交给客户端与这句话的语义不符。 | R49 |
| 9110-11.7.1-3 | RFC 9110 §11.7.1 Proxy-Authenticate | statement | any | 两侧 | 背景：WWW-Authenticate 的解析注意事项（一个字段值里可以有多个质询、字段可以出现多次）同样适用于 Proxy-Authenticate。网关解析上游的 407 时照此处理。 | — |
| 9110-11.7.2-1 | RFC 9110 §11.7.2 Proxy-Authorization | statement | client | 两侧 | 背景：Proxy-Authorization 的定义，值是 credentials。入口从这个字段取用户名（会话参数就在用户名里）；网关向要认证的上游发请求时用同一个字段带上游的凭据。 | R30、R31 |
| 9110-11.7.2-2 | RFC 9110 §11.7.2 Proxy-Authorization | statement | proxy | 入口 | Proxy-Authorization 只对要求认证的下一个 inbound 代理有效，由第一个等着收凭据的代理“消费”。入口要求认证，客户端的 Proxy-Authorization 就在入口这里用掉，不属于后面的上游和源站。条款没有用 MUST 写“转发前必须删除”，结论来自“consumed”和下一条 MAY 的限定。 | R39 |
| 9110-11.7.2-3 | RFC 9110 §11.7.2 Proxy-Authorization | MAY | proxy | 入口 | 只有在几个代理靠转交凭据来协同认证时，代理才可以把客户端的凭据转给下一个代理。网关与不可信的上游不是这种关系，这个 MAY 给的许可不适用：客户端的 Proxy-Authorization 不转给上游，发给上游的是网关自己为该上游配置的凭据。 | R39 |
| 9110-11.7.3-1 | RFC 9110 §11.7.3 Proxy-Authentication-Info | statement | proxy | 两侧 | Proxy-Authentication-Info 只对响应链上的下一个 outbound 客户端有效。上游回的这个字段是给网关的；入口用 Basic 时不需要发它。 | R84、R87 |
| 9110-15.4-1 | RFC 9110 §15.4 Redirection 3xx | SHOULD | client | 客户端 | 背景：客户端自动跟随重定向时，应当去掉实现自动生成的头字段、按新请求重新生成；列表第 2 项点名了“客户端代理配置专有的头字段，包括但不限于 Proxy-Authorization”。用来解释跟随重定向时代理凭据是重新生成还是被带到别处。引文只摘到列表第 2 项结束，原文的列表还有第 3 到 5 项。 | R39、R40 |
| 9110-15.5.8-1 | RFC 9110 §15.5.8 407 Proxy Authentication Required | MUST | proxy | 入口 | 407 表示客户端要先向代理认证才能用它处理这个请求；入口发 407 必须带 Proxy-Authenticate，里面的质询适用于入口自己。 | R32、R33、R45、R46 |
| 9110-15.5.8-2 | RFC 9110 §15.5.8 407 Proxy Authentication Required | MAY | client | 两侧 | 收到 407 的客户端可以带新的或替换过的 Proxy-Authorization 重发请求。是 MAY：重发与否、走原连接还是新连接、重试几次，条款都没有规定，要靠测量。网关收到上游的 407 时同理。 | R32、R33、R36、R43、R44、R47、R48、R49 |
| 9110-17.16.1-1 | RFC 9110 §17.16.1 Confidentiality of Credentials | statement | any | 两侧 | 头字段的保密全靠底层连接。客户端到入口、网关到上游若是明文 TCP，Proxy-Authorization（含用户名里的会话参数）在这一段就是明文可见的；条款说依赖逐用户认证的服务需要先有 secured 连接。 | R30、R31 |
| 9110-17.16.2-1 | RFC 9110 §17.16.2 Credentials and Idle Clients | statement | client | 客户端 | 背景：客户端通常无限期地留着认证信息。入口换了会话参数或吊销了凭据，客户端仍可能继续发旧的。 | R36、R38、R41、R42 |
| 9110-17.16.4-1 | RFC 9110 §17.16.4 Additional Response Fields | statement | sender | 入口 | 背景：在不加密的通道上，响应里出现 Proxy-Authentication-Info 本身就表明在用 HTTP 认证。 | — |

<details>
<summary>原文（28 条）</summary>

**9110-9.3.6-8**　RFC 9110 §9.3.6

> Proxy authentication might be used to establish the authority to create a tunnel.

**9110-9.3.8-1**　RFC 9110 §9.3.8

> The final recipient of the request SHOULD exclude any request fields that are likely to contain sensitive data when that recipient generates the response content.

**9110-11.1-1**　RFC 9110 §11.1

> HTTP provides a general framework for access control and authentication, via an extensible set of challenge-response authentication schemes, which can be used by a server to challenge a client request and by a client to provide authentication information. It uses a case-insensitive token to identify the authentication scheme:

**9110-11.2-1**　RFC 9110 §11.2

> The token68 syntax allows the 66 unreserved URI characters (\[URI\]), plus a few others, so that it can hold a base64, base64url (URL and filename safe alphabet), base32, or base16 (hex) encoding, with or without padding, but excluding whitespace (\[RFC4648\]).

**9110-11.2-2**　RFC 9110 §11.2

> Authentication parameters are name/value pairs, where the name token is matched case-insensitively and each parameter name MUST only occur once per challenge.

**9110-11.2-3**　RFC 9110 §11.2

> Parameter values can be expressed either as "token" or as "quoted- string" (Section 5.6). Authentication scheme definitions need to accept both notations, both for senders and recipients, to allow recipients to use generic parsing components regardless of the authentication scheme.

**9110-11.3-1**　RFC 9110 §11.3

> A 407 (Proxy Authentication Required) response message is used by a proxy to challenge the authorization of a client, including a Proxy-Authenticate header field containing at least one challenge applicable to the proxy for the requested resource.

**9110-11.3-2**　RFC 9110 §11.3

> \*Note:\* Many clients fail to parse a challenge that contains an unknown scheme. A workaround for this problem is to list well- supported schemes (such as "basic") first.

**9110-11.3-3**　RFC 9110 §11.3

> A client that wishes to authenticate itself with a proxy -- usually, but not necessarily, after receiving a 407 (Proxy Authentication Required) -- can do so by including a Proxy-Authorization header field with the request.

**9110-11.4-1**　RFC 9110 §11.4

> Both the Authorization field value and the Proxy-Authorization field value contain the client's credentials for the realm of the resource being requested, based upon a challenge received in a response (possibly at some point in the past).

**9110-11.4-2**　RFC 9110 §11.4

> Likewise, upon receipt of a request that omits proxy credentials or contains invalid or partial proxy credentials, a proxy that requires authentication SHOULD generate a 407 (Proxy Authentication Required) response that contains a Proxy-Authenticate header field with at least one (possibly new) challenge applicable to the proxy.

**9110-11.4-3**　RFC 9110 §11.4

> A server that receives valid credentials that are not adequate to gain access ought to respond with the 403 (Forbidden) status code (Section 15.5.4).

**9110-11.5-1**　RFC 9110 §11.5

> The protection space determines the domain over which credentials can be automatically applied. If a prior request has been authorized, the user agent MAY reuse the same credentials for all other requests within that protection space for a period of time determined by the authentication scheme, parameters, and/or user preferences (such as a configurable inactivity timeout).

**9110-11.5-2**　RFC 9110 §11.5

> For historical reasons, a sender MUST only generate the quoted-string syntax. Recipients might have to support both token and quoted- string syntax for maximum interoperability with existing clients that have been accepting both notations for a long time.

**9110-11.6.1-2**　RFC 9110 §11.6.1

> Some user agents do not recognize this form, however. As a result, sending a WWW-Authenticate field value with more than one member on the same field line might not be interoperable.

**9110-11.7.1-1**　RFC 9110 §11.7.1

> A proxy MUST send at least one Proxy-Authenticate header field in each 407 (Proxy Authentication Required) response that it generates.

**9110-11.7.1-2**　RFC 9110 §11.7.1

> Unlike WWW-Authenticate, the Proxy-Authenticate header field applies only to the next outbound client on the response chain. This is because only the client that chose a given proxy is likely to have the credentials necessary for authentication.

**9110-11.7.1-3**　RFC 9110 §11.7.1

> Note that the parsing considerations for WWW-Authenticate apply to this header field as well; see Section 11.6.1 for details.

**9110-11.7.2-1**　RFC 9110 §11.7.2

> The "Proxy-Authorization" header field allows the client to identify itself (or its user) to a proxy that requires authentication. Its value consists of credentials containing the authentication information of the client for the proxy and/or realm of the resource being requested.

**9110-11.7.2-2**　RFC 9110 §11.7.2

> Unlike Authorization, the Proxy-Authorization header field applies only to the next inbound proxy that demanded authentication using the Proxy-Authenticate header field. When multiple proxies are used in a chain, the Proxy-Authorization header field is consumed by the first inbound proxy that was expecting to receive credentials.

**9110-11.7.2-3**　RFC 9110 §11.7.2

> A proxy MAY relay the credentials from the client request to the next proxy if that is the mechanism by which the proxies cooperatively authenticate a given request.

**9110-11.7.3-1**　RFC 9110 §11.7.3

> However, unlike Authentication-Info, the Proxy-Authentication-Info header field applies only to the next outbound client on the response chain.

**9110-15.4-1**　RFC 9110 §15.4

> When automatically following a redirected request, the user agent SHOULD resend the original request message with the following modifications: 1. Replace the target URI with the URI referenced by the redirection response's Location header field value after resolving it relative to the original request's target URI. 2. Remove header fields that were automatically generated by the implementation, replacing them with updated values as appropriate to the new request. This includes: 1. Connection-specific header fields (see Section 7.6.1), 2. Header fields specific to the client's proxy configuration, including (but not limited to) Proxy-Authorization, 3. Origin-specific header fields (if any), including (but not limited to) Host, 4. Validating header fields that were added by the implementation's cache (e.g., If-None-Match, If-Modified-Since), and 5. Resource-specific header fields, including (but not limited to) Referer, Origin, Authorization, and Cookie.

**9110-15.5.8-1**　RFC 9110 §15.5.8

> The 407 (Proxy Authentication Required) status code is similar to 401 (Unauthorized), but it indicates that the client needs to authenticate itself in order to use a proxy for this request. The proxy MUST send a Proxy-Authenticate header field (Section 11.7.1) containing a challenge applicable to that proxy for the request.

**9110-15.5.8-2**　RFC 9110 §15.5.8

> The client MAY repeat the request with a new or replaced Proxy-Authorization header field (Section 11.7.2).

**9110-17.16.1-1**　RFC 9110 §17.16.1

> HTTP depends on the security properties of the underlying transport- or session-level connection to provide confidential transmission of fields. Services that depend on individual user authentication require a secured connection prior to exchanging credentials (Section 4.2.2).

**9110-17.16.2-1**　RFC 9110 §17.16.2

> Existing HTTP clients and user agents typically retain authentication information indefinitely.

**9110-17.16.4-1**　RFC 9110 §17.16.4

> The presence of the Authentication-Info and Proxy-Authentication-Info header fields alone indicates that HTTP authentication is in use.

</details>

### hop-by-hop：逐跳的头字段

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-5.1-1 | RFC 9110 §5.1 Field Names | MUST | proxy | 入口 | 网关转发明文请求和响应时，不认识的头字段必须原样转发；例外只有两种：字段名列在 Connection 里，或者网关被专门配置成拦截或改写它。默认“只转发白名单里的头”不符合这条；显式配置出来的名单算不算原文说的例外，原文没有细说，要在设计决定里写明。 | R02 |
| 9110-5.3-1 | RFC 9110 §5.3 Field Order | MUST NOT | proxy | 入口 | 网关转发消息时，同名字段各行的值不得调换先后顺序（用无序的 map 存头字段再写出去时要保住同名行的顺序）。topic 里没有专门的“字段转发”，归在 hop-by-hop。 | — |
| 9110-5.6.1.2-1 | RFC 9110 §5.6.1.2 Recipient Requirements | MUST | recipient | 两侧 | 列表型的字段（Connection、Transfer-Encoding、Via、Proxy-Authenticate 等）里的空元素，接收方必须能跳过，例如“Connection: close, , keep-alive”；同时跳过的个数要有上限，具体多少原文只说“合理”。 | — |
| 9110-6.6.1-1 | RFC 9110 §6.6.1 Date | MUST | recipient | 入口 | 网关转发明文响应时，上游或源站回来的响应没有 Date，就必须按收到的时间补一个 Date 再转给客户端。这是 Via 之外网关必须往转发的响应里加的另一个头。topic 里没有更贴切的一类，归在 hop-by-hop。 | — |
| 9110-7.6-1 | RFC 9110 §7.6 Message Forwarding | statement | intermediary | 入口 | 网关转发明文消息时，不认识的方法、状态码、字段名也照样转发，不因为不认识就拒绝。没有规范性关键词，是期望；字段的硬性要求见 9110-5.1-1。 | — |
| 9110-7.6-2 | RFC 9110 §7.6 Message Forwarding | MUST | intermediary | 入口 | 网关作为代理（不是隧道）转发消息时，必须实现 Connection 头的处理，并且不转发只属于进入的那条连接的字段。 | R02 |
| 9110-7.6.1-1 | RFC 9110 §7.6.1 Connection | MUST | sender | 两侧 | 只对当前连接有意义的字段，发送方必须把字段名列进 Connection。客户端发给入口的这类字段据此识别；网关向上游发自己的连接级字段时也要这样列。 | R02 |
| 9110-7.6.1-2 | RFC 9110 §7.6.1 Connection | MUST | intermediary | 入口 | 转发之前：解析 Connection，把其中每个 connection-option 同名的头字段和尾部字段删掉，再删掉 Connection 本身，或者换成网关自己对下一跳连接的选项。 | R02 |
| 9110-7.6.1-3 | RFC 9110 §7.6.1 Connection | SHOULD | intermediary | 入口 | 不管有没有列在 Connection 里，Proxy-Connection、Keep-Alive、TE、Transfer-Encoding、Upgrade 这几个字段，网关都应当先按其语义处理，转发前删掉或替换。清单是“包括但不限于”；Proxy-Authorization 不在这份清单里（见 9110-11.7.2-2）。 | R02、R21 |
| 9110-7.6.1-4 | RFC 9110 §7.6.1 Connection | MUST NOT | sender | 两侧 | 客户端把端到端字段的名字列进 Connection 是违规；按 9110-7.6.1-2，入口仍会删掉同名字段。网关自己发的 Connection 里不能列端到端字段。 | R02 |
| 9110-7.6.1-5 | RFC 9110 §7.6.1 Connection | statement | recipient | 两侧 | 收到没有在 Connection 里列出的连接级字段，通常是被上一跳错误转发的，接收方应当忽略（ought to，不是规范性关键词）。 | R02 |
| 9110-7.6.1-6 | RFC 9110 §7.6.1 Connection | statement | any | 两侧 | Connection 里的选项不分大小写：close、Close、KEEP-ALIVE 是同一个选项。入口按 9110-7.6.1-2 解析 Connection、按选项名删同名字段时，都按不分大小写比较。 | R02 |
| 9110-7.7-3 | RFC 9110 §7.7 Message Transformations | SHOULD NOT | proxy | 入口 | 描述通信链两端、资源状态或所选表示的头字段，网关不应改动，除非字段定义允许，或者出于隐私或安全的需要。 | — |
| 9110-7.7-4 | RFC 9110 §7.7 Message Transformations | MUST NOT | proxy | 入口 | 带 no-transform 指令的响应，网关不得改动其内容；加上或拆掉传输编码不算改内容。网关不改响应内容就自然满足这条。 | — |
| 9110-10.1.4-1 | RFC 9110 §10.1.4 TE | MUST | sender | 客户端 | 合规的客户端发 TE 时会在 Connection 里列 TE，用意是让中间人不转发它；网关转发时删掉 TE（另见 9110-7.6.1-3）。 | R02 |
| 9110-11.6.1-1 | RFC 9110 §11.6.1 WWW-Authenticate | MUST NOT | proxy | 入口 | 网关转发明文响应时不得改动 WWW-Authenticate：那是源站对 user agent 的质询，是端到端字段。 | — |
| 9110-11.6.2-1 | RFC 9110 §11.6.2 Authorization | MUST NOT | proxy | 入口 | 网关转发明文请求时不得改动 Authorization：那是给源站的凭据，原样转发。它与 Proxy-Authorization 是两个字段，不能混着处理。 | — |
| 9112-2.3-1 | RFC 9112 §2.3 HTTP Version | MUST | intermediary | 入口 | 网关转发明文请求和响应时，起始行里的版本号写网关自己的，不照抄收到的；原文留了一个例外：为了绕开上游的问题而有意降低版本。CONNECT 建成隧道之后不适用。 | — |
| 9112-7.1.1-1 | RFC 9112 §7.1.1 Chunk Extensions | statement | any | 两侧 | 背景：分块编码是逐连接的，中间方可以拆掉或重新分块，块的边界和扩展不保证原样到达对端。 | R19 |
| 9112-7.4-1 | RFC 9112 §7.4 Negotiating Transfer Codings | MUST NOT | client | 客户端 | 约束客户端：TE 里不写 chunked。用来判断客户端请求里与连接有关的头是否合规。 | R02 |
| 9112-7.4-2 | RFC 9112 §7.4 Negotiating Transfer Codings | MUST | sender | 两侧 | TE 只对紧邻的一跳有效。约束的是 TE 的发送方：客户端发 TE 必须同时在 Connection 里列出 TE；网关自己向上游发 TE 时也一样。 | R02 |
| 9112-C.2.2-1 | RFC 9112 §C.2.2 Keep-Alive Connections | statement | client | 客户端 | 背景：Proxy-Connection 不是标准头，规范鼓励客户端不要发（encouraged，不是规范性关键词）。这一段没有规定代理收到它之后该怎么办。 | R02、R04 |

<details>
<summary>原文（22 条）</summary>

**9110-5.1-1**　RFC 9110 §5.1

> A proxy MUST forward unrecognized header fields unless the field name is listed in the Connection header field (Section 7.6.1) or the proxy is specifically configured to block, or otherwise transform, such fields.

**9110-5.3-1**　RFC 9110 §5.3

> The order in which field lines with the same name are received is therefore significant to the interpretation of the field value; a proxy MUST NOT change the order of these field line values when forwarding a message.

**9110-5.6.1.2-1**　RFC 9110 §5.6.1.2

> Empty elements do not contribute to the count of elements present. A recipient MUST parse and ignore a reasonable number of empty list elements: enough to handle common mistakes by senders that merge values, but not so much that they could be used as a denial-of- service mechanism.

**9110-6.6.1-1**　RFC 9110 §6.6.1

> A recipient with a clock that receives a response message without a Date header field MUST record the time it was received and append a corresponding Date header field to the message's header section if it is cached or forwarded downstream.

**9110-7.6-1**　RFC 9110 §7.6

> Intermediaries are expected to forward messages even when protocol elements are not recognized (e.g., new methods, status codes, or field names) since that preserves extensibility for downstream recipients.

**9110-7.6-2**　RFC 9110 §7.6

> An intermediary not acting as a tunnel MUST implement the Connection header field, as specified in Section 7.6.1, and exclude fields from being forwarded that are only intended for the incoming connection.

**9110-7.6.1-1**　RFC 9110 §7.6.1

> When a field aside from Connection is used to supply control information for or about the current connection, the sender MUST list the corresponding field name within the Connection header field.

**9110-7.6.1-2**　RFC 9110 §7.6.1

> Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).

**9110-7.6.1-3**　RFC 9110 §7.6.1

> Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics. This includes but is not limited to: \* Proxy-Connection (Appendix C.2.2 of \[HTTP/1.1\]) \* Keep-Alive (Section 19.7.1 of \[RFC2068\]) \* TE (Section 10.1.4) \* Transfer-Encoding (Section 6.1 of \[HTTP/1.1\]) \* Upgrade (Section 7.8)

**9110-7.6.1-4**　RFC 9110 §7.6.1

> A sender MUST NOT send a connection option corresponding to a field that is intended for all recipients of the content.

**9110-7.6.1-5**　RFC 9110 §7.6.1

> In contrast, a connection-specific field received without a corresponding connection option usually indicates that the field has been improperly forwarded by an intermediary and ought to be ignored by the recipient.

**9110-7.6.1-6**　RFC 9110 §7.6.1

> Connection options are case-insensitive.

**9110-7.7-3**　RFC 9110 §7.7

> A proxy SHOULD NOT modify header fields that provide information about the endpoints of the communication chain, the resource state, or the selected representation (other than the content) unless the field's definition specifically allows such modification or the modification is deemed necessary for privacy or security.

**9110-7.7-4**　RFC 9110 §7.7

> A proxy MUST NOT transform the content (Section 6.4) of a response message that contains a no-transform cache directive (Section 5.2.2.6 of \[CACHING\]). Note that this does not apply to message transformations that do not change the content, such as the addition or removal of transfer codings (Section 7 of \[HTTP/1.1\]).

**9110-10.1.4-1**　RFC 9110 §10.1.4

> A sender of TE MUST also send a "TE" connection option within the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.

**9110-11.6.1-1**　RFC 9110 §11.6.1

> A proxy forwarding a response MUST NOT modify any WWW-Authenticate header fields in that response.

**9110-11.6.2-1**　RFC 9110 §11.6.2

> A proxy forwarding a request MUST NOT modify any Authorization header fields in that request.

**9112-2.3-1**　RFC 9112 §2.3

> Intermediaries that process HTTP messages (i.e., all intermediaries other than those acting as tunnels) MUST send their own HTTP-version in forwarded messages, unless it is purposefully downgraded as a workaround for an upstream issue.

**9112-7.1.1-1**　RFC 9112 §7.1.1

> The chunked coding is specific to each connection and is likely to be removed or recoded by each recipient (including intermediaries) before any higher-level application would have a chance to inspect the extensions.

**9112-7.4-1**　RFC 9112 §7.4

> A client MUST NOT send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients.

**9112-7.4-2**　RFC 9112 §7.4

> Since the TE header field only applies to the immediate connection, a sender of TE MUST also send a "TE" connection option within the Connection header field (Section 7.6.1 of \[HTTP\]) in order to prevent the TE header field from being forwarded by intermediaries that do not support its semantics.

**9112-C.2.2-1**　RFC 9112 §C.2.2

> One attempted solution was the introduction of a Proxy-Connection header field, targeted specifically at proxies. In practice, this was also unworkable, because proxies are often deployed in multiple layers, bringing about the same problem discussed above. As a result, clients are encouraged not to send the Proxy-Connection header field in any requests.

</details>

### via：Via

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-6.2-1 | RFC 9110 §6.2 Control Data | statement | intermediary | 入口 | 网关转发明文消息时，协议版本写网关自己用的版本；上一跳用的版本记在 Via 里（9110-7.6.3-1）。 | — |
| 9110-7.6.2-1 | RFC 9110 §7.6.2 Max-Forwards | MUST | intermediary | 入口 | 网关转发 TRACE 或 OPTIONS 时：有 Max-Forwards 就先检查。值为 0 不得转发，自己作为最终接收方应答；大于 0 则转发时写成减一后的值（或网关支持的上限，取小的）。topic 里没有专门的一类，与 Via 同属转发链的控制，归在 via。 | — |
| 9110-7.6.2-2 | RFC 9110 §7.6.2 Max-Forwards | MAY | recipient | 入口 | 别的方法带 Max-Forwards 时，网关可以不理会。 | — |
| 9110-7.6.3-1 | RFC 9110 §7.6.3 Via | MUST | proxy | 入口 | 网关作为代理转发的每个消息（请求和响应）都必须带上自己的 Via 项。隧道里的数据不是网关转发的 HTTP 消息，不适用（9110-3.7-4）；网关自己生成的响应（407、502 等）不是转发的消息。 | R87 |
| 9110-7.6.3-2 | RFC 9110 §7.6.3 Via | statement | intermediary | 入口 | Via 是追加，不是覆盖：已有的 Via 项保留，网关的项加在后面。 | — |
| 9110-7.6.3-3 | RFC 9110 §7.6.3 Via | statement | intermediary | 入口 | Via 项里的 received-protocol 写的是上一跳发来这个消息时用的协议版本（请求里是客户端的版本，响应里是上游或源站的版本），不是网关自己的版本。 | — |
| 9110-7.6.3-4 | RFC 9110 §7.6.3 Via | MAY | sender | 入口 | Via 项里的 received-by 可以用化名代替真实主机名。网关不必在 Via 里暴露自己的主机名或端口。 | — |
| 9110-9.3.7-1 | RFC 9110 §9.3.7 OPTIONS | MUST NOT | proxy | 入口 | 网关转发请求时，收到的请求没有 Max-Forwards 就不得自己加一个。与 9110-7.6.2-1 配套：有就按那一条检查、递减，没有就不加。 | — |

<details>
<summary>原文（8 条）</summary>

**9110-6.2-1**　RFC 9110 §6.2

> When a message is forwarded by an intermediary, the protocol version is updated to reflect the version used by that intermediary. The Via header field (Section 7.6.3) is used to communicate upstream protocol information within a forwarded message.

**9110-7.6.2-1**　RFC 9110 §7.6.2

> Each intermediary that receives a TRACE or OPTIONS request containing a Max-Forwards header field MUST check and update its value prior to forwarding the request. If the received value is zero (0), the intermediary MUST NOT forward the request; instead, the intermediary MUST respond as the final recipient. If the received Max-Forwards value is greater than zero, the intermediary MUST generate an updated Max-Forwards field in the forwarded message with a field value that is the lesser of a) the received value decremented by one (1) or b) the recipient's maximum supported value for Max-Forwards.

**9110-7.6.2-2**　RFC 9110 §7.6.2

> A recipient MAY ignore a Max-Forwards header field received with any other request methods.

**9110-7.6.3-1**　RFC 9110 §7.6.3

> A proxy MUST send an appropriate Via header field, as described below, in each message that it forwards.

**9110-7.6.3-2**　RFC 9110 §7.6.3

> Each intermediary appends its own information about how the message was received, such that the end result is ordered according to the sequence of forwarding recipients.

**9110-7.6.3-3**　RFC 9110 §7.6.3

> For each intermediary, the received-protocol indicates the protocol and protocol version used by the upstream sender of the message.

**9110-7.6.3-4**　RFC 9110 §7.6.3

> The received-by portion is normally the host and optional port number of a recipient server or client that subsequently forwarded the message. However, if the real host is considered to be sensitive information, a sender MAY replace it with a pseudonym.

**9110-9.3.7-1**　RFC 9110 §9.3.7

> A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field.

</details>

### framing：消息定界

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-6.2-2 | RFC 9110 §6.2 Control Data | SHOULD | recipient | 两侧 | 入口收到 HTTP/1.2 之类小版本号更高的请求、上游回这样的响应时，应当按 HTTP/1.1 处理，而不是因为版本号拒绝。 | — |
| 9110-7.5-1 | RFC 9110 §7.5 Response Correlation | statement | any | 两侧 | 响应可以在请求还没发完时就发出。入口可以在客户端的请求正文没传完时就回 407 或别的最终响应；上游也可能这样对网关。之后连接怎么办见 9110-10.1.1-9。 | R43 |
| 9110-7.5-2 | RFC 9110 §7.5 Response Correlation | SHOULD | client | 两侧 | 客户端在发请求的途中收到响应，没有明确的相反指示就应当把请求发完。所以入口提前回 407 之后，还可能继续收到那个请求剩下的正文；网关作为上游的客户端也照此办。 | R43 |
| 9110-8.6-1 | RFC 9110 §8.6 Content-Length | SHOULD | client | 客户端 | 背景：方法为内容定义了含义时，客户端不用 Transfer-Encoding 就应当发 Content-Length。用来解释客户端 POST 正文的分帧方式。 | R19 |
| 9112-2.2-4 | RFC 9112 §2.2 Message Parsing | MUST NOT | client | 客户端 | 客户端不该在请求前后多发 CRLF；据此判断客户端在代理连接上发的第一个字节是否合规。 | R23 |
| 9112-2.2-5 | RFC 9112 §2.2 Message Parsing | SHOULD | recipient | 入口 | 原文主语是 server。入口在等请求行时应当忽略至少一个前导空行。网关按首字节分流，持久连接上后续请求之前的 CRLF 要按这条跳过；连接的第一个字节就是 CR 时怎么分流，条款没有规定。 | R23 |
| 9112-6-1 | RFC 9112 §6 Message Body | statement | any | 两侧 | 判断请求有没有正文只看 Content-Length 和 Transfer-Encoding，不看方法：GET 带这两个头之一也有正文，POST 两个都没有就没有正文。 | R19 |
| 9112-6.1-1 | RFC 9112 §6.1 Transfer-Encoding | MUST | recipient | 两侧 | 入口必须能解析分块的请求正文，上游一侧必须能解析分块的响应正文。 | R19 |
| 9112-6.1-2 | RFC 9112 §6.1 Transfer-Encoding | MUST | sender | 两侧 | 约束发送方：请求里用了别的传输编码时，最后一层必须是 chunked；响应里则是 chunked 收尾或者以关闭连接结束。网关发出的消息要满足；收到的请求不满足时按 6.3 第 4 项处理。 | R19 |
| 9112-6.1-3 | RFC 9112 §6.1 Transfer-Encoding | MAY | recipient | 两侧 | 网关可以在转发时拆掉或加上传输编码（例如把分块的请求重新分块，或收齐后改成 Content-Length），前提是 Transfer-Encoding 头跟着改。所以正文的分帧方式是逐跳的，源站看到的分帧不一定是客户端发出的那一种。 | R19、R24 |
| 9112-6.1-5 | RFC 9112 §6.1 Transfer-Encoding | SHOULD | recipient | 入口 | 原文主语是 server。入口遇到自己不认识的传输编码应当回 501，不要猜着处理。 | — |
| 9112-6.1-6 | RFC 9112 §6.1 Transfer-Encoding | MUST NOT | client | 两侧 | 约束客户端。网关向上游转发带 Transfer-Encoding 的请求之前，要知道下一跳能处理 HTTP/1.1（配置或之前收到过的响应版本）；也用来判断客户端的明文 POST 用分块是否合规。 | R19 |
| 9112-6.1-7 | RFC 9112 §6.1 Transfer-Encoding | MUST NOT | sender | 入口 | 原文主语是 server。客户端的请求是 HTTP/1.0 时，网关回给它的响应不能带 Transfer-Encoding（上游回来的分块响应要先解掉，或者以关闭连接定界）。 | — |
| 9112-6.3-1 | RFC 9112 §6.3 Message Body Length | statement | recipient | 两侧 | 判定规则第 1 项（优先级最高）：网关读上游的响应时，对 HEAD 的响应和 1xx、204、304 一律到头部结束为止，不管它带什么 Content-Length 或 Transfer-Encoding。所以网关必须记住每个响应对应的请求方法。 | — |
| 9112-6.3-4 | RFC 9112 §6.3 Message Body Length | statement | recipient | 两侧 | 判定规则第 4 项之一：最后一层是 chunked 时，正文到分块编码自己宣告结束为止。 | R19 |
| 9112-6.3-5 | RFC 9112 §6.3 Message Body Length | statement | recipient | 上游 | 判定规则第 4 项之二：上游的响应带 Transfer-Encoding 而最后一层不是 chunked，正文读到对方关闭连接为止；这条上游连接不能再复用。 | — |
| 9112-6.3-10 | RFC 9112 §6.3 Message Body Length | MUST | recipient | 两侧 | 判定规则第 6 项：按 Content-Length 读正文；没读够对方就关了连接或者超时，必须把消息当作不完整并关闭连接，不能把收到的部分当作完整的消息。 | R24 |
| 9112-6.3-11 | RFC 9112 §6.3 Message Body Length | statement | recipient | 入口 | 判定规则第 7 项：请求既没有 Transfer-Encoding 也没有 Content-Length 就是没有正文；头部之后的字节属于下一个请求，入口不能把它们当作这个请求的正文。 | R19 |
| 9112-6.3-12 | RFC 9112 §6.3 Message Body Length | statement | recipient | 上游 | 判定规则第 8 项：上游的响应没有声明长度时，正文读到对方关闭连接为止；这条上游连接不能复用，网关也分辨不出正文是否被截断。 | — |
| 9112-6.3-13 | RFC 9112 §6.3 Message Body Length | MAY | recipient | 入口 | 原文主语是 server。入口可以用 411 拒绝只用分块、不带 Content-Length 的请求；这是允许，不是要求。源站或上游也可能这样做。 | R19 |
| 9112-6.3-14 | RFC 9112 §6.3 Message Body Length | SHOULD | client | 两侧 | 约束客户端：正文长度事先知道时应当用 Content-Length 而不是分块。用来判断客户端的明文 POST 怎么分帧；网关向上游转发已知长度的正文时也应当用 Content-Length。 | R19 |
| 9112-6.3-15 | RFC 9112 §6.3 Message Body Length | MUST | client | 客户端 | 约束用户代理：带正文的请求必须有合法的 Content-Length 或用分块，二者必居其一。 | R19 |
| 9112-6.3-17 | RFC 9112 §6.3 Message Body Length | SHOULD | sender | 入口 | 原文主语是 server。靠关闭连接定界的响应，客户端分不清是发完了还是中途断了。网关自己生成的响应，以及把上游“读到关闭为止”的响应（9112-6.3-12）转给客户端时，应当尽量用 Content-Length 或分块来定界。 | — |
| 9112-7.1-1 | RFC 9112 §7.1 Chunked Transfer Coding | statement | any | 两侧 | 背景：分块长度是十六进制；收到长度为零的块、可选的尾部字段和最后的空行才算结束。 | R19 |
| 9112-7.1-3 | RFC 9112 §7.1 Chunked Transfer Coding | SHOULD | recipient | 两侧 | Transfer-Encoding 里的 chunked 带了参数时应当按错误处理。 | — |
| 9112-7.1.1-2 | RFC 9112 §7.1.1 Chunk Extensions | MUST | recipient | 两侧 | 网关解析分块正文时必须能跳过不认识的块扩展，不能因为有扩展就解析失败。第二句（ought to，不是规范性关键词）建议入口给块扩展的总长度设上限，超限回 4xx。 | — |
| 9112-7.1.2-1 | RFC 9112 §7.1.2 Chunked Trailer Section | MUST NOT | recipient | 两侧 | 网关拆掉分块编码时可以丢弃尾部字段；保留的话要与头部分开转发，不能把尾部字段并进头部，除非该字段的定义明确允许。 | — |
| 9112-8-2 | RFC 9112 §8 Handling Incomplete Messages | MUST | client | 上游 | 上游的响应没收完（连接提前关闭、分块解码失败）时，网关必须把它记为不完整，不能当成完整的响应。 | R24 |
| 9112-8-3 | RFC 9112 §8 Handling Incomplete Messages | statement | any | 两侧 | “不完整”的定义：分块的没收到长度为零的结束块；按 Content-Length 的收到的字节数不够。网关按这个定义判断请求正文和上游响应是否完整。 | R24 |

<details>
<summary>原文（29 条）</summary>

**9110-6.2-2**　RFC 9110 §6.2

> A recipient that receives a message with a major version number that it implements and a minor version number higher than what it implements SHOULD process the message as if it were in the highest minor version within that major version to which the recipient is conformant.

**9110-7.5-1**　RFC 9110 §7.5

> All responses, regardless of the status code (including interim responses) can be sent at any time after a request is received, even if the request is not yet complete.

**9110-7.5-2**　RFC 9110 §7.5

> A client that receives a response while it is still sending the associated request SHOULD continue sending that request unless it receives an explicit indication to the contrary (see, e.g., Section 9.5 of \[HTTP/1.1\] and Section 6.4 of \[HTTP/2\]).

**9110-8.6-1**　RFC 9110 §8.6

> A user agent SHOULD send Content-Length in a request when the method defines a meaning for enclosed content and it is not sending Transfer-Encoding.

**9112-2.2-4**　RFC 9112 §2.2

> An HTTP/1.1 user agent MUST NOT preface or follow a request with an extra CRLF.

**9112-2.2-5**　RFC 9112 §2.2

> In the interest of robustness, a server that is expecting to receive and parse a request-line SHOULD ignore at least one empty line (CRLF) received prior to the request-line.

**9112-6-1**　RFC 9112 §6

> The presence of a message body in a request is signaled by a Content-Length or Transfer-Encoding header field. Request message framing is independent of method semantics.

**9112-6.1-1**　RFC 9112 §6.1

> A recipient MUST be able to parse the chunked transfer coding (Section 7.1) because it plays a crucial role in framing messages when the content size is not known in advance.

**9112-6.1-2**　RFC 9112 §6.1

> If any transfer coding other than chunked is applied to a request's content, the sender MUST apply chunked as the final transfer coding to ensure that the message is properly framed. If any transfer coding other than chunked is applied to a response's content, the sender MUST either apply chunked as the final transfer coding or terminate the message by closing the connection.

**9112-6.1-3**　RFC 9112 §6.1

> Unlike Content-Encoding (Section 8.4.1 of \[HTTP\]), Transfer-Encoding is a property of the message, not of the representation. Any recipient along the request/response chain MAY decode the received transfer coding(s) or apply additional transfer coding(s) to the message body, assuming that corresponding changes are made to the Transfer-Encoding field value.

**9112-6.1-5**　RFC 9112 §6.1

> A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented).

**9112-6.1-6**　RFC 9112 §6.1

> A client MUST NOT send a request containing Transfer-Encoding unless it knows the server will handle HTTP/1.1 requests (or later minor revisions); such knowledge might be in the form of specific user configuration or by remembering the version of a prior received response.

**9112-6.1-7**　RFC 9112 §6.1

> A server MUST NOT send a response containing Transfer- Encoding unless the corresponding request indicates HTTP/1.1 (or later minor revisions).

**9112-6.3-1**　RFC 9112 §6.3

> Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section.

**9112-6.3-4**　RFC 9112 §6.3

> If a Transfer-Encoding header field is present and the chunked transfer coding (Section 7.1) is the final encoding, the message body length is determined by reading and decoding the chunked data until the transfer coding indicates the data is complete.

**9112-6.3-5**　RFC 9112 §6.3

> If a Transfer-Encoding header field is present in a response and the chunked transfer coding is not the final encoding, the message body length is determined by reading the connection until it is closed by the server.

**9112-6.3-10**　RFC 9112 §6.3

> If a valid Content-Length header field is present without Transfer-Encoding, its decimal value defines the expected message body length in octets. If the sender closes the connection or the recipient times out before the indicated number of octets are received, the recipient MUST consider the message to be incomplete and close the connection.

**9112-6.3-11**　RFC 9112 §6.3

> If this is a request message and none of the above are true, then the message body length is zero (no message body is present).

**9112-6.3-12**　RFC 9112 §6.3

> Otherwise, this is a response message without a declared message body length, so the message body length is determined by the number of octets received prior to the server closing the connection.

**9112-6.3-13**　RFC 9112 §6.3

> A server MAY reject a request that contains a message body but not a Content-Length by responding with 411 (Length Required).

**9112-6.3-14**　RFC 9112 §6.3

> Unless a transfer coding other than chunked has been applied, a client that sends a request containing a message body SHOULD use a valid Content-Length header field if the message body length is known in advance, rather than the chunked transfer coding, since some existing services respond to chunked with a 411 (Length Required) status code even though they understand the chunked transfer coding.

**9112-6.3-15**　RFC 9112 §6.3

> A user agent that sends a request that contains a message body MUST send either a valid Content-Length header field or use the chunked transfer coding.

**9112-6.3-17**　RFC 9112 §6.3

> Since there is no way to distinguish a successfully completed, close- delimited response message from a partially received message interrupted by network failure, a server SHOULD generate encoding or length-delimited messages whenever possible.

**9112-7.1-1**　RFC 9112 §7.1

> The chunk-size field is a string of hex digits indicating the size of the chunk-data in octets. The chunked transfer coding is complete when a chunk with a chunk-size of zero is received, possibly followed by a trailer section, and finally terminated by an empty line.

**9112-7.1-3**　RFC 9112 §7.1

> The chunked coding does not define any parameters. Their presence SHOULD be treated as an error.

**9112-7.1.1-2**　RFC 9112 §7.1.1

> A recipient MUST ignore unrecognized chunk extensions. A server ought to limit the total length of chunk extensions received in a request to an amount reasonable for the services provided, in the same way that it applies length limitations and timeouts for other parts of a message, and generate an appropriate 4xx (Client Error) response if that amount is exceeded.

**9112-7.1.2-1**　RFC 9112 §7.1.2

> A recipient that removes the chunked coding from a message MAY selectively retain or discard the received trailer fields. A recipient that retains a received trailer field MUST either store/ forward the trailer field separately from the received header fields or merge the received trailer field into the header section. A recipient MUST NOT merge a received trailer field into the header section unless its corresponding header field definition explicitly permits and instructs how the trailer field value can be safely merged.

**9112-8-2**　RFC 9112 §8

> A client that receives an incomplete response message, which can occur when a connection is closed prematurely or when decoding a supposedly chunked transfer coding fails, MUST record the message as incomplete.

**9112-8-3**　RFC 9112 §8

> A message body that uses the chunked transfer coding is incomplete if the zero-sized chunk that terminates the encoding has not been received. A message that uses a valid Content-Length is incomplete if the size of the message body received (in octets) is less than the value given by Content-Length.

</details>

### smuggling：请求走私

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-5.1-2 | RFC 9110 §5.1 Field Names | statement | any | 两侧 | 字段名不分大小写。网关查找 Content-Length、Transfer-Encoding、Host、Proxy-Authorization，以及按 Connection 里的名字删逐跳头，都要按不分大小写比较；按大小写敏感去比会漏判、漏删。 | — |
| 9110-5.2-1 | RFC 9110 §5.2 Field Lines and Combined Field Value | statement | any | 两侧 | 同名字段出现多行时，字段值是各行的值按顺序用逗号连起来的列表。所以两行 Content-Length 等于一个列表值，按 9110-8.6-5、9112-6.3-7 处理；多行 Connection、Transfer-Encoding 也先这样合并再解析。 | R19 |
| 9110-5.3-2 | RFC 9110 §5.3 Field Order | MUST NOT | recipient | 入口 | 原文主语是 server。入口要读完整个请求头部分再动作（连目标、选上游、转发）：后面的头字段行里可能有凭据，或者故意误导的重复头。 | R04 |
| 9110-5.4-1 | RFC 9110 §5.4 Field Limits | MUST | recipient | 入口 | 原文主语是 server。入口对头字段行、字段值或整个头部分设了长度上限的话，超限必须回一个合适的 4xx，不能把超长的字段丢掉后继续处理；超长的 Proxy-Authorization（很长的用户名）属于这种情况。 | R65、R66、R67 |
| 9110-5.5-1 | RFC 9110 §5.5 Field Values | MUST | recipient | 两侧 | 解析字段值之前必须先去掉首尾的空白。入口解析 Content-Length、Connection、Proxy-Authorization，上游一侧解析响应头，都先去空白再求值；否则网关和下一跳会对同一个值得出不同的解读。 | — |
| 9110-5.5-2 | RFC 9110 §5.5 Field Values | MUST | recipient | 两侧 | 字段值里出现 CR、LF 或 NUL 时，收到的一方二选一：拒绝整条消息，或者把这些字符逐个换成空格之后再处理、再转发。入口对请求、上游一侧对响应都适用；不能原样转给下一跳。起始行和头部里的裸 CR 另见 9112-2.2-3。 | — |
| 9110-8.6-3 | RFC 9110 §8.6 Content-Length | statement | any | 入口 | 背景：Content-Length 与实际分帧不一致的消息被转发下去，会造成请求走私或响应拆分。下面两条 MUST NOT 的理由。 | R19 |
| 9110-8.6-4 | RFC 9110 §8.6 Content-Length | MUST NOT | sender | 入口 | 网关不得转发已知 Content-Length 不正确的消息：转发时发现正文长度与 Content-Length 对不上，不能照旧把头发给下一跳。 | R19、R24 |
| 9110-8.6-5 | RFC 9110 §8.6 Content-Length | MUST NOT | sender | 入口 | Content-Length 的值不合 1*DIGIT 语法的消息不得转发。唯一的例外是同一个十进制数重复成逗号列表（如“42, 42”）：接收方可以拒绝，也可以换成单个值；网关二选一并固定下来。 | R19 |
| 9110-8.6-6 | RFC 9110 §8.6 Content-Length | MUST | recipient | 两侧 | Content-Length 没有预定的上限。入口和上游两侧解析它时，必须防住整数转换的溢出和精度损失：很长的数字不能被截断或回绕成另一个长度（chunk-size 的对应要求见 9112-7.1-2）。这两句在原文里排在 9110-8.6-3 之前。 | R19 |
| 9110-17.5-1 | RFC 9110 §17.5 Attacks via Protocol Element Length | statement | recipient | 两侧 | 入口和上游两侧的解析都要设上限：方法、状态短语、字段名、数值、分块长度。没有规范性关键词（ought to）；超限时对客户端的应答见 9110-5.4-1。 | R65、R66、R67 |
| 9112-2.2-1 | RFC 9112 §2.2 Message Parsing | MUST | recipient | 两侧 | 入口解析请求、上游一侧解析响应，都按字节序列处理起始行和头部，不先把整条消息解码成 Unicode 字符串再切行。 | — |
| 9112-2.2-2 | RFC 9112 §2.2 Message Parsing | MAY | recipient | 两侧 | 把单个 LF 当作行结束符是允许的，不是必须的；网关接受还是拒绝裸 LF 由自己定。 | — |
| 9112-2.2-3 | RFC 9112 §2.2 Message Parsing | MUST | recipient | 两侧 | 收到的起始行或头部里有裸 CR 时，网关要么判该元素无效，要么先把每个裸 CR 换成空格再处理或转发；不能原样转给上游或客户端。第一句约束发送方：网关自己生成的消息里（正文之外）不能有裸 CR。 | — |
| 9112-2.2-6 | RFC 9112 §2.2 Message Parsing | MUST NOT | sender | 两侧 | 网关生成或转发的消息，起始行和第一个头之间不能有空白开头的行；也是判断客户端请求是否合规的依据。 | — |
| 9112-2.2-7 | RFC 9112 §2.2 Message Parsing | MUST | recipient | 两侧 | 起始行之后紧跟以空白开头的行时，网关要么拒绝整条消息，要么把这些行整行丢掉；不能把它们当成头部解释，也不能原样转发。 | — |
| 9112-3-1 | RFC 9112 §3 Request Line | MAY | recipient | 入口 | 请求行的宽松解析只是允许。网关之后还有上游代理和源站这些接收方，原文指出这种多个接收方的情形下宽松解析会带来请求走私的风险；网关可以只接受单个 SP 分隔的请求行。 | R01、R03 |
| 9112-5.1-1 | RFC 9112 §5.1 Field Line Parsing | MUST | recipient | 入口 | 原文主语是 server。入口收到头名和冒号之间有空白的请求，回 400 拒绝；不能去掉空白后继续转发。 | — |
| 9112-5.1-2 | RFC 9112 §5.1 Field Line Parsing | MUST | proxy | 入口 | 上游回来的响应里头名和冒号之间有空白时，网关转给客户端之前必须去掉这些空白（“such whitespace”指上一句说的头名与冒号之间的空白）。 | — |
| 9112-5.2-1 | RFC 9112 §5.2 Obsolete Line Folding | MUST NOT | sender | 两侧 | 网关发出的消息（转发的和自己生成的）里不能有折行的头。 | — |
| 9112-5.2-2 | RFC 9112 §5.2 Obsolete Line Folding | MUST | recipient | 入口 | 原文主语是 server。入口收到带折行头的请求，两条路二选一：回 400；或者先把每处折行换成空格，再解释头值、再转发。不能原样转给上游。 | — |
| 9112-5.2-3 | RFC 9112 §5.2 Obsolete Line Folding | MUST | proxy | 入口 | 上游回来的响应里有折行的头时，网关要么丢弃该响应、给客户端回 502，要么先把折行换成空格再解释和转发。 | — |
| 9112-6.1-8 | RFC 9112 §6.1 Transfer-Encoding | MUST | recipient | 入口 | 原文主语是 server。入口收到同时带 Content-Length 和 Transfer-Encoding 的请求：可以拒绝，也可以只按 Transfer-Encoding 处理；不管选哪种，回完响应必须关闭这条客户端连接。 | R19 |
| 9112-6.1-9 | RFC 9112 §6.1 Transfer-Encoding | MUST | recipient | 两侧 | 入口收到的 HTTP/1.0 请求、上游回来的 HTTP/1.0 响应只要带 Transfer-Encoding，就按分帧有问题处理，处理完关闭那条连接，不复用。 | — |
| 9112-6.1-10 | RFC 9112 §6.1 Transfer-Encoding | MUST NOT | sender | 两侧 | 网关按 9112-6.1-3 给消息加传输编码时，不得在已经分块的正文外面再套一层 chunked。反过来，收到 Transfer-Encoding 里 chunked 出现不止一次的消息，是发送方违规；接收方该怎么办这句没有说。这一句在原文里排在 9112-6.1-2 之前。 | R19 |
| 9112-6.2-1 | RFC 9112 §6.2 Content-Length | MUST NOT | sender | 两侧 | 网关发出的任何消息不能同时带 Content-Length 和 Transfer-Encoding；客户端这样发属于违规。 | R19 |
| 9112-6.3-3 | RFC 9112 §6.3 Message Body Length | MUST | intermediary | 入口 | 判定规则第 3 项：两个头都有时以 Transfer-Encoding 为准，原文说这种消息应当按错误处理（ought to，不是规范性关键词）。网关如果选择转发，必须先删掉 Content-Length 并按 Transfer-Encoding 处理正文；请求和响应两个方向都适用。 | R19 |
| 9112-6.3-6 | RFC 9112 §6.3 Message Body Length | MUST | recipient | 入口 | 原文主语是 server。判定规则第 4 项之三：入口收到带 Transfer-Encoding 而最后一层不是 chunked 的请求，必须回 400 并关闭连接，不转发。 | — |
| 9112-6.3-7 | RFC 9112 §6.3 Message Body Length | MUST | recipient | 两侧 | 判定规则第 5 项：没有 Transfer-Encoding 而 Content-Length 不合法（非数字、多个值不一致）时，分帧无效，按不可恢复的错误处理。唯一的例外是逗号分隔的列表里每个值都合法并且全部相同，这时按那一个值处理。 | — |
| 9112-6.3-8 | RFC 9112 §6.3 Message Body Length | MUST | recipient | 入口 | 原文主语是 server。接上一条：请求的 Content-Length 不合法时，入口回 400 并关闭客户端连接。 | — |
| 9112-6.3-9 | RFC 9112 §6.3 Message Body Length | MUST | proxy | 入口 | 接上一条：上游回来的响应 Content-Length 不合法时，网关必须关闭那条上游连接、丢弃该响应，并给客户端回 502。 | — |
| 9112-6.3-16 | RFC 9112 §6.3 Message Body Length | MUST NOT | client | 上游 | 上游连接上最后一个响应收完之后还有多余的数据时，网关不能把它当作另一个响应去处理或转发给客户端。 | — |
| 9112-7.1-2 | RFC 9112 §7.1 Chunked Transfer Coding | MUST | recipient | 两侧 | 网关解析 chunk-size 时要防整数溢出和精度损失：超出所用整数类型范围的值按错误处理，不能回绕成一个小数字。 | — |
| 9112-9.2-3 | RFC 9112 §9.2 Associating a Response to a Request | MUST NOT | client | 上游 | 空闲的上游连接上收到数据（只有 CRLF 的除外）时，网关不能把它当作有效的响应，并且应当关闭这条连接，不放回连接池。 | — |
| 9112-9.3-6 | RFC 9112 §9.3 Persistence | MUST | recipient | 两侧 | 原文主语是 server。入口在请求正文读完之前就回了响应（例如对带正文的 POST 回 407）时，要么把剩下的正文读完，要么回完就关闭连接，否则剩下的正文会被当成下一个请求。第二句约束客户端角色：网关要复用上游连接，就得先把上一个响应的正文读完。 | R34、R43 |
| 9112-11.1-1 | RFC 9112 §11.1 Response Splitting | statement | any | 两侧 | 背景（安全建议，没有规范性关键词）：头部只经过会过滤 CR、LF 的接口输出。网关把来自客户端的数据（目标主机、用户名里的会话参数等）写进发给上游的请求头或自己的响应头时，照此过滤 CR 和 LF。 | — |
| 9112-11.2-1 | RFC 9112 §11.2 Request Smuggling | statement | any | 两侧 | 背景：请求走私利用的是各个接收方解析不一致。网关与上游代理、源站正是这样一串接收方；原文指明防线是 6.3 节的分帧规则。 | R19 |
| 9112-11.3-2 | RFC 9112 §11.3 Message Integrity | statement | any | 上游 | 背景：明文 http 的消息对无意或恶意的修改没有任何保护。经不可信上游转发的明文请求和响应，HTTP 本身不提供发现改动的手段。 | R24 |

<details>
<summary>原文（38 条）</summary>

**9110-5.1-2**　RFC 9110 §5.1

> Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry"; see Section 16.3.1.

**9110-5.2-1**　RFC 9110 §5.2

> When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma.

**9110-5.3-2**　RFC 9110 §5.3

> A server MUST NOT apply a request to the target resource until it receives the entire request header section, since later header field lines might include conditionals, authentication credentials, or deliberately misleading duplicate header fields that could impact request processing.

**9110-5.4-1**　RFC 9110 §5.4

> A server that receives a request header field line, field value, or set of fields larger than it wishes to process MUST respond with an appropriate 4xx (Client Error) status code. Ignoring such header fields would increase the server's vulnerability to request smuggling attacks (Section 11.2 of \[HTTP/1.1\]).

**9110-5.5-1**　RFC 9110 §5.5

> A field value does not include leading or trailing whitespace. When a specific version of HTTP allows such whitespace to appear in a message, a field parsing implementation MUST exclude such whitespace prior to evaluating the field value.

**9110-5.5-2**　RFC 9110 §5.5

> Field values containing CR, LF, or NUL characters are invalid and dangerous, due to the varying ways that implementations might parse and interpret those characters; a recipient of CR, LF, or NUL within a field value MUST either reject the message or replace each of those characters with SP before further processing or forwarding of that message.

**9110-8.6-3**　RFC 9110 §8.6

> Because Content-Length is used for message delimitation in HTTP/1.1, its field value can impact how the message is parsed by downstream recipients even when the immediate connection is not using HTTP/1.1. If the message is forwarded by a downstream intermediary, a Content- Length field value that is inconsistent with the received message framing might cause a security failure due to request smuggling or response splitting.

**9110-8.6-4**　RFC 9110 §8.6

> As a result, a sender MUST NOT forward a message with a Content- Length header field value that is known to be incorrect.

**9110-8.6-5**　RFC 9110 §8.6

> Likewise, a sender MUST NOT forward a message with a Content-Length header field value that does not match the ABNF above, with one exception: a recipient of a Content-Length header field value consisting of the same decimal value repeated as a comma-separated list (e.g, "Content-Length: 42, 42") MAY either reject the message as invalid or replace that invalid field value with a single instance of the decimal value, since this likely indicates that a duplicate was generated or combined by an upstream message processor.

**9110-8.6-6**　RFC 9110 §8.6

> Any Content-Length field value greater than or equal to zero is valid. Since there is no predefined limit to the length of content, a recipient MUST anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows or precision loss due to integer conversion (Section 17.5).

**9110-17.5-1**　RFC 9110 §17.5

> Recipients ought to carefully limit the extent to which they process other protocol elements, including (but not limited to) request methods, response status phrases, field names, numeric values, and chunk lengths. Failure to limit such processing can result in arbitrary code execution due to buffer or arithmetic overflows, and increased vulnerability to denial-of-service attacks.

**9112-2.2-1**　RFC 9112 §2.2

> A recipient MUST parse an HTTP message as a sequence of octets in an encoding that is a superset of US-ASCII \[USASCII\].

**9112-2.2-2**　RFC 9112 §2.2

> Although the line terminator for the start-line and fields is the sequence CRLF, a recipient MAY recognize a single LF as a line terminator and ignore any preceding CR.

**9112-2.2-3**　RFC 9112 §2.2

> A sender MUST NOT generate a bare CR (a CR character not immediately followed by LF) within any protocol elements other than the content. A recipient of such a bare CR MUST consider that element to be invalid or replace each bare CR with SP before processing the element or forwarding the message.

**9112-2.2-6**　RFC 9112 §2.2

> A sender MUST NOT send whitespace between the start-line and the first header field.

**9112-2.2-7**　RFC 9112 §2.2

> A recipient that receives whitespace between the start-line and the first header field MUST either reject the message as invalid or consume each whitespace-preceded line without further processing of it (i.e., ignore the entire line, along with any subsequent lines preceded by whitespace, until a properly formed header field is received or the header section is terminated).

**9112-3-1**　RFC 9112 §3

> Although the request-line grammar rule requires that each of the component elements be separated by a single SP octet, recipients MAY instead parse on whitespace-delimited word boundaries and, aside from the CRLF terminator, treat any form of whitespace as the SP separator while ignoring preceding or trailing whitespace; such whitespace includes one or more of the following octets: SP, HTAB, VT (%x0B), FF (%x0C), or bare CR. However, lenient parsing can result in request smuggling security vulnerabilities if there are multiple recipients of the message and each has its own unique interpretation of robustness (see Section 11.2).

**9112-5.1-1**　RFC 9112 §5.1

> A server MUST reject, with a response status code of 400 (Bad Request), any received request message that contains whitespace between a header field name and colon.

**9112-5.1-2**　RFC 9112 §5.1

> A proxy MUST remove any such whitespace from a response message before forwarding the message downstream.

**9112-5.2-1**　RFC 9112 §5.2

> A sender MUST NOT generate a message that includes line folding (i.e., that has any field line value that contains a match to the obs-fold rule) unless the message is intended for packaging within the "message/http" media type.

**9112-5.2-2**　RFC 9112 §5.2

> A server that receives an obs-fold in a request message that is not within a "message/http" container MUST either reject the message by sending a 400 (Bad Request), preferably with a representation explaining that obsolete line folding is unacceptable, or replace each received obs-fold with one or more SP octets prior to interpreting the field value or forwarding the message downstream.

**9112-5.2-3**　RFC 9112 §5.2

> A proxy or gateway that receives an obs-fold in a response message that is not within a "message/http" container MUST either discard the message and replace it with a 502 (Bad Gateway) response, preferably with a representation explaining that unacceptable line folding was received, or replace each received obs-fold with one or more SP octets prior to interpreting the field value or forwarding the message downstream.

**9112-6.1-8**　RFC 9112 §6.1

> A server MAY reject a request that contains both Content-Length and Transfer-Encoding or process such a request in accordance with the Transfer-Encoding alone. Regardless, the server MUST close the connection after responding to such a request to avoid the potential attacks.

**9112-6.1-9**　RFC 9112 §6.1

> A server or client that receives an HTTP/1.0 message containing a Transfer-Encoding header field MUST treat the message as if the framing is faulty, even if a Content-Length is present, and close the connection after processing the message.

**9112-6.1-10**　RFC 9112 §6.1

> A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed).

**9112-6.2-1**　RFC 9112 §6.2

> A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field.

**9112-6.3-3**　RFC 9112 §6.3

> If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length. Such a message might indicate an attempt to perform request smuggling (Section 11.2) or response splitting (Section 11.1) and ought to be handled as an error. An intermediary that chooses to forward the message MUST first remove the received Content-Length field and process the Transfer-Encoding (as described below) prior to forwarding the message downstream.

**9112-6.3-6**　RFC 9112 §6.3

> If a Transfer-Encoding header field is present in a request and the chunked transfer coding is not the final encoding, the message body length cannot be determined reliably; the server MUST respond with the 400 (Bad Request) status code and then close the connection.

**9112-6.3-7**　RFC 9112 §6.3

> If a message is received without Transfer-Encoding and with an invalid Content-Length header field, then the message framing is invalid and the recipient MUST treat it as an unrecoverable error, unless the field value can be successfully parsed as a comma-separated list (Section 5.6.1 of \[HTTP\]), all values in the list are valid, and all values in the list are the same (in which case, the message is processed with that single value used as the Content-Length field value).

**9112-6.3-8**　RFC 9112 §6.3

> If the unrecoverable error is in a request message, the server MUST respond with a 400 (Bad Request) status code and then close the connection.

**9112-6.3-9**　RFC 9112 §6.3

> If it is in a response message received by a proxy, the proxy MUST close the connection to the server, discard the received response, and send a 502 (Bad Gateway) response to the client.

**9112-6.3-16**　RFC 9112 §6.3

> If the final response to the last request on a connection has been completely received and there remains additional data to read, a user agent MAY discard the remaining data or attempt to determine if that data belongs as part of the prior message body, which might be the case if the prior message's Content-Length value is incorrect. A client MUST NOT process, cache, or forward such extra data as a separate response, since such behavior would be vulnerable to cache poisoning.

**9112-7.1-2**　RFC 9112 §7.1

> Therefore, recipients MUST anticipate potentially large hexadecimal numerals and prevent parsing errors due to integer conversion overflows or precision loss due to integer representation.

**9112-9.2-3**　RFC 9112 §9.2

> If a client receives data on a connection that doesn't have outstanding requests, the client MUST NOT consider that data to be a valid response; the client SHOULD close the connection, since message delimitation is now ambiguous, unless the data consists only of one or more CRLF (which can be discarded per Section 2.2).

**9112-9.3-6**　RFC 9112 §9.3

> A server MUST read the entire request message body or close the connection after sending its response; otherwise, the remaining data on a persistent connection would be misinterpreted as the next request. Likewise, a client MUST read the entire response message body if it intends to reuse the same connection for a subsequent request.

**9112-11.1-1**　RFC 9112 §11.1

> A more effective mitigation is to prevent anything other than the server's core protocol libraries from sending a CR or LF within the header section, which means restricting the output of header fields to APIs that filter for bad octets and not allowing application servers to write directly to the protocol stream.

**9112-11.2-1**　RFC 9112 §11.2

> Request smuggling (\[Linhart\]) is a technique that exploits differences in protocol parsing among various recipients to hide additional requests (which might otherwise be blocked or disabled by policy) within an apparently harmless request. Like response splitting, request smuggling can lead to a variety of attacks on HTTP usage. This specification has introduced new requirements on request parsing, particularly with regard to message framing in Section 6.3, to reduce the effectiveness of request smuggling.

**9112-11.3-2**　RFC 9112 §11.3

> The "http" scheme provides no protection against accidental or malicious modification of messages.

</details>

### connection：连接管理

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-3.3-1 | RFC 9110 §3.3 Connections, Clients, and Servers | statement | any | 两侧 | 背景：client、server 是按连接分的角色。网关对连进来的客户端是 server，对上游代理是 client；本文件里原文写 server 的条款，适用于网关的入口一侧。 | — |
| 9110-3.3-3 | RFC 9110 §3.3 Connections, Clients, and Servers | MUST NOT | recipient | 入口 | 原文主语是 server（3.3 节的角色，即网关的入口一侧）。入口不能因为一条连接上先前的请求带过某个用户的凭据，就把后面不带凭据或带另一个用户凭据的请求算到同一个用户头上；例外只有连接是 secured 且专属于该 agent 的情形。 | R36、R41、R42 |
| 9110-3.7-1 | RFC 9110 §3.7 Intermediaries | statement | intermediary | 入口 | 背景：同一个中间人可以按请求切换角色。网关对绝对形式的请求是 proxy，CONNECT 成功之后是 tunnel。 | — |
| 9110-3.7-2 | RFC 9110 §3.7 Intermediaries | statement | any | 两侧 | 背景：术语。inbound 指朝源站方向，outbound 指朝 user agent 方向；后面条款里的 next inbound proxy 对网关来说就是上游代理。 | — |
| 9110-17.2-1 | RFC 9110 §17.2 Risks of Intermediaries | statement | intermediary | 上游 | 背景：中间人天然处在可以做中间人攻击的位置。上游代理看得到也改得了经过它的明文流量；网关不可信上游的前提与此一致。topic 里没有专门的安全一类，归在 connection。 | — |
| 9110-17.2-2 | RFC 9110 §17.2 Risks of Intermediaries | statement | intermediary | 上游 | 背景：中间人可信与否取决于运营它的人和策略，HTTP 本身解决不了。对上游说的话要靠协议之外的独立见证来核对。 | — |
| 9112-8-1 | RFC 9112 §8 Handling Incomplete Messages | MAY | recipient | 入口 | 原文主语是 server。入口收到不完整的请求（客户端中途取消或超时）时，可以先回一个错误响应再关闭连接；不回直接关也不违规。 | — |
| 9112-9.2-1 | RFC 9112 §9.2 Associating a Response to a Request | statement | any | 两侧 | 背景：HTTP/1.1 的请求和响应只靠同一条连接上的先后顺序对应。任何一侧的分帧判断出错都会让后面的响应错位，这是走私和响应拆分能成立的前提。 | — |
| 9112-9.2-2 | RFC 9112 §9.2 Associating a Response to a Request | MUST | client | 上游 | 网关在一条上游连接上同时有多个未应答的请求时，必须按发送顺序把响应对应到最早那个还没收到最终响应的请求；1xx 不算最终响应。 | — |
| 9112-9.3-1 | RFC 9112 §9.3 Persistence | SHOULD | any | 两侧 | 网关在入口和上游两侧都应当支持持久连接；HTTP/1.1 的消息默认连接保持。 | R02、R11、R13 |
| 9112-9.3-2 | RFC 9112 §9.3 Persistence | statement | recipient | 两侧 | 连接是否保持的判定顺序：最近一条消息里有 close 就不保持；否则 HTTP/1.1 保持；HTTP/1.0 只有带 keep-alive 且“接收方不是代理或者消息是响应”时才可以保持；其余关闭。网关在入口一侧是代理，所以客户端的 HTTP/1.0 请求即使带 keep-alive 也不保持；上游的 HTTP/1.0 响应带 keep-alive 时可以保持。 | R02、R34、R35 |
| 9112-9.3-3 | RFC 9112 §9.3 Persistence | MUST | client | 两侧 | 约束客户端：不支持持久连接就每个请求都带 close。网关对上游不复用连接时自己要照做；也用来解释客户端请求里的 Connection 头。 | R02 |
| 9112-9.3-4 | RFC 9112 §9.3 Persistence | MUST | sender | 入口 | 原文主语是 server。入口如果不让客户端复用连接，每个非 1xx 的响应都必须带 close。 | — |
| 9112-9.3-5 | RFC 9112 §9.3 Persistence | MAY | client | 两侧 | 在发出或收到 close 之前，客户端可以在同一条连接上继续发请求，包括收到 407 之后的重试；这是允许，客户端另开连接也合规。网关对上游连接的复用也以此为界。 | R11、R13、R32、R33、R36、R88 |
| 9112-9.3-7 | RFC 9112 §9.3 Persistence | MUST NOT | proxy | 入口 | 客户端的请求是 HTTP/1.0 时，入口回完响应就关闭连接，不理会它带的 keep-alive。 | — |
| 9112-9.3-8 | RFC 9112 §9.3 Persistence | statement | any | 两侧 | 连接要保持下去，上面的每条消息都得自带长度，不能靠关闭连接来定界。入口自己生成的 407、403、502 等响应，想让客户端在原连接上接着发请求，就要带 Content-Length 或用分块；上游一侧收到靠关闭定界的响应，那条上游连接不能复用。 | R32、R33、R88 |
| 9112-9.3.2-1 | RFC 9112 §9.3.2 Pipelining | MUST | recipient | 入口 | 原文主语是 server。客户端可以不等响应就在一条连接上连发请求，入口不能假定一次只来一个；响应必须按收到请求的顺序发回。并行处理只对全是安全方法的序列允许。 | — |
| 9112-9.4-1 | RFC 9112 §9.4 Concurrency | statement | client | 两侧 | 背景：规范不规定客户端的并发连接数上限，只鼓励保守。客户端并发时开几条代理连接都不违规；网关对上游开多少条连接同样没有硬性上限。 | R14、R15、R16 |
| 9112-9.4-2 | RFC 9112 §9.4 Concurrency | statement | any | 两侧 | 原文主语是 server。背景：收连接的一方可以拒绝它认为滥用的流量（例如单个客户端的连接过多）。入口可以限制每个客户端的连接数；上游也可能这样对待网关。 | R14、R15、R16 |
| 9112-9.5-1 | RFC 9112 §9.5 Failures and Timeouts | statement | any | 两侧 | 背景：空闲连接的超时多长、有没有，规范都不规定；入口和上游两侧的空闲超时由网关自己定，也不能假定上游的超时是多少。 | R90、R91 |
| 9112-9.5-2 | RFC 9112 §9.5 Failures and Timeouts | SHOULD | any | 两侧 | 网关因超时关闭连接时应当正常关闭（不是复位）；应当持续监视空闲连接上对方的关闭信号并及时关掉自己这一侧，连接池里的上游连接也一样。 | R90、R91 |
| 9112-9.5-4 | RFC 9112 §9.5 Failures and Timeouts | SHOULD | recipient | 入口 | 原文主语是 server。入口过载时应当靠传输层的流量控制顶住，而不是断开客户端连接、指望客户端重试。 | — |
| 9112-9.5-5 | RFC 9112 §9.5 Failures and Timeouts | SHOULD | client | 两侧 | 约束客户端：发正文的同时应当留意错误响应，看到对方不收正文并且要关连接，就应当停发并关闭自己这一侧。网关向上游转发正文时应当这样做；也用来解释客户端发带正文的 POST 遇到 407 时的行为。 | R20、R43 |
| 9112-9.6-1 | RFC 9112 §9.6 Tear-down | SHOULD | sender | 两侧 | 网关打算在某个响应之后关闭客户端连接（或在某个请求之后关闭上游连接）时，应当在那条消息里带 Connection: close。 | R02、R34、R35 |
| 9112-9.6-2 | RFC 9112 §9.6 Tear-down | MUST NOT | client | 两侧 | 约束客户端：发了 close 之后不能在这条连接上再发请求，读完最终响应必须关闭连接。网关向上游发了 close 时自己要遵守；也用来判断客户端的行为。 | R02 |
| 9112-9.6-3 | RFC 9112 §9.6 Tear-down | MUST | recipient | 入口 | 原文主语是 server。入口收到带 close 的请求：发完最终响应后必须主动开始关闭连接，应当在这个响应里带 close，这条连接上之后收到的请求一律不处理。 | R02 |
| 9112-9.6-4 | RFC 9112 §9.6 Tear-down | MUST | sender | 入口 | 原文主语是 server。入口自己在响应里发了 close（例如带 Connection: close 的 407），发完这个响应必须主动开始关闭连接，之后这条连接上收到的请求不处理。 | R34、R35 |
| 9112-9.6-5 | RFC 9112 §9.6 Tear-down | MUST | client | 两侧 | 约束客户端：收到带 close 的响应后不能在这条连接上再发请求，读完该响应就关闭连接。所以 407 带 close 时，合规的客户端只能换一条新连接重试；网关收到上游带 close 的响应后，那条上游连接也不能放回连接池。 | R32、R33、R34、R35 |
| 9112-9.6-6 | RFC 9112 §9.6 Tear-down | statement | sender | 入口 | 原文主语是 server。背景：发完响应立刻完全关闭 TCP 连接，客户端可能读不到最后那个响应（原文下一句解释了原因：客户端还在发数据时会引出 RST）。入口对正文没读完的请求回错误响应时要考虑这一点。 | R34、R35、R43 |
| 9112-9.6-7 | RFC 9112 §9.6 Tear-down | statement | sender | 入口 | 原文主语是 server。背景：通行的做法是分阶段关闭，先只关写的一侧，继续读到客户端也关闭或者确认最后的响应已被对方收到，再完全关闭。这是对惯例的描述，不是要求。 | R34、R35、R43 |
| 9112-9.6-8 | RFC 9112 §9.6 Tear-down | statement | any | 入口 | 入口不能把客户端的半关闭（收到 FIN）当作请求的结束，也不能据此认为客户端不要响应了而丢弃正在处理的请求。 | — |

<details>
<summary>原文（31 条）</summary>

**9110-3.3-1**　RFC 9110 §3.3

> The terms client and server refer only to the roles that these programs perform for a particular connection. The same program might act as a client on some connections and a server on others.

**9110-3.3-3**　RFC 9110 §3.3

> As a result, a server MUST NOT assume that two requests on the same connection are from the same user agent unless the connection is secured and specific to that agent.

**9110-3.7-1**　RFC 9110 §3.7

> In some cases, a single intermediary might act as an origin server, proxy, gateway, or tunnel, switching behavior based on the nature of each request.

**9110-3.7-2**　RFC 9110 §3.7

> The terms "inbound" and "outbound" are used to describe directional requirements in relation to the request route: inbound means "toward the origin server", whereas outbound means "toward the user agent".

**9110-17.2-1**　RFC 9110 §17.2

> HTTP intermediaries are inherently situated for on-path attacks.

**9110-17.2-2**　RFC 9110 §17.2

> Intermediaries are no more trustworthy than the people and policies under which they operate; HTTP cannot solve this problem.

**9112-8-1**　RFC 9112 §8

> A server that receives an incomplete request message, usually due to a canceled request or a triggered timeout exception, MAY send an error response prior to closing the connection.

**9112-9.2-1**　RFC 9112 §9.2

> HTTP/1.1 does not include a request identifier for associating a given request message with its corresponding one or more response messages. Hence, it relies on the order of response arrival to correspond exactly to the order in which requests are made on the same connection.

**9112-9.2-2**　RFC 9112 §9.2

> A client that has more than one outstanding request on a connection MUST maintain a list of outstanding requests in the order sent and MUST associate each received response message on that connection to the first outstanding request that has not yet received a final (non- 1xx) response.

**9112-9.3-1**　RFC 9112 §9.3

> HTTP/1.1 defaults to the use of "persistent connections", allowing multiple requests and responses to be carried over a single connection. HTTP implementations SHOULD support persistent connections.

**9112-9.3-2**　RFC 9112 §9.3

> A recipient determines whether a connection is persistent or not based on the protocol version and Connection header field (Section 7.6.1 of \[HTTP\]) in the most recently received message, if any: \* If the "close" connection option is present (Section 9.6), the connection will not persist after the current response; else, \* If the received protocol is HTTP/1.1 (or later), the connection will persist after the current response; else, \* If the received protocol is HTTP/1.0, the "keep-alive" connection option is present, either the recipient is not a proxy or the message is a response, and the recipient wishes to honor the HTTP/1.0 "keep-alive" mechanism, the connection will persist after the current response; otherwise, \* The connection will close after the current response.

**9112-9.3-3**　RFC 9112 §9.3

> A client that does not support persistent connections MUST send the "close" connection option in every request message.

**9112-9.3-4**　RFC 9112 §9.3

> A server that does not support persistent connections MUST send the "close" connection option in every response message that does not have a 1xx (Informational) status code.

**9112-9.3-5**　RFC 9112 §9.3

> A client MAY send additional requests on a persistent connection until it sends or receives a "close" connection option or receives an HTTP/1.0 response without a "keep-alive" connection option.

**9112-9.3-7**　RFC 9112 §9.3

> A proxy server MUST NOT maintain a persistent connection with an HTTP/1.0 client (see Appendix C.2.2 for information and discussion of the problems with the Keep-Alive header field implemented by many HTTP/1.0 clients).

**9112-9.3-8**　RFC 9112 §9.3

> In order to remain persistent, all messages on a connection need to have a self-defined message length (i.e., one not defined by closure of the connection), as described in Section 6.

**9112-9.3.2-1**　RFC 9112 §9.3.2

> A client that supports persistent connections MAY "pipeline" its requests (i.e., send multiple requests without waiting for each response). A server MAY process a sequence of pipelined requests in parallel if they all have safe methods (Section 9.2.1 of \[HTTP\]), but it MUST send the corresponding responses in the same order that the requests were received.

**9112-9.4-1**　RFC 9112 §9.4

> Previous revisions of HTTP gave a specific number of connections as a ceiling, but this was found to be impractical for many applications. As a result, this specification does not mandate a particular maximum number of connections but, instead, encourages clients to be conservative when opening multiple connections.

**9112-9.4-2**　RFC 9112 §9.4

> Note that a server might reject traffic that it deems abusive or characteristic of a denial-of-service attack, such as an excessive number of open connections from a single client.

**9112-9.5-1**　RFC 9112 §9.5

> The use of persistent connections places no requirements on the length (or existence) of this timeout for either the client or the server.

**9112-9.5-2**　RFC 9112 §9.5

> A client or server that wishes to time out SHOULD issue a graceful close on the connection. Implementations SHOULD constantly monitor open connections for a received closure signal and respond to it as appropriate, since prompt closure of both sides of a connection enables allocated system resources to be reclaimed.

**9112-9.5-4**　RFC 9112 §9.5

> A server SHOULD sustain persistent connections, when possible, and allow the underlying transport's flow-control mechanisms to resolve temporary overloads rather than terminate connections with the expectation that clients will retry.

**9112-9.5-5**　RFC 9112 §9.5

> A client sending a message body SHOULD monitor the network connection for an error response while it is transmitting the request. If the client sees a response that indicates the server does not wish to receive the message body and is closing the connection, the client SHOULD immediately cease transmitting the body and close its side of the connection.

**9112-9.6-1**　RFC 9112 §9.6

> The "close" connection option is defined as a signal that the sender will close this connection after completion of the response. A sender SHOULD send a Connection header field (Section 7.6.1 of \[HTTP\]) containing the "close" connection option when it intends to close a connection.

**9112-9.6-2**　RFC 9112 §9.6

> A client that sends a "close" connection option MUST NOT send further requests on that connection (after the one containing the "close") and MUST close the connection after reading the final response message corresponding to this request.

**9112-9.6-3**　RFC 9112 §9.6

> A server that receives a "close" connection option MUST initiate closure of the connection (see below) after it sends the final response to the request that contained the "close" connection option. The server SHOULD send a "close" connection option in its final response on that connection. The server MUST NOT process any further requests received on that connection.

**9112-9.6-4**　RFC 9112 §9.6

> A server that sends a "close" connection option MUST initiate closure of the connection (see below) after it sends the response containing the "close" connection option. The server MUST NOT process any further requests received on that connection.

**9112-9.6-5**　RFC 9112 §9.6

> A client that receives a "close" connection option MUST cease sending requests on that connection and close the connection after reading the response message containing the "close" connection option; if additional pipelined requests had been sent on the connection, the client SHOULD NOT assume that they will be processed by the server.

**9112-9.6-6**　RFC 9112 §9.6

> If a server performs an immediate close of a TCP connection, there is a significant risk that the client will not be able to read the last HTTP response.

**9112-9.6-7**　RFC 9112 §9.6

> To avoid the TCP reset problem, servers typically close a connection in stages. First, the server performs a half-close by closing only the write side of the read/write connection. The server then continues to read from the connection until it receives a corresponding close by the client, or until the server is reasonably certain that its own TCP stack has received the client's acknowledgement of the packet(s) containing the server's last response. Finally, the server fully closes the connection.

**9112-9.6-8**　RFC 9112 §9.6

> Note that a TCP connection that is half-closed by the client does not delimit a request message, nor does it imply that the client is no longer interested in a response.

</details>

### retry：重试

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-9.2.2-1 | RFC 9110 §9.2.2 Idempotent Methods | statement | any | 两侧 | 幂等方法是 PUT、DELETE 和安全方法（安全方法的清单在 9.2.1 节，本文件没有摘）。POST 和 CONNECT 都不在这句话列出的范围里。 | R92、R93、R94、R95 |
| 9110-9.2.2-2 | RFC 9110 §9.2.2 Idempotent Methods | statement | client | 两侧 | 背景：在读到响应之前通信失败，幂等请求可以自动重发。客户端在连接被关之后重发 GET 属于这种情况，入口会看到同一个请求到达两次。 | R90、R91、R92、R94、R96、R97、R98、R99、R101 |
| 9110-9.2.2-3 | RFC 9110 §9.2.2 Idempotent Methods | SHOULD NOT | client | 两侧 | 客户端不应自动重试非幂等方法的请求，除非知道语义其实幂等，或者能察觉原请求从未被执行。用来判断客户端重发 POST 的行为；网关作为上游的客户端时同样受约束，作为代理时另有更严的 9110-9.2.2-5。 | R93、R95 |
| 9110-9.2.2-4 | RFC 9110 §9.2.2 Idempotent Methods | statement | client | 客户端 | 背景：有的客户端在收到任何响应之前连接就被关时会重发 POST，用的是空闲的持久连接时尤其如此。所以入口关闭空闲连接的时机会影响 POST 被执行几次。 | R90、R93、R95 |
| 9110-9.2.2-5 | RFC 9110 §9.2.2 Idempotent Methods | MUST NOT | proxy | 入口 | 网关作为代理，转发 POST 等非幂等请求失败后，不得自动重发，也就不得自动换一个上游再发。CONNECT 不在本节列出的幂等方法里；网关向上游代理发 CONNECT 失败后换上游重发算不算“重试非幂等请求”，条款没有单独说明，未验证，要在设计决定里写明取哪种读法。 | R93、R95、R100 |
| 9110-9.2.2-6 | RFC 9110 §9.2.2 Idempotent Methods | SHOULD NOT | client | 两侧 | 自动重试失败后不应再自动重试：客户端对同一个请求最多自动重发一次；网关作为上游的客户端做的自动重试也以一次为限。 | R92、R94、R96、R97、R100 |
| 9110-15.5.9-1 | RFC 9110 §15.5.9 408 Request Timeout | MAY | client | 两侧 | 408 表示在愿意等的时间内没有收到完整的请求，入口等请求超时时可以用它。收到 408 的客户端可以（MAY）把在途的请求重发一遍；HTTP/1.1 下请求的边界已经丢了，原连接不能再用，重发走新连接。原文没有要求入口在关闭空闲连接之前发 408。 | R90 |
| 9112-9.3.1-1 | RFC 9112 §9.3.1 Retrying Requests | statement | any | 两侧 | 背景：连接随时可能被关闭，实现要准备好从中恢复；什么情况下可以自动重试不在这里规定，在 RFC 9110 的 9.2.2 节。 | R90、R91、R92、R93、R94、R95、R96、R97、R98、R99 |
| 9112-9.3.2-2 | RFC 9112 §9.3.2 Pipelining | MAY | intermediary | 入口 | 只说管线化转发的中间方：上游连接在收到响应之前断开时，未应答的请求全是幂等方法才可以由网关重试；否则应当把已收到的响应转给客户端，然后关闭客户端连接，让客户端自己恢复。网关不向上游做管线化时，这条不直接适用。 | R92、R93 |
| 9112-9.3.2-3 | RFC 9112 §9.3.2 Pipelining | SHOULD | client | 客户端 | 背景：做管线化的客户端，在连接关闭而响应没收全时，应当重试没有得到应答的请求。入口关闭连接之后同一个请求再次到达，可能出于这一条；不做管线化的客户端不受它约束。 | — |
| 9112-9.5-3 | RFC 9112 §9.5 Failures and Timeouts | MAY | any | 两侧 | 任何一方随时可以关闭连接，所以“新请求刚发出、对方正好关掉空闲连接”的竞争必然存在。网关在复用的上游连接上发请求要处理这种情况；客户端在复用的代理连接上也会遇到。 | R90、R91、R92、R93、R98 |

<details>
<summary>原文（11 条）</summary>

**9110-9.2.2-1**　RFC 9110 §9.2.2

> Of the request methods defined by this specification, PUT, DELETE, and safe request methods are idempotent.

**9110-9.2.2-2**　RFC 9110 §9.2.2

> Idempotent methods are distinguished because the request can be repeated automatically if a communication failure occurs before the client is able to read the server's response.

**9110-9.2.2-3**　RFC 9110 §9.2.2

> A client SHOULD NOT automatically retry a request with a non- idempotent method unless it has some means to know that the request semantics are actually idempotent, regardless of the method, or some means to detect that the original request was never applied.

**9110-9.2.2-4**　RFC 9110 §9.2.2

> Some clients take a riskier approach and attempt to guess when an automatic retry is possible. For example, a client might automatically retry a POST request if the underlying transport connection closed before any part of a response is received, particularly if an idle persistent connection was used.

**9110-9.2.2-5**　RFC 9110 §9.2.2

> A proxy MUST NOT automatically retry non-idempotent requests.

**9110-9.2.2-6**　RFC 9110 §9.2.2

> A client SHOULD NOT automatically retry a failed automatic retry.

**9110-15.5.9-1**　RFC 9110 §15.5.9

> The 408 (Request Timeout) status code indicates that the server did not receive a complete request message within the time that it was prepared to wait. If the client has an outstanding request in transit, it MAY repeat that request. If the current connection is not usable (e.g., as it would be in HTTP/1.1 because request delimitation is lost), a new connection will be used.

**9112-9.3.1-1**　RFC 9112 §9.3.1

> Connections can be closed at any time, with or without intention. Implementations ought to anticipate the need to recover from asynchronous close events. The conditions under which a client can automatically retry a sequence of outstanding requests are defined in Section 9.2.2 of \[HTTP\].

**9112-9.3.2-2**　RFC 9112 §9.3.2

> An intermediary that receives pipelined requests MAY pipeline those requests when forwarding them inbound, since it can rely on the outbound user agent(s) to determine what requests can be safely pipelined. If the inbound connection fails before receiving a response, the pipelining intermediary MAY attempt to retry a sequence of requests that have yet to receive a response if the requests all have idempotent methods; otherwise, the pipelining intermediary SHOULD forward any received responses and then close the corresponding outbound connection(s) so that the outbound user agent(s) can recover accordingly.

**9112-9.3.2-3**　RFC 9112 §9.3.2

> A client that pipelines requests SHOULD retry unanswered requests if the connection closes before it receives all of the corresponding responses.

**9112-9.5-3**　RFC 9112 §9.5

> A client, server, or proxy MAY close the transport connection at any time. For example, a client might have started to send a new request at the same time that the server has decided to close the "idle" connection.

</details>

### expect：Expect 与 100-continue

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-10.1.1-1 | RFC 9110 §10.1.1 Expect | statement | client | 客户端 | 背景：客户端发 100-continue 是想先知道请求会不会被拒绝再发内容；原文举的场景之一正是“第一次、没有验证过的凭据”。入口要认证时，对带 100-continue 的请求可以不等正文就回 407。 | R20、R43 |
| 9110-10.1.1-2 | RFC 9110 §10.1.1 Expect | MUST NOT | client | 两侧 | 没有内容的请求不得带 100-continue。用来判断客户端行为；网关自己向上游发请求时也不能给没有内容的请求加上它。 | R20 |
| 9110-10.1.1-3 | RFC 9110 §10.1.1 Expect | MUST | client | 客户端 | 客户端要等 100 再发内容，就必须发 Expect: 100-continue。反过来，没带这个头的请求，入口不必发 100，可以认为内容会直接跟上。 | R20 |
| 9110-10.1.1-4 | RFC 9110 §10.1.1 Expect | MAY | client | 客户端 | 发了 100-continue 的客户端可以不等响应就开始发内容。入口不能假定回 100 之前一定收不到正文。 | R20、R43 |
| 9110-10.1.1-5 | RFC 9110 §10.1.1 Expect | SHOULD NOT | client | 客户端 | 客户端不应无限期地等 100。网关即使不发 100，合规的客户端过一会儿也会开始发内容。 | R20 |
| 9110-10.1.1-6 | RFC 9110 §10.1.1 Expect | SHOULD | client | 两侧 | 收到 417 的客户端应当去掉 100-continue 再发一次。入口或上游回 417，会引出同一个请求的第二次到达。 | R20 |
| 9110-10.1.1-7 | RFC 9110 §10.1.1 Expect | MUST | recipient | 入口 | 原文主语是 server。HTTP/1.0 请求里的 100-continue 必须忽略：入口不对它发 100。 | R20 |
| 9110-10.1.1-8 | RFC 9110 §10.1.1 Expect | MAY | recipient | 入口 | 原文主语是 server。已经收到部分或全部内容，或者分帧表明没有内容时，可以不发 100。 | R20 |
| 9110-10.1.1-9 | RFC 9110 §10.1.1 Expect | SHOULD | sender | 入口 | 原文主语是 server。入口在读完请求内容之前就回最终状态码（例如对带正文的 POST 回 407）时，应当表明接下来是关连接还是继续读内容：要么带 Connection: close，要么把剩下的正文读掉之后才能在这条连接上处理下一个请求。 | R32、R34、R43 |
| 9110-10.1.1-10 | RFC 9110 §10.1.1 Expect | MUST | proxy | 入口 | 网关作为代理收到带 100-continue 且有内容要跟来的 HTTP/1.1 请求，只有两条路：仅凭方法、目标 URI 和头字段就能定最终状态码的（如 407），立即回；否则把请求行和头部分先转给下一跳。不能压着头不转、等正文收齐。 | R20、R43 |
| 9110-10.1.1-11 | RFC 9110 §10.1.1 Expect | MAY | proxy | 入口 | 只有在网关认为下一跳只支持 HTTP/1.0 时，才可以自己生成 100 让客户端开始发内容。条款没有给别的情况下代理自发 100 的许可。 | R20 |
| 9110-10.1.1-12 | RFC 9110 §10.1.1 Expect | MUST | sender | 入口 | 原文主语是 server。网关按 9110-10.1.1-11 自己发了 100 之后，收完并处理完请求内容，最终必须给出一个最终状态码，连接提前关闭的情况除外。这一句在原文里排在 9110-10.1.1-8 和 -9 之间。 | R20 |
| 9110-15.2-1 | RFC 9110 §15.2 Informational 1xx | MUST NOT | sender | 入口 | 原文主语是 server。入口不得向 HTTP/1.0 的客户端发 1xx 响应，包括转发上游或源站来的 100。 | R20 |
| 9110-15.2-2 | RFC 9110 §15.2 Informational 1xx | MUST | client | 上游 | 网关作为上游的客户端，必须能在最终响应之前解析一个或多个 1xx 响应，哪怕没有请求过；对 CONNECT 的应答也不例外。 | R20 |
| 9110-15.2-3 | RFC 9110 §15.2 Informational 1xx | MUST | proxy | 入口 | 网关转发明文请求时，下一跳回的 1xx 必须转给客户端；例外只有 1xx 是网关自己要来的（例如网关自己加了 Expect: 100-continue）。HTTP/1.0 客户端另受 9110-15.2-1 限制。 | R20 |

<details>
<summary>原文（15 条）</summary>

**9110-10.1.1-1**　RFC 9110 §10.1.1

> A "100-continue" expectation informs recipients that the client is about to send (presumably large) content in this request and wishes to receive a 100 (Continue) interim response if the method, target URI, and header fields are not sufficient to cause an immediate success, redirect, or error response. This allows the client to wait for an indication that it is worthwhile to send the content before actually doing so, which can improve efficiency when the data is huge or when the client anticipates that an error is likely (e.g., when sending a state-changing method, for the first time, without previously verified authentication credentials).

**9110-10.1.1-2**　RFC 9110 §10.1.1

> A client MUST NOT generate a 100-continue expectation in a request that does not include content.

**9110-10.1.1-3**　RFC 9110 §10.1.1

> A client that will wait for a 100 (Continue) response before sending the request content MUST send an Expect header field containing a 100-continue expectation.

**9110-10.1.1-4**　RFC 9110 §10.1.1

> A client that sends a 100-continue expectation is not required to wait for any specific length of time; such a client MAY proceed to send the content even if it has not yet received a response.

**9110-10.1.1-5**　RFC 9110 §10.1.1

> Furthermore, since 100 (Continue) responses cannot be sent through an HTTP/1.0 intermediary, such a client SHOULD NOT wait for an indefinite period before sending the content.

**9110-10.1.1-6**　RFC 9110 §10.1.1

> A client that receives a 417 (Expectation Failed) status code in response to a request containing a 100-continue expectation SHOULD repeat that request without a 100-continue expectation, since the 417 response merely indicates that the response chain does not support expectations (e.g., it passes through an HTTP/1.0 server).

**9110-10.1.1-7**　RFC 9110 §10.1.1

> A server that receives a 100-continue expectation in an HTTP/1.0 request MUST ignore that expectation.

**9110-10.1.1-8**　RFC 9110 §10.1.1

> A server MAY omit sending a 100 (Continue) response if it has already received some or all of the content for the corresponding request, or if the framing indicates that there is no content.

**9110-10.1.1-9**　RFC 9110 §10.1.1

> A server that responds with a final status code before reading the entire request content SHOULD indicate whether it intends to close the connection (e.g., see Section 9.6 of \[HTTP/1.1\]) or continue reading the request content.

**9110-10.1.1-10**　RFC 9110 §10.1.1

> Upon receiving an HTTP/1.1 (or later) request that has a method, target URI, and complete header section that contains a 100-continue expectation and indicates a request content will follow, a proxy MUST either: \* send an immediate response with a final status code, if that status can be determined by examining just the method, target URI, and header fields, or \* forward the request toward the origin server by sending a corresponding request-line and header section to the next inbound server.

**9110-10.1.1-11**　RFC 9110 §10.1.1

> If the proxy believes (from configuration or past interaction) that the next inbound server only supports HTTP/1.0, the proxy MAY generate an immediate 100 (Continue) response to encourage the client to begin sending the content.

**9110-10.1.1-12**　RFC 9110 §10.1.1

> A server that sends a 100 (Continue) response MUST ultimately send a final status code, once it receives and processes the request content, unless the connection is closed prematurely.

**9110-15.2-1**　RFC 9110 §15.2

> Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client.

**9110-15.2-2**　RFC 9110 §15.2

> A client MUST be able to parse one or more 1xx responses received prior to a final response, even if the client does not expect one.

**9110-15.2-3**　RFC 9110 §15.2

> A proxy MUST forward 1xx responses unless the proxy itself requested the generation of the 1xx response.

</details>

### status：状态码

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-10.2.3-1 | RFC 9110 §10.2.3 Retry-After | statement | sender | 入口 | 背景：503 带 Retry-After 表示预计多久不可用。条款没有要求客户端到时自动重试。 | R83 |
| 9110-15-1 | RFC 9110 §15 Status Codes | MUST | client | 两侧 | 不认识的状态码按首位数字归类、当作该类的 x00 处理。网关对上游回的陌生状态码照此办（陌生的 2xx 回给 CONNECT 也算成功，见 9110-9.3.6-5）；客户端对入口回的状态码也应如此。 | R80、R82、R83 |
| 9110-15-2 | RFC 9110 §15 Status Codes | SHOULD | client | 上游 | 上游回的状态码不在 100 到 599 之内时，网关应当按 5xx 处理。 | — |
| 9110-15.3-1 | RFC 9110 §15.3 Successful 2xx | statement | sender | 两侧 | 背景：2xx 类的定义。9.3.6 说的是“任何 2xx”都表示隧道建成，不只是 200。 | R84、R85 |
| 9110-15.5-1 | RFC 9110 §15.5 Client Error 4xx | SHOULD | sender | 入口 | 原文主语是 server。入口自己生成 4xx（400、403、407）时应当带一段说明错误的内容，并说明是暂时的还是永久的。对 CONNECT 回 4xx 也是普通的 HTTP 响应，可以有内容。 | R45、R46、R82、R86 |
| 9110-15.5.1-1 | RFC 9110 §15.5.1 400 Bad Request | statement | sender | 入口 | 背景：400 的含义，涵盖请求语法错误、分帧无效、带欺骗性的请求路由。入口拒绝畸形请求（含 9110-9.3.6-3 的无效端口）用它。 | R03 |
| 9110-15.5.4-1 | RFC 9110 §15.5.4 403 Forbidden | SHOULD NOT | client | 客户端 | 入口回 403 的含义：请求里带了凭据的话，表示凭据不足以获得访问。合规的客户端不应拿同一份凭据自动重发；这是 403 与 407 在客户端行为上的区别。 | R50、R51、R82、R86 |
| 9110-15.5.4-2 | RFC 9110 §15.5.4 403 Forbidden | MAY | client | 客户端 | 背景：收到 403 后客户端可以换凭据再试；403 也可能与凭据无关。 | R50、R51 |
| 9110-15.5.20-1 | RFC 9110 §15.5.20 421 Misdirected Request | MUST NOT | proxy | 入口 | 网关作为代理不得自己生成 421。 | — |
| 9110-15.6-1 | RFC 9110 §15.6 Server Error 5xx | SHOULD | sender | 入口 | 原文主语是 server。入口自己生成 5xx（502、503、504）时应当带一段说明错误的内容，并说明是暂时的还是永久的；这段内容客户端给不给调用方看要靠测量。 | R80、R81、R83 |
| 9110-15.6.3-1 | RFC 9110 §15.6.3 502 Bad Gateway | statement | proxy | 入口 | 502 的定义是“从 inbound 服务器收到无效响应”。上游代理或源站回了无法解析的应答时，入口回 502；上游连不上、被拒绝等情况不在这句话的字面范围里。 | R80、R81 |
| 9110-15.6.4-1 | RFC 9110 §15.6.4 503 Service Unavailable | MAY | sender | 入口 | 503 表示暂时过载或维护，过一段时间可能恢复；可以带 Retry-After 建议等多久。入口在没有可用上游这类暂时状况下可以用它。 | R83 |
| 9110-15.6.4-2 | RFC 9110 §15.6.4 503 Service Unavailable | statement | sender | 入口 | 背景：过载时不一定要回 503，直接拒绝连接也可以。 | R83 |
| 9110-15.6.5-1 | RFC 9110 §15.6.5 504 Gateway Timeout | statement | proxy | 入口 | 504 的定义是“没有及时收到上游服务器的响应”。网关等上游代理或经上游等源站超时，回 504，与 502 区分开。 | R80、R81 |
| 9112-2.2-8 | RFC 9112 §2.2 Message Parsing | SHOULD | recipient | 入口 | 原文主语是 server。入口端口同时听 HTTP 和 SOCKS5，所以适用的是后半句：按首字节判为 HTTP 之后，收到不合语法的字节应当回 400 并关闭连接。 | R23 |
| 9112-3-2 | RFC 9112 §3 Request Line | MUST | recipient | 入口 | 原文主语是 server。入口对请求目标设长度上限时，超限的请求回 414，不用别的状态码。 | — |
| 9112-3-4 | RFC 9112 §3 Request Line | SHOULD | recipient | 入口 | 原文主语是 server。入口给方法名设长度上限时，超过它实现的任何方法的长度，应当回 501。与 9112-3-2（请求目标超长回 414）是相邻的两句。 | — |
| 9112-4-1 | RFC 9112 §4 Status Line | SHOULD | client | 两侧 | 网关解析上游的响应（包括对 CONNECT 的应答）只看状态码，不看原因短语；网关自己给客户端的错误信息也不能只放在原因短语里，客户端可以忽略它。 | R80、R82、R86 |
| 9112-4-2 | RFC 9112 §4 Status Line | MUST | sender | 入口 | 原文主语是 server。网关自己生成的状态行（407、502、对 CONNECT 的 200 等），状态码后面的空格不能省，即使不写原因短语。 | — |

<details>
<summary>原文（19 条）</summary>

**9110-10.2.3-1**　RFC 9110 §10.2.3

> When sent with a 503 (Service Unavailable) response, Retry-After indicates how long the service is expected to be unavailable to the client.

**9110-15-1**　RFC 9110 §15

> However, a client MUST understand the class of any status code, as indicated by the first digit, and treat an unrecognized status code as being equivalent to the x00 status code of that class.

**9110-15-2**　RFC 9110 §15

> A client that receives a response with an invalid status code SHOULD process the response as if it had a 5xx (Server Error) status code.

**9110-15.3-1**　RFC 9110 §15.3

> The 2xx (Successful) class of status code indicates that the client's request was successfully received, understood, and accepted.

**9110-15.5-1**　RFC 9110 §15.5

> Except when responding to a HEAD request, the server SHOULD send a representation containing an explanation of the error situation, and whether it is a temporary or permanent condition.

**9110-15.5.1-1**　RFC 9110 §15.5.1

> The 400 (Bad Request) status code indicates that the server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid request message framing, or deceptive request routing).

**9110-15.5.4-1**　RFC 9110 §15.5.4

> If authentication credentials were provided in the request, the server considers them insufficient to grant access. The client SHOULD NOT automatically repeat the request with the same credentials.

**9110-15.5.4-2**　RFC 9110 §15.5.4

> The client MAY repeat the request with new or different credentials. However, a request might be forbidden for reasons unrelated to the credentials.

**9110-15.5.20-1**　RFC 9110 §15.5.20

> A proxy MUST NOT generate a 421 response.

**9110-15.6-1**　RFC 9110 §15.6

> Except when responding to a HEAD request, the server SHOULD send a representation containing an explanation of the error situation, and whether it is a temporary or permanent condition.

**9110-15.6.3-1**　RFC 9110 §15.6.3

> The 502 (Bad Gateway) status code indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request.

**9110-15.6.4-1**　RFC 9110 §15.6.4

> The 503 (Service Unavailable) status code indicates that the server is currently unable to handle the request due to a temporary overload or scheduled maintenance, which will likely be alleviated after some delay. The server MAY send a Retry-After header field (Section 10.2.3) to suggest an appropriate amount of time for the client to wait before retrying the request.

**9110-15.6.4-2**　RFC 9110 §15.6.4

> \*Note:\* The existence of the 503 status code does not imply that a server has to use it when becoming overloaded. Some servers might simply refuse the connection.

**9110-15.6.5-1**　RFC 9110 §15.6.5

> The 504 (Gateway Timeout) status code indicates that the server, while acting as a gateway or proxy, did not receive a timely response from an upstream server it needed to access in order to complete the request.

**9112-2.2-8**　RFC 9112 §2.2

> When a server listening only for HTTP request messages, or processing what appears from the start-line to be an HTTP request message, receives a sequence of octets that does not match the HTTP-message grammar aside from the robustness exceptions listed above, the server SHOULD respond with a 400 (Bad Request) response and close the connection.

**9112-3-2**　RFC 9112 §3

> A server that receives a request- target longer than any URI it wishes to parse MUST respond with a 414 (URI Too Long) status code (see Section 15.5.15 of \[HTTP\]).

**9112-3-4**　RFC 9112 §3

> A server that receives a method longer than any that it implements SHOULD respond with a 501 (Not Implemented) status code.

**9112-4-1**　RFC 9112 §4

> A client SHOULD ignore the reason-phrase content because it is not a reliable channel for information (it might be translated for a given locale, overwritten by intermediaries, or discarded when the message is forwarded via other versions of HTTP).

**9112-4-2**　RFC 9112 §4

> A server MUST send the space that separates the status-code from the reason-phrase even when the reason-phrase is absent (i.e., the status-line would end with the space).

</details>

### socks-negotiation：SOCKS5 方法协商

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 1928-3-1 | RFC 1928 §3 Procedure for TCP-based clients | statement | any | 入口 | 背景：1080 只是惯例（conventionally），条款没有要求 SOCKS 服务必须在这个端口上；入口和 HTTP 代理共用一个端口不与这句冲突。 | — |
| 1928-3-2 | RFC 1928 §3 Procedure for TCP-based clients | statement | any | 两侧 | 三个阶段的顺序是固定的：方法协商、所选方法的认证、请求。入口按这个顺序读，上游一侧按这个顺序写；认证没完成之前不该出现请求。 | R23、R110、R111 |
| 1928-3-3 | RFC 1928 §3 Procedure for TCP-based clients | statement | any | 两侧 | 背景：读报文图的约定。图里第二行的数字是字段的字节数，X'hh' 是固定取值；写 Variable 的格子（DST.ADDR、BND.ADDR 等）长度可变，由相关的长度字节或类型字段（ATYP）决定。下面引用报文图的条款都按这个约定读。 | — |
| 1928-3-4 | RFC 1928 §3 Procedure for TCP-based clients | statement | client | 两侧 | 方法协商报文是 VER、NMETHODS 各 1 字节，后跟 1 到 255 字节的 METHODS。入口要读满 NMETHODS 个字节再应答；图里 METHODS 的长度从 1 起，NMETHODS 为 0 的报文不在图给的范围内（条款没说服务端该怎么应对）。上游一侧网关自己发这个报文。 | R23、R110、R111 |
| 1928-3-5 | RFC 1928 §3 Procedure for TCP-based clients | statement | client | 两侧 | 连接上的第一个字节是 X'05'：入口按首字节分流时，这就是 SOCKS5 的判据。上游一侧网关发出的第一个字节也是它。 | R23 |
| 1928-3-6 | RFC 1928 §3 Procedure for TCP-based clients | statement | proxy | 两侧 | 原文的 server 是 SOCKS 服务端。入口只能从客户端列出的方法里选一个，应答是 VER、METHOD 两个字节。上游一侧：上游选了网关没列出的方法，就不符合这句，网关不该按那个方法继续。 | R110、R111、R118 |
| 1928-3-7 | RFC 1928 §3 Procedure for TCP-based clients | MUST | client | 两侧 | MUST 约束的是客户端。上游一侧：网关收到 X'FF' 必须关掉这条连接，不能在上面重试。入口：客户端列的方法都不能接受时回 X'05' X'FF'；之后关连接是客户端的义务，条款没有规定服务端要不要主动关。 | R119 |
| 1928-3-8 | RFC 1928 §3 Procedure for TCP-based clients | statement | any | 两侧 | 方法编号：X'00' 无认证，X'02' 用户名密码（RFC 1929），X'FF' 表示没有可接受的方法。入口要用代理用户名传会话参数时只能选 X'02'；客户端没列 X'02' 就拿不到用户名。 | R110、R111、R118、R119 |

<details>
<summary>原文（8 条）</summary>

**1928-3-1**　RFC 1928 §3

> The SOCKS service is conventionally located on TCP port 1080.

**1928-3-2**　RFC 1928 §3

> If the connection request succeeds, the client enters a negotiation for the authentication method to be used, authenticates with the chosen method, then sends a relay request. The SOCKS server evaluates the request, and either establishes the appropriate connection or denies it.

**1928-3-3**　RFC 1928 §3

> Unless otherwise noted, the decimal numbers appearing in packet- format diagrams represent the length of the corresponding field, in octets. Where a given octet must take on a specific value, the syntax X'hh' is used to denote the value of the single octet in that field. When the word 'Variable' is used, it indicates that the corresponding field has a variable length defined either by an associated (one or two octet) length field, or by a data type field.

**1928-3-4**　RFC 1928 §3

> The client connects to the server, and sends a version identifier/method selection message: +----+----------+----------+ \|VER \| NMETHODS \| METHODS \| +----+----------+----------+ \| 1 \| 1 \| 1 to 255 \| +----+----------+----------+

**1928-3-5**　RFC 1928 §3

> The VER field is set to X'05' for this version of the protocol. The NMETHODS field contains the number of method identifier octets that appear in the METHODS field.

**1928-3-6**　RFC 1928 §3

> The server selects from one of the methods given in METHODS, and sends a METHOD selection message: +----+--------+ \|VER \| METHOD \| +----+--------+ \| 1 \| 1 \| +----+--------+

**1928-3-7**　RFC 1928 §3

> If the selected METHOD is X'FF', none of the methods listed by the client are acceptable, and the client MUST close the connection.

**1928-3-8**　RFC 1928 §3

> The values currently defined for METHOD are: o X'00' NO AUTHENTICATION REQUIRED o X'01' GSSAPI o X'02' USERNAME/PASSWORD o X'03' to X'7F' IANA ASSIGNED o X'80' to X'FE' RESERVED FOR PRIVATE METHODS o X'FF' NO ACCEPTABLE METHODS

</details>

### socks-auth：SOCKS5 用户名密码认证

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 1928-3-9 | RFC 1928 §3 Procedure for TCP-based clients | statement | any | 两侧 | 背景：选定方法之后是该方法自己的子协商，定义在别的文档里；用户名密码方法的子协商在 RFC 1929。 | R117 |
| 1928-3-10 | RFC 1928 §3 Procedure for TCP-based clients | MUST | any | 两侧 | 同一句里有两级要求：GSSAPI 是 MUST，用户名密码是 SHOULD。网关只做无认证和用户名密码、不做 GSSAPI 的话，按这句的字面不算 compliant implementation，这一点要如实写进文档，不能声称完全符合 RFC 1928。 | R110、R111 |
| 1928-8-1 | RFC 1928 §8 Security Considerations | statement | any | 两侧 | 背景：安全性取决于协商出来的认证和封装方法。网关支持的两种方法（无认证、用户名密码）都不带封装，SOCKS5 这一层不提供机密性和完整性。 | R110、R111 |
| 1929-1-1 | RFC 1929 §1 Introduction | statement | any | 两侧 | 背景：本文定义的是 RFC 1928 方法 X'02' 对应的子协商。 | R117 |
| 1929-1-2 | RFC 1929 §1 Introduction | statement | any | 两侧 | 背景：读报文图的约定。1929-2-1 的图里 UNAME、PASSWD 下面的“1 to 255”是这两个字段的字节数范围。 | R128、R129、R131 |
| 1929-2-1 | RFC 1929 §2 Initial negotiation | statement | client | 两侧 | 认证请求是 VER、ULEN、UNAME、PLEN、PASSWD。图里 UNAME 和 PASSWD 的长度都是 1 到 255 字节：长度字段只有一个字节，超过 255 字节的用户名或密码无法表示；按图的字面，长度为 0 的用户名和密码也不在范围内。入口放在用户名里的会话参数因此不能超过 255 字节；入口收到 ULEN 或 PLEN 为 0 时是拒绝还是接受，条款没有规定，要自己定并写明。上游一侧：凭据超长或为空时不能照图发出，应在配置时报错。 | R117、R125、R126、R127、R128、R129、R130、R131、R132 |
| 1929-2-2 | RFC 1929 §2 Initial negotiation | statement | client | 两侧 | 子协商的版本字节是 X'01'，不是 SOCKS 的 X'05'。入口按 X'01' 校验，上游一侧按 X'01' 发送。 | R117 |
| 1929-2-3 | RFC 1929 §2 Initial negotiation | statement | client | 两侧 | 条款没有规定 UNAME、PASSWD 的字符集或编码，也没有保留任何字节：冒号、@、空格、非 ASCII 字节都可以出现。入口按字节原样取用户名再解析会话参数，不做转码；与 Basic 不同，这里用户名可以含冒号。 | R125、R126、R127、R130、R132 |
| 1929-2-4 | RFC 1929 §2 Initial negotiation | statement | proxy | 两侧 | 原文的 server 是 SOCKS 服务端。入口核对之后回 VER、STATUS 两个字节；上游一侧读两个字节。 | R117、R120 |
| 1929-2-5 | RFC 1929 §2 Initial negotiation | MUST | proxy | 两侧 | STATUS 只分 X'00'（成功）和非零（失败），没有更细的原因码。入口认证失败时回非零的 STATUS 之后必须关连接，不能让客户端在同一条连接上重试。上游一侧：收到非零的 STATUS 就当这条连接已经作废。 | R120 |
| 1929-3-1 | RFC 1929 §3 Security Considerations | statement | any | 两侧 | 原文是小写的 not recommended。用户名和密码在这个子协商里是明文：客户端到入口、网关到上游这两段在不可信的网络上都能被窃听到凭据。条款只是不建议，没有禁止；文档里要如实写明这一点。 | R117 |

<details>
<summary>原文（11 条）</summary>

**1928-3-9**　RFC 1928 §3

> The client and server then enter a method-specific sub-negotiation. Descriptions of the method-dependent sub-negotiations appear in separate memos.

**1928-3-10**　RFC 1928 §3

> Compliant implementations MUST support GSSAPI and SHOULD support USERNAME/PASSWORD authentication methods.

**1928-8-1**　RFC 1928 §8

> The security of such traversal is highly dependent on the particular authentication and encapsulation methods provided in a particular implementation, and selected during negotiation between SOCKS client and SOCKS server. Careful consideration should be given by the administrator to the selection of authentication methods.

**1929-1-1**　RFC 1929 §1

> This document describes one of those protocols, as it fits into the SOCKS Version 5 authentication "subnegotiation".

**1929-1-2**　RFC 1929 §1

> Unless otherwise noted, the decimal numbers appearing in packet- format diagrams represent the length of the corresponding field, in octets.

**1929-2-1**　RFC 1929 §2

> Once the SOCKS V5 server has started, and the client has selected the Username/Password Authentication protocol, the Username/Password subnegotiation begins. This begins with the client producing a Username/Password request: +----+------+----------+------+----------+ \|VER \| ULEN \| UNAME \| PLEN \| PASSWD \| +----+------+----------+------+----------+ \| 1 \| 1 \| 1 to 255 \| 1 \| 1 to 255 \| +----+------+----------+------+----------+

**1929-2-2**　RFC 1929 §2

> The VER field contains the current version of the subnegotiation, which is X'01'. The ULEN field contains the length of the UNAME field that follows.

**1929-2-3**　RFC 1929 §2

> The UNAME field contains the username as known to the source operating system. The PLEN field contains the length of the PASSWD field that follows. The PASSWD field contains the password association with the given UNAME.

**1929-2-4**　RFC 1929 §2

> The server verifies the supplied UNAME and PASSWD, and sends the following response: +----+--------+ \|VER \| STATUS \| +----+--------+ \| 1 \| 1 \| +----+--------+

**1929-2-5**　RFC 1929 §2

> A STATUS field of X'00' indicates success. If the server returns a \`failure' (STATUS value other than X'00') status, it MUST close the connection.

**1929-3-1**　RFC 1929 §3

> Since the request carries the password in cleartext, this subnegotiation is not recommended for environments where "sniffing" is possible and practical.

</details>

### socks-request：SOCKS5 请求

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 1928-4-1 | RFC 1928 §4 Requests | statement | client | 两侧 | 请求在子协商完成之后才发。入口在认证成功之后才开始读请求；上游一侧网关等子协商完成再发请求。 | R117、R118 |
| 1928-4-2 | RFC 1928 §4 Requests | MUST | client | 两侧 | 背景：只在所选方法带封装时才有要求。RFC 1929 的用户名密码方法没有定义封装，无认证也没有，所以请求按下面的格式直接发送。 | — |
| 1928-4-3 | RFC 1928 §4 Requests | statement | client | 两侧 | 请求是 VER、CMD、RSV、ATYP 各 1 字节，变长的 DST.ADDR，2 字节的 DST.PORT；RSV 那一格标的是固定值 X'00'。入口按这个布局解析，上游一侧按这个布局生成。 | R112、R113 |
| 1928-4-4 | RFC 1928 §4 Requests | statement | client | 两侧 | CMD 只定义了三个值：CONNECT X'01'、BIND X'02'、UDP ASSOCIATE X'03'；ATYP 只定义了 X'01'、X'03'、X'04'；端口是网络字节序。第一版入口只做 CONNECT，其余的命令和不认识的地址类型分别有对应的应答码（见 1928-6-2）。 | R112、R113、R114 |
| 1928-4-5 | RFC 1928 §4 Requests | statement | proxy | 入口 | 背景：服务端按来源和目标地址评估请求（typically，不是硬性要求）。应答可能不止一个，那是 BIND 的情形；CONNECT 只有一个应答。 | — |
| 1928-5-1 | RFC 1928 §5 Addressing | statement | any | 两侧 | ATYP 决定地址字段怎么读，请求里的 DST.ADDR 和应答里的 BND.ADDR 都一样。X'01' 是 4 字节的 IPv4 地址。上游一侧读应答时也要按 ATYP 把 BND.ADDR 读完，才能找到隧道数据的起点。 | R112、R113 |
| 1928-5-2 | RFC 1928 §5 Addressing | statement | any | 两侧 | ATYP 为 X'03' 时，地址字段的第一个字节是域名的长度，后面没有 NUL 结尾。长度只有一个字节，所以域名最长 255 字节：上游一侧遇到更长的目标名没法用这种地址类型表达，只能报错。入口收到域名就是客户端把解析交给了代理（socks5h 的做法）。 | R112、R113、R114 |
| 1928-5-3 | RFC 1928 §5 Addressing | statement | any | 两侧 | ATYP 为 X'04' 时是 16 字节的 IPv6 地址。入口不支持某种地址类型时，应答码表里有 X'08'（见 1928-6-2）。 | R112、R113 |
| 1928-6-4 | RFC 1928 §6 Replies | statement | sender | 两侧 | 原文是小写的 must（RFC 1928 早于 RFC 2119，这里按核对脚本的口径记作 statement）。网关发出的请求和应答里 RSV 都填 X'00'。收到 RSV 不是 X'00' 的报文该怎么办，条款没有规定。 | — |
| 1928-6-6 | RFC 1928 §6 Replies | statement | proxy | 入口 | 背景：服务端评估 CONNECT 时预期会用目标地址、端口和客户端的来源地址、端口（expected，不是硬性要求）。入口的访问控制用这几项加上认证得到的用户名。 | — |
| 1928-6-7 | RFC 1928 §6 Replies | statement | client | 入口 | 背景：BIND 用于需要客户端接受反向连接的协议。第一版不做；收到 CMD 为 X'02' 的请求时，应答码表里有 X'07' Command not supported 可用。 | — |
| 1928-6-8 | RFC 1928 §6 Replies | statement | client | 入口 | 背景：UDP ASSOCIATE 用于建立 UDP 中继的关联。第一版不做；收到 CMD 为 X'03' 的请求时同样可以回 X'07'。 | — |

<details>
<summary>原文（12 条）</summary>

**1928-4-1**　RFC 1928 §4

> Once the method-dependent subnegotiation has completed, the client sends the request details.

**1928-4-2**　RFC 1928 §4

> If the negotiated method includes encapsulation for purposes of integrity checking and/or confidentiality, these requests MUST be encapsulated in the method- dependent encapsulation.

**1928-4-3**　RFC 1928 §4

> The SOCKS request is formed as follows: +----+-----+-------+------+----------+----------+ \|VER \| CMD \| RSV \| ATYP \| DST.ADDR \| DST.PORT \| +----+-----+-------+------+----------+----------+ \| 1 \| 1 \| X'00' \| 1 \| Variable \| 2 \| +----+-----+-------+------+----------+----------+

**1928-4-4**　RFC 1928 §4

> o VER protocol version: X'05' o CMD o CONNECT X'01' o BIND X'02' o UDP ASSOCIATE X'03' o RSV RESERVED o ATYP address type of following address o IP V4 address: X'01' o DOMAINNAME: X'03' o IP V6 address: X'04' o DST.ADDR desired destination address o DST.PORT desired destination port in network octet order

**1928-4-5**　RFC 1928 §4

> The SOCKS server will typically evaluate the request based on source and destination addresses, and return one or more reply messages, as appropriate for the request type.

**1928-5-1**　RFC 1928 §5

> In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies the type of address contained within the field: o X'01' the address is a version-4 IP address, with a length of 4 octets

**1928-5-2**　RFC 1928 §5

> the address field contains a fully-qualified domain name. The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.

**1928-5-3**　RFC 1928 §5

> the address is a version-6 IP address, with a length of 16 octets.

**1928-6-4**　RFC 1928 §6

> Fields marked RESERVED (RSV) must be set to X'00'.

**1928-6-6**　RFC 1928 §6

> It is expected that the SOCKS server will use DST.ADDR and DST.PORT, and the client-side source address and port in evaluating the CONNECT request.

**1928-6-7**　RFC 1928 §6

> The BIND request is used in protocols which require the client to accept connections from the server.

**1928-6-8**　RFC 1928 §6

> The UDP ASSOCIATE request is used to establish an association within the UDP relay process to handle UDP datagrams.

</details>

### socks-reply：SOCKS5 应答

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 1928-6-1 | RFC 1928 §6 Replies | statement | proxy | 两侧 | 应答的布局与请求相同：VER、REP、RSV、ATYP 各 1 字节，变长的 BND.ADDR，2 字节的 BND.PORT。入口每个请求都按这个格式应答，失败时也一样要带上地址和端口字段；上游一侧按 ATYP 读完整个应答。 | R121 |
| 1928-6-2 | RFC 1928 §6 Replies | statement | proxy | 两侧 | 应答码只有 X'00' 到 X'08' 九个。入口要把失败归到其中一个：规则不允许 X'02'，网络不可达 X'03'，主机不可达 X'04'，连接被拒 X'05'，命令不支持 X'07'，地址类型不支持 X'08'，其余用 X'01'；码表里没有“超时”和“上游代理出错”，这两种情形归到哪个码要由网关自己定并写明。上游一侧收到 X'09' 以上的值按未定义的失败处理。 | R121 |
| 1928-6-3 | RFC 1928 §6 Replies | statement | proxy | 两侧 | 背景：BND.ADDR、BND.PORT 是服务端一侧绑定的地址和端口，端口是网络字节序；各命令下的具体含义见 1928-6-5 及 BIND、UDP ASSOCIATE 的段落。 | — |
| 1928-6-5 | RFC 1928 §6 Replies | statement | proxy | 两侧 | CONNECT 应答里的 BND 是服务端连目标时用的本地地址和端口。网关经上游出去时，连到目标的那一端在上游，网关自己的出站连接连的是上游；这种情形填什么条款没有规定，入口填什么要自己定并写明。上游一侧：不要假定 BND.ADDR 等于上游的接入地址，也不要拿它当出口 IP 的证据（那是上游自己说的）。 | R121 |
| 1928-6-9 | RFC 1928 §6 Replies | MUST | proxy | 两侧 | 入口发出失败应答后必须关掉这条 TCP 连接，期限从发现失败的那一刻算起（不是从发出应答算起），不超过 10 秒；失败之后不能在同一条连接上等下一个请求。上游一侧：收到失败应答后这条连接就不能再用了，上游迟迟不关时网关自己关。 | R121 |
| 1928-6-10 | RFC 1928 §6 Replies | statement | client | 两侧 | 原文是小写的 may。成功应答之后客户端才开始传数据：入口把应答之后的字节当作隧道数据原样转发；上游一侧网关等收到 X'00' 的应答再把客户端的数据发过去。条款没有明说应答之前到的数据怎么处理。 | R115、R116 |

<details>
<summary>原文（6 条）</summary>

**1928-6-1**　RFC 1928 §6

> The SOCKS request information is sent by the client as soon as it has established a connection to the SOCKS server, and completed the authentication negotiations. The server evaluates the request, and returns a reply formed as follows: +----+-----+-------+------+----------+----------+ \|VER \| REP \| RSV \| ATYP \| BND.ADDR \| BND.PORT \| +----+-----+-------+------+----------+----------+ \| 1 \| 1 \| X'00' \| 1 \| Variable \| 2 \| +----+-----+-------+------+----------+----------+

**1928-6-2**　RFC 1928 §6

> REP Reply field: o X'00' succeeded o X'01' general SOCKS server failure o X'02' connection not allowed by ruleset o X'03' Network unreachable o X'04' Host unreachable o X'05' Connection refused o X'06' TTL expired o X'07' Command not supported o X'08' Address type not supported o X'09' to X'FF' unassigned

**1928-6-3**　RFC 1928 §6

> BND.ADDR server bound address o BND.PORT server bound port in network octet order

**1928-6-5**　RFC 1928 §6

> In the reply to a CONNECT, BND.PORT contains the port number that the server assigned to connect to the target host, while BND.ADDR contains the associated IP address. The supplied BND.ADDR is often different from the IP address that the client uses to reach the SOCKS server, since such servers are often multi-homed.

**1928-6-9**　RFC 1928 §6

> When a reply (REP value other than X'00') indicates a failure, the SOCKS server MUST terminate the TCP connection shortly after sending the reply. This must be no more than 10 seconds after detecting the condition that caused a failure.

**1928-6-10**　RFC 1928 §6

> If the reply code (REP value of X'00') indicates a success, and the request was either a BIND or a CONNECT, the client may now start passing data.

</details>

### basic：Basic 认证方案

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 7617-1-1 | RFC 7617 §1 Introduction | statement | any | 两侧 | 背景：Basic 凭据只是 Base64，等于明文。客户端到入口、网关到上游这两段如果不在 TLS 里，凭据（包括用户名里的会话参数）对链路上的人可见。 | — |
| 7617-2-1 | RFC 7617 §2 The 'Basic' Authentication Scheme | REQUIRED | sender | 入口 | 约束的是发质询的一方。入口发 407 时，Proxy-Authenticate: Basic 必须带 realm 参数。 | R30、R31 |
| 7617-2-2 | RFC 7617 §2 The 'Basic' Authentication Scheme | OPTIONAL | sender | 入口 | 入口的质询可以带也可以不带 charset；带与不带时客户端发来的字节有没有差别，由矩阵测。 | R63、R64 |
| 7617-2-3 | RFC 7617 §2 The 'Basic' Authentication Scheme | MUST | recipient | 两侧 | 约束的是收质询的一方。上游一侧：网关解析上游的 Basic 质询时，不认识的参数必须忽略，不能因此判质询无效。入口：不要指望靠自造的质询参数向客户端传信息，合规的客户端会忽略它们。 | — |
| 7617-2-4 | RFC 7617 §2 The 'Basic' Authentication Scheme | statement | recipient | 两侧 | 方案名和参数名不分大小写。入口解析 Proxy-Authorization 时 basic、BASIC 都要认；上游一侧解析质询时 Basic、realm、charset 的大小写都不能写死。 | R60 |
| 7617-2-5 | RFC 7617 §2 The 'Basic' Authentication Scheme | statement | proxy | 入口 | Basic 用在代理上时，质询的形式是 407 加 Proxy-Authenticate。原文是 can，只说明形式，承接的上一句讲的是没带凭据的请求。凭据不对时回什么、CONNECT 是否同样处理，本条没有规定，依据在 RFC 9110（9110-11.7.1-1、9110-15.5.8-1）。 | R30、R31、R45、R46 |
| 7617-2-6 | RFC 7617 §2 The 'Basic' Authentication Scheme | statement | client | 两侧 | 凭据的构造：user-id、一个冒号、password 拼成 user-pass，编码成字节，再做 Base64。入口反过来做：Base64 解码，按第一个冒号拆开；上游一侧网关按这四步生成。解码之后是字节序列，用的是哪种字符编码凭据本身不带。 | R60、R61、R62、R63、R64、R65、R66、R67、R68、R69、R70 |
| 7617-2-7 | RFC 7617 §2 The 'Basic' Authentication Scheme | statement | any | 两侧 | 默认的字符编码没有定义，只保证与 US-ASCII 兼容。入口的会话参数语法只用 US-ASCII 字符，才不受客户端编码差异的影响；非 ASCII 的用户名到达时可能是 UTF-8，也可能是别的编码。 | R63、R64 |
| 7617-2-8 | RFC 7617 §2 The 'Basic' Authentication Scheme | MUST NOT | client | 两侧 | 约束的是凭据的内容，也就是生成它的一方。上游一侧：配置里的上游凭据含控制字符时不能发出。入口：解出来的用户名或密码含控制字符就是不合规的凭据；条款没有规定接收方必须怎么处理，入口拒绝它不违反条款。会话参数的语法不能用控制字符。 | — |
| 7617-2-9 | RFC 7617 §2 The 'Basic' Authentication Scheme | statement | any | 两侧 | 入口按第一个冒号拆：前面是用户名，后面全部是密码，所以密码可以含冒号，用户名不能。放在用户名里的会话参数因此不能用冒号做分隔符。上游一侧：上游凭据的用户名含冒号时无法用 Basic 表达，应在配置时报错。 | R68、R70 |
| 7617-2-10 | RFC 7617 §2 The 'Basic' Authentication Scheme | statement | client | 客户端 | 背景：很多客户端不检查用户名里的冒号，原样拼接；入口按第一个冒号拆出来的用户名会被截短，后半段进了密码。哪些客户端这样做由矩阵测。 | R70 |
| 7617-2.1-1 | RFC 7617 §2.1 The 'charset' auth-param | statement | sender | 入口 | 原文写的是 servers，这里指发质询的一方，入口发 407 时也适用（2.1 节末尾有 Proxy-Authorization 的例子）。charset 只是建议（purely advisory）：入口即使发了 charset="UTF-8"，也不能假定收到的凭据一定是 UTF-8。 | R63、R64 |
| 7617-2.1-2 | RFC 7617 §2.1 The 'charset' auth-param | statement | sender | 两侧 | charset 只有 UTF-8 这一个取值，不分大小写。入口要发就只能发这个值。上游一侧解析上游的质询时，看到 charset=UTF-8（任意大小写）就把上游凭据按 NFC 规范化后用 UTF-8 编码：这是按参数的含义做的设计选择，原文在这一节说这个参数只是建议性的（purely advisory），没有要求客户端照做。 | R64 |
| 7617-2.1-3 | RFC 7617 §2.1 The 'charset' auth-param | MUST | recipient | 入口 | 这两句在讲 charset="UTF-8" 的段落里。recipients 指谁原文没有明说，有两种读法：收凭据的一方（入口在质询里发了 charset="UTF-8"，就得能处理这两个 profile 里的全部字符，不能只收 ASCII）；或者收到 charset 参数的一方（那样上游一侧的网关也受约束）。side 按前一种读法填的入口。两个 profile 的内容在 RFC 7613 里，不在本次核对的文本之内：未验证。 | R64 |
| 7617-2.1-4 | RFC 7617 §2.1 The 'charset' auth-param | statement | any | 两侧 | charset 只出现在质询里，凭据里没有地方声明编码。入口无法从 Proxy-Authorization 得知客户端用了什么编码，只能按字节处理。 | R63、R64 |
| 7617-2.1-5 | RFC 7617 §2.1 The 'charset' auth-param | statement | client | 两侧 | 背景：原文的例子。用于代理认证时凭据的构造完全一样，只是放在 Proxy-Authorization 头里。 | R60 |
| 7617-2.2-1 | RFC 7617 §2.2 Reusing Credentials | MAY | client | 两侧 | 讲的是重用：客户端用过一组凭据之后，后续发给代理的请求可以直接带上它，不必等代理再发一次质询（MAY，约束客户端）。入口因此会看到没有先经 407 就带凭据的请求，这是合规的；上游一侧，网关对同一个上游代理的后续请求也可以这样重用。从未收到过质询的第一个请求带不带凭据（矩阵 R30、R31、R52、R53 量的情形），这两句没有规定；RFC 9110 的相关说法见 9110-11.3-3。 | R36、R37 |
| 7617-3-1 | RFC 7617 §3 Internationalization Considerations | statement | any | 两侧 | 背景：非 ASCII 的用户名或密码在双方没有约定编码时会出互通问题。会话参数和网关签发的凭据都限定在 US-ASCII 之内可以避开。 | R63、R64 |
| 7617-4-1 | RFC 7617 §4 Security Considerations | statement | any | 两侧 | 背景：Basic 的密码在网络上是明文。 | — |
| 7617-4-2 | RFC 7617 §4 Security Considerations | SHOULD NOT | any | 两侧 | 没有 TLS 之类的保护时，不应当用 Basic 保护敏感或有价值的信息。入口在明文端口上收 Basic、网关向明文的上游代理发 Basic 都属于这种情形；这是 SHOULD NOT，要么给这两段加 TLS，要么在文档里写明凭据在链路上可见。 | — |
| 7617-4-3 | RFC 7617 §4 Security Considerations | statement | proxy | 入口 | 入口用来核对客户端密码的数据，存放方式应当做到泄露之后不能轻易还原出密码（ought to，不是规范性关键词）。这句管的是入口核对别人密码的数据，不涉及网关为了向上游认证而必须持有的上游凭据。 | — |
| 7617-B.1-1 | RFC 7617 §B.1 User Agents | statement | client | 客户端 | 背景：客户端可以平时用自己的默认编码，看到 charset 参数再改用 UTF-8。所以同一个客户端在质询带不带 charset 时发来的字节可能不同。 | R63、R64 |
| 7617-B.2-1 | RFC 7617 §B.2 Servers | statement | client | 客户端 | 背景：发了 charset 之后，入口仍然会同时看到 UTF-8 和旧编码的凭据，还有坏掉的凭据或者干脆不带凭据的请求。 | R63、R64 |

<details>
<summary>原文（23 条）</summary>

**7617-1-1**　RFC 7617 §1

> This scheme is not considered to be a secure method of user authentication unless used in conjunction with some external secure system such as TLS (Transport Layer Security, \[RFC5246\]), as the user-id and password are passed over the network as cleartext.

**7617-2-1**　RFC 7617 §2

> The authentication parameter 'realm' is REQUIRED (\[RFC7235\], Section 2.2).

**7617-2-2**　RFC 7617 §2

> The authentication parameter 'charset' is OPTIONAL (see Section 2.1).

**7617-2-3**　RFC 7617 §2

> No other authentication parameters are defined -- unknown parameters MUST be ignored by recipients, and new parameters can only be defined by revising this specification.

**7617-2-4**　RFC 7617 §2

> Note that both scheme and parameter names are matched case- insensitively.

**7617-2-5**　RFC 7617 §2

> A proxy can respond with a similar challenge using the 407 (Proxy Authentication Required) status code (\[RFC7235\], Section 3.2) and the Proxy-Authenticate header field (\[RFC7235\], Section 4.3).

**7617-2-6**　RFC 7617 §2

> To receive authorization, the client 1. obtains the user-id and password from the user, 2. constructs the user-pass by concatenating the user-id, a single colon (":") character, and the password, 3. encodes the user-pass into an octet sequence (see below for a discussion of character encoding schemes), 4. and obtains the basic-credentials by encoding this octet sequence using Base64 (\[RFC4648\], Section 4) into a sequence of US-ASCII characters (\[RFC0020\]).

**7617-2-7**　RFC 7617 §2

> For backwards compatibility reasons, this specification continues to leave the default encoding undefined, as long as it is compatible with US-ASCII (mapping any US-ASCII character to a single octet matching the US-ASCII character code).

**7617-2-8**　RFC 7617 §2

> The user-id and password MUST NOT contain any control characters (see "CTL" in Appendix B.1 of \[RFC5234\]).

**7617-2-9**　RFC 7617 §2

> Furthermore, a user-id containing a colon character is invalid, as the first colon in a user-pass string separates user-id and password from one another; text after the first colon is part of the password. User-ids containing colons cannot be encoded in user-pass strings.

**7617-2-10**　RFC 7617 §2

> Note that many user agents produce user-pass strings without checking that user-ids supplied by users do not contain colons; recipients will then treat part of the username input as part of the password.

**7617-2.1-1**　RFC 7617 §2.1

> In challenges, servers can use the 'charset' authentication parameter to indicate the character encoding scheme they expect the user agent to use when generating "user-pass" (a sequence of octets). This information is purely advisory.

**7617-2.1-2**　RFC 7617 §2.1

> The only allowed value is "UTF-8"; it is to be matched case- insensitively (see \[RFC2978\], Section 2.3). It indicates that the server expects character data to be converted to Unicode Normalization Form C ("NFC"; see Section 3 of \[RFC5198\]) and to be encoded into octets using the UTF-8 character encoding scheme (\[RFC3629\]).

**7617-2.1-3**　RFC 7617 §2.1

> For the user-id, recipients MUST support all characters defined in the "UsernameCasePreserved" profile defined in Section 3.3 of \[RFC7613\], with the exception of the colon (":") character. For the password, recipients MUST support all characters defined in the "OpaqueString" profile defined in Section 4.2 of \[RFC7613\].

**7617-2.1-4**　RFC 7617 §2.1

> Note: The 'charset' is only defined on challenges, as Basic authentication uses a single token for credentials ('token68' syntax); thus, the credentials syntax isn't extensible.

**7617-2.1-5**　RFC 7617 §2.1

> Or, for proxy authentication: Proxy-Authorization: Basic dGVzdDoxMjPCow==

**7617-2.2-1**　RFC 7617 §2.2

> A client MAY preemptively send the corresponding Authorization header field with requests for resources in that space without receipt of another challenge from the server. Similarly, when a client sends a request to a proxy, it MAY reuse a user-id and password in the Proxy- Authorization header field without receiving another challenge from the proxy server.

**7617-3-1**　RFC 7617 §3

> User-ids or passwords containing characters outside the US-ASCII character repertoire will cause interoperability issues, unless both communication partners agree on what character encoding scheme is to be used.

**7617-4-1**　RFC 7617 §4

> The most serious flaw of Basic authentication is that it results in the cleartext transmission of the user's password over the physical network.

**7617-4-2**　RFC 7617 §4

> Because Basic authentication involves the cleartext transmission of passwords, it SHOULD NOT be used (without enhancements such as HTTPS \[RFC2818\]) to protect sensitive or valuable information.

**7617-4-3**　RFC 7617 §4

> Servers and proxies implementing Basic authentication need to store user passwords in some form in order to authenticate a request. These passwords ought to be stored in such a way that a leak of the password data doesn't make them trivially recoverable.

**7617-B.1-1**　RFC 7617 §B.1

> Other user agents can keep their default behavior and switch to UTF-8 when seeing the new parameter.

**7617-B.2-1**　RFC 7617 §B.2

> Clients that do understand the 'charset' parameter will then start to use UTF-8, while other clients will continue to send credentials in their default encoding, broken credentials, or no credentials at all. Until all clients are upgraded to support UTF-8, servers are likely to see both UTF-8 and "legacy" encodings in requests.

</details>

### proxy-status：Proxy-Status

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9209-1-1 | RFC 9209 §1 Introduction | statement | intermediary | 入口 | 背景：只靠 502、504 之类的状态码说不清出了什么事，这是 Proxy-Status 要解决的问题。客户端实际能不能看到入口响应里的头，由矩阵测。 | R80、R81、R82、R86 |
| 9209-1.1-1 | RFC 9209 §1.1 Notational Conventions | statement | any | 入口 | 本文的 next hop 是朝源站方向的下一段连接。对网关来说下一跳是上游代理，不是源站：按字面，connection_refused、connection_timeout 这些类型说的是网关到上游代理的连接；上游代理报告它连不上目标，不是同一回事，选错误类型时要分清。 | — |
| 9209-2-1 | RFC 9209 §2 The Proxy-Status HTTP Field | statement | intermediary | 入口 | Proxy-Status 是响应字段，由中间方填写。入口可以在自己生成的响应（407、403、502、503、504，以及 CONNECT 的响应）和转发的响应上用它说明处理情况。 | R80、R81、R82、R84、R85、R86、R87 |
| 9209-2-2 | RFC 9209 §2 The Proxy-Status HTTP Field | statement | intermediary | 入口 | 值是结构化字段的 List，一个成员代表一个中间方，离源站最近的在最前。入口给已经带有 Proxy-Status 的响应加成员时，加在末尾。 | — |
| 9209-2-3 | RFC 9209 §2 The Proxy-Status HTTP Field | statement | intermediary | 入口 | 加不加 Proxy-Status 由中间方自己决定，条款不要求每个响应都加。 | — |
| 9209-2-4 | RFC 9209 §2 The Proxy-Status HTTP Field | MUST | intermediary | 入口 | 成员本身必须是 String 或 Token，用来标识这个部署。入口用的名字应当来自部署配置（服务名、主机名或生成的字符串），不能写死成软件的名字。 | — |
| 9209-2-5 | RFC 9209 §2 The Proxy-Status HTTP Field | OPTIONAL | intermediary | 入口 | 所有参数都是可选的；鼓励多给信息，但要先过第 4 节关于泄露信息的考虑。 | — |
| 9209-2-6 | RFC 9209 §2 The Proxy-Status HTTP Field | SHOULD | intermediary | 两侧 | 转发的响应里已经有 Proxy-Status（上游代理或更后面的中间方加的）时，入口应当保留原有成员，再追加自己的；除非明确配置成去掉。只有明文的转发会遇到这种情况，隧道里的响应入口看不到。保留下来的成员是上游自己说的，内容未经核实（见 9209-4-3）。 | R87 |
| 9209-2-7 | RFC 9209 §2 The Proxy-Status HTTP Field | MUST NOT | server | 上游 | 背景：约束的是源站。合规的源站不会生成这个字段，所以从上游方向收到的 Proxy-Status 应当都出自中间方；网关无法核实这一点。 | — |
| 9209-2-8 | RFC 9209 §2 The Proxy-Status HTTP Field | SHOULD NOT | intermediary | 入口 | 能放在响应头里就不要放在 trailer 里。入口自己生成的错误响应都把 Proxy-Status 放在头里；只有响应头已经发出之后才出的错，才谈得上用 trailer，而且要满足 9209-2-10 的前提。 | — |
| 9209-2-9 | RFC 9209 §2 The Proxy-Status HTTP Field | MAY | intermediary | 入口 | Proxy-Status 可以放在 trailer 里。原文举的例子正是网关会遇到的：流式转发响应的中途上游连接断了，响应头已经发出，只能写进 trailer。限制见 9209-2-8、9209-2-10。这两句在原文里排在 9209-2-8 之前。 | — |
| 9209-2-10 | RFC 9209 §2 The Proxy-Status HTTP Field | MUST NOT | intermediary | 入口 | 要在 trailer 里发 Proxy-Status，同一条消息的头里必须已经有网关自己生成的、成员相同的 Proxy-Status（参数可以不同）。入口如果打算在转发中途出错时用 trailer 报告，就得在每个可能用到 trailer 的转发响应的头里先放上自己的成员；头里没放过，事后就不能用 trailer。 | — |
| 9209-2.1-1 | RFC 9209 §2.1 Proxy-Status Parameters | MUST | recipient | 两侧 | 约束的是读这个字段的一方。上游一侧：网关解析上游响应里的 Proxy-Status 时，不认识的参数必须忽略，不能当成错误。入口：客户端按同样的规则读入口发出的字段。 | — |
| 9209-2.1.1-1 | RFC 9209 §2.1.1 error | statement | intermediary | 入口 | error 参数的值是一个 Token（不带引号），取自错误类型表。入口在取不到响应时用它说明原因。 | R80、R81、R82、R86 |
| 9209-2.1.1-2 | RFC 9209 §2.1.1 error | statement | intermediary | 入口 | 有些错误类型本身就表明响应是中间方自己生成的，不是源站的。调用方可以据此区分“代理说的 502”和“源站说的 502”，前提是它看得到这个头。 | R80、R81、R82、R86 |
| 9209-2.1.1-3 | RFC 9209 §2.1.1 error | SHOULD | intermediary | 入口 | 入口发 error 时应当选最具体的类型，前提是它准确：拿不准具体原因时用泛指的类型，不要猜一个具体的。 | R80、R82、R86 |
| 9209-2.1.1-4 | RFC 9209 §2.1.1 error | SHOULD | intermediary | 入口 | 入口自己生成带 error 的响应时，状态码应当用该错误类型建议的那个（各类型的建议值见 2.3 节的条款）。原文留了例外，例如状态码已经发出去的时候。 | R80、R82、R83、R86 |
| 9209-2.1.2-1 | RFC 9209 §2.1.2 next-hop | statement | intermediary | 入口 | next-hop 标识这次选用的下一跳，对网关就是选中的上游代理。它可以是别名，不必是主机名或 IP；入口要用这个参数时用别名，免得把上游代理的地址告诉客户端（见 9209-4-1）。 | — |
| 9209-2.1.4-1 | RFC 9209 §2.1.4 received-status | statement | intermediary | 入口 | received-status 是中间方从下一跳收到的状态码。上游的 HTTP 代理对网关的请求或 CONNECT 回了错误状态时，入口可以用它把上游的原始状态码告诉调用方；上游是 SOCKS5 代理时没有 HTTP 状态码可填。 | R80、R82 |
| 9209-2.1.4-2 | RFC 9209 §2.1.4 received-status | MUST | intermediary | 入口 | 入口发 received-status 时，值必须是结构化字段的 Integer，例如 received-status=502，不加引号。 | R80、R82 |
| 9209-2.1.5-1 | RFC 9209 §2.1.5 details | statement | intermediary | 入口 | details 是自由文本的 String，可以放实现或部署特有的信息。入口可以用它放 error 表达不了的细节（例如上游 SOCKS5 的应答码）。放什么要按第 4 节权衡，原文没有禁止性的规定；不放上游地址之类的内部信息是网关自己的设计决定，要记进决策文档。 | R80、R81、R82、R86 |
| 9209-2.3-1 | RFC 9209 §2.3 Proxy Error Types | statement | intermediary | 入口 | 背景：实现不必产生全部错误类型，入口只用与自己的状态对得上的那些。 | — |
| 9209-2.3.1-1 | RFC 9209 §2.3.1 DNS Timeout | statement | intermediary | 入口 | 网关自己解析下一跳（上游代理）的主机名超时时用，建议状态码 504。目标主机名交给上游去解析的情形，解析不是网关做的，不适用这一类型。 | R80 |
| 9209-2.3.2-1 | RFC 9209 §2.3.2 DNS Error | statement | intermediary | 入口 | 网关自己解析下一跳的主机名出错时用，建议状态码 502，可带 rcode、info-code 两个附加参数。同样只适用于网关自己做的解析。 | R80 |
| 9209-2.3.4-1 | RFC 9209 §2.3.4 Destination Unavailable | statement | intermediary | 入口 | 网关认为下一跳不可用时用（例如最近的尝试都失败、健康检查判定它不可用），建议状态码 503。代理池里的上游都被判定不可用、不再去连时，符合这个描述。 | R83 |
| 9209-2.3.5-1 | RFC 9209 §2.3.5 Destination IP Prohibited | statement | intermediary | 入口 | 按配置禁止连接下一跳的 IP 地址时用，建议状态码 502。按字面说的是下一跳的 IP；入口按策略拒绝请求本身时用 http_request_denied（见 9209-2.3.17-1）。 | R80 |
| 9209-2.3.7-1 | RFC 9209 §2.3.7 Connection Refused | statement | intermediary | 入口 | 网关到下一跳的连接被拒时用，建议状态码 502。按字面是网关连上游代理被拒；上游代理报告目标拒绝连接（例如 SOCKS5 应答码 X'05'）算不算这一类，条款没有说，要自己定并写明。 | R80、R81 |
| 9209-2.3.8-1 | RFC 9209 §2.3.8 Connection Terminated | statement | intermediary | 入口 | 到下一跳的连接在收到完整响应之前被关掉时用，建议状态码 502；这一类型不只出现在中间方自己生成的响应里（false）。上游在握手或响应中途断开时适用。 | R80、R100 |
| 9209-2.3.9-1 | RFC 9209 §2.3.9 Connection Timeout | statement | intermediary | 入口 | 网关向下一跳发起连接超时时用，建议状态码 504。 | R80、R81 |
| 9209-2.3.10-1 | RFC 9209 §2.3.10 Connection Read Timeout | statement | intermediary | 入口 | 网关在连接上等数据、在配置的时限内没等到时用，建议状态码 504。例如连上了上游代理，但它迟迟不回 CONNECT 的响应或 SOCKS5 的应答。 | R80 |
| 9209-2.3.12-1 | RFC 9209 §2.3.12 Connection Limit Reached | statement | intermediary | 入口 | 网关按配置限制到下一跳的连接数、并且已经超限时用，建议状态码 503。 | R83 |
| 9209-2.3.16-1 | RFC 9209 §2.3.16 HTTP Request Error | statement | intermediary | 入口 | 中间方代源站生成 4xx 响应时用，状态码就是那个 4xx，可带 status-code、status-phrase。入口因为请求本身有问题而回 400 之类时适用；按策略拒绝用下一条。 | R86 |
| 9209-2.3.17-1 | RFC 9209 §2.3.17 HTTP Request Denied | statement | intermediary | 入口 | 入口按配置或策略拒绝请求、并且没有把请求转给下一跳时用，建议状态码 403。目标不在允许范围内、会话参数不被接受之类的拒绝适用。 | R82、R86 |
| 9209-2.3.18-1 | RFC 9209 §2.3.18 HTTP Incomplete Response | statement | intermediary | 入口 | 网关从下一跳收到的响应不完整时用，建议状态码 502；这一类型不只出现在中间方自己生成的响应里（false）。明文转发时上游的响应中途截断适用。它与 connection_terminated（9209-2.3.8-1）怎么分，原文没有说；按 9209-2.1.1-3 选更具体而且准确的那个。 | — |
| 9209-2.3.26-1 | RFC 9209 §2.3.26 HTTP Response Timeout | statement | intermediary | 入口 | 网关等完整的响应、到了配置的总时限时用，建议状态码 504。与 connection_read_timeout（9209-2.3.10-1，一段时间内没有新数据）不同，这里是等整个响应的时限。 | — |
| 9209-2.3.28-1 | RFC 9209 §2.3.28 HTTP Protocol Error | statement | intermediary | 入口 | 网关与下一跳通信时遇到 HTTP 协议错误、又没有更具体的类型可用时用，建议状态码 502。上游的 HTTP 代理回了无法解析的响应时适用；类型名里是 HTTP，上游是 SOCKS5 代理时的协议错误用不用它，条款没有说。 | R80 |
| 9209-2.3.29-1 | RFC 9209 §2.3.29 Proxy Internal Response | statement | intermediary | 入口 | 中间方没有尝试连接下一跳、自己生成了响应时用，状态码取最合适的那个。 | R86 |
| 9209-2.3.30-1 | RFC 9209 §2.3.30 Proxy Internal Error | statement | intermediary | 入口 | 中间方遇到与源站无关的内部错误时用，建议状态码 500。2.1.1 节把它列为没有合适的具体类型时可用的泛指类型之一。 | R80 |
| 9209-2.3.32-1 | RFC 9209 §2.3.32 Proxy Loop Detected | statement | intermediary | 入口 | 中间方发现请求要转给自己、或者用别的办法发现了环路时用，建议状态码 502。入口发现目标就是自己的监听地址时适用。 | — |
| 9209-4-1 | RFC 9209 §4 Security Considerations | statement | intermediary | 入口 | Proxy-Status 会泄露中间方的配置和后端拓扑。对网关来说，上游代理的地址、数量、健康状态都属于这类信息。原文只说有些信息可能只适合给有权限的一方看（might），没有禁止；入口对没通过认证的请求（407）不带这些细节，是可以做的设计决定，不是条款要求。 | R80、R81、R82 |
| 9209-4-2 | RFC 9209 §4 Security Considerations | statement | intermediary | 入口 | 生成不生成、放什么都要权衡；可以按请求的属性（认证、来源地址）有条件地生成。入口可以只对通过认证的调用方给出详细的 error 和 details。 | R80、R81、R82 |
| 9209-4-3 | RFC 9209 §4 Security Considerations | statement | intermediary | 上游 | 字段的内容没有任何核实手段。上游代理发来的 Proxy-Status 只是它自己的说法，网关不能拿它当证据，也不能据此判定上游的行为。 | — |

<details>
<summary>原文（42 条）</summary>

**9209-1-1**　RFC 9209 §1

> HTTP accommodates these types of errors with a few status codes -- for example, 502 (Bad Gateway) and 504 (Gateway Timeout). However, experience has shown that more information is necessary to aid debugging and communicate what's happened to the client.

**9209-1.1-1**　RFC 9209 §1.1

> Note that in this specification, "proxy" is used to indicate both forward and reverse proxies, otherwise known as gateways. "Next hop" indicates the connection in the direction leading to the origin server for the request.

**9209-2-1**　RFC 9209 §2

> The Proxy-Status HTTP response field allows an intermediary to convey additional information about its handling of a response and its associated request.

**9209-2-2**　RFC 9209 §2

> Its value is a List (see Section 3.1 of \[STRUCTURED-FIELDS\]). Each member of the List represents an intermediary that has handled the response. The first member represents the intermediary closest to the origin server, and the last member represents the intermediary closest to the user agent.

**9209-2-3**　RFC 9209 §2

> Intermediaries determine when it is appropriate to add the Proxy- Status field to a response.

**9209-2-4**　RFC 9209 §2

> Each member of the List identifies the intermediary that inserted the value and MUST have a type of either String or Token. Depending on the deployment, this might be a service name (but not a software or hardware product name; e.g., "ExampleCDN" is appropriate, but "ExampleProxy" is not because it doesn't identify the deployment), a hostname ("proxy-3.example.com"), an IP address, or a generated string.

**9209-2-5**　RFC 9209 §2

> While all of these parameters are OPTIONAL, intermediaries are encouraged to provide as much information as possible (but see Section 4 for security considerations in doing so).

**9209-2-6**　RFC 9209 §2

> When adding a value to the Proxy-Status field, intermediaries SHOULD preserve the existing members of the field to allow debugging of the entire chain of intermediaries handling the request unless explicitly configured to remove them (e.g., to prevent internal network details from leaking; see Section 4).

**9209-2-7**　RFC 9209 §2

> Origin servers MUST NOT generate the Proxy-Status field.

**9209-2-8**　RFC 9209 §2

> However, because it might be silently discarded along the path to the user agent (as is the case for all trailer fields; see Section 6.5 of \[HTTP\]), Proxy-Status SHOULD NOT be sent as a trailer field unless it is not possible to send it in the header section.

**9209-2-9**　RFC 9209 §2

> Proxy-Status MAY be sent as an HTTP trailer field. For example, if an intermediary is streaming a response and the inbound connection suddenly terminates, Proxy-Status can only be appended to the trailer section of the outbound message since the header section has already been sent.

**9209-2-10**　RFC 9209 §2

> To allow recipients to reconstruct the relative ordering of Proxy- Status members conveyed in trailer fields with those conveyed in header fields, an intermediary MUST NOT send Proxy-Status as a trailer field unless it has also generated a Proxy-Status header field with the same member (although potentially different parameters) in that message.

**9209-2.1-1**　RFC 9209 §2.1

> Unrecognised parameters MUST be ignored.

**9209-2.1.1-1**　RFC 9209 §2.1.1

> The error parameter's value is a Token that is a proxy error type. When present, it indicates that the intermediary encountered an issue when obtaining this response.

**9209-2.1.1-2**　RFC 9209 §2.1.1

> The presence of some proxy error types indicates that the response was generated by the intermediary itself, rather than being forwarded from the origin server. This is the case when, for example, the origin server can't be contacted, so the proxy has to create its own response.

**9209-2.1.1-3**　RFC 9209 §2.1.1

> When sending the error parameter, the most specific proxy error type SHOULD be sent, provided that it accurately represents the error condition.

**9209-2.1.1-4**　RFC 9209 §2.1.1

> Each proxy error type has a recommended HTTP status code. When generating an HTTP response containing the error, its HTTP status code SHOULD be set to the recommended HTTP status code. However, there may be circumstances (e.g., for backwards compatibility with previous behaviours, a status code has already been sent) when another status code might be used.

**9209-2.1.2-1**　RFC 9209 §2.1.2

> The next-hop parameter's value is a String or Token that identifies the intermediary or origin server selected (and used, if contacted) to obtain this response. It might be a hostname, IP address, or alias.

**9209-2.1.4-1**　RFC 9209 §2.1.4

> The received-status parameter's value indicates the HTTP status code that the intermediary received from the next-hop server when obtaining this response.

**9209-2.1.4-2**　RFC 9209 §2.1.4

> The value MUST be an Integer.

**9209-2.1.5-1**　RFC 9209 §2.1.5

> The details parameter's value is a String containing additional information not captured anywhere else. This can include implementation-specific or deployment-specific information.

**9209-2.3-1**　RFC 9209 §2.3

> Note that implementations might not produce all proxy error types. The set of types below is designed to map to existing states in implementations and therefore may not be applicable to some.

**9209-2.3.1-1**　RFC 9209 §2.3.1

> Name: dns\_timeout Description: The intermediary encountered a timeout when trying to find an IP address for the next-hop hostname. Extra Parameters: None Recommended HTTP Status Code: 504 Response Only Generated by Intermediaries: true

**9209-2.3.2-1**　RFC 9209 §2.3.2

> Name: dns\_error Description: The intermediary encountered a DNS error when trying to find an IP address for the next-hop hostname. Extra Parameters: rcode: A String conveying the DNS RCODE that indicates the error type. See \[RFC8499\], Section 3. info-code: An Integer conveying the Extended DNS Error Code INFO- CODE. See \[RFC8914\]. Recommended HTTP Status Code: 502 Response Only Generated by Intermediaries: true

**9209-2.3.4-1**　RFC 9209 §2.3.4

> Name: destination\_unavailable Description: The intermediary considers the next hop to be unavailable; e.g., recent attempts to communicate with it may have failed, or a health check may indicate that it is down. Extra Parameters: None Recommended HTTP Status Code: 503 Response Only Generated by Intermediaries: true

**9209-2.3.5-1**　RFC 9209 §2.3.5

> Name: destination\_ip\_prohibited Description: The intermediary is configured to prohibit connections to the next-hop IP address. Extra Parameters: None Recommended HTTP Status Code: 502 Response Only Generated by Intermediaries: true

**9209-2.3.7-1**　RFC 9209 §2.3.7

> Name: connection\_refused Description: The intermediary's connection to the next hop was refused. Extra Parameters: None Recommended HTTP Status Code: 502 Response Only Generated by Intermediaries: true

**9209-2.3.8-1**　RFC 9209 §2.3.8

> Name: connection\_terminated Description: The intermediary's connection to the next hop was closed before a complete response was received. Extra Parameters: None Recommended HTTP Status Code: 502 Response Only Generated by Intermediaries: false

**9209-2.3.9-1**　RFC 9209 §2.3.9

> Name: connection\_timeout Description: The intermediary's attempt to open a connection to the next hop timed out. Extra Parameters: None Recommended HTTP Status Code: 504 Response Only Generated by Intermediaries: true

**9209-2.3.10-1**　RFC 9209 §2.3.10

> Name: connection\_read\_timeout Description: The intermediary was expecting data on a connection (e.g., part of a response) but did not receive any new data in a configured time limit. Extra Parameters: None Recommended HTTP Status Code: 504 Response Only Generated by Intermediaries: false

**9209-2.3.12-1**　RFC 9209 §2.3.12

> Name: connection\_limit\_reached Description: The intermediary is configured to limit the number of connections it has to the next hop, and that limit has been exceeded. Extra Parameters: None Recommended HTTP Status Code: 503 Response Only Generated by Intermediaries: true

**9209-2.3.16-1**　RFC 9209 §2.3.16

> Name: http\_request\_error Description: The intermediary is generating a client (4xx) response on the origin's behalf. Applicable status codes include (but are not limited to) 400, 403, 405, 406, 408, 411, 413, 414, 415, 416, 417, and 429. Extra Parameters: status-code: An Integer containing the generated status code. status-phrase: A String containing the generated status phrase. Recommended HTTP Status Code: The applicable 4xx status code Response Only Generated by Intermediaries: true

**9209-2.3.17-1**　RFC 9209 §2.3.17

> Name: http\_request\_denied Description: The intermediary rejected the HTTP request based on its configuration and/or policy settings. The request wasn't forwarded to the next hop. Extra Parameters: None Recommended HTTP Status Code: 403 Response Only Generated by Intermediaries: true

**9209-2.3.18-1**　RFC 9209 §2.3.18

> Name: http\_response\_incomplete Description: The intermediary received an incomplete response to the request from the next hop. Extra Parameters: None Recommended HTTP Status Code: 502 Response Only Generated by Intermediaries: false

**9209-2.3.26-1**　RFC 9209 §2.3.26

> Name: http\_response\_timeout Description: The intermediary reached a configured time limit waiting for the complete response. Extra Parameters: None Recommended HTTP Status Code: 504 Response Only Generated by Intermediaries: false

**9209-2.3.28-1**　RFC 9209 §2.3.28

> Name: http\_protocol\_error Description: The intermediary encountered an HTTP protocol error when communicating with the next hop. This error should only be used when a more specific one is not defined. Extra Parameters: None Recommended HTTP Status Code: 502 Response Only Generated by Intermediaries: false

**9209-2.3.29-1**　RFC 9209 §2.3.29

> Name: proxy\_internal\_response Description: The intermediary generated the response itself without attempting to connect to the next hop. Extra Parameters: None Recommended HTTP Status Code: The most appropriate status code for the response Response Only Generated by Intermediaries: true

**9209-2.3.30-1**　RFC 9209 §2.3.30

> Name: proxy\_internal\_error Description: The intermediary encountered an internal error unrelated to the origin. Extra Parameters: None Recommended HTTP Status Code: 500 Response Only Generated by Intermediaries: true

**9209-2.3.32-1**　RFC 9209 §2.3.32

> Name: proxy\_loop\_detected Description: The intermediary tried to forward the request to itself, or a loop has been detected using different means (e.g., \[RFC8586\]). Extra Parameters: None Recommended HTTP Status Code: 502 Response Only Generated by Intermediaries: true

**9209-4-1**　RFC 9209 §4

> One of the primary security concerns when using Proxy-Status is leaking information that might aid an attacker. For example, information about the intermediary's configuration and backend topology can be exposed, allowing attackers to directly target backend services that are not prepared for high traffic volume or malformed inputs. Some information might only be suitable to reveal to authorized parties.

**9209-4-2**　RFC 9209 §4

> As a result, care needs to be taken when deciding to generate a Proxy-Status field and what information to include in it. Note that intermediaries are not required to generate a Proxy-Status field in any response and can conditionally generate them based upon request attributes (e.g., authentication tokens, IP address).

**9209-4-3**　RFC 9209 §4

> Also, the field's content is not verified; an intermediary can claim certain actions (e.g., sending a request over an encrypted channel) but fail to actually do that.

</details>

### h2：HTTP/2

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9113-8.5-1 | RFC 9113 §8.5 The CONNECT Method | statement | any | 入口 | HTTP/2 的 CONNECT 把隧道建在一条流上，连接本身不变成隧道；HTTP/1.1 的 CONNECT 是整条连接变成隧道。入口要支持它，先得实现 HTTP/2 的成帧、多路复用和流控，这是第一版入口不做 HTTP/2 CONNECT 的原因。 | — |
| 9113-8.5-2 | RFC 9113 §8.5 The CONNECT Method | MUST | client | 客户端 | 背景：HTTP/2 的 CONNECT 请求只有 :method 和 :authority，:scheme 和 :path 必须省略，否则是畸形请求。第一版入口不说 HTTP/2，不会收到这种请求。 | — |
| 9113-8.5-3 | RFC 9113 §8.5 The CONNECT Method | statement | proxy | 入口 | 背景：HTTP/2 的隧道里代理要在 DATA 帧和 TCP 字节流之间来回转换，而不是原样转发字节。这是与 HTTP/1.1 隧道在实现上的主要差别。 | — |
| 9113-8.5-4 | RFC 9113 §8.5 The CONNECT Method | MUST | proxy | 入口 | 背景：HTTP/2 的隧道要求代理把 TCP 一侧的错误转成 CONNECT_ERROR 的流错误，反过来流或连接出错时必须向 TCP 一侧发 RST。以后要做 HTTP/2 入口时，这是必须实现的一条；第一版不涉及。 | — |

<details>
<summary>原文（4 条）</summary>

**9113-8.5-1**　RFC 9113 §8.5

> In HTTP/2, the CONNECT method establishes a tunnel over a single HTTP/2 stream to a remote host, rather than converting the entire connection to a tunnel.

**9113-8.5-2**　RFC 9113 §8.5

> \* The ":method" pseudo-header field is set to CONNECT. \* The ":scheme" and ":path" pseudo-header fields MUST be omitted. \* The ":authority" pseudo-header field contains the host and port to connect to (equivalent to the authority-form of the request-target of CONNECT requests; see Section 3.2.3 of \[HTTP/1.1\]). A CONNECT request that does not conform to these restrictions is malformed (Section 8.1.1).

**9113-8.5-3**　RFC 9113 §8.5

> After the initial HEADERS frame sent by each peer, all subsequent DATA frames correspond to data sent on the TCP connection. The frame payload of any DATA frames sent by the client is transmitted by the proxy to the TCP server; data received from the TCP server is assembled into DATA frames by the proxy.

**9113-8.5-4**　RFC 9113 §8.5

> A proxy treats any error in the TCP connection, which includes receiving a TCP segment with the RST bit set, as a stream error (Section 5.4.2) of type CONNECT\_ERROR. Correspondingly, a proxy MUST send a TCP segment with the RST bit set if it detects an error with the stream or the HTTP/2 connection.

</details>

### websocket：WebSocket

| 条款 | 出处 | 级别 | 约束谁 | 哪一侧 | 对网关的含义 | 矩阵行 |
| --- | --- | --- | --- | --- | --- | --- |
| 9110-7.8-1 | RFC 9110 §7.8 Upgrade | MUST | sender | 客户端 | 合规的客户端发 Upgrade 时，Connection 里会有 upgrade 选项，其用意就是让中间人不转发这个字段。ws:// 经代理以绝对形式的 GET 发来时，网关按 9110-7.6.1-2 会删掉 Upgrade；要支持就得由网关自己与下一跳做升级，条款没有规定代理怎么做。 | R21 |
| 9110-7.8-2 | RFC 9110 §7.8 Upgrade | statement | any | 两侧 | 背景：Upgrade 只作用于当前这一条连接，是逐跳的。wss:// 走 CONNECT 隧道时，升级发生在隧道里，网关看不到。 | R21、R22 |
| 9110-7.8-3 | RFC 9110 §7.8 Upgrade | MAY | recipient | 入口 | 原文主语是 server。入口收到带 Upgrade 的明文请求可以不升级，继续按 HTTP/1.1 处理。 | R21 |
| 6455-3-1 | RFC 6455 §3 WebSocket URIs | OPTIONAL | client | 客户端 | 背景：ws:// 的 URI 不写端口时端口是 80，wss:// 是 443。4.1 节第 3 步里的 /port/ 就来自这里，所以 ws:// 经代理时 CONNECT 的目标端口是 80。 | R21、R22 |
| 6455-4.1-1 | RFC 6455 §4.1 Client Requirements | SHOULD | client | 客户端 | WebSocket 客户端配置了代理时，应当让代理开一条到 /host/:/port/ 的 TCP 连接，也就是隧道，而不是发绝对形式的 GET。入口因此会收到目标端口是 80 的 CONNECT；入口如果只允许对 443 做 CONNECT，合规的 ws:// 客户端就连不上。 | R21、R22 |
| 6455-4.1-2 | RFC 6455 §4.1 Client Requirements | statement | client | 客户端 | 背景：原文给的例子就是对 80 端口的 CONNECT，带 Host 头。这只是例子（might），不是对请求格式的规定；实际的客户端怎么发由矩阵测（R21）。矩阵里 CONNECT 请求行和 Host 头的两行（R03、R05）量的是 HTTPS 的 CONNECT，只能作对照。 | R21 |
| 6455-4.1-3 | RFC 6455 §4.1 Client Requirements | statement | client | 客户端 | 背景：没有单独的 WebSocket 代理设置的客户端，被鼓励优先用 SOCKS5 代理，其次用给 HTTPS 配的代理，最后才是给 HTTP 配的代理。同一个客户端的 ws:// 流量可能从 SOCKS5 入口进来，也可能以 CONNECT 进来。 | R21、R22 |
| 6455-4.1-4 | RFC 6455 §4.1 Client Requirements | MUST | client | 客户端 | wss:// 时客户端在隧道建好之后先做 TLS 握手，再发 WebSocket 握手：入口在隧道里看到的首包是 TLS ClientHello。ws:// 时隧道里是明文的 HTTP 升级请求。 | R21、R22 |
| 6455-4.1-5 | RFC 6455 §4.1 Client Requirements | MUST | client | 客户端 | 背景：只约束客户端。代理报错（入口对 CONNECT 回非 2xx，或 SOCKS5 应答失败）时，合规的 WebSocket 客户端必须让这次连接失败并放弃这次尝试。之后会不会重新发起，这句没有说；矩阵里没有专门量 WebSocket 连接失败的行。这一句是原文列表的第 4 步，排在 6455-4.1-4（第 5 步）之前。 | — |

<details>
<summary>原文（9 条）</summary>

**9110-7.8-1**　RFC 9110 §7.8

> A sender of Upgrade MUST also send an "Upgrade" connection option in the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.

**9110-7.8-2**　RFC 9110 §7.8

> The Upgrade header field only applies to switching protocols on top of the existing connection; it cannot be used to switch the underlying connection (transport) protocol, nor to switch the existing communication to a different connection.

**9110-7.8-3**　RFC 9110 §7.8

> A server MAY ignore a received Upgrade header field if it wishes to continue using the current protocol on that connection.

**6455-3-1**　RFC 6455 §3

> The port component is OPTIONAL; the default for "ws" is port 80, while the default for "wss" is port 443.

**6455-4.1-1**　RFC 6455 §4.1

> \_Proxy Usage\_: If the client is configured to use a proxy when using the WebSocket Protocol to connect to host /host/ and port /port/, then the client SHOULD connect to that proxy and ask it to open a TCP connection to the host given by /host/ and the port given by /port/.

**6455-4.1-2**　RFC 6455 §4.1

> EXAMPLE: For example, if the client uses an HTTP proxy for all traffic, then if it was to try to connect to port 80 on server example.com, it might send the following lines to the proxy server: CONNECT example.com:80 HTTP/1.1 Host: example.com

**6455-4.1-3**　RFC 6455 §4.1

> NOTE: Implementations that do not expose explicit UI for selecting a proxy for WebSocket connections separate from other proxies are encouraged to use a SOCKS5 \[RFC1928\] proxy for WebSocket connections, if available, or failing that, to prefer the proxy configured for HTTPS connections over the proxy configured for HTTP connections.

**6455-4.1-4**　RFC 6455 §4.1

> If /secure/ is true, the client MUST perform a TLS handshake over the connection after opening the connection and before sending the handshake data \[RFC2818\].

**6455-4.1-5**　RFC 6455 §4.1

> If the connection could not be opened, either because a direct connection failed or because any proxy used returned an error, then the client MUST \_Fail the WebSocket Connection\_ and abort the connection attempt.

</details>

## 按矩阵行反查

| 矩阵行 | 这一行看什么 | 相关条款 |
| --- | --- | --- |
| R01 | 明文请求到达代理的形式 | 9110-3.7-3、9110-4.2.1-1、9110-4.2.3-1、9110-4.2.3-2、9110-4.2.4-1、9110-4.2.4-2、9110-7.1-2、9110-7.1-3、9110-7.2-1、9110-7.3.2-1、9110-7.7-1、9110-7.7-2、9112-3-1、9112-3.2-1、9112-3.2-2、9112-3.2-3、9112-3.2.1-1、9112-3.2.2-1、9112-3.2.2-2、9112-3.2.2-3、9112-3.2.2-4、9112-3.3-1 |
| R02 | 明文请求里与连接有关的头 | 9110-5.1-1、9110-7.6-2、9110-7.6.1-1、9110-7.6.1-2、9110-7.6.1-3、9110-7.6.1-4、9110-7.6.1-5、9110-7.6.1-6、9110-10.1.4-1、9112-7.4-1、9112-7.4-2、9112-9.3-1、9112-9.3-2、9112-9.3-3、9112-9.6-1、9112-9.6-2、9112-9.6-3、9112-C.2.2-1 |
| R03 | CONNECT 请求行 | 9110-7.1-1、9110-7.1-2、9110-9.3.6-1、9110-9.3.6-2、9110-9.3.6-3、9110-9.3.6-4、9110-15.5.1-1、9112-3-1、9112-3.1-1、9112-3.2-1、9112-3.2.3-1、9112-3.2.3-2、9112-3.3-2 |
| R04 | CONNECT 带的头 | 9110-5.3-2、9110-7.2-2、9110-7.2-3、9110-9.3.6-12、9112-C.2.2-1 |
| R05 | CONNECT 的 Host 头 | 9110-7.1-3、9110-7.2-1、9110-7.2-2、9110-7.2-3、9112-3.2-2、9112-3.2-3、9112-3.3-2 |
| R06 | 隧道里客户端发的首包 | 9110-3.7-4、9110-9.3.6-1、9110-9.3.6-5、9110-9.3.6-12、9110-15.3.1-1、9112-9.7-1 |
| R11 | 明文同一个源连续 3 次：代理连接数 | 9110-7.3.2-1、9112-9.3-1、9112-9.3-5 |
| R13 | 明文两个源交替各 2 次：代理连接数 | 9110-7.3.2-1、9112-9.3-1、9112-9.3-5 |
| R14 | HTTPS 6 个并发（源站支持 h2）：隧道数 | 9112-9.4-1、9112-9.4-2 |
| R15 | HTTPS 6 个并发（源站只说 HTTP/1.1）：隧道数 | 9112-9.4-1、9112-9.4-2 |
| R16 | 明文 6 个并发：代理连接数 | 9112-9.4-1、9112-9.4-2 |
| R17 | 目标是 localhost 的明文请求 | 9110-7.6-3、9110-7.7-1、9112-3.2.2-1 |
| R18 | 目标是 localhost 的 HTTPS 请求 | 9110-7.6-3、9110-9.3.6-9、9112-3.2.3-2 |
| R19 | 明文 POST 的正文怎么分帧 | 9110-5.2-1、9110-8.6-1、9110-8.6-3、9110-8.6-4、9110-8.6-5、9110-8.6-6、9112-6-1、9112-6.1-1、9112-6.1-2、9112-6.1-3、9112-6.1-6、9112-6.1-8、9112-6.1-10、9112-6.2-1、9112-6.3-3、9112-6.3-4、9112-6.3-11、9112-6.3-13、9112-6.3-14、9112-6.3-15、9112-7.1-1、9112-7.1.1-1、9112-11.2-1 |
| R20 | 2 MiB 的明文 POST 先不先发 Expect: 100-continue | 9110-10.1.1-1、9110-10.1.1-2、9110-10.1.1-3、9110-10.1.1-4、9110-10.1.1-5、9110-10.1.1-6、9110-10.1.1-7、9110-10.1.1-8、9110-10.1.1-10、9110-10.1.1-11、9110-10.1.1-12、9110-15.2-1、9110-15.2-2、9110-15.2-3、9112-9.5-5 |
| R21 | ws:// 经代理的方式 | 9110-7.6.1-3、9110-7.8-1、9110-7.8-2、9110-7.8-3、9112-3.2.2-1、6455-3-1、6455-4.1-1、6455-4.1-2、6455-4.1-3、6455-4.1-4 |
| R22 | wss:// 经代理的方式 | 9110-7.8-2、9112-3.2.3-2、6455-3-1、6455-4.1-1、6455-4.1-3、6455-4.1-4 |
| R23 | 代理连接上客户端发的第一个字节 | 9112-2.2-4、9112-2.2-5、9112-2.2-8、1928-3-2、1928-3-4、1928-3-5 |
| R24 | POST 的正文是否完整到达源站 | 9110-8.6-4、9112-6.1-3、9112-6.3-10、9112-8-2、9112-8-3、9112-11.3-2 |
| R30 | 明文：第一个请求带不带凭据 | 9110-11.1-1、9110-11.3-3、9110-11.4-2、9110-11.7.2-1、9110-17.16.1-1、7617-2-1、7617-2-5 |
| R31 | CONNECT：第一个 CONNECT 带不带凭据 | 9110-9.3.6-8、9110-11.1-1、9110-11.3-3、9110-11.4-2、9110-11.7.2-1、9110-17.16.1-1、7617-2-1、7617-2-5 |
| R32 | 明文：407 之后的重试走哪条连接 | 9110-10.1.1-9、9110-11.3-1、9110-11.7.1-1、9110-15.5.8-1、9110-15.5.8-2、9112-9.3-5、9112-9.3-8、9112-9.6-5 |
| R33 | CONNECT：407 之后的重试走哪条连接 | 9110-3.3-2、9110-9.3.6-6、9110-9.3.6-8、9110-11.3-1、9110-11.7.1-1、9110-15.5.8-1、9110-15.5.8-2、9112-9.3-5、9112-9.3-8、9112-9.6-5 |
| R34 | 明文：407 带 Connection: close | 9110-10.1.1-9、9110-11.7.1-1、9112-9.3-2、9112-9.3-6、9112-9.6-1、9112-9.6-4、9112-9.6-5、9112-9.6-6、9112-9.6-7 |
| R35 | CONNECT：407 带 Connection: close | 9110-9.3.6-6、9110-9.3.6-8、9110-11.7.1-1、9112-9.3-2、9112-9.6-1、9112-9.6-4、9112-9.6-5、9112-9.6-6、9112-9.6-7 |
| R36 | 明文连续 3 次：代理收到的请求数 / 其中没带凭据的 | 9110-3.3-3、9110-11.3-3、9110-11.4-1、9110-11.5-1、9110-15.5.8-2、9110-17.16.2-1、9112-9.3-5、7617-2.2-1 |
| R37 | 访问第二个源时 CONNECT 带不带凭据 | 9110-11.3-3、9110-11.4-1、9110-11.5-1、7617-2.2-1 |
| R38 | HTTPS 同一个源连续 3 次（要认证）：隧道数 | 9110-11.4-1、9110-11.5-1、9110-17.16.2-1 |
| R39 | 代理凭据有没有被带到源站 | 9110-11.7.2-2、9110-11.7.2-3、9110-15.4-1 |
| R40 | 三种重定向是否都走通 | 9110-15.4-1 |
| R41 | 明文，同一个进程两个用户交替 | 9110-3.3-3、9110-17.16.2-1 |
| R42 | HTTPS，同一个进程两个用户交替 | 9110-3.3-3、9110-17.16.2-1 |
| R43 | 带正文的明文 POST 遇到认证：完整的正文发了几遍 | 9110-7.5-1、9110-7.5-2、9110-10.1.1-1、9110-10.1.1-4、9110-10.1.1-9、9110-10.1.1-10、9110-15.5.8-2、9112-9.3-6、9112-9.5-5、9112-9.6-6、9112-9.6-7 |
| R44 | HTTPS 6 个并发（要认证）：收到几个 407 | 9110-15.5.8-2 |
| R45 | 没配凭据，明文：调用方看到什么 | 9110-11.3-1、9110-11.3-2、9110-11.4-2、9110-11.5-2、9110-11.6.1-2、9110-11.7.1-1、9110-15.5-1、9110-15.5.8-1、7617-2-5 |
| R46 | 没配凭据，HTTPS：调用方看到什么 | 9110-11.3-1、9110-11.3-2、9110-11.4-2、9110-11.5-2、9110-11.6.1-2、9110-11.7.1-1、9110-15.5-1、9110-15.5.8-1、7617-2-5 |
| R47 | 密码错，明文：带着凭据试了几次 | 9110-11.4-2、9110-15.5.8-2 |
| R48 | 密码错，HTTPS：带着凭据试了几次 | 9110-11.4-2、9110-15.5.8-2 |
| R49 | 密码错，HTTPS，代理一直回 407：调用方看到什么 | 9110-11.4-2、9110-11.7.1-1、9110-11.7.1-2、9110-15.5.8-2 |
| R50 | 密码错，HTTPS，代理回 403：调用方看到什么 | 9110-11.4-3、9110-15.5.4-1、9110-15.5.4-2 |
| R51 | 密码错，明文，代理回 403：调用方看到什么 | 9110-11.4-3、9110-15.5.4-1、9110-15.5.4-2 |
| R52 | 代理没要求认证，明文请求带不带凭据 | 9110-11.3-3 |
| R53 | 代理没要求认证，CONNECT 带不带凭据 | 9110-11.3-3 |
| R60 | 常见的参数写法（连字符） | 9110-11.2-1、7617-2-4、7617-2-6、7617-2.1-5 |
| R61 | 下划线、点、波浪号、等号、分号、逗号 | 9110-11.2-1、7617-2-6 |
| R62 | 要转义的字符：@ % + / 和空格 | 9110-11.2-1、7617-2-6 |
| R63 | UTF-8 用户名，质询不带 charset | 9110-11.2-2、7617-2-2、7617-2-6、7617-2-7、7617-2.1-1、7617-2.1-4、7617-3-1、7617-B.1-1、7617-B.2-1 |
| R64 | UTF-8 用户名，质询带 charset="UTF-8" | 9110-11.2-2、7617-2-2、7617-2-6、7617-2-7、7617-2.1-1、7617-2.1-2、7617-2.1-3、7617-2.1-4、7617-3-1、7617-B.1-1、7617-B.2-1 |
| R65 | 用户名 255 字节 | 9110-5.4-1、9110-17.5-1、7617-2-6 |
| R66 | 用户名 256 字节 | 9110-5.4-1、9110-17.5-1、7617-2-6 |
| R67 | 用户名 1024 字节 | 9110-5.4-1、9110-17.5-1、7617-2-6 |
| R68 | 密码里有冒号、@、空格、%2F、加号 | 9110-11.2-1、7617-2-6、7617-2-9 |
| R69 | 空密码 | 7617-2-6 |
| R70 | 用户名里有冒号（“原样”指原样拼接，服务端只能按第一个冒号拆） | 7617-2-6、7617-2-9、7617-2-10 |
| R80 | CONNECT 回 502：默认用法 | 9110-9.3.6-6、9110-15-1、9110-15.6-1、9110-15.6.3-1、9110-15.6.5-1、9112-4-1、9209-1-1、9209-2-1、9209-2.1.1-1、9209-2.1.1-2、9209-2.1.1-3、9209-2.1.1-4、9209-2.1.4-1、9209-2.1.4-2、9209-2.1.5-1、9209-2.3.1-1、9209-2.3.2-1、9209-2.3.5-1、9209-2.3.7-1、9209-2.3.8-1、9209-2.3.9-1、9209-2.3.10-1、9209-2.3.28-1、9209-2.3.30-1、9209-4-1、9209-4-2 |
| R81 | CONNECT 回 502：加上需要主动打开的手段 | 9110-15.6-1、9110-15.6.3-1、9110-15.6.5-1、9209-1-1、9209-2-1、9209-2.1.1-1、9209-2.1.1-2、9209-2.1.5-1、9209-2.3.7-1、9209-2.3.9-1、9209-4-1、9209-4-2 |
| R82 | CONNECT 回 403：默认用法 | 9110-9.3.6-6、9110-11.4-3、9110-15-1、9110-15.5-1、9110-15.5.4-1、9112-4-1、9209-1-1、9209-2-1、9209-2.1.1-1、9209-2.1.1-2、9209-2.1.1-3、9209-2.1.1-4、9209-2.1.4-1、9209-2.1.4-2、9209-2.1.5-1、9209-2.3.17-1、9209-4-1、9209-4-2 |
| R83 | CONNECT 回 503 带 Retry-After: 1：发了几次 CONNECT | 9110-9.3.6-6、9110-10.2.3-1、9110-15-1、9110-15.6-1、9110-15.6.4-1、9110-15.6.4-2、9209-2.1.1-4、9209-2.3.4-1、9209-2.3.12-1 |
| R84 | CONNECT 成功时 200 里附加的头：默认用法 | 9110-6.4.1-1、9110-8.6-2、9110-9.3.6-5、9110-9.3.6-10、9110-9.3.6-11、9110-11.7.3-1、9110-15.3-1、9110-15.3.1-1、9112-6.1-4、9112-6.3-2、9209-2-1 |
| R85 | CONNECT 成功时 200 里附加的头：加上需要主动打开的手段 | 9110-6.4.1-1、9110-8.6-2、9110-9.3.6-5、9110-9.3.6-10、9110-9.3.6-11、9110-15.3-1、9110-15.3.1-1、9112-6.1-4、9112-6.3-2、9209-2-1 |
| R86 | 明文请求被代理回 403：默认用法 | 9110-11.4-3、9110-15.5-1、9110-15.5.4-1、9112-4-1、9209-1-1、9209-2-1、9209-2.1.1-1、9209-2.1.1-2、9209-2.1.1-3、9209-2.1.1-4、9209-2.1.5-1、9209-2.3.16-1、9209-2.3.17-1、9209-2.3.29-1 |
| R87 | 明文请求成功时代理附加的响应头：默认用法 | 9110-7.6.3-1、9110-11.7.3-1、9209-2-1、9209-2-6 |
| R88 | CONNECT 失败但代理没关连接：下一个 CONNECT 走哪条连接 | 9110-3.3-2、9110-9.3.6-6、9112-9.3-5、9112-9.3-8 |
| R89 | CONNECT 失败之后，对另一个源的请求 | 9110-9.3.6-6 |
| R90 | 明文：空闲连接被代理关掉后再请求 | 9110-9.2.2-2、9110-9.2.2-4、9110-15.5.9-1、9112-9.3.1-1、9112-9.5-1、9112-9.5-2、9112-9.5-3 |
| R91 | HTTPS：空闲隧道被代理关掉后再请求 | 9110-3.7-5、9110-9.2.2-2、9110-9.3.6-7、9112-9.3.1-1、9112-9.5-1、9112-9.5-2、9112-9.5-3 |
| R92 | 明文，复用的连接，GET，连接被关（FIN）：请求到达几次，结果 | 9110-9.2.2-1、9110-9.2.2-2、9110-9.2.2-6、9112-9.3.1-1、9112-9.3.2-2、9112-9.5-3 |
| R93 | 明文，复用的连接，POST，连接被关（FIN）：请求到达几次，结果 | 9110-9.2.2-1、9110-9.2.2-3、9110-9.2.2-4、9110-9.2.2-5、9112-9.3.1-1、9112-9.3.2-2、9112-9.5-3 |
| R94 | HTTPS，复用的隧道，GET，隧道被切断（FIN）：请求到达几次，结果 | 9110-9.2.2-1、9110-9.2.2-2、9110-9.2.2-6、9110-9.3.6-7、9112-9.3.1-1、9112-9.8-1、9112-9.8-2、9112-11.3-1 |
| R95 | HTTPS，复用的隧道，POST，隧道被切断（FIN）：请求到达几次，结果 | 9110-9.2.2-1、9110-9.2.2-3、9110-9.2.2-4、9110-9.2.2-5、9110-9.3.6-7、9112-9.3.1-1、9112-9.8-1、9112-9.8-2、9112-11.3-1 |
| R96 | 明文，新连接上的第一个 GET，连接被关：请求到达几次，结果 | 9110-9.2.2-2、9110-9.2.2-6、9112-9.3.1-1 |
| R97 | HTTPS，新隧道里的第一个 GET，隧道被切断：请求到达几次，结果 | 9110-9.2.2-2、9110-9.2.2-6、9110-9.3.6-7、9112-9.3.1-1、9112-9.8-1、9112-9.8-2 |
| R98 | 明文，复用的连接，GET，连接被复位（RST）：请求到达几次，结果 | 9110-9.2.2-2、9112-9.3.1-1、9112-9.5-3 |
| R99 | HTTPS，复用的隧道，GET，隧道被复位（RST）：请求到达几次，结果 | 9110-9.2.2-2、9110-9.3.6-7、9112-9.3.1-1 |
| R100 | CONNECT 发出后代理不回应就关连接：发了几次 CONNECT，结果 | 9110-9.2.2-5、9110-9.2.2-6、9209-2.3.8-1 |
| R101 | HTTPS（源站支持 h2），复用的隧道，GET，隧道被切断：请求到达几次，结果 | 9110-9.2.2-2、9110-9.3.6-7 |
| R110 | 没配凭据时提供的认证方法 | 1928-3-2、1928-3-4、1928-3-6、1928-3-8、1928-3-10、1928-8-1 |
| R111 | 配了凭据时提供的认证方法 | 1928-3-2、1928-3-4、1928-3-6、1928-3-8、1928-3-10、1928-8-1 |
| R112 | socks5h：请求里的地址类型 | 1928-4-3、1928-4-4、1928-5-1、1928-5-2、1928-5-3 |
| R113 | socks5（客户端自己解析），目标是 localhost：请求里的地址类型 | 1928-4-3、1928-4-4、1928-5-1、1928-5-2、1928-5-3 |
| R114 | socks5（客户端自己解析），域名本机解析不了 | 1928-4-4、1928-5-2 |
| R115 | SOCKS5 建好以后的首包（HTTPS） | 1928-6-10 |
| R116 | SOCKS5 建好以后的首包（明文） | 1928-6-10 |
| R117 | 用户名密码认证，凭据正确 | 1928-3-9、1928-4-1、1929-1-1、1929-2-1、1929-2-2、1929-2-4、1929-3-1 |
| R118 | 配了凭据而代理选了无认证 | 1928-3-6、1928-3-8、1928-4-1 |
| R119 | 代理回 0xFF（没有可接受的方法）时的报错 | 1928-3-7、1928-3-8 |
| R120 | 用户名密码不对时的报错 | 1929-2-4、1929-2-5 |
| R121 | 应答码 2、4、5 的报错能否区分 | 1928-6-1、1928-6-2、1928-6-5、1928-6-9 |
| R125 | SOCKS5 用户名密码：常见的参数写法（连字符） | 1929-2-1、1929-2-3 |
| R126 | SOCKS5 用户名密码：要转义的字符：@ % + / 和空格 | 1929-2-1、1929-2-3 |
| R127 | SOCKS5 用户名密码：UTF-8 用户名 | 1929-2-1、1929-2-3 |
| R128 | SOCKS5 用户名密码：用户名 255 字节 | 1929-1-2、1929-2-1 |
| R129 | SOCKS5 用户名密码：用户名 256 字节（超出 RFC 1929 的上限） | 1929-1-2、1929-2-1 |
| R130 | SOCKS5 用户名密码：密码里有冒号、@、空格、%2F、加号 | 1929-2-1、1929-2-3 |
| R131 | SOCKS5 用户名密码：空密码 | 1929-1-2、1929-2-1 |
| R132 | SOCKS5 用户名密码：用户名里有冒号 | 1929-2-1、1929-2-3 |

行表共 104 行，96 行有条款指到。没有条款指到的 8 行：R07、R08、R09、R10、R12、R122、R123、R124。
