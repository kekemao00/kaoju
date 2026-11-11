# go 驱动笔记

写给实现 `go` 这一列驱动的人。2026-11-10 写成，**只读了文档和源码，没有运行过任何 Go 程序，更没有让客户端连过任何代理**；
这里的每一条都还没有被实测证实，实测对不上的地方以实测为准，并记进报告的“与预期不符”。
对应的逐行预期在 `research/phase2/expectations/go.json`。

## 读的是哪个版本

| 部件 | 版本 | 来源 |
| --- | --- | --- |
| Go 标准库 | 1.24.7（linux/amd64） | 本机 `/usr/local/go/src`（`VERSION` 文件写 `go1.24.7`） |
| 发行说明 | 1.20、1.23、1.24、1.25 | `golang/website` 仓库 `_content/doc/go1.NN.md`（master，2026-11-10 取） |
| 对比用的旧版、新版 `transport.go` | 1.22、1.23、1.25 | `golang/go` 仓库 `release-branch.go1.NN` 分支（2026-11-10 取） |

下文的出处写成“文件:行号”，路径相对于 `/usr/local/go/src`，行号是 1.24.7 的。
`transport.go`、`request.go`、`client.go`、`transfer.go`、`response.go`、`socks_bundle.go`、`h2_bundle.go` 都在 `net/http/` 下。

这一列的定义：`http.DefaultTransport` 的克隆，只改 `Proxy`；凭据写在代理 URL 的 userinfo 里；
信任测试 CA 用环境变量 `SSL_CERT_FILE`；HTTP/2 保持默认开启。只用标准库，不引入第三方包。

## 0. 先看这三个会改变结果的选择

这三处驱动怎么写，矩阵里的格子就怎么变。预期文件是按下面“建议”的写法填的。

| 选择 | 建议 | 换一种写法会怎样 |
| --- | --- | --- |
| `go.mod` 的 `go` 行 | 写 `go 1.24`（或 `go 1.24.7`） | 写 1.23 及以下时，GODEBUG 的默认值回到旧版：`tlsmlkem=0`（`internal/godebugs/table.go:60`），ClientHello 从 1492 字节变成约 270 字节，R07 翻转 |
| 两个用户怎么换凭据（B11、B12、S14） | 同一个 `Transport`，`Proxy` 函数按请求返回不同的 URL | 每个用户一个 `Transport` 时，R42、R124 从“用了别人的隧道 / 连接”变成“各开各的”（见第 3 节） |
| POST 的正文怎么给 | 读进内存，`bytes.NewReader` | 直接把 `*os.File` 当 body 时长度未知，R19 变成 chunked，断连后的重试规则也跟着变（见第 6 节） |

## 1. 代理怎么配

### HTTP 代理

`Transport.Proxy` 是一个 `func(*http.Request) (*url.URL, error)`（`transport.go:115-128` 的文档）。
固定代理的常规写法是 `http.ProxyURL(u)`（`transport.go:503-509`）；凭据放在 URL 的 userinfo 里，
文档原话：“If the proxy URL contains a userinfo subcomponent, the proxy request will pass the username and password in a Proxy-Authorization header.”

```go
func proxyURL(scheme, host string, port int, user, pass *string) *url.URL {
	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}
	if user != nil {
		u.User = url.UserPassword(*user, *pass) // 原样保存，不转义
	}
	return u
}

tr := http.DefaultTransport.(*http.Transport).Clone()
tr.Proxy = http.ProxyURL(proxyURL("http", "127.0.0.1", port, &user, &pass))
client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
```

- **用 `url.UserPassword` 构造，不要手拼字符串再 `url.Parse`。** `UserPassword` 把两个字符串原样存下（`net/url/url.go:399-401`），
  `Username()`、`Password()` 原样取回（`:414-428`）。手拼的话，用户名里的 `@`、`/`、空格、`%41` 会让解析失败或被反转义：
  `parseAuthority` 以最后一个 `@` 切分，`validUserinfo` 不接受空格和 `/`，其余部分按百分号反转义（`net/url/url.go:588-612`、`:1267` 起）。
  一定要用字符串的话，用户名和密码各自先过 `url.PathEscape`（注意 `+` 在 userinfo 里是字面量，不是空格）。
- 空密码用 `url.UserPassword(user, "")`。发出去是 `用户名:`。
- 凭据是 Transport 自己加的，**先带，不等 407**：
  - 明文：`dialConn` 给连接挂一个 `mutateHeaderFunc`，这条连接上的每个请求都写 `Proxy-Authorization`（`transport.go:1818-1824`、`:2744-2749`）。
  - HTTPS：CONNECT 请求头里直接带（`transport.go:1841-1844`）。隧道里的请求不带。
  - 值是 `"Basic " + base64(用户名 + ":" + 密码)`，按 Go 字符串的原字节，也就是 UTF-8（`transport.go:986-996`、`client.go:422-425`）。
    不看质询里的 `charset`，没有长度检查。
- net/http 里**没有处理 407 的代码**。明文请求的 407 当普通响应交给调用方（`err == nil`，`StatusCode == 407`）；
  CONNECT 的 407 变成 error（见第 7 节）。密码错了不会重试。
- CONNECT 请求长这样（`transport.go:1845-1850`、`request.go:649-696`）：

  ```
  CONNECT a.kaoju.test:443 HTTP/1.1
  Host: a.kaoju.test:443
  User-Agent: Go-http-client/1.1
  Proxy-Authorization: Basic …        （配了凭据才有）
  ```

  没有 `Proxy-Connection`，没有 `Content-Length`（`transfer.go:254-276`）。想加头用 `Transport.ProxyConnectHeader`
  或 `GetProxyConnectHeader`（`transport.go:253-265`），这一列不设它们。
- 明文请求是绝对形式（`request.go:646-648`），头只有 `Host`、`User-Agent`、`Accept-Encoding: gzip`，再加凭据；没有 `Connection`、`Proxy-Connection`。
  不要自己加 `Accept-Encoding`，也不要设 `DisableCompression`，保持默认。

### SOCKS5 代理

同一个字段，scheme 换成 `socks5` 或 `socks5h`：

```go
tr.Proxy = http.ProxyURL(proxyURL("socks5h", "127.0.0.1", port, &user, &pass))
```

- 1.24 里 `socks5` 和 `socks5h` **两种都支持，行为完全一样**（文档 `transport.go:119-121`：“"socks5" is treated the same as "socks5h"”；
  代码 `transport.go:1800` 一个分支）。域名**总是交给代理解析**：目标不是 IP 字面量就按 ATYP=3 发（`socks_bundle.go:92-109`）。
  用例给什么 scheme 就原样用什么（S03、S04 给的是 `socks5`），并在结果的 `config` 里注明两者等价、客户端做不到“自己解析”。
- 没配凭据时只提供方法 `00`；配了凭据提供 `00, 02`（`transport.go:1803-1813`、`socks_bundle.go:58-68`）。
  代理选了 `00` 就不发凭据，照常继续（`socks_bundle.go:444-446`）。
- 用户名、密码原样按 RFC 1929 发（`socks_bundle.go:443-455`）。用户名为空、用户名或密码超过 255 字节时，
  **在写出认证字节之前**返回 `invalid username/password`（`:448-450`）。空密码不拒绝，PLEN 写 0。
- SOCKS5 握手之后：目标是 https 就在这条连接上做 TLS（ALPN 照常提供 h2），目标是 http 就直接发源站形式的请求（`transport.go:1906-1946`）。

### 显式 Proxy 函数与 ProxyFromEnvironment 的区别

`http.DefaultTransport` 的 `Proxy` 是 `ProxyFromEnvironment`，它对 `localhost` 和回环 IP 一律不走代理
（`transport.go:494-501` 的文档；`vendor/golang.org/x/net/http/httpproxy/proxy.go:116-117`、`:178-187`），并且认 `NO_PROXY`。
显式的 `ProxyURL` 没有这些旁路：`connectMethodForRequest` 只管调用 `t.Proxy`（`transport.go:974-979`）。
所以这一列里目标是 `localhost` 的请求（A10、A11、S03）也经代理。克隆之后一定要把 `Proxy` 换掉，否则继承的是环境变量那一套。

## 2. 信任测试 CA

用环境变量，不碰 `TLSClientConfig`：

```
SSL_CERT_FILE=<用例里的 ca_file>
```

- `crypto/x509/root_unix.go:36-37`：设了 `SSL_CERT_FILE` 就只读这一个文件，不再找系统的证书包。
  系统的证书**目录**仍然会被扫（`:52-75`，`SSL_CERT_DIR` 没设时用默认目录）；想连目录也隔离，再设 `SSL_CERT_DIR` 指向一个空目录。
- 系统根证书池只加载一次（`crypto/x509/root.go:30-31` 的 `once`），之后再改环境变量不起作用。
  `ca_file` 是每次运行才知道的，所以要么由包装脚本在启动 Go 程序之前设好，要么在 `main` 的最开头、第一次 TLS 握手之前 `os.Setenv`；
  两种都行，在 `config` 里写明用的是哪一种。
- 这样 `TLSClientConfig` 保持 nil，HTTP/2 的启用条件不受影响。（克隆自 `DefaultTransport` 的 Transport 带着 `ForceAttemptHTTP2: true`，
  即使设了 `TLSClientConfig` 也照样启用 HTTP/2，`transport.go:290-295`、`:469-475`；但这一列按约定不设。）
- 任何地方都不许写 `InsecureSkipVerify`（仓库规矩）。

## 3. 同一个进程里对不同请求用不同的代理凭据

两种写法都常见，Go 没有“会话”对象：

**(a) 同一个 Transport，Proxy 函数按请求返回不同的 URL。** `Proxy` 的签名本来就带 `*http.Request`，按请求选代理是这个字段的设计用途。
请求怎么告诉 `Proxy` 函数该用谁：放在 context 里。

```go
type userKey struct{}

tr.Proxy = func(r *http.Request) (*url.URL, error) {
	i, _ := r.Context().Value(userKey{}).(int) // 没有就是“不配凭据”的那个 URL
	return proxyURLs[i], nil
}
req, _ := http.NewRequestWithContext(context.WithValue(ctx, userKey{}, 1), "GET", u, nil)
```

`Proxy` 函数拿到的就是这次请求本身（`transport.go:974-979`）；重定向后的请求沿用原请求的 context（`client.go:667`），所以每一跳都能取到。

**(b) 每组凭据一个 Transport（各自 `Clone()`）。** 写法最直白，也有人这样做；代价是连接池不共享。

PROTOCOL 要求“一个用例从头到尾用同一个客户端实例（同一个连接池）”，所以**用 (a)**，并在结果的 `config` 里写明。两种写法的差别不只是风格：

- HTTP/1.1 一层的连接池键 `connectMethodKey.proxy` 是 `proxyURL.String()`，**含 userinfo**（`transport.go:2003-2018`、`:2049-2052`）。
  不同凭据是不同的键，明文请求各走各的连接、各带各的凭据（B11）。
- **HTTP/2 的连接池只按目标地址分，不看代理**（`h2_bundle.go:802-813`、`:8054-8056`）。经 (a) 换用户访问同一个 HTTPS 源时：
  第二个用户的键没有空闲连接，于是新建隧道（CONNECT 带第二个用户的凭据）、做 TLS、协商出 h2；
  `addConnIfNeeded` 发现池里已经有到 `a.kaoju.test:443` 的可用连接，返回“不需要”，新连接被关掉（`h2_bundle.go:886-893`、`:7720-7731`）；
  请求随后走的是**第一个用户的隧道**。预期 R42 是“用了别人的隧道”，R124 是“用了别人的连接”。
  这是读源码推出来的，没有在文档里找到说明，把握中等；实测如果是“各开各的”，先查驱动是不是不小心用了两个 Transport，或者 h2 没协商上。
- 用 (b) 时每个 Transport 有自己的 HTTP/2 池（`Clone` 不复制 h2 的状态，`transport.go:329-372`），不会串。

## 4. 并发、重定向、POST

### 并发 6 个请求

```go
var wg sync.WaitGroup
for i := range steps {
	wg.Add(1)
	go func() { defer wg.Done(); results[i] = do(client, steps[i]) }()
}
wg.Wait()
```

`Transport` 和 `Client` 可以并发使用（`transport.go:71-72`）。

- `MaxConnsPerHost` 默认 0，不限（`transport.go:213-218`、`:1568-1571`）；每个找不到空闲连接的请求各起一次拨号（`:1593-1602`）。
  所以 6 个并发的 HTTP/1.1 请求是 6 条连接 / 隧道（A08、A09、B14、S13）。
- `MaxIdleConnsPerHost` 默认 2（`transport.go:60`、`:1040-1045`）：只决定请求结束后**留下**几条空闲连接，多出来的会被客户端关掉。不要改它。
- HTTP/2（A07）：Transport 在拨号时还不知道对端会不会说 h2，所以 6 个请求照样发出 6 个 CONNECT；协商出 h2 之后只留一条，其余关掉
  （`h2_bundle.go:878-885` 的注释就是讲这件事）。隧道数预期是 6，但取决于时序（最先建好的连接会直接交给还在等的请求，`transport.go:1088-1097`），
  3 遍不一样也不奇怪。

### 重定向

`http.Client` 默认跟随，最多 10 跳（`client.go:819-824`）。`follow` 为假的步骤其实也不会遇到重定向，不用特别处理；
要明确不跟随时用 `CheckRedirect: func(...) error { return http.ErrUseLastResponse }`（`client.go:493`）。
跳转后的请求重新选连接方式，凭据规则不变。代理凭据不是请求头的一部分（是 Transport 加的），不存在“重定向时被带走”的问题。

### POST

```go
body, _ := os.ReadFile(step.BodyFile)
req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
req.Header.Set("Content-Type", "application/octet-stream")
```

- `NewRequestWithContext` 认得 `*bytes.Reader`、`*bytes.Buffer`、`*strings.Reader`：设好 `ContentLength` 和 `GetBody`（`request.go:925-943`）。
  于是发的是 `Content-Length`，不是 chunked。
- **不发 `Expect: 100-continue`**。Transport 只在调用方自己设了这个头时才等 100（`transport.go:2776-2779`）；
  `ExpectContinueTimeout`（默认 1 秒）只在那种情况下起作用（`transport.go:232-239`）。驱动不要设这个头。

### 每个响应都要读完再关

```go
defer resp.Body.Close()
b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
io.Copy(io.Discard, resp.Body) // 读到 EOF，连接才会回到空闲池
```

HTTP/1.1 的连接只有在响应体读到 EOF 之后才放回空闲池（`transport.go:2395-2404`）。没读完就 `Close`，连接会被关掉，
连接复用（R11、R13、R36）和“复用的连接上断连”那几个用例（F03 到 F06、F09、F10 的 `only_if_reused`）就都测不到了。

## 5. 断连以后的重发规则

`Transport.roundTrip` 的循环（`transport.go:665-740`）在请求失败后问 `shouldRetryRequest`（`:808-853`）：

1. 连接不是复用的（`!pc.isReused()`）→ 不重试。新连接上的失败一律交给调用方。
2. `nothingWrittenError`（一个字节都没写出去，`:2578-2583`、`:2218-2228`）→ 没有正文或有 `GetBody` 就重试，POST 也重试。
3. 请求不可重放 → 不重试。可重放的定义（`request.go:1534-1548`）：没有正文或有 `GetBody`，**并且**方法是 GET、HEAD、OPTIONS、TRACE，
   或者带了 `Idempotency-Key` / `X-Idempotency-Key` 头。
4. `transportReadFromServerError`（等响应的第一个字节时读失败，EOF 或 RST 都算，`:1016-1026`、`:2275-2294`）→ 重试。
5. `errServerClosedIdle`（`:1009-1013`）→ 重试。
6. 其余 → 不重试。

对应到用例：复用的连接上已发出的 GET 被 FIN 或 RST，重发一次（F03、F05、F09、F10 预期“2 次，成功”）；POST 不重发（F04、F06 预期“1 次，失败”，
调用方看到 `EOF`）；新连接上的第一个请求不重发（F07、F08）；CONNECT 没有回应不重试（F11，error 是 `unexpected EOF`）。

空闲连接被对端关掉时，后台的 `readLoop` 会发现并把它移出空闲池（`:2275-2282`、`:2417-2436`），下一个请求直接新建连接（F01、F02），调用方无感。

**HTTP/2 另有一套**（`h2_bundle.go:8130-8174`）：只对“连接不可用”“收到 GOAWAY”“REFUSED_STREAM”重试。
隧道被切断时流以 `unexpected EOF` 中止（`:9853-9891`），不在重试之列，回到 `shouldRetryRequest` 也落到最后的 `return false`。
所以 F12（h2）预期“1 次，失败”，与 HTTP/1.1 的 F05 不同。把握中等。

驱动不要自己加重试，也不要给 POST 加 `Idempotency-Key`。

## 6. 正文类型对行为的影响（为什么用 bytes.NewReader）

| body 的类型 | `ContentLength` | `GetBody` | 发出去 | 断连后 |
| --- | --- | --- | --- | --- |
| `*bytes.Reader` 等三种 | 已知 | 有 | `Content-Length` | 规则 2 可以重发；规则 3 仍然拦住 POST |
| `*os.File`、其他 `io.Reader` | 未知（-1） | 无 | `Transfer-Encoding: chunked` | 规则 2 也不重发 |

出处：`request.go:925-943`、`:1552-1560`，`transfer.go:254-263`。

## 7. 代理出错时调用方能拿到什么

### 默认用法

`client.Do` 的 error 是 `*url.Error`，文字是 `Get "<URL>": <内层 error>`（`client.go:617-633`、`net/url/url.go:32`）。
驱动的 `default_text` 记 `fmt.Sprintf("%T: %v", err, err)`，再用 `errors.Unwrap` 一层层往下各记一行。

| 情况 | 调用方看到 | 出处 |
| --- | --- | --- |
| CONNECT 回非 200（含 407、403、502、503） | error，内层文字**只有原因短语**，如 `Proxy Authentication Required`。状态码、响应头、正文都没有。原因短语为空时是 `unknown status code` | `transport.go:1896-1903` |
| CONNECT 回 200 但带了附加的头 | 看不到，响应读完即丢 | `transport.go:1872-1873` |
| CONNECT 发出后连接被关 | error：`unexpected EOF` | `response.go:164`、`transport.go:1883-1886` |
| 明文请求被代理回 407、403 | 普通的 `*http.Response`：`resp.Status` 带原因短语，`Header`、`Body` 齐全，`err == nil` | `transport.go:2288-2290`、`response.go:168-173` |
| 连不上代理、到 `https://` 代理的 TLS 失败 | `*net.OpError`，`Op` 是 `proxyconnect` | `transport.go:1747-1753` |
| SOCKS5：代理回 `0xFF` | `socks connect tcp <代理>-><目标>: no acceptable authentication methods` | `socks_bundle.go:80-83`、`:352-356` |
| SOCKS5：用户名密码被拒 | `… username/password authentication failed` | `socks_bundle.go:467-469` |
| SOCKS5：用户名超过 255 字节或为空 | `… invalid username/password` | `socks_bundle.go:448-450` |
| SOCKS5：应答码非 0 | `… unknown error <说明>`；2 是 `connection not allowed by ruleset`，4 是 `host unreachable`，5 是 `connection refused` | `socks_bundle.go:121-123`、`:196-219` |

`default_text` 成功时要记 `resp.Status`（不是只记 `StatusCode`）：Go 的接口给原因短语。

### 需要主动打开的手段（`extra_text`）

只有一个：**`Transport.OnProxyConnectResponse`**（`transport.go:130-133`，Go 1.20 加入）。文档：
“OnProxyConnectResponse is called when the Transport gets an HTTP response from a proxy for a CONNECT request.
It's called before the check for a 200 OK response. If it returns an error, the request fails with that error.”

```go
tr.OnProxyConnectResponse = func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, connectRes *http.Response) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\n", connectRes.Proto, connectRes.Status)
	connectRes.Header.Write(&sb)
	if connectRes.StatusCode != 200 && connectRes.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(connectRes.Body, 4096))
		sb.Write(b)
	}
	record(ctx, sb.String()) // 按 context 里的步骤号存起来
	return nil               // 一定返回 nil，不改变默认行为
}
```

- 它对 200 和非 200 都会被调用（`transport.go:1888-1894` 在状态码检查之前），能看到状态码、原因短语、响应头。
- **正文**：文档没说能不能读。从源码看，CONNECT 的非 2xx 响应带 `Content-Length` 时 `connectRes.Body` 是可读的
  （只有 HEAD 的响应不读正文，`transfer.go:250-252`）。**只在非 200 时读**：200 之后连接上接着就是隧道的字节，读了会卡住或吃掉数据。
  读的时候限长。预期 R81 按“读了正文”填的是四样都看得到；驱动如果只记状态和头，那一格会是“状态码、原因短语、响应头”，要在 `extra_how` 里写清楚记了什么。
- 钩子必须返回 nil。返回 error 会把请求的 error 换成你给的那个，`default_text` 就不是默认用法了。
- 钩子是在拨号协程里调用的，一个步骤可能触发多次（并发、重试），记录要加锁、按步骤归档。
- 这个钩子对 SOCKS5 不起作用。SOCKS5 失败没有任何额外手段，`extra_text` 留空。
- `ProxyConnectHeader`、`GetProxyConnectHeader` 是往 CONNECT **里加头**的，看不到响应，不算。
  `net/http/httptrace` 的回调里（`httptrace/trace.go:85-163`）没有一个给出 CONNECT 的响应，也不算。

明文请求的代理报错本来就是完整的响应，不需要额外手段。

## 8. 版本相关的坑

- **socks5h**：1.23 起才认 `socks5h` 这个 scheme（1.22 的 `transport.go:117` 只列 `socks5`；1.23 的 `:119-121` 加上 `socks5h` 并写明两者相同）。
  1.22 及以前只能写 `socks5`，行为同样是域名交给代理。
- **ClientHello 的大小**：1.23 默认启用 `X25519Kyber768Draft00`（发行说明 1.23 的 crypto/tls 一节，`GODEBUG=tlskyber=0` 关闭）；
  1.24 换成 `X25519MLKEM768`（发行说明 1.24，`GODEBUG=tlsmlkem=0` 关闭；`crypto/tls/defaults.go:20-25`），并且同时发 X25519 的 key share
  （`crypto/tls/handshake_client.go:162-186`）。照 `crypto/tls/handshake_messages.go:104-345` 逐项数，A02 的 ClientHello 是 **1492 字节**（含 5 字节记录头），
  超过一个以太网 TCP 包的载荷。1.22 及以前只有几百字节。**GODEBUG 的默认值跟 `go.mod` 的 `go` 行走**，见第 0 节。
  运行时把 `go.mod` 的 `go` 行和 `GODEBUG` 环境变量的值一并写进 `versions`。
- **`OnProxyConnectResponse`**：1.20 加入（发行说明 1.20 的 net/http 一节）。更早的版本没有任何办法看到 CONNECT 响应的状态码和头。
- **`ProxyConnectHeader`** 是 1.8 加入的，**`GetProxyConnectHeader`** 是 1.16（`/usr/local/go/api/go1.8.txt:205`、`go1.16.txt:371`）；这一列两个都不用。
- 1.24.7 与 `release-branch.go1.25` 的 `dialConn`、`shouldRetryRequest` 逐行比过，没有差别；与 1.23 相比，`dialConn` 只多了“明文 HTTP/2”那一段（`transport.go:1912-1928`），
  默认配置下不生效。也就是说 CONNECT 的构造、非 200 的 error 文字、重试规则在 1.23 到 1.25 之间没变。
- CONNECT 非 200 的 error 只有原因短语这件事由来已久；代码里 `resp.StatusCode != 200`，**201、204 之类的 2xx 也算失败**（`transport.go:1896`）。
- `Proxy-Authorization` 由 Transport 加（明文在 `extraHeaders` 里，HTTPS 在 CONNECT 里）。调用方自己写进 `req.Header` 的同名头不在
  `Request.write` 的排除名单里（`request.go:99-105`），会原样随请求发出，HTTPS 时就是发进隧道、到源站（这一句是读代码推的，未验证）。驱动不要自己设这个头。

## 9. 驱动的其他细节

- 环境：PROTOCOL 要求不继承代理变量。克隆之后 `Proxy` 被显式覆盖，环境变量本来也不起作用；`SSL_CERT_FILE` 之外不需要别的变量。
  不要设 `GODEBUG`。
- 超时：`http.Client{Timeout: timeout_s 秒}`（`client.go` 里 `Client.Timeout` 的文档）。它覆盖整个请求，包括读正文。
- `user` 为 `null` 的步骤：`Proxy` 返回不带 `User` 的 URL（`u.User == nil`）。不要返回带空用户名的 userinfo，那样会发 `Proxy-Authorization: Basic Og==`。
- 一个用例一个 `Transport`、一个 `Client`，从头用到尾；用例结束时 `tr.CloseIdleConnections()`。
- `config` 字段照实写：`http.DefaultTransport.(*http.Transport).Clone()`，`Proxy` 的写法（固定 URL 还是按 context 选），userinfo 用 `url.UserPassword`，
  `SSL_CERT_FILE`，有没有装 `OnProxyConnectResponse`（装了也只是旁听，返回 nil）。
- 构建：`go build` 需要的只有标准库。`go.mod` 里不写 `godebug` 行，不写 `toolchain` 行以外的东西。
