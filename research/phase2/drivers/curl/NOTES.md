# curl 命令行：给写驱动的人的笔记

写于 2026-11-10，只凭文档和源码，**没有做任何实测**。对应两列：`curl`（`-x` 配代理、`-U` 给凭据）和
`curl-anyauth`（另加 `--proxy-anyauth`）。逐行的预期在 `expectations/curl.json`、`expectations/curl-anyauth.json`。

出处的写法：`lib/…:行号`、`src/…:行号`、`docs/…` 都指上游标签 `curl-8_5_0`
（`https://raw.githubusercontent.com/curl/curl/curl-8_5_0/` 下的同名文件）。“手册”指本机 `curl --manual`。

## 版本：本机的 curl 不是上游的 8.5.0 原版

`curl --version` 报的是 `curl 8.5.0 … libcurl/8.5.0 OpenSSL/3.0.13 … nghttp2/1.59.0`，下一行写着
`security patched: 8.5.0-2ubuntu10.16`。这是 Ubuntu 24.04 的包，在 8.5.0 上叠了几十个安全补丁
（`/usr/share/doc/libcurl4t64/changelog.Debian.gz`）。和这次测量有关的有两个：

| 补丁 | 变更记录里的说明 | 影响 |
| --- | --- | --- |
| CVE-2026-3784（10.8） | wrong proxy connection reuse with credentials，改 `lib/url.c` | 上游 8.5.0 复用到 HTTP 代理的连接和隧道时不比代理凭据（`lib/url.c:699-708`）；上游的修复（8.19.0）让 `proxy_info_matches` 同时比较代理用户名和密码。矩阵的 R42 取决于它 |
| CVE-2026-6253（10.9） | clear the proxy credentials as well on port or scheme change，改 `lib/transfer.*` | 跟随重定向换了端口或协议时处理代理凭据。上游的修复（8.20.0）是恢复成选项里设的值，`-U` 设的凭据不受影响。R40 取决于它 |

补丁正文**没有读到**（存放补丁的站点从这台机器访问不了），上面“影响”一栏是从变更记录和上游后续版本的源码推出来的，属于**未验证**。
结果里的版本号除了 `8.5.0`，最好把 `security patched` 那一行也记下来：驱动的 `curl_versions()` 现在只留了第一行和 `Release-Date` 的日期部分。

这个构建的特性（`curl --version` 的 Features、Protocols）：

- 有 `HTTP2`、`NTLM`、`SPNEGO`、`GSS-API`、`AsynchDNS`、`IPv6`。`GSS-API` 影响 SOCKS5 问候里提供的方法（见下），`NTLM` 影响 `--proxy-anyauth` 时的连接复用（见下）。
- Protocols 里**没有 `ws`、`wss`**：8.5.0 的 WebSocket 还是实验特性，这个包没编进去。A15、A16 的 `only` 本来也不含 curl。

## 代理怎么配

| 用途 | 惯用写法 | 出处 |
| --- | --- | --- |
| HTTP 代理 | `curl -x http://127.0.0.1:端口 URL` | `docs/cmdline-opts/proxy.d`：不写协议或写 `http://` 都当作 HTTP 代理；不写端口默认 1080 |
| SOCKS5 代理，域名交给代理解析 | `curl -x socks5h://127.0.0.1:端口 URL`（等价的老写法是 `--socks5-hostname 主机:端口`） | `proxy.d`、`docs/cmdline-opts/socks5-hostname.d`；`lib/url.c:2210-2211` |
| SOCKS5 代理，curl 自己解析 | `curl -x socks5://127.0.0.1:端口 URL`（老写法 `--socks5`） | `lib/url.c:2212-2213`、`lib/socks.c:577-578` |
| 凭据 | `-U 用户名:密码`（`--proxy-user`），HTTP 代理和 SOCKS5 代理通用 | `docs/cmdline-opts/proxy-user.d`；SOCKS5 用的就是这一对（`lib/url.c:2531-2539`） |
| 凭据（另一种写法，这次不测） | 写进代理 URL：`-x http://用户名:密码@主机:端口`，要按 URL 的规则转义 | `proxy.d`：“User and password that might be provided in the proxy string are URL decoded by curl” |

要点：

- `https://` 目标经 HTTP 代理一定走 CONNECT；`http://` 目标发绝对形式的请求，除非加 `-p/--proxytunnel`（`src/tool_operate.c:1372`，这次不加）。
- curl 默认会读环境变量 `http_proxy`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY`（`lib/url.c:2081` 起的 `detect_proxy`、`:2434-2449`）。
  `-x` 压过代理变量，但 `NO_PROXY` 仍然生效，所以驱动要在干净的环境里启动。源码里没有对 `localhost`、回环地址的特判。
- `-U` 的值里没有冒号时，curl 会在终端上**提示输入密码**（`src/tool_paramhlp.c:507-541`）。空密码要写成 `-U 用户名:`，不能省掉冒号；
  驱动的 `"%s:%s" % (user, pass)` 是对的。

### `-U` 的字节处理（最容易踩的坑）

1. 按**第一个冒号**拆成用户名和密码（`lib/setopt.c:110-127`、`lib/url.c:2598-2618`）。分号不是分隔符。
2. 用户名和密码各做一次 **URL 解码**（`lib/url.c:2370-2389`）。手册里 `-U` 一节没有写这一点，写在
   `docs/libcurl/opts/CURLOPT_PROXYUSERPWD.3`：“Both the name and the password are URL decoded before used, so to include for example a colon in the user name you should encode it as %3A.
   (This is different to how CURLOPT_USERPWD(3) is used - beware.)”。加号不会变成空格。
3. HTTP 代理：`Proxy-Authorization: Basic base64(用户名:密码)`（`lib/http.c:351-381`），字节原样，不做字符集转换，不看质询里的 `charset`。
4. SOCKS5：解码后的用户名、密码原样写进 RFC 1929 的报文（`lib/socks.c:714-749`）。

按惯用写法（原样传 `-U`，不转义），预期是：

| 输入 | HTTP 代理收到 | SOCKS5 代理收到 |
| --- | --- | --- |
| 用户名含 `%41` | `%41` 变成 `A`（变了） | 同左（变了） |
| 密码含 `%2F` | `%2F` 变成 `/`（变了） | 同左（变了） |
| 用户名含冒号 `sess:ab12` | 拼回去的字节相同（矩阵记“原样”），但 curl 认为用户名是 `sess` | UNAME 是 `sess`，PASSWD 是 `ab12:…`（变了） |
| `@`、`+`、`/`、空格、UTF-8 | 原样 | 原样 |

要让代理收到字面的 `%` 或用户名里的冒号，得写成 `%25`、`%3A`。这属于“为了测试改写法”，驱动不做；但报告里应该写明。

长度：HTTP 这一侧没有 255 的界限，`-U` 的上限是 8000000 字节（`lib/urldata.h:120`、`lib/setopt.c:119-121`）。
SOCKS5 用户名或密码超过 255 字节时 curl 在客户端报错（`lib/socks.c:729-733`：`Excessive user name length for proxy auth`，
`:739-743`：`Excessive password length for proxy auth`，退出码 97），认证报文不会发出。

## 认证流程

| | `curl`（默认） | `curl-anyauth` |
| --- | --- | --- |
| 第一个请求或 CONNECT | 直接带 `Proxy-Authorization: Basic`（`lib/http.c:907-911`、`:793-806`；`proxy-basic.d`：Basic 是默认方法） | 不带；等 407 里的 `Proxy-Authenticate: Basic` 再选方法重发（`src/tool_operate.c:1379-1381`、`lib/http.c:673-698`、`:1128-1131`；`proxy-anyauth.d`：可能多一个来回） |
| 407 之后（明文） | 带着 Basic 还收到 407：判为认证问题，407 当普通响应返回，不重试（`lib/http.c:1132-1139`） | 407 的正文读完，连接留着就在原连接上重发；407 带 `Connection: close` 就另开连接重发 |
| 407 之后（CONNECT） | 同上，随后报 `CONNECT tunnel failed, response 407` | 按 `Content-Length` 把 407 的正文读掉，在原连接上重发 CONNECT（`lib/cf-h1-proxy.c:489-498`、`:941-965`）；带 `Connection: close` 时关掉重连再发（`:948-960`，`-v` 里能看到 `Connect me again please`） |
| 代理不要求认证 | 照样带 | 一直不带 |
| 同一进程的下一个 URL | 每个 URL 都先带 | **每个 URL 都重新来一遍“不带 → 407 → 带”**：认证状态记在 easy 句柄上，工具给每个 URL 一个新句柄（`src/tool_operate.c:963`） |

- CONNECT 请求：`CONNECT 主机:端口 HTTP/1.1`，头依次是 `Host`、（`Proxy-Authorization`）、`User-Agent`、`Proxy-Connection: Keep-Alive`
  （`lib/http_proxy.c:84-147`、`lib/cf-h1-proxy.c:243-245`）。`-H` 加的头不进 CONNECT（要用 `--proxy-header`）。
- 明文请求：`Host`、（`Proxy-Authorization`）、`User-Agent`、`Accept`、`Proxy-Connection: Keep-Alive`（`lib/http.c:3309-3349`）。
- 隧道建成后 `Proxy-Authorization` 被清掉，隧道里的请求不带它（`lib/cf-h1-proxy.c:196-199`、`lib/http.c:915-927`）。
- 带正文的 POST 遇到 `--proxy-anyauth`：第一遍不带凭据但正文照发（方法还没选定，不算协商中，`lib/http.c:940-949`）。
  如果 407 到的时候正文还没发完，curl 会直接关连接（`lib/http.c:557`、`:617-619`：`Mid-auth HTTP and much data left to send`）。
  仪器是读完正文才回 407 的，所以不会走到这一步。
- `Expect: 100-continue`：8.5.0 的阈值是 1 MiB（`lib/http.h:186-188` 的 `EXPECT_100_THRESHOLD`，`lib/http.c:2535`、`:2709`），正文超过它或长度未知时才发。
  等 100 的超时默认 1 秒（`CURLOPT_EXPECT_100_TIMEOUT_MS`）。

## 同一个进程里对不同请求用不同的代理凭据

有：`--next`。它开始一个新的“操作”，局部选项（`-x`、`-U`、`--proxy-anyauth`、`--cacert`、`-L`、`-d`、`-o`、`-w` 等）要重写，
全局选项（`-v`、`--parallel`、`--rate`、`--fail-early` 等）沿用（`docs/cmdline-opts/next.d`）。

```sh
curl -x http://127.0.0.1:端口 -U 用户甲:密码甲 URL1 --next -x http://127.0.0.1:端口 -U 用户乙:密码乙 URL2
```

连接缓存在整个进程里是同一个：每个 URL 一个 easy 句柄，都挂在同一个 share 上，share 共享连接、DNS、TLS 会话
（`src/tool_operate.c:1282`、`:2778-2794`）。所以 `--next` 不清连接缓存，前一段留下的连接后一段能复用。

哪些连接能复用（`lib/url.c:913-1310` 的 `ConnectionExists`，连接束的键在 `lib/conncache.c:126-150`）：

| 情况 | 上游 8.5.0 | 备注 |
| --- | --- | --- |
| 明文经 HTTP 代理 | 键是代理的主机和端口，不比目标主机，也不比代理凭据；每个请求带自己的 `Proxy-Authorization` | 打了 CVE-2026-3784 补丁后，不同凭据应当各用各的连接（未验证） |
| HTTPS 经 HTTP 代理（隧道） | 键是目标主机和端口；**不比代理凭据**，第二个用户会用上第一个用户建的隧道 | 本机的包打了补丁，预期不会（未验证）。R42 就看这个 |
| SOCKS5 | 比 SOCKS 代理的主机、端口、用户名、密码（`lib/url.c:710-727`、`:1073-1076`） | |
| 加了 `--proxy-anyauth` 又给了 `-U` | 走 NTLM 的分支：只复用代理用户名、密码都相同的连接（`lib/url.c:930-933`、`:1238-1247`） | 这条分支里不做“连接是否已断”的检查（在 `:1254-1270` 就 `continue` 了）；SOCKS 连接的 `http_proxy.user` 为空，所以 `--proxy-anyauth` 加 `-U` 加 SOCKS 时完全不复用连接 |

## 信任测试用的 CA

`--cacert 文件`（每个 `--next` 段都要写）。它只换掉校验源站证书用的 CA 文件，不影响代理行为、ALPN 和 HTTP 版本
（`docs/cmdline-opts/cacert.d`）。等价的还有环境变量 `CURL_CA_BUNDLE`。不要用 `-k`。
`--proxy-cacert` 是给 `https://` 代理用的，这次用不到。

连接复用时会比较 TLS 配置（`lib/url.c:1203-1211`），各段的 `--cacert` 要一致，否则同一个源也不复用。

## 并发、重定向、POST

| 要做的事 | 写法 | 出处和注意 |
| --- | --- | --- |
| 并发 6 个 | `--parallel --parallel-max 6 URL1 … URL6`（`-Z`） | `parallel.d`、`parallel-max.d`。全局选项，一个进程里要么全并发要么全串行 |
| 跟随重定向 | `-L` | `location.d`。默认最多 50 跳 |
| POST | `--data-binary @文件 -H 'Content-Type: application/octet-stream'` | 文件整个读进内存，发 `Content-Length`（`src/tool_operate.c:1435-1438`）。`-d @文件` 会去掉换行，不能用来发二进制 |
| 等一会儿 | 没有专门的写法。`--rate N/单位` 规定相邻两次传输**开始时刻**的最小间隔 | `rate.d`（7.84.0 加入）。对 `--parallel` 无效 |

`--parallel` 并不等于“同时发出”。没有 `--parallel-immediate` 时，工具给每个传输设 `CURLOPT_PIPEWAIT`
（`src/tool_operate.c:2299-2302`；`parallel-immediate.d`：默认“宁可等一等，看能不能复用成多路复用的流”）。
工具默认的 HTTP 版本是 `2TLS`（`:1495-1498`），libcurl 因此认为“也许能多路复用”，在还不知道对端支不支持之前，
同一个连接束的后续传输都先挂起（`lib/url.c:960-967`）。按源码推出来的结果：

| 用例 | 预期 | 原因 |
| --- | --- | --- |
| HTTPS，源站支持 h2 | 1 条隧道，6 个流 | 第一条隧道的 ALPN 定下是 h2，其余传输加到它上面 |
| HTTPS，源站只说 HTTP/1.1 | 6 条隧道，但后 5 条是在第一条握手完成之后才开的 | ALPN 定下以后放出挂起的传输（`lib/vtls/vtls.c:2151-2153`、`lib/multi.c:3664-3702`、`:1936-1941`） |
| 明文经代理 | 5 条连接：第 1 个请求先单独跑完，第 2 个复用它的连接，其余 4 个另开 | 明文要等第一个响应的状态行才知道不能多路复用（`lib/http.c:4487-4489`），叫醒发生在第一个传输结束时（`lib/multi.c:696`） |

也就是说，明文的 6 个“并发”请求里第一个是先单独发的，总耗时大约是两个请求的时长。这是 curl 按默认用法的真实行为，
驱动不要为了“真并发”加 `--parallel-immediate`；需要的话可以作为另一列。

## 代理出错时调用方能拿到什么

默认用法（不加 `-v`、`-i`、`-D`）下，命令行的调用方只有：退出码、标准错误里的一行 `curl: (N) 文字`、标准输出（或 `-o` 的文件）里的响应正文。
状态码本身要靠 `-w '%{http_code}'` 才拿得到，驱动把它算进了 `default_text`（见文末“口径上的疑问”）。

| 情况 | 退出码 | 标准错误 | 出处 |
| --- | --- | --- | --- |
| CONNECT 回非 2xx（含认证失败后的 407、403） | 56 | `curl: (56) CONNECT tunnel failed, response <状态码>` | `lib/cf-h1-proxy.c:975-982` |
| CONNECT 发出后代理直接关连接 | 56 | `curl: (56) Proxy CONNECT aborted` | `lib/cf-h1-proxy.c:407-420` |
| 明文请求被代理回 407、403 等 | 0 | 无；这是普通响应，正文照常输出（加 `-f` 才变成退出码 22） | `lib/http.c:1187-1253` |
| 明文请求发出后连接被关、没有任何响应（新连接上） | 52 | `curl: (52) Empty reply from server` | `lib/http.c:1648-1654` |
| SOCKS5：代理回 `0xFF` | 97 | `curl: (97) No authentication method was acceptable.` | `lib/socks.c:689-691` |
| SOCKS5：用户名密码被拒 | 97 | `curl: (97) User was rejected by the SOCKS5 server (1 <状态>).` | `lib/socks.c:776-779` |
| SOCKS5：应答码非 0 | 97 | `curl: (97) Can't complete SOCKS5 connection to <主机>. (<应答码>)` | `lib/socks.c:978-982` |
| SOCKS5：`socks5://` 下本地解析失败 | 97 | 解析失败的文字 | `lib/socks.c:787-842`；注意这时已经连上代理并完成了方法协商 |
| SOCKS5：用户名超过 255 字节 | 97 | `curl: (97) Excessive user name length for proxy auth` | `lib/socks.c:729-733` |

手册对这几个退出码的说明：52“The server did not reply anything”，56“Failure in receiving network data”，97“Proxy handshake error”。

CONNECT 失败时 curl **不读响应正文**（407 且准备重试时才按长度读掉，`lib/cf-h1-proxy.c:489-534`），所以正文里的说明无论用什么手段都看不到；
失败后这条连接一律关掉，不管代理有没有要求关（`:978-980`）。CONNECT 失败以后 `%{http_code}` 是 `000`（`:194` 把它清零），状态码在 `%{http_connect}` 里。

文档里写明、需要主动打开的额外手段（`extra_text` 的候选）：

| 手段 | 能多看到什么 | 出处 |
| --- | --- | --- |
| `-v`（配 `--trace-ids` 便于按传输切分，8.2.0 加入） | CONNECT 的请求、响应的状态行和每个头；选了哪种认证；连接是否复用（`Re-using existing connection`）；`Connect me again please` 之类的过程 | 手册 `-v`；`lib/cf-h1-proxy.c:282`、`:467-468` |
| `-D 文件` 或 `-i` | 响应头，**包括 CONNECT 的响应头**（除非加 `--suppress-connect-headers`） | `dump-header.d`、`suppress-connect-headers.d`；`lib/cf-h1-proxy.c:470-473` |
| `-w '%{http_connect}'` | 最后一次 CONNECT 的状态码 | `write-out.d` |
| `-w '%{errormsg}'`、`'%{exitcode}'`、`'%{json}'` | 每次传输各自的报错文字和退出码（串行多个 URL 时进程退出码只反映最后一个出错的） | `write-out.d` |
| `--retry N` | 对超时和 408、429、500、502、503、504 重试，认 `Retry-After` | `retry.d`。默认不重试，驱动不加 |

SOCKS5 的失败细分（`CURLINFO_PROXY_ERROR`，`CURLPX_*`）只有库接口，8.5.0 的命令行没有对应的 `-w` 变量（`write-out.d` 里没有），只能看报错文字。

## 连接被关以后

- 复用前先探测连接是否已断（`lib/url.c:776-826`、`:1291-1295`），已断就换新连接，调用方无感。
- 请求发出后一个字节都没收到，而且用的是**复用的**连接：自动在新连接上重发，最多 5 次，**不看方法，POST 也重发**
  （`lib/transfer.c:1757-1824` 的 `Curl_retry_request`，`lib/multi.c:2404-2423`）。`-v` 里是 `Connection died, retrying a fresh connect`。
  这与 `--retry` 无关，默认就有，也关不掉。
- 新连接上的第一个请求没有这种重发；CONNECT 阶段的失败也没有。

## SOCKS5 的细节

- 问候里提供的方法：`0`，构建带 GSS-API 时加 `1`，有用户名时加 `2`（`lib/socks.c:606-620`；`CURLOPT_SOCKS5_AUTH` 默认 `Basic|GSSAPI`，`lib/url.c:399`）。
  本机构建带 GSS-API，预期没配凭据时是 `00,01`，配了是 `00,01,02`。`--socks5-basic` 可以只留用户名密码，这次不加。
- `socks5h://`：域名以 ATYP=3 交给代理（`lib/socks.c:896-921`）；域名超过 255 字节在客户端报错（`:593-597`）。
- `socks5://`：先连代理、协商方法、认证，然后才在本地解析（`lib/socks.c:787-800`）。`localhost` 不查 DNS，用写死的地址表，`::1` 在前
  （`lib/hostip.c:565-601`、`:793-795`），所以预期发的是 ATYP=4。本地解析不了的域名：代理端口上会看到连接和问候，但没有请求。
- 经 SOCKS5 的明文请求是源站形式（`GET /路径`），HTTPS 直接开始 TLS，没有 CONNECT。

## 版本相关的坑

| 版本 | 变化 | 出处 |
| --- | --- | --- |
| 7.36.0 | `--next` | `next.d` |
| 7.54.0 | `--suppress-connect-headers` | `suppress-connect-headers.d` |
| 7.55.0 | `--socks5-basic`、`--socks5-gssapi` | `socks5-basic.d` |
| 7.66.0 | `--parallel` | `parallel.d` |
| 7.68.0 | `--parallel-immediate` | `parallel-immediate.d` |
| 7.84.0 | `--rate` | `rate.d` |
| 8.2.0 | `--trace-ids` | `trace-ids.d`。驱动用的 `-w` 变量 `xfer_id`、`conn_id` 在 8.5.0 的源码里有（`src/tool_writeout.c:78`、`:149`），但 8.5.0 的 `write-out.d` 没有写；哪个版本加的未验证 |
| 8.5.0（本次） | `Expect: 100-continue` 的阈值是 1 MiB；WebSocket 是实验特性，Ubuntu 的包没编进去 | `lib/http.h:186-188`；`curl --version` |
| 8.19.0（上游） | HTTP 代理连接和隧道的复用开始比较代理凭据（CVE-2026-3784）。Ubuntu 把它补进了 8.5.0-2ubuntu10.8 | curl-8_19_0 的 `lib/url.c:588-601`；本机的变更记录 |
| 8.20.0（上游） | 跟随重定向时把代理凭据恢复成选项里设的值（CVE-2026-6253）。Ubuntu 补进了 8.5.0-2ubuntu10.9 | curl-8_20_0 的 `lib/transfer.c:457-473`、`lib/http.c:1263`；本机的变更记录 |

`docs/KNOWN_BUGS` 6.6：`--proxy-anyauth` 遇到同时通告 Negotiate 和 NTLM 的代理，一种方法失败后不会换另一种。只发 Basic 质询时碰不到。

没有查清、标**未验证**的：

- `Expect` 阈值是在哪个版本从 1024 字节改成 1 MiB 的（只确认了 8.5.0 的值）。
- 上面两个 Ubuntu 补丁的正文。
- ClientHello 的确切长度（只按 OpenSSL 3.0 没有后量子密钥交换估计在五百多字节）。

## 口径上的疑问（留给定方案的人）

1. `default_text` 里有 `-w '%{http_code}'` 的值。不加 `-w` 时，curl 对一个普通的 403 响应什么都不提示（退出码 0、标准错误为空），
   状态码不可见。R86 的“状态码”因此是 `-w` 带来的；`-i` 也是很常见的写法，加了它原因短语和响应头就都看得见。哪一种算“默认用法”需要在报告里写明。
2. R114 的三个取值没有覆盖 curl 的做法（先连代理、协商完才解析），只能落到“其他”。
3. R119、R120 的关键词表里没有 `user`、`rejected`：curl 对密码错的报错是 `User was rejected by the SOCKS5 server`，
   明明在说认证，按规则却记成“只说失败”。
4. R70 与 R132：同一个 `-U sess:ab12:密码`，HTTP 那边因为是拼接后比较记“原样”，SOCKS5 那边记“变了”，其实是同一件事（按第一个冒号拆）。
5. PROTOCOL 写“其余端口按连不上处理”，但 `harness/server.go:293-295` 把目标端口等于内置源站端口的也接到内置源站（A10、A11、S03 靠这个）。
6. 明文 6 个“并发”在 curl 的默认用法下不是同时发出的（见上），与 PROTOCOL“`parallel` 里的请求要同时发出”有出入。
