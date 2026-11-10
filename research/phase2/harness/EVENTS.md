# obsproxy 的事件格式

事件格式第 1 版（`start.events_version`）。抓包核对（`pcap_check.py`）和事实提取（`derive.py`）以本文件为准。
字段有不兼容的改动时版本号加一，并在文末记下改了什么。

事件有哪些、各自记什么，由 [`../PROTOCOL.md`](../PROTOCOL.md) 的事件表规定；这里给出确切的字段名、类型和例子。
例子都是真实的输出，取自单元测试留下的事件文件（`OBSPROXY_TEST_DUMP=目录 go test ./...`），没有改动。

## 通用约定

- 文件是 JSONL：每行一个 JSON 对象，以 `\n` 结尾。每个事件一次写完整行，写完即落到文件上，没有用户态缓冲。
- 第一行是 `start`，最后一行是 `end`。没有 `end` 的文件说明仪器不是正常退出的，这次运行不能用。
- 每个事件都有 `t` 和 `ev`，字段的先后固定（`t`、`ev`、`conn` 在最前）。下面的表按字段出现的顺序列出。
- 表里列出的字段**总是出现**；不适用时值是 `null`，不会省略。唯一的例外是 `late`（见下）。
- 字符串不做 HTML 转义。不是合法 UTF-8 的字节不会出现在字符串字段里：相应的字段是 `null`，原样的字节看同名的 `_hex` 字段。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `t` | 数 | 仪器启动以来的毫秒数，保留到微秒。写事件时取值，所以文件里的 `t` 不会倒退 |
| `ev` | 字符串 | 事件名 |
| `conn` | 整数 | 连接编号：三个监听端口上每接受一条 TCP 连接加一，从 1 开始。除 `start`、`end` 外每个事件都有 |
| `late` | `true` | 只在一种情况下出现：这个事件是在它那条连接的 `conn_end` 之后才写出来的（处理协程与关闭赛跑）。正常运行里不应出现；出现了说明事件的先后不可靠 |

编号都是整个运行里唯一的：`conn`（连接）、`tunnel`（隧道）、`oconn`（源站连接）各自从 1 开始计数。
`seq` 是某条连接上的序号（见各事件）。

一条连接上事件的先后：`accept` 最先，`conn_end` 最后；有隧道时 `tunnel_close` 紧挨在 `conn_end` 之前。
不同连接的事件按写出的时刻交错。

几个到处用到的取值：

- 监听端口 `listener`：`proxy`（代理端口）、`origin_http`（明文源站端口上的直连）、`origin_https`（HTTPS 源站端口上的直连）。
- 头的列表 `headers`：`[[名, 值], …]`。
- 十六进制一律小写、不带分隔符。

## start

仪器开始接受连接之前写。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `version` | 字符串 | obsproxy 的版本 |
| `events_version` | 整数 | 事件格式的版本，本文件是 1 |
| `go` | 字符串 | 编译用的 Go 版本 |
| `pid` | 整数 | 进程号 |
| `started_at` | 字符串 | `t=0` 对应的时刻，RFC 3339，UTC |
| `proxy_port`、`origin_http_port`、`origin_https_port` | 整数 | 三个监听端口（都在 127.0.0.1 上） |
| `max_seconds` | 整数 | `-max-seconds` 的值；0 表示不限 |
| `profile` | 对象 | 实际生效的配置：没写的字段已经填上默认值，结构与 PROTOCOL.md 里的配置相同。`connect.fail`、`forward.fail` 非空时带全六个字段，三个 `drop` 非空时带全四个字段 |

```json
{"t":0.766,"ev":"start","version":"1.0.0","events_version":1,"go":"go1.24.7","pid":10408,"started_at":"2026-11-10T13:47:18.662933967Z","proxy_port":35003,"origin_http_port":41361,"origin_https_port":45587,"max_seconds":120,"profile":{"auth":{"mode":"none","accept":[],"accept_any_user":false,"challenge":["Basic realm=\"kaoju\""],"on407":"keepalive","reject_status":407},"connect":{"ok_headers":[],"fail":null,"drop":null},"forward":{"fail":null,"add_response_headers":[],"send_100_continue":true},"conn":{"idle_close_ms":0,"drop":null},"tunnel":{"idle_close_ms":0},"origin":{"h2":true,"drop":null},"socks":{"auth":"none","auth_fail_status":1,"rep":0}}}
```

## end

最后一行。写完以后不再有任何事件。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `reason` | 字符串 | 为什么退出：`signal:SIGTERM`、`signal:SIGINT`、`max_seconds` |
| `version` | 字符串 | 同 `start` |
| `proxy_port`、`origin_http_port`、`origin_https_port` | 整数 | 同 `start` |
| `conns` | 整数 | 一共接受了多少条连接（等于 `accept` 的个数） |
| `tunnels` | 整数 | 一共开了多少条隧道（等于 `tunnel_open` 的个数） |
| `oconns` | 整数 | 一共有多少条源站连接（等于 `origin_conn` 的个数） |
| `events` | 整数 | 文件的总行数，含 `start` 和 `end` 自己 |

```json
{"t":221.214,"ev":"end","reason":"signal:SIGTERM","version":"1.0.0","proxy_port":35003,"origin_http_port":41361,"origin_https_port":45587,"conns":6,"tunnels":1,"oconns":1,"events":28}
```

## accept

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | 新连接的编号 |
| `listener` | 字符串 | 哪个监听端口 |
| `peer_port` | 整数 | 对端（客户端）的端口。对端地址总是 127.0.0.1。抓包核对用“对端端口加监听端口”对上包里的连接 |

```json
{"t":0.498,"ev":"accept","conn":1,"listener":"proxy","peer_port":44720}
```

## first_bytes

连接上第一次读到数据时写。对端一个字节都没发就关了的连接没有这个事件。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `listener` | 字符串 | 同 `accept` |
| `n_first_read` | 整数 | 第一次读系统调用读到的字节数（缓冲区 64 KiB） |
| `hex` | 字符串 | 这些字节里的前 16 个（不足 16 个就是全部） |
| `kind` | 字符串 | 按第一个字节归类：`socks5`（0x05）、`socks4`（0x04）、`tls`（0x16）、`http`（英文字母）、`other` |

代理端口上，`socks4` 和 `tls` 只记录然后按 `fin` 关（`conn_end.reason` 是 `socks4_unsupported`、`tls_on_proxy_port`）；
`http` 和 `other` 都交给 HTTP 入口解析。源站端口上的直连也按同样的规则归类，但不据此分流。

```json
{"t":0.709,"ev":"first_bytes","conn":1,"listener":"proxy","n_first_read":175,"hex":"47455420687474703a2f2f612e6b616f","kind":"http"}
```

## http_request

代理端口上的 HTTP 入口每收到一个请求写一个。**在请求的正文读完以后写**（`t_head` 是请求头读完的时刻），
所以 `Expect: 100-continue` 的那个 100 的 `http_response` 排在它前面。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `seq` | 整数 | 这条连接上的第几个请求，从 1 开始 |
| `t_head` | 数 | 请求头读完的时刻（与 `t` 同一个时钟） |
| `form` | 字符串 | `connect`（方法是 CONNECT）、`absolute`（目标以 `scheme://` 开头）、`origin`（目标以 `/` 开头）、`other` |
| `method`、`target`、`version` | 字符串 | 请求行的三段，原样。解析不出来的段是空串 |
| `k` | 字符串或 `null` | 请求目标的查询参数 `k`（做过百分号解码）。CONNECT 一律是 `null` |
| `headers` | 头的列表 | 全部头，原顺序、原大小写。值去掉了首尾的空格和制表符，其余原样 |
| `head_b64` | 字符串 | 请求头的原始字节（请求行到空行，含空行）的标准 base64。请求行之前的空行不算在内 |
| `body_len` | 整数 | 正文的字节数；chunked 的是解开以后的长度 |
| `body_sha256` | 字符串 | 正文的 SHA-256（chunked 的是解开以后的）；没有正文时是空串的哈希 |
| `auth` | 对象 | 对 `Proxy-Authorization` 的解析和判定，见下 |
| `error` | 字符串或 `null` | 请求有问题时的说明，以下列之一开头：`incomplete_head`（头没发完连接就断了）、`head_too_large`（超过 64 KiB，回 431）、`bad_head`（回 400）、`unsupported_version`（回 505）、`bad_framing`（回 400）、`bad_body`（chunked 格式不对，回 400）、`incomplete_body`（正文没发完连接就断了） |

`auth` 对象（有多个 `Proxy-Authorization` 头时只看第一个）：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `present` | 布尔 | 请求有没有 `Proxy-Authorization` 头 |
| `scheme` | 字符串或 `null` | 方案名，原大小写 |
| `raw` | 字符串或 `null` | 头的值，原样（`headers` 里那一项的值） |
| `user`、`pass` | 字符串或 `null` | base64 解开以后按第一个冒号拆出的用户名和密码；不是合法 UTF-8、或者没解出来时是 `null` |
| `user_hex`、`pass_hex` | 字符串或 `null` | 同上，字节的十六进制；没解出来时是 `null`。比较字节时用这两个 |
| `lenient` | 布尔 | 严格的 base64（标准字母表、带填充）解不开，放宽以后（缺填充，或 URL 字母表）才解开。这时 `result` 仍是 `malformed`，`user`、`pass` 是放宽以后解出来的 |
| `result` | 字符串 | `none`（没带）、`ok`（Basic，凭据与 `auth.accept` 相符）、`bad`（不是 Basic，或凭据不符）、`malformed`（Basic 但 base64 解不开，或解开以后没有冒号） |

`result` 只是把凭据与配置比较，与 `auth.mode` 无关：代理不要求认证时照样记下判定，只是不据此拒绝。

```json
{"t":2.405,"ev":"http_request","conn":1,"seq":2,"t_head":2.364,"form":"absolute","method":"GET","target":"http://a.kaoju.test/echo?k=B01.s1","version":"HTTP/1.1","k":"B01.s1","headers":[["Host","a.kaoju.test"],["Proxy-Authorization","Basic a2FvanUtdXNlcjprYW9qdS1wYXNzLTE="]],"head_b64":"R0VUIGh0dHA6Ly9hLmthb2p1LnRlc3QvZWNobz9rPUIwMS5zMSBIVFRQLzEuMQ0KSG9zdDogYS5rYW9qdS50ZXN0DQpQcm94eS1BdXRob3JpemF0aW9uOiBCYXNpYyBhMkZ2YW5VdGRYTmxjanByWVc5cWRTMXdZWE56TFRFPQ0KDQo=","body_len":0,"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","auth":{"present":true,"scheme":"Basic","raw":"Basic a2FvanUtdXNlcjprYW9qdS1wYXNzLTE=","user":"kaoju-user","user_hex":"6b616f6a752d75736572","pass":"kaoju-pass-1","pass_hex":"6b616f6a752d706173732d31","lenient":false,"result":"ok"},"error":null}
```

CONNECT 的例子：

```json
{"t":0.835,"ev":"http_request","conn":1,"seq":1,"t_head":0.809,"form":"connect","method":"CONNECT","target":"a.kaoju.test:443","version":"HTTP/1.1","k":null,"headers":[["Host","a.kaoju.test:443"],["User-Agent","rawtest/1"]],"head_b64":"Q09OTkVDVCBhLmthb2p1LnRlc3Q6NDQzIEhUVFAvMS4xDQpIb3N0OiBhLmthb2p1LnRlc3Q6NDQzDQpVc2VyLUFnZW50OiByYXd0ZXN0LzENCg0K","body_len":0,"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","auth":{"present":false,"scheme":null,"raw":null,"user":null,"user_hex":null,"pass":null,"pass_hex":null,"lenient":false,"result":"none"},"error":null}
```

## http_response

代理在 HTTP 入口上每写回一个响应写一个（含 1xx）。在响应的字节写出之后写。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `seq` | 整数 | 回应的是这条连接上的第几个请求（`http_request.seq`） |
| `status` | 整数 | 状态码 |
| `reason` | 字符串 | 原因短语 |
| `headers` | 头的列表 | 写出的全部头，按写出的顺序 |
| `body_len` | 整数 | 写出的正文字节数（HEAD 的响应是 0） |
| `by` | 字符串 | `proxy`：代理自己生成的；`origin`：内置源站的处理函数生成、由代理回写的（绝对形式的请求转发成功） |
| `cause` | 字符串 | 为什么回这个响应，见下 |
| `close` | 布尔 | 写完以后代理是否关连接。关的话响应里带 `Connection: close`（响应本身已有 `Connection` 头的除外，比如 101），随后按 `fin` 关 |
| `error` | 字符串或 `null` | 写的时候出的错 |

`cause` 的取值：`forward`（转发成功）、`connect_ok`（CONNECT 的 200）、`continue`（100）、
`auth_required`（没带凭据，407）、`auth_rejected`（凭据不对，407 或 403）、
`connect_fail`、`forward_fail`（配置的 `connect.fail`、`forward.fail`）、
`unmapped_port`（目标端口没有对应的内置源站，502）、`https_absolute`（绝对形式的 `https://`，502）、
`websocket`（绝对形式的 WebSocket 握手，101）、`websocket_rejected`（握手不对）、
`bad_request`、`bad_version`、`head_too_large`、`bad_connect_target`、`bad_target`、`bad_scheme`、
`not_proxy_request`（不是绝对形式也不是 CONNECT，400）。

```json
{"t":2.127,"ev":"http_response","conn":1,"seq":1,"status":407,"reason":"Proxy Authentication Required","headers":[["Proxy-Authenticate","Basic realm=\"kaoju\""],["Proxy-Authenticate","Basic realm=\"other\", charset=\"UTF-8\""],["Content-Type","text/plain; charset=utf-8"],["Content-Length","40"]],"body_len":40,"by":"proxy","cause":"auth_required","close":false,"error":null}
```

转发成功的例子：

```json
{"t":1.536,"ev":"http_response","conn":1,"seq":1,"status":200,"reason":"OK","headers":[["Date","Tue, 10 Nov 2026 13:47:28 GMT"],["Content-Type","application/json"],["Cache-Control","no-store"],["Access-Control-Allow-Origin","*"],["Content-Length","331"]],"body_len":331,"by":"origin","cause":"forward","close":false,"error":null}
```

## tunnel_open

CONNECT 回了 200、或 SOCKS5 回了成功应答之后写。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | 隧道所在的代理连接。一条连接至多一条隧道 |
| `tunnel` | 整数 | 隧道编号 |
| `via` | 字符串 | `connect` 或 `socks5` |
| `req_seq` | 整数或 `null` | `via=connect` 时是建立它的那个 CONNECT 的 `http_request.seq`；`socks5` 时是 `null` |
| `target_host` | 字符串 | 目标主机，原样（不解析）。IPv6 不带方括号 |
| `target_port` | 整数 | 目标端口 |
| `mapped` | 字符串 | 接到了哪个内置源站：`origin_http`（端口 80 或明文源站的实际端口）、`origin_https`（443 或 HTTPS 源站的实际端口） |

```json
{"t":1.229,"ev":"tunnel_open","conn":1,"tunnel":1,"via":"connect","req_seq":1,"target_host":"a.kaoju.test","target_port":443,"mapped":"origin_https"}
```

## tunnel_first_bytes

隧道里客户端发来的首批字节。隧道里一个字节都没来就关了的没有这个事件。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn`、`tunnel` | 整数 | |
| `n_first_read` | 整数 | 隧道里第一次读到的字节数。`early_bytes` 大于 0 时等于 `early_bytes` |
| `early_bytes` | 整数 | 客户端没等 200（或 SOCKS5 应答）就发来的隧道字节数：它们是和握手一起读进来的。通常是 0 |
| `n_buffered` | 整数 | 写这个事件时手头的字节数。首包是 TLS 记录而第一次没读全时，仪器接着读到整条记录到齐（最多等 2 秒），所以它可能大于 `n_first_read`。这些字节随后原样交给源站 |
| `hex` | 字符串 | 前 16 个字节 |
| `kind` | 字符串 | `tls_client_hello`（TLS 握手记录，里面是 ClientHello）、`http`（1 到 15 个大写字母后跟一个空格）、`other` |
| `tls` | 对象或 `null` | `kind` 是 `tls_client_hello` 时的解析结果，否则 `null` |

`tls` 对象：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `record_len` | 整数 | 第一条 TLS 记录的长度，不含 5 个字节的记录头 |
| `complete` | 布尔 | 这条记录是否完整到齐（等了 2 秒还不齐就是 `false`） |
| `record_version` | 整数 | 记录头里的版本（769 即 0x0301） |
| `legacy_version` | 整数 | ClientHello 的 `legacy_version`（771 即 0x0303） |
| `sni` | 字符串或 `null` | `server_name` 扩展里的主机名；没有这个扩展是 `null` |
| `alpn` | 字符串数组 | ALPN 列表，按客户端给的顺序；没有这个扩展是 `[]` |
| `versions` | 整数数组 | `supported_versions` 扩展，含 GREASE 值 |
| `groups` | 整数数组 | `supported_groups` 扩展，含 GREASE 值 |
| `key_shares` | 整数数组 | `key_share` 扩展里各份额所属的组 |
| `parse_error` | 字符串或 `null` | 解析在哪一步停下的；完整解析是 `null` |

```json
{"t":2.18,"ev":"tunnel_first_bytes","conn":1,"tunnel":1,"n_first_read":1489,"early_bytes":0,"n_buffered":1489,"hex":"16030105cc010005c803039aa449bcec","kind":"tls_client_hello","tls":{"record_len":1484,"complete":true,"record_version":769,"legacy_version":771,"sni":"a.kaoju.test","alpn":["http/1.1"],"versions":[772,771],"groups":[4588,29,23,24,25],"key_shares":[4588,29],"parse_error":null}}
```

## tunnel_close

每个 `tunnel_open` 恰好对应一个，紧挨在所在连接的 `conn_end` 之前。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn`、`tunnel` | 整数 | |
| `by` | 字符串 | `client`（客户端先关的）、`origin`（内置源站关的，比如回完 `Connection: close` 的响应、WebSocket 发完关闭帧、TLS 握手失败）、`proxy`（仪器按配置切断，或仪器退出） |
| `reason` | 字符串 | 同这条连接的 `conn_end.reason` |
| `bytes_c2s` | 整数 | 隧道里客户端发来的字节数（含 `early_bytes`；不含 CONNECT 请求或 SOCKS5 握手） |
| `bytes_s2c` | 整数 | 隧道里写给客户端的字节数（不含 CONNECT 的 200 或 SOCKS5 的应答） |

```json
{"t":8.27,"ev":"tunnel_close","conn":1,"tunnel":1,"by":"client","reason":"client_eof","bytes_c2s":1768,"bytes_s2c":2860}
```

## socks5_greeting

代理端口上首字节是 0x05 的连接，读完方法协商的请求后写。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `version` | 整数 | VER 字节 |
| `methods` | 整数数组 | 客户端提供的方法，按原顺序（0 无认证，1 GSSAPI，2 用户名密码） |
| `raw_hex` | 字符串 | 整条消息（VER、NMETHODS、METHODS）的字节 |

```json
{"t":0.846,"ev":"socks5_greeting","conn":1,"version":5,"methods":[0,2],"raw_hex":"05020002"}
```

## socks5_method

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `selected` | 整数 | 服务端选的方法：0、2，或 255（0xFF，没有可接受的方法；回完就按 `fin` 关） |

```json
{"t":0.929,"ev":"socks5_method","conn":1,"selected":2}
```

## socks5_auth

选了方法 2 时，读完用户名密码子协商（RFC 1929）并回了状态之后写。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `version` | 整数 | 子协商的 VER 字节（应为 1） |
| `ulen`、`plen` | 整数 | 用户名、密码的长度字节 |
| `user`、`pass` | 字符串或 `null` | 用户名、密码；不是合法 UTF-8 时是 `null` |
| `user_hex`、`pass_hex` | 字符串 | 同上，字节的十六进制（长度为 0 时是空串） |
| `status` | 整数 | 回给客户端的状态字节：0 成功；失败时是配置的 `socks.auth_fail_status` |
| `result` | 字符串 | `ok`、`bad`（凭据不符）、`malformed`（VER 不是 1） |

```json
{"t":1.052,"ev":"socks5_auth","conn":1,"version":1,"ulen":10,"plen":12,"user":"kaoju-user","user_hex":"6b616f6a752d75736572","pass":"kaoju-pass-1","pass_hex":"6b616f6a752d706173732d31","status":0,"result":"ok"}
```

## socks5_request

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `version` | 整数 | VER 字节 |
| `cmd` | 整数 | 命令：1 CONNECT，2 BIND，3 UDP ASSOCIATE |
| `rsv` | 整数 | 保留字节，照实记录 |
| `atyp` | 整数 | 地址类型：1 IPv4，3 域名，4 IPv6 |
| `host` | 字符串或 `null` | 目标主机：域名原样（不是合法 UTF-8 时 `null`），IP 写成文本形式。地址类型不认识时 `null` |
| `port` | 整数或 `null` | 目标端口；地址类型不认识时 `null` |
| `raw_hex` | 字符串 | 整条请求的字节（地址类型不认识时只有前 4 个字节） |

```json
{"t":1.213,"ev":"socks5_request","conn":1,"version":5,"cmd":1,"rsv":0,"atyp":3,"host":"a.kaoju.test","port":80,"raw_hex":"050100030c612e6b616f6a752e746573740050"}
```

## socks5_reply

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `rep` | 整数 | 应答码。非 0 时回完就按 `fin` 关 |
| `cause` | 字符串 | `ok`、`profile_rep`（配置的 `socks.rep`）、`unsupported_cmd`（7）、`unmapped_port`（5）、`unsupported_atyp`（8）、`bad_version`（1） |
| `raw_hex` | 字符串 | 应答的字节。绑定地址固定是 0.0.0.0:0（ATYP=1） |

```json
{"t":1.313,"ev":"socks5_reply","conn":1,"rep":0,"cause":"ok","raw_hex":"05000001000000000000"}
```

## origin_conn

一条连接交给内置源站时写：隧道，或源站端口上的直连。绝对形式的请求由代理在进程内直接调用源站的处理函数，没有源站连接。
HTTPS 源站的 `origin_conn` 在 TLS 握手有了结果以后才写。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | 最外层的 TCP 连接 |
| `oconn` | 整数 | 源站连接编号 |
| `via` | 字符串 | `tunnel` 或 `direct` |
| `tunnel` | 整数或 `null` | `via=tunnel` 时的隧道编号 |
| `listener` | 字符串 | 哪个源站：`origin_http` 或 `origin_https` |
| `tls` | 布尔 | 是不是 HTTPS 源站 |
| `alpn` | 字符串或 `null` | 协商出的 ALPN（`h2`、`http/1.1`；客户端没提供 ALPN 时是空串）。明文或握手失败时 `null` |
| `tls_version` | 字符串或 `null` | 协商出的 TLS 版本，如 `TLS 1.3` |
| `sni` | 字符串或 `null` | 握手里的服务器名 |
| `error` | 字符串或 `null` | TLS 握手失败的原因 |

```json
{"t":6.411,"ev":"origin_conn","conn":1,"oconn":1,"via":"tunnel","tunnel":1,"listener":"origin_https","tls":true,"alpn":"http/1.1","tls_version":"TLS 1.3","sni":"a.kaoju.test","error":null}
```

## origin_request

内置源站每收到一个请求写一个。三条来路：`tunnel`（隧道里）、`direct`（源站端口上的直连）、
`forward`（代理端口上绝对形式的请求，认证通过、没有被 `forward.fail` 或 `conn.drop` 拦下，由代理转交）。
正文读完以后、回应之前写。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | 最外层的 TCP 连接 |
| `oconn` | 整数或 `null` | 源站连接编号；`forward` 是 `null` |
| `tunnel` | 整数或 `null` | 隧道编号；只有 `tunnel` 有 |
| `via` | 字符串 | `tunnel`、`direct`、`forward` |
| `seq` | 整数或 `null` | 这条源站连接上的第几个请求，从 1 开始（h2 按流到达处理函数的先后计数）；`forward` 是 `null` |
| `req_seq` | 整数或 `null` | 只有 `forward` 有：对应的 `http_request.seq` |
| `k` | 字符串或 `null` | 查询参数 `k` |
| `method` | 字符串 | |
| `path` | 字符串 | 路径（解码以后），不含查询串 |
| `query` | 字符串 | 查询串，原样 |
| `proto` | 字符串 | `HTTP/1.1`、`HTTP/1.0`、`HTTP/2.0` |
| `host` | 字符串 | `tunnel`、`direct`：Host 头（h2 是 `:authority`）；`forward`：请求目标里的主机（带端口就带着） |
| `headers` | 头的列表 | 见下 |
| `body_len`、`body_sha256` | 整数、字符串 | 正文的长度和 SHA-256 |
| `has_proxy_authorization` | 布尔 | 源站收到的头里有没有 `Proxy-Authorization`。`forward` 恒为 `false`（代理转交前去掉了） |
| `tls` | 布尔 | 请求是不是在 TLS 里到的 |
| `action` | 字符串 | `respond`（照常回应）、`drop`（按 `origin.drop` 丢弃，随后有一条 `action`）、`none`（正文没读完连接就断了） |
| `status` | 整数或 `null` | 回应的状态码；`action` 不是 `respond` 时 `null` |
| `error` | 字符串或 `null` | 读正文出的错 |

`headers` 两种情况不一样：

- `tunnel`、`direct`：请求由 Go 的 `net/http` 解析，拿不到线上的原顺序和原大小写。名字是规范化以后的写法（`User-Agent`），
  按名字排序，同名的值保持先后。`Host` 不在里面（在 `host` 字段里）。h2 的伪头不在里面。
- `forward`：是 `http_request.headers` 去掉逐跳头（`Connection`、`Keep-Alive`、`TE`、`Trailer`、`Transfer-Encoding`、`Upgrade`）、
  `Connection` 点名的头、`Proxy-` 开头的头和 `Host` 之后剩下的，原顺序、原大小写。

要看客户端在代理端口上发的头的原样，用 `http_request`；隧道里 TLS 之内的原始字节仪器不记。

隧道里的例子：

```json
{"t":6.953,"ev":"origin_request","conn":1,"oconn":1,"tunnel":1,"via":"tunnel","seq":1,"req_seq":null,"k":"A02.s1","method":"GET","path":"/echo","query":"k=A02.s1","proto":"HTTP/1.1","host":"a.kaoju.test","headers":[["Proxy-Authorization","Basic c2hvdWxkOm5vdA=="]],"body_len":0,"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","has_proxy_authorization":true,"tls":true,"action":"respond","status":200,"error":null}
```

代理转交的例子：

```json
{"t":1.261,"ev":"origin_request","conn":1,"oconn":null,"tunnel":null,"via":"forward","seq":null,"req_seq":1,"k":"A01.s1","method":"GET","path":"/echo","query":"k=A01.s1","proto":"HTTP/1.1","host":"a.kaoju.test","headers":[["User-Agent","rawtest/1"],["X-MiXeD-cAsE","padded value"],["x-dup","1"],["X-Dup","2"]],"body_len":0,"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","has_proxy_authorization":false,"tls":false,"action":"respond","status":200,"error":null}
```

被丢弃的例子：

```json
{"t":10.511,"ev":"origin_request","conn":1,"oconn":1,"tunnel":1,"via":"tunnel","seq":2,"req_seq":null,"k":"F05.s2","method":"POST","path":"/echo","query":"k=F05.s2","proto":"HTTP/1.1","host":"a.kaoju.test","headers":[["Content-Length","70000"]],"body_len":70000,"body_sha256":"21ba0bd0d2838f5c266e6b90479806b66b908e79433217cde999733aead4a509","has_proxy_authorization":false,"tls":true,"action":"drop","status":null,"error":null}
```

## action

仪器按配置主动做的动作。写在动作生效之前；这条连接上随后只剩 `tunnel_close`（有隧道时）和 `conn_end`
（隧道的首包或 TLS 握手还没到齐就被关时，中间会先补写 `tunnel_first_bytes`、`origin_conn`）。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | 被关的连接 |
| `what` | 字符串 | `connect_drop`（`connect.drop`）、`conn_drop`（`conn.drop`）、`origin_drop`（`origin.drop`）、`conn_idle_close`（`conn.idle_close_ms`）、`tunnel_idle_close`（`tunnel.idle_close_ms`） |
| `how` | 字符串 | `fin` 或 `rst` |
| `k` | 字符串或 `null` | 被丢弃的请求的 `k`；与请求无关的动作是 `null` |
| `tunnel` | 整数或 `null` | 涉及的隧道 |
| `oconn` | 整数或 `null` | 涉及的源站连接（只有 `origin_drop` 有） |

`auth.on407=close`、`connect.fail`、`forward.fail` 的 `close`、`socks.rep`、SOCKS5 认证失败之后的关闭不写 `action`：
它们体现在 `http_response.close`、`socks5_reply`、`socks5_auth` 和 `conn_end.reason` 里。

```json
{"t":10.706,"ev":"action","conn":1,"what":"origin_drop","how":"fin","k":"F05.s2","tunnel":1,"oconn":1}
```

空闲关闭的例子：

```json
{"t":454.972,"ev":"action","conn":1,"what":"conn_idle_close","how":"fin","k":null,"tunnel":null,"oconn":null}
```

## conn_end

每个 `accept` 恰好对应一个，是这条连接的最后一个事件。仪器退出时还开着的连接也会补上。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `conn` | 整数 | |
| `listener` | 字符串 | 同 `accept` |
| `by` | 字符串 | 谁先关的：`client` 或 `proxy`（仪器这一侧，含内置源站；隧道里具体是谁看 `tunnel_close.by`）。仪器动手关之前已经见到对端的 FIN 或 RST（包括还躺在内核接收队列里没读的 FIN）就算 `client` |
| `close` | 字符串 | 先关的那一方的关法：`fin` 或 `rst` |
| `reason` | 字符串 | 见下 |
| `bytes_in` | 整数 | 仪器从这条连接上读到的全部字节数 |
| `bytes_out` | 整数 | 仪器写到这条连接上的全部字节数 |
| `bytes_drained` | 整数 | `bytes_in` 当中，有多少是仪器决定关闭之后读到的（`fin` 关法等对方把话说完的那段时间里，或关闭前清点接收队列时）。这些字节记了账，但没有被解析 |
| `sha256_in`、`sha256_out` | 字符串 | 两个方向全部字节的 SHA-256 |
| `dur_ms` | 数 | 从接受到关闭完成的毫秒数 |

两个方向的统计都在最外层的 TCP 连接上做：代理端口上的请求和响应、SOCKS5 握手、隧道里的全部字节（TLS 记录）都算在内。
抓包核对拿这四个数与包里重建出来的字节流比。仪器主动关连接时，对端还在路上、仪器没读到的字节不在 `bytes_in` 里
（核对时表现为仪器的记录是抓包的前缀）。

`by` 说的是 TCP 这一层，按仪器动手关的那一刻它所见到的来记：TLS 的 close_notify、WebSocket 的关闭帧、`Connection: close`
这些应用层的“我要关了”不算。两边几乎同时关的时候（比如源站发完 close_notify 正要关，客户端收到后抢先发了 FIN），
`by` 和 `tunnel_close.by` 取决于对端的 FIN 有没有赶在仪器动手之前到达；FIN 的先后以抓包为准。

`fin` 关法：先半关（发 FIN），把对方还在发的读掉，直到对方也关或满 1 秒，再关。`rst` 关法：`SO_LINGER` 设 0 后关，内核发 RST。
`by` 是 `client` 时 `close` 记的是对端的关法；配置要求 `rst` 的动作在对端已经先关的情况下仍然按 `rst` 关，但 `by`、`close` 记的是对端。

`reason` 的取值：

| 取值 | 含义 |
| --- | --- |
| `client_eof`、`client_reset` | 对端先关的（`by=client`）：FIN、RST |
| `response_close` | 代理回了带 `Connection: close` 的响应之后关的（请求要求关闭、`auth.on407=close`、`fail` 的 `close`、400 一类的错误响应） |
| `conn_idle`、`tunnel_idle` | 空闲关闭 |
| `connect_drop`、`conn_drop`、`origin_drop` | 按配置丢弃 |
| `origin_close` | 内置源站关的（隧道或直连） |
| `tls_handshake_failed` | 内置 HTTPS 源站的 TLS 握手失败 |
| `websocket_done` | 绝对形式的 WebSocket：发完关闭帧 |
| `socks_no_method`、`socks_auth_failed`、`socks_reply_failure`、`socks_malformed` | SOCKS5：回了 0xFF、认证失败、回了非 0 的应答码、版本字节不对 |
| `socks4_unsupported`、`tls_on_proxy_port` | 代理端口上首字节是 0x04、0x16 |
| `shutdown` | 仪器退出时还开着 |
| `io_error` | 读写出了别的错（少见） |

仪器按配置切断的例子：

```json
{"t":11.085,"ev":"conn_end","conn":1,"listener":"proxy","by":"proxy","close":"fin","reason":"origin_drop","bytes_in":71982,"bytes_out":2401,"bytes_drained":0,"sha256_in":"66a20037001b737347001267152ff82df7b3c82654f9ad189aade2bb73a897f4","sha256_out":"44f47da0f8b9d1f0c2f34d37259dc9e9d359ba341b60c944c48b8868a01393cb","dur_ms":10.478}
```

客户端先关的例子：

```json
{"t":1.9,"ev":"conn_end","conn":1,"listener":"proxy","by":"client","close":"fin","reason":"client_eof","bytes_in":175,"bytes_out":497,"bytes_drained":0,"sha256_in":"904051bc337f3bab7992c6b1732cd0f6ac44cca15ffc4dc5d413a4795a1ec4d5","sha256_out":"467b39540415ce718f09d3ca83ac8d748a0fcb703919c9c7a798b48492210431","dur_ms":1.404}
```

## 其他

- `log_error`：事件编码失败时写的替身（字段 `of` 是原事件名，`error` 是原因）。不应出现；出现了这次运行不能用。
- 怎样从事件回答矩阵里的问题：某一步的请求用 `k` 找（`http_request.k`、`origin_request.k`）；
  请求在哪条代理连接上看 `conn`；隧道是哪个 CONNECT 建的，用 `tunnel_open` 的 `conn` 和 `req_seq` 找回 `http_request`；
  SOCKS5 隧道的用户名在同一个 `conn` 的 `socks5_auth` 里。

## 变更记录

- 第 1 版（2026-11-10）：初版。
