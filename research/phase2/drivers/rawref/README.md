# rawref：参照客户端

`rawref` 不是被测对象，是用来检验仪器的（[`../../PROTOCOL.md`](../../PROTOCOL.md) 的“仪器自检”一节）。
它用裸套接字说话，发出的每个字节都由 [`driver.py`](driver.py) 写死，所以矩阵里它那一列该是什么值，
可以不看任何测量结果、只从 `rows.json` 的规则和下面的策略推出来。手写的答案在
[`../../selfcheck_expected.json`](../../selfcheck_expected.json)；对 `rawref` 跑全部用例，矩阵里它那一列必须与答案逐格相同。

只用 Python 标准库（`socket`、`ssl`、`threading` 等）。改 `driver.py` 的任何行为，都要同时改本文件和答案。

```sh
python3 drivers/rawref/driver.py <用例.json> <结果.json>
python3 drivers/rawref/driver.py --versions        # 打印 {"rawref": "1"}
```

下面的策略是答案的依据。标了“（补充）”的是任务给出的策略没有写到、由实现定下来的细节。

## HTTP 代理（`proxy.scheme` 是 `http`）

**明文（`http://`）**：到代理的 TCP 连接上发绝对形式的请求，HTTP/1.1。头的顺序固定：

```
GET http://a.kaoju.test/echo?k=A01.s1 HTTP/1.1
Host: a.kaoju.test
User-Agent: kaoju-rawref/1
Accept: */*
Proxy-Connection: keep-alive
Proxy-Authorization: Basic …            （只在这一步配了凭据时）
Content-Type: application/octet-stream  （只在有正文时）
Content-Length: N                       （只在有正文时）
```

- `Host` 的值是 URL 里的“主机[:端口]”原样：URL 写了端口就带，没写就不带。
- POST 的正文用 `Content-Length` 分帧，头和正文一次写出；从不发 `Expect`，从不用 chunked。
- 请求目标是 URL 原样（去掉片段）。

**HTTPS（`https://`）**：先在到代理的新连接上发 CONNECT，头的顺序固定：

```
CONNECT a.kaoju.test:443 HTTP/1.1
Host: a.kaoju.test:443
User-Agent: kaoju-rawref/1
Proxy-Connection: keep-alive
Proxy-Authorization: Basic …            （只在这一步配了凭据时）
```

- 目标总是“主机:端口”，URL 没写端口时是 443；`Host` 与目标逐字节相同。
- 收到 2xx 以后用 `ssl` 模块在这条连接上做 TLS：证书校验开启（`ssl.create_default_context(cafile=用例的 ca_file)`，
  校验主机名），SNI 是主机名，ALPN 只提供 `http/1.1`。
- （补充）密钥交换组固定为只有 `prime256v1`（`set_ecdh_curve`）。原因：ClientHello 的长度取决于 OpenSSL 的版本
  （3.5 起默认带后量子的密钥份额，实测 1534 字节；固定以后是 517 字节），不固定的话“ClientHello 的长度”那一行就推不出来。
- 隧道里发原始形式的请求，头固定为 `Host`、`User-Agent: kaoju-rawref/1`、`Accept: */*`
  （有正文时再加 `Content-Type`、`Content-Length`）。（补充）隧道里不带 `Proxy-Connection`，也从不带 `Proxy-Authorization`。

**localhost 不绕过代理**：目标是 `localhost` 的请求和别的目标走同样的路。

## 凭据

- 配了凭据（步骤的 `user` 不是 `null`）就在第一个请求或 CONNECT 上先带：
  `Proxy-Authorization: Basic base64(用户名的 UTF-8 + ":" + 密码的 UTF-8)`，不做任何转义，长度不设上限。
  同一条连接上之后的每个绝对形式请求也都带。代理要不要认证不影响带不带。
- 没配凭据就不带。
- 收到 407（或 403）不重试：
  - 明文：把这个响应当作这一步的结果（`ok` 为真，`status` 是 407）。
  - CONNECT：这一步报错，文字固定为 `rawref: CONNECT failed: <状态码> <原因短语>`（任何非 2xx 的 CONNECT 响应都这样）。
    （补充）失败的 CONNECT 所在的连接读完响应就关，不管代理有没有留着它；下一个 CONNECT 总是新连接。

## 连接复用

- 连接池的键：
  - 经 HTTP 代理的明文请求：只有凭据。所有明文目标共用到代理的连接；换了凭据是另一个键。
  - 经 HTTP 代理的 HTTPS、经 SOCKS5 的全部请求：（凭据、目标协议、主机、端口）。
- 每个键最多 1 条连接，顺序的请求复用它。发请求之前不探测连接是否还活着。
- `parallel` 步骤里每个请求各开一条新连接（或隧道），用完即关，不进连接池、也不用池里的连接。
- 请求发出后读到 EOF 或复位（发的时候出错也算）：不重发，这一步记为失败，报错文字固定为 `rawref: connection closed`，
  连接从池里拿掉。新连接上的第一个请求、CONNECT 没等到响应、TLS 握手途中断开也是同样的文字，同样不重发。
- （补充）响应带 `Connection: close`、是 HTTP/1.0、或正文靠连接关闭来分界时，读完就关连接、从池里拿掉。
- 用例结束时关掉池里的所有连接。

## 重定向

`follow` 为真时最多跟 5 跳（301、302、303、307、308 且带 `Location`）。跳转后的请求按新 URL 的协议走上面的规则
（明文走绝对形式、HTTPS 走 CONNECT，各用各的池键），凭据仍是这一步的凭据。
（补充）301、302、303 之后改用不带正文的 GET，307、308 保持方法和正文；第 5 跳之后还是重定向就把那个响应当作结果。

## SOCKS5（`proxy.scheme` 是 `socks5` 或 `socks5h`）

顺序固定：先检查凭据长度，再（`socks5`）解析域名，然后才连代理。

1. 配了凭据而用户名或密码的 UTF-8 超过 255 字节：不连代理，报 `rawref: socks credential too long`。
2. 地址：`socks5h` 发域名（ATYP 3）；`socks5` 自己用 `socket.getaddrinfo` 解析后发 IPv4（ATYP 1）或 IPv6（ATYP 4），
   解析失败就不连代理，报 `rawref: resolve failed`。（补充）解析结果里有 IPv4 就用第一个 IPv4，否则用第一个 IPv6；
   主机本身是 IP 字面量时不解析，直接发。
3. 方法协商：没配凭据发 `05 01 00`（方法列表 `[00]`）；配了凭据发 `05 02 00 02`（`[00, 02]`）。
   - 服务端回 `0xFF`：报 `rawref: socks no acceptable method`。
   - 服务端选 `02`：发 `01 ULEN 用户名 PLEN 密码`（原样的 UTF-8 字节，密码为空时 PLEN 是 0）。
     状态不是 0：报 `rawref: socks auth failed status=<n>`。
   - 服务端选 `00`：不发凭据，直接往下走。
4. 请求：`05 01 00 ATYP 地址 端口`。应答码不是 0：报 `rawref: socks reply <n>`。
5. 建好以后按目标协议做 TLS（设置同上）或直接发明文请求。请求是原始形式，头同“隧道里”的那一组。

连接池键是（凭据、目标协议、主机、端口）。握手途中连接断开报 `rawref: connection closed`。

## ws 步骤

- `ws://` 经 HTTP 代理：新开一条到代理的连接，发绝对形式的 GET（目标是 `ws://…` 原样），不走 CONNECT。头的顺序固定：
  `Host`、`User-Agent: kaoju-rawref/1`、`Upgrade: websocket`、`Connection: Upgrade`、
  `Sec-WebSocket-Key: a2FvanUtcmF3cmVmLWtleQ==`（固定值）、`Sec-WebSocket-Version: 13`，配了凭据时最后加 `Proxy-Authorization`。
- `wss://` 经 HTTP 代理：CONNECT 加 TLS（同 HTTPS），在隧道里发原始形式的 GET，带同一组升级头。
- 经 SOCKS5：SOCKS5 建好后同上（`wss://` 先做 TLS）。
- 读到 101 就算 `ok`（`status` 记 101）；不是 101 的响应照常当作结果。（补充）读到 101 后核对 `Sec-WebSocket-Accept`，
  不发任何帧，等对端关闭（最多 2 秒）再关。ws 步骤的连接不进连接池，也不用池里的连接。
- 用例里的 `page` 字段不用（那是给浏览器的）。

## 结果里写什么

- `ok`：拿到了一个 HTTP 响应（不论状态码）。`status`：最终响应的状态码；报错时是 `null`。
- `default_text`：
  - 拿到响应时：第一行 `<状态码> <原因短语>`，然后是全部响应头（每行 `名: 值`），空行，正文的前 4 KiB。
    跟随了重定向时是最后那个响应。
  - CONNECT 失败时：只有 `rawref: CONNECT failed: <状态码> <原因短语>` 这一句，不含响应头和正文。
  - 其他失败：只有那句固定的报错。全部报错文字：

    | 文字 | 什么时候 |
    | --- | --- |
    | `rawref: CONNECT failed: <状态码> <原因短语>` | CONNECT 的响应不是 2xx |
    | `rawref: connection closed` | 发请求或读响应时遇到 EOF、复位 |
    | `rawref: timeout` | 这一步超过了 `timeout_s` |
    | `rawref: resolve failed` | `socks5` 下域名解析失败 |
    | `rawref: socks no acceptable method` | SOCKS5 服务端回 `0xFF` |
    | `rawref: socks auth failed status=<n>` | SOCKS5 用户名密码认证的状态不是 0 |
    | `rawref: socks reply <n>` | SOCKS5 应答码不是 0 |
    | `rawref: socks credential too long` | 用户名或密码超过 255 字节 |
    | `rawref: proxy connect failed` | 连不上代理 |
    | `rawref: tls failed: …` | TLS 握手失败（证书校验不过等） |
    | `rawref: internal error: …` 等 | 其余异常（不应出现） |

- `extra_text`：这一步里发过的每个 CONNECT 的响应（无论成败）：状态行、完整的响应头、正文的前 4 KiB；
  `extra_how` 是 `rawref 自己记录的 CONNECT 响应`。这一步没有发过 CONNECT（明文请求、SOCKS5、复用已有的隧道）时两项都是 `null`。
- 每步有超时（用例的 `timeout_s`，从这一步开始算到结束）。任何异常都落到这一步的结果里，进程以 0 退出。
- `sleep` 和 `parallel` 本身各占一项（`ok` 是 `null`），`parallel` 的各个请求紧跟在后面，与 curl 驱动的写法相同。
