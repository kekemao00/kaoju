# requests 驱动笔记

写给实现 `requests` 这一列驱动的人。2026-11-10 写成，**只读了文档和源码，没有让客户端连过任何代理**；
这里的每一条都还没有被实测证实，实测对不上的地方以实测为准，并记进报告的“与预期不符”。
对应的逐行预期在 `research/phase2/expectations/requests.json`。

## 读的是哪些版本

| 部件 | 版本 | 来源 |
| --- | --- | --- |
| requests | 2.34.2 | 本机 `site-packages/requests`；文档和 `HISTORY.md` 取自仓库标签 `v2.34.2` |
| urllib3 | 2.8.0 | PyPI 的 `urllib3-2.8.0-py3-none-any.whl`（SHA-256 `0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3`）；`CHANGES.rst` 取自标签 `2.8.0` |
| PySocks | 1.7.1 | PyPI 的 `PySocks-1.7.1-py3-none-any.whl`（SHA-256 `2725bd0a9925919b9b51739eea5f9e2bae91e83288108a9ad338b2e3a4435ee5`） |
| CPython | 3.13.18 | 本机 `/usr/local/lib/python3.13/http/client.py`、`ssl.py` |
| OpenSSL | 3.5.9 | `ssl.OPENSSL_VERSION`（只读了版本号） |

下文的出处写成“文件:行号（版本）”。`requests/…` 指 requests 2.34.2，`urllib3/…` 指 urllib3 2.8.0，
`http/client.py` 指 CPython 3.13.18 的标准库，`socks.py` 指 PySocks 1.7.1。

**本机实际装的是 urllib3 2.7.0，不是 2.8.0，PySocks 没有装。** `requirements.txt` 要把这几个版本都钉死，
装进驱动自己的虚拟环境：

```
requests==2.34.2
urllib3==2.8.0
PySocks==1.7.1
```

（`certifi`、`idna`、`charset-normalizer` 是 requests 的硬依赖，也要钉版本。）
2.7.0 和 2.8.0 逐文件比过，差别见文末“版本相关的坑”，都不在 requests 用到的路径上。

## 1. 代理怎么配

### HTTP 代理

文档写法（`docs/user/advanced.rst`，Proxies 一节）：每次请求传 `proxies=`，凭据写进代理 URL。

```python
import requests
from urllib.parse import quote

def proxy_url(scheme, host, port, user=None, password=None):
    if user is None:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"

s = requests.Session()
p = proxy_url("http", "127.0.0.1", port, "kaoju-user", "kaoju-pass-1")
r = s.get(url, proxies={"http": p, "https": p}, verify=ca_file, timeout=15)
```

- `http` 和 `https` 两个键都要给，值是同一个代理 URL。键是**目标**的协议，值的协议才是代理的协议
  （`requests/utils.py:885-908` `select_proxy`）。
- 文档同一节有警告：`session.proxies` 会被环境变量里的代理覆盖，要稳妥就每次请求都显式传 `proxies=`。
  PROTOCOL 的表里写的也是 `proxies=` 参数，照这个写。
- 显式传入的代理不受 `NO_PROXY` 和回环地址的影响：旁路判断只作用在环境变量里的代理上
  （`requests/sessions.py:845-851`、`requests/utils.py:911-939`）。目标是 `localhost` 也走代理。

凭据是谁发的、什么时候发：

- requests 从代理 URL 解出用户名密码，生成 `Proxy-Authorization: Basic …`，作为 `proxy_headers` 交给 urllib3 的
  `ProxyManager`（`requests/adapters.py:295-303`、`:613-632`）。只要用户名非空就生成。
- 明文请求：urllib3 在每个请求发出前把 `proxy_headers` 并进请求头（`urllib3/connectionpool.py:754-756`）。**第一个请求就带**，不等 407。
- HTTPS：`proxy_headers` 作为 CONNECT 的头（`urllib3/connectionpool.py:1061-1074` → `http/client.py:993-1014`）。
  **第一个 CONNECT 就带**；隧道里的请求不带（`:754` 的条件）。
- CONNECT 是标准库发的：`CONNECT 主机:端口 HTTP/1.1`，头只有 `proxy_headers` 里的那些，再加一个自动补上的 `Host`
  （`http/client.py:955-963`、`:997-1010`）。没有 `User-Agent`，没有 `Proxy-Connection`。
- 收到 407 以后**没有任何重试**：requests 里没有处理代理质询的代码。`requests.auth.HTTPProxyAuth` 不是干这个的，见第 6 节。

### SOCKS5 代理

文档写法（同一文件，SOCKS 小节）：先装 `requests[socks]`（就是 PySocks），然后

```python
p = proxy_url("socks5h", "127.0.0.1", port, user, password)   # 域名交给代理解析
p = proxy_url("socks5",  "127.0.0.1", port, user, password)   # 客户端自己解析
r = s.get(url, proxies={"http": p, "https": p}, verify=ca_file, timeout=15)
```

- 文档原话：`socks5` 在客户端解析域名，`socks5h` 交给代理解析。两种写法 requests 都支持，用例给哪个就用哪个，
  不需要“用它唯一支持的写法”。对应源码 `urllib3/contrib/socks.py:197-202`（`rdns` 为假或真）。
- 凭据同样写在 URL 里。requests 解出来以后显式传给 `SOCKSProxyManager`（`requests/adapters.py:283-293`），
  PySocks 用 UTF-8 把它们转成字节（`socks.py:317-319`）。
- 没装 PySocks 时报 `InvalidSchema("Missing dependencies for SOCKS support.")`（`requests/adapters.py:62-67`）。
- 经 SOCKS 的明文请求用源站形式（`GET /路径`），不是绝对形式（`requests/adapters.py:586-597`）。

### 凭据写进 URL 时必须转义

用 `quote(…, safe='')`，用户名和密码分别转义。出处是解析的那一头：`requests/utils.py:1070-1084` `get_auth_from_url`
对 `urlparse` 给出的用户名、密码各做一次 `unquote`。文档只写了 `http://user:password@host/` 这个形状，没有讲转义。

- 不能用 `quote` 的默认值：默认 `safe='/'`，用户名里的 `/` 不会被转义，会把 URL 的 authority 截断。
- 还原用的是 `unquote` 不是 `unquote_plus`，`+` 不会变成空格。用户名里字面的 `%41` 要写成 `%2541`，`quote` 会自动这样做。
- **空密码要保留冒号**，写成 `user:@host`。写成 `user@host` 时 `urlparse` 给出的密码是 `None`，`unquote(None)` 抛 `TypeError`，
  被当成“没有凭据”（`requests/utils.py:1078-1082`），HTTP 代理和 SOCKS 都不会发任何凭据。上面的 `proxy_url` 写法天然保留冒号。
- HTTP 代理的凭据按 **latin-1** 编码（`requests/auth.py:65-69`）。用户名里有 latin-1 以外的字符（比如中文）时，
  `.encode('latin1')` 抛 `UnicodeEncodeError`，发生在连接代理之前，而且**不是** `requests.RequestException` 的子类。
  D04、D05 预期就是这个结果：照常按上面的写法配，把异常记成这一步失败，**不要**为了让它通过而换编码绕过去。
- SOCKS 这一侧不经过 latin-1，UTF-8 用户名应当原样到达。

## 2. 同一个进程里换凭据

没有专门的接口。常规做法就是**每次请求传不同的 `proxies=`**（代理 URL 里的用户信息不同）：

```python
s.get(url, proxies={"http": p_user0, "https": p_user0}, …)
s.get(url, proxies={"http": p_user1, "https": p_user1}, …)
```

`HTTPAdapter.proxy_manager` 这个字典以完整的代理 URL 字符串（含用户信息）为键
（`requests/adapters.py:281-303`），每套凭据得到一个独立的 `ProxyManager` 或 `SOCKSProxyManager`，各有各的连接池。
所以同一个 Session 里两套凭据的连接和隧道不会互相复用。B11、B12、S14 都这样写，不需要报 `unsupported`。

## 3. 信任测试用的 CA

文档（`docs/user/advanced.rst`，SSL Cert Verification 一节）给了三种等价的写法，任选一种，都不关闭校验：

```python
s.get(url, verify=ca_file, …)        # 每次请求
s.verify = ca_file                   # 整个 Session
# 或环境变量 REQUESTS_CA_BUNDLE=ca_file（只在 verify 没有另外指定时生效，requests/sessions.py:855-860）
```

- 这只改变信任的根（`requests/adapters.py:97-105` 把路径作为 `ca_certs` 传给 urllib3），不碰代理、连接池和 ALPN。
  HTTP/2 本来就不会用：urllib3 默认只报 `http/1.1`（`urllib3/util/ssl_.py:20`、`:435`）。
- 不要用 `verify=False`，也不要自己挂带 `ssl_context` 的 `HTTPAdapter`。
- **测试 CA 要过得了严格校验。** Python 3.13 起 urllib3 给上下文加了 `VERIFY_X509_STRICT` 和 `VERIFY_X509_PARTIAL_CHAIN`
  （`urllib3/util/ssl_.py:290-298`）。CA 证书和源站证书缺少规范要求的扩展时，握手会以证书校验失败告终，所有 HTTPS 用例都会失败。
  哪些扩展会被拒绝取决于 OpenSSL，这里没有逐项核对（**未验证**）；`obsproxy gen-ca` 的产物如果在这一列上握手失败，先查这里。

## 4. 并发、重定向、POST

**一个用例一个 `requests.Session()`**，从头用到尾（文档 Keep-Alive 一节：同一个 Session 里自动复用连接；
正文读完连接才回池，默认 `stream=False` 时 requests 自己读完，`requests/sessions.py:826-827`）。
不要挂自定义的 `HTTPAdapter`，默认值就是要测的东西：`pool_connections=10`、`pool_maxsize=10`、`pool_block=False`、
`max_retries=0`（`requests/adapters.py:79-82`、`:201-209`）。

并发 6 个请求：requests 没有并发接口，文档（Blocking Or Non-Blocking? 一节）让用户另找线程类的方案。
通行写法是标准库线程池加共用的 Session：

```python
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=len(steps)) as ex:
    futures = [ex.submit(do_step, st) for st in steps]
    results = [f.result() for f in futures]
```

- 文档没有承诺 Session 是线程安全的，这只是通行做法。
- 连接池不阻塞：池里没有空闲连接时直接新建（`urllib3/connectionpool.py:285-298`），所以 6 个并发预期是 6 条连接或隧道，
  `pool_maxsize=10` 只决定用完以后留下几条。

重定向：默认就跟随（文档 quickstart 的 Redirection and History：除 HEAD 外都跟随；`requests/sessions.py:568`）。
`follow` 为真时什么都不用加；`follow` 为假的步骤也不要特意传 `allow_redirects=False`，保持默认。
跳转是 requests 自己做的，每一跳重新选代理、重新取连接池（`requests/sessions.py:186-307`）。

POST：

```python
with open(step["body_file"], "rb") as f:
    body = f.read()
r = s.post(url, data=body, headers={"Content-Type": "application/octet-stream"}, proxies=…, verify=ca_file, timeout=15)
```

`bytes` 正文带 `Content-Length`（`requests/models.py:630-644`）。直接传文件对象（文档 Streaming Uploads）也会带
`Content-Length`（`:603-626`），只有传生成器才会变成 chunked。requests 不发 `Expect: 100-continue`。

超时必须给：文档 Timeouts 一节写明默认不超时。用用例里的 `timeout_s`。

## 5. 代理出错时调用方拿到什么

### 默认用法

| 情形 | 调用方拿到的 | 出处 |
| --- | --- | --- |
| 明文请求被代理回 407、403 等 | 一个普通的 `Response`：`status_code`、`reason`、`headers`、正文都有 | `requests/adapters.py:365-401` |
| CONNECT 回非 200（407、403、502、503 都一样） | `requests.exceptions.ProxyError`。文字形如 `HTTPSConnectionPool(host='a.kaoju.test', port=443): Max retries exceeded with url: /echo?k=… (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 502 原因短语')))`。只有状态码和原因短语；响应头和正文拿不到 | `http/client.py:1019-1029`；`urllib3/connectionpool.py:833-843`；`urllib3/util/retry.py:553-555`；`requests/adapters.py:722-723` |
| CONNECT 发出后连接被关 | `requests.exceptions.ConnectionError`，文字形如 `('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))` | `http/client.py:309-313`；`urllib3/connectionpool.py:844-849`；`requests/adapters.py:710-711` |
| 请求发出后连接被关或被复位 | 同上（复位时里层是 `ConnectionResetError`）。**不重发**：requests 传的是 `Retry(0, read=False)` | `requests/adapters.py:208-209`；`urllib3/util/retry.py:507-510` |
| SOCKS5 失败（方法被拒、认证失败、应答码非 0） | `requests.exceptions.ConnectionError`（不是 `ProxyError`）。文字形如 `SOCKSHTTPSConnectionPool(…): Max retries exceeded with url: … (Caused by NewConnectionError("SOCKSHTTPSConnection(…): Failed to establish a new connection: 0x02: Connection not allowed by ruleset"))` | `socks.py:501-533`、`:806-820`；`urllib3/contrib/socks.py:128-147`；`requests/adapters.py:729` |
| HTTP 代理的用户名有 latin-1 以外的字符 | 裸的 `UnicodeEncodeError`，没有发出任何字节 | `requests/auth.py:65-69` |

PySocks 的几种报错文字（`socks.py:101-110`、`:487-513`）：

- 代理回 `0xFF`：`All offered SOCKS5 authentication methods were rejected`
- 代理选了用户名密码而客户端没配：`No username/password supplied. Server requested username/password authentication`
- 用户名密码不对：`SOCKS5 authentication failed`
- 应答码：`0x02: Connection not allowed by ruleset`、`0x04: Host unreachable`、`0x05: Connection refused`（其余见源码的表）

记 `default_text` 时：

- 成功的步骤记 `r.status_code`、`r.reason`、`r.headers`、正文前 4 KiB。
- 失败的步骤要 `except Exception`，不能只接 `requests.RequestException`（上表最后一行不是它的子类）。
  异常的文字要连同 cause 链一起记，沿 `__cause__`、`__context__` 往下走：

```python
def exc_text(e):
    out, seen = [], set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        out.append(f"{type(e).__module__}.{type(e).__qualname__}: {e}")
        e = e.__cause__ or e.__context__
    return "\n".join(out)
```

### 需要主动打开的手段（`extra_text`）

文档里写明的只有一个：`docs/api.rst`“Migrating to 1.x”一节给出的调试写法，

```python
import http.client
http.client.HTTPConnection.debuglevel = 1
```

它让标准库把发出的请求头（`send: …`）和收到的响应头（`reply: …`、`header: …`）**打印到标准输出**
（`http/client.py:1090`、`:308`）。对 CONNECT，`_tunnel` 在判断状态码**之前**把代理响应的每个头打印出来
（`http/client.py:1021-1025`），所以 CONNECT 成功和失败时代理附加的头都看得到；CONNECT 响应的正文标准库不读，任何手段都看不到。

用法建议：

```python
import contextlib, io
buf = io.StringIO()
http.client.HTTPConnection.debuglevel = 1
try:
    with contextlib.redirect_stdout(buf):
        r = s.get(…)
finally:
    http.client.HTTPConnection.debuglevel = 0
extra_text, extra_how = buf.getvalue(), "http.client.HTTPConnection.debuglevel = 1（requests 文档 docs/api.rst）"
```

- 它只打印，不改变线上的字节。`redirect_stdout` 是进程级的，不要在 `parallel` 步骤里用；E 组（R81、R85 用到）打开就够了。
- `send:` 那一行会带出 `Proxy-Authorization` 的值。测试凭据是假的，无妨，但结果文件会进公开仓库，心里要有数。
- 文档同一处还让把 `urllib3` 这个 logger 调到 DEBUG。它只多出“Starting new HTTPS connection”一类的行，对这里的行没有帮助。
- 另有一条**文档没写**的路：`stream=True` 之后 `r.raw.connection.get_proxy_response_headers()`
  （`http/client.py:1034-1046`，Python 3.12 起有）能取到 CONNECT 成功时的响应头；失败时连接对象已被丢弃，取不到。
  它不算“文档里写明的手段”，不要用它填 `extra_text`。

## 6. 容易踩的地方

- **不要用 `requests.auth.HTTPProxyAuth`。** 它把 `Proxy-Authorization` 直接加在请求自己的头上（`requests/auth.py:116-121`），
  HTTPS 时这个头会进隧道、到达源站。常规做法是凭据写在代理 URL 里。
- 不要设 `trust_env=False`，也不要动 `max_retries`、连接池大小、`Connection` 头。驱动的运行环境已经是干净的。
- `socks5`（客户端自己解析）时，PySocks 是**先连上代理、协商完认证方法，写请求时才解析目标**（`socks.py:519-520`、`:571-576`）。
  解析失败时代理那边会看到一条有问候、没有完整请求的连接（`:540-542` 的 `writer.close()` 会把已缓冲的 `05 01 00` 冲出去）。这不是驱动的毛病。
- `socks5` 且目标是 `localhost` 时，写进 SOCKS 请求的是 `getaddrinfo` 第一条结果的地址族（`socks.py:573-585`），
  IPv4 还是 IPv6 取决于运行的机器，本机和 CI 可能不同。
- SOCKS5 的空密码：PySocks 把空密码当成没有凭据（`socks.py:317-319`、`:457`），问候里不提供用户名密码方法。
  HTTP 代理则会发 `user:`。两边不一样，都是预期内的。
- SOCKS5 用户名 128 字节以上：PySocks 写长度字节用的是 `chr(len(username)).encode()`（`socks.py:491-494`），
  长度不小于 128 时这是两个字节，认证报文从长度字段开始就错位。S18、S19 预期代理收到的用户名是错的，不是驱动的毛病。
- 一个用例里的步骤失败以后，Session 照常能用，不需要重建。

## 7. 版本相关的坑

| 版本 | 行为 | 出处 |
| --- | --- | --- |
| requests 低于 2.31.0 | 跟随跳转到 HTTPS 时把 `Proxy-Authorization` 重新加到请求头上，经隧道泄露给源站（CVE-2023-32681）。2.31.0 起只在新地址不是 https 时才加 | `HISTORY.md` 2.31.0 一节；`requests/sessions.py:355-366` |
| requests 2.32.0 到 2.32.4 | `verify=True` 时复用一个全局 `SSLContext`；2.32.5 撤回。传 CA 文件路径的写法不受影响 | `HISTORY.md` 2.32.0、2.32.5 两节 |
| requests 2.12.0 | 起容忍代理凭据里的空密码，之前会把凭据整个丢掉 | `HISTORY.md` 2.12.0 一节 |
| Python 低于 3.11.16（3.11 系列） | urllib3 换用自带的 `_tunnel` 副本，CONNECT 用的是 `HTTP/1.0`。3.12 起是 `HTTP/1.1` 并自动带 `Host` | `urllib3/connection.py:276-345`；`http/client.py:943-963` 的文档字符串 |
| Python 3.12 起 | 有 `get_proxy_response_headers()`，`_tunnel` 会保留 CONNECT 响应的头 | `http/client.py:1021`、`:1034-1046` |
| Python 3.13 起 | urllib3 默认加 `VERIFY_X509_STRICT`，对测试 CA 更挑剔 | `urllib3/util/ssl_.py:290-298` |
| urllib3 2.8.0 对比 2.7.0 | ① SOCKS 代理 URL 里的凭据改为先百分号解码再用（只在调用方没有显式传用户名密码时才走这条路，requests 总是显式传，不受影响）；② `_tunnel` 副本适用的 Python 版本范围变了，并加了头的合法性检查（3.13 用标准库的，不受影响）；③ 绝对形式的请求目标去掉 `#fragment`；④ 主机名校验更严。用例都碰不到 | 两个版本的源码逐文件比较；`CHANGES.rst` 2.8.0 一节 |
| urllib3 2.x | HTTP/2 是试验性的，要调用 `urllib3.http2.inject_into_urllib3()` 并装 `h2`；默认不开，requests 不调用 | `urllib3/http2/__init__.py:15-40`；`CHANGES.rst` |
| PySocks 1.7.1 | 2019 年以后没有新版本；上面说的长度字节问题和空密码行为都在这一版里 | `socks.py:16`、`:317-319`、`:491-494` |
| OpenSSL 3.5 起 | 默认的 ClientHello 带后量子混合密钥交换的公钥，预期超过 1460 字节；更早的 OpenSSL 不会。Python 链接哪个 OpenSSL，本机和 CI 可能不同 | OpenSSL 3.5 的变更记录（凭记忆引用，**未验证**）；urllib3 和 requests 都不设密钥交换组（`urllib3/util/ssl_.py:256-328`） |

Python 3.11 及更早的标准库本身怎样发 CONNECT 没有读（本机只有 3.13），上表那一行只是 urllib3 里保留的副本所显示的，记为**未验证**。
