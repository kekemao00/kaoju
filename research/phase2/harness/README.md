# obsproxy

第 2 阶段（客户端行为矩阵）的测量仪器：一个只做观察的代理，自带明文和 HTTPS 两个源站。
它把代理端口上收到的每个请求、每次 SOCKS5 握手、每条隧道的首包都记成事件，并对每条 TCP 连接两个方向的全部字节
各记一份字节数和 SHA-256，供抓包核对。

- 它做什么、配置有哪些字段、默认值是什么：[`../PROTOCOL.md`](../PROTOCOL.md) 的“仪器 / obsproxy”一节。
- 事件的确切字段、类型和例子：[`EVENTS.md`](EVENTS.md)。

只用 Go 标准库。只监听 127.0.0.1，从不向外拨号：目标端口是 80（或明文源站的实际端口）的交给内置明文源站，
443（或 HTTPS 源站的实际端口）的交给内置 HTTPS 源站，其余端口按“连不上”处理。主机名不解析。

## 构建

```sh
cd research/phase2/harness
go build -trimpath -o obsproxy .      # Go 1.24 或更新
```

## 运行

```sh
./obsproxy gen-ca -dir /path/to/ca          # 生成测试用 CA：ca.pem、ca.key（ECDSA P-256，7 天有效）
./obsproxy serve -profile P.json -ca-dir /path/to/ca -events E.jsonl [-max-seconds 120]
./obsproxy version
```

`serve` 就绪后在标准输出打印一行 JSON，然后一直运行到收到 SIGTERM、SIGINT 或超过 `-max-seconds`（0 表示不限）：

```json
{"proxy_port":40123,"origin_http_port":40124,"origin_https_port":40125}
```

退出时关闭所有连接，为还开着的连接补写 `conn_end`，最后写 `end`。正常退出的退出码是 0；
配置或参数有问题是 2（配置里出现不认识的字段也算，防止字段名写错而悄悄不生效）；其他错误是 1。

配置文件是一个 JSON 对象，只需要写与默认值不同的字段，最简单的是 `{}`。

被测客户端要信任 `ca.pem`（加进信任根），不要关闭证书校验。这张 CA 带名字约束，只能给 `kaoju.test`、`localhost`
和 127.0.0.1 签发；源站证书每次启动现签，私钥不落盘。手工试一下：

```sh
env -i PATH="$PATH" HOME=/path/to/empty-home \
  curl --cacert /path/to/ca/ca.pem -x http://127.0.0.1:40123 'https://a.kaoju.test/echo?k=A02.s1'
```

（`env -i` 是为了清掉环境里已有的代理变量，否则 curl 可能绕过或走错代理。）

## 测试

```sh
gofmt -l . && go vet ./...
go test -race -count=1 ./...
go test -run '^$' -fuzz '^FuzzHTTPHead$' -fuzztime 10s
go test -run '^$' -fuzz '^FuzzSocks5$' -fuzztime 10s
go test -run '^$' -fuzz '^FuzzClientHello$' -fuzztime 10s
```

测试用裸 TCP 套接字对着仪器说话（隧道里的 TLS 用 `crypto/tls`，测试 CA 放进 `RootCAs`），只连 127.0.0.1。
每个测试结束时都核对三件事：事件文件的结构（`start` 开头、`end` 结尾、每个 `accept` 恰好一个 `conn_end`、
每种事件的字段与 `EVENTS.md` 一致）；每条测试连接上 `conn_end` 的字节数和 SHA-256 与测试自己发收的字节完全相同。

`OBSPROXY_TEST_DUMP=目录 go test ./...` 会把每个测试的事件文件留在那个目录里，`EVENTS.md` 里的例子就取自那里。

## 文件

| 文件 | 内容 |
| --- | --- |
| `main.go` | 命令行 |
| `profile.go` | 配置的解析、默认值和校验 |
| `server.go` | 监听、首字节分流、退出 |
| `cconn.go` | 一条被接受的 TCP 连接：字节记账、`fin` 与 `rst` 两种关法、`conn_end` |
| `httphead.go`、`proxyhttp.go` | HTTP 入口：请求头和正文的解析、认证、CONNECT、绝对形式的转发 |
| `socks5.go` | SOCKS5 入口（RFC 1928、1929） |
| `tunnel.go`、`clienthello.go` | 隧道：首包记录、ClientHello 解析、把连接递给内置源站 |
| `origin.go` | 内置源站：`/echo`、`/redirect`、`/page`、`/ws` |
| `ca.go` | 测试 CA 和源站证书 |
| `events.go` | 事件的写出 |
