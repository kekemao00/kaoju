# 运行器

`run.py` 对每个（列、用例、第几遍）做一次互相隔离的运行，把仪器的事件、驱动的结果和抓包核对的结论汇成一条记录。
测量口径见 [`../PROTOCOL.md`](../PROTOCOL.md)，仪器见 [`../harness/README.md`](../harness/README.md)。只用 Python 标准库。

## 怎么跑

```sh
cd research/phase2
python3 runner/run.py                                   # 注册表里的全部列、全部用例，各 3 遍
python3 runner/run.py --variants curl,curl-anyauth --cases 'A*,B02' --repeats 1 --out /path/to/out
```

| 参数 | 含义 | 默认 |
| --- | --- | --- |
| `--variants` | 逗号分隔的列名 | `drivers/registry.json` 里的全部 |
| `--cases` | 逗号分隔的用例号，可用通配符 | 全部 |
| `--repeats` | 每个用例跑几遍 | `cases.json` 的 `repeats` |
| `--jobs` | 同时进行几次运行 | 2 |
| `--out` | 输出目录 | `research/phase2/out` |
| `--work` | 工作目录 | 临时目录下按时间戳新建 |
| `--keep-pcap` | 保留每次运行的工作目录（抓包、事件、驱动的文件） | 不保留 |
| `--tcpdump` | tcpdump 命令，比如 `'sudo tcpdump'` | `tcpdump` |
| `--obsproxy` | 已构建好的 obsproxy | 用 `go build` 现场构建到工作目录 |

需要：Go（构建 obsproxy）、能在 `lo` 上抓包的 tcpdump（root，或用 `--tcpdump 'sudo tcpdump'`）、
certutil（给 Chromium 建 NSS 数据库；没有就跳过并警告）。

退出码：0 正常；1 有运行在运行器这一层出了错（看记录里的 `runner_errors`）；130 被中断（已完成的运行照样写出）。
驱动崩溃、超时、核对不通过不影响退出码，在结尾的小结里按列计数。

## 一次运行做什么

启动时构建 obsproxy，`gen-ca` 生成这次运行的测试 CA，建一个 home 模板
（`.pki/nssdb` 里以 `C,,` 信任 `ca.pem`）。然后每次运行在自己的子目录里：

1. 写 `profile.json`（用例的 `profile` 字段，原样），启动 `obsproxy serve`，读就绪行拿到三个端口。
2. 启动 tcpdump（`-i lo -n --immediate-mode -B 32768 -U -s 0 -w run.pcap`，过滤表达式只含这三个端口），
   等它在标准错误里打印 `listening on` 再继续。
3. 生成运行时的用例文件：替换 `{origin_http_port}`、`{origin_https_port}`；按 `body_bytes` 生成正文文件
   （第 i 个字节是 `(i*131+7)%251`），步骤里写上 `body_file`；填 `proxy`、`ca_file`、`home_dir`、`work_dir`、`timeout_s`、`variant`。
4. 在干净环境里启动驱动：`<注册表里的 cmd> <用例.json> <结果.json>`。总超时是顶层各步 `timeout_s` 之和
   （`parallel` 算一步，`sleep` 按它的时长）加 30 秒；超时就把驱动连同它的子进程杀掉，记 `driver.timeout=true`。
5. 等 300 毫秒，SIGTERM obsproxy 并等它退出；再等 300 毫秒，SIGINT tcpdump，读它的统计。
6. 调 `pcap_check.check(run.pcap, events.jsonl)`。模块导入不了时记 `{"status": "missing"}`，运行照常进行。

tcpdump 的两个附加参数是实测出来必须加的：不加 `--immediate-mode`，停抓包前最后约 1 秒的包还在内核缓冲里，
SIGINT 时直接丢掉（短的运行会抓到 0 个包）；加了以后默认的缓冲区在 6 路并发的用例上会报 `dropped by kernel`，
`-B 32768`（32 MiB）之后 80 次并发用例没有再出现。

## 干净环境

被测客户端（驱动进程及其子进程）只看得到这些环境变量：

| 变量 | 值 |
| --- | --- |
| `PATH` | 沿用外面的 |
| `HOME` | 这次运行专用的目录，从 home 模板复制 |
| `LANG`、`LC_ALL` | `C.UTF-8` |
| `TMPDIR` | 这次运行的工作目录 |
| 注册表里该驱动声明的 `env` | 值里可用 `{ca_file}`、`{home}`、`{work}`、`{repo}` |

其余一概不继承：`*_proxy`、`NO_PROXY`、`SSL_CERT_FILE`、`CURL_CA_BUNDLE`、`REQUESTS_CA_BUNDLE`、`NODE_EXTRA_CA_CERTS` 等都没有。
信任测试 CA 的办法是把 `ca.pem` 加进信任根（参数、驱动声明的环境变量，或 NSS 数据库），不关闭证书校验。
obsproxy 和 certutil 也在同样的环境里运行；`go build` 和 tcpdump 用外面的环境。

## 注册表

`../drivers/registry.json` 是列名到驱动的映射，新驱动在里面加一项即可：

```json
{"curl": {"cmd": ["python3", "drivers/curl/driver.py", "--variant", "curl"], "env": {}, "desc": "…"}}
```

`cmd` 里含 `/` 的相对路径相对于 `research/phase2/`；`cmd` 和 `env` 的值都可以用上面四个模板。
`cmd` 后面加 `--versions` 时，驱动要在标准输出打印一个 JSON 对象（客户端和依赖的版本）。
以下划线开头的键、或没有 `cmd` 的项会被忽略，可以用来放说明。

## 输出

`out/raw/<列>.jsonl.gz`：每行一条记录，按用例号、遍数排序；gzip 头里的 mtime 固定为 0、不带文件名。
只重跑一部分时合并进已有文件，同一个“用例 + 遍数”的旧记录被替换。

```json
{
  "variant": "curl", "case": "B02", "repeat": 1,
  "ports": {"proxy_port": 40123, "origin_http_port": 40124, "origin_https_port": 40125},
  "events": [],
  "result": {},
  "driver": {"exit": 0, "timeout": false, "stderr_tail": "", "ms": 64},
  "tcpdump": {"captured": 23, "received": 46, "dropped": 0},
  "pcap_check": {"status": "ok"},
  "skipped": null,
  "runner_errors": []
}
```

- `events`：obsproxy 的全部事件（格式见 [`../harness/EVENTS.md`](../harness/EVENTS.md)）。
- `result`：驱动写的结果文件；驱动崩溃或超时而没写出来时是 `null`。
- `tcpdump`：`captured`、`received by filter`、`dropped by kernel` 三个数。判断丢包只看 `dropped`；
  回环网卡上 `received` 恒为 `captured` 的两倍（每个包进、出各过一次过滤器）。
- `pcap_check`：`pcap_check.check` 的返回值；另有 `missing`（模块导入不了）和运行器自己记的 `error`。
- `skipped`：用例的 `only` 非空且不含该列时是 `"only"`，这时不运行，其余字段为空。
- `runner_errors`：运行器这一层的问题（仪器没起来、抓包没起来、事件文件不完整等）；非空的运行不能用。

`out/versions.json`：每个驱动 `--versions` 的输出，加上环境信息（发行版、内核版本、架构、obsproxy 和 tcpdump 的版本、
运行时刻 UTC）。不记录主机名、用户名、IP。只跑一部分列时，其余列保留原来的记录。

抓包文件默认随工作目录删除；`--keep-pcap` 时留在 `<work>/runs/<列>/<用例>-r<遍数>/`。
核对结论是 `mismatch` 或 `error` 的运行，工作目录总是保留，供查原因。

## 仪器自检和全链路

`selfcheck.py` 是仪器自检（[`../PROTOCOL.md`](../PROTOCOL.md)“仪器自检”一节）的闸门：读 `<out>/selfcheck.json`
（`matrix.py` 写的 rawref 一列；没有时读 `<out>/matrix.json` 里的 rawref 列）和 `../selfcheck_expected.json`，
按行表逐行比较。它不采信 `matrix.py` 自己写的 `pass`，而是重新比：格子缺失、各遍取值不同、值与答案不同、
答案里多出行表没有的行，都算不一致。

```sh
python3 runner/selfcheck.py --out /path/to/out      # 退出码：0 全部相同；1 有不一致（逐条列出）；2 输入读不了或没有 rawref 的数据
```

`matrix.py` 在自检不通过时只在标准错误里提示、退出码仍是 0，所以要靠 `selfcheck.py` 的退出码把关。

`../run_all.sh` 把整条链按顺序跑一遍，任何一步失败就停：构建 obsproxy（到临时目录）→ `gofmt`、`go vet`、`go test -race`
→ 本目录和各驱动的单元测试 → `run.py` → `derive.py` → `matrix.py` → `selfcheck.py`。
`--variants`、`--repeats`、`--out`、`--tcpdump` 原样传给 `run.py`，`--out` 同时是后面三步读写的目录。

```sh
./run_all.sh                                             # 注册表里的全部列，各 3 遍，写到 research/phase2/out
./run_all.sh --variants rawref --repeats 1 --out /path/to/out
```

## 测试

```sh
python3 -m unittest discover -s research/phase2/runner -p 'test_*.py'
python3 -m unittest discover -s research/phase2/drivers/curl -p 'test_*.py'
```
