# 第 2 阶段报告用的表格

由 `tools/report_tables.py` 生成，不要手改。

**规模。** 用例 90 个（A 组 16、B 组 14、C 组 8、D 组 11、E 组 7、F 组 12、S 组 22），每个 3 遍；矩阵 104 行 × 11 列，其中有数据的 11 列。

**仪器自检。** 参照客户端 `rawref` 一列与手写答案比较 104 行，不一致 0 行，结论：通过。

**各列的版本和正式运行的时刻**（`out/versions.json`）

| 列 | 版本 | 运行时刻（UTC） | 系统 |
| --- | --- | --- | --- |
| `curl` | curl 8.5.0；distro_packages curl 8.5.0-2ubuntu10.16、libcurl4t64 8.5.0-2ubuntu10.16；openssl 3.0.13；nghttp2 1.59.0 | 2026-11-10T23:42:22Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `curl-anyauth` | curl 8.5.0；distro_packages curl 8.5.0-2ubuntu10.16、libcurl4t64 8.5.0-2ubuntu10.16 | 2026-11-10T23:48:35Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `requests` | requests 2.34.2；urllib3 2.8.0；PySocks 1.7.1；python 3.13.18；openssl OpenSSL 3.5.9 29 Sep 2026 | 2026-11-10T19:41:44Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `go` | go go1.24.7 | 2026-11-10T19:44:38Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-fetch-env` | node 22.23.4；node 内置的 undici 6.29.1；openssl 3.5.9 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-http-env` | node 22.23.4 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-undici` | node 22.23.4；undici 8.12.4 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-agents` | node 22.23.4；http-proxy-agent 9.1.0；https-proxy-agent 9.1.0；socks-proxy-agent 10.1.0；socks 2.8.10 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `node-axios` | node 22.23.4；axios 1.21.1；axios 自带的 https-proxy-agent 5.0.1；follow-redirects 1.16.3 | 2026-11-10T23:41:48Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `chromium-pw` | playwright 1.63.0；browser_version 153.0.8010.12；node v22.23.4 | 2026-11-10T23:35:08Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |
| `firefox-pw` | playwright 1.63.0；browser_version 155.0；node v22.23.4 | 2026-11-11T01:13:16Z | Ubuntu 24.04.5 LTS，内核 7.0.0-1017-azure |
| `rawref` | rawref 1 | 2026-11-10T23:35:22Z | Ubuntu 24.04.5 LTS，内核 6.18.44-fc-v338 |

**运行次数和抓包核对**（`out/pcap_check.json`）

| 列 | 运行 | 按用例的 only 跳过 | 逐字节相同 | prefix | 不一致 | tcpdump 丢包 | 运行器出错 | 驱动超时 | 驱动非零退出 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `chromium-pw` | 270 | 0 | 270 | 0 | 0 | 0 | 0 | 0 | 0 |
| `curl` | 264 | 6 | 261 | 3 | 0 | 0 | 0 | 0 | 0 |
| `curl-anyauth` | 264 | 6 | 261 | 3 | 0 | 0 | 0 | 0 | 0 |
| `firefox-pw` | 270 | 0 | 270 | 0 | 0 | 0 | 0 | 0 | 0 |
| `go` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-agents` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-axios` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-fetch-env` | 270 | 0 | 270 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-http-env` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `node-undici` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| `rawref` | 270 | 0 | 264 | 6 | 0 | 0 | 0 | 0 | 0 |
| `requests` | 264 | 6 | 264 | 0 | 0 | 0 | 0 | 0 | 0 |
| 合计 | 3192 | 48 | 3180 | 12 | 0 | 0 | 0 | 0 | 0 |

**实测与预期**（`out/expectation_diff.md`；预期写于实测之前）

| 列 | 比较的格子 | 相符 | 不符 | 预期是“不知道” | 不符的行 |
| --- | --- | --- | --- | --- | --- |
| `curl` | 104 | 104 | 0 | 0 |  |
| `curl-anyauth` | 104 | 104 | 0 | 0 |  |
| `requests` | 103 | 103 | 0 | 1 |  |
| `go` | 104 | 104 | 0 | 0 |  |
| `node-fetch-env` | 104 | 96 | 8 | 0 | R10、R11、R36、R38、R94、R95、R99、R101 |
| `node-http-env` | 102 | 102 | 0 | 2 |  |
| `node-undici` | 104 | 96 | 8 | 0 | R11、R92、R93、R94、R95、R98、R99、R122 |
| `node-agents` | 104 | 104 | 0 | 0 |  |
| `node-axios` | 104 | 104 | 0 | 0 |  |
| `chromium-pw` | 104 | 103 | 1 | 0 | R89 |
| `firefox-pw` | 103 | 96 | 7 | 1 | R11、R13、R81、R85、R92、R98、R122 |
| 合计 | 1140 | 1116 | 24 | | |

**矩阵里的格子。** 各遍取值不同（不稳定）的 6 格；落到“其他：”的 3 格；“不支持”的 99 格；挂了读数须知的 82 格（`caveats.json` 共 19 条）。

**规范条款**（`spec/clauses/`，引文由 `spec/check_quotes.py` 逐字核对）

| RFC | 条款数 | 其中标了矩阵行的 |
| --- | --- | --- |
| RFC 1928 | 29 | 20 |
| RFC 1929 | 8 | 8 |
| RFC 6455 | 6 | 5 |
| RFC 7617 | 23 | 17 |
| RFC 9110 | 147 | 116 |
| RFC 9112 | 113 | 69 |
| RFC 9113 | 4 | 0 |
| RFC 9209 | 42 | 26 |
| 合计 | 372 | 261 |
