# research/phase2：规范与客户端行为矩阵

第 2 阶段（`docs/brief.md` 1B 第 5 条）。结论在 [`docs/research/phase2-report.md`](../../docs/research/phase2-report.md)，
测量口径在 [`PROTOCOL.md`](PROTOCOL.md)。先读 PROTOCOL，再读这里。

| 路径 | 内容 |
| --- | --- |
| `PROTOCOL.md` | 测量方案：问题与设计决定的对应、被测客户端、仪器、用例、矩阵规则、变更记录 |
| `cases.json`、`rows.json` | 90 个用例和矩阵的 104 行（取值规则）；由 `tools/gen_cases.py`、`tools/gen_rows.py` 生成，逐字节可重现 |
| `expectations/` | 11 列客户端的预期，只凭文档和源码写，先于该列的正式实测；实测之后不改 |
| `caveats.json` | 读数须知：实测之后补的说明，只加说明、不改取值 |
| `spec/` | 从 RFC 原文摘出的 372 条条款，`check_quotes.py` 逐字核对引文；说明见 `spec/README.md` |
| `harness/` | 仪器 `obsproxy`（Go 标准库）：HTTP 代理、SOCKS5 代理和源站合在一个进程里，事件格式见 `harness/EVENTS.md` |
| `runner/` | `run.py` 取数（带抓包核对）、`derive.py` 提取事实、`matrix.py` 生成矩阵、`collect.py` 汇总、`selfcheck.py` 仪器自检、`compare_env.py` 两个环境对比；说明见 `runner/README.md` |
| `drivers/` | 各客户端的驱动和写驱动之前的笔记（`NOTES.md`），`registry.json` 是列名到命令的注册表 |
| `selfcheck_expected.json` | 参照客户端 `rawref` 的手写答案 |
| `tools/report_tables.py` | 报告里的表格；`--check` 核对报告引用的每个格子和条款号 |
| `out/` | 输出：`raw/`（每列的原始记录）、`matrix.{json,md}`、`expectation_diff.*`、`selfcheck.json`、`pcap_check.json`、`versions.json`、`spec_clauses.md`、`report_tables.md` |
| `run_all.sh` | 全链路：构建仪器、测试、取数、矩阵、自检 |

`out/observations/` 不进仓库，由 `runner/derive.py` 从 `out/raw/` 重新生成。`firefox-pw` 一列只能在 CI 上跑（`.github/workflows/phase2.yml`）。

全部连接都在 127.0.0.1 上，不访问任何第三方地址。除安装依赖外不需要网络。
