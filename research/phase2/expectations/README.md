# 预先登记的预期

每个文件对应矩阵的一列（被测客户端的一种用法），文件名就是列名：`<列>.json`。
里面是在任何实测之前，只凭该客户端的文档、源码和变更记录写下的预期：行表（[`../rows.json`](../rows.json)）的每一行会测出什么值。
方案见 [`../PROTOCOL.md`](../PROTOCOL.md) 的“预期”一节。

## 何时写的

2026-11-10，第一次正式运行之前（各文件的 `written` 字段）。写的时候不许让客户端连任何代理，`method` 字段写明“只凭文档和源码，未做任何实测”。
实测开始以后这些文件不改：对不上的格子要么是仪器或驱动有问题，要么是文档和印象错了，两种都记进报告。

## 文件格式

- `variant`：列名，与文件名一致。
- `client_version`、`sources`：读的是哪个版本、哪些文件。
- `rows`：`{行号: {expect, basis, confidence}}`，104 行都有。
  - `expect`：`matrix.py` 会输出的规范化字符串（行表里 `values` 的固定取值，或按 `how` 写出的确切字符串），或“不知道”。
  - `basis`：依据。源码写“路径:行号”加一句解释，文档写章节名或选项名。
  - `confidence`：`high`、`medium`、`low`。

## “不知道”的含义

读了文档和源码仍然没有把握，所以不写预期。这样的行不参加比对，不算对也不算错。
它不等于“不支持”或“不适用”：后两者是有依据的预期（这个客户端做不到，或这一行不看这一列），照常比对。

## 怎么与实测比

`runner/matrix.py` 生成矩阵时读这个目录（`--expectations`，默认就是这里），由 `build_expectation_diff` 逐格比较，
写出 `out/expectation_diff.json` 和 `out/expectation_diff.md`。
一个格子算相符，要求实测值在各遍之间稳定，并且与 `expect` 逐字相同；“不知道”的行和该列没有数据的行不比。
因为是逐字比较，写法必须规范。提交前跑：

```sh
cd research/phase2
python3 runner/check_expectations.py          # 有问题退出 1 并逐条列出
python3 runner/check_expectations.py --stats  # 另外打印下面这张表
```

检查器除了行表的词表，还接受两种 `matrix.py` 自己会输出的写法，并把它们列为提示：
“其他：<消息>”（消息要与 `matrix.py` 里的字面量逐字相同）和多用例行的后缀“（不含 <用例号>：不支持）”。
目前有 5 格是这样写的：`node-fetch-env` 的 R19、R20、R39、R90，`node-http-env` 的 R39。

## 统计

由 `runner/check_expectations.py --stats` 生成，不手改。“给了预期”是 `expect` 不是“不知道”的行数（含“不支持”“不适用”），后三列是其中各置信度的行数。

| 列 | 给了预期 | high | medium | low | 不知道 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `curl` | 104 | 89 | 15 | 0 | 0 |
| `curl-anyauth` | 104 | 87 | 17 | 0 | 0 |
| `requests` | 103 | 93 | 10 | 0 | 1 |
| `go` | 104 | 98 | 6 | 0 | 0 |
| `node-fetch-env` | 104 | 85 | 19 | 0 | 0 |
| `node-http-env` | 102 | 96 | 6 | 0 | 2 |
| `node-undici` | 104 | 84 | 19 | 1 | 0 |
| `node-agents` | 104 | 94 | 10 | 0 | 0 |
| `node-axios` | 104 | 88 | 16 | 0 | 0 |
| `chromium-pw` | 104 | 84 | 16 | 4 | 0 |
| `firefox-pw` | 103 | 51 | 52 | 0 | 1 |
