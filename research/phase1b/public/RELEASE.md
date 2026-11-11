# 1B 公开库 第 1 版

脱敏后的 1B（72 小时实测）逐条记录，一个 SQLite 文件。说明见 [`research/phase1b/PUBLIC.md`](../PUBLIC.md)，决策 D16、D18。

| 文件 | 字节 | SHA-256 |
| --- | --- | --- |
| `phase1b-public-v1.sqlite.xz`（发布附件） | 695,145,580 | `c4573ea9715f896dc15df487755eebb694d71e26a9eab686d02ead264247785b` |
| `phase1b-public-v1.sqlite`（解压以后） | 5,503,934,464 | `22c88af3410b3e9675685088b049e5323c489893a84fd858eb7ba2cd4155dd50` |

发布地址：**还没有发布**（等用户确认；发布以后在这里填上）。

## 用法

```sh
sha256sum phase1b-public-v1.sqlite.xz        # 与上表核对
xz -dk phase1b-public-v1.sqlite.xz
cd research/phase1b
./run_public.sh /path/phase1b-public-v1.sqlite /tmp/phase1b-out
python3 pub_check.py compare /tmp/phase1b-out out/
```

## 这一版的检查结果

- 导出报告：[`export_report.json`](export_report.json)（每张表留了哪些列、换了哪些列）
- 残留扫描：[`scan_report.json`](scan_report.json)（没有发现残留）
- 与 `out/` 的比对：[`compare.txt`](compare.txt)（只有清单里的差别）
- 假名能被公开列表的历史对回去的比例：[`linkage.json`](linkage.json)
