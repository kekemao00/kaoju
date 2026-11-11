# 1B 公开库 第 1 版

脱敏后的 1B（72 小时实测）逐条记录，一个 SQLite 文件。说明见 [`research/phase1b/PUBLIC.md`](../PUBLIC.md)，决策 D16、D18。

发布地址：<https://github.com/kekemao00/kaoju/releases/tag/phase1b-public-v1>（2026-11-11 发布）。
附件是压缩文件拆成的 4 段，下载后按顺序合并成一个文件再核对。

| 文件 | 字节 | SHA-256 |
| --- | --- | --- |
| `phase1b-public-v1.sqlite.xz.part-0` | 209,715,200 | `a138403f5f0ec8fd96f816d4054aaa3bef690519002b361bff9ebde01041ce54` |
| `phase1b-public-v1.sqlite.xz.part-1` | 209,715,200 | `f9aa850993f3f3ed0b0b3ea1ce3bd51ee1c220a49505e38d80e7f62b3958ad5b` |
| `phase1b-public-v1.sqlite.xz.part-2` | 209,715,200 | `f5122a778ab1238aec4d3b65371e1789906740c3c362042ca19fe512fccc9b41` |
| `phase1b-public-v1.sqlite.xz.part-3` | 65,999,980 | `77b98e9d6de950d231560f19f680d95900afb2be35b3492c69da05864bbcdc44` |
| `phase1b-public-v1.sqlite.xz`（4 段合并） | 695,145,580 | `c4573ea9715f896dc15df487755eebb694d71e26a9eab686d02ead264247785b` |
| `phase1b-public-v1.sqlite`（解压以后） | 5,503,934,464 | `22c88af3410b3e9675685088b049e5323c489893a84fd858eb7ba2cd4155dd50` |

上面 4 段的 SHA-256 与 GitHub 给每个附件记的摘要（Release 页面上每个文件旁边的 `sha256:`）逐一核对过，相同。

## 用法

```sh
base=https://github.com/kekemao00/kaoju/releases/download/phase1b-public-v1
for i in 0 1 2 3; do curl -LO "$base/phase1b-public-v1.sqlite.xz.part-$i"; done
cat phase1b-public-v1.sqlite.xz.part-0 phase1b-public-v1.sqlite.xz.part-1 \
    phase1b-public-v1.sqlite.xz.part-2 phase1b-public-v1.sqlite.xz.part-3 > phase1b-public-v1.sqlite.xz
sha256sum phase1b-public-v1.sqlite.xz        # 与上表核对
xz -dk phase1b-public-v1.sqlite.xz
cd research/phase1b
./run_public.sh /path/phase1b-public-v1.sqlite /tmp/phase1b-out
python3 pub_check.py compare /tmp/phase1b-out out/
```

导出用的密钥在发布以后删掉了：从假名算不回原值，连导出的人也一样。以后要重新导出就换一把新密钥、升版本号。

## 这一版的检查结果

- 导出报告：[`export_report.json`](export_report.json)（每张表留了哪些列、换了哪些列）
- 残留扫描：[`scan_report.json`](scan_report.json)（没有发现残留）
- 与 `out/` 的比对：[`compare.txt`](compare.txt)（只有清单里的差别）
- 假名能被公开列表的历史对回去的比例：[`linkage.json`](linkage.json)
