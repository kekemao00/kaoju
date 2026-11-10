# research/

第一阶段研究用到的脚本和数据。普查和竞品拆解的结果都可以用下面的命令重新生成；实测工具在 `fieldtest/`，有自己的说明。

## 目录

| 路径 | 内容 |
| --- | --- |
| `census/fetch_history.sh` | 克隆列表仓库的 30 天历史、节点订阅仓库的最新快照，下载离线 ASN/国家库 |
| `census/sources.json` | 纳入普查的 18 个 HTTP/SOCKS 列表仓库及其文件路径 |
| `census/census.py` | 重建条目时间线，计算更新节奏、在榜时长、包含度矩阵、独占条目、网络集中度 |
| `census/nodes_census.py` | 解析 11 个节点订阅的分享链接，统计协议构成、去重、重叠、跳过证书校验的比例 |
| `census/report_tables.py` | 把普查结果整理成报告里的表格和数字，避免手抄 |
| `census/parse_check.py` | 按文件输出普查脚本的解析结果，供实测工具的解析器逐个文件核对 |
| `census/make_heatmap_widget.py` | 从包含度矩阵生成报告里那张热力图的绘图代码 |
| `census/out/` | 上述脚本的输出，以及上游追溯的数据 |
| `competitors/classify_issues.py` | jhao104/proxy_pool 290 条未关闭 issue 的归类（人工，依据标题） |
| `competitors/notes.md` | 竞品拆解的证据清单：项目、提交号、文件路径、结论 |
| `fieldtest/` | 第一阶段 1B 的实测工具：judge 端点、列表快照采集器、分阶段探测器。部署见 `fieldtest/README.md`，测量口径见 `fieldtest/PROTOCOL.md` |
| `phase1b/` | 第一阶段 1B 实测数据的分析：入库（SQLite）、九个指标模块、事后分析、报告表格（`run_all.sh` 一键运行）。结论见 `../docs/research/phase1b-report.md`，说明见 `phase1b/README.md` |

## 复现

需要 git、python3（3.10 以上，只用标准库）和 npm。全程只读 GitHub，不连接任何代理。

```bash
cd research/census
./fetch_history.sh /tmp/census-work 2026-10-06      # 约 1.4 GB 磁盘
python3 census.py --hist-dir /tmp/census-work/hist --ipdb-dir /tmp/census-work/ipdb --out out/   # 约 10 分钟
python3 nodes_census.py --nodes-dir /tmp/census-work/nodes --ipdb-dir /tmp/census-work/ipdb --out out/
python3 report_tables.py
python3 ../competitors/classify_issues.py
```

列表每天都在变，重新运行得到的数字会和报告里的不同；报告里的数字对应 2026-11-05 的快照。
要得到完全相同的结果，需要把各仓库检出到 `out/census_summary.json` 里记录的最后一次快照时间之前。

## `census/out/` 文件说明

| 文件 | 说明 |
| --- | --- |
| `census_summary.json` | 列表普查的全部数字 |
| `sources_summary.csv` | 每个来源一行的汇总 |
| `overlap_matrix.csv` | 行来源被列来源包含的百分比 |
| `nodes_summary.json`、`nodes_summary.csv`、`nodes_overlap_matrix.csv` | 节点订阅普查 |
| `repo_refcount.txt` | 三个聚合器引用的 GitHub 仓库及被引用次数 |
| `repo_liveness.tsv` | 这些仓库是否还在、最后一次提交时间 |
| `gfpcom_urls.txt`、`sevenworks_urls.txt`、`monosans_urls.txt` | 三个聚合器各自的上游 URL 清单 |

## 数据来源与许可

- 列表仓库的内容归各仓库所有，本目录只保存统计结果，不转存列表本身。
- 网络归属使用 [ip-location-db](https://github.com/sapics/ip-location-db) 的 ASN 库
  （CC BY 4.0，数据来自 RouteViews、DB-IP、NRO）和国家库（CC0）。
