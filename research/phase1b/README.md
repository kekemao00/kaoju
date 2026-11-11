# research/phase1b/

第一阶段 1B（72 小时实测）的分析脚本。原始数据先灌进 SQLite，九个指标模块各算一类指标写成 JSON，
事后分析模块 `m_posthoc.py`（看过数据以后加的，决策 D14）另写一个 JSON，`report_tables.py` 再把这些 JSON 整理成报告里用的 Markdown 表格。
结论写在 [`../../docs/research/phase1b-report.md`](../../docs/research/phase1b-report.md)。口径以 [`../fieldtest/PROTOCOL.md`](../fieldtest/PROTOCOL.md)
第 1.2 版为准，库的表结构见 [`SCHEMA.md`](SCHEMA.md)。报告里的数字都由这里的脚本生成，不手抄。

只用 Python 3.10 以上的标准库（含 sqlite3）；证书链校验用只依赖 Go 标准库的小工具 `certcheck/`。不联网。

## 目录

| 路径 | 内容 |
| --- | --- |
| `run_all.sh` | 一键运行：编译 certcheck → 入库 → 九个模块 → 事后分析 → 报告表格，任何一步失败就停，最后打印各步用时 |
| `ingest.py` | 把 `probe-` / `judge-` / `snap-` 记录（`.jsonl` 或 `.jsonl.gz`，同一小时两种都有时只读一份）、`state.json.gz`、`evidence/` 清单流式灌进 SQLite；`state.json.gz` 里带时区（真实数据是 +08:00）的时间保留偏移换算成 UTC |
| `SCHEMA.md` | 库的表结构：每列对应哪个 Go 结构体字段、时间怎么换算、已知的坑、可以出现在输出里的列（白名单） |
| `m_instrument.py` | 仪器核对：对照、不变量、连接速率、运行段与中断、记录文件完整性、启动积压、证据库、快照完整性 |
| `m_availability.py` | 可用率：漏斗（连得上、有协议回应、累计可用率、要求认证）、时点可用率序列、各来源、聚合器抽样与独有条目、从没探访过的条目 |
| `m_lifetime.py` | 寿命：Kaplan–Meier（第一段寿命与全部寿命）、死而复生、各来源、实际复测间隔 |
| `m_freshness.py` | 列表时效：上榜新鲜度、下榜滞后、下榜后是否其实还活着、快照增减序列 |
| `m_labels.py` | 标签准确率（严格 / 宽松两种映射）、标签与实测的对照表、https 标签的端口是否说 TLS、CONNECT 连 80 端口 |
| `m_integrity.py` | 内容被改（截断 / 局部改动 / 整页替换、gzip）、响应头、匿名程度、请求被改、重放、出口地址、节点出口 |
| `m_mitm.py` | “中间人”总数与三层细分（冒充 judge / 被送到别的网站 / 去向不明），按叶子证书和 /24 汇总 |
| `m_nodes.py` | 免费节点：构成、严格与照链接两种可用、严格校验的损失、预检、轮次、出口不变量、订阅快照、sing-box 报错分类 |
| `m_literature.py` | 与 Mani 等 2018、Tsirantonakis 等 2018、Mehanna 等 2024 逐项对账（内容与中间人的分类规则直接调用 m_integrity / m_mitm） |
| `m_posthoc.py` | 事后分析（决策 D14，不是 PROTOCOL 原定口径）：主要比例按 IP 重算、整页替换按正文归并并认出 judge 自己的说明页、经 Cloudflare 转发的请求、中间人 IP 的两群（可选：落在 AWS 公布地址段里的） |
| `certcheck/` | 证书链离线校验（`main.go`，只用 Go 标准库）：按尝试时刻、用固定的公共根证书校验证据里存下的链，不看主机名、不补全中间证书 |
| `report_tables.py` | 读 `out/*.json`，打印报告用的全部表格和关键数字，并把 PROTOCOL“与文献对账”的预期范围和实测值并排、标出是否在范围内 |
| `crosscheck_as_summary_saw.py` | 核对“与 summary.json 不一致”是否全由 summary 漏读的 judge 文件造成（SCHEMA 坑 20）：把这些文件在库里用 TEMP VIEW 藏起来，原样重跑指定模块，比对藏前藏后的不一致项。`run_all.sh` 之后单独跑，写 `out/rotation_check.json` |
| `check_report_numbers.py` | 核对 `docs/research/phase1b-report.md` 正文里的数都能在 `out/report.md` 和 `out/*.json` 里找到（数字不手抄）；不是数据的常量列在脚本的 `ALLOWED` 里并写明理由 |
| `out/` | 输出目录：十个模块 JSON、`rotation_check.json` 和 `report.md`。只提交真实数据的结果；夹具或合成数据的输出不提交 |
| `PUBLIC.md` | 公开数据（决策 D16、D18）：公开的是什么、假名和代表值的规则、随库带上的中间结果、重算结果与 `out/` 必然不同的字段、脱敏挡不住什么 |
| `run_public.sh` | 第三方的一条命令：在公开库上重算全部输出（不要 Go、证据文件和真实地址） |
| `pub_export.py` | 真实库 → 公开库：白名单里的列、带密钥的假名、等价的代表值、随库带上的中间结果；`--selftest` 在合成库上核对 |
| `pub_pseudo.py` | 假名的规则（HMAC-SHA256）：地址保持 /24 结构、judge 的地址单列、哈希和编号等长 |
| `pubdb.py` | 真实库与公开库之间的接缝：真实库上记下模块从证据文件算出的中间结果（`PHASE1B_RECORD`），公开库上取回 |
| `pub_check.py` | `compare`：重算结果与 `out/` 比对，只允许清单里的差别；`scan`：用真实库里的身份值扫公开库；`linkage`：假名能被公开列表历史对回去的比例 |
| `public/` | 导出报告、扫描结果、比对结果和 linkage 的计数（只有计数和列名） |

## 复现

没有原始数据的第三方：用公开库和 `run_public.sh`，见 [`PUBLIC.md`](PUBLIC.md)。下面是从原始数据包开始的做法。

需要：Python 3.10 以上；Go 1.24（编译 certcheck，或者用 `CERTCHECK=` 指定已编译的二进制）；
系统根证书 `/etc/ssl/certs/ca-certificates.crt`（Debian / Ubuntu 的 ca-certificates 包，包版本和 Mozilla 根库版本会写进 `mitm.json`，
换一台机器分析，“被送到别的网站”一层的结果可能不同）。

```sh
cd research/phase1b
mkdir -p /data/1b && tar xzf fieldtest-pack.tar.gz -C /data/1b      # 解出 /data/1b/fieldtest/
./run_all.sh /data/1b/fieldtest /data/1b/state.json.gz /data/1b/phase1b.sqlite
```

- 第一个参数是解包后的 `fieldtest/` 目录（指向它的上一层也行）；第二个是单独传来的 `state.json.gz`（写 `-` 表示用数据目录里的同名文件，没有就不建候选池表）；
  第三个是 SQLite 库的路径，**不要放在仓库里**（`run_all.sh` 和 `ingest.py` 都拒绝仓库内的路径；仓库根的 `.gitignore` 也挡住了 `*.sqlite`、`*.db`、`probe-` / `judge-` / `snap-` 记录、`state.json(.gz)`、`evidence/` 和部署包）。
- 库已存在时要加 `--force`（删掉重建）或 `--skip-ingest`（沿用，只重跑模块和报告）。
- 可选环境变量：`PYTHON`、`CERTCHECK`、`ROOTS`（公共根证书 PEM）、`ROOTS_NOTE`（根证书库的说明，读不到包版本时用）、
  `FORMAL_START`（见下面“正式起点”）、`AWS_RANGES`（AWS 公布的 `ip-ranges.json`，给了 `m_posthoc` 就数中间人 IP 落在其中的比例，
  文件的 `syncToken` 和 `createDate` 写进 `posthoc.json`；文件本身不进仓库，换一天下载结果可能略有不同）。SQLite 的临时排序文件放在 `SQLITE_TMPDIR`（没设就是 `TMPDIR`）指向的目录，真实数据需要几 GB 的空间。
- 输出：`out/<模块>.json` 十个、`out/report.md`（跑模块之前先删掉上一次生成的这十一个文件）；标准错误上是各步的进度和最后的用时表，
  标准输出上是 `report.md` 第三节（预期范围 vs 实测）那张表。需要 bash 4.4 以上。
- 真实数据上的体积和用时（2026-11-10，4 核、15 GB 内存的云端工作区，Python 3.13）：数据包（`fieldtest pack` 的输出）525 MB，入库 220 个文件、982 万条记录用 330 秒，库 12.2 GB。
  `run_all.sh --skip-ingest` 各步：instrument 104 秒、availability 174 秒、lifetime 49 秒、freshness 585 秒、labels 102 秒、integrity 366 秒、
  mitm 57 秒、nodes 370 秒、literature 424 秒、posthoc 223 秒、report 约 20 秒（输出检查改成按词查集合以前要 33 分钟），合计约 41 分钟。这次运行时机器上同时还在跑另一个核对，单独跑会快一些。
- 跑完 `run_all.sh` 之后再跑两个核对（用时约 20 分钟和 1 秒）：

  ```sh
  python3 crosscheck_as_summary_saw.py --db /data/1b/phase1b.sqlite --summary /data/1b/fieldtest/summary.json \
      --data /data/1b/fieldtest --certcheck <certcheck 二进制> --write out/rotation_check.json
  python3 check_report_numbers.py      # 核对 docs/research/phase1b-report.md 里的数
  ```

### 正式起点

PROTOCOL“正式测量的起止”和决策 D13：72 小时从最终版本的探测器启动算起（2026-11-06 约 08:06 UTC，以 `probe-` 里的 `start` 记录为准），
之前的数据标为试运行，不并入。各模块按同一条规则从 `start` / `version` 记录推起点（第一条 start；之后若有状态被清空的 start
或版本变了，取最后一次这样的 start），只有 `m_lifetime` 默认取第一条 start。跑完先看 `report.md` 第一节：

- 各模块的正式起点不一致，或者不是 D13 写的那一刻，就用 `FORMAL_START=<带时区的 ISO 时间> ./run_all.sh --skip-ingest ...` 重跑，
  它会传给所有模块（`m_lifetime` / `m_freshness` 用 `--since`，其余用 `--formal-start`）。
- 各模块都不裁 72 小时的上界（`m_mitm` 的 `--formal-end 72h` 可以单独裁），超出的时长写在第一节，引用数字时写明实际时长。

### 夹具上的烟雾测试

fieldtest 的端到端测试会在工作目录里留下一份小数据（58 个候选、33 个夹具代理、10 个节点用例，约 4 分钟），布局与真实数据相同：

```sh
cd research/fieldtest
SINGBOX=/path/to/sing-box ./test/e2e.sh /tmp/e2e-1b          # 约 5 分钟，数据在 /tmp/e2e-1b/data
cd ../phase1b
./run_all.sh --force /tmp/e2e-1b/data /tmp/e2e-1b/data/state.json.gz /tmp/e2e-1b/phase1b.sqlite
rm -f out/*.json out/report.md                                # 夹具的输出不提交
```

在夹具上，做交叉核对的七个模块与 fieldtest 自带汇总（`summary.json`）应当逐项一致，只有 `judge.req` 差一条
（summary 生成时 judge 还没落盘最后一条，SCHEMA 的坑 7）。真实数据上 judge 相关的差得多，原因是 summary 跨整点生成时漏掉了刚轮转的文件
（SCHEMA 的坑 20），`instrument.json` 的 `crosscheck.judge_rotation` 逐项核对过。夹具故意放了篡改、冒充 TLS、透明代理等行为，
所以第三节里有几项落在 PROTOCOL 预期范围之外，这是夹具的构成所致；夹具只跑了几分钟，报告里“跑满 72 小时：否”也是预期的。

### 单独运行与自检

```sh
python3 m_<模块>.py --db 库 --out out/ [--summary 数据目录/summary.json] [--markdown]   # m_mitm、m_literature 另要 --data 数据目录
python3 m_<模块>.py --selftest        # 每个模块在临时目录里建合成库，核对预期值
python3 report_tables.py --selftest   # 范围判断、输出检查、PROTOCOL 常量与原文一致
python3 report_tables.py --db 库 --no-appendix   # 只要正文的表格
```

## 每个模块算什么

| 模块 | PROTOCOL 小节 | 主要指标（JSON 里的位置） |
| --- | --- | --- |
| `m_instrument` | 对照与自检、频率与限速、正式测量的起止、记录 | 对照成功率与失败时段（`controls`）；六条不变量（`invariants`）；连接速率（`rate`）；stat 与记录文件（`runtime`）；启动积压（`backlog`）；证据库缺失（`evidence`）；快照完整性（`snapshots`）；被排除的条目（`excluded`）；测量机上的预检与仪器自检（`preflight`，从数据目录里的 `preflight.txt` 只取时间、自检项数、sing-box 版本和结论，主机名和地址不读）；总结论（`verdict`） |
| `m_availability` | 指标定义（连得上、有协议回应、可用、时点 / 累计可用率）、测量对象 | 漏斗（`funnel`）、时点序列与结束时刻（`point_series`、`point_end`）、累计可用率（`cumulative`）、各来源（`by_source`）、聚合器（`aggregators`）、从没探访过（`never_visited`）、密集 /24（`dense_prefixes`） |
| `m_lifetime` | 指标定义（寿命） | 各组 Kaplan–Meier（`groups.*.first_life_km`、`all_lives_km`）、死而复生（`resurrection`）、各来源（`by_source`）、复测间隔（`retest_interval`）、停机与回环失败窗口（`window`） |
| `m_freshness` | 指标定义（上榜新鲜度、下榜滞后） | 上榜新鲜度（`listing_freshness`）、下榜（`delisting`：候选层面与来源层面、下榜滞后、下榜后 24 小时内仍可用）、快照序列（`snapshots`） |
| `m_labels` | 指标定义（标签准确率）、一次探访 | 按标签与按来源的准确率（`accuracy`、`accuracy_by_source`）、对照表（`matrix`）、https 标签与端口策略（`https_label`） |
| `m_integrity` | 指标定义（内容被改、请求被改、匿名程度、重放、出口地址） | `content`、`response_headers`、`anonymity`、`request_tamper`、`replay`、`egress`、`nodes_egress`、仪器检查（`checks`）、三条预期范围（`protocol_expectations`） |
| `m_mitm` | 指标定义（中间人）、“中间人”的细分 | 原定义总数与比例（`total`）、三层细分（`layers`）、按叶子证书（`leaves`）、按 /24（`prefixes`）、节点（`nodes`）、每小时（`hourly`）、证书链校验的工具与根库（`certcheck`） |
| `m_nodes` | 指标定义（节点可用）、频率与限速 | 构成（`nodes`）、可用性（`availability`）、预检（`precheck`）、轮次（`rounds`）、出口（`egress`）、sing-box 报错（`nerr`）、订阅（`subscriptions`） |
| `m_literature` | 与文献对账 | `mani_2018`（每天有回应、HTML 内容不符、证书被替换、带出地址、https 改 http）、`tsirantonakis_2018`、`mehanna_2024` |

`report_tables.py` 的 `report.md` 分八节：数据与观察窗口；仪器核对；PROTOCOL 预期范围 vs 实测（范围值抄在 `EXPECTED_RANGES`，
运行时与 PROTOCOL 原文逐行核对，PROTOCOL 改了而代码没跟上就报错）；与文献逐项对照（文献数字抄在 `PAPER_ROWS`，同样核对；
另有一张表把 PROTOCOL 的抄录与论文原文逐条核对，见 `PAPER_CHECKS`）；按 PROTOCOL“要回答的问题”整理的关键数字；与 `summary.json` 的交叉核对；
事后分析（`m_posthoc`）；各模块的提醒。附录是九个模块自己的详细表格。
每张表前一行写口径；比例都写成“分子/分母（百分比）”。

## 口径里“看过数据以后加的两条”

PROTOCOL 第 1.2 版（2026-11-06，决策 D12、D13）在“指标定义”一节末尾加了两小节，都是开始探测之后看过数据才加的，报告引用时要标明：

1. **“中间人”的细分**（PROTOCOL“‘中间人’的细分”）。总数照原定义报告，细分另列。
   实现在 `m_mitm.py`（`mitm.json` 的 `total` 是原定义，`layers` / `leaves` / `prefixes` 是细分）和 `certcheck/`；
   `m_literature.py` 的 `mani_2018.cert_replaced` 调用同一套分类；`report.md` 第三、五节两者并列。
2. **候选密集的地址段**（PROTOCOL“候选密集的地址段”）。
   - 从没探访过的条目不进任何比例的分母，单独计数并按 /24 汇总：`availability.json` 的 `never_visited`、`labels.json` 的 `n.从没探访过`。
   - 上榜新鲜度只算上榜后 10 分钟内完成第一次探访的条目，其余单独报告条数和延迟分布：`freshness.json` 的 `listing_freshness.新上榜`。
   - 时点 / 累计可用率、标签准确率、各类篡改、中间人比例另给一组去掉候选超过 100 个的 /24 的结果：各 JSON 里的 `excluding_dense`；
     被去掉的 /24 及其候选数、探访数在 `availability.json` 的 `dense_prefixes`（`report.md` 第一节）。
   - `lifetime.json` 的 `regular_excluding_dense_prefixes` 是本目录额外给的，PROTOCOL 没要求，不替换主结果。

## 看过 72 小时数据以后加的（决策 D14）

72 小时实测结束、看过结果以后又加了几项，都不改 PROTOCOL 的口径，与原定口径分开报告（`report.md` 第七节、`posthoc.json`），引用时要写明是事后分析：

1. **按 IP 重算**（`m_posthoc.py`）。PROTOCOL 的单位是候选（ip:port）；真实数据里少数 IP 各开了几十到几百个端口，
   “中间人候选占 43%”这类数字主要由几百个 IP 决定，所以主要比例（漏斗、中间人、正文不符、带出地址）另按 IP 算一遍。
2. **整页替换的来历**：按证据哈希归并，与 judge 说明页模板（`judge.go infoPage()` 里联系方式之前的固定部分，从源码读）逐字节比对开头，
   认出“代理丢了路径、向 judge 要了 `/`”的那一类；judge 一侧同时数收到的 `GET /`。只输出计数，正文和哈希不输出。
3. **经 Cloudflare 转发的请求**（judge 收到的请求里带 `Cf-Connecting-Ip`）：解释了 `Accept-Encoding` 被改、出口与入口不同等几项的大头；
   与 `Accept-Encoding` 被改的交叉表在 `posthoc.json` 的 `cloudflare.*.Accept-Encoding 被改`。
4. **中间人 IP 的两群**：按 IP 在列表里有没有 100 个以上候选分开，给证书里写的签发者组织（只取 O，像域名、含地址或 judge 名字的隐去；
   整体上出现在不到 5 个不同代理 IP 上的组织名不列出、合并计数，同 `m_mitm` 的门槛）；给了 `AWS_RANGES` 时数落在 AWS 公布地址段里的 IP。
5. **分析时补的两个变体**：`m_freshness` 的“下榜后 24 小时内仍可用（只算 24 小时内没再上榜的）”；`m_instrument` 把 TLS 校验通过后的
   `http_body_mismatch` 里“收到的正文恰是期望正文的前缀”的那部分单列为截断（代理提前断开），不算内容层异常。
6. **观察窗口**：从最终版本的第一条 `start` 到 `stop`，72.88 小时，不裁到 72 小时（各模块本来就不裁，D14 把它定下来）。
7. **哪些 /24 可以点名**：只有候选超过 100 个的 /24（候选 = 状态文件 ∪ 尝试记录里的代理候选，各模块口径里最宽的一种）。
   `report_tables.py --db` 对 `report.md` 和每个 `out/*.json` 都核对这一条，不符就不写出；各模块去掉的 /24 逐个比候选数，不只比集合。
8. **复测偏晚按是否在密集 /24 分开**（`m_instrument` 的 `backlog.revisit_ratio.by_dense_24`）：只用来找连不上一类复测偏晚的原因，不改任何原定口径。
9. **证书组织名的门槛**：`m_mitm` 的叶子证书表和 `m_posthoc` 的签发者组织，只列出现在至少 5 个不同代理 IP 上的组织名。
   只在一两个 IP 上出现的名字能把一家真实机构和一个具体的代理对上号，这和“不输出第三方主机名”是同一类问题。

## 跨模块的共同约定

- **正式起点**：见上。正式起点之前的探访和尝试算试运行，各模块在 `window` 里给出被排除的条数；与 `summary.json` 交叉核对时不裁（summary.go 不区分）。
- **aborted 的探访不作数**（程序退出时被打断，`prober.go` Visit；summary.go 也跳过）；`class` 含 canceled 的尝试没发起连接，不算。
- **“可用”有两种记法**：visit 口径（`visit.state='working'`，等价于 `visit.ok` 非空 / `n_ok>0`，只看主流程的 HTML 尝试）和
  att 口径（至少一条 `class='ok'` 且目的地是 judge，含附加测试里的 JS / 二进制载荷）。累计可用率（`m_availability`）、Mehanna 等的“活跃”（`m_literature`）
  用 att 口径，与 summary.go `Funnel.Working` 一致；寿命（`m_lifetime`）、标签准确率（`m_labels`）用 visit 口径；两种口径不一致的条数在各模块 `checks` 里。
- **有协议回应**照 summary.go `attempt()`：握手通过，或握手应答码非零（含拒绝和要求认证），或收到 HTTP 状态码。
- **候选密集的 /24** 的阈值是 100（`--dense-threshold` 可改）。候选 = 状态文件里的候选 ∪ 尝试记录（或探访记录）里出现过的代理候选，
  各模块同一口径（决策 D14）；没有状态文件时各模块退回快照与探访的并集。只数状态文件会漏掉下榜超过 24 小时、被状态文件丢掉的候选：
  真实数据上只数状态文件得到的密集 /24 少了 29 个，其中有些按并集数有几百个候选，中间人“去掉密集 /24”的比例因此差了几倍。
  `report.md` 第一节核对各模块去掉的是不是同一组 /24，不同就列为读取问题（`--strict` 下不写出）。
- **时间**：记录的 `ts` 是 UTC；状态文件的时间保留时区再换成 UTC（`meta.state_tz_offsets` 应只有 `+08:00`）；输出里的时间截到分钟（`m_lifetime` 保留毫秒）。
- **百分比** = 100 × 分子 / 分母，一位小数，分母为 0 时为 null；每个比例都同时给出分子、分母，每个模块的 `definitions` 写着一句话口径和 PROTOCOL 小节名。

## 各模块记下的解释

PROTOCOL 没写清、各模块自己取的读法（完整的在各 JSON 的 `definitions` 和模块文件开头的注释里）：

**可用率（m_availability）**
- “某一时刻在榜”由快照重建：每个列表文件（来源 × 标签）按时间处理增减，首次快照（base=1）把该文件的集合重置为它的条目（与 summary.go `snapLine` 相同）；结束时刻与状态文件的 `listed` 交叉核对。
- 时点可用率的分母只含“在榜且之前至少探访过一次”的条目；在榜但没探访过的另计，分成“候选池里排队”和“不进候选池”（私网、judge 自己、知名端口、退出名单）。
- 聚合器不逐条记快照，聚合器条目的“在榜”只在结束时刻由状态文件给出；时点序列里聚合器一行的分母是“抽样时刻不晚于该时刻且探访过”的抽样条目，不看是否仍在榜。
- “聚合器独有”= 抽样条目在整个观察期从未出现在任何常规列表快照里，并与状态文件的 `group=1` 交叉核对。
- 分组取最后一次探访的 `group`（summary.go 的做法）；候选全集 = 状态文件 ∪ 有探访记录的（下榜 24 小时后被丢弃的条目只在探访记录里，单独计数）。
- 每个来源的累计可用率给两种分母：结束时在榜的（= summary.go `SourceRow`）和观察期内曾经在榜的。

**寿命（m_lifetime）**
- 死亡时刻 = 连续两次不可用里第一次不可用的探访时刻；右删失时刻取最后一次可用的探访时刻（不是观察结束时刻）。
- 回环对照失败窗口（失败前后最近一次成功之间）和停机时段（stop→start、崩溃的最后心跳→start、心跳缺席超过 10 分钟）里的不可用探访当作没观察到；可用探访照算。只用回环对照，公网对照的失败只作参考。
- 分组：任何一次探访 `group=0` 就算常规列表；来源按快照的 add 事件和聚合器抽样成员归属，一个候选可属多个来源，各来源的结果不能相加。
- Kaplan–Meier 用 Greenwood 方差和 log(-log) 95% 区间；主结果只看每个候选的第一段寿命（PROTOCOL“从第一次可用起”），全部寿命另给。
- 复测间隔的名义值从 `start` 记录的探测器配置读，不写死。

**列表时效（m_freshness）**
- 新上榜 = 观察窗口内第一次出现、且是普通快照（base=0）的 add；首次快照和重启后的快照里的条目上榜时刻不可知，不算新上榜，只计数；上榜前已在候选池的、下榜后又上榜的单独报告。
- 第一次探访完成时刻 = `visit.ts + visit.ms`；上榜新鲜度的分子是那次探访可用。
- 候选层面下榜 = 从所有列表文件消失；来源层面下榜 = 从该来源的全部文件消失（“按来源”用它）。重启后快照里消失的记为无声下榜，时刻取那次快照。
- 下榜时按最后一次探访分四类（没探访过 / 从未可用 / 仍可用 / 已死）；“死了多久才下榜”只看已死一类。
- 下榜后 24 小时内仍可用的分母 = 下榜后观察满 24 小时、且期间探访过的下榜事件。
- 10 分钟内又回到列表的下榜算换榜抖动（`--flap-min`），默认不进主结果，含与不含两组都给；聚合器仍可能列着的下榜同样单独一组。

**标签准确率（m_labels）**
- PROTOCOL 没写标签到协议的映射，取两种都报：严格（http→转发、https→CONNECT、connect→CONNECT、socks4/5→自身）和宽松（探测器为该标签先试的协议集合，`prober.go labelProtos()`）。
- 实测可用按 `visit.ok`；summary.go 的 labels 表用 att 的 `class='ok'`（附加测试里 JS / 二进制载荷通过就算转发可用），差别在 `checks` 里，交叉核对时按 summary.go 口径重算。
- 分母 = 带该标签、探访过的候选（连不上的也在内），另给以“曾经可用”“最近一次可用”为分母的条件版本；一个候选有几个标签就进几个分母。
- “最近一次通过”是保守估计：平时只试上一次通过的协议，标签协议从未通过时只在每 24 小时的完整识别里再试。
- 端口“说 TLS”= 握手成功或对方按 TLS 应答（证书对不对不论）；CONNECT 连 80 端口的“允许”按握手通过算，分母是 CONNECT 曾通过的候选。

**完整性（m_integrity）**
- “能转发的代理”= 至少一次明文响应 200 的代理，另给“端到端可用过”作第二分母。内容被改只算明文（经 TLS 隧道的正文不符是仪器异常，进 `checks`）。
- 截断 / 局部改动 / 整页替换照 summary.go `BodyChange`；期望长度取成功响应长度的众数（`meta.payload_len`）。
- 匿名程度主口径照 summary.go：只算 HTTP 转发、`class=ok`、judge 收到的请求，按代理取最差一级；另给全部明文、judge 收到的全部明文、节点三个范围。
  探测器自己对转发代理发 `Proxy-Connection`，代理透传它会被判“匿名”，这类请求单独计数。
- Cookie 是否被改需要共享密钥算期望值，数据包里没有：只在金丝雀正确时借金丝雀头的值比 Cookie，否则记“无法判定”。
- 同一 nonce 多份时以最早到达的一份为准；重放的 judge 侧统计按全部 nonce 算，归到代理时只算 `class=ok` 且 judge 收到的。
- 出口“与入口相同”= judge 看到的对端地址等于候选 IP；稳定性按观察期内不同出口地址的个数分桶。
- judge 每 2 秒落盘，只核对早于 judge 最后一条记录 10 秒的成功尝试。
- 同一个请求头出现两次时取最后一个（derive.go 把请求头读进 map，后写的覆盖先写的）；真实数据里有一个代理把 Accept 发了两次。
- 回显服务 vs judge：与“该代理整个观察期的出口集合”比，集合按记录流的顺序累积（summary.go `observer_vs_judge` 的做法），所以在 judge 第一次看到这个代理之前的回显不计。

**中间人（m_mitm）**
- 主口径：代理、目的地 judge 的 TLS 端口、`proto≠tlsproxy`、正式起点之后；节点和第二观察者另计。
- 证据没存下、但 `tls.detail=unknown_authority` 的尝试归“冒充 judge”（Go 已核对过主机名），并单独给出这部分的条数；其余没存下的进“证据未存”，再按 `tls.subj` 的 CN 细分。
- 名字匹配：不分大小写、去末尾点，通配符按 Go 的规则只匹配一层；judge 主机名取库里的 `self_names`，不写进输出。
- 证书链校验：`x509.Certificate.Verify`，根 = `--roots` 的全部证书，中间证书 = 证据里叶子之后的证书，不看主机名，时刻 = 尝试发生的时刻（同一文件同一小时先按最早一次校验，有效期边界落在这一小时里再逐次重算）。
- 候选层面按最严重一层归类：冒充 judge > 去向不明 > 被送到别的网站 > 证据未存 > 未校验（PROTOCOL 没规定）。
- “可用隧道代理”PROTOCOL 没定义：给“隧道建立过的候选”和“隧道曾可用或遇到过中间人的候选”两个分母。
- 按叶子证书汇总只输出组织名（O）和计数，证书哈希、CN、SAN 不输出；组织名整体上出现在不到 5 个不同代理 IP 上的写成“不列出”（`ORG_MIN_IPS`，决策 D14）。

**节点（m_nodes）**
- 见过的节点 = 正式起点后在节点描述、订阅事件、预检、尝试任一处出现过的标识；比例给三个分母（见过、可探测、探测过）。
- 节点可用（严格）只看 judge 的 TLS 端口（summary.go `nodeOK`）；“只有照链接才可用”= 照链接分组通过、严格从没通过；严格校验的损失另给以“链接要求跳过校验的节点”为分母的一组。
- 轮次编号重启后从 1 重数，按运行段编号；尝试按时间窗归到轮次，独立核对每轮的计数。
- sing-box 的报错原文可能含节点地址，不输出，只按关键词归入固定的几类计数。

**仪器核对（m_instrument）**
- 对照的期望次数 = 各运行段 floor(时长 / 周期) + 1 之和；回环失败时段按分钟取并集，另给“算到下一次成功”的取法（给寿命排除用）。
- “TLS 内请求一致”照 derive.go 的核对项，只对 TLS 校验通过、`class=ok`、judge 收到的尝试算；ClientHello 指纹基线 = 对照组成功尝试的指纹集合（应恰好 1 个）。
- 连接速率只数真正发起过连接的记录（非 canceled 的 att + 有 TCP 的预检），与配置的每秒 40 条比较。
- 启动积压：同一候选相邻两次探访的实际间隔 ÷ 计划间隔，按前一次探访所在的小时和那次探访后的状态取中位数和 p90；跨重启的对子不算。
  另给启动时的候选池（正式起点后第一条 stat）、p90 超过 2 的小时，以及按候选是否在密集 /24 分开的一组（事后）。
- 被排除的条目取每个运行段最后一条 stat 的计数，不跨段相加（进程内计数，重启归零）。
- `error.what` 可能带候选的 ip:port，输出前归一化成占位符。

**与文献对账（m_literature）**
- “每天”是从正式起点起算的 24 小时窗口（72 小时 = 3 个测量日），中位数只取完整的测量日。
- Mani 等“有回应”的分母“当天在榜”含被排除、不进候选池的条目（他们的分母是列表里全部条目），另给“进入候选池”“当天探访过”两个分母。
- 证书被替换：Mani 等经 CONNECT 和 SOCKS 两种代理测 HTTPS，所以与 1.06% 对账用全部隧道协议（socks5 / socks4 / connect），只算 CONNECT 的另给；
  Mani 等“无害 / 恶意”我们不人工判定：局部改动是有害的上界候选，截断 + 整页替换多半无害。
- https 链接改成 http：记录里没有这项，从存下的局部改动正文里数指向 judge 的 https 链接少了几个、`http://` 多了几个（D14）。证据缺失、改成别的主机名只会少数；
  同一正文既删了 https 链接、又在别处加了 `http://<judge>/`，删掉的会被算成剥离，所以不是严格的下限。模板里实际有 10 处 `https://`（PROTOCOL 说 8 个链接，另有样式表和脚本各一处）。
- Tsirantonakis 等与 Mehanna 等的“全部条目 / 全部候选”分母按文献口径含从没探访过的条目，这是 PROTOCOL 1.2 规则的例外，只用于对账。

## 未解决的问题与已知局限

**需要跨模块定下来的（应写进 `docs/decisions/README.md` 再改代码）**
- 正式起点：`m_availability` 等在“状态被清空的 start”出现时自动把起点挪过去（并写 warning），`m_lifetime` 只提醒不挪。真实数据若有这种 start，各模块的起点会不一致，`report.md` 第一节会标出来，用 `FORMAL_START` 统一。
- 72 小时上界：已定（D14），不裁，观察窗口 72.88 小时；`m_integrity` 给出超出的时长和尝试数，`m_mitm` 的 `--formal-end 72h` 保留给想看裁过的结果的人。
- “证书被替换”该与中间人总数还是与“冒充 judge”一层对账，PROTOCOL 写明待定；报告两者都给。
- 输出里能出现哪些 /24：已定（D14），只许点名候选超过 100 个的 /24（状态文件 ∪ att）。`m_availability` / `m_labels` 的“从没探访过”按 /24 汇总、
  `m_mitm` 的中间人 /24 前 20 个，在真实数据上列出的都满足这一条（`report_tables.py --db` 核对过）；但这几个模块自己还不按这条过滤，
  换一份数据可能列出不密集的 /24，那时 `report_tables.py` 会拒绝写出，需要在模块里加过滤。
- `ingest.OUTPUT_WHITELIST` 允许输出 `error.what`，而探测器的程序错误会把候选 ip:port 写进去；`m_instrument` 自己归一化了，规则应移到 ingest（加派生列或在 SCHEMA 的输出规则里写明）。
- （已改）各模块的输出检查只依赖库里的 `self_names` / `self_ips`，源码里不再写 judge 的名字和地址。

**各模块作者保留的意见**
- `m_availability`：状态被清空的 start 会自动挪起点（依据 PROTOCOL 原文和 `sched.go Pool.Load`），挪动超过 1 小时时要求用 `--formal-start` 显式确认。
- `m_lifetime`：第一次探访就可用的候选（寿命起点可能早于观察起点）主结果照 PROTOCOL“从第一次可用起”保留，另给剔除它们的一组；跨停机确认的死亡把停机时长算进了寿命，只计数没修正；重启后没有宽限期。
- `m_freshness`：同一轮内几秒之差的一删一加照常记事件，再按 `--flap-min` 归为抖动并默认排除；聚合器仍列着的判断加了“之间没有重启”的条件。
- `m_labels`：“曾经通过（att 口径）”一列照 summary.go 不过滤 aborted 探访里的尝试；聚合器成员的标签取累计标签，后来也进了常规列表的会多算到聚合器名下。
- `m_integrity`：与 summary.json 对账节点出口时，入口地址取“这条尝试之前最近一次有结果的预检”（summary.go 按记录流顺序的做法）；回显服务 vs judge 的 summary.go 口径与顺序有关，真实数据里可能差几条。
- `m_mitm`：其他模块的字面量没有动（见上）；同一文件同一小时按最早一次校验的等价性有一个理论上没覆盖的情形（根库里有一张生效和过期都落在 72 小时内的根），Mozilla 根库里没有这样的根。
- `m_nodes`：不含点和冒号的单标签主机名不当作地址拦截（公网 DNS 解析不了，不泄露可达地址）。
- `m_instrument`：TLS 校验通过后的失败只把内容层类别当作仪器异常，连接层的（超时、断开）和正文被截断（代理提前断开）算代理行为。
- `m_literature`：对夹具用 `--formal-start` 挪到第二次启动时“从没探访过 15”是对的（它们在候选池里但正式起点后没轮到）。

**还没验证的**
- Python 3.10：脚本按 3.10 的语法写，各模块的 `--selftest` 在 3.11 和 3.13 上跑过，真实数据只在 3.13 上跑过；3.10 本身没有跑过。
- 夹具只跑了几分钟：没有死亡、没有普通快照里的新上榜、没有候选密集的 /24、没有“被送到别的网站 / 去向不明”的中间人、节点没有 DNS 失败等，
  这些分支只由各模块 `--selftest` 的合成库覆盖，没有在真实形状的数据上跑过。
- 真实数据的 `start.judge_host` 若写的是 IP 而不是域名，“名字是 judge 的”只能靠 SAN 的 IP 条目判断，没有验证。
- “被送到别的网站”不联网补全中间证书，只发叶子的真实网站会落进“去向不明”（错误类别 `unknown_authority_leaf_only` 单独计数）。
- 证据库有上限（每个代理 12 份、总共 1 GB），超限后中间人和 https 改 http 的判定只能按“证据未存”计数。

## 输出里刻意不含什么

仓库是公开的。`out/` 里的文件和脚本里的常量都不含：

- **judge 的主机名和公网地址**：只在库里（`self_names`、`self_ips`），各模块按它们判等，输出前确认一个都没有；需要提到时写“judge”。
- **单个代理的 ip:port 或 IP**：只给聚合计数；/24 前缀以 `a.b.c.0/24` 的形式出现，而且只能是候选密集的 /24（决策 D14）。
- **第三方的主机名**：judge 收到的杂项请求里的 Host、证书里像域名的组织名都不输出。
- **证据正文**：judge 说明页里有联系方式；`m_posthoc` 只读正文开头与模板比对，正文本身和哈希都不输出。
- **节点的分享链接、凭据、节点标识和服务器地址**；sing-box 报错原文不输出，只给分类计数。
- **证书的哈希、CN、SAN**（只给组织名 O，含地址或邮箱样式的组织名换成“(已隐去)”，出现在不到 5 个不同代理 IP 上的组织名不列出）；请求头原文、nonce、证据文件的哈希。
- **用户邮箱**和任何邮箱样式的字符串。

各模块写 JSON 前按 `ingest.OUTPUT_WHITELIST` 取列并用正则和库里的身份表扫一遍；`report_tables.py` 写 `report.md` 前再查一遍：
IPv4 只允许 `a.b.c.0/24`（根证书包版本号这种长得像地址的值按 JSON 里的原值放行），给了 `--db` 时还核对库里 judge 的名字与地址、节点标识与主机名，
命中就不输出（只报行号和类别，不回显命中的值）。原始数据和 SQLite 库不进仓库。
