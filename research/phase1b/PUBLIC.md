# 1B 的公开数据：脱敏后的逐条记录

决策 D16（做法和修正见 D18）：1B（72 小时实测）的原始探测数据公开脱敏后的逐条记录，附一条命令从它重算 [`out/`](out/)。
对应验收标准 AC-60（[`docs/design/07-acceptance.md`](../../docs/design/07-acceptance.md)）：重算出的输出与仓库里的逐字节相同；
因为脱敏而必然不同的字段事先列出清单，清单之外不许有差别。

本文写清楚四件事：公开的是什么、怎么换的、重算的结果和仓库版本差在哪里、脱敏挡不住什么。

## 一、公开的是什么、怎么用

公开的是一个 SQLite 文件，作为发布附件放在仓库之外（GitHub Release，不进 git 历史）。它就是 `ingest.py` 建出的那个库的脱敏版本：
**表名、列名和真实库相同，分析模块一行不改就能在上面跑**；只是列少了，地址、主机名、哈希换成了假名，几列自由文本换成了“等价的代表值”。

```sh
# 下载发布附件，核对 SHA-256（写在发布说明和 docs/HANDOFF.md 里），解压
xz -d phase1b-public-v1.sqlite.xz
# 在公开库上重算全部输出（4 核的机器上一个多小时；只要 Python 3.10 以上的标准库，不要 Go、不要证据文件、不联网）
./run_public.sh phase1b-public-v1.sqlite /tmp/phase1b-out
# 与仓库里的 out/ 比对：只允许第三节清单里的差别
python3 pub_check.py compare /tmp/phase1b-out out/
```

公开库里有哪些表、每张表留了哪些列、哪些列换过、哪些列不出，导出工具逐表记在 [`public/export_report.json`](public/export_report.json)（只有列名和计数）。
原则是白名单：`pub_export.py` 的 `SPEC` 里写明了怎么处理的列才出去，没写的一律不出。不出的有：各表的 `raw`（原始 JSON 行）、
Go 错误原文和 banner（`*_detail`、`*_banner`）、judge 收到的请求头原文（`headers`、`raw_head`）、来源端口、快照的 `etag`/`sha256`/增删清单、
聚合器抽样的成员清单、节点的端口和传输参数、状态文件里的原始时间文本，以及 `meta` 里的三个本机路径。

库里另有三类不是从真实库原样复制的表：

| 表 | 内容 |
| --- | --- |
| `pub_*` | 随库带上的中间结果（第二节最后一部分） |
| `pub_file` | 数据包里另两个文件的脱敏版本：`summary.json`（去掉抽样成员、例子，合并 sing-box 报错原文，警告只留归类）和 `preflight.txt`（只留 `m_instrument` 读的那几行） |
| `meta` 里的 `public_*` | 公开库的版本、假名段、说明 |

## 二、怎么换的

### 假名（`pub_pseudo.py`）

全部是带密钥的 HMAC-SHA256。密钥是 32 字节随机数，只在导出的那台机器上，不进仓库、不随公开库发布，发布以后删掉
（以后要重新导出就换一把新密钥、升版本号，新旧两版的假名对不上）。所以知道算法也无法从假名算回原值，也无法拿“猜一个地址、算一下假名”去验证猜测。

| 原值 | 假名 | 保留了什么 |
| --- | --- | --- |
| 代理的公网 IPv4 | `240.0.0.0/4` 里的地址 | 相等；同一个真实 /24 里的地址落进同一个假 /24（模块按 /24 汇总）；最后一段在 /24 内打乱 |
| 保留地址（私网、回环等） | 原样 | 模块要据此判断“不是公网” |
| judge 的地址（含 NAT 后的私网地址） | `240.0.0.101` 起的固定地址 | 相等；不参与上面的 /24 结构 |
| IPv6 | `2001:db8::/32` 加 96 位 HMAC | 相等 |
| `prefix24` 列 | 假 /24；`out/` 里已经点了名的那些 /24 保持原样 | 输出里印出的 /24 不变 |
| 候选键 `ip:port` | 假名地址 + 原端口 | 相等、端口 |
| judge 的主机名 | `judge.invalid` | 是不是 judge 的名字 |
| 节点编号、证据哈希、正文哈希、叶子证书哈希、`nonce` | 等长的十六进制假名 | 相等 |
| 节点入口的主机名、Host/SNI 里别的名字 | `h-<假名>.invalid` | 相等 |

哈希也要换：证据正文里含 judge 的主机名，不带密钥的哈希能被拿来验证对主机名的猜测。

### 等价的代表值

有几列是自由文本，模块对它们只做固定的判断。公开库里换成“在这些判断下结果相同”的代表值；导出时用模块自己的函数或同一条 SQL
逐个核对原值和代表值落进同一类（`pub_export.py` 的 `check_*` 和 `_check_dn`），核对不过就停。

| 列 | 模块拿它做什么 | 公开库里是什么 |
| --- | --- | --- |
| `att.tls_subj` | 有没有 CN、CN 是不是 judge 的名字、取组织名 O | `CN=judge.invalid` 或 `CN=cn-<假名>`、组织名（见下）、末尾 `X=<假名>` 保持不同原值互不相同 |
| `att.tls_issuer` | 取组织名 O | 组织名加 `X=<假名>` |
| 证书上的组织名 | `m_mitm`、`m_posthoc` 印出出现在至少 5 个代理 IP 上的名字 | 达到这个门槛、又不含地址和 judge 身份的原样；其余换成同一类的假名（`org-<假名>`、`….example`、`…@hidden`、`… judge.invalid`） |
| `nerr.msg`（sing-box 报错原文） | `m_nodes.NERR_CASE` 分类 | 所属类别的代表值（`config: x`、`x509`、`timeout`、`refused`、`eof`、`dns`、`other`） |
| `req.target` 等 | 是不是绝对 URI、是不是恰好 `/` | `/` 原样，其余 `http://judge.invalid/x/<假名>`、`/x/<假名>`、`x-<假名>` |
| `req_header.value` | 四个探测器自己发的头是不是原值；Cookie 是不是 `pc=` 加金丝雀；值里有没有探测器的地址 | 原值是公开常量的照留，改过的换记号；金丝雀两边换成同一个假名；其余头的值清空，只留里面那个探测器地址的假名 |
| `*.err`、`load_err`、`problem` | 有没有 | 非空的换成 `x` |
| `start.probe`、`start.raw` | 取几个数值配置项 | 只留数值、布尔和端口清单 |
| judge 的监听端口 | 数有几种 | 序号 |

### 随库带上的中间结果

有三处计算要读库以外的东西，公开库里没有这些东西：证书链校验（读证据文件里的证书链，调 `certcheck`）、正文里的链接
（读证据正文）、AWS 地址段（真实地址才对得上）。做法是在真实库上跑的时候把这几处算出的**结果**记下来（环境变量 `PHASE1B_RECORD`，
`pubdb.Recorder`），导出时脱敏后放进公开库的 `pub_*` 表；模块在公开库上（`meta` 里有 `public_version`）改从这些表取（`pubdb.replay_*`）。
现算和取回走的是同一段后续代码。

| 表 | 来自 | 内容 |
| --- | --- | --- |
| `pub_chains_leafinfo`、`pub_chains_chk`、`pub_json` 里的 `chains_info` | `m_mitm.verify_chains`（`m_literature` 也调） | 每个证书链文件：能不能解析、叶子的假名、名字是不是 judge 的、自签、组织名（同上的规则）、密钥和签名算法；每个校验时刻的结果。有效期只留长度，具体日期不出 |
| `pub_body_links` | `m_literature.mani_sslstrip` | 每个正文证据里 `https://<judge>/` 和 `http://<judge>/` 各出现几次 |
| `pub_body_infopage` | `m_posthoc.judge_info_page` | 整页替换的正文是不是 judge 自己的说明页 |
| `pub_aws`、`pub_json` 里的 `aws_note` | `m_posthoc.mitm_fleet` | 中间人 IP（假名）落在 AWS 公布的哪个区域；地址段文件的版本 |

这些结果只对默认参数那一次运行成立。换了正式起点（`FORMAL_START`）要重新校验的文件就不同，模块会报错停下，不会悄悄给出错的数。
这几处第三方只能核对“从这些结果往后的计算”，核对不了结果本身（要证据原文）。

## 三、重算的结果与仓库版本的差别

`pub_check.py compare` 逐个文件比对：JSON 按结构逐项比（键的顺序也比），`report.md` 逐行比。允许的差别只有 `pub_check.py` 里的 `ALLOWED`、`ALLOWED_ORDER`、`ALLOWED_TIES`：

| 文件 | 字段 | 为什么必然不同 |
| --- | --- | --- |
| 每个 JSON | `generated_utc` | 生成时刻 |
| `lifetime.json`、`freshness.json` | `seconds` | 模块自己的运行用时 |
| `instrument.json` | `preflight.source` | 真实库上 `preflight.txt` 是按 `meta.data_dir` 找到的，公开库没有本机路径，由 `run_public.sh` 用 `--preflight` 给 |
| `report.md` | “各模块的输出”表的生成时刻列 | 同 `generated_utc` |
| `freshness.json` | `n` 下“上榜事件（候选层面，按种类）”的**键的顺序**（键和值都相同） | `m_freshness.Replay` 按候选键排序重放，各种事件按先遇到的顺序成为键；候选键换成假名以后排序变了 |
| `posthoc.json` | `replaced_bodies` 的“前 10 种”里**尝试数并列的条目之间的先后**（条目本身相同） | 尝试数相同的正文按证据哈希的顺序排；哈希换成假名以后并列的几种先后不同 |

前四行是动手之前就知道的；后两行是第一次在公开库上重算时比对出来的，查清是排序依赖原值、内容没有变以后才加进清单（`pub_check.py` 里写了每一处的原因）。后两类差别的比对办法是：键的顺序只在那一个路径上放过；并列的条目先按内容排好再逐项比，条目和每个名次上的尝试数都必须相同。

在真实库旁边跑出的比对结果在 [`public/compare.txt`](public/compare.txt)：12 个文件里 `rotation_check.json` 逐字节相同，其余只有上表里的差别。

## 四、脱敏挡不住什么

- **代理的假名能被对回真实地址。** 列表来源都是公开的 GitHub 仓库，有提交历史。公开库里每个候选留下的“端口 + 在哪个来源、哪次快照上榜或下榜”
  就是它的指纹；拿列表的历史版本按同样的时刻比一比，指纹独一无二的候选就能对回真实的 `ip:port`。这样的候选约占九成，
  具体数字由 `pub_check.py linkage` 在真实库上算出，见 [`public/linkage.json`](public/linkage.json)。
  所以代理地址的假名只是一层礼貌：它让数据不能被直接当成“某个地址做了什么”的清单来用，但挡不住有心人。
  这些地址本来就是公开列表里的（PROTOCOL：“记录里只有本来就公开的代理地址和我们自己的请求”），决策 D16 写的“代价：第三方核对不了地址本身”说得不准，
  准确的说法是：公开库不直接给出地址，但大部分能从公开列表的历史里对回去。
- **测量机的大致位置。** 对回真实地址以后，到这些代理的延迟能粗略推测测量机在哪里（精度未验证）。
- **真正藏住的是 judge 的身份**：主机名、地址、证书、说明页上的联系方式。它们在公开库里只以假名出现，导出前用真实库里的全部身份值扫了一遍
  （`pub_check.py scan`，结果在 [`public/scan_report.json`](public/scan_report.json)，只有计数）。
- 出现在至少 5 个代理 IP 上的证书组织名原样保留（`out/` 里本来就印出来了）；这些名字可能是真实机构，被冒用的。

## 五、怎么导出（维护者）

```sh
# 1. 在真实库上跑一遍，同时记下中间结果（与生成仓库 out/ 那次相同的参数）
PHASE1B_RECORD=/path/record.sqlite CERTCHECK=… ROOTS_NOTE=… AWS_RANGES=… ./run_all.sh --skip-ingest <数据目录> <state.json.gz> <真实库>
git diff --stat out/            # 只应有生成时刻和用时；确认后 git checkout -- out/
# 2. 导出（公开库和密钥都不许放在仓库里，脚本会拒绝）
python3 pub_export.py --db <真实库> --record /path/record.sqlite --key /path/pub.key --out /path/public.sqlite \
    --summary <数据目录>/summary.json --preflight <数据目录>/preflight.txt --report public/export_report.json
# 3. 两项检查
python3 pub_check.py scan /path/public.sqlite --real <真实库> --report public/scan_report.json
./run_public.sh /path/public.sqlite /tmp/re && python3 pub_check.py compare /tmp/re out/ | tee public/compare.txt
python3 pub_check.py linkage --real <真实库> --write public/linkage.json
# 4. 压缩、记下 SHA-256，给用户看过再发布；发布以后删掉密钥
```

自检：`python3 pub_pseudo.py`、`python3 pubdb.py`（CI 里跑）。
