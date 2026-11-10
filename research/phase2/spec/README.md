# 规范部分：条款文件和核对工具

第 2 阶段的规范部分（`../PROTOCOL.md` 开头说的 `spec/`）。这里把 RFC 里与网关有关的条款逐条记下来，每条附原文；
引文是不是原文、在不在所标的章节里，由脚本对着 RFC 文本核对，不靠人眼。RFC 文本不进仓库，只引用需要的句子。

题目指定的是 RFC 9110、9112、1928、1929；补充用的是 RFC 7617（Basic）、9209（Proxy-Status）、9113（HTTP/2）、6455（WebSocket）。

| 文件 | 作用 |
| --- | --- |
| `clauses/rfcNNNN.json` | 条款，一篇 RFC 一个文件 |
| `check_quotes.py` | 逐条核对条款文件 |
| `spec_tables.py` | 把条款渲染成 `../out/spec_clauses.md` |
| `fetch_rfcs.sh`、`rfc_sha256.txt` | 取 RFC 纯文本；八个文本文件的 SHA-256 登记 |
| `test_check_quotes.py`、`test_spec_tables.py`、`test_fetch_rfcs.py` | 单元测试 |

三个脚本只用 Python 标准库和常见的命令行工具（`curl`、`dpkg-deb`、`tar`、`gzip`、`sha256sum`）。

## 条款文件的格式

```json
{"rfc": 9110, "title": "HTTP Semantics", "text_sha256": "<所用 rfc9110.txt 的 SHA-256>", "clauses": [
  {"id": "9110-9.3.6-1",
   "section": "9.3.6", "section_title": "CONNECT",
   "quote": "……",
   "level": "MUST",
   "binds": "proxy",
   "side": "入口",
   "topic": "connect",
   "gateway": "……",
   "rows": ["R03", "R05"]}
]}
```

文件名是 `rfc<号>.json`，`rfc` 是整数，`title` 是 RFC 文本开头写的标题，`text_sha256` 是写条款时所用文本文件的 SHA-256。每条条款：

| 字段 | 含义和取值 |
| --- | --- |
| `id` | `RFC 号-章节号-序号`，全部文件里唯一。章节号形如 `9.3.6`，附录形如 `A`、`B.1` |
| `section`、`section_title` | 章节号，和原文里那一节的标题（照抄） |
| `quote` | 原文逐字引用：一个或几个连续的完整句子，不省略、不改写、不加省略号；换行和连续空白折成一个空格 |
| `level` | `MUST`、`MUST NOT`、`SHOULD`、`SHOULD NOT`、`MAY`、`REQUIRED`、`RECOMMENDED`、`OPTIONAL`，或 `statement`（没有规范性关键词的事实陈述或定义） |
| `binds` | 约束谁：`client`、`proxy`、`server`、`tunnel`、`sender`、`recipient`、`intermediary`、`any`。`server` 指源站。原文主语是 server、而指的是连接上收请求的角色（RFC 9110 3.3 节）的条款，按义务发生在收请求时还是发响应时填 `recipient` 或 `sender`，并在 `gateway` 开头写明“原文主语是 server” |
| `side` | 对网关而言：`入口`（网关作为代理或 SOCKS5 服务端）、`上游`（网关作为上游代理的客户端）、`两侧`、`客户端`（只约束连到网关的客户端，网关据此判断客户端的行为是否合规）。约束代理转发行为的条款填 `入口`，即使动作落在上游连接上（例如丢弃上游的响应、关闭上游连接）；`上游`、`两侧` 留给网关以客户端角色也受约束的条款 |
| `topic` | `request-target`、`connect`、`tunnel`、`proxy-auth`、`hop-by-hop`、`via`、`framing`、`smuggling`、`connection`、`retry`、`expect`、`status`、`socks-negotiation`、`socks-auth`、`socks-request`、`socks-reply`、`basic`、`proxy-status`、`h2`、`websocket` |
| `gateway` | 中文，一两句：这条对网关的实现意味着什么。只说条款本身推得出的，不夸大；推不出具体要求的写“背景” |
| `rows` | 与矩阵的哪些行有关（`../rows.json` 的 id），没有就写空数组 |

## 取 RFC 文本

```sh
./fetch_rfcs.sh DIR                      # 先试 rfc-editor，有文件下载不下来或哈希不对就改用 apt 取剩下的
./fetch_rfcs.sh --from rfc-editor DIR    # 只从 https://www.rfc-editor.org/rfc/rfcNNNN.txt 下载（CI 上用）
./fetch_rfcs.sh --from apt DIR           # 只从 Ubuntu 的软件包里取：apt-get download 后解包，不安装，不需要 root
export KAOJU_RFC_DIR=DIR
```

取哪些文件由 `rfc_sha256.txt` 决定（`sha256sum` 的格式，`cd DIR && sha256sum -c …/rfc_sha256.txt` 也能核对）。
取到的文件哈希与登记的不一致就不放进目标目录，留作 `rfcNNNN.txt.rejected`；最后还有文件没就绪，脚本以 1 退出。其余选项见脚本开头的注释。
要核对别的 RFC，先把它的文本哈希登记进 `rfc_sha256.txt`：没登记的文本 `check_quotes.py` 不认。

- 登记的哈希与 2026-11-10 在 Ubuntu 24.04 上用 `--from apt` 取到的文本一致：`doc-rfc-std`（RFC 9110、9112）和
  `doc-rfc-std-proposed`（其余六篇），软件包版本都是 20230121-1。
- 这两个包在 Ubuntu 的 multiverse 组件里（`apt-cache show doc-rfc-std` 的 Section 是 `multiverse/doc`）。
  RFC 文本不放进仓库。这里只陈述事实，不是法律意见。

## 核对

```sh
python3 check_quotes.py --rfc-dir DIR    # 或者设好 KAOJU_RFC_DIR 后不带参数
python3 check_quotes.py --json           # 机器可读：ok、files、problems、notes，每条有 file、id、code、message
python3 check_quotes.py --strict         # 有提示也算不通过
```

退出码：0 通过；1 有问题；2 没法核对（没给文本目录、读不到 `../rows.json` 或 `rfc_sha256.txt`、一个条款文件都没有）。

怎么比：

- 引文和 RFC 文本都把换行和连续空白折成一个空格，引文必须是文本的子串；大小写、标点都要一样。
- 带换页符的旧格式先去掉分页留下的页脚（顶格、以 `[Page N]` 结尾的行）、换页符和页眉（`RFC 号  标题  年月`），跨页的句子才连得上。
  八篇里 RFC 1928、1929、6455、7617 是这种格式；没有换页符的文本（RFC 9110 等）什么都不去掉。
- 行尾的连字符不处理：原文在 `packet-` 处换行，引文里就是 `packet- format`。
- 新格式里的旁注每行以 `|` 开头。引文不带这些竖线、或者照文本原样带着，两种都认；表格的行不动。
- 章节的范围是从它的标题行到下一个同级或更高级的标题行，标题从文本里解析（顶格、前面是空行的编号行）。
  所以标成 9.3 的引文落在 9.3.6 里也算在章节里，只给一条提示。没有编号的小标题（RFC 1928 第 6 节里的 CONNECT、BIND 等）算在所在的编号章节里。
- 级别：声明的关键词要以大写、独立成词的形式出现在引文里，`MUST` 不能只是 `MUST NOT` 的一部分，`RECOMMENDED` 不能只是
  `NOT RECOMMENDED` 的一部分；引文里另有别的关键词不算错。`statement` 的引文里不许有大写的规范性关键词
  （`SHALL`、`SHALL NOT`、`NOT RECOMMENDED` 也算）。RFC 1928、1929 照同样的规则查。
  例外只有一个：RFC 1928 第 3 节的方法名 `NO AUTHENTICATION REQUIRED` 不算关键词。

问题（任何一条都使退出码为 1）：

| 代号 | 含义 |
| --- | --- |
| `json` | 条款文件不是合法的 JSON 对象 |
| `filename` | 文件名不是 rfcNNNN.json，或与文件里的 rfc 不一致 |
| `top-field` | 文件顶层缺字段或类型不对 |
| `text` | 找不到或读不了对应的 RFC 文本 |
| `title` | title 与 RFC 文本开头写的标题不一致 |
| `sha256` | text_sha256 与实际的文本文件不一致 |
| `registry` | 文本文件与 rfc_sha256.txt 登记的不一致，或没有登记 |
| `field` | 条款缺字段、类型不对或为空 |
| `id-format` | id 不是“RFC 号-章节号-序号” |
| `id-rfc` | id 里的 RFC 号与文件不一致 |
| `id-section` | id 里的章节号与 section 不一致 |
| `id-duplicate` | id 重复 |
| `enum` | level、binds、side、topic 不在允许的取值里 |
| `rows` | rows 不是行号的列表、有重复，或行号不在 rows.json 里 |
| `quote-not-found` | 引文不是 RFC 文本的子串 |
| `section-unknown` | RFC 文本里没有声明的章节 |
| `section-mismatch` | 引文在原文里，但不在声明的章节里 |
| `section-title` | section_title 与原文的章节标题不一致 |
| `level` | level 与引文里的规范性关键词不一致 |

提示（不影响退出码，要人看一眼）：

| 代号 | 含义 |
| --- | --- |
| `unknown-field` | 条款里有格式之外的字段 |
| `quote-whitespace` | 引文里的空白没有折成一个空格 |
| `section-deeper` | 引文落在声明章节的下一级小节里，可以标得更细 |
| `sentence` | 引文的开头或结尾看起来不在句子边界上（启发式） |

`sentence` 是启发式的：引文前面不是句末标点、段首或行首的项目符号，或者引文不以句末标点结尾而后面又不是另一段，就提示。
它查得出截掉半句的引文，但不保证没有漏报、误报。

脚本不查的：`binds`、`side`、`topic`、`gateway` 的解读对不对（只查取值合不合法）；条款选得全不全。这些要人审。

## 渲染

```sh
python3 spec_tables.py            # 写 ../out/spec_clauses.md
python3 spec_tables.py --check    # 只比较现有的输出与条款文件是否一致，不一致退出 1
```

按 topic 分节，每条一行，原文在每节表后的折叠块里；另有概览和按矩阵行的反查表。只渲染、不核对，不需要 RFC 文本；
条款文件不全也能运行。输出只取决于条款文件、`../rows.json` 和 `rfc_sha256.txt`，改了条款文件就重新生成。
`gateway` 当作 Markdown 行内文本原样放进表格（只转义竖线），原文和章节标题里的 Markdown 标记字符会被转义。

## 测试

```sh
python3 -m unittest discover -s research/phase2/spec -p 'test_*.py'
KAOJU_RFC_DIR=DIR python3 -m unittest discover -s research/phase2/spec -p 'test_*.py'   # 多跑一组对着真文本的
```

测试用的两篇假 RFC（一篇新格式、一篇带分页的旧格式）是自己编的文字。`fetch_rfcs.sh` 的测试不连外网：
apt 来源用现做的假 `.deb`，rfc-editor 来源用本机起的 HTTP 服务。

## 没有验证过的

- `--from rfc-editor` 没有对着真的 rfc-editor 跑过（写这些脚本的机器访问不了它）。下载、核对哈希、失败后改用 apt 的逻辑只对着本机起的 HTTP 服务测过。
- rfc-editor 上的文本与登记的哈希是否逐字节相同：未验证。不相同时 `fetch_rfcs.sh` 会报错；那时要先查清差在哪儿再决定登记哪一份，
  换了文本，条款文件的 `text_sha256` 和全部引文都要重新核对。
- `--from apt` 只在 Ubuntu 24.04、软件包版本 20230121-1 上跑过。
- 章节解析只对着这八篇的版式验证过：有目录的六篇，正文里解析出的章节号与目录完全相同（`TestRealTexts`）；RFC 1928、1929 没有目录，是人看的。
