#!/usr/bin/env python3
"""与文献对账（第一阶段 1B，PROTOCOL“与文献对账”一节）：为三篇文献的每个数字算出我们数据里口径最接近的对应值，并写明差异。

用法：
    python3 m_literature.py --db <sqlite> --out <目录> [--markdown] [--data <数据目录>] [--summary <summary.json>]
                            [--roots <PEM>] [--certcheck <二进制|go>] [--formal-start auto|first|<ISO 时间>]
                            [--dense-threshold 100] [--no-import]
    python3 m_literature.py --selftest

只读 ingest.py 建好的库（mode=ro，中间表都建在 TEMP 库里），结果写到 <目录>/literature.json；
加 --markdown 时把主要表格以 Markdown 打印到标准输出。每个比例都给分子、分母和口径，百分比保留一位小数。
文献自己的数字不写在这里（要另行对原文核对后由人填入），每项只留 paper_value: null 的占位。

三篇文献与我们的对应（细节见 DEFINITIONS，差异写在各项的 difference 里）：

- Mani 等，ACSAC 2018：每天“有回应”的占每天在榜的（按天给出并取中位数，另标每天的中断分钟数）；明文 HTML 内容不符的请求比例及其中局部改动的比例，
  以及 PROTOCOL 预期范围的“正文不符的代理占能转发的代理”；
  支持 HTTPS（可用隧道代理：隧道曾可用或遇到过中间人；hs_ok=1 作第二口径）的代理里证书被替换的比例（总数，以及 m_mitm 三层细分各自的数）；
  请求头带出客户端地址的代理占能转发代理的比例；诱饵页里的 https 链接被改成 http 的次数（从证据正文数出来）。
  这四项含聚合器抽样，另按候选来源分组。
- 所有“探访过”的比例：分子只算正式起点后有非 aborted 探访的候选（summary.go finish() 的做法），只在试运行里出现过的候选不进候选池；
  两类候选都单独报告条数。checks 里核对每个比例的分子不大于分母。
- Tsirantonakis 等，NDSS 2018：TCP 连得上过的条目数与比例；取回过测试页（明文 HTTP 转发、HTML、状态 200）的条目数；
  改动了内容的代理数及占取回过测试页的比例；其中局部改动的比例。
- Mehanna 等，MADWeb 2024：至少活跃过一次（曾通过端到端校验；更宽的口径是曾有协议回应）的比例。

分类规则复用同目录的 m_integrity（内容被改的 BodyChange 分类、judge 收到的请求头 → 带出客户端地址）和 m_mitm（“中间人”三层细分）：
能 import 就调用它们的建表函数（规则就是同一份代码），import 不了时用本模块内置的同规则实现（--no-import 强制走这条路，
自检里两条路的结果逐项比对）。m_mitm 的三层细分还需要数据目录和 certcheck；不可用时只能按 tls_detail_enum 判“冒充 judge”，
其余层记为“无法细分”。

设计要点（真实数据有一千多万条 att）：att 只按候选和“测量日”分组扫一遍（TEMP 表 lit_pd，量级是候选数 × 天数），
之后的指标都是对这张表和 m_integrity 的 aj / pc（到达 HTTP 阶段的尝试）的 SQL 聚合；在榜区间由 list_event 的加减事件用窗口函数算出
（TEMP 表 lit_iv，量级是上榜次数）。内存由 SQLite 页缓存主导。只用 Python 3.10+ 标准库。
证据正文（https 链接被改写的计数）用游标逐行读，同一个证据文件只读一次。

临时空间：TEMP 表和大的 GROUP BY / 排序落在 SQLite 的临时文件里（temp_store=FILE）。真实数据（一千多万条 att，另有
m_integrity / m_mitm 的中间表）要几 GB，默认在系统临时目录（/tmp 等）。那里空间不够时，运行前设环境变量
SQLITE_TMPDIR=<有空间的目录>（SQLite 在 Unix 上按 SQLITE_TMPDIR → TMPDIR → /var/tmp → /usr/tmp → /tmp 的顺序找临时目录）。
"""
import argparse
import datetime as dt
import gzip
import importlib
import json
import os
import re
import sqlite3
import statistics
import sys
import tempfile

MODULE = "m_literature"
OUTPUT_NAME = "literature.json"
PROTOCOL_VERSION = "1.2"
DENSE_THRESHOLD = 100   # PROTOCOL 1.2“候选密集的地址段”：候选超过 100 个的 /24
DAY_S = 86400           # “每天”= 从正式起点起算的 24 小时窗口（取的解释，见 DEFINITIONS）
# payload.go htmlTemplate 里 https://{{HOST}} 出现 10 处：<link> 样式表、<script src>、导航里 6 个 <a>、表单 action、iframe src。
# PROTOCOL 和源码注释说“8 个 https 链接”（应是不算 <link> 和 <script> 的 8 个）；这里按模板实际出现的 10 处计，并在输出里注明。
HTML_HTTPS_LINKS = 10
TUNNEL_PROTOS = ("socks5", "socks4", "connect")       # 在隧道里对 judge 做 TLS 握手的协议（attempt.go run()）
HTTPISH_LABELS = ("http", "https", "connect")          # 列表标签里属于 HTTP 代理的（lists.go labelNames）
DEFAULT_ROOTS = "/etc/ssl/certs/ca-certificates.crt"
# summary.go attempt()：c.responsive = (HS != nil && (HS.OK || HS.Code != 0)) || (HTTP != nil && HTTP.Code != 0)。
# omitempty：hs_ok=false、hs_code=0、http_code=0 在库里都是 NULL。
RESPONSIVE_SQL = "(COALESCE(hs_ok, 0) = 1 OR COALESCE(hs_code, 0) != 0 OR COALESCE(http_code, 0) != 0)"
NOT_CANCELED = "COALESCE(class, '') NOT LIKE '%canceled%'"

# 内容被改的三类名字（summary.go BodyChange 的返回值；m_integrity.BODY_KINDS 相同）
K_TRUNC = "正文被截断"
K_PARTIAL = "正文被局部改动（注入或改写）"
K_REPLACED = "正文被整页替换"
BODY_KINDS = [K_TRUNC, K_PARTIAL, K_REPLACED]
# “中间人”三层细分的名字（m_mitm 的常量；import 得到时以它为准）
L_JUDGE = "冒充 judge"
L_OTHER = "被送到别的网站"
L_UNKNOWN = "去向不明"
L_NOEV = "证据未存（无法判链）"
L_UNCHECKED = "未校验"
L_UNAVAIL = "无法细分（mitm 模块不可用）"
LAYERS = [L_JUDGE, L_OTHER, L_UNKNOWN, L_NOEV, L_UNCHECKED, L_UNAVAIL]
SEVERITY = {L_JUDGE: 0, L_UNKNOWN: 1, L_OTHER: 2, L_NOEV: 3, L_UNCHECKED: 4, L_UNAVAIL: 5}

# derive.go sentHeaders / proxyHeaders（import 到 m_integrity 时以它的为准）
SENT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "close",
    "Cookie": "",
    "X-Probe-Canary": "",
}
PROXY_HEADERS = [
    "Via", "X-Forwarded-For", "Forwarded", "X-Real-Ip", "Proxy-Connection",
    "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "Client-Ip",
    "X-Client-Ip", "Forwarded-For", "X-Proxy-Id", "X-Bluecoat-Via",
    "Surrogate-Capability", "X-Cache", "X-Squid-Error", "Cdn-Loop",
    "Proxy-Authorization", "X-Proxy-Connection", "Xroxy-Connection", "X-Originating-Ip",
    "True-Client-Ip", "Cf-Connecting-Ip", "X-Cluster-Client-Ip",
]

# 本模块在 SELECT 列表或 GROUP BY 里用到、并且会进入输出（作为维度或被聚合的值）的列。
# 只在库内做连接或判等、不进入输出的列（att.cand/nonce/http_ev、list_event.cand、cands.key、req.remote、req_header.value、
# self_ips.ip、self_names.name、evidence.hash/path）不在这里。
OUTPUT_COLUMNS = {
    "att": ["proto", "dst", "kind", "class", "tcp_ok", "hs_ok", "hs_code", "hs_class", "tls_class", "tls_detail_enum",
            "http_class", "http_code", "cand_kind", "prefix24", "ts_epoch"],
    "visit": ["group", "labels", "aborted", "prefix24", "ts_epoch"],
    "cands": ["prefix24", "group", "label_names", "visits", "ever_ok", "first_seen_epoch", "delisted_at_epoch"],
    "list_event": ["src", "label", "event", "base", "prefix24", "ts_epoch"],
    "req": ["req_canary", "method", "ts_epoch"],
    "req_header": ["name"],
    "stat_pool": ["key", "value", "ts_epoch"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["ts_epoch"],
    "version": ["version", "ts_epoch"],
    "evidence": ["ext"],
    "meta": ["ingest_version", "first_ts", "last_ts", "state_tz_offsets", "payload_len", "state_cands"],
}

DEFINITIONS = {
    "正式起点与观察窗口": "PROTOCOL“正式测量的起止”：默认取第一条 start；之后有 resumed_candidates=0 的 start（状态被清空）或版本变了就取那之后的。"
                 "之前的数据是试运行，不并入：只在正式起点之前出现过的候选（有 visit / att、正式起点后没有、也不在状态文件 cands 里）不进候选池，"
                 "单独报告条数。结束 = att / req / stop 的最晚时刻。可用 --formal-start 覆盖。与 summary.json 交叉核对时不裁（summary.go 不裁）",
    "中断": "PROTOCOL“正式测量的起止”：“中断的时段（两次 stop 与 start 之间）在报告里写明”。每条 start（第一条除外）与它和前一条 start 之间最早的 stop 配对，"
          "中断 = [stop, start)；两条 start 之间没有 stop（异常退出）时，用这段里最后一条 att 的时刻估计中断的开始，并标明是估计。"
          "按测量日的表另给“中断分钟数”（中断与当天窗口重叠的分钟数）：中断较长的那天“有回应 / 在榜”会偏低，取中位数时要看这一列",
    "测量日": "“每天”取从正式起点起算的 24 小时窗口（第 k 天 = [起点 + 24k 小时, 起点 + 24(k+1) 小时)），不是 UTC 日历日：72 小时正好 3 个完整的测量日，"
           "按日历日会多出两个半天。不满 24 小时的窗口单独标出，中位数只在完整窗口上取（没有完整窗口时才用全部窗口）。这是本模块取的解释，PROTOCOL 没规定",
    "在榜（当天）": "条目在当天任一时刻出现在某个常规列表里。在榜区间由 list_event 的加减事件算出：add 开始、del 结束；探测器重启后的首次快照（base=1）"
               "把还在榜的条目再 add 一遍，不算新上榜；条目在某次首次快照里没出现，就当作在那一刻下榜（重启期间下榜的条目没有 del 事件）。"
               "聚合器抽样的条目不在 list_event 里，不进这项。没有 list_event 时退而用状态文件 cands 的 first_seen / delisted_at（结束时刻的快照，近似）。"
               "PROTOCOL“指标定义·时点可用率”的“在榜”",
    "在榜·进入候选池": "在榜条目里出现在 cands（状态文件）或 visit / att 里的：被排除的条目（judge 自己的地址、私网地址、28 个知名端口、退出名单）在 list_event 里有、"
                 "候选池里没有（SCHEMA“坑”13），数量在 stat_pool 的 skipped_* 里。Mani 等的分母是列表里全部条目，所以两种分母都给。PROTOCOL“频率与限速”（不探测的地址）与“与文献对账”",
    "有协议回应": "至少一次尝试得到协议层面的回答，包括拒绝和要求认证：照 summary.go attempt() 的 responsive——握手通过、握手有应答码（SOCKS 应答码 / CONNECT 状态码，"
              "含 hs_auth、hs_refused）、或收到 HTTP 状态码。PROTOCOL“指标定义·有协议回应”，对应 Mani 等的 responsive。canceled 的尝试不算",
    "连得上": "至少一次尝试的 TCP 阶段通过（tcp_ok=1）。PROTOCOL“指标定义·连得上”",
    "可用（曾通过端到端校验）": "至少一次尝试 class='ok' 且目的地是 judge（判定链：状态 200、正文哈希、金丝雀）。PROTOCOL“指标定义·可用”“累计可用率”",
    "探访过": "正式起点之后至少有一次非 aborted 的 visit 记录。PROTOCOL 1.2“候选密集的地址段”：从没探访过的条目不进任何比例的分母，单独报告条数。"
            "分母是“探访过的”（或含从没探访过的“全部条目”）时，分子也只算探访过的候选，照 summary.go finish()：visits==0 的候选整个跳过，分子分母都不含。"
            "停机时在途的探访被整次标成 aborted（prober.go：ctx 取消时 v.Aborted=true，“这次探访的结果不作数”），其中已完成的尝试不是 canceled；"
            "只有这种探访的候选“有尝试、但没有探访过”，单独报告条数，不进这些比例的分子和分母。"
            "分母本身由尝试定义的比例（隧道建立过 / 曾可用、能转发、取回过 HTML）分子分母都取正式起点后全部非 canceled 尝试，与 summary.go 的 findings 和 Anon 相同（它们不看探访）。"
            "按测量日统计时，“当天有尝试”按尝试时刻分天，分子（当天连得上 / 有回应 / 可用）也按尝试时刻，所以分子是分母的子集；"
            "visit 记录在探访结束时写（prober.go VisitRec），跨过 24 小时边界的探访会落到后一天，“当天探访过（按 visit 记录时刻）”只作参考列。"
            "例外：Tsirantonakis 等和 Mehanna 等的分母是收集到的全部条目，为了与文献对账另给“/ 全部条目（文献口径）”，"
            "这个分母含从没探访过的条目，违反 PROTOCOL 1.2 的分母规则，键名里写明，仅供对账",
    "内容被改（HTML，按请求）": "明文（dst=judge_http）HTML 载荷（kind=h）、状态 200 的请求里正文 SHA-256 不符的（http_class='http_body_mismatch'）。"
                     "分类照 summary.go BodyChange：截断 / 局部改动（期望正文不少于一半的行原样出现，probe.Similarity）/ 整页替换；只有局部改动算篡改。"
                     "主口径只算 HTTP 转发（proto=forward，Mani 等的对象是 HTTP 代理、用绝对 URI 转发），另给“全部明文”（含 SOCKS / CONNECT 隧道里的明文）。"
                     "按代理另给 PROTOCOL 预期范围的口径“正文不符的代理 / 能转发的代理”：分子取能转发的代理里正文不符过的（伪造或返回缓存、judge 从没收到它转发请求的代理不在分母里，"
                     "单独计数），这样分子是分母的子集。PROTOCOL“指标定义·内容被改”与“与文献对账”（预期范围表）",
    "无害 / 有害": "Mani 等把不符分成无害（错误页等）和恶意。我们没有人工判定，只能用 BodyChange：局部改动 = 有害的上界候选（注入、改写、剥离 https 都落在这里），"
              "截断 + 整页替换 = 多半无害（传输问题、错误页、门户页）。两者都不是对意图的判断。PROTOCOL“指标定义·内容被改”（只有局部改动算篡改）与“与文献对账”",
    "支持 HTTPS（可用隧道代理）": "PROTOCOL 预期范围表的分母是“可用隧道代理”。主分母取“隧道曾可用或遇到过中间人”：HTTP CONNECT 到 judge 443 端口的尝试里 class='ok' 过，"
                           "或者隧道里拿到的证书不是 judge 的（中间人）。只取 class='ok' 的话中间人代理（隧道通、TLS 被接管，从不 ok）不在分母里，分子就不是分母的子集；"
                           "这是本模块取的解释。第二口径取 CONNECT 握手通过过（hs_ok=1）的代理：含隧道另一头不是 TLS（tls_not_tls）、tls_eof 等从没可用过的代理，比“可用隧道代理”宽。"
                           "另给把 socks5/socks4 也算进去的“全部隧道协议”范围。PROTOCOL“一次尝试”（握手阶段：CONNECT 请求连到 judge）与“与文献对账”（预期范围表：证书被替换的代理占可用隧道代理）",
    "证书被替换": "隧道里 TLS 握手拿到的证书不是 judge 的（tls_class='tls_cert_invalid'，proto≠tlsproxy）。总数照 PROTOCOL“中间人”原定义；"
             "三层细分照 PROTOCOL 1.2“‘中间人’的细分”，由 m_mitm 算：冒充 judge（叶子证书上的名字是 judge 的）/ 被送到别的网站 / 去向不明，"
             "另有证据未存（无法判链）。Mani 等的判据是“经代理拿到的证书与直连拿到的不同”，与我们的总数最接近；对账用哪一层待定（PROTOCOL“与文献对账”）",
    "请求头带出客户端地址": "以 judge 记下的请求头为准（同一 nonce 取最早到达的那份），照 derive.go Derive：任一请求头的值里含探测器自己的地址（self_ips，来源 start.judge_ip；"
                   "探测器与 judge 同机）→ 透明。按代理计：该代理任一被 judge 收到的 HTTP 转发请求带出了地址。PROTOCOL“指标定义·请求被改、匿名程度”",
    "能转发的代理": "HTTP 转发（proto=forward）到 judge 的请求至少有一次被 judge 收到（不限 class、不限载荷：正文不符、金丝雀不符的也算，代理确实把请求转过去了）。"
              "另给 summary.go Anon 的口径（class='ok' 且 judge 收到）。“全部明文”范围里是任一协议到 judge 明文端口的请求被 judge 收到过。"
              "PROTOCOL“与文献对账”（预期范围表：请求头带出客户端地址、明文正文不符，两项的分母都是能转发的代理）与“指标定义·请求被改、匿名程度”",
    "候选来源": "Mani 等的四项（内容被改、证书被替换、带出客户端地址、https 被改写）的主结果含聚合器抽样（cands.group=1）的候选，"
            "另在“按候选来源”里分常规列表 / 聚合器抽样给出主要比例（候选来源取 lit_pool.grp：状态文件的 group，没有时取最后一次探访的）。"
            "每天有回应只含常规列表（聚合器抽样的条目不在 list_event 里）；Tsirantonakis 等只取常规列表；Mehanna 等三组都给",
    "https 链接被改成 http": "记录里没有这项的字段（HTTPResult 只有 len/sha/pre/suf/sim/canary/flags/added/hdr/ev，summary.go BodyChange 也只分三类），"
                        "所以从 evidence/ 里存下的正文（att.http_ev）数：HTML 不符的请求里，正文中“http://<judge 主机名>/”和“https://<judge 主机名>/”各出现几次。"
                        "被改的链接数 = min(http 次数, max(0, 10 − https 次数))：https 少了几个、又多出几个 http，才算被改。只在被归为局部改动的正文里算；"
                        "整页替换的正文里出现 http://<judge>/ 多半是回显请求地址（如“REQUEST_URI = http://…”这类代理检测页），https 一个没少、"
                        "只是多出 http://<judge>/ 的局部改动是给链接加前缀（如“http://<judge>/https://<judge>/…”这类网页代理的改写），这两类都单列、不算剥离。"
                        "这是看过真实数据之后改的计法（原来只要出现 http://<judge>/ 就算，整页替换的回显会被误算），只改分析脚本、不改测量口径。"
                        "正文带 gzip 魔数的先解开。证据没存下（探测器没拿到、证据库超限）或读不了的请求单独计数。judge 主机名只在库内比对，不输出。"
                        "范围与“内容被改”相同：主口径只算 HTTP 转发（proto=forward），另给全部明文。"
                        "PROTOCOL“一次尝试”（载荷：HTML 诱饵页有 8 个 https 链接）与“与文献对账”（把 https 链接改成 http）",
    "取回过测试页": "HTTP 转发（proto=forward）、明文、HTML 载荷、状态 200 的请求至少一次（无论正文对不对）。Tsirantonakis 等的对应数字是成功取回 honeysite 页面的代理。"
              "另给“任一协议明文 200”。PROTOCOL“与文献对账”（Tsirantonakis 等：取回过测试页）",
    "改动了内容（按代理）": "取回过测试页的代理里，至少一次 HTML 正文不符的。其中局部改动 = 至少一次被归为局部改动。Tsirantonakis 等按 DOM 差异找改动、再人工判恶意；"
                  "我们按哈希找不符、按行相似度分类，没有人工判定。PROTOCOL“指标定义·内容被改”与“与文献对账”（改动了内容）",
    "至少活跃过一次": "Mehanna 等的 active。主口径 = 曾通过端到端校验（可用）；更宽的口径 = 曾有协议回应。分母按 PROTOCOL 1.2 取探访过的候选；"
               "另给全部候选（含从没探访过的，文献口径：Mehanna 等的分母是收集到的全部，见“探访过”的例外）。按常规列表 / 聚合器抽样分开。"
               "PROTOCOL“指标定义·累计可用率”与“与文献对账”（Mehanna 等：至少活跃过一次）",
    "比例自检": "checks 里逐个核对输出中的每个比例（含 num / den / pct 的对象）：分子不大于分母。按上面的定义分子都是分母的子集，出现例外说明口径实现有错",
    "候选密集的 /24":"候选数超过阈值（默认 100）的 /24（状态文件 cands ∪ 出现过的代理候选）。各比例另给一组去掉这些 /24 里全部候选的结果。PROTOCOL 1.2“候选密集的地址段”",
    "百分比": "100 × 分子 / 分母，保留一位小数；分母为 0 时为 null。每个比例都同时给出分子、分母，checks 里核对每个比例的分子不大于分母。"
            "paper_value 一律 null，由人对原文核对后填入；文献的数字（结果和对象规模）不写进本模块的输出，PROTOCOL“与文献对账”表里有转述，以原文为准",
}

# 与原文口径的差异，各项共用的部分
DIFF_COMMON = ("我们每 20 分钟（可用的）到 6 小时（连不上的）复测一次、72 小时；诱饵站不是真实站点，只有一个观测点；"
               "判定链是“状态 200 + 正文哈希 + 响应头金丝雀”，不是人工看页面。")


# ---------------------------------------------------------------- 小工具

def pct(num, den):
    return round(100.0 * num / den, 1) if den else None


def ratio(num, den):
    return {"num": int(num or 0), "den": int(den or 0), "pct": pct(num or 0, den or 0)}


def iso_minute(epoch):
    """时间只在分桶（到分钟）之后输出。"""
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def parse_iso(s):
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    t = dt.datetime.fromisoformat(s)
    if t.tzinfo is None:
        raise ValueError("时间必须带时区：%r" % s)
    return t.timestamp()


def fmt(v, suffix=""):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:,.1f}{suffix}"
    return f"{v:,}{suffix}"


def rfmt(r):
    if not r:
        return "—"
    return f"{fmt(r['num'])}/{fmt(r['den'])}（{fmt(r['pct'], '%')}）"


def sql_in(values):
    return ",".join("'%s'" % v.replace("'", "''") for v in values)


def median(values):
    vals = [v for v in values if v is not None]
    return round(statistics.median(vals), 1) if vals else None


def item(paper_metric, ours, difference, **extra):
    """一个与文献对账的条目：原文口径、我们的值、差异说明、占位的 paper_value。"""
    d = {"paper_metric": paper_metric, "paper_value": None, "ours": ours, "difference": difference}
    d.update(extra)
    return d


class DB:
    def __init__(self, path):
        # mode=ro：库文件只读；临时表都建在 TEMP 库里（query_only 会连 TEMP 表一起禁掉，所以不用它）
        self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        self.con.execute("PRAGMA cache_size = -262144")  # 256 MB 页缓存，内存不随记录数增长
        self.con.execute("PRAGMA temp_store = FILE")
        self.fs = None

    def q(self, sql, params=()):
        return self.con.execute(sql, params).fetchall()

    def one(self, sql, params=()):
        return self.con.execute(sql, params).fetchone()

    def scalar(self, sql, params=()):
        row = self.one(sql, params)
        return row[0] if row else None

    def x(self, sql, params=()):
        self.con.execute(sql, params)

    def many(self, sql, rows):
        self.con.executemany(sql, rows)

    def has_table(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) > 0

    def has_temp(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_temp_master WHERE type='table' AND name=?", (name,)) > 0

    def has_column(self, table, col):
        return any(r[1] == col for r in self.q('PRAGMA table_info("%s")' % table))

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))

    def counts(self, sql, params=()):
        return {("null" if k is None else str(k)): int(v or 0) for k, v in self.q(sql, params)}


def _import_sibling(name, allow):
    """import 同目录的模块；失败返回 None（本模块必须能独立运行）。"""
    if not allow:
        return None
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        return importlib.import_module(name)
    except Exception as e:  # noqa: BLE001
        print("提示：import %s 失败（%s），改用本模块内置的同规则实现" % (name, type(e).__name__), file=sys.stderr)
        return None


def check_whitelist(db):
    """输出前按白名单核对本模块用到的列。优先用同目录 ingest.py 的权威常量，拿不到就读库里的 meta.output_whitelist。"""
    wl, source = None, None
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        import ingest  # noqa: E402
        wl, source = ingest.OUTPUT_WHITELIST, "ingest.OUTPUT_WHITELIST"
    except Exception:  # noqa: BLE001
        raw = db.meta("output_whitelist")
        if raw:
            wl, source = json.loads(raw), "meta.output_whitelist"
    if wl is None:
        raise SystemExit("拿不到可输出列白名单（ingest.py 不可导入，库里也没有 meta.output_whitelist），拒绝输出")
    problems = []
    for table, cols in OUTPUT_COLUMNS.items():
        allowed = wl.get(table)
        if allowed is None:
            problems.append("表 %s 不在白名单里" % table)
            continue
        bad = [c for c in cols if c not in allowed]
        if bad:
            problems.append("表 %s 的列不可输出：%s" % (table, ", ".join(bad)))
    if problems:
        raise SystemExit("白名单检查不通过：" + "；".join(problems))
    return source


# ---------------------------------------------------------------- 观察窗口（规则与其他模块相同）

def observation_window(db, formal_start_arg):
    """正式起点与结束时刻。规则同 m_integrity / m_mitm 的 observation_window（PROTOCOL“正式测量的起止”）。"""
    starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0) FROM start ORDER BY ts_epoch") if db.has_table("start") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch") if db.has_table("version") else []
    ends = []
    for t in ("att", "req", "stop"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None
    first_att = db.scalar("SELECT MIN(ts_epoch) FROM att") if db.has_table("att") else None
    rule = []
    if starts:
        fs = starts[0][0]
        rule.append("第一条 start")
        cleared = [s for s in starts[1:] if s[1] == 0]
        if cleared:
            fs = cleared[-1][0]
            rule.append("之后有 resumed_candidates=0 的 start（状态被清空）：取最后一次")
        if len({v for _, v in versions}) > 1:
            change = None
            for i in range(1, len(versions)):
                if versions[i][1] != versions[i - 1][1]:
                    change = versions[i][0]
            after = [s[0] for s in starts if s[0] >= change - 1]  # version 与 start 几乎同时写，留 1 秒余量
            if after and after[0] > fs:
                fs = after[0]
                rule.append("版本变过：取最后一次版本变化之后的第一条 start")
    else:
        fs = first_att
        rule.append("没有 start 记录：取第一条 att")
    if formal_start_arg and formal_start_arg != "auto":
        if formal_start_arg == "first":
            fs = starts[0][0] if starts else first_att
            rule = ["--formal-start first"]
        else:
            fs = parse_iso(formal_start_arg)
            rule = ["--formal-start 指定"]
    if fs is None:
        raise SystemExit("库里没有任何尝试记录，定不了正式起点")
    trial = int(db.scalar("SELECT COUNT(*) FROM att WHERE ts_epoch < ?", (fs,)) or 0)
    intr = interruptions(db, starts)
    return {
        "formal_start_utc": iso_minute(fs), "formal_start_rule": "；".join(rule), "end_utc": iso_minute(end),
        "hours": round((end - fs) / 3600.0, 2) if end is not None else None,
        "starts": len(starts), "versions": sorted({v for _, v in versions}),
        "trial_run_attempts_before_formal_start": trial,
        "interruptions": [{"stop_utc": iso_minute(b), "start_utc": iso_minute(e), "seconds": round(e - b, 3), "minutes": round((e - b) / 60.0, 2),
                           "begin_source": src, "resumed_candidates": rc, "after_formal_start": b >= fs}
                          for b, e, src, rc in intr],
        "interruption_minutes_after_formal_start": round(sum(max(0.0, e - max(b, fs)) for b, e, _, _ in intr if e > fs) / 60.0, 2),
        "_fs": fs, "_end": end, "_intr": [(max(b, fs), e) for b, e, _, _ in intr if e > fs],
    }


def interruptions(db, starts):
    """PROTOCOL“正式测量的起止”：中断的时段（两次 stop 与 start 之间）要写明。每条 start（第一条除外）与它和前一条 start 之间
    最早的 stop 配对；中间没有 stop（异常退出）时，用这段里最后一条 att 的时刻估计中断开始。返回 [(开始, 结束, 来源, resumed_candidates)]。"""
    stops = [r[0] for r in db.q("SELECT ts_epoch FROM stop WHERE ts_epoch IS NOT NULL ORDER BY ts_epoch")] if db.has_table("stop") else []
    out = []
    for i in range(1, len(starts)):
        prev_s, s, rc = starts[i - 1][0], starts[i][0], starts[i][1]
        between = [t for t in stops if prev_s <= t <= s]
        if between:
            out.append((between[0], s, "stop 记录", int(rc)))
            continue
        last = db.scalar("SELECT MAX(ts_epoch) FROM att WHERE ts_epoch >= ? AND ts_epoch < ?", (prev_s, s))
        out.append((last if last is not None else prev_s, s,
                    "估计：两条 start 之间没有 stop（异常退出），取这段里最后一条 att" if last is not None
                    else "估计：两条 start 之间没有 stop 也没有 att，取前一条 start", int(rc)))
    return out


def payload_lengths(db):
    """各载荷的期望长度（BodyChange 的 wantLen）。同 m_integrity.payload_lengths。"""
    out, source = {}, {}
    raw = db.meta("payload_len")
    if raw:
        try:
            for k, v in json.loads(raw).items():
                if isinstance(v, dict) and v.get("len"):
                    out[k] = int(v["len"])
                    source[k] = "meta.payload_len"
        except (ValueError, AttributeError):
            pass
    for k in ("h", "j", "b"):
        if k in out:
            continue
        row = db.one("""SELECT http_len, COUNT(*) AS n FROM att
                        WHERE class = 'ok' AND dst IN ('judge_http', 'judge_tls') AND COALESCE(kind, 'h') = ? AND http_len IS NOT NULL
                        GROUP BY http_len ORDER BY n DESC LIMIT 1""", (k,))
        if row:
            out[k] = int(row[0])
            source[k] = "att 里 class=ok 的众数"
    return out, source


# ---------------------------------------------------------------- 内容与请求的分类表：优先用 m_integrity，否则内置同规则实现

def build_integrity_tables(db, fs, dense_threshold, allow_import):
    """建 TEMP 表 aj（到达 HTTP 阶段、带 nonce、目的地 judge 的尝试，与 judge 对账：seen / leak / anon）、pc（收到状态码的尝试，带 BodyChange 分类）、
    dense24、ips、plen。能 import m_integrity 就用它的 build_tables（规则同一份代码），否则用下面的内置实现（列是 m_integrity 版本的子集）。"""
    plen, plen_src = payload_lengths(db)
    mi = _import_sibling("m_integrity", allow_import)
    if mi is not None:
        try:
            info = mi.build_tables(db, fs, dense_threshold, plen)
            return {"source": "m_integrity.build_tables", "plen": plen, "plen_source": plen_src,
                    "self_ips_source": info.get("self_ips_source"), "self_ips_count": info.get("self_ips_count"),
                    "sent_headers": mi.SENT_HEADERS, "proxy_headers": mi.PROXY_HEADERS}
        except Exception as e:  # noqa: BLE001
            print("提示：m_integrity.build_tables 失败（%s），改用内置实现" % type(e).__name__, file=sys.stderr)
            for t in ("ips", "plen", "cu", "dense24", "rq_n", "rq_first", "rh", "rd", "basefp", "aj", "pc", "ob", "fl", "ad"):
                db.x("DROP TABLE IF EXISTS temp.%s" % t)
    return build_integrity_tables_builtin(db, fs, dense_threshold, plen, plen_src)


def build_integrity_tables_builtin(db, fs, dense_threshold, plen, plen_src):
    """m_integrity.build_tables 的子集实现，规则一致：
    - ips：探测器自己的地址（summary.go selfIPs 只用 c.Judge.PublicIP，即 start.judge_ip）；
    - dense24：候选超过阈值的 /24（cands ∪ att 里的代理候选）；
    - aj：att 里带 nonce、目的地 judge、非 canceled 的尝试，LEFT JOIN judge 最早收到的同 nonce 请求（derive.go：按 TS 稳定排序取第一份）：
          seen、leak（任一非 Host 头的值含探测器地址）、anon（leak→transparent，含 proxyHeaders 里的头→anonymous，否则 elite）；
    - pc：cand_kind 为 proxy/node、目的地 judge、收到状态码的尝试，body_change 照 summary.go BodyChange。"""
    db.x("CREATE TEMP TABLE ips (ip TEXT PRIMARY KEY)")
    self_src, n_self = None, 0
    if db.has_table("self_ips"):
        rows = db.q("SELECT DISTINCT ip FROM self_ips WHERE source = 'start.judge_ip' AND ip IS NOT NULL AND ip != ''")
        self_src = "start.judge_ip"
        if not rows:
            rows = db.q("SELECT DISTINCT ip FROM self_ips WHERE ip IS NOT NULL AND ip != ''")
            self_src = "self_ips 全部来源（没有 start.judge_ip）"
        for (ip,) in rows:
            db.x("INSERT OR IGNORE INTO ips VALUES (?)", (ip,))
        n_self = db.scalar("SELECT COUNT(*) FROM ips")
    db.x("CREATE TEMP TABLE plen (kind TEXT PRIMARY KEY, len INTEGER)")
    for k, v in plen.items():
        db.x("INSERT INTO plen VALUES (?, ?)", (k, v))
    if db.has_table("cands"):
        db.x("""CREATE TEMP TABLE cu AS SELECT key AS cand, prefix24 FROM cands
                UNION SELECT DISTINCT cand, prefix24 FROM att WHERE cand_kind = 'proxy'""")
    else:
        db.x("CREATE TEMP TABLE cu AS SELECT DISTINCT cand, prefix24 FROM att WHERE cand_kind = 'proxy'")
    db.x("CREATE TEMP TABLE dense24 AS SELECT prefix24, COUNT(*) AS n FROM cu WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING n > ?",
         (dense_threshold,))
    db.x("CREATE INDEX temp.dense24_p ON dense24(prefix24)")

    db.x("""CREATE TEMP TABLE rq_first AS
            SELECT rid, nonce, remote, COALESCE(req_canary, 'missing') AS req_canary, method
            FROM (SELECT rid, nonce, remote, req_canary, method, ROW_NUMBER() OVER (PARTITION BY nonce ORDER BY ts_epoch, rid) AS rn
                  FROM req WHERE nonce IS NOT NULL) WHERE rn = 1""")
    db.x("CREATE INDEX temp.rq_first_rid ON rq_first(rid)")
    db.x("CREATE INDEX temp.rq_first_nonce ON rq_first(nonce)")
    db.x("""CREATE TEMP TABLE rh AS
            SELECT h.req_rid,
                   MAX(h.name IN (%s)) AS revealed,
                   MAX(h.name != 'Host' AND EXISTS (SELECT 1 FROM ips WHERE instr(h.value, ips.ip) > 0)) AS leak
            FROM req_header h JOIN rq_first f ON f.rid = h.req_rid GROUP BY h.req_rid""" % sql_in(PROXY_HEADERS))
    db.x("CREATE INDEX temp.rh_rid ON rh(req_rid)")
    db.x("""CREATE TEMP TABLE rd AS
            SELECT f.nonce, f.rid AS req_rid, f.remote, COALESCE(h.leak, 0) AS leak, COALESCE(h.revealed, 0) AS revealed,
                   CASE WHEN COALESCE(h.leak, 0) THEN 'transparent' WHEN COALESCE(h.revealed, 0) THEN 'anonymous' ELSE 'elite' END AS anon
            FROM rq_first f LEFT JOIN rh h ON h.req_rid = f.rid""")
    db.x("CREATE INDEX temp.rd_nonce ON rd(nonce)")
    db.x("""CREATE TEMP TABLE aj AS
            SELECT a.rid, a.cand, a.cand_kind, a.cand_ip, a.prefix24, a.visit, a.proto, a.dst, COALESCE(a.kind, 'h') AS kind, a.arm,
                   a.class, a.http_class, a.http_code, a.ts_epoch, (a.ts_epoch >= ?) AS in_win, COALESCE(a.tls_ok, 0) AS tls_ok, a.nonce,
                   (r.nonce IS NOT NULL) AS seen, r.remote, r.anon, r.leak, r.revealed
            FROM att a LEFT JOIN rd r ON r.nonce = a.nonce
            WHERE a.nonce IS NOT NULL AND a.dst IN ('judge_http', 'judge_tls') AND %s""" % NOT_CANCELED.replace("class", "a.class"), (fs,))
    db.x("CREATE INDEX temp.aj_cand ON aj(cand)")
    db.x("CREATE INDEX temp.aj_kind ON aj(cand_kind, dst, class)")
    db.x("""CREATE TEMP TABLE pc AS
            SELECT a.rid, a.cand, a.cand_kind, a.prefix24, a.proto, a.dst, COALESCE(a.kind, 'h') AS kind, a.class, a.http_class,
                   a.http_code, (a.ts_epoch >= ?) AS in_win,
                   COALESCE(a.http_len, 0) AS len, COALESCE(a.http_pre, 0) AS pre, COALESCE(a.http_suf, 0) AS suf,
                   COALESCE(a.http_sim, 0) AS sim, p.len AS want_len,
                   CASE WHEN a.http_class = 'http_body_mismatch' THEN
                        CASE WHEN COALESCE(a.http_pre, 0) = COALESCE(a.http_len, 0) AND COALESCE(a.http_len, 0) < COALESCE(p.len, 0)
                                  THEN '%s'
                             WHEN (COALESCE(a.kind, 'h') = 'b' AND COALESCE(a.http_sim, 0) >= 90)
                                  OR (COALESCE(a.kind, 'h') != 'b' AND COALESCE(a.http_sim, 0) >= 50)
                                  THEN '%s'
                             ELSE '%s' END
                   END AS body_change,
                   (a.http_ev IS NOT NULL) AS has_ev
            FROM att a LEFT JOIN plen p ON p.kind = COALESCE(a.kind, 'h')
            WHERE a.cand_kind IN ('proxy', 'node') AND a.dst IN ('judge_http', 'judge_tls')
              AND a.http_code IS NOT NULL AND %s""" % (K_TRUNC, K_PARTIAL, K_REPLACED, NOT_CANCELED.replace("class", "a.class")), (fs,))
    db.x("CREATE INDEX temp.pc_cand ON pc(cand)")
    db.x("CREATE INDEX temp.pc_k ON pc(cand_kind, dst, http_class)")
    return {"source": "本模块内置（与 m_integrity.build_tables 同规则的子集）", "plen": plen, "plen_source": plen_src,
            "self_ips_source": self_src, "self_ips_count": int(n_self or 0),
            "sent_headers": SENT_HEADERS, "proxy_headers": PROXY_HEADERS}


# ---------------------------------------------------------------- “中间人”三层：优先跑 m_mitm 的流程，否则只按 detail 判

def build_mitm_table(db, fs, data_dir, roots, certcheck_arg, allow_import):
    """建 TEMP 表 mcl（每条中间人尝试一行，带 layer）。能 import m_mitm 就跑它的 build_mitm_table → verify_chains → build_subj_names → classify
    （三层细分的规则和证书链校验都是它的代码）；否则内置：detail=unknown_authority → 冒充 judge，其余 → 无法细分。"""
    mm = _import_sibling("m_mitm", allow_import)
    layers = {"judge": L_JUDGE, "other": L_OTHER, "unknown": L_UNKNOWN, "noev": L_NOEV, "unchecked": L_UNCHECKED}
    if mm is not None:
        try:
            hosts, ips = mm.judge_identity(db)
            db.fs = fs
            n_m = mm.build_mitm_table(db, fs)
            cert = mm.verify_chains(db, data_dir, roots, certcheck_arg, hosts, ips)
            mm.build_subj_names(db, hosts, ips)
            mm.classify(db)
            layers = {"judge": mm.L_JUDGE, "other": mm.L_OTHER, "unknown": mm.L_UNKNOWN, "noev": mm.L_NOEV, "unchecked": mm.L_UNCHECKED}
            roots_info = cert.get("roots") or {}
            return {"source": "m_mitm（build_mitm_table → verify_chains → build_subj_names → classify）", "mitm_attempts": int(n_m or 0),
                    "judge_hostname_available": len(hosts) > 0,
                    "certcheck": {"tool": cert.get("tool"), "go_version": cert.get("go_version"),
                                  "roots_certs": roots_info.get("certs"), "roots_package_version": roots_info.get("package_version"),
                                  "stored_files": cert.get("stored_files"), "jobs": cert.get("jobs"), "refined_jobs": cert.get("refined_jobs"),
                                  "read_errors": cert.get("read_errors"), "parse_errors": cert.get("parse_errors"), "note": cert.get("note")},
                    "layers": layers}
        except BaseException as e:  # noqa: BLE001  SystemExit 也要接住：certcheck 失败不该让整个模块退出
            if isinstance(e, KeyboardInterrupt):
                raise
            # 错误原文可能带证据文件路径（哈希）或地址，只记类型，原文打到 stderr
            print("提示：m_mitm 流程失败（%s）：%s" % (type(e).__name__, str(e)[:300]), file=sys.stderr)
            for t in ("m", "leafinfo", "chk", "subjname", "issuername", "mc", "mcl"):
                db.x("DROP TABLE IF EXISTS temp.%s" % t)
            note = "m_mitm 流程失败（%s），退回内置实现" % type(e).__name__
        else:  # pragma: no cover
            note = None
    else:
        note = "m_mitm 不可用"
    db.x("""CREATE TEMP TABLE mcl AS
            SELECT a.rid, a.cand, a.cand_kind, a.prefix24, a.proto, a.dst, a.ts_epoch, COALESCE(a.tls_detail_enum, 'other') AS detail,
                   CASE WHEN a.tls_detail_enum = 'unknown_authority' THEN '%s' ELSE '%s' END AS layer
            FROM att a
            WHERE a.tls_class = 'tls_cert_invalid' AND a.proto != 'tlsproxy' AND COALESCE(a.cand_kind, '') != 'control'
              AND a.ts_epoch >= ? AND %s""" % (L_JUDGE, L_UNAVAIL, NOT_CANCELED.replace("class", "a.class")), (fs,))
    db.x("CREATE INDEX temp.mcl_cand ON mcl(cand)")
    return {"source": "本模块内置（只按 tls_detail_enum=unknown_authority 判“冒充 judge”；" + note + "）",
            "mitm_attempts": int(db.scalar("SELECT COUNT(*) FROM mcl") or 0), "judge_hostname_available": None, "certcheck": None,
            "layers": layers}


# ---------------------------------------------------------------- 本模块自己的表

def build_pool(db, fs):
    """TEMP 表 lit_pool：每个代理候选一行。cand、prefix24、grp（0 常规 / 1 聚合器抽样）、httpish（标签含 http/https/connect）、
    in_state（在状态文件里）、visited（正式起点后有非 aborted 的 visit）。来源：cands ∪ 正式起点后的 visit ∪ 正式起点后的 att 代理候选。
    cands 是结束时刻的快照，整张表都收；visit / att 只收正式起点之后的（PROTOCOL“正式测量的起止”：试运行数据不并入正式结果），
    只在试运行里出现过的候选由 denominators() 单独报告条数。"""
    has_c, has_v = db.has_table("cands"), db.has_table("visit")
    db.x("CREATE TEMP TABLE lit_pool (cand TEXT PRIMARY KEY, prefix24 TEXT, grp INTEGER, httpish INTEGER, in_state INTEGER, visited INTEGER)")
    if has_c:
        db.x("""INSERT OR IGNORE INTO lit_pool
                SELECT key, prefix24, COALESCE("group", 0),
                       CASE WHEN label_names IS NULL THEN NULL
                            ELSE EXISTS (SELECT 1 FROM json_each(cands.label_names) WHERE value IN (%s)) END,
                       1, 0 FROM cands""" % sql_in(HTTPISH_LABELS))
    if has_v:
        # 没有状态文件（或候选不在里面）时从 visit 取：group 取最后一次探访的，标签取任一次探访里出现过的。
        # 先在派生表里去掉已经在 lit_pool 里的候选，两个相关子查询（其中一个对该候选的全部 visit 行做 json_each）只对补进来的候选执行。
        db.x("""INSERT OR IGNORE INTO lit_pool
                SELECT v.cand, v.prefix24,
                       (SELECT COALESCE("group", 0) FROM visit v2 WHERE v2.cand = v.cand ORDER BY v2.ts_epoch DESC, v2.rid DESC LIMIT 1),
                       (SELECT MAX(EXISTS (SELECT 1 FROM json_each(v3.labels) WHERE value IN (%s))) FROM visit v3 WHERE v3.cand = v.cand AND v3.labels IS NOT NULL),
                       0, 0
                FROM (SELECT DISTINCT cand, prefix24 FROM visit
                      WHERE ts_epoch >= ? AND cand NOT IN (SELECT cand FROM lit_pool)) v""" % sql_in(HTTPISH_LABELS), (fs,))
    db.x("""INSERT OR IGNORE INTO lit_pool
            SELECT DISTINCT cand, prefix24, 0, NULL, 0, 0 FROM att
            WHERE cand_kind = 'proxy' AND ts_epoch >= ? AND cand NOT IN (SELECT cand FROM lit_pool)""", (fs,))
    if has_v:
        db.x("""UPDATE lit_pool SET visited = 1 WHERE cand IN (
                    SELECT cand FROM visit WHERE COALESCE(aborted, 0) = 0 AND ts_epoch >= ?)""", (fs,))
    else:
        db.x("UPDATE lit_pool SET visited = 1 WHERE cand IN (SELECT cand FROM att WHERE cand_kind = 'proxy' AND ts_epoch >= ? AND %s)"
             % NOT_CANCELED, (fs,))
    db.x("CREATE INDEX temp.lit_pool_g ON lit_pool(grp, visited)")
    # 只在试运行里出现过的候选：正式起点前有 visit / att，正式起点后没有，也不在 cands 里（走 ts_epoch 索引，只扫试运行那一段）
    trial_src = ["SELECT cand, prefix24 FROM att WHERE cand_kind = 'proxy' AND ts_epoch < ?"]
    params = [fs]
    if has_v:
        trial_src.append("SELECT cand, prefix24 FROM visit WHERE ts_epoch < ?")
        params.append(fs)
    r = db.one("""SELECT COUNT(DISTINCT cand), COUNT(DISTINCT prefix24) FROM (%s)
                  WHERE cand NOT IN (SELECT cand FROM lit_pool)""" % " UNION ".join(trial_src), tuple(params))
    return {"cands_table": has_c, "visit_table": has_v,
            "_trial_only": {"条目": int(r[0] or 0), "所在 /24": int(r[1] or 0)}}


def build_per_day(db, fs):
    """TEMP 表 lit_pd：每个 (代理候选, 测量日) 一行，正式起点后、非 canceled 的尝试里各项“至少一次”；lit_pa：按候选合并（整个窗口）。
    一次 att 扫描（走 ts_epoch 索引），结果量级是候选数 × 天数。"""
    tun = sql_in(TUNNEL_PROTOS)
    db.x("""CREATE TEMP TABLE lit_pd AS
            SELECT cand, prefix24, CAST((ts_epoch - ?) / %d AS INTEGER) AS day,
                   COUNT(*) AS n_att,
                   MAX(COALESCE(tcp_ok, 0) = 1) AS tcp,
                   MAX(%s) AS responsive,
                   MAX(class = 'ok' AND dst IN ('judge_http', 'judge_tls')) AS ok,
                   MAX(proto = 'connect' AND dst = 'judge_tls' AND COALESCE(hs_ok, 0) = 1) AS connect_tunnel,
                   MAX(proto = 'connect' AND dst = 'judge_tls' AND class = 'ok') AS connect_ok,
                   MAX(proto = 'connect' AND dst = 'judge_tls' AND tls_class = 'tls_cert_invalid') AS connect_mitm,
                   MAX(proto IN (%s) AND dst = 'judge_tls' AND COALESCE(hs_ok, 0) = 1) AS tunnel_hs,
                   MAX(proto IN (%s) AND dst = 'judge_tls' AND class = 'ok') AS tunnel_ok,
                   MAX(proto IN (%s) AND dst = 'judge_tls' AND tls_class = 'tls_cert_invalid') AS tunnel_mitm,
                   MAX(proto = 'forward' AND dst = 'judge_http' AND COALESCE(kind, 'h') = 'h' AND http_code = 200) AS fwd_h_200,
                   MAX(proto = 'forward' AND dst = 'judge_http' AND http_code = 200) AS fwd_200,
                   MAX(dst = 'judge_http' AND http_code = 200) AS plain_200,
                   MAX(hs_class = 'hs_auth' OR http_code = 407) AS auth
            FROM att
            WHERE cand_kind = 'proxy' AND ts_epoch >= ? AND %s
            GROUP BY cand, prefix24, day""" % (DAY_S, RESPONSIVE_SQL, tun, tun, tun, NOT_CANCELED), (fs, fs))
    db.x("CREATE INDEX temp.lit_pd_cd ON lit_pd(cand, day)")
    db.x("""CREATE TEMP TABLE lit_pa AS
            SELECT cand, prefix24, SUM(n_att) AS n_att, MAX(tcp) AS tcp, MAX(responsive) AS responsive, MAX(ok) AS ok,
                   MAX(connect_tunnel) AS connect_tunnel, MAX(connect_ok) AS connect_ok, MAX(connect_mitm) AS connect_mitm,
                   MAX(tunnel_hs) AS tunnel_hs, MAX(tunnel_ok) AS tunnel_ok, MAX(tunnel_mitm) AS tunnel_mitm,
                   MAX(fwd_h_200) AS fwd_h_200, MAX(fwd_200) AS fwd_200, MAX(plain_200) AS plain_200, MAX(auth) AS auth
            FROM lit_pd GROUP BY cand, prefix24""")
    db.x("CREATE INDEX temp.lit_pa_c ON lit_pa(cand)")
    # 每 (候选, 测量日) 的探访数（非 aborted）
    if db.has_table("visit"):
        db.x("""CREATE TEMP TABLE lit_pv AS
                SELECT cand, CAST((ts_epoch - ?) / %d AS INTEGER) AS day, COUNT(*) AS n
                FROM visit WHERE COALESCE(aborted, 0) = 0 AND ts_epoch >= ? GROUP BY cand, day""" % DAY_S, (fs, fs))
    else:
        db.x("CREATE TEMP TABLE lit_pv AS SELECT cand, day, n_att AS n FROM lit_pd")
    db.x("CREATE INDEX temp.lit_pv_cd ON lit_pv(cand, day)")
    # 每个候选的 HTML 转发正文情况（从 pc）与 judge 收到的转发请求（从 aj）
    db.x("""CREATE TEMP TABLE lit_pb AS
            SELECT cand,
                   MAX(proto = 'forward' AND kind = 'h' AND http_code = 200) AS fwd_h_200,
                   MAX(proto = 'forward' AND kind = 'h' AND http_class = 'http_body_mismatch') AS fwd_h_mis,
                   MAX(proto = 'forward' AND kind = 'h' AND body_change = '%s') AS fwd_h_partial,
                   MAX(proto = 'forward' AND kind = 'h' AND body_change = '%s') AS fwd_h_trunc,
                   MAX(proto = 'forward' AND kind = 'h' AND body_change = '%s') AS fwd_h_replaced,
                   MAX(kind = 'h' AND http_code = 200) AS h_200,
                   MAX(kind = 'h' AND http_class = 'http_body_mismatch') AS h_mis,
                   MAX(kind = 'h' AND body_change = '%s') AS h_partial
            FROM pc WHERE in_win = 1 AND cand_kind = 'proxy' AND dst = 'judge_http' GROUP BY cand""" % (K_PARTIAL, K_TRUNC, K_REPLACED, K_PARTIAL))
    db.x("CREATE INDEX temp.lit_pb_c ON lit_pb(cand)")
    db.x("""CREATE TEMP TABLE lit_pl AS
            SELECT cand,
                   MAX(seen) AS seen_any, MAX(seen AND class = 'ok') AS seen_ok,
                   MAX(seen AND leak) AS leak_any, MAX(seen AND class = 'ok' AND leak) AS leak_ok,
                   SUM(seen) AS n_seen, SUM(seen AND leak) AS n_leak, SUM(seen AND class = 'ok') AS n_seen_ok, SUM(seen AND class = 'ok' AND leak) AS n_leak_ok
            FROM aj WHERE in_win = 1 AND cand_kind = 'proxy' AND proto = 'forward' AND dst = 'judge_http' GROUP BY cand""")
    db.x("CREATE INDEX temp.lit_pl_c ON lit_pl(cand)")


def build_intervals(db):
    """TEMP 表 lit_iv：每个 (来源, 标签, 条目) 的在榜区间 [s, e)，e 为 NULL 表示观察结束时仍在榜。见 DEFINITIONS“在榜（当天）”。
    返回区间的来源说明。"""
    if db.has_table("list_event") and db.scalar("SELECT COUNT(*) FROM list_event") > 0:
        db.x("CREATE TEMP TABLE lit_base AS SELECT DISTINCT src, label, ts_epoch FROM list_event WHERE COALESCE(base, 0) = 1")
        db.x("CREATE INDEX temp.lit_base_i ON lit_base(src, label, ts_epoch)")
        # 区间开始：add 事件，且前一个事件是 del 或没有；或者前一个 add 与本次之间有一次该文件的首次快照（那时它不在榜，所以是重新上榜）
        db.x("""CREATE TEMP TABLE lit_iv AS
                SELECT e.src, e.label, e.cand, e.prefix24, e.ts_epoch AS s,
                       (SELECT MIN(d.ts_epoch) FROM list_event d
                         WHERE d.cand = e.cand AND d.src = e.src AND d.label = e.label AND d.event = 'del' AND d.ts_epoch > e.ts_epoch) AS e_del,
                       (SELECT MIN(b.ts_epoch) FROM lit_base b
                         WHERE b.src = e.src AND b.label = e.label AND b.ts_epoch > e.ts_epoch
                           AND NOT EXISTS (SELECT 1 FROM list_event x WHERE x.cand = e.cand AND x.src = e.src AND x.label = e.label
                                                                        AND x.event = 'add' AND x.ts_epoch = b.ts_epoch)) AS e_base
                FROM (SELECT src, label, cand, prefix24, ts_epoch, event,
                             LAG(event) OVER (PARTITION BY src, label, cand ORDER BY ts_epoch, rid) AS prev,
                             LAG(ts_epoch) OVER (PARTITION BY src, label, cand ORDER BY ts_epoch, rid) AS prev_ts
                      FROM list_event) e
                WHERE e.event = 'add'
                  AND (e.prev IS NULL OR e.prev = 'del'
                       OR EXISTS (SELECT 1 FROM lit_base b WHERE b.src = e.src AND b.label = e.label
                                                             AND b.ts_epoch > e.prev_ts AND b.ts_epoch < e.ts_epoch))""")
        db.x("ALTER TABLE lit_iv ADD COLUMN e REAL")
        db.x("UPDATE lit_iv SET e = MIN(COALESCE(e_del, 1e18), COALESCE(e_base, 1e18))")
        db.x("UPDATE lit_iv SET e = NULL WHERE e >= 1e17")
        source = "list_event 的加减事件（首次快照里没出现的当作那时下榜）"
    elif db.has_table("cands"):
        db.x("""CREATE TEMP TABLE lit_iv AS
                SELECT NULL AS src, NULL AS label, key AS cand, prefix24, first_seen_epoch AS s, NULL AS e_del, NULL AS e_base, delisted_at_epoch AS e
                FROM cands WHERE COALESCE("group", 0) = 0 AND first_seen_epoch IS NOT NULL""")
        source = "cands 的 first_seen / delisted_at（没有 list_event；结束时刻的快照，近似）"
    else:
        db.x("CREATE TEMP TABLE lit_iv (src TEXT, label TEXT, cand TEXT, prefix24 TEXT, s REAL, e_del REAL, e_base REAL, e REAL)")
        source = "没有 list_event 也没有 cands，算不出在榜区间"
    db.x("CREATE INDEX temp.lit_iv_c ON lit_iv(cand)")
    db.x("CREATE INDEX temp.lit_iv_s ON lit_iv(s)")
    return source


def nd(alias, exclude_dense):
    """“去掉密集 /24”的过滤条件。"""
    return (" AND NOT EXISTS (SELECT 1 FROM dense24 d WHERE d.prefix24 = %s.prefix24)" % alias) if exclude_dense else ""


GROUPS = (("regular", "常规列表（group=0）", 0), ("aggregator_sample", "聚合器抽样（group=1）", 1))


def gf(alias, grp):
    """按候选来源过滤（lit_pool.grp）；grp 为 None 时不过滤。见 DEFINITIONS“候选来源”。"""
    if grp is None:
        return ""
    return " AND EXISTS (SELECT 1 FROM lit_pool g WHERE g.cand = %s.cand AND g.grp = %d)" % (alias, int(grp))


# ---------------------------------------------------------------- 分母

K_N_ABORTED = "其中有非 canceled 尝试、但没有非 aborted 探访的候选（停机时在途的探访，结果不作数；不进按探访定义的比例的分子和分母）"
K_N_TRIAL = "只在试运行里出现过的候选（正式起点前有 visit / att、之后没有、也不在 cands 里；不进候选池）"


def denominators(db, fs, pool_info, iv_source):
    out = {}
    r = db.one("SELECT COUNT(*), SUM(grp = 0), SUM(grp = 1), SUM(visited), SUM(grp = 0 AND visited), SUM(grp = 1 AND visited), SUM(in_state), SUM(httpish = 1) FROM lit_pool")
    out["候选池里的代理候选（cands ∪ visit ∪ att）"] = int(r[0] or 0)
    out["其中常规列表（group=0）"] = int(r[1] or 0)
    out["其中聚合器抽样（group=1）"] = int(r[2] or 0)
    out["其中正式起点后探访过"] = int(r[3] or 0)
    out["其中常规列表且探访过"] = int(r[4] or 0)
    out["其中聚合器抽样且探访过"] = int(r[5] or 0)
    out["其中在状态文件 cands 里"] = int(r[6] or 0)
    out["其中标签含 http/https/connect"] = int(r[7] or 0)
    nv = db.one("SELECT COUNT(*), COUNT(DISTINCT prefix24) FROM lit_pool WHERE visited = 0")
    out["从没探访过的候选（不进任何比例的分母）"] = {"条目": int(nv[0] or 0), "所在 /24": int(nv[1] or 0)}
    ab = db.one("""SELECT COUNT(*), COUNT(DISTINCT a.prefix24) FROM lit_pa a
                   WHERE a.cand NOT IN (SELECT cand FROM lit_pool WHERE visited = 1)""")
    out[K_N_ABORTED] = {"条目": int(ab[0] or 0), "所在 /24": int(ab[1] or 0)}
    out[K_N_TRIAL] = pool_info.get("_trial_only")
    out["在榜区间的来源"] = iv_source
    out["在榜区间数（lit_iv）"] = int(db.scalar("SELECT COUNT(*) FROM lit_iv") or 0)
    out["在榜过的条目（list_event 里出现过的）"] = int(db.scalar("SELECT COUNT(DISTINCT cand) FROM lit_iv") or 0)
    out["在榜过但不在候选池的条目（被排除：judge 自己的地址、私网、知名端口、退出名单）"] = int(db.scalar(
        "SELECT COUNT(DISTINCT cand) FROM lit_iv WHERE cand NOT IN (SELECT cand FROM lit_pool)") or 0)
    if db.has_table("stat_pool"):
        last = db.scalar("SELECT MAX(ts_epoch) FROM stat_pool")
        if last is not None:
            out["最后一条运行状况里被排除的条目数（stat_pool.skipped_*）"] = db.counts(
                "SELECT key, value FROM stat_pool WHERE ts_epoch = ? AND key LIKE 'skipped_%'", (last,))
    out["正式起点后的代理尝试（非 canceled）"] = int(db.scalar("SELECT COALESCE(SUM(n_att), 0) FROM lit_pa") or 0)
    out["到达 HTTP 阶段并带 nonce、目的地 judge 的代理尝试（aj，正式起点后）"] = int(db.scalar(
        "SELECT COUNT(*) FROM aj WHERE in_win = 1 AND cand_kind = 'proxy'") or 0)
    out["其中 judge 收到"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE in_win = 1 AND cand_kind = 'proxy' AND seen = 1") or 0)
    out["收到状态码的明文尝试（pc，代理，dst=judge_http，正式起点后）"] = int(db.scalar(
        "SELECT COUNT(*) FROM pc WHERE in_win = 1 AND cand_kind = 'proxy' AND dst = 'judge_http'") or 0)
    out["候选密集的 /24 个数"] = int(db.scalar("SELECT COUNT(*) FROM dense24") or 0)
    out["候选密集的 /24 里的候选数"] = int(db.scalar("SELECT COALESCE(SUM(n), 0) FROM dense24") or 0)
    out["探测器自己的地址个数（self_ips）"] = pool_info.get("self_ips_count")
    return out


# ---------------------------------------------------------------- Mani 等（ACSAC 2018）

R_RESP_ATT = "有回应 / 当天有尝试（PROTOCOL 1.2：没探访过的不进分母；按尝试时刻分天）"
R_OK_ATT = "可用 / 当天有尝试（按尝试时刻分天）"


def mani_responsive_daily(db, fs, end, exclude_dense, intr=()):
    """每个测量日：在榜条目数、其中进入候选池 / 当天有尝试 / 当天连得上 / 当天有协议回应 / 当天可用，以及几种分母下的比例；按完整测量日取中位数。
    分子（连得上 / 有回应 / 可用）和“当天有尝试”都按尝试时刻分天（lit_pd），并只算正式起点后探访过的候选（lit_pool.visited=1，
    summary.go finish() 跳过 visits==0 的候选），所以分子是这个分母的子集。“当天探访过（按 visit 记录时刻）”只作参考：
    visit 记录在探访结束时写（prober.go VisitRec），跨过 24 小时边界的探访会落到后一天。intr 是正式起点后的中断 [(开始, 结束)]。"""
    days = []
    k = 0
    while fs + k * DAY_S < end:
        ws = fs + k * DAY_S
        we = min(ws + DAY_S, end)
        days.append((k, ws, we, (we - ws) >= DAY_S - 1))
        k += 1
    f_iv = nd("i", exclude_dense)
    rows = []
    for k, ws, we, complete in days:
        r = db.one("""SELECT COUNT(DISTINCT i.cand),
                             COUNT(DISTINCT CASE WHEN p.cand IS NOT NULL THEN i.cand END),
                             COUNT(DISTINCT CASE WHEN v.cand IS NOT NULL THEN i.cand END),
                             COUNT(DISTINCT CASE WHEN d.n_att > 0 THEN i.cand END),
                             COUNT(DISTINCT CASE WHEN d.n_att > 0 AND p.visited = 1 THEN i.cand END),
                             COUNT(DISTINCT CASE WHEN d.tcp AND p.visited = 1 THEN i.cand END),
                             COUNT(DISTINCT CASE WHEN d.responsive AND p.visited = 1 THEN i.cand END),
                             COUNT(DISTINCT CASE WHEN d.ok AND p.visited = 1 THEN i.cand END)
                      FROM lit_iv i
                      LEFT JOIN lit_pool p ON p.cand = i.cand
                      LEFT JOIN lit_pv v ON v.cand = i.cand AND v.day = ?
                      LEFT JOIN lit_pd d ON d.cand = i.cand AND d.day = ?
                      WHERE i.s < ? AND COALESCE(i.e, 1e18) > ?""" + f_iv, (k, k, we, ws))
        listed, in_pool, visited, attempted_any, attempted, tcp, resp, ok = [int(v or 0) for v in r]
        gap = sum(max(0.0, min(e, we) - max(b, ws)) for b, e in intr)
        rows.append({
            "测量日": k, "起（UTC）": iso_minute(ws), "止（UTC）": iso_minute(we), "小时": round((we - ws) / 3600.0, 2), "完整": complete,
            "中断分钟数": round(gap / 60.0, 2),
            "在榜条目": listed, "其中进入候选池": in_pool,
            "其中当天有尝试（限探访过的候选）": attempted,
            "其中当天有尝试（含只有 aborted 探访的候选，参考）": attempted_any,
            "其中当天探访过（按 visit 记录时刻，参考）": visited,
            "当天连得上": tcp, "当天有协议回应": resp, "当天可用": ok,
            "有回应 / 在榜（Mani 等的口径）": ratio(resp, listed),
            "有回应 / 进入候选池": ratio(resp, in_pool),
            R_RESP_ATT: ratio(resp, attempted),
            "可用 / 在榜": ratio(ok, listed),
            R_OK_ATT: ratio(ok, attempted),
        })
    basis = [r for r in rows if r["完整"]] or rows
    med = {
        "取中位数的测量日数": len(basis), "只用完整测量日": any(r["完整"] for r in rows),
        "这些测量日的中断分钟数": [r["中断分钟数"] for r in basis],
        "在榜条目": median([r["在榜条目"] for r in basis]),
        "当天有协议回应": median([r["当天有协议回应"] for r in basis]),
        "有回应 / 在榜（%）": median([r["有回应 / 在榜（Mani 等的口径）"]["pct"] for r in basis]),
        "有回应 / 进入候选池（%）": median([r["有回应 / 进入候选池"]["pct"] for r in basis]),
        "有回应 / 当天有尝试（%）": median([r[R_RESP_ATT]["pct"] for r in basis]),
        "可用 / 在榜（%）": median([r["可用 / 在榜"]["pct"] for r in basis]),
        "可用 / 当天有尝试（%）": median([r[R_OK_ATT]["pct"] for r in basis]),
    }
    return item(
        "每天有回应的代理数 / 当天列表里的代理数，取各天的中位数（Mani 等：responsive = 至少连上一次并取回内容，含意外内容；我们的“有协议回应”还算拒绝和要求认证，比原文宽）",
        {"按测量日": rows, "中位数": med},
        "“每天”是从正式起点起算的 24 小时窗口（72 小时 = 3 天，中位数只取完整的天）；Mani 等测了 50 天、每天一次；“在榜”按 list_event 的加减事件逐 10 分钟推算，Mani 等按每天抓一次的列表；"
        "连不上的条目我们 30 分钟起加倍、最长 6 小时复测一次，当天在榜但没轮到探访的条目算在“在榜”分母、不算在分子（Mani 等每天测每个条目一次）；"
        "被我们排除的条目（私网、judge 自己、知名端口）在 Mani 等的分母里、不在我们的候选池里，所以另给“进入候选池”和“当天有尝试”两个分母；"
        "探测器停机的时段（“中断分钟数”）里没有尝试，那天的比例会偏低。"
        "原文的 responsive 是至少连上一次并取回内容（含意外内容）；我们的“有协议回应”还算 SOCKS/CONNECT 的拒绝和要求认证，不取回内容也算，比原文宽；"
        "所以另给要求内容正确的“可用 / 在榜”，比原文窄。" + DIFF_COMMON,
    )


R_FWD_MIS = "正文不符的代理 / 能转发的代理（与 PROTOCOL 预期范围对账）"
R_FWD_PARTIAL = "局部改动的代理 / 能转发的代理（PROTOCOL 预期范围“其中属于局部改动的”）"


def mani_html(db, exclude_dense):
    """明文 HTML 内容不符的请求比例，及其中局部改动（有害的上界候选）的比例。按请求为主，另给按代理；
    按代理另给 PROTOCOL 预期范围的口径“正文不符的代理 / 能转发的代理”（分母同 mani_leak 的主口径，judge 收到过它转发的请求）。
    含聚合器抽样，另按候选来源分组（DEFINITIONS“候选来源”）。"""
    out = {}
    for key, desc, cond, jcond in (("forward", "仅 HTTP 转发（proto=forward，最接近 Mani 等的 HTTP 代理）；含聚合器抽样", "p.proto = 'forward'", "j.proto = 'forward'"),
                                   ("all_plain", "全部明文（含 SOCKS / CONNECT 隧道里的明文 HTTP）；含聚合器抽样", "1 = 1", "1 = 1")):

        def calc(grp):
            base = ("FROM pc p WHERE p.in_win = 1 AND p.cand_kind = 'proxy' AND p.dst = 'judge_http' AND p.kind = 'h' AND " + cond
                    + nd("p", exclude_dense) + gf("p", grp))
            # 能转发的代理：judge 收到过它到明文端口的请求（forward 范围只看 HTTP 转发，与 lit_pl.seen_any 相同；不限载荷和 class）
            fwd_sql = ("SELECT j.cand FROM aj j WHERE j.in_win = 1 AND j.cand_kind = 'proxy' AND j.dst = 'judge_http' AND j.seen = 1 AND "
                       + jcond + nd("j", exclude_dense) + gf("j", grp))
            n200 = int(db.scalar("SELECT COUNT(*) " + base + " AND p.http_code = 200") or 0)
            n_any = int(db.scalar("SELECT COUNT(*) " + base) or 0)
            by = db.counts("SELECT p.body_change, COUNT(*) " + base + " AND p.http_class = 'http_body_mismatch' GROUP BY 1")
            cb = db.counts("SELECT p.body_change, COUNT(DISTINCT p.cand) " + base + " AND p.http_class = 'http_body_mismatch' GROUP BY 1")
            c200 = int(db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_code = 200") or 0)
            cmis = int(db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_class = 'http_body_mismatch'") or 0)
            n_fwd = int(db.scalar("SELECT COUNT(DISTINCT cand) FROM (%s)" % fwd_sql) or 0)
            cmis_f = int(db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.http_class = 'http_body_mismatch' AND p.cand IN (%s)" % fwd_sql) or 0)
            cpart_f = int(db.scalar("SELECT COUNT(DISTINCT p.cand) " + base + " AND p.body_change = '%s' AND p.cand IN (%s)" % (K_PARTIAL, fwd_sql)) or 0)
            return {"n200": n200, "n_any": n_any, "by": by, "cb": cb, "c200": c200, "cmis": cmis, "n_fwd": n_fwd, "cmis_f": cmis_f, "cpart_f": cpart_f}

        a = calc(None)
        mis = sum(a["by"].values())
        partial = a["by"].get(K_PARTIAL, 0)
        groups = {}
        for gname, gdesc, g in GROUPS:
            b = calc(g)
            gmis = sum(b["by"].values())
            groups[gname] = {"口径": gdesc,
                             "正文不符 / HTML 200（按请求）": ratio(gmis, b["n200"]),
                             "其中局部改动 / 不符（按请求）": ratio(b["by"].get(K_PARTIAL, 0), gmis),
                             "能转发的代理": b["n_fwd"],
                             R_FWD_MIS: ratio(b["cmis_f"], b["n_fwd"]),
                             R_FWD_PARTIAL: ratio(b["cpart_f"], b["n_fwd"])}
        out[key] = {
            "口径": desc,
            "按请求": {
                "HTML 请求（状态 200）": a["n200"], "HTML 请求（收到任何状态码）": a["n_any"],
                "正文不符 / HTML 200": ratio(mis, a["n200"]),
                "正文不符 / 收到任何状态码": ratio(mis, a["n_any"]),
                "各类 / HTML 200": {k: ratio(a["by"].get(k, 0), a["n200"]) for k in BODY_KINDS},
                "其中局部改动（有害的上界候选）/ 不符": ratio(partial, mis),
                "其中截断 + 整页替换（多半无害）/ 不符": ratio(mis - partial, mis),
                "局部改动 / HTML 200（对应 Mani 等“恶意占全部 HTML 请求”）": ratio(partial, a["n200"]),
            },
            "按代理": {
                "能转发的代理（judge 收到过它转发的请求，PROTOCOL 预期范围的分母）": a["n_fwd"],
                R_FWD_MIS: ratio(a["cmis_f"], a["n_fwd"]),
                R_FWD_PARTIAL: ratio(a["cpart_f"], a["n_fwd"]),
                "正文不符、但 judge 从没收到它转发请求的代理（伪造或返回缓存，不在上面的分母里）": a["cmis"] - a["cmis_f"],
                "取回过 HTML（200）的代理": a["c200"],
                "正文不符的代理 / 取回过的": ratio(a["cmis"], a["c200"]),
                "各类（一个代理可属多类）/ 取回过的": {k: ratio(a["cb"].get(k, 0), a["c200"]) for k in BODY_KINDS},
                "局部改动的代理 / 不符的代理": ratio(a["cb"].get(K_PARTIAL, 0), a["cmis"]),
            },
            "按候选来源": groups,
        }
    return item(
        "明文 HTML 请求里内容与直连不符的比例；其中无害（错误页等）与恶意的划分，恶意的占全部 HTML 请求的比例（Mani 等人工分类）",
        out,
        "Mani 等按请求计、对真实站点的页面与直连结果做差异比较并人工分类无害 / 恶意；我们对固定的诱饵页按 SHA-256 判不符，"
        "按行相似度分成截断 / 局部改动 / 整页替换，没有人工判定——局部改动包含注入、改广告 ID、剥离 https，也可能包含无害的压缩或改写；"
        "截断多半是传输问题，整页替换多半是错误页或门户页。我们只对 HTTP 转发代理拿 HTML 载荷，每次探访一次、附加测试每 6 小时一次。" + DIFF_COMMON,
    )


D_CERT = "隧道曾可用或遇到过中间人的代理（PROTOCOL 预期范围“可用隧道代理”的分母）"
D_CERT_HS = "隧道建立过的代理（hs_ok=1，第二口径）"
R_CERT = "中间人候选 / 隧道曾可用或遇到过中间人（与 PROTOCOL 预期范围对账）"
R_CERT_HS = "中间人候选 / 隧道建立过的代理（第二口径）"


def mani_cert(db, exclude_dense, layer_names):
    """支持 HTTPS（可用隧道代理）的代理里证书被替换的比例：总数 + 三层细分（来自 mcl）。另给全部隧道协议的范围。
    主分母是“隧道曾可用或遇到过中间人”（PROTOCOL 预期范围表“证书被替换的代理占可用隧道代理”，取的解释见 DEFINITIONS“支持 HTTPS”），
    hs_ok=1 的作第二口径。含聚合器抽样，另按候选来源分组。"""
    out = {}
    scopes = (("connect", "仅 HTTP CONNECT；含聚合器抽样（比全部隧道协议窄：Mani 等经 CONNECT 和 SOCKS 两种代理测 HTTPS，与原文可比的是 tunnel 一组）", "connect_tunnel", "connect_ok", "connect_mitm", "m.proto = 'connect'"),
              ("tunnel", "全部隧道协议（socks5 / socks4 / connect）；含聚合器抽样。Mani 等经 CONNECT 和 SOCKS 两种代理测 HTTPS，与原文 1.06% 对账用这一组", "tunnel_hs", "tunnel_ok", "tunnel_mitm", "m.proto IN (%s)" % sql_in(TUNNEL_PROTOS)))
    layer_order = [layer_names["judge"], layer_names["other"], layer_names["unknown"], layer_names["noev"], layer_names["unchecked"], L_UNAVAIL]
    sev = {name: i for i, name in enumerate([layer_names["judge"], layer_names["unknown"], layer_names["other"], layer_names["noev"], layer_names["unchecked"], L_UNAVAIL])}
    for key, desc, c_hs, c_ok, c_mitm, m_cond in scopes:

        def dens(grp):
            r = db.one("SELECT SUM(a.%s), SUM(a.%s), SUM(a.%s), SUM(a.%s OR a.%s) FROM lit_pa a WHERE 1 = 1 %s"
                       % (c_hs, c_ok, c_mitm, c_ok, c_mitm, nd("a", exclude_dense) + gf("a", grp)))
            return [int(v or 0) for v in r]

        den_a, c_okn, num, den_b = dens(None)
        mb = "FROM mcl m WHERE m.cand_kind = 'proxy' AND m.dst = 'judge_tls' AND " + m_cond + nd("m", exclude_dense)
        tot_c = db.scalar("SELECT COUNT(DISTINCT m.cand) " + mb)
        by_layer = db.q("SELECT m.layer, COUNT(*), COUNT(DISTINCT m.cand) " + mb + " GROUP BY m.layer")
        bl = {L: (int(a), int(c)) for L, a, c in by_layer}
        case = "CASE m.layer " + " ".join("WHEN '%s' THEN %d" % (L, s) for L, s in sev.items()) + " ELSE 9 END"
        worst = db.q("SELECT sev, COUNT(*) FROM (SELECT m.cand, MIN(%s) AS sev %s GROUP BY m.cand) GROUP BY sev" % (case, mb))
        sev_name = {v: k for k, v in sev.items()}
        wb = {sev_name.get(s, "?"): int(c) for s, c in worst}
        layers = {}
        for L in layer_order:
            a, c = bl.get(L, (0, 0))
            layers[L] = {"尝试": a, "候选（不互斥）": c, "候选（按候选取最严重一层）": wb.get(L, 0),
                         "候选（最严重一层）/ 隧道曾可用或遇到过中间人（与 PROTOCOL 预期范围对账）": ratio(wb.get(L, 0), den_b),
                         "候选（最严重一层）/ 隧道建立过的代理（第二口径）": ratio(wb.get(L, 0), den_a)}
        groups = {}
        for gname, gdesc, g in GROUPS:
            ga, _, gn, gb = dens(g)
            groups[gname] = {"口径": gdesc, D_CERT: gb, "证书被替换（中间人，总数）的代理": gn, R_CERT: ratio(gn, gb), R_CERT_HS: ratio(gn, ga)}
        out[key] = {
            "口径": desc,
            D_CERT: den_b,
            "其中隧道曾可用的代理（class=ok）": c_okn,
            D_CERT_HS: den_a,
            "证书被替换（中间人，总数）的代理": num,
            R_CERT: ratio(num, den_b),
            R_CERT_HS: ratio(num, den_a),
            "仪器核对：mcl 里的中间人候选数（应等于上面的总数）": int(tot_c or 0),
            "三层细分": layers,
            "按候选来源": groups,
        }
    return item(
        "支持 HTTPS 的代理里，经代理拿到的证书与直连不同的比例",
        out,
        "Mani 等比较经代理与直连拿到的证书；我们校验证书链并要求叶子公钥是 judge 的（tls_cert_invalid 即“不是 judge 的证书”），总数与他们的判据最接近；"
        "三层细分是 PROTOCOL 1.2 看过数据后加的：只有“冒充 judge”是按我们要访问的主机名出示了证书的确凿中间人，“被送到别的网站”和“去向不明”是连接没到 judge。"
        "“支持 HTTPS”我们的主分母取隧道曾可用或遇到过中间人的代理（PROTOCOL 预期范围表的“可用隧道代理”），另给 CONNECT 握手通过过（hs_ok=1）的第二口径；"
        "Mani 等的分母（支持 HTTPS 的代理）的判据待核对原文。对账用哪一层待定，三层和总数都报告。" + DIFF_COMMON,
    )


def mani_leak(db, exclude_dense):
    """请求头带出客户端地址的代理占能转发代理的比例（derive.go 的 transparent）。含聚合器抽样，另按候选来源分组。"""

    def calc(grp):
        f = nd("a", exclude_dense) + ("" if grp is None else " AND a.grp = %d" % int(grp))
        r = db.one("""SELECT SUM(l.seen_any), SUM(l.leak_any), SUM(l.seen_ok), SUM(l.leak_ok), SUM(l.n_seen), SUM(l.n_leak), SUM(l.n_seen_ok), SUM(l.n_leak_ok)
                      FROM lit_pl l JOIN lit_pool a ON a.cand = l.cand WHERE 1 = 1 %s""" % f)
        return [int(v or 0) for v in r]

    seen_any, leak_any, seen_ok, leak_ok, n_seen, n_leak, n_seen_ok, n_leak_ok = calc(None)
    groups = {}
    for gname, gdesc, g in GROUPS:
        s_any, l_any = calc(g)[:2]
        groups[gname] = {"口径": gdesc, "能转发的代理": s_any, "带出客户端地址的代理": ratio(l_any, s_any)}
    ours = {
        "口径": "HTTP 转发（proto=forward）到 judge 明文端口、被 judge 收到的请求；含聚合器抽样",
        "按代理（主口径：judge 收到过它转发的请求，不限 class；与 PROTOCOL 预期范围对账）": {"能转发的代理": seen_any, "带出客户端地址的代理": ratio(leak_any, seen_any)},
        "按代理（summary.go Anon 的口径：class=ok 且 judge 收到）": {"能转发的代理": seen_ok, "带出客户端地址的代理": ratio(leak_ok, seen_ok)},
        "按请求（judge 收到的 HTTP 转发请求）": {"请求": n_seen, "带出客户端地址": ratio(n_leak, n_seen)},
        "按请求（class=ok 且 judge 收到）": {"请求": n_seen_ok, "带出客户端地址": ratio(n_leak_ok, n_seen_ok)},
        "按候选来源（按代理，主口径）": groups,
    }
    return item(
        "请求头里泄露客户端 IP 的代理占能转发请求的代理的比例",
        ours,
        "判定都以服务端收到的请求头为准（我们是 judge 记下的原始头；探测器与 judge 同机，所以找的是 judge 的公网地址）；"
        "“能转发”我们取 judge 收到过该代理转发的明文请求（任何正文），Mani 等的分母（能转发请求的代理）的判据待核对原文。只看 HTTP 转发，不看 CONNECT 隧道（隧道里请求头被 TLS 保护）。" + DIFF_COMMON,
    )


GZIP_MAGIC = b"\x1f\x8b"


K_NOEV = "无证据（探测器没拿到 / 证据库超限没存 / 文件缺失或读不了）"
SSL_SCOPES = (("forward", "仅 HTTP 转发（proto=forward，与内容被改的主口径相同）；含聚合器抽样"),
              ("all_plain", "全部明文（含 SOCKS / CONNECT 隧道里的明文 HTTP）；含聚合器抽样"))


def _ssl_acc(desc, n_mis):
    return {"口径": desc, "模板里 https://<judge> 出现的次数": HTML_HTTPS_LINKS,
            "说明": "PROTOCOL 和 payload.go 的注释说“8 个 https 链接”（6 个导航 <a>、表单 action、iframe src）；模板里另有 <link> 样式表和 <script src> 两处，共 10 处，这里按 10 处计",
            "HTML 不符的请求": n_mis, "有证据正文可读": 0, K_NOEV: 0,
            "至少一个 https 链接被改成 http 的请求": 0, "其中全部链接都被改": 0, "被改的链接总数": 0, "涉及的代理": 0,
            "涉及的代理（按候选来源）": {g[0]: 0 for g in GROUPS},
            SSL_ECHO: 0, SSL_PREFIX: 0,
            "按正文分类": {}, "被改链接数分布（局部改动的请求数）": {}, "_cands": set()}


SSL_ECHO = "整页替换的正文里出现 http://<judge>/ 的请求（多半是回显请求地址，不算剥离）"
SSL_PREFIX = "局部改动里多出 http://<judge>/、但 https 链接一个没少的请求（加前缀改写，不算剥离）"


def ssl_classify(bc, n_https, n_http):
    """一份 HTML 不符正文：(类别, 被改的链接数)。类别：strip（https 链接被改成 http）/ echo / prefix / none。
    被改的链接数 = min(http 次数, max(0, 模板 https 次数 − 正文 https 次数))，只在局部改动里算。"""
    stripped = min(n_http, max(0, HTML_HTTPS_LINKS - n_https))
    if n_http <= 0:
        return "none", 0
    if bc == K_PARTIAL:
        return ("strip", stripped) if stripped > 0 else ("prefix", 0)
    if bc == K_REPLACED:
        return "echo", 0
    return "none", 0


def mani_sslstrip(db, data_dir):
    """诱饵页里的 https 链接被改成 http 的次数：从 evidence/ 里存下的 HTML 不符正文数。judge 主机名只在库内取、不输出。
    一次游标遍历同时算出“全部 / 去掉密集 /24”×“forward / 全部明文”四组，同一个证据文件只读一次（cache 按证据哈希，四组共用）。
    返回 {"all": item, "excluding_dense": item}。"""
    hosts = []
    if db.has_table("self_names"):
        hosts = [r[0] for r in db.q("SELECT DISTINCT name FROM self_names WHERE source = 'start.judge_host' AND name IS NOT NULL AND name != ''")]
        if not hosts:
            hosts = [r[0] for r in db.q("SELECT DISTINCT name FROM self_names WHERE name IS NOT NULL AND name != ''")]
    where = ("WHERE p.in_win = 1 AND p.cand_kind = 'proxy' AND p.dst = 'judge_http' AND p.kind = 'h' AND p.http_class = 'http_body_mismatch'")
    counts_sql = ("SELECT SUM(p.proto = 'forward'), COUNT(*), SUM(p.proto = 'forward' AND d.prefix24 IS NULL), SUM(d.prefix24 IS NULL) "
                  "FROM pc p LEFT JOIN dense24 d ON d.prefix24 = p.prefix24 " + where)
    nf, na, nfx, nax = [int(v or 0) for v in db.one(counts_sql)]
    accs = {("all", "forward"): _ssl_acc(SSL_SCOPES[0][1], nf), ("all", "all_plain"): _ssl_acc(SSL_SCOPES[1][1], na),
            ("excluding_dense", "forward"): _ssl_acc(SSL_SCOPES[0][1], nfx), ("excluding_dense", "all_plain"): _ssl_acc(SSL_SCOPES[1][1], nax)}
    title = "把页面里的 https 链接改成 http 的代理数（Mani 等报告的是有没有发现）"
    diff = ("我们的诱饵页有指向 judge 自己的 https 链接，在存下的不符正文里数 https 少了几个、http://<judge 主机名>/ 多了几个，只在局部改动里算；"
            "整页替换里的回显和加前缀的改写单列、不算。证据库有上限（每个代理 12 份、总共 1 GB），"
            "没存下的请求判不了，这一项只会让计数偏少；反过来，同一份局部改动的正文若既删了 https 链接、又在别处加了 http://<judge 主机名>/，"
            "删掉的会被算成被改，会让计数偏多，所以不是严格的下限（“被改链接数分布”可以核对）。Mani 等看的是真实站点页面里的链接。" + DIFF_COMMON)

    def finish(note=None, extra_diff=""):
        out = {}
        for variant in ("all", "excluding_dense"):
            ours = {}
            for scope, _ in SSL_SCOPES:
                acc = accs[(variant, scope)]
                cs = acc.pop("_cands")
                acc["涉及的代理"] = len(cs)
                acc["有链接被改的请求 / 有证据可读的不符请求"] = ratio(acc["至少一个 https 链接被改成 http 的请求"], acc["有证据正文可读"])
                acc["被改链接数分布（局部改动的请求数）"] = dict(sorted(acc["被改链接数分布（局部改动的请求数）"].items(), key=lambda kv: int(kv[0])))
                if note:
                    acc["note"] = note
                ours[scope] = acc
            out[variant] = item(title, ours, extra_diff + diff)
        return out

    if not hosts:
        return finish("库里没有 judge 的主机名（self_names），无法在正文里找 http://<judge>/，这项算不出")
    ev_dir = os.path.join(data_dir, "evidence") if data_dir else None
    if not ev_dir or not os.path.isdir(ev_dir):
        for acc in accs.values():
            acc[K_NOEV] = acc["HTML 不符的请求"]
        return finish("数据目录不可用（--data 或 meta.data_dir 下没有 evidence/），只能报告不符的请求数", "证据目录不可用时无法判定。")
    has_ev_table = db.has_table("evidence")
    sql = ("SELECT p.cand, p.proto, p.body_change, a.http_ev, %s, g.grp, (d.prefix24 IS NOT NULL) "
           "FROM pc p JOIN att a ON a.rid = p.rid %s LEFT JOIN lit_pool g ON g.cand = p.cand LEFT JOIN dense24 d ON d.prefix24 = p.prefix24 "
           % ("e.path" if has_ev_table else "NULL", " LEFT JOIN evidence e ON e.hash = a.http_ev AND e.ext = 'body'" if has_ev_table else "")) + where
    needles_https = [("https://%s/" % h).lower().encode() for h in hosts]
    needles_http = [("http://%s/" % h).lower().encode() for h in hosts]
    cache = {}   # 证据哈希 → (https 次数, http 次数) 或 None；量级是不同证据文件的个数（证据库有总量上限）
    gname = {g: name for name, _, g in GROUPS}
    for cand, proto, bc, ev, path, grp, dense in db.con.execute(sql):   # 游标逐行，不 fetchall
        targets = [accs[("all", "all_plain")]]
        if proto == "forward":
            targets.append(accs[("all", "forward")])
        if not dense:
            targets.append(accs[("excluding_dense", "all_plain")])
            if proto == "forward":
                targets.append(accs[("excluding_dense", "forward")])
        counts = None
        if ev:
            if ev not in cache:
                fp = os.path.join(data_dir, path if path is not None else os.path.join("evidence", ev[:2], ev + ".body"))
                try:
                    with open(fp, "rb") as fh:
                        body = fh.read()
                    if body[:2] == GZIP_MAGIC:
                        try:
                            body = gzip.decompress(body)
                        except Exception:  # noqa: BLE001
                            pass
                    low = body.lower()
                    cache[ev] = (sum(low.count(n) for n in needles_https), sum(low.count(n) for n in needles_http))
                except OSError:
                    cache[ev] = None
            counts = cache[ev]
        for acc in targets:
            if counts is None:
                acc[K_NOEV] += 1
                continue
            acc["有证据正文可读"] += 1
            n_https, n_http = counts
            kind, stripped = ssl_classify(bc, n_https, n_http)
            b = acc["按正文分类"].setdefault(bc or "?", {"请求": 0, "有链接被改": 0, "含 http://<judge>/": 0})
            b["请求"] += 1
            if n_http > 0:
                b["含 http://<judge>/"] += 1
            if kind == "strip":
                acc["至少一个 https 链接被改成 http 的请求"] += 1
                acc["被改的链接总数"] += stripped
                b["有链接被改"] += 1
                if cand not in acc["_cands"]:
                    acc["_cands"].add(cand)
                    g = gname.get(grp)
                    if g:
                        acc["涉及的代理（按候选来源）"][g] += 1
                if stripped >= HTML_HTTPS_LINKS:
                    acc["其中全部链接都被改"] += 1
            elif kind == "echo":
                acc[SSL_ECHO] += 1
            elif kind == "prefix":
                acc[SSL_PREFIX] += 1
            if bc == K_PARTIAL:
                k = str(stripped)
                acc["被改链接数分布（局部改动的请求数）"][k] = acc["被改链接数分布（局部改动的请求数）"].get(k, 0) + 1
    return finish()


# ---------------------------------------------------------------- Tsirantonakis 等（NDSS 2018）

# 文献口径的分母（含从没探访过的条目）：违反 PROTOCOL 1.2“候选密集的地址段”的分母规则，是为了与文献对账的例外，键名里写明
L_ALL_ENTRIES = "/ 全部条目（文献口径；按 PROTOCOL 1.2 从没探访过的条目不进分母，这里是例外，仅供对账）"
L_ALL_CANDS = "/ 全部候选（文献口径；按 PROTOCOL 1.2 从没探访过的候选不进分母，这里是例外，仅供对账）"

def tsirantonakis(db, exclude_dense):
    """常规列表条目：TCP 连得上过、取回过测试页、改动了内容、其中局部改动。按全部条目和“标签含 http/https/connect”两个范围。"""
    out = {}
    for key, desc, cond in (("all", "常规列表的全部条目（group=0）", "a.grp = 0"),
                            ("httpish", "常规列表里标签含 http/https/connect 的条目（Tsirantonakis 等只测 HTTP 代理）", "a.grp = 0 AND a.httpish = 1")):
        # 分子只算探访过的候选（JOIN 条件里要求 a.visited = 1）：summary.go finish() 跳过 visits==0 的候选，见 DEFINITIONS“探访过”
        base = ("FROM lit_pool a LEFT JOIN lit_pa p ON p.cand = a.cand AND a.visited = 1 LEFT JOIN lit_pb b ON b.cand = a.cand AND a.visited = 1 WHERE "
                + cond + nd("a", exclude_dense))
        r = db.one("""SELECT COUNT(*), SUM(a.visited), SUM(COALESCE(p.tcp, 0)), SUM(COALESCE(p.responsive, 0)), SUM(COALESCE(p.ok, 0)),
                             SUM(COALESCE(b.fwd_h_200, 0)), SUM(COALESCE(b.fwd_h_mis, 0)), SUM(COALESCE(b.fwd_h_partial, 0)),
                             SUM(COALESCE(b.fwd_h_trunc, 0)), SUM(COALESCE(b.fwd_h_replaced, 0)),
                             SUM(COALESCE(p.plain_200, 0)), SUM(COALESCE(b.h_200, 0)), SUM(COALESCE(b.h_mis, 0)), SUM(COALESCE(b.h_partial, 0)),
                             SUM(a.visited = 0 AND a.cand IN (SELECT cand FROM lit_pa)) """ + base)
        n_all, n_vis, tcp, resp, ok, fetched, mis, partial, trunc, replaced, plain200, h200, hmis, hpartial, n_aborted_only = [int(v or 0) for v in r]
        out[key] = {
            "口径": desc,
            "条目（含从没探访过的）": n_all, "探访过的条目": n_vis, "从没探访过": n_all - n_vis,
            "从没探访过·其中有尝试、但探访都被中止（不进分子）": n_aborted_only,
            "TCP 连得上过": {"条目": tcp, "/ 探访过的": ratio(tcp, n_vis), L_ALL_ENTRIES: ratio(tcp, n_all)},
            "取回过测试页（HTTP 转发、HTML、200）": {"条目": fetched, "/ 探访过的": ratio(fetched, n_vis), L_ALL_ENTRIES: ratio(fetched, n_all),
                                          "/ TCP 连得上过": ratio(fetched, tcp)},
            "任一协议明文 200 过（参考）": plain200,
            "有协议回应过（参考）": resp, "曾通过端到端校验（参考）": ok,
            "改动了内容": {"代理": mis, "/ 取回过测试页": ratio(mis, fetched),
                      "各类（一个代理可属多类）": {K_TRUNC: trunc, K_PARTIAL: partial, K_REPLACED: replaced}},
            "其中局部改动（有害的上界候选）": {"代理": partial, "/ 取回过测试页": ratio(partial, fetched),
                               "/ 改动了内容": ratio(partial, mis)},
            "全部明文 HTML（含隧道内明文，参考）": {"取回过": h200, "改动了内容": ratio(hmis, h200), "其中局部改动": ratio(hpartial, h200)},
        }
    return item(
        "HTTP 代理里 TCP 可连的条目数；取回了测试页的条目数；其中改动了内容的代理数与占取回过测试页的比例，及属恶意或不受欢迎的代理数与比例",
        out,
        "Tsirantonakis 等两个月、每天约 22 次，用看起来真实的 honeysite，按 DOM 差异找改动、人工分恶意；我们 72 小时、固定诱饵页、按哈希判不符、"
        "按行相似度分类，“局部改动”不是恶意判定。他们的对象只有 HTTP 代理，所以另给“标签含 http/https/connect”的范围；"
        "我们的列表多数由维护者自动筛过，TCP 可连的比例应偏高。从没探访过的条目（候选密集的 /24 的限速结果）单独报告，不进“探访过的”分母；"
        "他们的分母是全部条目，所以另给“/ 全部条目（文献口径）”，那个分母违反 PROTOCOL 1.2 的分母规则，仅供对账。" + DIFF_COMMON,
    )


# ---------------------------------------------------------------- Mehanna 等（MADWeb 2024）

def mehanna(db, exclude_dense):
    """至少活跃过一次：曾通过端到端校验（主口径）与曾有协议回应（更宽）。按常规 / 聚合器抽样 / 全部，分母给全部候选与探访过的候选。"""
    out = {}
    for key, desc, cond in (("regular", "常规列表（group=0）", "a.grp = 0"), ("aggregator_sample", "聚合器抽样（group=1）", "a.grp = 1"), ("all", "全部候选", "1 = 1")):
        # 分子只算探访过的候选（JOIN 条件里要求 a.visited = 1），见 DEFINITIONS“探访过”
        base = "FROM lit_pool a LEFT JOIN lit_pa p ON p.cand = a.cand AND a.visited = 1 WHERE " + cond + nd("a", exclude_dense)
        r = db.one("SELECT COUNT(*), SUM(a.visited), SUM(COALESCE(p.ok, 0)), SUM(COALESCE(p.responsive, 0)), SUM(COALESCE(p.tcp, 0)), "
                   "SUM(a.visited = 0 AND a.cand IN (SELECT cand FROM lit_pa)) " + base)
        n_all, n_vis, ok, resp, tcp, n_aborted_only = [int(v or 0) for v in r]
        out[key] = {
            "口径": desc, "候选（含从没探访过的）": n_all, "探访过的候选": n_vis,
            "从没探访过·其中有尝试、但探访都被中止（不进分子）": n_aborted_only,
            "曾通过端到端校验（可用）": {"候选": ok, "/ 探访过的": ratio(ok, n_vis), L_ALL_CANDS: ratio(ok, n_all)},
            "曾有协议回应（更宽）": {"候选": resp, "/ 探访过的": ratio(resp, n_vis), L_ALL_CANDS: ratio(resp, n_all)},
            "曾连得上（参考）": {"候选": tcp, "/ 探访过的": ratio(tcp, n_vis), L_ALL_CANDS: ratio(tcp, n_all)},
        }
    extra = {}
    if db.has_table("cands"):
        # 状态文件自己的 ever_ok（整个运行期间，含试运行）作为交叉核对
        extra["状态文件 cands.ever_ok=1 的候选（整个运行期间，含试运行）"] = db.counts(
            'SELECT COALESCE("group", 0), SUM(COALESCE(ever_ok, 0)) FROM cands GROUP BY 1')
    return item(
        "收集到的代理里至少活跃过一次的比例（30 个月，每天测试）",
        {"ranges": out, "crosscheck": extra},
        "Mehanna 等 30 个月、每天一次，对象是多个来源汇总的全部代理；我们 72 小时、每 20 分钟到 6 小时一次，常规列表全测、聚合器只抽样 5,000 条；"
        "“活跃”我们取通过端到端校验（状态 200 + 正文哈希 + 金丝雀），另给“有协议回应”作上界。时间短得多，所以“至少一次”的比例应偏低；"
        "但列表多由维护者筛过，又会偏高。他们的分母是收集到的全部，所以另给“/ 全部候选（文献口径）”，那个分母含从没探访过的候选，"
        "违反 PROTOCOL 1.2 的分母规则，仅供对账。" + DIFF_COMMON,
    )


# ---------------------------------------------------------------- 与 summary.json 交叉核对

def crosscheck_summary(db, path, fs):
    """与 fieldtest 自带汇总比对。summary.go 不裁正式起点，所以这里按整个数据重算漏斗（seen / tcp / responsive / working），
    group 取最后一次非 aborted 探访的；findings 只核对与本模块有关的几项。只读 summary.json 的计数字段。"""
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    cmp = {}

    def put(key, want, got):
        cmp[key] = {"summary": want, "computed": got, "match": (want == got)}

    if db.has_table("visit"):
        db.x("DROP TABLE IF EXISTS lit_x_all")
        db.x("""CREATE TEMP TABLE lit_x_all AS
                SELECT cand, MAX(COALESCE(tcp_ok, 0) = 1) AS tcp, MAX(%s) AS responsive, MAX(class = 'ok' AND dst IN ('judge_http', 'judge_tls')) AS ok
                FROM att WHERE cand_kind = 'proxy' AND %s GROUP BY cand""" % (RESPONSIVE_SQL, NOT_CANCELED))
        rows = db.q("""SELECT g.grp, COUNT(*), SUM(COALESCE(x.tcp, 0)), SUM(COALESCE(x.responsive, 0)), SUM(COALESCE(x.ok, 0))
                       FROM (SELECT v.cand, (SELECT COALESCE("group", 0) FROM visit v2 WHERE v2.cand = v.cand AND COALESCE(v2.aborted, 0) = 0
                                              ORDER BY v2.ts_epoch DESC, v2.rid DESC LIMIT 1) AS grp
                             FROM visit v WHERE COALESCE(v.aborted, 0) = 0 GROUP BY v.cand) g
                       LEFT JOIN lit_x_all x ON x.cand = g.cand GROUP BY g.grp""")
        mine = {int(g): (int(n), int(t), int(r), int(o)) for g, n, t, r, o in rows}
        for grp, name in ((0, "regular"), (1, "aggregator_sample")):
            want = (s.get("funnel") or {}).get(name) or {}
            got = mine.get(grp, (0, 0, 0, 0))
            for i, k in enumerate(("seen", "tcp", "responsive", "working")):
                if k in want or got[i]:
                    put("funnel.%s.%s" % (name, k), want.get(k, 0), got[i])
    fd = s.get("findings") or {}
    F = {}
    F["请求头里带出了探测器的地址"] = db.one(
        "SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE cand_kind IN ('proxy', 'node') AND class = 'ok' AND seen = 1 AND leak = 1")
    for k in BODY_KINDS:
        F[k] = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM pc WHERE cand_kind IN ('proxy', 'node') AND body_change = ?", (k,))
    F["隧道里的证书不是 judge 的（中间人）"] = db.one(
        "SELECT COUNT(*), COUNT(DISTINCT cand) FROM att WHERE tls_class = 'tls_cert_invalid' AND proto != 'tlsproxy' AND cand_kind IN ('proxy', 'node') AND %s" % NOT_CANCELED)
    for name, got in F.items():
        want = fd.get(name)
        if want is None and (got[0] or 0) == 0:
            continue
        put("findings.%s.attempts" % name, want.get("attempts", 0) if want else 0, int(got[0] or 0))
        put("findings.%s.candidates" % name, want.get("candidates", 0) if want else 0, int(got[1] or 0))
    return {"summary_generated": s.get("generated"), "comparisons": cmp,
            "matched": sum(1 for v in cmp.values() if v["match"]), "total": len(cmp),
            "mismatches": sorted(k for k, v in cmp.items() if not v["match"]),
            "note": "按整个数据算（summary.go 不裁正式起点）；正式起点之前有试运行数据时，这里的数与主口径不同是正常的"}


# ---------------------------------------------------------------- 仪器检查

def ratio_violations(obj, path=""):
    """遍历结果，找出分子大于分母的比例（含 num / den / pct 三个键的对象）。返回路径列表。"""
    bad = []
    if isinstance(obj, dict):
        if set(obj.keys()) == {"num", "den", "pct"}:
            if (obj["num"] or 0) > (obj["den"] or 0):
                bad.append("%s：%s/%s" % (path, obj["num"], obj["den"]))
            return bad
        for k, v in obj.items():
            bad.extend(ratio_violations(v, path + "." + str(k) if path else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            bad.extend(ratio_violations(v, "%s[%d]" % (path, i)))
    return bad


def checks(db, res=None):
    out = {}
    if res is not None:
        bad = ratio_violations({k: v for k, v in res.items() if k not in ("checks", "crosscheck")})
        out["各比例的分子不大于分母（应为 0 个例外）"] = {"例外": len(bad), "路径": bad[:20]}
        for variant, ex in (("all", False), ("excluding_dense", True)):
            h = res["mani_2018"]["html_modified"][variant]["ours"]["forward"]["按代理"]["能转发的代理（judge 收到过它转发的请求，PROTOCOL 预期范围的分母）"]
            lk = res["mani_2018"]["client_ip_leak"][variant]["ours"]["按代理（主口径：judge 收到过它转发的请求，不限 class；与 PROTOCOL 预期范围对账）"]["能转发的代理"]
            out["内容被改与带出地址的“能转发的代理”是同一个分母（%s）" % variant] = {"内容被改（aj）": h, "带出地址（lit_pl）": lk, "一致": h == lk}
    out["lit_pa 的候选都在 lit_pool 里（应为 0 个例外）"] = int(db.scalar("SELECT COUNT(*) FROM lit_pa WHERE cand NOT IN (SELECT cand FROM lit_pool)") or 0)
    out["在榜区间结束早于开始（应为 0）"] = int(db.scalar("SELECT COUNT(*) FROM lit_iv WHERE e IS NOT NULL AND e < s") or 0)
    out["同一 (来源, 标签, 条目) 的在榜区间互相重叠（应为 0）"] = int(db.scalar(
        """SELECT COUNT(*) FROM lit_iv a JOIN lit_iv b ON a.src IS b.src AND a.label IS b.label AND a.cand = b.cand AND a.s < b.s
           WHERE COALESCE(a.e, 1e18) > b.s""") or 0)
    out["中间人尝试：lit_pa 与 mcl 的候选数一致（connect）"] = {
        "lit_pa": int(db.scalar("SELECT COALESCE(SUM(connect_mitm), 0) FROM lit_pa") or 0),
        "mcl": int(db.scalar("SELECT COUNT(DISTINCT cand) FROM mcl WHERE cand_kind = 'proxy' AND dst = 'judge_tls' AND proto = 'connect'") or 0)}
    out["中间人尝试里 proto 不是隧道协议的（应为 0）"] = int(db.scalar(
        "SELECT COUNT(*) FROM mcl WHERE cand_kind = 'proxy' AND proto NOT IN (%s)" % sql_in(TUNNEL_PROTOS)) or 0)
    return out


# ---------------------------------------------------------------- 输出前的断言

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?!\d|\.\d|/24)")
HOSTPORT_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}:\d{1,5}")
HEX12_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{12,}(?![0-9a-fA-F])")


def _scan_text(text):
    """把输出里唯一一个已知的、既不是地址也不是哈希、却长得像 IPv4 的值摘掉，供正则扫描用：m_mitm 报告的根证书包版本
    （rules_source.mitm_certcheck.roots_package_version，Ubuntu 的 ca-certificates 形如 20260816ubuntu0.24.04.1，尾部会被 IPV4_RE 命中）。
    只摘这一个字段的确切值（按 JSON 编码后的字符串整体替换），其余一律按规则判；做法与 m_mitm.assert_clean 相同。"""
    scan = text
    try:
        d = json.loads(text)
        v = ((d.get("rules_source") or {}).get("mitm_certcheck") or {}).get("roots_package_version")
        if v:
            scan = scan.replace(json.dumps(str(v), ensure_ascii=False), '""')
    except (ValueError, AttributeError):
        pass
    return scan


def assert_clean(text, db):
    """最后一道保险：输出文本里不许有 ip:port、不带 /24 的 IPv4、judge 的主机名或 IP、长十六进制串（nonce、哈希、节点 id）、邮箱样式。
    这是断言，不是放行手段：唯一的例外见 _scan_text。"""
    bad = []
    scan = _scan_text(text)
    if HOSTPORT_RE.search(scan):
        bad.append("ip:port")
    if IPV4_RE.search(scan):
        bad.append("不带 /24 的 IPv4")
    if HEX12_RE.search(scan):
        bad.append("长十六进制串（哈希/nonce/节点 id）")
    for table, col in (("self_names", "name"), ("self_ips", "ip")):
        if db.has_table(table):
            for (v,) in db.q("SELECT DISTINCT %s FROM %s" % (col, table)):
                if v and v.lower() in text.lower():
                    bad.append("judge 身份（%s）" % table)
                    break
    for literal in ("@",):  # judge 的名字和地址只从库里的 self_names / self_ips 取（上面已查），源码里不写
        if literal in text:
            bad.append("字面量 %s" % literal)
    if bad:
        raise SystemExit("输出含不许出现的内容：%s；已拒绝写出" % "、".join(bad))


# ---------------------------------------------------------------- Markdown

def print_markdown(res):
    w = res["window"]
    n = res["n"]
    print("### 观察窗口与分母\n")
    print(f"- 正式起点 {w['formal_start_utc']}（{w['formal_start_rule']}），结束 {w['end_utc']}，共 {fmt(w['hours'])} 小时；"
          f"试运行尝试 {fmt(w['trial_run_attempts_before_formal_start'])} 条；正式起点后中断 {fmt(w['interruption_minutes_after_formal_start'])} 分钟")
    for x in w["interruptions"]:
        print(f"  - 中断：{x['stop_utc']} → {x['start_utc']}，{fmt(x['minutes'])} 分钟（{x['seconds']} 秒；{x['begin_source']}；"
              f"{'正式起点后' if x['after_formal_start'] else '试运行期间'}）")
    print(f"- 候选池 {fmt(n['候选池里的代理候选（cands ∪ visit ∪ att）'])}（常规 {fmt(n['其中常规列表（group=0）'])}，聚合器抽样 {fmt(n['其中聚合器抽样（group=1）'])}），"
          f"探访过 {fmt(n['其中正式起点后探访过'])}，从没探访过 {fmt(n['从没探访过的候选（不进任何比例的分母）']['条目'])}"
          f"（其中有尝试但探访都被中止 {fmt(n[K_N_ABORTED]['条目'])}）；只在试运行里出现过 {fmt(n[K_N_TRIAL]['条目'])}；"
          f"在榜过的条目 {fmt(n['在榜过的条目（list_event 里出现过的）'])}，其中被排除、不在候选池 {fmt(n['在榜过但不在候选池的条目（被排除：judge 自己的地址、私网、知名端口、退出名单）'])}；"
          f"密集 /24 {fmt(n['候选密集的 /24 个数'])} 个")
    print(f"- 分类规则来源：内容与请求 = {res['rules_source']['integrity']}；中间人三层 = {res['rules_source']['mitm']}")

    m = res["mani_2018"]
    print("\n### Mani 等（ACSAC 2018）\n")
    print("| 测量日 | 起（UTC） | 小时 | 中断分钟 | 在榜 | 进入候选池 | 当天有尝试 | 有回应 | 有回应/在榜 | 有回应/当天有尝试 | 可用/在榜 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in m["responsive_daily"]["all"]["ours"]["按测量日"]:
        print(f"| {r['测量日']}{'' if r['完整'] else '（不完整）'} | {r['起（UTC）']} | {fmt(r['小时'])} | {fmt(r['中断分钟数'])} | {fmt(r['在榜条目'])} | "
              f"{fmt(r['其中进入候选池'])} | {fmt(r['其中当天有尝试（限探访过的候选）'])} | {fmt(r['当天有协议回应'])} | "
              f"{rfmt(r['有回应 / 在榜（Mani 等的口径）'])} | {rfmt(r[R_RESP_ATT])} | {rfmt(r['可用 / 在榜'])} |")
    med = m["responsive_daily"]["all"]["ours"]["中位数"]
    print(f"\n- 中位数（{fmt(med['取中位数的测量日数'])} 个测量日）：在榜 {fmt(med['在榜条目'])}，有回应 {fmt(med['当天有协议回应'])}，"
          f"有回应/在榜 {fmt(med['有回应 / 在榜（%）'], '%')}，有回应/当天有尝试 {fmt(med['有回应 / 当天有尝试（%）'], '%')}，可用/在榜 {fmt(med['可用 / 在榜（%）'], '%')}")
    print("\n| 口径 | 范围 | HTML 200 请求 | 正文不符 | 局部改动/不符 | 多半无害/不符 | 局部改动/HTML 200 | 不符的代理/能转发的代理 | 局部改动的代理/能转发的代理 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        for scope in ("forward", "all_plain"):
            r = m["html_modified"][key]["ours"][scope]["按请求"]
            c = m["html_modified"][key]["ours"][scope]["按代理"]
            print(f"| {label} | {scope} | {fmt(r['HTML 请求（状态 200）'])} | {rfmt(r['正文不符 / HTML 200'])} | {rfmt(r['其中局部改动（有害的上界候选）/ 不符'])} | "
                  f"{rfmt(r['其中截断 + 整页替换（多半无害）/ 不符'])} | {rfmt(r['局部改动 / HTML 200（对应 Mani 等“恶意占全部 HTML 请求”）'])} | "
                  f"{rfmt(c[R_FWD_MIS])} | {rfmt(c[R_FWD_PARTIAL])} |")
    print("\n| 口径 | 范围 | 隧道曾可用或遇到过中间人 | 中间人（总数） | " + " | ".join(L for L in LAYERS[:4]) + " | 中间人/hs_ok=1（第二口径） |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        for scope in ("connect", "tunnel"):
            c = m["cert_replaced"][key]["ours"][scope]
            lay = c["三层细分"]
            cells = []
            for L in LAYERS[:4]:
                v = lay.get(L)
                cells.append(rfmt(v["候选（最严重一层）/ 隧道曾可用或遇到过中间人（与 PROTOCOL 预期范围对账）"]) if v else "—")
            print(f"| {label} | {scope} | {fmt(c[D_CERT])} | {rfmt(c[R_CERT])} | " + " | ".join(cells) + f" | {rfmt(c[R_CERT_HS])} |")
    lk = m["client_ip_leak"]["all"]["ours"]
    a = lk["按代理（主口径：judge 收到过它转发的请求，不限 class；与 PROTOCOL 预期范围对账）"]
    b = lk["按代理（summary.go Anon 的口径：class=ok 且 judge 收到）"]
    print(f"\n- 请求头带出客户端地址：按代理 {rfmt(a['带出客户端地址的代理'])}（judge 收到过转发请求的代理）；class=ok 口径 {rfmt(b['带出客户端地址的代理'])}；"
          f"按请求 {rfmt(lk['按请求（judge 收到的 HTTP 转发请求）']['带出客户端地址'])}")
    for scope, _ in SSL_SCOPES:
        ss = m["sslstrip"]["all"]["ours"][scope]
        print(f"- https 链接被改成 http（{scope}）：HTML 不符请求 {fmt(ss['HTML 不符的请求'])}，有证据可读 {fmt(ss['有证据正文可读'])}，"
              f"有链接被改的请求 {fmt(ss['至少一个 https 链接被改成 http 的请求'])}（全部链接都被改 {fmt(ss['其中全部链接都被改'])}），"
              f"被改链接 {fmt(ss['被改的链接总数'])} 个，涉及 {fmt(ss['涉及的代理'])} 个代理（只算局部改动）；"
              f"不算剥离的：整页替换里回显 http://<judge>/ {fmt(ss[SSL_ECHO])}，局部改动里加前缀 {fmt(ss[SSL_PREFIX])}；无证据 {fmt(ss[K_NOEV])}"
              + (f"；{ss['note']}" if ss.get("note") else ""))

    t = res["tsirantonakis_2018"]
    print("\n### Tsirantonakis 等（NDSS 2018）\n")
    print("| 口径 | 范围 | 条目 | 探访过 | TCP 连得上过/探访过 | TCP 连得上过/全部条目（文献口径） | 取回过测试页/探访过 | 改动了内容/取回过 | 局部改动/取回过 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        for scope in ("all", "httpish"):
            r = t[key]["ours"][scope]
            print(f"| {label} | {scope} | {fmt(r['条目（含从没探访过的）'])} | {fmt(r['探访过的条目'])} | {rfmt(r['TCP 连得上过']['/ 探访过的'])} | "
                  f"{rfmt(r['TCP 连得上过'][L_ALL_ENTRIES])} | {rfmt(r['取回过测试页（HTTP 转发、HTML、200）']['/ 探访过的'])} | "
                  f"{rfmt(r['改动了内容']['/ 取回过测试页'])} | {rfmt(r['其中局部改动（有害的上界候选）']['/ 取回过测试页'])} |")

    me = res["mehanna_2024"]
    print("\n### Mehanna 等（MADWeb 2024）\n")
    print("| 口径 | 范围 | 候选 | 探访过 | 曾可用/探访过 | 曾有回应/探访过 | 曾可用/全部（文献口径） |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    for key, label in (("all", "全部"), ("excluding_dense", "去掉密集 /24")):
        for scope in ("regular", "aggregator_sample", "all"):
            r = me[key]["ours"]["ranges"][scope]
            print(f"| {label} | {scope} | {fmt(r['候选（含从没探访过的）'])} | {fmt(r['探访过的候选'])} | "
                  f"{rfmt(r['曾通过端到端校验（可用）']['/ 探访过的'])} | {rfmt(r['曾有协议回应（更宽）']['/ 探访过的'])} | "
                  f"{rfmt(r['曾通过端到端校验（可用）'][L_ALL_CANDS])} |")
    print("\n### 仪器检查\n")
    for k, v in res["checks"].items():
        print(f"- {k}：{v}")
    if "crosscheck" in res:
        x = res["crosscheck"]
        print(f"\n### 与 summary.json 交叉核对：{x['matched']}/{x['total']} 项一致" + (f"；不一致：{', '.join(x['mismatches'])}" if x["mismatches"] else ""))


# ---------------------------------------------------------------- 主流程

def run(db_path, out_dir, data_dir=None, roots=DEFAULT_ROOTS, certcheck_arg=None, summary_path=None, formal_start="auto",
        dense_threshold=DENSE_THRESHOLD, allow_import=True, markdown=False, write=True):
    db = DB(db_path)
    wl_source = check_whitelist(db)
    for t in ("att", "req", "req_header"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表" % t)
    for col in ("tls_detail_enum", "cand_kind", "prefix24"):
        if not db.has_column("att", col):
            raise SystemExit("att 表没有派生列 %s，需要 ingest.py 第 3 版以上建的库" % col)
    win = observation_window(db, formal_start)
    fs, end, intr = win.pop("_fs"), win.pop("_end"), win.pop("_intr")
    if end is None:
        end = fs
    if data_dir is None:
        data_dir = db.meta("data_dir")

    it = build_integrity_tables(db, fs, dense_threshold, allow_import)
    mt = build_mitm_table(db, fs, data_dir, roots, certcheck_arg, allow_import)
    pool_info = build_pool(db, fs)
    pool_info["self_ips_count"] = it.get("self_ips_count")
    build_per_day(db, fs)
    iv_source = build_intervals(db)

    res = {
        "module": MODULE, "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol_version": PROTOCOL_VERSION, "protocol_section": "与文献对账", "whitelist_source": wl_source, "dense_threshold": dense_threshold,
        "db_meta": {k: db.meta(k) for k in ("ingest_version", "first_ts", "last_ts", "state_tz_offsets", "state_cands")},
        "note": "文献的数字不写在这里：paper_value 一律 null，由人对原文核对后填入。每项的 difference 写我们的口径与原文口径的差异。",
        "definitions": DEFINITIONS,
        "window": win,
        "rules_source": {"integrity": it["source"], "mitm": mt["source"], "mitm_certcheck": mt.get("certcheck"),
                         "mitm_judge_hostname_available": mt.get("judge_hostname_available"),
                         "payload_expected_len": {"len": it["plen"], "source": it["plen_source"]}, "self_ips_source": it.get("self_ips_source")},
        "tables": {k: v for k, v in pool_info.items() if not k.startswith("_")},
    }
    res["n"] = denominators(db, fs, pool_info, iv_source)
    # paper_scope 只写对象、时长和频率（差异说明要用）；对象规模和结果数字由人对原文核对后填入 paper_value
    res["mani_2018"] = {
        "paper": "Mani 等，ACSAC 2018", "paper_scope": "被列出的代理，50 天，每天探测一次",
        "responsive_daily": {"all": mani_responsive_daily(db, fs, end, False, intr), "excluding_dense": mani_responsive_daily(db, fs, end, True, intr)},
        "html_modified": {"all": mani_html(db, False), "excluding_dense": mani_html(db, True)},
        "cert_replaced": {"all": mani_cert(db, False, mt["layers"]), "excluding_dense": mani_cert(db, True, mt["layers"])},
        "client_ip_leak": {"all": mani_leak(db, False), "excluding_dense": mani_leak(db, True)},
        "sslstrip": mani_sslstrip(db, data_dir),
    }
    res["tsirantonakis_2018"] = {
        "paper": "Tsirantonakis 等，NDSS 2018", "paper_scope": "HTTP 代理，两个月，每天约 22 次",
        "all": tsirantonakis(db, False), "excluding_dense": tsirantonakis(db, True),
    }
    res["mehanna_2024"] = {
        "paper": "Mehanna 等，MADWeb 2024", "paper_scope": "多个来源汇总的代理，30 个月，每天测试",
        "all": mehanna(db, False), "excluding_dense": mehanna(db, True),
    }
    res["checks"] = checks(db, res)
    bad = res["checks"]["各比例的分子不大于分母（应为 0 个例外）"]
    if bad["例外"]:
        print("警告：%d 个比例的分子大于分母，口径实现有错：%s" % (bad["例外"], "；".join(bad["路径"][:5])), file=sys.stderr)
    if summary_path:
        res["crosscheck"] = crosscheck_summary(db, summary_path, fs)

    text = json.dumps(res, ensure_ascii=False, indent=1, sort_keys=False)
    assert_clean(text, db)
    if write:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, OUTPUT_NAME)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("已写出 %s（%d 字节）" % (path, len(text.encode("utf-8"))), file=sys.stderr)
    if markdown:
        print_markdown(res)
    return res


# ---------------------------------------------------------------- 自检：合成库

SELF_IP = "192.0.2.250"            # TEST-NET-1
SELF_HOST = "judge.selftest.invalid"
T0_ISO = "2026-11-06T00:00:00Z"


def _synthetic_db(path, data_dir):
    """最小合成库，覆盖主要分支：两个完整测量日加一个不完整的；重启后的首次快照把一个条目隐式下榜；重新上榜；试运行尝试；
    透明 / 匿名 / 高匿的转发；局部改动（含 https 被剥离、证据可读）、整页替换、证据缺失；CONNECT 隧道里的中间人（unknown_authority 与
    hostname_mismatch 无证据）；连不上、无回应、从没探访过的条目；聚合器抽样（含 SOCKS 隧道里的明文 HTML 被局部改动、部分 https 被剥离）；
    一个候选超过 100 个的 /24；只在试运行里出现过的候选 K；只有 aborted 探访、却有真实尝试的候选 L；
    尝试在第 0 天末尾、visit 记录落在第 1 天的候选 P；一次 6 分钟的中断（stop 22.9h → start 23h）。"""
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE att (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, kind TEXT, arm TEXT, nonce TEXT,
        tcp_ok INTEGER, hs_ok INTEGER, hs_class TEXT, hs_code INTEGER, tls_ok INTEGER, tls_class TEXT, tls_detail TEXT, tls_leaf TEXT, tls_subj TEXT,
        tls_issuer TEXT, tls_self INTEGER, class TEXT, http_class TEXT, http_code INTEGER, http_len INTEGER, http_pre INTEGER, http_suf INTEGER,
        http_sim INTEGER, http_canary TEXT, http_ev TEXT, ip TEXT, ev TEXT, cand_kind TEXT, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT, tls_detail_enum TEXT);
    CREATE TABLE att_http_flag (rid INTEGER PRIMARY KEY, att_rid INTEGER, flag TEXT);
    CREATE TABLE att_http_added (rid INTEGER PRIMARY KEY, att_rid INTEGER, header TEXT);
    CREATE TABLE visit (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, "group" INTEGER, n INTEGER, prev TEXT, state TEXT,
        full INTEGER, listed INTEGER, labels TEXT, tried TEXT, ok TEXT, auth INTEGER, aborted INTEGER, next_min REAL, ms INTEGER,
        cand_ip TEXT, cand_port INTEGER, prefix24 TEXT, n_ok INTEGER);
    CREATE TABLE cands (rid INTEGER PRIMARY KEY, key TEXT, ip TEXT, port INTEGER, prefix24 TEXT, "group" INTEGER, label_names TEXT, visits INTEGER,
        ever_ok INTEGER, first_seen_epoch REAL, delisted_at_epoch REAL);
    CREATE TABLE list_event (rid INTEGER PRIMARY KEY, snap_rid INTEGER, ts TEXT, ts_epoch REAL, src TEXT, label TEXT, cand TEXT, event TEXT, base INTEGER,
        cand_ip TEXT, cand_port INTEGER, prefix24 TEXT);
    CREATE TABLE req (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, remote TEXT, rport INTEGER, tls INTEGER, hello_fp TEXT, method TEXT,
        target TEXT, nonce TEXT, age_s INTEGER, kind TEXT, req_canary TEXT, status INTEGER);
    CREATE TABLE req_header (rid INTEGER PRIMARY KEY, req_rid INTEGER, nonce TEXT, seq INTEGER, name TEXT, value TEXT);
    CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_leaf (leaf TEXT, source TEXT, n INTEGER, first_ts TEXT, last_ts TEXT);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE start (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER);
    CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL);
    CREATE TABLE version (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, version TEXT);
    CREATE TABLE evidence (hash TEXT, ext TEXT, bytes INTEGER, path TEXT);
    CREATE TABLE stat_pool (rid INTEGER PRIMARY KEY, stat_rid INTEGER, ts TEXT, ts_epoch REAL, key TEXT, value INTEGER);
    CREATE INDEX le_c ON list_event(cand, ts_epoch);
    CREATE INDEX le_s ON list_event(src, label, ts_epoch);
    """)
    T0 = parse_iso(T0_ISO)
    H = 3600.0
    con.execute("INSERT INTO self_ips VALUES (?, 'start.judge_ip', 1)", (SELF_IP,))
    con.execute("INSERT INTO self_names VALUES (?, 'start.judge_host', 1)", (SELF_HOST,))
    con.execute("INSERT INTO self_leaf VALUES ('9' || '9', 'control_ok', 1, NULL, NULL)")
    con.execute("INSERT INTO meta VALUES ('payload_len', ?)", (json.dumps({"h": {"len": 2704}, "j": {"len": 1306}, "b": {"len": 32768}}),))
    con.execute("INSERT INTO meta VALUES ('data_dir', ?)", (data_dir,))
    con.execute("INSERT INTO start VALUES (1, NULL, ?, 0)", (T0,))
    con.execute("INSERT INTO start VALUES (2, NULL, ?, 9)", (T0 + 23 * H,))
    con.execute("INSERT INTO version VALUES (1, NULL, ?, 'test')", (T0,))
    con.execute("INSERT INTO version VALUES (2, NULL, ?, 'test')", (T0 + 23 * H,))
    con.execute("INSERT INTO stop VALUES (1, NULL, ?)", (T0 + 22.9 * H,))
    con.execute("INSERT INTO stop VALUES (2, NULL, ?)", (T0 + 50 * H,))
    con.execute("INSERT INTO stat_pool VALUES (1, 1, NULL, ?, 'skipped_skip_port', 2)", (T0 + 49 * H,))

    # 候选：名字 → (ip, port, 标签, group)
    C = {
        "A": ("192.0.2.1", 8080, "http", 0), "B": ("192.0.2.2", 8080, "http", 0), "C": ("192.0.2.3", 3128, "http", 0),
        "D": ("192.0.2.4", 1080, "socks5", 0), "E": ("198.51.100.5", 8080, "http", 0), "F": ("198.51.100.6", 8080, "http", 0),
        "H": ("192.0.2.8", 8080, "http", 0), "I": ("192.0.2.9", 8080, "https", 0), "J": ("192.0.2.10", 8080, "http", 0),
        "G": ("203.0.113.250", 1080, "socks5", 1),
        "K": ("192.0.2.11", 8080, "http", 0),         # 只在试运行里出现过：不在 cands、不在 list_event
        "L": ("198.51.100.12", 8080, "http", 0),      # 在 cands；正式起点后只有一次 aborted 探访，但其中的尝试是真实的
        "P": ("198.51.100.13", 1080, "socks5", 0),    # 尝试在第 0 天末尾，visit 记录在第 1 天开头
    }
    key = {k: "%s:%d" % (v[0], v[1]) for k, v in C.items()}
    p24 = {k: ".".join(v[0].split(".")[:3]) + ".0/24" for k, v in C.items()}
    cand_rows = []
    for k, (ip, port, lab, grp) in C.items():
        if k == "K":
            continue
        cand_rows.append((key[k], ip, port, p24[k], grp, json.dumps([lab]), 0, 0, T0, None))
    for i in range(1, 121):  # 密集 /24：203.0.113.0/24 共 121 个候选
        cand_rows.append(("203.0.113.%d:8080" % i, "203.0.113.%d" % i, 8080, "203.0.113.0/24", 0, '["http"]', 0, 0, T0, None))
    con.executemany("INSERT INTO cands (key, ip, port, prefix24, \"group\", label_names, visits, ever_ok, first_seen_epoch, delisted_at_epoch) VALUES (?,?,?,?,?,?,?,?,?,?)", cand_rows)

    # 列表事件：首次快照 T0（A B C D E F H I J + 一个被排除的条目 X），J 在 5h 下榜、40h 重新上榜，B 在 30h 下榜；
    # 重启后的首次快照 T0+23h 不含 F（隐式下榜）和 J
    le = []
    excluded = "10.0.0.1:8080"
    for k in ("A", "B", "C", "D", "E", "F", "H", "I", "J", "L", "P"):
        le.append((T0, "src/one", C[k][2], key[k], "add", 1, p24[k]))
    le.append((T0, "src/one", "http", excluded, "add", 1, "10.0.0.0/24"))
    le.append((T0 + 5 * H, "src/one", "http", key["J"], "del", 0, p24["J"]))
    for k in ("A", "B", "C", "D", "E", "H", "I", "P"):
        le.append((T0 + 23 * H, "src/one", C[k][2], key[k], "add", 1, p24[k]))
    le.append((T0 + 23 * H, "src/one", "http", excluded, "add", 1, "10.0.0.0/24"))
    le.append((T0 + 30 * H, "src/one", "http", key["B"], "del", 0, p24["B"]))
    le.append((T0 + 40 * H, "src/one", "http", key["J"], "add", 0, p24["J"]))
    con.executemany("INSERT INTO list_event (ts_epoch, src, label, cand, event, base, prefix24) VALUES (?,?,?,?,?,?,?)", le)

    seq = {"att": 0, "req": 0, "hdr": 0, "visit": 0, "nonce": 0}

    def visit(k, t, aborted=0):
        seq["visit"] += 1
        ip, port, lab, grp = C[k]
        con.execute("INSERT INTO visit (rid, ts_epoch, visit, cand, \"group\", n, prev, state, listed, labels, aborted, cand_ip, cand_port, prefix24) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (seq["visit"], t, "v%d" % seq["visit"], key[k], grp or None, seq["visit"], "open", "open", 1, json.dumps([lab]), aborted or None, ip, port, p24[k]))

    def att(k, t, proto, dst, cls, kind=None, tcp=1, hs=None, hs_class=None, hs_code=None, tls_class=None, detail=None, ev=None,
            http_class=None, code=None, ln=None, pre=None, suf=None, sim=None, http_ev=None, seen=None, headers=(), nonce=True):
        seq["att"] += 1
        n = None
        if nonce and code is not None:
            seq["nonce"] += 1
            n = "n%06d" % seq["nonce"]
        ip, port, lab, grp = C[k]
        con.execute("""INSERT INTO att (rid, ts_epoch, visit, cand, proto, dst, kind, nonce, tcp_ok, hs_ok, hs_class, hs_code, tls_class, tls_detail,
                       tls_subj, class, http_class, http_code, http_len, http_pre, http_suf, http_sim, http_ev, ev, cand_kind, cand_ip, cand_port, prefix24, tls_detail_enum)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (seq["att"], t, "v", key[k], proto, dst, kind, n, tcp or None, hs, hs_class, hs_code, tls_class, detail,
                     ("CN=other.example" if tls_class else None), cls, http_class, code, ln, pre, suf, sim, http_ev, ev,
                     "proxy", ip, port, p24[k], detail if tls_class == "tls_cert_invalid" else None))
        if n and seen:
            seq["req"] += 1
            con.execute("INSERT INTO req (rid, ts_epoch, remote, tls, method, nonce, kind, req_canary, status) VALUES (?,?,?,?,?,?,?,?,?)",
                        (seq["req"], t + 0.2, ip, None, "GET", n, kind or "h", "ok", 200))
            hs_rows = [("User-Agent", SENT_HEADERS["User-Agent"]), ("Accept", SENT_HEADERS["Accept"]), ("Accept-Language", SENT_HEADERS["Accept-Language"]),
                       ("Accept-Encoding", "identity"), ("Cookie", "pc=zz"), ("X-Probe-Canary", "zz")] + list(headers)
            for i, (hn, hv) in enumerate(hs_rows):
                seq["hdr"] += 1
                con.execute("INSERT INTO req_header VALUES (?,?,?,?,?,?)", (seq["hdr"], seq["req"], n, i, hn, hv))
        return seq["att"]

    # A：转发可用、透明（X-Forwarded-For 带探测器地址）；每天一次 + 第 2 天（不完整）一次
    for t in (T0 + 1 * H, T0 + 25 * H, T0 + 49 * H):
        visit("A", t)
        att("A", t, "forward", "judge_http", "ok", "h", code=200, ln=2704, seen=True, headers=[("X-Forwarded-For", SELF_IP + ", 10.1.1.1")])
    # B：试运行时转发可用（不计）；第 0 天 HTML 局部改动（https 被剥离，证据可读）；第 1 天局部改动、证据缺失；高匿
    att("B", T0 - 1 * H, "forward", "judge_http", "ok", "h", code=200, ln=2704, seen=True)
    visit("B", T0 - 1 * H)
    visit("B", T0 + 2 * H)
    att("B", T0 + 2 * H, "forward", "judge_http", "http_body_mismatch", "h", http_class="http_body_mismatch", code=200, ln=2694, pre=336, suf=230, sim=84,
        http_ev="evB", seen=True)
    visit("B", T0 + 26 * H)
    att("B", T0 + 26 * H, "forward", "judge_http", "http_body_mismatch", "h", http_class="http_body_mismatch", code=200, ln=2694, pre=336, suf=230, sim=84,
        http_ev="evMissing", seen=True)
    # C：CONNECT 隧道建立、证书 unknown_authority（冒充 judge）；转发 407（有回应、不可用）
    for t in (T0 + 3 * H, T0 + 27 * H):
        visit("C", t)
        att("C", t, "connect", "judge_tls", "tls_cert_invalid", "h", hs=1, hs_code=200, tls_class="tls_cert_invalid", detail="unknown_authority", ev="evDerC")
        att("C", t, "forward", "judge_http", "http_status", "h", http_class="http_status", code=407)
    # D：socks5 连得上、握手超时（无回应）
    for t in (T0 + 4 * H, T0 + 28 * H):
        visit("D", t)
        att("D", t, "socks5", "judge_tls", "hs_timeout", hs=0, hs_class="hs_timeout")
    # E：从没探访过
    # F：连不上（tcp_refused），只在第 0 天在榜
    visit("F", T0 + 6 * H)
    att("F", T0 + 6 * H, "forward", "judge_http", "tcp_refused", "h", tcp=0)
    # H：转发取回 HTML 但整页替换（证据可读，0 个 judge 链接）；匿名（Via）；CONNECT 隧道可用
    visit("H", T0 + 7 * H)
    att("H", T0 + 7 * H, "forward", "judge_http", "http_body_mismatch", "h", http_class="http_body_mismatch", code=200, ln=500, pre=0, suf=0, sim=0,
        http_ev="evH", seen=True, headers=[("Via", "1.1 fixture")])
    att("H", T0 + 7 * H, "connect", "judge_tls", "ok", "h", hs=1, hs_code=200, code=200, ln=2704, seen=True)
    visit("H", T0 + 31 * H)
    att("H", T0 + 31 * H, "connect", "judge_tls", "ok", "h", hs=1, hs_code=200, code=200, ln=2704, seen=True)
    # I：CONNECT 隧道建立、证书 hostname_mismatch、没拿到证据
    for t in (T0 + 8 * H, T0 + 32 * H):
        visit("I", t)
        att("I", t, "connect", "judge_tls", "tls_cert_invalid", "h", hs=1, hs_code=200, tls_class="tls_cert_invalid", detail="hostname_mismatch")
    # J：第 0 天转发 302（有回应）；第 1 天无尝试
    visit("J", T0 + 1 * H)
    att("J", T0 + 1 * H, "forward", "judge_http", "http_status", "h", http_class="http_status", code=302)
    # G：聚合器抽样，第 0 天 socks5 隧道可用
    visit("G", T0 + 9 * H)
    att("G", T0 + 9 * H, "socks5", "judge_tls", "ok", "h", hs=1, code=200, ln=2704, seen=True)
    # G：SOCKS5 隧道里的明文 HTML 被局部改动（证据可读，10 个链接里 3 个被改成 http）：只进“全部明文”范围
    att("G", T0 + 9 * H, "socks5", "judge_http", "http_body_mismatch", "h", hs=1, http_class="http_body_mismatch", code=200, ln=2700,
        pre=336, suf=230, sim=84, http_ev="evG", seen=True)
    # K：只在试运行里出现过（正式起点前一次探访，连不上）
    visit("K", T0 - 2 * H)
    att("K", T0 - 2 * H, "forward", "judge_http", "tcp_refused", "h", tcp=0)
    # L：正式起点后只有一次 aborted 的探访，其中一条真实尝试（SOCKS5 要求认证 → 连得上、有回应）
    att("L", T0 + 12 * H, "socks5", "judge_tls", "hs_auth", hs=0, hs_class="hs_auth", hs_code=2)
    visit("L", T0 + 12 * H, aborted=1)
    # P：尝试在第 0 天末尾（23.95h，SOCKS5 要求认证），探访结束、visit 记录在第 1 天（24.05h）
    att("P", T0 + 23.95 * H, "socks5", "judge_tls", "hs_auth", hs=0, hs_class="hs_auth", hs_code=2)
    visit("P", T0 + 24.05 * H)
    # 一条 canceled 的尝试（不计）和一条 aborted 的探访（不计）
    att("A", T0 + 10 * H, "forward", "judge_http", "canceled", "h", tcp=0, nonce=False)
    visit("A", T0 + 10 * H, aborted=1)
    con.commit()

    # 证据正文：B 的 https 链接全被改成 http（10 处）；H 是别的页面，回显了请求地址（http://<judge>/，不算剥离）
    os.makedirs(os.path.join(data_dir, "evidence", "ev"), exist_ok=True)
    body_b = "\n".join('<a href="http://%s/p%d">x</a>' % (SELF_HOST, i) for i in range(HTML_HTTPS_LINKS)).encode()
    body_h = gzip.compress(("<html><body>Welcome to the portal<br>REQUEST_URI = http://%s/p/h/x</body></html>" % SELF_HOST).encode())
    body_g = "\n".join('<a href="%s://%s/p%d">x</a>' % ("http" if i < 3 else "https", SELF_HOST, i) for i in range(HTML_HTTPS_LINKS)).encode()
    for h, body in (("evB", body_b), ("evH", body_h), ("evG", body_g)):
        p = os.path.join("evidence", "ev", h + ".body")
        with open(os.path.join(data_dir, p), "wb") as f:
            f.write(body)
        con.execute("INSERT INTO evidence VALUES (?, 'body', ?, ?)", (h, len(body), p))
    con.commit()
    con.close()
    # summary.json：按 summary.go 的口径手算的期望值，用来走交叉核对的代码路径
    # regular：A B C D F H I J + K（试运行，summary.go 不裁）+ P；L 只有 aborted 探访，summary.go 跳过
    summ = {"generated": "x", "funnel": {"regular": {"seen": 10, "tcp": 8, "responsive": 7, "working": 3},
                                         "aggregator_sample": {"seen": 1, "tcp": 1, "responsive": 1, "working": 1}},
            "findings": {"请求头里带出了探测器的地址": {"attempts": 3, "candidates": 1},
                         K_PARTIAL: {"attempts": 3, "candidates": 2}, K_REPLACED: {"attempts": 1, "candidates": 1},
                         "隧道里的证书不是 judge 的（中间人）": {"attempts": 4, "candidates": 2}}}
    sp = os.path.join(data_dir, "summary.json")
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(summ, f, ensure_ascii=False)
    return sp


def selftest():
    tmp = tempfile.mkdtemp(prefix="m_literature_selftest_")
    db_path = os.path.join(tmp, "synthetic.sqlite")
    data_dir = os.path.join(tmp, "data")
    os.makedirs(data_dir)
    summary_path = _synthetic_db(db_path, data_dir)
    failures = []
    n_asserts = [0]

    def expect(name, got, want):
        n_asserts[0] += 1
        if got != want:
            failures.append("%s: 得到 %r，期望 %r" % (name, got, want))

    results = {}
    for label, allow in (("import", True), ("builtin", False)):
        try:
            results[label] = run(db_path, os.path.join(tmp, "out_" + label), data_dir=data_dir, summary_path=summary_path,
                                 allow_import=allow, markdown=False, write=True)
        except SystemExit as e:
            failures.append("%s 路径运行失败：%s" % (label, e))
            results[label] = None
    res = results["builtin"]
    if res is None:
        print("自检失败：内置路径没跑完", file=sys.stderr)
        for x in failures:
            print("  - " + x, file=sys.stderr)
        return 1

    expect("正式起点", res["window"]["formal_start_utc"], "2026-11-06T00:00Z")
    expect("结束", res["window"]["end_utc"], "2026-11-08T02:00Z")
    expect("试运行尝试", res["window"]["trial_run_attempts_before_formal_start"], 2)   # B、K 各一条
    iv = res["window"]["interruptions"]
    expect("中断条数", len(iv), 1)
    expect("中断分钟", (iv[0]["minutes"], iv[0]["begin_source"], iv[0]["after_formal_start"]) if iv else None, (6.0, "stop 记录", True))
    expect("正式起点后中断分钟", res["window"]["interruption_minutes_after_formal_start"], 6.0)
    n = res["n"]
    expect("候选池", n["候选池里的代理候选（cands ∪ visit ∪ att）"], 132)    # K 只在试运行里出现，不进候选池
    expect("常规", n["其中常规列表（group=0）"], 131)
    expect("聚合器", n["其中聚合器抽样（group=1）"], 1)
    expect("探访过", n["其中正式起点后探访过"], 10)       # A B C D F H I J G P（E、L 和密集 /24 没探访）
    expect("从没探访过", n["从没探访过的候选（不进任何比例的分母）"]["条目"], 122)   # E、L、密集 /24 的 120 个
    expect("只有 aborted 探访的候选", n[K_N_ABORTED], {"条目": 1, "所在 /24": 1})   # L
    expect("只在试运行里出现过的候选", n[K_N_TRIAL], {"条目": 1, "所在 /24": 1})     # K
    expect("在榜过的条目", n["在榜过的条目（list_event 里出现过的）"], 12)
    expect("被排除的条目", n["在榜过但不在候选池的条目（被排除：judge 自己的地址、私网、知名端口、退出名单）"], 1)
    expect("密集 /24", n["候选密集的 /24 个数"], 1)
    expect("stat_pool skipped", n["最后一条运行状况里被排除的条目数（stat_pool.skipped_*）"], {"skipped_skip_port": 2})

    rd = res["mani_2018"]["responsive_daily"]["all"]["ours"]
    days = rd["按测量日"]
    expect("测量日数", len(days), 3)
    expect("完整标记", [d["完整"] for d in days], [True, True, False])
    expect("第 0 天在榜", days[0]["在榜条目"], 12)          # 11 个候选 + 被排除的 X
    expect("第 0 天进入候选池", days[0]["其中进入候选池"], 11)
    expect("第 0 天探访过（visit 记录时刻）", days[0]["其中当天探访过（按 visit 记录时刻，参考）"], 8)    # 除 E、L（aborted）、P（visit 记录在第 1 天）
    expect("第 0 天有尝试（限探访过）", days[0]["其中当天有尝试（限探访过的候选）"], 9)                # + P；L 只有 aborted 探访，不算
    expect("第 0 天有尝试（含 aborted）", days[0]["其中当天有尝试（含只有 aborted 探访的候选，参考）"], 10)
    expect("第 0 天有回应", days[0]["当天有协议回应"], 7)    # A B C H I J P（L 有回应但没探访过，不进分子）
    expect("第 0 天连得上", days[0]["当天连得上"], 8)        # A B C D H I J P
    expect("第 0 天可用", days[0]["当天可用"], 2)            # A H
    expect("第 0 天中断分钟", days[0]["中断分钟数"], 6.0)
    expect("第 1 天中断分钟", days[1]["中断分钟数"], 0.0)
    expect("第 0 天 有回应/在榜", days[0]["有回应 / 在榜（Mani 等的口径）"], {"num": 7, "den": 12, "pct": 58.3})
    expect("第 0 天 有回应/当天有尝试", days[0][R_RESP_ATT], {"num": 7, "den": 9, "pct": 77.8})
    expect("第 1 天在榜", days[1]["在榜条目"], 10)           # F、L 在 23h 隐式下榜；J 在 40h 重新上榜；X、P 仍在
    expect("第 1 天有回应", days[1]["当天有协议回应"], 5)    # A B C H I（P 的 visit 记录在第 1 天，但尝试在第 0 天）
    expect("第 1 天 有回应/当天有尝试", days[1][R_RESP_ATT], {"num": 5, "den": 6, "pct": 83.3})   # A B C D H I
    expect("第 2 天在榜", days[2]["在榜条目"], 9)            # B 在 30h 下榜
    expect("第 2 天有回应", days[2]["当天有协议回应"], 1)
    expect("中位数天数", rd["中位数"]["取中位数的测量日数"], 2)
    expect("中位数 有回应/在榜", rd["中位数"]["有回应 / 在榜（%）"], round((58.3 + 50.0) / 2, 1))
    rdx = res["mani_2018"]["responsive_daily"]["excluding_dense"]["ours"]["按测量日"]
    expect("去密集 第 0 天在榜（list_event 里没有密集 /24，不变）", rdx[0]["在榜条目"], 12)

    hm = res["mani_2018"]["html_modified"]["excluding_dense"]["ours"]["forward"]["按请求"]
    expect("HTML 200", hm["HTML 请求（状态 200）"], 6)       # A×3 B×2 H×1
    expect("HTML 任意状态", hm["HTML 请求（收到任何状态码）"], 9)   # + C×2 407 + J 302
    expect("HTML 不符", hm["正文不符 / HTML 200"], {"num": 3, "den": 6, "pct": 50.0})
    expect("局部改动/不符", hm["其中局部改动（有害的上界候选）/ 不符"], {"num": 2, "den": 3, "pct": 66.7})
    expect("无害/不符", hm["其中截断 + 整页替换（多半无害）/ 不符"], {"num": 1, "den": 3, "pct": 33.3})
    expect("局部改动/200", hm["局部改动 / HTML 200（对应 Mani 等“恶意占全部 HTML 请求”）"], {"num": 2, "den": 6, "pct": 33.3})
    hp = res["mani_2018"]["html_modified"]["all"]["ours"]["forward"]["按代理"]
    expect("取回 HTML 的代理", hp["取回过 HTML（200）的代理"], 3)
    expect("不符代理", hp["正文不符的代理 / 取回过的"], {"num": 2, "den": 3, "pct": 66.7})
    expect("局部改动代理/不符代理", hp["局部改动的代理 / 不符的代理"], {"num": 1, "den": 2, "pct": 50.0})
    expect("能转发的代理（HTML）", hp["能转发的代理（judge 收到过它转发的请求，PROTOCOL 预期范围的分母）"], 3)   # A B H
    expect("不符代理/能转发", hp[R_FWD_MIS], {"num": 2, "den": 3, "pct": 66.7})
    expect("局部改动代理/能转发", hp[R_FWD_PARTIAL], {"num": 1, "den": 3, "pct": 33.3})
    hpa = res["mani_2018"]["html_modified"]["all"]["ours"]["all_plain"]
    expect("全部明文 HTML 200", hpa["按请求"]["HTML 请求（状态 200）"], 7)    # + G 在 SOCKS 隧道里的明文
    expect("全部明文 不符代理/能转发", hpa["按代理"][R_FWD_MIS], {"num": 3, "den": 4, "pct": 75.0})   # B H G / A B H G
    expect("全部明文 聚合器 不符代理/能转发", hpa["按候选来源"]["aggregator_sample"][R_FWD_MIS], {"num": 1, "den": 1, "pct": 100.0})
    expect("forward 聚合器 能转发", res["mani_2018"]["html_modified"]["all"]["ours"]["forward"]["按候选来源"]["aggregator_sample"]["能转发的代理"], 0)

    ce = res["mani_2018"]["cert_replaced"]["all"]["ours"]["connect"]
    expect("CONNECT 隧道建立过", ce[D_CERT_HS], 3)      # C H I
    expect("CONNECT 可用或中间人", ce[D_CERT], 3)
    expect("中间人总数", ce["证书被替换（中间人，总数）的代理"], 2)
    expect("中间人/可用或中间人（主口径）", ce[R_CERT], {"num": 2, "den": 3, "pct": 66.7})
    expect("中间人/隧道建立过（第二口径）", ce[R_CERT_HS], {"num": 2, "den": 3, "pct": 66.7})
    expect("mcl 核对", ce["仪器核对：mcl 里的中间人候选数（应等于上面的总数）"], 2)
    expect("冒充 judge 候选", ce["三层细分"][L_JUDGE]["候选（按候选取最严重一层）"], 1)
    expect("内置路径 无法细分", ce["三层细分"][L_UNAVAIL]["候选（按候选取最严重一层）"], 1)
    ct = res["mani_2018"]["cert_replaced"]["all"]["ours"]["tunnel"]
    expect("全部隧道 建立过", ct[D_CERT_HS], 4)        # + G
    expect("全部隧道 可用或中间人", ct[D_CERT], 4)
    expect("全部隧道 去密集", res["mani_2018"]["cert_replaced"]["excluding_dense"]["ours"]["tunnel"][D_CERT_HS], 3)
    expect("全部隧道 聚合器", ct["按候选来源"]["aggregator_sample"][R_CERT], {"num": 0, "den": 1, "pct": 0.0})
    expect("全部隧道 常规", ct["按候选来源"]["regular"][R_CERT], {"num": 2, "den": 3, "pct": 66.7})

    lk = res["mani_2018"]["client_ip_leak"]["all"]["ours"]
    LK = "按代理（主口径：judge 收到过它转发的请求，不限 class；与 PROTOCOL 预期范围对账）"
    expect("能转发（seen）", lk[LK]["能转发的代理"], 3)    # A B H
    expect("带出地址 代理", lk[LK]["带出客户端地址的代理"], {"num": 1, "den": 3, "pct": 33.3})
    expect("带出地址 常规", lk["按候选来源（按代理，主口径）"]["regular"]["带出客户端地址的代理"], {"num": 1, "den": 3, "pct": 33.3})
    expect("能转发（ok）", lk["按代理（summary.go Anon 的口径：class=ok 且 judge 收到）"]["能转发的代理"], 1)      # 只有 A（B 的 ok 在试运行）
    expect("带出地址 请求", lk["按请求（judge 收到的 HTTP 转发请求）"]["带出客户端地址"], {"num": 3, "den": 6, "pct": 50.0})

    ss = res["mani_2018"]["sslstrip"]["all"]["ours"]["forward"]
    expect("sslstrip 不符请求", ss["HTML 不符的请求"], 3)
    expect("sslstrip 可读", ss["有证据正文可读"], 2)
    expect("sslstrip 无证据", ss[K_NOEV], 1)
    expect("sslstrip 命中请求", ss["至少一个 https 链接被改成 http 的请求"], 1)
    expect("sslstrip 全改", ss["其中全部链接都被改"], 1)
    expect("sslstrip 链接数", ss["被改的链接总数"], HTML_HTTPS_LINKS)
    expect("sslstrip 代理", ss["涉及的代理"], 1)
    expect("sslstrip 按分类", ss["按正文分类"], {K_PARTIAL: {"请求": 1, "有链接被改": 1, "含 http://<judge>/": 1},
                                             K_REPLACED: {"请求": 1, "有链接被改": 0, "含 http://<judge>/": 1}})
    expect("sslstrip 整页替换的回显单列", (ss[SSL_ECHO], ss[SSL_PREFIX]), (1, 0))
    # 计法本身：剥离 / 回显 / 加前缀 / 截断
    expect("ssl_classify 全部剥离", ssl_classify(K_PARTIAL, 0, HTML_HTTPS_LINKS), ("strip", HTML_HTTPS_LINKS))
    expect("ssl_classify 部分剥离", ssl_classify(K_PARTIAL, 7, 3), ("strip", 3))
    expect("ssl_classify 加前缀（https 没少）", ssl_classify(K_PARTIAL, HTML_HTTPS_LINKS, HTML_HTTPS_LINKS), ("prefix", 0))
    expect("ssl_classify 加前缀又删了 2 个链接", ssl_classify(K_PARTIAL, 8, 8), ("strip", 2))
    expect("ssl_classify 整页替换回显", ssl_classify(K_REPLACED, 0, 1), ("echo", 0))
    expect("ssl_classify 截断", ssl_classify(K_TRUNC, 4, 0), ("none", 0))
    expect("ssl_classify 局部改动没有 http", ssl_classify(K_PARTIAL, 6, 0), ("none", 0))
    sa = res["mani_2018"]["sslstrip"]["all"]["ours"]["all_plain"]
    expect("sslstrip 全部明文 不符请求", sa["HTML 不符的请求"], 4)
    expect("sslstrip 全部明文 命中/链接/代理", (sa["至少一个 https 链接被改成 http 的请求"], sa["被改的链接总数"], sa["涉及的代理"]), (2, HTML_HTTPS_LINKS + 3, 2))
    expect("sslstrip 全部明文 按候选来源", sa["涉及的代理（按候选来源）"], {"regular": 1, "aggregator_sample": 1})
    expect("sslstrip 全部明文 分布（只算局部改动）", sa["被改链接数分布（局部改动的请求数）"], {"3": 1, str(HTML_HTTPS_LINKS): 1})
    sx = res["mani_2018"]["sslstrip"]["excluding_dense"]["ours"]["all_plain"]
    expect("sslstrip 去密集 全部明文（G 在密集 /24）", (sx["HTML 不符的请求"], sx["至少一个 https 链接被改成 http 的请求"]), (3, 1))

    ts = res["tsirantonakis_2018"]["excluding_dense"]["ours"]["all"]
    expect("Ts 条目", ts["条目（含从没探访过的）"], 11)
    expect("Ts 探访过", ts["探访过的条目"], 9)
    expect("Ts 只有 aborted 探访", ts["从没探访过·其中有尝试、但探访都被中止（不进分子）"], 1)
    expect("Ts TCP / 探访过（L 连得上但没探访过，不进分子）", ts["TCP 连得上过"]["/ 探访过的"], {"num": 8, "den": 9, "pct": 88.9})
    expect("Ts TCP / 全部条目（文献口径）", ts["TCP 连得上过"][L_ALL_ENTRIES], {"num": 8, "den": 11, "pct": 72.7})
    expect("Ts 取回测试页", ts["取回过测试页（HTTP 转发、HTML、200）"]["条目"], 3)
    expect("Ts 改动", ts["改动了内容"]["/ 取回过测试页"], {"num": 2, "den": 3, "pct": 66.7})
    expect("Ts 局部改动", ts["其中局部改动（有害的上界候选）"]["/ 取回过测试页"], {"num": 1, "den": 3, "pct": 33.3})
    tsh = res["tsirantonakis_2018"]["excluding_dense"]["ours"]["httpish"]
    expect("Ts httpish 条目", tsh["条目（含从没探访过的）"], 9)    # 去掉 socks5 的 D、P
    expect("Ts httpish TCP", tsh["TCP 连得上过"]["条目"], 6)
    tsa = res["tsirantonakis_2018"]["all"]["ours"]["all"]
    expect("Ts 全部（含密集）条目", tsa["条目（含从没探访过的）"], 131)

    me = res["mehanna_2024"]["excluding_dense"]["ours"]["ranges"]
    expect("Me 常规 可用", me["regular"]["曾通过端到端校验（可用）"][L_ALL_CANDS], {"num": 2, "den": 11, "pct": 18.2})
    expect("Me 常规 有回应", me["regular"]["曾有协议回应（更宽）"]["/ 探访过的"], {"num": 7, "den": 9, "pct": 77.8})
    expect("Me 常规 只有 aborted 探访", me["regular"]["从没探访过·其中有尝试、但探访都被中止（不进分子）"], 1)
    expect("Me 聚合器（去密集后为空）", me["aggregator_sample"]["候选（含从没探访过的）"], 0)
    mea = res["mehanna_2024"]["all"]["ours"]["ranges"]
    expect("Me 聚合器 可用", mea["aggregator_sample"]["曾通过端到端校验（可用）"][L_ALL_CANDS], {"num": 1, "den": 1, "pct": 100.0})

    ck = res["checks"]
    expect("区间重叠", ck["同一 (来源, 标签, 条目) 的在榜区间互相重叠（应为 0）"], 0)
    expect("区间倒置", ck["在榜区间结束早于开始（应为 0）"], 0)
    expect("mcl 一致", ck["中间人尝试：lit_pa 与 mcl 的候选数一致（connect）"], {"lit_pa": 2, "mcl": 2})
    expect("各比例分子不大于分母", ck["各比例的分子不大于分母（应为 0 个例外）"], {"例外": 0, "路径": []})
    expect("能转发分母一致", ck["内容被改与带出地址的“能转发的代理”是同一个分母（all）"]["一致"], True)
    expect("ratio_violations 能发现例外", ratio_violations({"x": [{"num": 3, "den": 2, "pct": 150.0}]}), ["x[0]：3/2"])
    x = res["crosscheck"]
    expect("交叉核对全部一致", x["mismatches"], [])
    expect("交叉核对项数", x["total"], 16)

    # 两条路径（import 同目录模块 / 内置实现）的结果应一致，只有中间人细分的层名不同
    ri = results["import"]
    if ri is not None:
        def strip(d):
            s = json.dumps(d, ensure_ascii=False, sort_keys=True)
            return s
        for sec in ("n", "tsirantonakis_2018", "mehanna_2024"):
            expect("两条路径一致：%s" % sec, strip(ri[sec]) == strip(res[sec]), True)
        for sub in ("responsive_daily", "html_modified", "client_ip_leak", "sslstrip"):
            expect("两条路径一致：mani.%s" % sub, strip(ri["mani_2018"][sub]) == strip(res["mani_2018"][sub]), True)
        ci = ri["mani_2018"]["cert_replaced"]["all"]["ours"]["connect"]
        expect("import 路径 中间人总数", ci["证书被替换（中间人，总数）的代理"], 2)
        if ri["rules_source"]["mitm"].startswith("m_mitm"):
            expect("import 路径 冒充 judge", ci["三层细分"][L_JUDGE]["候选（按候选取最严重一层）"], 1)
            expect("import 路径 证据未存", ci["三层细分"][L_NOEV]["候选（按候选取最严重一层）"], 1)
        else:
            print("提示：import 路径没有用上 m_mitm（%s）" % ri["rules_source"]["mitm"], file=sys.stderr)
        expect("import 路径用了 m_integrity", ri["rules_source"]["integrity"], "m_integrity.build_tables")

    text = json.dumps(res, ensure_ascii=False)
    expect("输出里没有 ip:port", bool(HOSTPORT_RE.search(text)), False)
    expect("输出里没有裸 IPv4", bool(IPV4_RE.search(text)), False)
    # assert_clean 的分支：根证书包版本（尾部像 IPv4）要放行；别处的裸 IPv4、ip:port、judge 身份仍要拦下
    db_chk = DB(db_path)
    ok_text = json.dumps({"rules_source": {"mitm_certcheck": {"roots_package_version": "20260816ubuntu0.24.04.1"}}, "n": {"x": 1}}, ensure_ascii=False)
    try:
        assert_clean(ok_text, db_chk)
        expect("assert_clean 放行根证书包版本", True, True)
    except SystemExit as e:
        expect("assert_clean 放行根证书包版本", str(e), "")
    for name, bad_text in (("裸 IPv4", ok_text.replace('"x": 1', '"x": "198.51.100.7"')),
                           ("ip:port", ok_text.replace('"x": 1', '"x": "198.51.100.7:8080"')),
                           ("judge 主机名", ok_text.replace('"x": 1', '"x": "%s"' % SELF_HOST)),
                           ("探测器地址", ok_text.replace('"x": 1', '"x": "%s"' % SELF_IP)),
                           ("长十六进制", ok_text.replace('"x": 1', '"x": "%s"' % ("ab" * 16)))):
        try:
            assert_clean(bad_text, db_chk)
            expect("assert_clean 拦下 " + name, "放行了", "拦下")
        except SystemExit:
            expect("assert_clean 拦下 " + name, "拦下", "拦下")
    expect("输出里没有探测器地址", SELF_IP in text, False)
    expect("输出里没有 judge 主机名", SELF_HOST in text, False)
    if failures:
        print("自检失败 %d/%d 项：" % (len(failures), n_asserts[0]), file=sys.stderr)
        for f in failures:
            print("  - " + f, file=sys.stderr)
        return 1
    print("自检通过：%d 项断言，合成库 %s" % (n_asserts[0], db_path), file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="与文献对账（PROTOCOL“与文献对账”：Mani 等 2018、Tsirantonakis 等 2018、Mehanna 等 2024）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 %s" % OUTPUT_NAME)
    ap.add_argument("--data", help="数据目录（含 evidence/）；默认取库里 meta.data_dir。https 链接改写的计数和 m_mitm 的证书链校验要用")
    ap.add_argument("--roots", default=DEFAULT_ROOTS, help="公共根证书 PEM（传给 m_mitm），默认 %s" % DEFAULT_ROOTS)
    ap.add_argument("--certcheck", help="certcheck 二进制的路径或 'go'（传给 m_mitm）")
    ap.add_argument("--summary", help="fieldtest 自带的 summary.json，给了就交叉核对漏斗与几项 findings")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--formal-start", default="auto", help="auto（按 PROTOCOL 规则）/ first（第一条 start）/ 带时区的 ISO 时间")
    ap.add_argument("--dense-threshold", type=int, default=DENSE_THRESHOLD, help="“候选密集的 /24”的阈值，默认 100")
    ap.add_argument("--no-import", action="store_true", help="不 import 同目录的 m_integrity / m_mitm，全部用本模块内置的同规则实现")
    ap.add_argument("--selftest", action="store_true", help="在临时目录里建合成库并核对预期值（两条路径都跑）")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    run(args.db, args.out, data_dir=args.data, roots=args.roots, certcheck_arg=args.certcheck, summary_path=args.summary,
        formal_start=args.formal_start, dense_threshold=args.dense_threshold, allow_import=not args.no_import, markdown=args.markdown)


if __name__ == "__main__":
    main()
