#!/usr/bin/env python3
"""仪器核对（第一阶段 1B）：先检查探测器，再谈结论。

对应 PROTOCOL 的“对照与自检”“正式测量的起止”“频率与限速”“已知局限（启动积压）”“记录”几节：
对照探测的成功率与失败时段、汇总程序逐条核对的几条不变量、连接速率、起止与中断、启动积压、
证据库是否有超限未保存的证据、快照是否按期抓取、被排除的条目数，并与 fieldtest 自带的 summary.json 交叉核对。

用法：
    python3 m_instrument.py --db <sqlite> --out <目录> [--markdown] [--summary <summary.json>]
    python3 m_instrument.py --selftest

只读 ingest.py 建好的库（mode=ro，临时表都建在 TEMP 库里），结果写到 <目录>/instrument.json。
每个数字都给分子、分母和口径；百分比保留一位小数。输出前按 SCHEMA.md 的可输出列白名单检查用到的列，
写出前再对文本做一次“不许出现地址和 judge 身份”的断言（最后一道保险，不是放行手段）。

口径与官方汇总程序（internal/summary/summary.go、derive.go）的对应关系写在各函数注释里；
PROTOCOL 没说清的地方，取的解释都写在 DEFINITIONS 和注释里。

设计要点（真实数据有一千多万条 att，每行约 1.2 KB，SCHEMA“坑”19）：
- att 整表（或整个 nonce 索引）只扫三遍，每遍都把结果落成 TEMP 小表，之后只查小表：
  1. denominators()：按分钟 × cand_kind 计数（att_min，几千行），分母和连接速率都从它算；
  2. build_reconciliation()：带 nonce、目的地 judge 的尝试与 judge 的 req 按 nonce 关联（aj），全部不变量从它算；
  3. evidence()：证据哈希按 (哈希, cand_kind) 计数（ev_raw → ev_ref），缺失与孤儿文件都从它算。
  其余对 att 的访问都走索引（control:* 按 att(cand, ts_epoch) 范围扫描；运行段末尾按 att(ts_epoch) 取 MAX；
  judge 多出的 nonce 按 att(nonce) 逐个查）。任何相关子查询里都不许整表扫 att：自检用 EXPLAIN QUERY PLAN 逐条核对，
  并核对整表扫描恰好三遍（DB.check_plans）。中间结果放 TEMP 表（temp_store=FILE），内存由 SQLite 页缓存主导。
- 仪器核对看的是整份数据（含试运行）：仪器在任何时段出错都要知道。正式起点只用来给“启动积压”定小时编号。
"""
import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import tempfile

MODULE = "m_instrument"
JUDGE_LAG_S = 10          # judge 每 2 秒落盘；judge 最后一条记录前 10 秒之内的成功尝试不算“judge 没收到”（summary.go judgeHorizon；HANDOFF“坑”）
CONTROL_PERIOD_S = {"control:loopback": 60, "control:public": 60, "control:observer": 300}  # prober.go controlLoop：每分钟一轮，观察者每 5 轮一次
STAT_PERIOD_S = 300       # prober.go housekeeping：每 5 分钟一条 stat
STAT_GAP_FACTOR = 1.5     # 间隔超过 5 分钟 × 1.5 的 stat 空洞算疑似中断（解释：ticker 抖动不会超过这个倍数）
CONTROL_GAP_FACTOR = 3    # 同一对照项两次之间超过周期 × 3 算“对照没按时运行”
IDLE_GAP_MIN = 5          # 运行期间连续 5 分钟没有任何连接算空闲空洞（疑似卡住）
AGG_PERIOD_S = 6 * 3600   # prober.go snapshotLoop：聚合器每 6 小时抓一次（抽样失败时下个常规周期重试）
NSNAP_DEFAULT_MIN = 30    # cfg.Default() Nodes.SnapshotMin；节点配置不写进 start 记录，只能按默认值估期望
P90_FLAG = 2.0            # 复测间隔比的 p90 超过它的小时单独列出（实际间隔超过计划的两倍）：中位数正常不等于没有长尾
RECOVER_BAND = (0.9, 1.1) # 复测间隔“实际/计划”比值的中位数落在这个区间算恢复正常
RECOVER_MIN_PAIRS = 5     # 一个小时里至少有这么多对探访才拿它判断恢复
DENSE_THRESHOLD = 100     # PROTOCOL 1.2“候选密集的地址段”：候选超过它的 /24，与其他模块同一条线、同一口径（决策 D14）
MAX_LIST = 300            # 失败时段、空洞等列表最多列出的条数
DEFAULT_CONN_PER_SEC = 40.0   # cfg.Default() Probe.ConnPerSec；start.probe 里没有这一项时用它（并标 from_default）
DEFAULT_SNAPSHOT_MIN = 10     # cfg.Default() Probe.SnapshotMin
# TLS 校验通过之后 HTTP 阶段的“内容层”失败类别（attempt.go fetchJudge、wire.Get）：钉扎通过的隧道里不该出现。
# 其余 http_<NetClass>（timeout / eof / reset / unreach / refused / other）是连接层，代理随时可以断开连接。
HTTP_CONTENT_CLASSES = ["http_status", "http_body_mismatch", "http_malformed"]


def http_content_level(cls):
    return cls in HTTP_CONTENT_CLASSES or (cls or "").startswith("http_canary_")

# derive.go sentHeaders：探测器自己发出的请求头（值来自 wire.BuildRequest / wire.UA）。Cookie 与 X-Probe-Canary 的值因请求而异，单独比较。
SENT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "close",
    "Cookie": "",
    "X-Probe-Canary": "",
}
TAMPER_NAMES = ["canary_missing", "canary_changed", "cookie_missing", "cookie_changed",
                "user_agent_missing", "user_agent_changed", "accept_missing", "accept_changed",
                "accept_language_missing", "accept_language_changed", "accept_encoding_missing", "accept_encoding_changed",
                "method_changed"]
# summary.go warnings() 里各条自动检查的开头；交叉核对时只按开头归类，不抄警告原文（原文可能含路径或列表 URL）
WARNING_PREFIXES = ["经回环访问 judge", "从本机访问自己的公网地址", "直连第二观察者全部失败", "已探访", "经代理能到第二观察者",
                    "曾经可用的候选", "列表 ", "订阅 ", "仪器异常", "探测器认为成功，但 judge 没收到请求", "judge 的日志里没有",
                    "最近一轮节点探测出错", "最近一轮探测了", "已经见到", "运行中的错误"]
# summary.go 里与仪器有关的 findings（只读 attempts / candidates 两个计数字段）
INSTRUMENT_FINDINGS = ["探测器认为成功，但 judge 没收到请求", "仪器异常：TLS 内的请求到达 judge 时与发出时不同",
                       "仪器异常：节点探测的流量从本机直接出去了", "响应头里回显的地址与 judge 日志不一致", "同一请求被 judge 收到多次（重放）"]

# 本模块会进入输出（作为维度或被聚合的值）的列。连接键（att.nonce、req.nonce、att.cand、visit.cand、evidence.hash、self_ips.ip 等）
# 只在库内做 JOIN / 判等，不进入输出，所以不在这里。
OUTPUT_COLUMNS = {
    "att": ["proto", "dst", "kind", "arm", "class", "tls_ok", "cand_kind", "ts_epoch", "http_len", "http_pre"],
    "req": ["tls", "hello_fp", "method", "req_canary", "ts_epoch"],
    "req_header": ["name"],
    "tls_fail": ["hello_fp", "ts_epoch"],
    "noise": ["ts_epoch"],
    "req_dropped": ["n", "ts_epoch"],
    "noise_dropped": ["n", "ts_epoch"],
    "npre": ["round", "class", "tcp_ok", "ts_epoch"],
    "nround": ["round", "known", "listed", "supported", "backoff", "tcp_ok", "probed", "ok_strict", "ok_linked", "bad_config",
               "batches", "ms", "ts_epoch"],
    "stat": ["up_min", "visits", "records", "ts_epoch"],
    "stat_pool": ["key", "value", "ts_epoch"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["visits", "ts_epoch"],
    "version": ["version", "ts_epoch"],
    "error": ["what", "ts_epoch"],
    "visit": ["group", "state", "next_min", "aborted", "ts_epoch"],
    "snap": ["src", "label", "status", "base", "agg", "changed", "n", "ts_epoch"],
    "nsnap": ["src", "status", "base", "changed", "n", "ts_epoch"],
    "agg_sample": ["src", "sample", "ts_epoch"],
    "evidence": ["ext", "bytes"],
    "files": ["name", "prefix", "hour", "compressed", "status", "records", "bad_lines"],
    "file_kind": ["k", "n"],
    "misc": ["k"],
    "bad_line": ["why"],
    "meta": ["records_by_kind", "first_ts", "last_ts", "duplicate_hour_files", "unknown_fields", "misplaced_kinds",
             "judge_leaf_observed_count", "judge_leaf_tls_ok_extra_count", "payload_len", "state_tz_offsets", "evidence_files",
             "evidence_bytes", "summary_json", "ingest_version"],
}

DEFINITIONS = {
    "对照成功率": "对照组尝试（att.cand 为 control:*，不经代理直接访问）里 class='ok' 的比例，按对照项（cand × dst）分列；跳过 class 含 canceled 的"
              "（程序退出时没发起连接，summary.go attempt() 也跳过）。PROTOCOL“对照与自检”；对应 summary.go Control",
    "对照的期望次数": "prober.go controlLoop：每次启动立即一轮，之后每分钟一轮；回环与公网各 HTTP、HTTPS 一次，第二观察者每 5 轮一次。"
               "期望次数 = 各运行段 floor(时长/周期)+1 之和；运行段见“运行段与中断”。实际/期望明显小于 1 说明探测器停过或卡过",
    "对照失败时段": "同一对照项按时间排序，连续非 ok 的尝试合成一段（起止取整到分钟，给次数和失败类别）。回环对照失败的时段里代理的失败不算“死亡”"
               "（PROTOCOL“对照与自检”），这里另给回环两项合并后的失败时段供其他模块排除。PROTOCOL 没定这种时段的边界，给两种取法："
               "loopback_fail_spans 按分钟取并集（止点是最后一次失败所在的分钟，不含失败之后、下一次成功之前的空档）；"
               "loopback_fail_spans_to_next_ok 从每次失败到该项下一次成功为止（之后没有成功的到所在运行段的段末），起点向下、止点向上取整到分钟。"
               "排除代理失败时建议用后者",
    "对照没按时运行": "同一对照项相邻两次尝试间隔超过周期 × 3；空洞里有已知中断的端点（段末或下一条 start）、或有任何一条 start 的标为“重启解释”"
               "（含没有 stop 的崩溃重启），其余是无记录的停顿",
    "不变量·judge 收到": "探测器 class='ok'、带 nonce、目的地是 judge（dst judge_tls / judge_http）的尝试，judge 的 req 里必须有同一 nonce。"
                   "只核对 ts 早于“judge 最后一条记录前 10 秒”的尝试（judge 每 2 秒落盘，summary.go judgeHorizon）；之后的记为“余量内无法判定”。"
                   "PROTOCOL“对照与自检·不变量”；对应 summary.go “探测器认为成功，但 judge 没收到请求”",
    "不变量·TLS 内请求一致": "TLS 校验通过（att.tls_ok=1）、class='ok'、到 judge_tls 且 judge 收到的尝试，judge 记下的请求必须与探测器发出的完全一致："
                     "照 derive.go Derive：方法是 GET；User-Agent / Accept / Accept-Language / Accept-Encoding 与发出的相同；Cookie 为 pc=<金丝雀>"
                     "（req_canary='ok' 时用 X-Probe-Canary 头的值当金丝雀；不是 ok 时 Cookie 无法单独判定，并入金丝雀项）；X-Probe-Canary 核对为 ok；"
                     "没有多出任何头（Host 除外，Connection 缺失不算）。判“被改”的任何一项或多出任何头都算违反。"
                     "对应 summary.go “仪器异常：TLS 内的请求到达 judge 时与发出时不同”（它的条件是 Tamper 非空或 AddedReq 非空或指纹不同；这里把指纹单列）",
    "不变量·ClientHello 指纹": "TLS 校验通过、到 judge_tls、judge 收到的尝试，judge 看到的 ClientHello 指纹（req.hello_fp）必须等于直连对照时的指纹"
                       "（基线 = control:* 到 judge_tls 成功尝试对应 req 的 hello_fp 集合，应恰好 1 个；summary.go baseFP）。列出不同的指纹及次数。"
                       "另给全部 TLS 请求和 tls_fail 的指纹分布作参考（后者多是扫描器）",
    "不变量·节点出口不是本机": "节点（proto='node'）class='ok' 且 judge 收到的尝试（judge_tls 与 judge_http 都算），judge 看到的对端地址"
                        "（req.remote，最早到达的一份）不能是探测器所在机器的地址。本机地址 = self_ips 里 start.judge_ip（配置的公网 IP，"
                        "summary.go selfIPs 只用它）、judge_remote:control:public（judge 日志里公网对照的对端地址，即本机出去的流量 judge 看到的地址，"
                        "云主机做 NAT 时是内网地址）、judge_remote:control:loopback（回环）。只用 start.judge_ip 时 NAT 主机上这条永远不会触发，"
                        "所以公网对照经过 NAT 而本机地址里缺实测对端地址时标为“无法判定”（determinable=false），不报 0 违反。"
                        "judge_remote_public_equals_judge_ip 是 NAT 信号（false = 经过 NAT）。违反说明流量没走节点。只输出计数，不输出地址",
    "不变量·回显与日志一致": "judge 在响应头 X-Judge-Remote 里回显的对端地址（att.ip）必须等于 judge 日志里同一 nonce 的 remote。"
                      "对应 summary.go “响应头里回显的地址与 judge 日志不一致”。PROTOCOL“指标定义·出口地址”说回显只用来和日志互相核对",
    "不变量·对照请求原样到达": "对照组（不经代理）的成功尝试，judge 记下的请求必须与发出的一致、没有多出的头、同一 nonce 只收到一次、对端地址是本机。"
                       "这是对仪器自身（探测器 + judge）的检查：对照组都不一致，就不能拿 judge 的记录判代理",
    "不变量·配置唯一": "多条 start 记录里 judge 主机名、judge 公网 IP、三种载荷的期望哈希应各只有一个取值（中途改配置会留下不同的值）。只输出 DISTINCT 个数",
    "连接速率": "真正发起过连接的记录数：class 不含 canceled 的 att（canceled 在排队领配额时放弃，没有连接）加上有 tcp 对象的 npre（没有 tcp 对象的预检没发起连接：DNS 失败、"
             "skip_ipv6、skip_not_public、canceled）。按分钟和按 10 分钟分桶，峰值与平均都换算成每秒，与 start.probe.conn_per_sec（配置 40 条/秒）比较。"
             "注意 npre 的 ts 在排队领配额之前就记下了（nodes.go precheck 先建 NPreRec 再 Lim.Wait），att 的 ts 在领到配额之后（attempt.go Run），"
             "所以 npre 这部分最多会提前一个排队时长落到前一个桶里；att 的排队时间不算进 ms。summary.go Rate 只数 att，这里另算一份同口径的作交叉核对。"
             "PROTOCOL“频率与限速”",
    "运行段与中断": "start 记录（prober.Run 写，字段 resumed_candidates、load_err、http_port、https_port、probe、payload_sha256）到段末为一个运行段。"
              "段末 = 其后（下一条 start 之前）第一条 stop（字段 visits）；没有 stop 的（进程被杀、OOM、断电：prober.Run 只在 ctx 结束后正常退出时才写 stop）"
              "取本段里探测器写的最后一条记录（att / visit / stat / npre / nround / nerr / error / snap / nsnap / agg_sample 的最大 ts；judge 是另一个进程，不算），"
              "并标 ended_by_stop=false。中断 = 段末到下一条 start。PROTOCOL“正式测量的起止”写的是“两次 stop 与 start 之间”，那是按正常停止写的，"
              "崩溃重启没有 stop，这里推广为段末。运行时长按段末算。resumed_candidates=0 的 start 说明状态被清空。版本号在单独的 version 记录里"
              "（cmd/fieldtest/main.go 写，紧接在 start 之前），应只有一个取值",
    "stat 空洞": "stat 记录每 5 分钟一条（prober.go housekeeping）加正常停止时一条；相邻两条间隔超过 5 分钟 × 1.5 的算空洞。空洞里有已知中断的端点或任何一条 start 的标为“重启解释”，"
              "其余是无记录的中断或进程卡住。另核对 stat.up_min 与“stat 时刻 − 本段 start 时刻”是否一致（差超过 1 分钟算异常）",
    "空闲空洞": "运行段内连续 5 分钟以上没有任何连接记录（按分钟计数表），也是疑似卡住的信号；对照探测每分钟都有连接，正常运行时不该出现",
    "复测间隔比": "同一候选相邻两次非 aborted 探访的实际间隔 ÷ 前一次 visit 的 next_min（计划间隔，含 ±10% 随机浮动），按前一次探访所在的小时（自正式起点起算）"
             "和探访后的状态（visit.state：working / open / dead）分组取中位数和 p90。next_min=0（不再探访）的不算；两次探访之间有一条 start（重启，含没有 stop 的崩溃重启）"
             "的对子不算（中断不是积压）；第一次探访早于正式起点的对子不算（pairs_before_formal_start_excluded，单位是对子；visits_before_formal_start 是探访条数）。"
             "恢复的小时 = 最后一个“至少 5 对且中位数在 [0.9, 1.1] 之外”的小时 + 1（PROTOCOL“已知局限”说积压“之后恢复正常”，恢复后应持续正常）；"
             "没有区间外的小时为 0；hours_out_of_band 列出区间外的小时供核对；hours_p90_over_2 列出对子数够数、p90 超过 2（实际间隔超过计划的两倍）的小时，"
             "中位数正常不等于没有长尾",
    "节点轮次时长": "nround.ms 换算成分钟；轮次编号在重启后从 1 重新开始，所以按运行段编号列出。PROTOCOL“频率与限速”（每 60 分钟一轮）",
    "证据库缺失": "att.ev（证书链，evidence/<前两位>/<哈希>.der）和 att.http_ev（正文，.body）引用的哈希在 evidence 表（数据目录里实际存在的文件）里找不到的个数。"
             "证据库有上限（每个候选最多 12 份、总共 1 GB，rec.Evidence.Put 超限不保存），找不到的就是超限未保存的。"
             "另给孤儿文件数：evidence 里有、att 里没有任何引用的（.der 对 att.ev，.body 对 att.http_ev）。只输出个数，不输出哈希",
    "快照完整性": "每个列表文件（来源 × 标签）的抓取次数、失败次数（err 非空或 status 不是 200/304，summary.go snapLine）、304 次数、有变化次数、首次快照（base）次数。"
             "期望次数：常规列表每 snapshot_min 分钟一次（start.probe.snapshot_min，默认 10），每个运行段 floor(时长/间隔)+1；聚合器每 6 小时一次，每段 floor(时长/6h)+1"
             "（抽样没成功时会在下个常规周期重试，所以实际可以多于期望）；订阅每 30 分钟一次（节点配置不在记录里，按 cfg.Default 的 30 分钟）",
    "启动时的候选池": "正式起点之后第一条 stat 记录里的 pool（sched.go Pool 的计数：total 是池里的条目数，new 是还没探访过的），"
                "以及正式起点之后 pool.total 的最大值。状态文件从空开始时，首次快照后的条目都在 new 里排队等第一次探访",
    "被排除的条目": "stat.pool 里 skipped_<原因> 的值：判为不探测的上榜条目数（judge 自己的地址、私网地址、知名端口、退出名单、解析不了）。"
              "这是每个进程内的累计计数（sched.go Pool.Skipped 不存进状态文件），重启后归零且首次快照会把全部条目再过一遍，所以按运行段给每段最后一条 stat 的值，不跨段相加。PROTOCOL“频率与限速”",
    "测量机上的仪器自检": "fieldtest preflight 在测量机上写下的 preflight.txt（--preflight 给的文件，没给就找入库时数据目录里的那份）。"
                  "只取四样：预检时间、“仪器自检”一节核对的项数和不符的项数、sing-box 版本、结论行的失败和注意项数；"
                  "其余行（含主机名和地址）不读进输出。PROTOCOL“对照与自检”：selftest 在预检时于测量用的机器上跑一遍，有任何一项不符，数据不可信。"
                  "preflight.txt 不记探测器版本，它与正式测量是不是同一个二进制，只能按时间先后推断",
    "交叉核对": "与 fieldtest 自带 summary.json（--summary 给的文件，没给就找入库时数据目录里的那份，再没有就只用 meta.summary_json 里抄下的 records / judge）比对："
             "自动检查（warnings，按开头归类计数）、control、rate、records、judge、snapshots、nodes.subscriptions、nodes.precheck、pool、与仪器有关的 findings。"
             "summary.go 不裁窗口、按整份数据算，这里同样按整份数据算。summary 的 control 键与本模块一样把含点号的观察者名换成 obs:<观察者>；"
             "snapshots / nodes.subscriptions 只比库里也有的来源（其余只计数）",
    "交叉核对·findings 口径": "比对 findings 时按 summary.go 的口径另算一份（findings_summary_go_caliber）：五条都不含对照组（attempt() 对 control:* 在 integrity() 之前 return）；"
                        "节点出口只看 judge_tls（nodeEgress 只在 a.Dst == judge_tls 时调用），本机地址只用 start.judge_ip；TLS 内不同的指纹条件是"
                        "“最近一次对照指纹非空且本条 hello_fp 与之不等”，hello_fp 为空也算不等（summary.go 第 614 行）。"
                        "本模块各条不变量的主结果更严（对照组也查、节点 judge_http 也查、本机地址含实测对端地址），另列为 findings_module_caliber，不参与比对",
    "记录文件缺失小时": "files 表里同一前缀首末小时之间没有文件的小时。整小时落在已知中断里（或第一条 start 之前、最后一段结束之后）的标 explained_by_restart："
                  "探测器停着就不写 probe- / snap-，judge 也收不到对照请求",
    "参考·TLS 通过后 HTTP 失败": "att.tls_ok=1、到 judge_tls、class 不是 ok（也不含 canceled）的尝试，按类别计数。内容层（http_status、http_body_mismatch、http_malformed、"
                           "http_canary_*）在钉扎通过的隧道里不该出现，非 0 就是仪器或 judge 的异常信号。http_body_mismatch 里收到的正文恰为期望正文前缀的"
                           "（代理提前断开）另计为 body_truncated、不算内容层：这个细分是 72 小时实测结束、看过数据以后加的（决策 D14，引用时标“事后”），"
                           "按原定义内容层 = content_level + body_truncated；连接层（http_timeout / http_eof / http_reset 等）代理随时可以造成，只作参考。"
                           "PROTOCOL 不变量说的是“TLS 校验通过的请求”，几条不变量只核对了 class='ok' 的，这一项补上其余的；summary.go integrity 对非 ok 直接跳过",
    "百分比": "100 × 分子 / 分母，保留一位小数；分母为 0 时为 null。每个比例都同时给出分子、分母",
}


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


def iso_minute_ceil(epoch):
    """向上取整到分钟（区间止点用，保证按分钟列出的区间覆盖整个时段）。"""
    if epoch is None:
        return None
    e = float(epoch)
    return iso_minute(e if e % 60 == 0 else (e // 60 + 1) * 60)


def iso_hour(epoch):
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:00Z")


def fmt(v, suffix=""):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:,.1f}{suffix}"
    return f"{v:,}{suffix}"


def rfmt(r):
    return f"{fmt(r['num'])}/{fmt(r['den'])}（{fmt(r['pct'], '%')}）"


def sql_in(values):
    return ", ".join("'%s'" % v.replace("'", "''") for v in values)


# 比较值的请求头（rh 表的列名 → 头名）
HEADER_COLS = [("cookie", "Cookie"), ("canary_hdr", "X-Probe-Canary"), ("ua", "User-Agent"),
               ("accept", "Accept"), ("alang", "Accept-Language"), ("aenc", "Accept-Encoding")]


def last_header_cols():
    """rh 表里各比较头的取值：同名头出现多次时取最后一个，照 derive.go Derive 的 got[k] = v 逐个覆盖。
    seq 是头在 judge 记录里的位置；补成 10 位定长前缀后取 MAX 就是最后一个，再去掉前缀。
    （原来写的是 MAX(value)，同名头重复、值不同时取到的是字典序最大的那个，与 derive.go 不一致）"""
    return ",\n".join("substr(MAX(CASE WHEN h.name = '%s' THEN printf('%%010d', h.seq) || h.value END), 11) AS %s" % (name, col)
                       for col, name in HEADER_COLS)


ADDR_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?")
NODEID_RE = re.compile(r"\b[0-9a-f]{12}\b")


def norm_what(what):
    """error.what 虽在白名单里，但 Env.Panic 会把候选地址拼进去（prober.go dispatch：“程序错误: 探访 192.0.2.1:8080”；
    nodes.go：“程序错误: 节点预检 <id>”“节点探测 <id>”，id 是 12 位十六进制，nodes/link.go），输出前归一化。
    这条规则本该在 ingest 里统一做（派生列加 what 移出白名单），那是 ingest.py 的改动，不在本模块；在那之前本模块自己归一化，
    assert_clean 再兜一次底。"""
    if what is None:
        return "(空)"
    s = ADDR_RE.sub("<候选>", str(what))
    s = NODEID_RE.sub("<节点>", s)
    return s[:80]


def safe_dst(dst):
    """att.dst 的 obs:<名> 是配置里的观察者名；万一有人把主机名当名字，输出前换成编号（OUTPUT_RULES att.dst）。"""
    if dst and dst.startswith("obs:") and "." in dst:
        return "obs:<观察者>"
    return dst


_SQL_KEYWORDS = {"WHERE", "LEFT", "JOIN", "INNER", "CROSS", "GROUP", "ORDER", "ON", "USING", "LIMIT", "UNION", "AS", "NATURAL"}
PLAN_SCAN_RE = re.compile(r"^SCAN (\w+)\b")
PLAN_OPEN_RANGE_RE = re.compile(r"^SEARCH (\w+) USING (?:COVERING )?INDEX \w+ \(\w+>\?\)$")


OBS_KEY_RE = re.compile(r" (obs:\S+)")


def norm_control_key(name):
    """对照项名 “<cand> <dst>” 里的 obs:<名> 照 safe_dst 归一化（交叉核对时用于 summary.json 的 control 键）。"""
    return OBS_KEY_RE.sub(lambda m: " " + safe_dst(m.group(1)), str(name))


class DB:
    def __init__(self, path, check_plans=False):
        self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        self.con.execute("PRAGMA cache_size = -262144")  # 256 MB 页缓存，内存不随记录数增长
        self.con.execute("PRAGMA temp_store = FILE")
        # 自检用：每条语句执行前先 EXPLAIN QUERY PLAN，记下整表扫 att 的语句和“相关子查询里整表扫 att”的语句
        self.check_plans = check_plans
        self.att_full_scans = []        # [(语句开头, 计划行)]
        self.correlated_att_scans = []  # 同上；应为空

    def _plan(self, sql, params):
        try:
            rows = self.con.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
        except sqlite3.Error:
            return
        # att 在这条语句里的名字：表名本身加上别名（计划里写别名）
        names = {"att"}
        for alias in re.findall(r"\b(?:FROM|JOIN)\s+att\s+(?:AS\s+)?([A-Za-z_]\w*)", sql, flags=re.I):
            if alias.upper() not in _SQL_KEYWORDS:
                names.add(alias)
        detail = {r[0]: r[3] for r in rows}
        parent = {r[0]: r[1] for r in rows}
        head = " ".join(sql.split())[:90]
        for nid, d in detail.items():
            # 整表扫描，或只有一个开区间下界的索引扫描（例如 att_nonce (nonce>?) 是把整个 nonce 索引走一遍）
            m = PLAN_SCAN_RE.match(d) or PLAN_OPEN_RANGE_RE.match(d)
            if not m or m.group(1) not in names:
                continue
            p, correlated = parent.get(nid), False
            while p:
                if detail.get(p, "").startswith("CORRELATED"):
                    correlated = True
                p = parent.get(p)
            (self.correlated_att_scans if correlated else self.att_full_scans).append((head, d))

    def _exec(self, sql, params):
        if self.check_plans:
            self._plan(sql, params)
        return self.con.execute(sql, params)

    def q(self, sql, params=()):
        return self._exec(sql, params).fetchall()

    def one(self, sql, params=()):
        return self._exec(sql, params).fetchone()

    def scalar(self, sql, params=()):
        row = self.one(sql, params)
        return row[0] if row else None

    def x(self, sql, params=()):
        self._exec(sql, params)

    def has_table(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)) > 0

    def columns(self, table):
        return [r[1] for r in self.q('PRAGMA table_info("%s")' % table)]

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))

    def meta_json(self, key):
        v = self.meta(key)
        if v is None:
            return None
        try:
            return json.loads(v)
        except ValueError:
            return None


def check_whitelist(db):
    """输出前按白名单核对本模块用到的列。优先用同目录 ingest.py 的权威常量，拿不到就读库里的 meta.output_whitelist。"""
    wl = None
    source = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import ingest  # noqa: E402
        wl = ingest.OUTPUT_WHITELIST
        source = "ingest.OUTPUT_WHITELIST"
    except Exception:
        raw = db.meta("output_whitelist")
        if raw:
            wl = json.loads(raw)
            source = "meta.output_whitelist"
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


# ---------------------------------------------------------------- 运行段、中断、正式起点

# 探测器进程（fieldtest probe）写的、带 ts_epoch 的记录表。judge 是另一个进程（deploy/fieldtest-judge.service），
# 它的记录不说明探测器还活着，所以不在这里。version 由 main.go 在 start 之前写，也不算。
PROBER_TS_TABLES = ("att", "visit", "stat", "npre", "nround", "nerr", "error", "stop", "snap", "nsnap", "agg_sample")


def last_prober_record(db, t0, t1):
    """[t0, t1) 里探测器写的最后一条记录的时刻（t1 为 None 表示到数据结束）；没有就返回 t0（start 本身）。
    att / visit / stat / npre 有 ts_epoch 索引，MAX 只读索引的一端；其余是小表。"""
    best = t0
    for t in PROBER_TS_TABLES:
        if not db.has_table(t) or "ts_epoch" not in db.columns(t):
            continue
        if t1 is None:
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s WHERE ts_epoch >= ?" % t, (t0,))
        else:
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s WHERE ts_epoch >= ? AND ts_epoch < ?" % t, (t0, t1))
        if v is not None and v > best:
            best = v
    return best


def segments_and_window(db, formal_start_arg):
    """运行段、中断、版本、正式起点。
    运行段 = 一条 start 到段末；段末 = 其后（下一条 start 之前）第一条 stop，没有 stop 的（进程被杀、OOM、断电，
    prober.Run 只在 ctx 结束后正常退出时才写 stop）取本段里探测器写的最后一条记录。中断 = 段末 → 下一条 start。
    PROTOCOL“正式测量的起止”写的是“两次 stop 与 start 之间”，那是按正常停止写的；崩溃重启没有 stop，正是最需要写明的中断，
    所以这里把中断的起点推广为段末，并用 ended_by_stop 区分两种。
    正式起点的规则与 m_availability 相同（PROTOCOL“正式测量的起止”）：第一条 start；之后有 resumed_candidates=0 的 start 取最后一次；
    版本变过取变化之后的第一条 start。"""
    starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0) FROM start ORDER BY ts_epoch, rid") if db.has_table("start") else []
    stops = db.q("SELECT ts_epoch, visits FROM stop ORDER BY ts_epoch, rid") if db.has_table("stop") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch, rid") if db.has_table("version") else []
    ends = []
    for t in ("att", "visit", "stat", "stop", "npre", "req"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None
    firsts = []
    for t in ("att", "visit", "stat", "start"):
        if db.has_table(t):
            v = db.scalar("SELECT MIN(ts_epoch) FROM %s" % t)
            if v is not None:
                firsts.append(v)
    first = min(firsts) if firsts else None

    segs = []
    for i, (s, resumed) in enumerate(starts):
        nxt_start = starts[i + 1][0] if i + 1 < len(starts) else None
        stop_after = [x for x in stops if x[0] >= s and (nxt_start is None or x[0] < nxt_start)]
        if stop_after:
            e, visits = stop_after[0]
        else:
            e, visits = last_prober_record(db, s, nxt_start), None
        segs.append({"idx": i + 1, "start": s, "end": e, "resumed_candidates": int(resumed), "has_stop": bool(stop_after),
                     "stop_visits": visits})
    if not segs and first is not None and end is not None:
        segs.append({"idx": 1, "start": first, "end": last_prober_record(db, first, None), "resumed_candidates": None,
                     "has_stop": False, "stop_visits": None, "note": "没有 start 记录，按数据首末时间当一个运行段"})

    interruptions = []
    for i in range(len(starts) - 1):
        interruptions.append({"from": segs[i]["end"], "start": starts[i + 1][0], "ended_by_stop": segs[i]["has_stop"]})

    rule = []
    fs = None
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
            after = [s[0] for s in starts if s[0] >= change - 1]
            if after and after[0] > fs:
                fs = after[0]
                rule.append("版本变过：取最后一次版本变化之后的第一条 start")
    else:
        fs = first
        rule.append("没有 start 记录：取数据里最早的记录")
    if formal_start_arg and formal_start_arg != "auto":
        if formal_start_arg == "first":
            fs = starts[0][0] if starts else first
            rule = ["--formal-start first"]
        else:
            s = formal_start_arg.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            t = dt.datetime.fromisoformat(s)
            if t.tzinfo is None:
                raise SystemExit("--formal-start 必须带时区")
            fs = t.timestamp()
            rule = ["--formal-start 指定"]

    uptime = sum((sg["end"] - sg["start"]) for sg in segs if sg["end"] is not None)
    window = {
        "first_record_utc": iso_minute(first), "last_record_utc": iso_minute(end),
        "span_hours": round((end - first) / 3600.0, 2) if (first is not None and end is not None) else None,
        "formal_start_utc": iso_minute(fs), "formal_start_rule": "；".join(rule),
        "formal_hours": round((end - fs) / 3600.0, 2) if (fs is not None and end is not None) else None,
        "starts": [{"utc": iso_minute(s), "resumed_candidates": int(r)} for s, r in starts],
        "stops": [{"utc": iso_minute(s), "visits": v} for s, v in stops],
        "versions": sorted({v for _, v in versions}), "version_records": len(versions),
        "version_unique": len({v for _, v in versions}) <= 1,
        "segments": [{"idx": sg["idx"], "start_utc": iso_minute(sg["start"]), "end_utc": iso_minute(sg["end"]),
                      "minutes": round((sg["end"] - sg["start"]) / 60.0, 1) if sg["end"] is not None else None,
                      "resumed_candidates": sg["resumed_candidates"], "ended_by_stop": sg["has_stop"],
                      "end_rule": "stop 记录" if sg["has_stop"] else "本段探测器写的最后一条记录（没有 stop）",
                      "stop_visits": sg["stop_visits"]}
                     for sg in segs],
        "segments_without_stop": sum(1 for sg in segs if not sg["has_stop"]),
        "last_segment_ended_by_stop": segs[-1]["has_stop"] if segs else None,
        "interruptions": [{"from_utc": iso_minute(i["from"]), "start_utc": iso_minute(i["start"]),
                           "minutes": round((i["start"] - i["from"]) / 60.0, 1), "ended_by_stop": i["ended_by_stop"]}
                          for i in interruptions],
        "interruptions_without_stop": sum(1 for i in interruptions if not i["ended_by_stop"]),
        "interruption_minutes_total": round(sum((i["start"] - i["from"]) for i in interruptions) / 60.0, 1),
        "uptime_minutes_total": round(uptime / 60.0, 1),
        "state_cleared_restarts": sum(1 for s in starts[1:] if s[1] == 0),
        "_segs": segs, "_interruptions": interruptions, "_starts": [s for s, _ in starts], "_fs": fs, "_end": end, "_first": first,
    }
    return window


def expected_runs(segs, period_s):
    """各运行段 floor(时长/周期)+1 之和：定时循环“启动立即一次、之后每周期一次”的期望次数。"""
    n = 0
    for sg in segs:
        if sg["end"] is None:
            continue
        n += int((sg["end"] - sg["start"]) // period_s) + 1
    return n


def explained_by_restart(W, t0, t1):
    """空洞 [t0, t1] 能不能由重启解释：里面有某个中断的起点（段末：stop 或崩溃前最后一条记录）或终点，
    或者 (t0, t1] 里有任何一条 start（崩溃重启没有 stop，但一定有 start）。两端各留 1 秒余量（stat 与 stop 只差几毫秒）。"""
    for i in W["_interruptions"]:
        if t0 - 1 <= i["from"] <= t1 + 1 or t0 - 1 <= i["start"] <= t1 + 1:
            return True
    return any(t0 < s <= t1 + 1 for s in W.get("_starts", []))


def in_interruption(W, t0, t1):
    """[t0, t1) 整段落在某个中断（段末 → 下一条 start）里，或在第一条 start 之前 / 最后一段结束之后（探测器没在运行）。"""
    for i in W["_interruptions"]:
        if i["from"] <= t0 and t1 <= i["start"]:
            return True
    segs = W["_segs"]
    if segs and (t1 <= segs[0]["start"] or (segs[-1]["end"] is not None and t0 >= segs[-1]["end"])):
        return True
    return False


def segment_of(segs, ts):
    """ts 属于哪个运行段：start 不晚于 ts 的最后一段（停止时写的 stat 与下一条 start 只差几毫秒，所以不留正向余量）。"""
    found = None
    for sg in segs:
        if sg["start"] <= ts + 0.0005:
            found = sg
    return found


def quantiles(values, qs=(0.5, 0.9, 0.99)):
    """最近秩法的分位数（与 summary.go Latency 的取法一致：v[min(n-1, int(q*n))]）。"""
    v = sorted(values)
    if not v:
        return [None for _ in qs]
    return [v[min(len(v) - 1, int(q * len(v)))] for q in qs]


# 控制组的 cand 只有三种写法（prober.go controlLoop）；按前缀做范围扫描能用 att(cand, ts_epoch) 索引
CONTROL_RANGE = "cand >= 'control:' AND cand < 'control;' AND cand_kind = 'control'"


# ---------------------------------------------------------------- 对照

def controls(db, W):
    """summary.go Control：对照项 = cand + ' ' + dst，ok / total。另给期望次数、失败时段、没按时运行的空洞。"""
    segs = W["_segs"]
    rows = db.q("""SELECT cand, dst, class, COUNT(*) FROM att
                   WHERE %s AND class NOT LIKE '%%canceled%%' GROUP BY 1, 2, 3 ORDER BY 1, 2, 3""" % CONTROL_RANGE)
    items = {}
    for cand, dst, cls, n in rows:
        key = "%s %s" % (cand, safe_dst(dst))
        it = items.setdefault(key, {"cand": cand, "dst": safe_dst(dst), "total": 0, "ok": 0, "classes": {}})
        it["total"] += n
        it["classes"][cls] = int(n)
        if cls == "ok":
            it["ok"] += n
    for key, it in items.items():
        period = CONTROL_PERIOD_S.get(it["cand"])
        it["成功率"] = ratio(it["ok"], it["total"])
        it["period_s"] = period
        exp = expected_runs(segs, period) if period else None
        it["期望次数"] = exp
        it["实际/期望"] = round(it["total"] / exp, 3) if exp else None
        del it["total"], it["ok"]

    # 失败时段：gaps-and-islands，按对照项
    db.x("""CREATE TEMP TABLE ctl AS
            SELECT rid, cand, dst, ts_epoch, class, (class = 'ok') AS ok,
                   ROW_NUMBER() OVER (PARTITION BY cand, dst ORDER BY ts_epoch, rid) AS rn,
                   ROW_NUMBER() OVER (PARTITION BY cand, dst, (class = 'ok') ORDER BY ts_epoch, rid) AS rn_ok,
                   LAG(ts_epoch) OVER (PARTITION BY cand, dst ORDER BY ts_epoch, rid) AS prev_ts
            FROM att WHERE %s AND class NOT LIKE '%%canceled%%'""" % CONTROL_RANGE)
    spans = db.q("""SELECT cand, dst, MIN(ts_epoch), MAX(ts_epoch), COUNT(*), group_concat(DISTINCT class)
                    FROM ctl WHERE ok = 0 GROUP BY cand, dst, rn - rn_ok ORDER BY 3, 1, 2""")
    fail_spans = [{"item": "%s %s" % (c, safe_dst(d)), "from_utc": iso_minute(a), "to_utc": iso_minute(b),
                   "span_minutes": round((b - a) / 60.0, 1), "attempts": int(n), "classes": sorted(cls.split(","))}
                  for c, d, a, b, n, cls in spans]
    # 回环两项（HTTP、HTTPS）合并后的失败时段：按分钟看，任一回环尝试失败的分钟算失败分钟，相邻的失败分钟合成一段
    # （两项交错出现，不能直接在行序列上做 islands）。供其他模块把这些时段里代理的失败排除
    db.x("""CREATE TEMP TABLE ctl_lo AS
            SELECT m, fails, total, m - ROW_NUMBER() OVER (ORDER BY m) AS grp FROM (
              SELECT CAST(ts_epoch / 60 AS INTEGER) AS m, SUM(ok = 0) AS fails, COUNT(*) AS total
              FROM ctl WHERE cand = 'control:loopback' GROUP BY 1)
            WHERE fails > 0""")
    lo_spans = db.q("SELECT MIN(m), MAX(m), COUNT(*), SUM(fails), SUM(total) FROM ctl_lo GROUP BY grp ORDER BY 1")
    loopback_fail = [{"from_utc": iso_minute(a * 60), "to_utc": iso_minute(b * 60), "minutes": int(n), "failed_attempts": int(f), "attempts": int(t)}
                     for a, b, n, f, t in lo_spans]
    # 另一种止点：每次回环失败到该项（同一 cand × dst）下一次成功为止，两项的区间取并集。
    # 对照每分钟一次，“我们这边坏了”严格说要持续到下一次成功；上面按分钟取并集的止点是最后一次失败所在的分钟，
    # 会漏掉失败之后、下一次成功之前那一段（最多近一分钟）。之后再也没有成功的，止点取该失败所在运行段的段末。
    lo_iv = []
    for ts, nxt_ok in db.q("""SELECT ts_epoch, nxt_ok FROM (
                                SELECT ts_epoch, ok, MIN(CASE WHEN ok = 1 THEN ts_epoch END)
                                       OVER (PARTITION BY cand, dst ORDER BY ts_epoch, rid ROWS BETWEEN 1 FOLLOWING AND UNBOUNDED FOLLOWING) AS nxt_ok
                                FROM ctl WHERE cand = 'control:loopback')
                              WHERE ok = 0 ORDER BY ts_epoch"""):
        if nxt_ok is None:
            sg = segment_of(segs, ts)
            nxt_ok = sg["end"] if sg and sg["end"] is not None and sg["end"] >= ts else ts
        lo_iv.append([ts, nxt_ok, 1])
    merged = []
    for a, b, n in sorted(lo_iv):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
            merged[-1][2] += n
        else:
            merged.append([a, b, n])
    loopback_fail_next_ok = [{"from_utc": iso_minute(a), "to_utc": iso_minute_ceil(b), "minutes": round((b - a) / 60.0, 1),
                              "failed_attempts": int(n)} for a, b, n in merged]
    # 没按时运行：相邻两次间隔 > 周期 × 3
    gaps = []
    for cand, period in CONTROL_PERIOD_S.items():
        for c, d, p, t in db.q("""SELECT cand, dst, prev_ts, ts_epoch FROM ctl
                                  WHERE cand = ? AND prev_ts IS NOT NULL AND ts_epoch - prev_ts > ? ORDER BY ts_epoch""",
                               (cand, period * CONTROL_GAP_FACTOR)):
            gaps.append({"item": "%s %s" % (c, safe_dst(d)), "from_utc": iso_minute(p), "to_utc": iso_minute(t),
                         "minutes": round((t - p) / 60.0, 1), "explained_by_restart": explained_by_restart(W, p, t)})
    gaps.sort(key=lambda g: g["from_utc"])
    total_fail_att = sum(s["attempts"] for s in fail_spans)
    return {
        "items": items,
        "fail_spans": fail_spans[:MAX_LIST], "fail_spans_count": len(fail_spans), "fail_attempts_total": total_fail_att,
        "loopback_fail_spans": loopback_fail[:MAX_LIST], "loopback_fail_spans_count": len(loopback_fail),
        "loopback_fail_minutes_total": round(sum(s["minutes"] for s in loopback_fail), 1),
        "loopback_fail_spans_rule": "按分钟取并集：任一回环尝试失败的分钟算失败分钟，相邻的合成一段；止点是最后一次失败所在的分钟",
        "loopback_fail_spans_to_next_ok": loopback_fail_next_ok[:MAX_LIST], "loopback_fail_spans_to_next_ok_count": len(loopback_fail_next_ok),
        "loopback_fail_minutes_to_next_ok_total": round(sum(s["minutes"] for s in loopback_fail_next_ok), 1),
        "loopback_fail_spans_to_next_ok_rule": "每次回环失败到该项下一次成功为止（之后没有成功的到所在运行段的段末），两项取并集；"
                                               "from_utc 向下、to_utc 向上取整到分钟，排除代理失败时用这一种更稳妥",
        "schedule_gaps": gaps[:MAX_LIST], "schedule_gaps_count": len(gaps),
        "schedule_gaps_unexplained": sum(1 for g in gaps if not g["explained_by_restart"]),
    }


# ---------------------------------------------------------------- 不变量

def truncation_want_lengths(db, kinds):
    """各载荷种类（只算 kinds 里的）的期望正文长度（BodyChange 的 wantLen）：优先 meta.payload_len（ingest 从成功尝试里数出的
    最常见长度），缺的种类取 class=ok 到达 judge 的尝试里最常见的 http_len（要扫 att，所以只在缺的时候做）。长度本身不是敏感信息。"""
    out = {}
    raw = db.meta("payload_len") if hasattr(db, "meta") else None
    if raw:
        try:
            for k, v in json.loads(raw).items():
                if isinstance(v, dict) and v.get("len"):
                    out[k] = int(v["len"])
        except (ValueError, AttributeError):
            pass
    out = {k: v for k, v in out.items() if k in kinds}
    for k in kinds:
        if k not in out:
            row = db.one("""SELECT http_len, COUNT(*) AS n FROM att
                            WHERE class = 'ok' AND dst IN ('judge_http', 'judge_tls') AND COALESCE(kind, 'h') = ? AND http_len IS NOT NULL
                            GROUP BY http_len ORDER BY n DESC LIMIT 1""", (k,))
            if row:
                out[k] = int(row[0])
    return out


def is_truncated(http_len, http_pre, want_len):
    """summary.go BodyChange：pre == gotLen 且 gotLen < wantLen 判截断。"""
    if want_len is None:
        return False
    gl, pre = int(http_len or 0), int(http_pre or 0)
    return pre == gl and gl < int(want_len)


def judge_horizon(db):
    """judge 日志最后一条记录（任何种类）前 10 秒（summary.go judgeLast / judgeHorizon）。"""
    last = None
    for t in ("req", "noise", "tls_fail", "noise_dropped", "req_dropped"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None and (last is None or v > last):
                last = v
    return (last - JUDGE_LAG_S) if last is not None else None, last


def build_reconciliation(db):
    """TEMP 表 aj：探测器带 nonce、目的地 judge 的尝试，与 judge 的 req 按 nonce 关联（derive.go Derive 取最早到达的一条）。
    请求头的派生（Tamper / AddedReq）照 derive.go 的逐头循环改写成 GROUP BY；Host 不参与。"""
    db.x("""CREATE TEMP TABLE rq_first AS
            SELECT rid, nonce, remote, COALESCE(tls, 0) AS tls, method, COALESCE(req_canary, 'missing') AS req_canary, hello_fp, ts_epoch
            FROM (SELECT rid, nonce, remote, tls, method, req_canary, hello_fp, ts_epoch,
                         ROW_NUMBER() OVER (PARTITION BY nonce ORDER BY ts_epoch, rid) AS rn
                  FROM req WHERE nonce IS NOT NULL)
            WHERE rn = 1""")
    db.x("CREATE INDEX temp.rq_first_nonce ON rq_first(nonce)")
    db.x("CREATE INDEX temp.rq_first_rid ON rq_first(rid)")
    db.x("CREATE TEMP TABLE rq_n AS SELECT nonce, COUNT(*) AS copies, COUNT(DISTINCT remote) AS n_remote FROM req WHERE nonce IS NOT NULL GROUP BY nonce")
    db.x("CREATE INDEX temp.rq_n_nonce ON rq_n(nonce)")
    sent = sql_in(SENT_HEADERS.keys())
    if db.has_table("req_header"):
        db.x("""CREATE TEMP TABLE rh AS
                SELECT h.req_rid,
                       SUM(h.name != 'Host' AND h.name NOT IN (%s)) AS n_added,
                       %s
                FROM req_header h JOIN rq_first f ON f.rid = h.req_rid
                GROUP BY h.req_rid""" % (sent, last_header_cols()))
    else:
        db.x("CREATE TEMP TABLE rh (req_rid INTEGER, n_added INTEGER, cookie TEXT, canary_hdr TEXT, ua TEXT, accept TEXT, alang TEXT, aenc TEXT)")
    db.x("CREATE INDEX temp.rh_rid ON rh(req_rid)")
    db.x("""CREATE TEMP TABLE rd AS
            SELECT f.nonce, f.rid AS req_rid, f.remote, f.tls AS req_tls, f.method, f.req_canary, f.hello_fp, f.ts_epoch AS req_ts,
                   n.copies, n.n_remote,
                   COALESCE(h.n_added, 0) AS n_added,
                   (f.req_canary = 'missing') AS t_canary_missing,
                   (f.req_canary = 'bad') AS t_canary_changed,
                   (h.cookie IS NULL) AS t_cookie_missing,
                   (h.cookie IS NOT NULL AND f.req_canary = 'ok' AND h.cookie != 'pc=' || COALESCE(h.canary_hdr, '')) AS t_cookie_changed,
                   (h.ua IS NULL) AS t_user_agent_missing,
                   (h.ua IS NOT NULL AND h.ua != ?) AS t_user_agent_changed,
                   (h.accept IS NULL) AS t_accept_missing,
                   (h.accept IS NOT NULL AND h.accept != ?) AS t_accept_changed,
                   (h.alang IS NULL) AS t_accept_language_missing,
                   (h.alang IS NOT NULL AND h.alang != ?) AS t_accept_language_changed,
                   (h.aenc IS NULL) AS t_accept_encoding_missing,
                   (h.aenc IS NOT NULL AND h.aenc != ?) AS t_accept_encoding_changed,
                   (COALESCE(f.method, '') != 'GET') AS t_method_changed
            FROM rq_first f JOIN rq_n n ON n.nonce = f.nonce LEFT JOIN rh h ON h.req_rid = f.rid""",
         (SENT_HEADERS["User-Agent"], SENT_HEADERS["Accept"], SENT_HEADERS["Accept-Language"], SENT_HEADERS["Accept-Encoding"]))
    tsum = " + ".join("t_%s" % t for t in TAMPER_NAMES)
    db.x("ALTER TABLE rd ADD COLUMN tamper INTEGER")
    db.x("UPDATE rd SET tamper = ((%s) > 0)" % tsum)
    db.x("CREATE INDEX temp.rd_nonce ON rd(nonce)")

    # 探测器侧：带 nonce、目的地 judge、非 canceled 的尝试（控制组、代理、节点都在）
    tcols = ", ".join("r.t_%s" % t for t in TAMPER_NAMES)
    db.x("""CREATE TEMP TABLE aj AS
            SELECT a.rid, a.cand, a.cand_kind, a.proto, a.dst, a.arm, a.class, a.ts_epoch, a.ip AS echo_ip,
                   COALESCE(a.tls_ok, 0) AS tls_ok, a.nonce, COALESCE(a.kind, 'h') AS pkind, a.http_len, a.http_pre,
                   (r.nonce IS NOT NULL) AS seen, r.remote, r.req_tls, r.hello_fp, r.copies, r.n_remote, r.n_added, r.tamper, %s
            FROM att a LEFT JOIN rd r ON r.nonce = a.nonce
            WHERE a.nonce IS NOT NULL AND a.dst IN ('judge_tls', 'judge_http') AND a.class NOT LIKE '%%canceled%%'""" % tcols)
    db.x("CREATE INDEX temp.aj_kind ON aj(cand_kind, class, seen)")
    db.x("CREATE INDEX temp.aj_nonce ON aj(nonce)")


# “本机出去的流量 judge 看到的地址”：start.judge_ip（配置的公网 IP，summary.go selfIPs 只用它）加上 judge 日志里对照请求的对端地址
# （ingest.fill_self_identity：judge_remote:control:public 是本机连自己公网地址时 judge 看到的源地址，做 NAT 的云主机上是内网地址；
# judge_remote:control:loopback 是回环地址）。后两者是实测值，有没有 NAT 都准确（SCHEMA“judge 的身份从哪里取”）。
SELF_IP_SOURCES = ("start.judge_ip", "judge_remote:control:public", "judge_remote:control:loopback")


def self_ip_filter(db):
    """探测器所在机器的地址。返回 (SQL 子查询, 用到的来源列表, 说明)。只用于库内判等，地址本身不输出。"""
    if not db.has_table("self_ips"):
        return None, [], "库里没有 self_ips 表"
    used = [s for s, in db.q("SELECT DISTINCT source FROM self_ips WHERE source IN (%s) ORDER BY 1" % sql_in(SELF_IP_SOURCES))]
    if used:
        return "SELECT ip FROM self_ips WHERE source IN (%s)" % sql_in(used), used, "、".join(used)
    if db.scalar("SELECT COUNT(*) FROM self_ips"):
        return "SELECT ip FROM self_ips", ["(全部)"], "self_ips 全部来源（没有 start 记录，也没有对照请求的对端地址）"
    return None, [], "self_ips 为空"


def self_ip_sets_equal(db, a, b):
    """两种来源的地址集合是否相同（只输出布尔值）；任一边没有行时为 None。"""
    if not db.has_table("self_ips"):
        return None
    sa = {r[0] for r in db.q("SELECT ip FROM self_ips WHERE source = ?", (a,))}
    sb = {r[0] for r in db.q("SELECT ip FROM self_ips WHERE source = ?", (b,))}
    if not sa or not sb:
        return None
    return sa == sb


def by_kind(db, where, params=()):
    return {k: int(n) for k, n in db.q("SELECT cand_kind, COUNT(*) FROM aj WHERE %s GROUP BY 1 ORDER BY 1" % where, params)}


def invariants(db, W):
    """六条不变量加配置唯一性。调用前要先 build_reconciliation(db) 建好 aj。"""
    horizon, judge_last = judge_horizon(db)
    out = {"judge_last_record_utc": iso_minute(judge_last), "judge_horizon_utc": iso_minute(horizon), "judge_lag_s": JUDGE_LAG_S}

    # 1. judge 收到
    den = db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok'")
    if horizon is None:
        viol = 0
        undet = db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 0")
    else:
        viol = db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 0 AND ts_epoch < ?", (horizon,))
        undet = db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 0 AND ts_epoch >= ?", (horizon,))
    out["judge_received"] = {
        "violations": int(viol), "attempts_involved": int(viol), "candidates_involved": int(db.scalar(
            "SELECT COUNT(DISTINCT cand) FROM aj WHERE class = 'ok' AND seen = 0 AND ts_epoch < ?", (horizon if horizon is not None else 0,)) or 0),
        "denominator_ok_attempts_with_nonce_to_judge": int(den),
        "违反率": ratio(viol, den),
        "undeterminable_within_lag": int(undet),
        "by_kind_violations": by_kind(db, "class = 'ok' AND seen = 0 AND ts_epoch < ?", (horizon if horizon is not None else 0,)),
        "by_kind_denominator": by_kind(db, "class = 'ok'"),
        # 反向：judge 收到了探测器没记录的 nonce（文件末尾没写完的一行会造成这种情况；多了就要查）
        "req_nonces_without_attempt": int(db.scalar("SELECT COUNT(*) FROM rq_first r WHERE NOT EXISTS (SELECT 1 FROM att a WHERE a.nonce = r.nonce)")),
        "req_nonces_total": int(db.scalar("SELECT COUNT(*) FROM rq_first")),
        # 探测器没判 ok、judge 却收到了：正常（例如收到响应后核对不过），只作参考
        "attempts_not_ok_but_seen": int(db.scalar("SELECT COUNT(*) FROM aj WHERE class != 'ok' AND seen = 1")),
    }
    # judge 侧限速丢弃：丢过 req 就解释不了“没收到”
    for t, label in (("req_dropped", "judge_req_dropped_total"), ("noise_dropped", "judge_noise_dropped_total")):
        out["judge_received"][label] = int(db.scalar("SELECT COALESCE(SUM(n), 0) FROM %s" % t)) if db.has_table(t) else None

    # 2. TLS 内请求一致（不含指纹）
    base = "tls_ok = 1 AND class = 'ok' AND dst = 'judge_tls' AND seen = 1"
    den2 = db.scalar("SELECT COUNT(*) FROM aj WHERE %s" % base)
    viol2 = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND (tamper = 1 OR n_added > 0)" % base)
    tamper_breakdown = {}
    for t in TAMPER_NAMES:
        n = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND t_%s = 1" % (base, t))
        if n:
            tamper_breakdown[t] = int(n)
    added_names = []
    if db.has_table("req_header") and viol2:
        sent = sql_in(SENT_HEADERS.keys())
        base_a = " AND ".join("a." + c for c in base.split(" AND "))   # 同一条件，带表别名
        added_names = [{"header": h, "requests": int(n)} for h, n in db.q(
            """SELECT h.name, COUNT(DISTINCT h.req_rid) FROM req_header h
               WHERE h.name != 'Host' AND h.name NOT IN (%s)
                 AND h.req_rid IN (SELECT r.req_rid FROM rd r JOIN aj a ON a.nonce = r.nonce WHERE %s AND r.n_added > 0)
               GROUP BY 1 ORDER BY 2 DESC LIMIT 30""" % (sent, base_a))]
    out["tls_request_identical"] = {
        "violations": int(viol2), "attempts_involved": int(viol2),
        "candidates_involved": int(db.scalar("SELECT COUNT(DISTINCT cand) FROM aj WHERE %s AND (tamper = 1 OR n_added > 0)" % base) or 0),
        "denominator_tls_ok_seen_attempts": int(den2), "违反率": ratio(viol2, den2),
        "by_kind_violations": by_kind(db, base + " AND (tamper = 1 OR n_added > 0)"),
        "by_kind_denominator": by_kind(db, base),
        "tamper_breakdown": tamper_breakdown,
        "with_added_headers": int(db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND n_added > 0" % base)),
        "added_header_names": added_names,
        # 参考：全部（含明文）成功且 judge 收到的尝试里，请求被改 / 多出头的次数——明文代理改头是被测行为，不是仪器问题
        "reference_all_ok_seen": {
            "attempts": int(db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 1")),
            "tamper": int(db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 1 AND tamper = 1")),
            "added_headers": int(db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 1 AND n_added > 0")),
        },
    }

    # 3. ClientHello 指纹
    basefps = [r[0] for r in db.q("""SELECT DISTINCT hello_fp FROM aj WHERE cand_kind = 'control' AND dst = 'judge_tls' AND class = 'ok'
                                     AND seen = 1 AND hello_fp IS NOT NULL ORDER BY 1""")]
    if basefps:
        # hello_fp 为 NULL（judge 没记指纹）也算“不等于基线”，所以用 COALESCE 把 NULL 当 0
        not_base = "NOT COALESCE(hello_fp IN (%s), 0)" % sql_in(basefps)
        den3 = db.scalar("SELECT COUNT(*) FROM aj WHERE %s" % base)
        viol3 = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND %s" % (base, not_base))
        cands3 = db.scalar("SELECT COUNT(DISTINCT cand) FROM aj WHERE %s AND %s" % (base, not_base))
        nofp = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND hello_fp IS NULL" % base)
        others = [{"hello_fp": fp if fp is not None else "(judge 没记指纹)", "attempts": int(n), "candidates": int(c),
                   "by_kind": {k: int(m) for k, m in db.q("SELECT cand_kind, COUNT(*) FROM aj WHERE %s AND hello_fp IS ? GROUP BY 1" % base, (fp,))}}
                  for fp, n, c in db.q("""SELECT hello_fp, COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND %s
                                          GROUP BY 1 ORDER BY 2 DESC LIMIT 50""" % (base, not_base))]
    else:
        den3 = viol3 = nofp = cands3 = 0
        others = []
    all_tls_fps = [{"hello_fp": fp, "requests": int(n), "is_baseline": fp in basefps} for fp, n in db.q(
        "SELECT hello_fp, COUNT(*) FROM req WHERE COALESCE(tls, 0) = 1 GROUP BY 1 ORDER BY 2 DESC LIMIT 50")]
    tls_fail_fps = []
    if db.has_table("tls_fail"):
        tls_fail_fps = {"total": int(db.scalar("SELECT COUNT(*) FROM tls_fail")),
                        "with_baseline_fp": int(db.scalar("SELECT COUNT(*) FROM tls_fail WHERE hello_fp IN (%s)" % (sql_in(basefps) or "''"))),
                        "distinct_fps": int(db.scalar("SELECT COUNT(DISTINCT hello_fp) FROM tls_fail")),
                        "without_fp": int(db.scalar("SELECT COUNT(*) FROM tls_fail WHERE hello_fp IS NULL"))}
    out["tls_hello_fingerprint"] = {
        "baseline_fps": basefps, "baseline_count": len(basefps), "baseline_unique": len(basefps) == 1,
        "violations": int(viol3), "attempts_involved": int(viol3), "candidates_involved": int(cands3 or 0),
        "denominator_tls_ok_seen_attempts": int(den3), "违反率": ratio(viol3, den3),
        "without_fp_in_judge_log": int(nofp),
        "other_fps": others,
        "all_tls_requests_by_fp": all_tls_fps,
        "tls_fail_fps": tls_fail_fps,
    }

    # 4. 节点出口不是本机（本模块口径：节点到 judge_tls 和 judge_http 的成功尝试都算；summary.go nodeEgress 只看 judge_tls，
    #    交叉核对时另按它的口径算，见 crosscheck）
    self_sql, self_used, self_src = self_ip_filter(db)
    # NAT 信号：judge 日志里公网对照的对端地址与配置的公网 IP 是否相同（不同 = 本机访问自己的公网地址经过了 NAT）
    nat_equal = self_ip_sets_equal(db, "start.judge_ip", "judge_remote:control:public")
    pub_nat = None
    if db.has_table("self_ips") and db.scalar("SELECT COUNT(*) FROM self_ips WHERE source = 'start.judge_ip'"):
        pub_nat = int(db.scalar("""SELECT COUNT(*) FROM aj WHERE cand_kind = 'control' AND class = 'ok' AND seen = 1 AND cand = 'control:public'
                                   AND remote NOT IN (SELECT ip FROM self_ips WHERE source = 'start.judge_ip')"""))
    den4 = db.scalar("SELECT COUNT(*) FROM aj WHERE proto = 'node' AND class = 'ok' AND seen = 1")
    if self_sql:
        viol4 = db.scalar("SELECT COUNT(*) FROM aj WHERE proto = 'node' AND class = 'ok' AND seen = 1 AND remote IN (%s)" % self_sql)
        by_arm = {a or "(无)": int(n) for a, n in db.q("SELECT arm, COUNT(*) FROM aj WHERE proto = 'node' AND class = 'ok' AND seen = 1 AND remote IN (%s) GROUP BY 1" % self_sql)}
        nodes4 = db.scalar("SELECT COUNT(DISTINCT cand) FROM aj WHERE proto = 'node' AND class = 'ok' AND seen = 1 AND remote IN (%s)" % self_sql)
    else:
        viol4, by_arm, nodes4 = None, {}, None
    # 能不能判定：没有本机地址，或者公网对照经过了 NAT 而本机地址里没有 judge 日志里实测的那个对端地址，“0 违反”都不说明问题
    pub_seen = int(db.scalar("SELECT COUNT(*) FROM aj WHERE cand_kind = 'control' AND cand = 'control:public' AND class = 'ok' AND seen = 1"))
    if not self_sql:
        status4 = "无法判定：没有本机地址"
    elif "judge_remote:control:public" in self_used:
        status4 = "可判定（本机地址含 judge 日志里公网对照的实测对端地址）"
    elif pub_seen == 0:
        status4 = "可判定（公网对照没有被 judge 收到过：本机直出的流量到不了 judge 的公网地址；本机地址只有配置的公网 IP 和回环地址）"
    elif pub_nat == 0:
        status4 = "可判定（公网对照的对端地址都等于配置的公网 IP，没有 NAT）"
    else:
        status4 = "无法判定：公网对照的对端地址不是（或无法确认是）配置的公网 IP，可能经过 NAT，而本机地址里缺 judge 日志里实测的对端地址"
    determinable4 = status4.startswith("可判定")
    out["node_egress_not_self"] = {
        "violations": viol4 if viol4 is None else int(viol4), "attempts_involved": viol4 if viol4 is None else int(viol4),
        "nodes_involved": nodes4 if nodes4 is None else int(nodes4),
        "denominator_node_ok_seen_attempts": int(den4), "违反率": ratio(viol4, den4) if viol4 is not None else None,
        "by_arm_violations": by_arm, "self_ip_source": self_src, "self_ip_sources_used": self_used,
        "judge_remote_public_equals_judge_ip": nat_equal,
        "determinable": determinable4, "status": status4,
        "by_dst_denominator": {safe_dst(d): int(n) for d, n in db.q("SELECT dst, COUNT(*) FROM aj WHERE proto = 'node' AND class = 'ok' AND seen = 1 GROUP BY 1")},
    }

    # 5. 回显与日志一致
    den5 = db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 1 AND echo_ip IS NOT NULL")
    viol5 = db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 1 AND echo_ip IS NOT NULL AND echo_ip != remote")
    out["echo_matches_log"] = {
        "violations": int(viol5), "attempts_involved": int(viol5),
        "candidates_involved": int(db.scalar("SELECT COUNT(DISTINCT cand) FROM aj WHERE class = 'ok' AND seen = 1 AND echo_ip IS NOT NULL AND echo_ip != remote") or 0),
        "denominator_ok_seen_with_echo": int(den5), "违反率": ratio(viol5, den5),
        "by_kind_violations": by_kind(db, "class = 'ok' AND seen = 1 AND echo_ip IS NOT NULL AND echo_ip != remote"),
        "ok_seen_without_echo": int(db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 1 AND echo_ip IS NULL")),
    }

    # 6. 对照请求原样到达
    cb = "cand_kind = 'control' AND class = 'ok' AND seen = 1"
    den6 = db.scalar("SELECT COUNT(*) FROM aj WHERE %s" % cb)
    v_t = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND (tamper = 1 OR n_added > 0)" % cb)
    v_c = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND copies > 1" % cb)
    v_e = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND echo_ip IS NOT NULL AND echo_ip != remote" % cb)
    # pub_nat 在第 4 条里按 start.judge_ip 单独算过（不能用含 judge_remote:control:public 的本机地址集合，否则恒为 0）
    lo_not_lo = db.scalar("SELECT COUNT(*) FROM aj WHERE %s AND cand = 'control:loopback' AND remote NOT LIKE '127.%%' AND remote != '::1'" % cb)
    out["control_request_intact"] = {
        "violations": int(v_t + v_c + v_e), "attempts_involved": int(db.scalar(
            "SELECT COUNT(*) FROM aj WHERE %s AND (tamper = 1 OR n_added > 0 OR copies > 1 OR (echo_ip IS NOT NULL AND echo_ip != remote))" % cb)),
        "denominator_control_ok_seen": int(den6),
        "tamper_or_added": int(v_t), "duplicate_nonce": int(v_c), "echo_mismatch": int(v_e),
        "control_public_remote_not_judge_ip": pub_nat,
        "judge_remote_public_equals_judge_ip": nat_equal,
        "control_loopback_remote_not_loopback": int(lo_not_lo),
        "note": "control_public_remote_not_judge_ip 只拿 start.judge_ip 比：> 0 说明本机访问自己的公网地址经过了 NAT（云主机常见），不影响代理的判定；"
                "但这时 derive.go 按 judge_ip 判“带出探测器地址”会漏判，另见 SCHEMA“judge 的身份从哪里取”。"
                "“节点出口不是本机”已把 judge 日志里实测的对端地址并入本机地址，不受 NAT 影响",
    }

    # 参考：TLS 校验通过（经钉扎的隧道）之后 HTTP 阶段却失败的尝试。PROTOCOL 的不变量说的是“TLS 校验通过的请求”，
    # 上面几条只核对了 class='ok' 的；钉扎通过后正文、金丝雀、状态码出错在隧道里按理不可能发生，同样是仪器（或 judge）异常的信号。
    # 连接层的失败（超时、断开、重置）代理随时可以造成，不算异常，只列出。tls_ok=1 的尝试一定走到了 fetchJudge，一定有 nonce，所以都在 aj 里。
    # summary.go integrity 对 class != 'ok' 直接跳过，交叉核对不会提醒这一项。
    # http_body_mismatch 里有一种不是内容出错：代理在正文传到一半时断开，收到的正文是期望正文的前缀（summary.go BodyChange 判“截断”：
    # http_pre == http_len < 期望长度）。TLS 里的内容代理改不了，但断开连接随时能做，这一种归连接层，不算仪器异常。
    tf_rows = db.q("""SELECT class, cand_kind, pkind, http_len, http_pre, COUNT(*) FROM aj
                      WHERE tls_ok = 1 AND dst = 'judge_tls' AND class != 'ok' GROUP BY 1, 2, 3, 4, 5""")
    want = truncation_want_lengths(db, sorted({r[2] for r in tf_rows if r[0] == "http_body_mismatch"}))
    tf_by_class, tf_content, tf_transport, tf_trunc, tf_content_kind = {}, 0, 0, 0, {}
    for cls, kind, pk, hlen, hpre, n in tf_rows:
        n = int(n)
        tf_by_class[cls] = tf_by_class.get(cls, 0) + n
        if cls == "http_body_mismatch" and is_truncated(hlen, hpre, want.get(pk)):
            tf_trunc += n
        elif http_content_level(cls):
            tf_content += n
            tf_content_kind[kind] = tf_content_kind.get(kind, 0) + n
        else:
            tf_transport += n
    out["tls_ok_but_http_failed"] = {
        "attempts": tf_content + tf_transport + tf_trunc, "by_class": tf_by_class,
        "content_level": tf_content, "content_level_by_kind": tf_content_kind,
        "body_truncated": tf_trunc,
        "transport_level": tf_transport,
        "payload_len_used": want,
        "denominator_tls_ok_to_judge_tls_not_canceled": int(db.scalar("SELECT COUNT(*) FROM aj WHERE tls_ok = 1 AND dst = 'judge_tls'")),
        "note": "内容层（%s，不含截断）在钉扎通过的隧道里不该出现，非 0 就要查仪器或 judge；body_truncated 是 http_body_mismatch 里"
                "收到的正文恰为期望正文前缀的那部分（代理提前断开，BodyChange 判“截断”）；连接层（http_timeout / http_eof / http_reset 等）"
                "和截断都只作参考。截断单列是看过数据以后加的（决策 D14，事后），按原定义内容层是 content_level + body_truncated" % "、".join(HTTP_CONTENT_CLASSES + ["http_canary_*"]),
    }

    # 7. 配置唯一
    cfg = {}
    if db.has_table("start"):
        cols = db.columns("start")
        cfg["start_records"] = int(db.scalar("SELECT COUNT(*) FROM start"))
        for col, label in (("judge_host_sha8", "distinct_judge_host"), ("judge_ip_sha8", "distinct_judge_ip"),
                           ("payload_sha256", "distinct_payload_sha256_sets"), ("http_port", "distinct_http_port"), ("https_port", "distinct_https_port")):
            if col in cols:
                cfg[label] = int(db.scalar("SELECT COUNT(DISTINCT %s) FROM start" % col))
        if "probe" in cols:
            cfg["distinct_probe_config"] = int(db.scalar("SELECT COUNT(DISTINCT probe) FROM start"))
            # 哪些探测配置项在多条 start 之间不同：只输出键名，不输出值（exclude_file 是本机路径）
            probes = []
            for (p,) in db.q("SELECT probe FROM start"):
                try:
                    probes.append(json.loads(p) if p else {})
                except ValueError:
                    probes.append({})
            keys = sorted({k for p in probes for k in p})
            cfg["probe_config_keys_differing"] = [k for k in keys if len({json.dumps(p.get(k), sort_keys=True) for p in probes}) > 1]
            cfg["conn_per_sec_values"] = [r[0] for r in db.q("SELECT DISTINCT json_extract(probe, '$.conn_per_sec') FROM start ORDER BY 1")]
            cfg["snapshot_min_values"] = [r[0] for r in db.q("SELECT DISTINCT json_extract(probe, '$.snapshot_min') FROM start ORDER BY 1")]
            cfg["alive_interval_min_values"] = [r[0] for r in db.q("SELECT DISTINCT json_extract(probe, '$.alive_interval_min') FROM start ORDER BY 1")]
        cfg["load_err_records"] = int(db.scalar("SELECT COUNT(*) FROM start WHERE load_err IS NOT NULL AND load_err != ''")) if "load_err" in cols else None
    cfg["judge_leaf_observed_count"] = db.meta("judge_leaf_observed_count")
    cfg["judge_leaf_tls_ok_extra_count"] = db.meta("judge_leaf_tls_ok_extra_count")
    # 唯一性只看 judge 身份、载荷、端口和叶子证书；探测配置的差异单独列键名（duration_hours 之类的差异不影响口径，
    # 但 conn_per_sec / snapshot_min / alive_interval_min 等限速与调度项变了就是改口径，报告里要分段）
    ident_keys = ("distinct_judge_host", "distinct_judge_ip", "distinct_payload_sha256_sets", "distinct_http_port", "distinct_https_port")
    cfg["all_unique"] = all(cfg.get(k) in (None, 0, 1) for k in ident_keys) and str(cfg.get("judge_leaf_observed_count")) in ("1", "None")
    cfg["schedule_config_changed"] = bool(set(cfg.get("probe_config_keys_differing", [])) - {"duration_hours"})
    out["config_unique"] = cfg

    out["summary"] = {
        "any_violation": any((out[k].get("violations") or 0) > 0 for k in
                             ("judge_received", "tls_request_identical", "tls_hello_fingerprint", "node_egress_not_self", "echo_matches_log", "control_request_intact")),
        "violations_total": sum((out[k].get("violations") or 0) for k in
                                ("judge_received", "tls_request_identical", "tls_hello_fingerprint", "node_egress_not_self", "echo_matches_log", "control_request_intact")),
    }
    return out


# ---------------------------------------------------------------- 连接速率

def start_probe_values(db, key):
    """start.probe 里某一配置项出现过的取值（去掉 NULL：start.probe 为空或 JSON 里没有这一项时 json_extract 给 NULL）。"""
    if not db.has_table("start") or "probe" not in db.columns("start"):
        return []
    return [v for (v,) in db.q("SELECT DISTINCT json_extract(probe, '$.%s') FROM start ORDER BY 1" % key) if v is not None]


def rate(db, W, N):
    segs = W["_segs"]
    # att 部分来自 denominators() 建的 att_min（按分钟 × cand_kind，att 只在那里扫一遍）
    db.x("""CREATE TEMP TABLE conn_min AS
            SELECT m, SUM(n_att) AS n_att, SUM(n_npre) AS n_npre, SUM(n_att + n_npre) AS n FROM (
              SELECT m, SUM(n_conn) AS n_att, 0 AS n_npre FROM att_min GROUP BY 1 HAVING SUM(n_conn) > 0
              UNION ALL
              SELECT CAST(ts_epoch / 60 AS INTEGER), 0, COUNT(*) FROM npre WHERE tcp_ok IS NOT NULL GROUP BY 1
            ) GROUP BY m""" if db.has_table("npre") else
         """CREATE TEMP TABLE conn_min AS
            SELECT m, SUM(n_conn) AS n_att, 0 AS n_npre, SUM(n_conn) AS n FROM att_min GROUP BY 1 HAVING SUM(n_conn) > 0""")
    db.x("CREATE INDEX temp.conn_min_m ON conn_min(m)")
    cfg_vals = start_probe_values(db, "conn_per_sec")
    limit_from_default = not cfg_vals
    limit = cfg_vals[0] if cfg_vals else DEFAULT_CONN_PER_SEC
    tot = db.one("SELECT COALESCE(SUM(n), 0), COALESCE(SUM(n_att), 0), COALESCE(SUM(n_npre), 0), COUNT(*), MAX(n), MAX(n_att) FROM conn_min")
    total, n_att, n_npre, minutes_with_data, peak_min, peak_att = tot
    uptime_s = sum((sg["end"] - sg["start"]) for sg in segs if sg["end"] is not None)
    top = [{"minute_utc": iso_minute(m * 60), "connections": int(n), "per_sec": round(n / 60.0, 2), "att": int(a), "npre": int(p)}
           for m, n, a, p in db.q("SELECT m, n, n_att, n_npre FROM conn_min ORDER BY n DESC, m LIMIT 10")]
    over = db.one("SELECT COUNT(*), COALESCE(SUM(n), 0) FROM conn_min WHERE n > ?", (limit * 60,))
    ten = db.one("""SELECT MAX(n), COUNT(*), COALESCE(SUM(n), 0) FROM (SELECT SUM(n) AS n FROM conn_min GROUP BY m / 10)""")
    top10 = [{"window_utc": iso_minute(m10 * 600), "connections": int(n), "per_sec": round(n / 600.0, 2)}
             for m10, n in db.q("SELECT m / 10 AS m10, SUM(n) AS n FROM conn_min GROUP BY 1 ORDER BY 2 DESC LIMIT 5")]
    by_hour = [{"hour_utc": iso_hour(h * 3600), "connections": int(n), "att": int(a), "npre": int(p), "per_sec": round(n / 3600.0, 2),
                "peak_minute_per_sec": round(mx / 60.0, 2)}
               for h, n, a, p, mx in db.q("SELECT m / 60 AS h, SUM(n), SUM(n_att), SUM(n_npre), MAX(n) FROM conn_min GROUP BY 1 ORDER BY 1")]
    # 分布：有数据的分钟里每秒连接数的分位（conn_min 最多几千行，直接取回来算）
    qs = [None if v is None else round(v / 60.0, 2) for v in quantiles([r[0] for r in db.q("SELECT n FROM conn_min")])]
    # summary.go Rate 同口径：只数 att，avg 按有尝试的分钟平均，"%.1f"
    att_minutes = db.scalar("SELECT COUNT(*) FROM conn_min WHERE n_att > 0")
    summary_like = {
        "attempts_per_sec_avg": ("%.1f" % (n_att / att_minutes / 60.0)) if att_minutes else None,
        "attempts_per_sec_peak_minute": ("%.1f" % (peak_att / 60.0)) if peak_att else None,
        "configured_conn_per_sec": limit,
    }
    # 空闲空洞：运行段内连续 ≥ IDLE_GAP_MIN 分钟没有连接
    idle = []
    mins = [r[0] for r in db.q("SELECT m FROM conn_min ORDER BY m")]
    for a, b in zip(mins, mins[1:]):
        if b - a > IDLE_GAP_MIN:
            t0, t1 = (a + 1) * 60, b * 60
            idle.append({"from_utc": iso_minute(t0), "to_utc": iso_minute(t1), "minutes": int(b - a - 1),
                         "explained_by_restart": explained_by_restart(W, t0, t1)})
    return {
        "configured_conn_per_sec": limit, "configured_values_seen": cfg_vals, "configured_from_default": limit_from_default,
        "connections_total": int(total), "att_connections": int(n_att), "npre_connections": int(n_npre),
        "canceled_att_excluded": N["att"] - N["att_not_canceled"],
        "npre_without_tcp_excluded": (N["npre"] - N["npre_with_tcp"]) if N.get("npre") is not None else 0,
        "minutes_with_connections": int(minutes_with_data),
        "uptime_minutes": round(uptime_s / 60.0, 1),
        "per_sec_avg_over_uptime": round(total / uptime_s, 2) if uptime_s else None,
        "per_sec_avg_over_minutes_with_data": round(total / minutes_with_data / 60.0, 2) if minutes_with_data else None,
        "per_sec_peak_minute": round(peak_min / 60.0, 2) if peak_min else None,
        "per_sec_minute_quantiles_p50_p90_p99": qs,
        "minutes_over_limit": {"minutes": int(over[0]), "connections": int(over[1]), "limit_per_minute": limit * 60},
        "top_minutes": top,
        "per_sec_peak_10min": round(ten[0] / 600.0, 2) if ten[0] else None, "windows_10min": int(ten[1]), "top_10min_windows": top10,
        "by_hour": by_hour,
        "summary_go_style_att_only": summary_like,
        "idle_gaps": idle[:MAX_LIST], "idle_gaps_count": len(idle), "idle_gaps_unexplained": sum(1 for g in idle if not g["explained_by_restart"]),
        "note": DEFINITIONS["连接速率"],
    }


# ---------------------------------------------------------------- 起止、stat、记录文件

def runtime(db, W):
    segs = W["_segs"]
    out = {}
    if db.has_table("stat"):
        rows = db.q("SELECT ts_epoch, up_min, visits, records FROM stat ORDER BY ts_epoch, rid")
        gaps = []
        for (a, _, _, _), (b, _, _, _) in zip(rows, rows[1:]):
            if b - a > STAT_PERIOD_S * STAT_GAP_FACTOR:
                gaps.append({"from_utc": iso_minute(a), "to_utc": iso_minute(b), "minutes": round((b - a) / 60.0, 1),
                             "explained_by_restart": explained_by_restart(W, a, b)})
        # up_min 与本段 start 的一致性
        bad_up = 0
        checked = 0
        for ts, up, _, _ in rows:
            seg = segment_of(segs, ts)
            if seg is None or up is None:
                continue
            checked += 1
            if abs((ts - seg["start"]) / 60.0 - up) > 1.0:
                bad_up += 1
        out["stat"] = {
            "records": len(rows), "expected_records": expected_runs(segs, STAT_PERIOD_S) - len(segs) + sum(1 for sg in segs if sg["has_stop"]),
            "expected_rule": "每段 floor(时长/5min) 条，加停止时的一条",
            "gaps": gaps[:MAX_LIST], "gaps_count": len(gaps), "gaps_unexplained": sum(1 for g in gaps if not g["explained_by_restart"]),
            "up_min_checked": checked, "up_min_inconsistent": bad_up,
            "last": {"utc": iso_minute(rows[-1][0]), "up_min": round(rows[-1][1], 1) if rows[-1][1] is not None else None,
                     "visits": rows[-1][2], "records": rows[-1][3]} if rows else None,
        }
    if db.has_table("error"):
        out["errors"] = {"records": int(db.scalar("SELECT COUNT(*) FROM error")),
                         "by_what": {}}
        for what, n in db.q("SELECT what, COUNT(*) FROM error GROUP BY 1 ORDER BY 2 DESC"):
            k = norm_what(what)
            out["errors"]["by_what"][k] = out["errors"]["by_what"].get(k, 0) + int(n)
    # 记录文件：小时覆盖、重复、坏行
    if db.has_table("files"):
        files = {}
        for prefix in ("probe", "judge", "snap"):
            hrs = [r[0] for r in db.q("SELECT DISTINCT hour FROM files WHERE prefix = ? AND status = 'read' ORDER BY 1", (prefix,))]
            missing = []
            if len(hrs) >= 2:
                t0 = dt.datetime.strptime(hrs[0], "%Y%m%d-%H").replace(tzinfo=dt.timezone.utc)
                t1 = dt.datetime.strptime(hrs[-1], "%Y%m%d-%H").replace(tzinfo=dt.timezone.utc)
                have = set(hrs)
                t = t0
                while t <= t1:
                    h = t.strftime("%Y%m%d-%H")
                    if h not in have:
                        missing.append(h)
                    t += dt.timedelta(hours=1)
            # 缺失的小时整段落在已知中断里（探测器停着就不写 probe- / snap-，judge 也收不到对照请求）算重启解释
            missing_d = []
            for h in missing:
                h0 = dt.datetime.strptime(h, "%Y%m%d-%H").replace(tzinfo=dt.timezone.utc).timestamp()
                missing_d.append({"hour": h, "explained_by_restart": in_interruption(W, h0, h0 + 3600)})
            st = {s: int(n) for s, n in db.q("SELECT status, COUNT(*) FROM files WHERE prefix = ? GROUP BY 1", (prefix,))}
            files[prefix] = {"hours_read": len(hrs), "first_hour": hrs[0] if hrs else None, "last_hour": hrs[-1] if hrs else None,
                             "missing_hours": missing_d[:MAX_LIST], "missing_hours_count": len(missing),
                             "missing_hours_unexplained": sum(1 for m in missing_d if not m["explained_by_restart"]), "status_counts": st,
                             "compressed": int(db.scalar("SELECT COUNT(*) FROM files WHERE prefix = ? AND status = 'read' AND compressed = 1", (prefix,))),
                             "bad_lines": int(db.scalar("SELECT COALESCE(SUM(bad_lines), 0) FROM files WHERE prefix = ?", (prefix,)))}
        files["duplicate_hour_files"] = db.meta_json("duplicate_hour_files")
        files["unknown_fields"] = db.meta_json("unknown_fields")
        files["misplaced_kinds"] = db.meta_json("misplaced_kinds")
        files["misc_records"] = int(db.scalar("SELECT COUNT(*) FROM misc")) if db.has_table("misc") else None
        files["bad_line_by_why"] = {w: int(n) for w, n in db.q("SELECT why, COUNT(*) FROM bad_line GROUP BY 1")} if db.has_table("bad_line") else None
        out["files"] = files
    out["version_unique"] = W["version_unique"]
    out["versions"] = W["versions"]
    return out


# ---------------------------------------------------------------- 启动积压

def p90_over(per_hour, min_pairs):
    """每种状态里对子数够数（≥ min_pairs）、p90 超过 P90_FLAG 的小时：个数、小时号、p90 最大的那个小时。"""
    out = {}
    for state in ("working", "open", "dead"):
        hs = [(h, per_hour[h][state]) for h in sorted(per_hour)
              if per_hour[h].get(state) and per_hour[h][state]["pairs"] >= min_pairs and per_hour[h][state]["p90"] is not None]
        over = [(h, x) for h, x in hs if x["p90"] > P90_FLAG]
        top = max(hs, key=lambda t: (t[1]["p90"], -t[0])) if hs else None
        out[state] = {"hours_with_enough_pairs": len(hs), "hours": len(over), "hour_list": [h for h, _ in over],
                      "max_p90": top[1]["p90"] if top else None, "max_p90_hour": top[0] if top else None}
    return out


def recovered_hour(by_hour):
    """by_hour：{小时: {"pairs", "median"} 或 None}。返回 (恢复的小时, 区间外的小时列表)。
    PROTOCOL“已知局限”说的是积压“之后恢复正常”，即恢复后应持续正常，所以取“最后一个区间外的小时 + 1”，
    而不是第一个区间内的小时（第 0 小时碰巧对子少且正常、第 1-2 小时才显出积压时，后者会报 0）。
    只看对子数 ≥ RECOVER_MIN_PAIRS 的小时。"""
    q = sorted(h for h, m in by_hour.items() if m and m["pairs"] >= RECOVER_MIN_PAIRS)
    bad = [h for h in q if not (RECOVER_BAND[0] <= by_hour[h]["median"] <= RECOVER_BAND[1])]
    oob = [{"hour": h, "pairs": by_hour[h]["pairs"], "median": by_hour[h]["median"]} for h in bad]
    if not q:
        return None, oob
    if not bad:
        return 0, oob
    if any(h > bad[-1] for h in q):
        return bad[-1] + 1, oob
    return None, oob


def hourly_ratio(db, where):
    """vpair 按（前一次探访所在的小时, 前一次探访后的状态）分组的对子数、中位数、p90。where 是附加的 SQL 条件（以 AND 开头，或空串）。"""
    rows = db.q("""SELECT hour, state, cnt, MAX(CASE WHEN rn IN ((cnt + 1) / 2, (cnt + 2) / 2) THEN ratio END) AS med_hi,
                          MIN(CASE WHEN rn IN ((cnt + 1) / 2, (cnt + 2) / 2) THEN ratio END) AS med_lo,
                          MAX(CASE WHEN rn = CAST(0.9 * cnt + 0.999999 AS INTEGER) THEN ratio END) AS p90
                   FROM (SELECT hour, state, ratio, ROW_NUMBER() OVER (PARTITION BY hour, state ORDER BY ratio) rn,
                                COUNT(*) OVER (PARTITION BY hour, state) cnt FROM vpair WHERE 1 = 1 %s)
                   GROUP BY hour, state ORDER BY hour, state""" % where)
    per_hour = {}
    for hour, state, cnt, hi, lo, p90 in rows:
        per_hour.setdefault(int(hour), {})[state] = {"pairs": int(cnt), "median": round((hi + lo) / 2.0, 3), "p90": round(p90, 3) if p90 is not None else None}
    return per_hour


def revisit_by_dense(db):
    """复测间隔比按候选是否在候选密集的 /24 里分开（看过数据以后加的分解，决策 D14 之后补；不改原定口径）。
    候选密集的 /24 = 状态文件 cands ∪ 尝试记录里的代理候选，按 /24 数候选超过 DENSE_THRESHOLD 的（与其他模块同一口径）。
    没有 cands 表（合成库、旧库）时返回 None。"""
    if not db.has_table("cands"):
        return None
    att_part = " UNION SELECT DISTINCT cand, prefix24 FROM att WHERE cand_kind = 'proxy'" if db.has_table("att") else ""
    db.x("DROP TABLE IF EXISTS temp.idense")
    db.x("""CREATE TEMP TABLE idense AS SELECT prefix24 FROM (SELECT key AS cand, prefix24 FROM cands%s)
            WHERE prefix24 IS NOT NULL GROUP BY prefix24 HAVING COUNT(*) > ?""" % att_part, (DENSE_THRESHOLD,))
    n_dense = int(db.scalar("SELECT COUNT(*) FROM idense"))
    split = {}
    for state, d, cnt, over in db.q("""SELECT state, COALESCE(prefix24 IN (SELECT prefix24 FROM idense), 0) AS d, COUNT(*), SUM(ratio > ?)
                                       FROM vpair GROUP BY state, d ORDER BY state, d""", (P90_FLAG,)):
        split.setdefault(state, {})["密集 /24" if d else "其他 /24"] = {
            "对子": int(cnt), "间隔比超过 %g 的对子" % P90_FLAG: ratio(int(over or 0), int(cnt))}
    nd = hourly_ratio(db, "AND COALESCE(prefix24 IN (SELECT prefix24 FROM idense), 0) = 0")
    return {
        "threshold": DENSE_THRESHOLD, "dense_prefixes": n_dense,
        "by_state": split,
        "hours_p90_over_%g_excluding_dense" % P90_FLAG: p90_over(nd, RECOVER_MIN_PAIRS),
        "note": "复测间隔比（实际 / 计划）按前一次探访后的状态和候选所在 /24 是否候选密集分开。候选密集的 /24 里同时最多 4 个探访（PROTOCOL“频率与限速”），"
                "排不上队的复测会晚。这是看过数据以后加的分解，只用来找复测偏晚的原因，不改任何原定口径",
    }


def backlog(db, W):
    fs, inter = W["_fs"], W["_interruptions"]
    out = {}
    if db.has_table("visit") and fs is not None:
        # 中断表：段末（stop，或崩溃前最后一条记录）→ 下一条 start。对子跨中断的判据是“两次探访之间有一条 start”：
        # 崩溃时段末可能正是这对的第一次探访本身，用 start 判不会漏
        db.x("CREATE TEMP TABLE intr (from_e REAL, start_e REAL)")
        for i in inter:
            db.x("INSERT INTO intr VALUES (?, ?)", (i["from"], i["start"]))
        p24 = "prefix24" if "prefix24" in db.columns("visit") else "NULL AS prefix24"   # 旧库、合成库没有这一列
        db.x("""CREATE TEMP TABLE vpair AS
                SELECT t, state, grp, next_min, t_next, prefix24,
                       CAST((t - ?) / 3600 AS INTEGER) AS hour,
                       ((t_next - t) / 60.0) / next_min AS ratio
                FROM (SELECT ts_epoch AS t, state, COALESCE("group", 0) AS grp, next_min, %s,
                             LEAD(ts_epoch) OVER (PARTITION BY cand ORDER BY ts_epoch, rid) AS t_next
                      FROM visit WHERE COALESCE(aborted, 0) = 0)
                WHERE t_next IS NOT NULL AND next_min > 0""" % p24, (fs,))
        # 正式起点之前的对子（试运行）先删掉：CAST 向零取整，留着会被并进第 0 小时
        before_fs = db.scalar("SELECT COUNT(*) FROM vpair WHERE t < ?", (fs,))
        db.x("DELETE FROM vpair WHERE t < ?", (fs,))
        spanning = db.scalar("SELECT COUNT(*) FROM vpair v WHERE EXISTS (SELECT 1 FROM intr i WHERE i.start_e > v.t AND i.start_e <= v.t_next)")
        db.x("DELETE FROM vpair WHERE EXISTS (SELECT 1 FROM intr i WHERE i.start_e > vpair.t AND i.start_e <= vpair.t_next)")
        db.x("CREATE INDEX temp.vpair_hs ON vpair(hour, state)")
        per_hour = hourly_ratio(db, "")
        recovered, out_of_band = {}, {}
        for state in ("working", "open", "dead"):
            recovered[state], out_of_band[state] = recovered_hour({h: per_hour[h].get(state) for h in per_hour})
        overall = {state: {"pairs": int(cnt), "median": round(med, 3)} for state, cnt, med in db.q(
            """SELECT state, cnt, AVG(ratio) FROM (SELECT state, ratio, ROW_NUMBER() OVER (PARTITION BY state ORDER BY ratio) rn,
                                                          COUNT(*) OVER (PARTITION BY state) cnt FROM vpair)
               WHERE rn IN ((cnt + 1) / 2, (cnt + 2) / 2) GROUP BY state""")}
        by_group_first_hours = {}
        for grp, hour, cnt, med in db.q(
            """SELECT grp, hour, cnt, AVG(ratio) FROM (SELECT grp, hour, ratio, ROW_NUMBER() OVER (PARTITION BY grp, hour ORDER BY ratio) rn,
                                                               COUNT(*) OVER (PARTITION BY grp, hour) cnt FROM vpair WHERE state = 'working' AND hour < 6)
               WHERE rn IN ((cnt + 1) / 2, (cnt + 2) / 2) GROUP BY grp, hour ORDER BY grp, hour"""):
            by_group_first_hours.setdefault("aggregator_sample" if grp == 1 else "regular", {})[int(hour)] = {"pairs": int(cnt), "median": round(med, 3)}
        dense_split = revisit_by_dense(db)
        out["revisit_ratio"] = {
            "pairs_total": int(db.scalar("SELECT COUNT(*) FROM vpair")),
            "pairs_excluded_spanning_interruption": int(spanning),
            "pairs_before_formal_start_excluded": int(before_fs),
            "visits_before_formal_start": int(db.scalar("SELECT COUNT(*) FROM visit WHERE COALESCE(aborted, 0) = 0 AND ts_epoch < ?", (fs,))),
            "by_hour": [{"hour": h, "hour_utc": iso_hour(fs + h * 3600), **per_hour[h]} for h in sorted(per_hour)],
            "recovered_hour": recovered, "recover_band": list(RECOVER_BAND), "recover_min_pairs": RECOVER_MIN_PAIRS,
            "recovered_hour_rule": "最后一个对子数 ≥ %d 且中位数在区间外的小时 + 1（此后各个够数的小时都在区间内，且至少有一个）；"
                                   "没有区间外的小时则为 0；最后一个区间外的小时之后再没有够数的小时、或一个够数的小时都没有，为 null" % RECOVER_MIN_PAIRS,
            "hours_out_of_band": out_of_band,
            "hours_p90_over_%g" % P90_FLAG: p90_over(per_hour, RECOVER_MIN_PAIRS),
            "overall_median": overall,
            "working_first_6h_by_group": by_group_first_hours,
            "by_dense_24": dense_split,
        }
    if db.has_table("nround"):
        segs = W["_segs"]
        rounds = []
        prev_t = None
        for ts, rnd, known, listed, supported, backoff, tcp_ok, probed, oks, okl, badc, batches, ms, err in db.q(
                "SELECT ts_epoch, round, known, listed, supported, backoff, tcp_ok, probed, ok_strict, ok_linked, bad_config, batches, ms, err FROM nround ORDER BY ts_epoch, rid"):
            seg = segment_of(segs, ts)
            seg_idx = seg["idx"] if seg else None
            rounds.append({"segment": seg_idx, "round": rnd, "start_utc": iso_minute(ts), "minutes": round((ms or 0) / 60000.0, 2),
                           "since_prev_round_min": round((ts - prev_t) / 60.0, 1) if prev_t is not None else None,
                           "known": known, "listed": listed, "supported": supported, "backoff": backoff, "tcp_ok": tcp_ok, "probed": probed,
                           "ok_strict": oks, "ok_linked": okl, "bad_config": badc, "batches": batches, "had_error": bool(err)})
            prev_t = ts
        durs = sorted(r["minutes"] for r in rounds)
        later = sorted(r["minutes"] for r in rounds[1:])
        out["node_rounds"] = {
            "rounds": rounds, "count": len(rounds),
            "first_round_minutes": rounds[0]["minutes"] if rounds else None,
            "median_minutes_all": durs[len(durs) // 2] if durs else None,
            "median_minutes_after_first": later[len(later) // 2] if later else None,
            "max_minutes": durs[-1] if durs else None,
            "rounds_with_error": sum(1 for r in rounds if r["had_error"]),
        }
    # 启动时的候选池：正式起点之后第一条 stat 的 pool（stat 每 5 分钟一条），以及整个窗口里 pool.total 的最大值
    if db.has_table("stat_pool") and fs is not None:
        first = db.scalar("SELECT MIN(ts_epoch) FROM stat_pool WHERE ts_epoch >= ?", (fs,))
        if first is not None:
            pool = {k: int(v) for k, v in db.q("SELECT key, value FROM stat_pool WHERE ts_epoch = ? ORDER BY key", (first,))}
            mx = db.one("SELECT ts_epoch, value FROM stat_pool WHERE key = 'total' AND ts_epoch >= ? ORDER BY value DESC, ts_epoch LIMIT 1", (fs,))
            out["pool_at_first_stat"] = {
                "utc": iso_minute(first), "minutes_after_formal_start": round((first - fs) / 60.0, 1),
                "pool": {k: v for k, v in pool.items() if not k.startswith("skipped_")},
                "pool_total_max": int(mx[1]) if mx else None, "pool_total_max_utc": iso_minute(mx[0]) if mx else None,
                "note": DEFINITIONS["启动时的候选池"],
            }
    return out


# ---------------------------------------------------------------- 证据库

def evidence(db):
    """att.ev（证书链，.der）和 att.http_ev（正文，.body）引用的哈希与 evidence 表（数据目录里实际存在的文件）对账。
    att 只扫一遍：按 (cand_kind, ev, http_ev) 计数落成 TEMP 表 ev_raw，再拆成 ev_ref（ext, hash, cand_kind, n），
    之后的引用数、去重数、缺失数、孤儿文件都只查 ev_ref 和 evidence（几千到几万行）。
    以前孤儿文件用“evidence 每行一个 NOT EXISTS (att 里有没有这个哈希)”的相关子查询，att 上没有 ev 索引，
    每个证据文件都要把 att 全表扫一遍，真实数据上跑不完（核对意见第 1 条）。"""
    has_ev = db.has_table("evidence")
    out = {"evidence_table_present": has_ev}
    if has_ev:
        out["files_by_ext"] = {e: {"files": int(n), "bytes": int(b or 0)} for e, n, b in db.q("SELECT ext, COUNT(*), SUM(bytes) FROM evidence GROUP BY 1")}
        out["meta_evidence_files"] = db.meta("evidence_files")
        out["meta_evidence_bytes"] = db.meta("evidence_bytes")
    db.x("""CREATE TEMP TABLE ev_raw AS
            SELECT COALESCE(cand_kind, '(空)') AS cand_kind, ev, http_ev, COUNT(*) AS n
            FROM att WHERE ev IS NOT NULL OR http_ev IS NOT NULL GROUP BY 1, 2, 3""")
    db.x("""CREATE TEMP TABLE ev_ref AS
            SELECT 'der' AS ext, ev AS hash, cand_kind, SUM(n) AS n FROM ev_raw WHERE ev IS NOT NULL GROUP BY 2, 3
            UNION ALL
            SELECT 'body', http_ev, cand_kind, SUM(n) FROM ev_raw WHERE http_ev IS NOT NULL GROUP BY 2, 3""")
    db.x("CREATE INDEX temp.ev_ref_eh ON ev_ref(ext, hash)")
    # 每个 (ext, hash) 在不在 evidence 里：先落成 TEMP 表（evidence 的主键是 (hash, ext)，IN 子查询会建临时索引）
    if has_ev:
        db.x("""CREATE TEMP TABLE ev_hit AS
                SELECT DISTINCT r.ext, r.hash, ((r.ext, r.hash) IN (SELECT ext, hash FROM evidence)) AS present FROM ev_ref r""")
    else:
        db.x("CREATE TEMP TABLE ev_hit AS SELECT DISTINCT ext, hash, 0 AS present FROM ev_ref")
    db.x("CREATE INDEX temp.ev_hit_eh ON ev_hit(ext, hash)")
    rows = db.q("""SELECT r.ext, r.cand_kind, SUM(r.n), COUNT(*), SUM(CASE WHEN h.present = 0 THEN r.n ELSE 0 END), SUM(h.present = 0)
                   FROM ev_ref r JOIN ev_hit h ON h.ext = r.ext AND h.hash = r.hash
                   GROUP BY 1, 2 ORDER BY 2, 1""")
    by_kind = {}
    tot = {"der": [0, 0], "body": [0, 0]}
    for ext, kind, n, d, miss, miss_d in rows:
        k = by_kind.setdefault(kind, {"der": {"attempts_with_ev": 0, "distinct_hashes": 0, "attempts_missing_file": 0, "distinct_hashes_missing_file": 0},
                                      "body": {"attempts_with_http_ev": 0, "distinct_hashes": 0, "attempts_missing_file": 0, "distinct_hashes_missing_file": 0}})
        k[ext]["attempts_with_ev" if ext == "der" else "attempts_with_http_ev"] = int(n or 0)
        k[ext]["distinct_hashes"] = int(d or 0)
        k[ext]["attempts_missing_file"] = int(miss or 0)
        k[ext]["distinct_hashes_missing_file"] = int(miss_d or 0)
        tot[ext][0] += int(n or 0)
        tot[ext][1] += int(miss or 0)
    out["by_kind"] = by_kind
    # 跨类别去重：同一哈希可能被几种 cand_kind 引用，所以不能把 by_kind 的去重数相加
    dist = {ext: (int(d or 0), int(md or 0)) for ext, d, md in db.q("SELECT ext, COUNT(*), SUM(present = 0) FROM ev_hit GROUP BY 1")}
    out["der"] = {"attempts_with_ev": tot["der"][0], "distinct_hashes_referenced": dist.get("der", (0, 0))[0],
                  "attempts_missing_file": tot["der"][1], "distinct_hashes_missing_file": dist.get("der", (0, 0))[1],
                  "缺失率（按尝试）": ratio(tot["der"][1], tot["der"][0])}
    out["body"] = {"attempts_with_http_ev": tot["body"][0], "distinct_hashes_referenced": dist.get("body", (0, 0))[0],
                   "attempts_missing_file": tot["body"][1], "distinct_hashes_missing_file": dist.get("body", (0, 0))[1],
                   "缺失率（按尝试）": ratio(tot["body"][1], tot["body"][0])}
    if has_ev:
        # 孤儿：evidence 里有、att 里没有任何引用的文件（例如文件末尾没写完的那一行引用了它）。按 ext 区分：.der 只对 att.ev，.body 只对 att.http_ev
        out["orphan_files_not_referenced"] = {
            ext: int(db.scalar("SELECT COUNT(*) FROM evidence e WHERE e.ext = ? AND e.hash NOT IN (SELECT hash FROM ev_ref WHERE ext = ?)", (ext, ext)))
            for ext in ("der", "body")}
        out["files_other_ext"] = int(db.scalar("SELECT COUNT(*) FROM evidence WHERE ext NOT IN ('der', 'body')"))
    out["limit_note"] = "rec.Evidence：每个候选最多 12 份、总共 1 GB，超限不保存；同一哈希只存一份"
    return out


# ---------------------------------------------------------------- 快照完整性

def snapshots(db, W):
    segs = W["_segs"]
    out = {}
    snap_min_vals = start_probe_values(db, "snapshot_min")   # 已去掉 NULL
    snap_min = snap_min_vals[0] if snap_min_vals and snap_min_vals[0] else DEFAULT_SNAPSHOT_MIN
    exp_reg = expected_runs(segs, snap_min * 60)
    exp_agg = expected_runs(segs, AGG_PERIOD_S)
    exp_sub = expected_runs(segs, NSNAP_DEFAULT_MIN * 60)
    if db.has_table("snap"):
        rows = db.q("""SELECT src, label, COALESCE(agg, 0), COUNT(*),
                              SUM(err IS NOT NULL OR status NOT IN (200, 304)), SUM(status = 200), SUM(status = 304),
                              SUM(COALESCE(changed, 0)), SUM(COALESCE(base, 0)), MIN(ts_epoch), MAX(ts_epoch),
                              MAX(CASE WHEN COALESCE(changed, 0) = 1 THEN n END)
                       FROM snap GROUP BY 1, 2, 3 ORDER BY 1, 2""")
        files = []
        for src, label, agg, n, failed, s200, s304, changed, base, t0, t1, last_n in rows:
            exp = exp_agg if agg else exp_reg
            files.append({"src": src, "label": label, "aggregator": bool(agg), "fetches": int(n), "failed": int(failed or 0),
                          "status_200": int(s200 or 0), "status_304": int(s304 or 0), "changed": int(changed or 0), "base_snapshots": int(base or 0),
                          "expected_fetches": exp, "实际/期望": round(n / exp, 3) if exp else None,
                          "失败率": ratio(failed or 0, n), "first_utc": iso_minute(t0), "last_utc": iso_minute(t1)})
        by_src = {}
        for f in files:
            s = by_src.setdefault(f["src"], {"aggregator": f["aggregator"], "files": 0, "fetches": 0, "failed": 0, "changed": 0})
            s["files"] += 1
            s["fetches"] += f["fetches"]
            s["failed"] += f["failed"]
            s["changed"] += f["changed"]
        # 抓取间隔：常规文件相邻两次间隔超过 3 倍的空洞
        gaps = db.q("""SELECT src, label, prev_ts, ts_epoch FROM (
                         SELECT src, label, ts_epoch, LAG(ts_epoch) OVER (PARTITION BY src, label ORDER BY ts_epoch, rid) AS prev_ts
                         FROM snap WHERE COALESCE(agg, 0) = 0)
                       WHERE prev_ts IS NOT NULL AND ts_epoch - prev_ts > ? ORDER BY prev_ts""", (snap_min * 60 * CONTROL_GAP_FACTOR,))
        gap_list = [{"src": s, "label": l, "from_utc": iso_minute(a), "to_utc": iso_minute(b), "minutes": round((b - a) / 60.0, 1),
                     "explained_by_restart": explained_by_restart(W, a, b)} for s, l, a, b in gaps]
        status_other = {str(st): int(n) for st, n in db.q("SELECT status, COUNT(*) FROM snap WHERE status NOT IN (200, 304) GROUP BY 1")}
        out["lists"] = {"snapshot_min": snap_min, "snapshot_min_values_seen": snap_min_vals, "snapshot_min_from_default": not snap_min_vals,
                        "expected_regular_fetches_per_file": exp_reg,
                        "expected_aggregator_fetches_per_file": exp_agg, "files": files, "by_src": by_src,
                        "files_count": len(files), "regular_files": sum(1 for f in files if not f["aggregator"]),
                        "aggregator_files": sum(1 for f in files if f["aggregator"]),
                        "fetch_gaps": gap_list[:MAX_LIST], "fetch_gaps_count": len(gap_list),
                        "fetch_gaps_unexplained": sum(1 for g in gap_list if not g["explained_by_restart"]),
                        "non_200_304_status_counts": status_other,
                        "with_err": int(db.scalar("SELECT COUNT(*) FROM snap WHERE err IS NOT NULL"))}
    if db.has_table("agg_sample"):
        out["aggregator_samples"] = {src: {"records": int(n), "sample_total": int(s or 0)} for src, n, s in db.q(
            "SELECT src, COUNT(*), SUM(sample) FROM agg_sample GROUP BY 1 ORDER BY 1")}
        out["aggregator_samples_note"] = "每个聚合器应恰好 1 条（抽样只做一次，重启后不重抽）；多于 1 条说明状态被清空后重抽，样本不可比"
    if db.has_table("nsnap"):
        rows = db.q("""SELECT src, COUNT(*), SUM(err IS NOT NULL OR status NOT IN (200, 304)), SUM(status = 200), SUM(status = 304),
                              SUM(COALESCE(changed, 0)), SUM(COALESCE(base, 0)), MAX(CASE WHEN COALESCE(changed, 0) = 1 THEN n END)
                       FROM nsnap GROUP BY 1 ORDER BY 1""")
        out["subscriptions"] = {"expected_fetches": exp_sub, "expected_rule": "每 %d 分钟一次（节点配置不在记录里，按 cfg.Default）" % NSNAP_DEFAULT_MIN,
                                "subs": [{"src": s, "fetches": int(n), "failed": int(f or 0), "status_200": int(a or 0), "status_304": int(b or 0),
                                          "changed": int(c or 0), "base_snapshots": int(bs or 0), "实际/期望": round(n / exp_sub, 3) if exp_sub else None,
                                          "失败率": ratio(f or 0, n)} for s, n, f, a, b, c, bs, _ in rows]}
    return out


# ---------------------------------------------------------------- 被排除的条目

def excluded(db, W):
    if not db.has_table("stat_pool"):
        return {"note": "库里没有 stat_pool 表"}
    segs = W["_segs"]
    per_seg = []
    for sg in segs:
        last = db.scalar("SELECT MAX(ts_epoch) FROM stat_pool WHERE ts_epoch >= ? AND ts_epoch <= ?", (sg["start"] - 1, (sg["end"] if sg["end"] is not None else 1e18) + 1))
        if last is None:
            per_seg.append({"segment": sg["idx"], "last_stat_utc": None, "pool": {}, "skipped": {}})
            continue
        pool = {k: int(v) for k, v in db.q("SELECT key, value FROM stat_pool WHERE ts_epoch = ? ORDER BY key", (last,))}
        per_seg.append({"segment": sg["idx"], "last_stat_utc": iso_minute(last),
                        "pool": {k: v for k, v in pool.items() if not k.startswith("skipped_")},
                        "skipped": {k[len("skipped_"):]: v for k, v in pool.items() if k.startswith("skipped_")},
                        "skipped_total": sum(v for k, v in pool.items() if k.startswith("skipped_"))})
    keys = sorted({k for s in per_seg for k in s["skipped"]})
    return {"by_segment": per_seg, "skipped_reasons_seen": keys,
            "first_segment_skipped_total": per_seg[0]["skipped_total"] if per_seg and "skipped_total" in per_seg[0] else None,
            "max_skipped_total_any_segment": max((s.get("skipped_total", 0) for s in per_seg), default=None),
            "note": DEFINITIONS["被排除的条目"]}


# ---------------------------------------------------------------- 分母

def denominators(db):
    """各分母。att 只扫一遍：按分钟 × cand_kind 计数落成 TEMP 表 att_min（几千行），分母和 rate() 的连接速率都从它算；
    aj 是 build_reconciliation 建的 TEMP 表。n_conn = class 不含 canceled 的条数（与原来 rate() 的 WHERE class NOT LIKE 同口径，
    class 为 NULL 的不算连接），n_canceled = class 含 canceled 的条数。"""
    n = {}
    db.x("""CREATE TEMP TABLE att_min AS
            SELECT CAST(ts_epoch / 60 AS INTEGER) AS m, cand_kind, COUNT(*) AS n_all,
                   SUM(class LIKE '%canceled%') AS n_canceled, SUM(class NOT LIKE '%canceled%') AS n_conn
            FROM att GROUP BY 1, 2""")
    rows = db.q("SELECT cand_kind, SUM(n_all), SUM(n_canceled) FROM att_min GROUP BY 1")
    n["att"] = int(sum(r[1] for r in rows))
    n["att_not_canceled"] = int(n["att"] - sum(r[2] or 0 for r in rows))
    n["att_by_kind"] = {(k if k is not None else "(空)"): int(v) for k, v, _ in rows}
    n["att_control"] = n["att_by_kind"].get("control", 0)
    n["att_with_nonce_to_judge"] = int(db.scalar("SELECT COUNT(*) FROM aj"))
    n["att_ok_with_nonce_to_judge"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok'"))
    n["att_tls_ok_to_judge_tls_ok_seen"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE tls_ok = 1 AND class = 'ok' AND dst = 'judge_tls' AND seen = 1"))
    n["att_node_ok_seen"] = int(db.scalar("SELECT COUNT(*) FROM aj WHERE proto = 'node' AND class = 'ok' AND seen = 1"))
    n["req"] = int(db.scalar("SELECT COUNT(*) FROM req"))
    n["req_distinct_nonce"] = int(db.scalar("SELECT COUNT(*) FROM rq_first"))
    for t in ("noise", "tls_fail", "npre", "nround", "stat", "start", "stop", "version", "error", "visit", "snap", "nsnap", "agg_sample", "evidence"):
        n[t] = int(db.scalar("SELECT COUNT(*) FROM %s" % t)) if db.has_table(t) else None
    n["npre_with_tcp"] = int(db.scalar("SELECT COUNT(*) FROM npre WHERE tcp_ok IS NOT NULL")) if db.has_table("npre") else None
    n["files_read"] = int(db.scalar("SELECT COUNT(*) FROM files WHERE status = 'read'")) if db.has_table("files") else None
    return n


# ---------------------------------------------------------------- 与 summary.json 交叉核对

def summary_go_findings(db):
    """按 summary.go 的口径算与仪器有关的五条 findings（attempt() / integrity() / nodeEgress()），只用于与 summary.json 比对。
    与本模块不变量的差别：
    - 对照组（control:*）在 attempt() 里调 integrity() 之前就 return，五条都不含对照组；
    - “节点出口”只在 a.Dst == judge_tls 时调 nodeEgress()，本机地址只有 selfIPs = [c.Judge.PublicIP]（start.judge_ip）；
    - “TLS 内不同”的指纹条件是 b.baseFP != "" && d.HelloFP != b.baseFP：baseFP 是处理到这条尝试时最近一次对照 judge_tls
      成功且 judge 记了指纹的 hello_fp（这里按 ts 排序近似文件顺序），hello_fp 为空也算不等；第一条对照之前的尝试不比指纹；
    - “没收到”只算 ts 早于 judgeHorizon 的（与本模块相同）；judge 没有任何记录时 judgeHorizon 为空，一条也不算。
    返回 {名称: (attempts, candidates)}；candidates 在 summary.go 里对节点是 "node <id>"、对代理是 cand，与按 cand 去重等价。"""
    nc = "cand_kind != 'control' AND class = 'ok'"
    out = {}
    horizon, _ = judge_horizon(db)
    if horizon is None:
        out["探测器认为成功，但 judge 没收到请求"] = (0, 0)
    else:
        r = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND seen = 0 AND ts_epoch < ?" % nc, (horizon,))
        out["探测器认为成功，但 judge 没收到请求"] = (int(r[0]), int(r[1]))
    db.x("""CREATE TEMP TABLE sg_tls AS
            WITH ev AS (
              SELECT ts_epoch, rid, 1 AS is_ctl, hello_fp, NULL AS cand, 0 AS core FROM aj
               WHERE cand_kind = 'control' AND dst = 'judge_tls' AND class = 'ok' AND seen = 1 AND hello_fp IS NOT NULL AND hello_fp != ''
              UNION ALL
              SELECT ts_epoch, rid, 0, hello_fp, cand, (tamper = 1 OR n_added > 0) FROM aj
               WHERE %s AND seen = 1 AND tls_ok = 1),
            g AS (SELECT *, SUM(is_ctl) OVER (ORDER BY ts_epoch, is_ctl DESC, rid ROWS UNBOUNDED PRECEDING) AS grp FROM ev)
            SELECT cand, core, hello_fp, MAX(CASE WHEN is_ctl = 1 THEN hello_fp END) OVER (PARTITION BY grp) AS base FROM g""" % nc)
    r = db.one("""SELECT COUNT(*), COUNT(DISTINCT cand) FROM sg_tls
                  WHERE cand IS NOT NULL AND (core = 1 OR (base IS NOT NULL AND COALESCE(hello_fp, '') != base))""")
    out["仪器异常：TLS 内的请求到达 judge 时与发出时不同"] = (int(r[0]), int(r[1]))
    has_cfg_ip = db.has_table("self_ips") and db.scalar("SELECT COUNT(*) FROM self_ips WHERE source = 'start.judge_ip'")
    if has_cfg_ip:
        r = db.one("""SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE proto = 'node' AND dst = 'judge_tls' AND class = 'ok' AND seen = 1
                      AND remote IN (SELECT ip FROM self_ips WHERE source = 'start.judge_ip')""")
        out["仪器异常：节点探测的流量从本机直接出去了"] = (int(r[0]), int(r[1]))
    else:
        out["仪器异常：节点探测的流量从本机直接出去了"] = (None, None)
    r = db.one("""SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND seen = 1
                  AND echo_ip IS NOT NULL AND echo_ip != '' AND echo_ip != COALESCE(remote, '')""" % nc)
    out["响应头里回显的地址与 judge 日志不一致"] = (int(r[0]), int(r[1]))
    r = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM aj WHERE %s AND seen = 1 AND copies > 1" % nc)
    out["同一请求被 judge 收到多次（重放）"] = (int(r[0]), int(r[1]))
    return out


def find_summary(db, arg):
    if arg:
        return arg, "argument"
    d = db.meta("data_dir")
    if d:
        for cand in (os.path.join(d, "summary.json"), os.path.join(d, "fieldtest", "summary.json")):
            if os.path.isfile(cand):
                return cand, "data_dir"
    return None, "meta_only"


def find_preflight(db, arg):
    if arg:
        return arg, "argument"
    d = db.meta("data_dir")
    if d:
        for cand in (os.path.join(d, "preflight.txt"), os.path.join(d, "fieldtest", "preflight.txt")):
            if os.path.isfile(cand):
                return cand, "data_dir"
    return None, "none"


def preflight(path, source):
    """测量机上的预检报告：只取预检时间、仪器自检的项数、sing-box 版本和结论行，主机名、地址等其余内容不读进输出。"""
    if not path:
        return {"source": source, "note": "没有 preflight.txt"}
    out = {"source": source, "预检时间": None, "仪器自检": None, "sing-box 版本": None, "结论": None}
    section = None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            m = re.match(r"^预检\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*$", line)
            if m:
                out["预检时间"] = m.group(1)
                continue
            m = re.match(r"^结论：(\d+) 项失败，(\d+) 项注意", line)
            if m:
                out["结论"] = {"失败": int(m.group(1)), "注意": int(m.group(2))}
                continue
            if line and not line[0].isspace():
                section = line.strip()
                continue
            if section == "仪器自检":
                # 通过时是“  通过  共核对 N 项，M 项不符”；不通过时 preflight.go 另起一行重印汇总，前面没有状态词
                m = re.match(r"^\s+(?:(\S+)\s+)?共核对 (\d+) 项，(\d+) 项不符\s*$", line)
                if m and (out["仪器自检"] is None or m.group(1)):
                    out["仪器自检"] = {"状态": m.group(1), "核对": int(m.group(2)), "不符": int(m.group(3))}
            elif section == "sing-box":
                m = re.search(r"sing-box version (\d+\.\d+\.\d+)", line)
                if m:
                    out["sing-box 版本"] = m.group(1)
    return out


def crosscheck(db, path, source, R):
    cmp = {}

    def put(key, want, got):
        cmp[key] = {"summary": want, "computed": got, "match": (want == got)}

    s = None
    if path:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
    else:
        mj = db.meta_json("summary_json")
        if mj:
            s = mj
    if not s:
        return {"source": source, "note": "没有 summary.json，也没有 meta.summary_json", "comparisons": {}}
    out = {"source": source, "generated": s.get("generated"), "first_record": s.get("first_record"), "last_record": s.get("last_record")}
    # 自动检查：按开头归类，不抄原文
    warns = s.get("warnings")
    if warns is not None:
        cats = {}
        for w in warns:
            k = next((p for p in WARNING_PREFIXES if w.startswith(p)), "其他")
            cats[k.strip()] = cats.get(k.strip(), 0) + 1
        out["warnings"] = {"count": len(warns), "by_category": cats,
                           "instrument_related": sum(v for k, v in cats.items() if k.startswith("仪器异常") or k.startswith("探测器认为成功"))}
    # records
    recs = s.get("records") or {}
    mine = {k: int(n) for k, n in db.q("SELECT k, SUM(n) FROM file_kind GROUP BY 1")} if db.has_table("file_kind") else {}
    for k in sorted(set(recs) | {k for k in mine if k not in ("req", "noise", "tls_fail", "noise_dropped", "req_dropped")}):
        put("records.%s" % k, recs.get(k, 0), mine.get(k, 0))
    jd = s.get("judge") or {}
    for k in ("req", "tls_fail", "noise_dropped", "req_dropped"):
        if k in jd or mine.get(k):
            put("judge.%s" % k, jd.get(k, 0), mine.get(k, 0))
    if "noise" in jd:
        # summary.go：Judge["noise"] = noise 记录数 + noise_dropped 的 n 之和
        nd = int(db.scalar("SELECT COALESCE(SUM(n), 0) FROM noise_dropped")) if db.has_table("noise_dropped") else 0
        put("judge.noise(+dropped n)", jd.get("noise", 0), mine.get("noise", 0) + nd)
    # control（summary 里有这一节才比；比并集，免得漏掉某一边没有的对照项）
    if "control" in s:
        # summary 的键与本模块一样做观察者名归一化（obs:<名> 含点号时换成 obs:<观察者>），否则键名会把主机名带进输出，
        # 两边键也对不上；归一化后撞在一起的几项合并计数（本模块的 items 也是这样合并的）
        ctl = {}
        for name, v in (s.get("control") or {}).items():
            k = norm_control_key(name)
            acc = ctl.setdefault(k, {"ok": 0, "total": 0})
            acc["ok"] += int((v or {}).get("ok", 0))
            acc["total"] += int((v or {}).get("total", 0))
        items = R["controls"]["items"]
        for name in sorted(set(ctl) | set(items)):
            want = ctl.get(name) or {}
            got = items.get(name) or {}
            put("control.%s" % name, {"ok": want.get("ok", 0), "total": want.get("total", 0)},
                {"ok": got.get("成功率", {}).get("num", 0), "total": got.get("成功率", {}).get("den", 0)})
    # rate
    rt = s.get("rate") or {}
    mine_rt = R["rate"]["summary_go_style_att_only"]
    for k in ("attempts_per_sec_avg", "attempts_per_sec_peak_minute", "configured_conn_per_sec"):
        if k in rt:
            put("rate.%s" % k, rt[k], mine_rt.get(k))
    # snapshots：来源名只用库里 snap.src / nsnap.src 也有的（白名单列）；summary 里有、库里没有的只计数，不抄名字
    by_src = (R.get("snapshots", {}).get("lists") or {}).get("by_src") or {}
    unknown_src = 0
    for row in s.get("snapshots") or []:
        src = row.get("src")
        if src not in by_src:
            unknown_src += 1
            continue
        got = by_src.get(src) or {}
        for k in ("fetches", "failed", "changed"):
            put("snapshots.%s.%s" % (src, k), row.get(k, 0), got.get(k, 0))
    subs = {x["src"]: x for x in (R.get("snapshots", {}).get("subscriptions") or {}).get("subs", [])}
    unknown_sub = 0
    for row in (s.get("nodes") or {}).get("subscriptions") or []:
        src = row.get("src")
        if src not in subs:
            unknown_sub += 1
            continue
        got = subs.get(src) or {}
        for k in ("fetches", "failed", "changed"):
            put("nodes.subscriptions.%s.%s" % (src, k), row.get(k, 0), got.get(k, 0))
    if unknown_src or unknown_sub:
        # summary 里有、库里没有的来源个数（summary 一侧为 N，本模块为 0）
        put("snapshots.summary_only_sources", unknown_src, 0)
        put("nodes.subscriptions.summary_only_sources", unknown_sub, 0)
    # nodes.precheck：每个节点最后一次预检的类别分布
    pre = (s.get("nodes") or {}).get("precheck")
    if pre is not None and db.has_table("npre"):
        mine_pre = {c: int(n) for c, n in db.q(
            """SELECT class, COUNT(*) FROM (SELECT node, class, ROW_NUMBER() OVER (PARTITION BY node ORDER BY ts_epoch DESC, rid DESC) rn FROM npre)
               WHERE rn = 1 GROUP BY 1""")}
        for k in sorted(set(pre) | set(mine_pre)):
            put("nodes.precheck.%s" % k, pre.get(k, 0), mine_pre.get(k, 0))
    # pool：最后一条 stat
    pool = s.get("pool")
    if pool and db.has_table("stat_pool"):
        last = db.scalar("SELECT MAX(ts_epoch) FROM stat_pool")
        mine_pool = {k: int(v) for k, v in db.q("SELECT key, value FROM stat_pool WHERE ts_epoch = ?", (last,))} if last is not None else {}
        for k in sorted(set(pool) | set(mine_pool)):
            put("pool.%s" % k, pool.get(k, 0), mine_pool.get(k, 0))
    # 与仪器有关的 findings（只读 attempts / candidates）。比对用 summary.go 的口径另算一份（summary_go_findings），
    # 本模块主结果的口径更严（含对照组、节点含 judge_http 等），两者的差别写在 definitions“交叉核对·findings 口径”
    fd = s.get("findings") or {}
    inv = R["invariants"]
    horizon = inv.get("judge_horizon_utc")
    sg_f = summary_go_findings(db)
    mine_f = {
        "探测器认为成功，但 judge 没收到请求": (inv["judge_received"]["violations"], inv["judge_received"]["candidates_involved"]),
        "仪器异常：TLS 内的请求到达 judge 时与发出时不同": (inv["tls_request_identical"]["violations"] + inv["tls_hello_fingerprint"]["violations"], None),
        "仪器异常：节点探测的流量从本机直接出去了": (inv["node_egress_not_self"]["violations"], inv["node_egress_not_self"]["nodes_involved"]),
        "响应头里回显的地址与 judge 日志不一致": (inv["echo_matches_log"]["violations"], inv["echo_matches_log"]["candidates_involved"]),
        "同一请求被 judge 收到多次（重放）": (int(db.scalar("SELECT COUNT(*) FROM aj WHERE class = 'ok' AND seen = 1 AND copies > 1")),
                                 int(db.scalar("SELECT COUNT(DISTINCT cand) FROM aj WHERE class = 'ok' AND seen = 1 AND copies > 1"))),
    }
    out["findings_summary_go_caliber"] = {k: {"attempts": v[0], "candidates": v[1]} for k, v in sg_f.items()}
    out["findings_module_caliber"] = {k: {"attempts": v[0], "candidates": v[1],
                                          "note": "TLS 内不同 = 请求一致 + 指纹两条不变量的违反数之和（同一尝试可能两条都违反，只作量级参考）"
                                          if k.startswith("仪器异常：TLS") else None} for k, v in mine_f.items()}
    if "findings" in s:
        for name in INSTRUMENT_FINDINGS:
            want = fd.get(name) or {}
            got = sg_f.get(name)
            if name in fd or (got and got[0]):
                put("findings.%s.attempts" % name, want.get("attempts", 0), got[0] if got else None)
                put("findings.%s.candidates" % name, want.get("candidates", 0), got[1] if got else None)
    out["comparisons"] = cmp
    out["mismatches"] = sorted(k for k, v in cmp.items() if not v["match"])
    out["mismatch_count"] = len(out["mismatches"])
    out["judge_rotation"] = judge_rotation_explanation(db, s, cmp)
    out["note"] = ("records.att 等可能差 1：文件末尾没写完的一行 Go 直接丢弃、ingest 能解析就入库（SCHEMA“坑”8）。"
                   "judge.* 与“重放”可能少算：summary.json 生成时 judge 当前小时的文件还在写，读到一半时整点轮转（改名压缩），"
                   "rec.Each 遇到消失的文件直接跳过（rec.go eachFile 的 os.ErrNotExist），之后新开的文件也没读到；judge_rotation 逐项核对"
                   "“summary + 生成时所在小时及以后的 judge 文件里的记录 = 本模块”是否成立。"
                   "findings 的 candidates 在 summary.go 里对节点用 'node <id>' 计数，这里用 cand（节点 id），互不冲突。judge_horizon=%s" % horizon)
    return out


def parse_iso_utc(text):
    if not text:
        return None
    try:
        return dt.datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def judge_rotation_explanation(db, s, cmp):
    """summary 生成时所在小时及以后的 judge 文件（files.hour >= 生成时刻的小时）里各类记录的条数，以及加上它们之后
    summary 与本模块是否对得上。只输出计数和布尔值，不输出文件名以外的东西（文件名只含日期和小时）。"""
    gen = parse_iso_utc(s.get("generated"))
    if gen is None or not db.has_table("files") or not db.has_table("file_kind"):
        return {"note": "summary 没有 generated，或库里没有 files / file_kind 表，无法核对"}
    gen_hour = dt.datetime.fromtimestamp(gen, dt.timezone.utc).strftime("%Y%m%d-%H")
    late = [(int(i), h) for i, h in db.q("SELECT id, hour FROM files WHERE prefix = 'judge' AND hour >= ? ORDER BY hour", (gen_hour,))]
    ids = [i for i, _ in late]
    out = {"summary_generated_hour_utc": "%s-%s-%sT%s:00Z" % (gen_hour[:4], gen_hour[4:6], gen_hour[6:8], gen_hour[9:]), "late_judge_files": len(late),
           "late_judge_file_hours": [h for _, h in late]}
    if not ids:
        out["late_records"] = {}
        out["explained"] = {}
        return out
    idl = ",".join(str(i) for i in ids)
    lk = {k: int(n) for k, n in db.q("SELECT k, SUM(n) FROM file_kind WHERE file_id IN (%s) GROUP BY 1" % idl)}
    nd = int(db.scalar("SELECT COALESCE(SUM(n), 0) FROM noise_dropped WHERE file_id IN (%s)" % idl)) if db.has_table("noise_dropped") else 0
    late_n = {"judge.req": lk.get("req", 0), "judge.tls_fail": lk.get("tls_fail", 0),
              "judge.noise_dropped": lk.get("noise_dropped", 0), "judge.req_dropped": lk.get("req_dropped", 0),
              "judge.noise(+dropped n)": lk.get("noise", 0) + nd}
    # 生成时刻之前就写进这些文件的 req（summary 本该读到；读不到只能是文件在读的过程中消失了）
    out["late_req_before_generated"] = int(db.scalar("SELECT COUNT(*) FROM req WHERE file_id IN (%s) AND ts_epoch <= ?" % idl, (gen,)) or 0)
    # 重放：summary 按它读到的 req 数 copies；漏掉的文件里的副本会让一部分重放看起来只到了一次
    nc = "cand_kind != 'control' AND class = 'ok'"
    db.x("DROP TABLE IF EXISTS temp.late_rq")
    db.x("CREATE TEMP TABLE late_rq AS SELECT nonce, COUNT(*) AS n FROM req WHERE file_id IN (%s) AND nonce IS NOT NULL GROUP BY nonce" % idl)
    r = db.one("""SELECT COUNT(*), COUNT(DISTINCT a.cand) FROM aj a JOIN late_rq l ON l.nonce = a.nonce
                  WHERE %s AND a.seen = 1 AND a.copies > 1 AND a.copies - l.n <= 1""" % nc.replace("cand_kind", "a.cand_kind").replace("class", "a.class"))
    late_n["findings.同一请求被 judge 收到多次（重放）.attempts"] = int(r[0] or 0)
    # 候选数不能简单相减（同一候选可能还有别的重放没漏），按“summary 看得到的重放”重新数一遍
    r2 = db.one("""SELECT COUNT(DISTINCT a.cand) FROM aj a LEFT JOIN late_rq l ON l.nonce = a.nonce
                   WHERE %s AND a.seen = 1 AND a.copies - COALESCE(l.n, 0) > 1""" % nc.replace("cand_kind", "a.cand_kind").replace("class", "a.class"))
    out["late_records"] = {k: v for k, v in late_n.items() if v}
    expl = {}
    for k, v in cmp.items():
        if v["match"]:
            continue
        if k == "findings.同一请求被 judge 收到多次（重放）.candidates":
            expl[k] = {"summary_visible_recount": int(r2[0] or 0), "explained": int(r2[0] or 0) == v["summary"]}
        elif k in late_n:
            want, got = v["summary"], v["computed"]
            expl[k] = {"late": late_n[k], "explained": (want or 0) + late_n[k] == got}
    out["explained"] = expl
    out["all_judge_mismatches_explained"] = bool(expl) and all(e["explained"] for e in expl.values()) and \
        all(k in expl for k in cmp if not cmp[k]["match"] and (k.startswith("judge.") or k.startswith("findings.同一请求")))
    return out


# ---------------------------------------------------------------- 输出前的断言

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?!\d|\.\d|/24)")
HOSTPORT_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}:\d{1,5}")


def assert_clean(text, db):
    """最后一道保险：输出文本里不许有 ip:port、不带 /24 的 IPv4、judge 的主机名或 IP、邮箱。这是断言，不是放行手段。"""
    bad = []
    if HOSTPORT_RE.search(text):
        bad.append("ip:port")
    if IPV4_RE.search(text):
        bad.append("不带 /24 的 IPv4")
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

def print_markdown(R):
    W = R["window"]
    print("### 起止与中断\n")
    print(f"- 记录 {W['first_record_utc']} 至 {W['last_record_utc']}（{fmt(W['span_hours'])} 小时）；正式起点 {W['formal_start_utc']}（{W['formal_start_rule']}），"
          f"正式 {fmt(W['formal_hours'])} 小时")
    print(f"- start {len(W['starts'])} 条，stop {len(W['stops'])} 条，版本 {W['versions']}（唯一：{W['version_unique']}），"
          f"状态被清空的重启 {W['state_cleared_restarts']} 次；中断 {len(W['interruptions'])} 次合计 {fmt(W['interruption_minutes_total'])} 分钟"
          f"（其中没有 stop 的崩溃重启 {W['interruptions_without_stop']} 次），没有 stop 的运行段 {W['segments_without_stop']} 个，"
          f"运行合计 {fmt(W['uptime_minutes_total'])} 分钟")
    print("\n| 运行段 | 起 | 止 | 分钟 | 恢复的候选 | 以 stop 结束 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for sg in W["segments"]:
        print(f"| {sg['idx']} | {sg['start_utc']} | {sg['end_utc']} | {fmt(sg['minutes'])} | {fmt(sg['resumed_candidates'])} | {sg['ended_by_stop']} |")

    C = R["controls"]
    print("\n### 对照（不经代理）\n")
    print("| 对照项 | 成功/总数（成功率） | 周期（秒） | 期望次数 | 实际/期望 | 失败类别 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for name in sorted(C["items"]):
        it = C["items"][name]
        cls = ", ".join(f"{k} {v}" for k, v in sorted(it["classes"].items()) if k != "ok") or "—"
        print(f"| {name} | {rfmt(it['成功率'])} | {fmt(it['period_s'])} | {fmt(it['期望次数'])} | {fmt(it['实际/期望'])} | {cls} |")
    print(f"\n失败时段 {C['fail_spans_count']} 段（失败尝试 {C['fail_attempts_total']} 次）；回环失败分钟 {C['loopback_fail_spans_count']} 段合计 "
          f"{fmt(C['loopback_fail_minutes_total'])} 分钟（算到下一次成功：{C['loopback_fail_spans_to_next_ok_count']} 段合计 {fmt(C['loopback_fail_minutes_to_next_ok_total'])} 分钟）；"
          f"没按时运行的空洞 {C['schedule_gaps_count']} 个（重启解释不了的 {C['schedule_gaps_unexplained']} 个）")
    if C["fail_spans"]:
        print("\n| 对照项 | 起 | 止 | 跨度（分钟） | 尝试 | 类别 |")
        print("| --- | --- | --- | --- | --- | --- |")
        for sp in C["fail_spans"][:20]:
            print(f"| {sp['item']} | {sp['from_utc']} | {sp['to_utc']} | {fmt(sp['span_minutes'])} | {sp['attempts']} | {', '.join(sp['classes'])} |")

    I = R["invariants"]
    print(f"\n### 不变量（judge 最后一条记录 {I['judge_last_record_utc']}，核对截止 {I['judge_horizon_utc']}）\n")
    print("| 不变量 | 违反次数 | 涉及的 att | 分母 | 违反率 | 备注 |")
    print("| --- | --- | --- | --- | --- | --- |")
    jr = I["judge_received"]
    print(f"| 探测器 ok 的请求 judge 都收到 | {jr['violations']} | {jr['attempts_involved']} | {fmt(jr['denominator_ok_attempts_with_nonce_to_judge'])} | "
          f"{fmt(jr['违反率']['pct'], '%')} | 余量内无法判定 {jr['undeterminable_within_lag']}；judge 多出的 nonce {jr['req_nonces_without_attempt']}；judge 丢弃 req {fmt(jr['judge_req_dropped_total'])} |")
    ti = I["tls_request_identical"]
    print(f"| TLS 内请求到达时与发出一致 | {ti['violations']} | {ti['attempts_involved']} | {fmt(ti['denominator_tls_ok_seen_attempts'])} | "
          f"{fmt(ti['违反率']['pct'], '%')} | 改动项 {ti['tamper_breakdown'] or '无'}；多出头 {ti['with_added_headers']} |")
    hf = I["tls_hello_fingerprint"]
    print(f"| TLS ClientHello 指纹等于直连基线 | {hf['violations']} | {hf['attempts_involved']} | {fmt(hf['denominator_tls_ok_seen_attempts'])} | "
          f"{fmt(hf['违反率']['pct'], '%')} | 基线 {hf['baseline_count']} 个；不同指纹 {len(hf['other_fps'])} 种 |")
    ne = I["node_egress_not_self"]
    print(f"| 节点出口不是本机 | {fmt(ne['violations'])} | {fmt(ne['attempts_involved'])} | {fmt(ne['denominator_node_ok_seen_attempts'])} | "
          f"{fmt(ne['违反率']['pct'] if ne['违反率'] else None, '%')} | {ne['status']}；本机地址来源 {ne['self_ip_source']}；"
          f"公网对照对端等于配置 IP：{ne['judge_remote_public_equals_judge_ip']} |")
    em = I["echo_matches_log"]
    print(f"| 响应头回显地址等于 judge 日志 | {em['violations']} | {em['attempts_involved']} | {fmt(em['denominator_ok_seen_with_echo'])} | "
          f"{fmt(em['违反率']['pct'], '%')} | 成功但没回显 {em['ok_seen_without_echo']} |")
    ci = I["control_request_intact"]
    print(f"| 对照请求原样到达 | {ci['violations']} | {ci['attempts_involved']} | {fmt(ci['denominator_control_ok_seen'])} | — | "
          f"改动/多头 {ci['tamper_or_added']}，重复 nonce {ci['duplicate_nonce']}，回显不符 {ci['echo_mismatch']}，公网对照经 NAT {fmt(ci['control_public_remote_not_judge_ip'])} |")
    tf = I["tls_ok_but_http_failed"]
    print(f"\n参考：TLS 校验通过后 HTTP 失败 {tf['attempts']} 次（分母 {fmt(tf['denominator_tls_ok_to_judge_tls_not_canceled'])}）："
          f"内容层 {tf['content_level']}（不该出现），正文被截断 {tf['body_truncated']}（代理提前断开），连接层 {tf['transport_level']}；"
          f"按类别 {tf['by_class'] or '无'}")
    cu = I["config_unique"]
    print(f"\n配置唯一：start {cu.get('start_records')} 条；judge 主机名 {cu.get('distinct_judge_host')} 个、公网 IP {cu.get('distinct_judge_ip')} 个、"
          f"载荷哈希组 {cu.get('distinct_payload_sha256_sets')} 个、探测配置 {cu.get('distinct_probe_config')} 个"
          f"（不同的键：{cu.get('probe_config_keys_differing') or '无'}）；judge 叶子证书 {cu.get('judge_leaf_observed_count')} 张")
    if hf["other_fps"]:
        print("\n| 非基线指纹 | 尝试 | 候选 | 按类别 |")
        print("| --- | --- | --- | --- |")
        for o in hf["other_fps"]:
            print(f"| {o['hello_fp']} | {o['attempts']} | {o['candidates']} | {o['by_kind']} |")

    RT = R["rate"]
    print(f"\n### 连接速率（配置 {RT['configured_conn_per_sec']} 条/秒{'，start 记录里没有、取默认值' if RT['configured_from_default'] else ''}）\n")
    print(f"- 连接 {fmt(RT['connections_total'])}（att {fmt(RT['att_connections'])} + 有 tcp 的 npre {fmt(RT['npre_connections'])}；"
          f"排除 canceled att {fmt(RT['canceled_att_excluded'])}、没发起连接的 npre {fmt(RT['npre_without_tcp_excluded'])}）")
    print(f"- 每秒：按运行时长平均 {fmt(RT['per_sec_avg_over_uptime'])}，按有连接的分钟平均 {fmt(RT['per_sec_avg_over_minutes_with_data'])}，"
          f"最高的一分钟 {fmt(RT['per_sec_peak_minute'])}，最高的 10 分钟 {fmt(RT['per_sec_peak_10min'])}；分钟分位 p50/p90/p99 {RT['per_sec_minute_quantiles_p50_p90_p99']}；"
          f"超过上限的分钟 {RT['minutes_over_limit']['minutes']} 个")
    print(f"- summary.go 口径（只数 att）：平均 {RT['summary_go_style_att_only']['attempts_per_sec_avg']}，峰值分钟 {RT['summary_go_style_att_only']['attempts_per_sec_peak_minute']}")
    print(f"- 空闲空洞（≥{IDLE_GAP_MIN} 分钟没有连接）{RT['idle_gaps_count']} 个，重启解释不了的 {RT['idle_gaps_unexplained']} 个")

    U = R["runtime"]
    if "stat" in U:
        st = U["stat"]
        print(f"\n### stat 与记录文件\n")
        print(f"- stat {st['records']} 条（期望约 {st['expected_records']}），空洞 {st['gaps_count']} 个（重启解释不了的 {st['gaps_unexplained']} 个），"
              f"up_min 不一致 {st['up_min_inconsistent']}/{st['up_min_checked']}")
    if "errors" in U:
        print(f"- error 记录 {U['errors']['records']} 条：{U['errors']['by_what'] or '无'}")
    if "files" in U:
        for p in ("probe", "judge", "snap"):
            f = U["files"][p]
            print(f"- {p}- 文件 {f['hours_read']} 个小时（{f['first_hour']} 至 {f['last_hour']}），缺 {f['missing_hours_count']} 个小时"
                  f"（重启解释不了的 {f['missing_hours_unexplained']} 个），坏行 {f['bad_lines']}，状态 {f['status_counts']}")

    B = R["backlog"]
    if "revisit_ratio" in B:
        rv = B["revisit_ratio"]
        print(f"\n### 启动积压：复测间隔 实际/计划（中位数，按正式起点后的小时）\n")
        print(f"- 对子 {fmt(rv['pairs_total'])}，跨中断不算 {rv['pairs_excluded_spanning_interruption']}，正式起点之前不算 {rv['pairs_before_formal_start_excluded']}；"
              f"恢复到约 1.0 的小时：{rv['recovered_hour']}；区间外的小时 {rv['hours_out_of_band']}；整体中位数 {rv['overall_median']}")
        print("\n| 小时 | working 中位数（对子） | open 中位数（对子） | dead 中位数（对子） |")
        print("| --- | --- | --- | --- |")
        for h in rv["by_hour"][:12]:
            cells = []
            for stt in ("working", "open", "dead"):
                m = h.get(stt)
                cells.append(f"{fmt(m['median'])}（{m['pairs']}）" if m else "—")
            print(f"| {h['hour']}（{h['hour_utc']}） | " + " | ".join(cells) + " |")
        if len(rv["by_hour"]) > 12:
            print(f"| … 共 {len(rv['by_hour'])} 个小时，其余见 JSON | | | |")
    if "node_rounds" in B:
        nr = B["node_rounds"]
        m2 = lambda v: "—" if v is None else f"{v:.2f}"
        print(f"\n节点轮次 {nr['count']} 轮：第一轮 {m2(nr['first_round_minutes'])} 分钟，之后中位 {m2(nr['median_minutes_after_first'])} 分钟，最长 {m2(nr['max_minutes'])} 分钟，出错 {nr['rounds_with_error']} 轮")

    E = R["evidence"]
    print(f"\n### 证据库\n")
    print(f"- 证书链：引用 {fmt(E['der']['attempts_with_ev'])} 次、{fmt(E['der']['distinct_hashes_referenced'])} 个哈希，找不到文件 {E['der']['attempts_missing_file']} 次 / "
          f"{E['der']['distinct_hashes_missing_file']} 个哈希（{fmt(E['der']['缺失率（按尝试）']['pct'], '%')}）")
    print(f"- 正文：引用 {fmt(E['body']['attempts_with_http_ev'])} 次、{fmt(E['body']['distinct_hashes_referenced'])} 个哈希，找不到文件 {E['body']['attempts_missing_file']} 次 / "
          f"{E['body']['distinct_hashes_missing_file']} 个哈希（{fmt(E['body']['缺失率（按尝试）']['pct'], '%')}）")
    if "orphan_files_not_referenced" in E:
        print(f"- 没有被任何尝试引用的证据文件：{E['orphan_files_not_referenced']}")

    S = R["snapshots"]
    if "lists" in S:
        L = S["lists"]
        print(f"\n### 快照完整性（常规每 {L['snapshot_min']} 分钟，期望 {L['expected_regular_fetches_per_file']} 次/文件；聚合器每 6 小时，期望 {L['expected_aggregator_fetches_per_file']} 次/文件）\n")
        print("| 来源 | 标签 | 聚合器 | 抓取 | 失败 | 304 | 有变化 | 首次快照 | 实际/期望 |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for f in L["files"]:
            print(f"| {f['src']} | {f['label']} | {'是' if f['aggregator'] else ''} | {f['fetches']} | {f['failed']} | {f['status_304']} | {f['changed']} | {f['base_snapshots']} | {fmt(f['实际/期望'])} |")
        print(f"\n抓取空洞 {L['fetch_gaps_count']} 个（重启解释不了的 {L['fetch_gaps_unexplained']} 个）")
    if "subscriptions" in S:
        print(f"\n| 订阅 | 抓取 | 失败 | 304 | 有变化 | 实际/期望（期望 {S['subscriptions']['expected_fetches']}） |")
        print("| --- | --- | --- | --- | --- | --- |")
        for sb in S["subscriptions"]["subs"]:
            print(f"| {sb['src']} | {sb['fetches']} | {sb['failed']} | {sb['status_304']} | {sb['changed']} | {fmt(sb['实际/期望'])} |")

    X = R["excluded"]
    if "by_segment" in X:
        print("\n### 被排除的条目（stat.pool 的 skipped_*，每个运行段最后一条）\n")
        print("| 运行段 | 最后一条 stat | 原因 → 条数 | 合计 | 候选池 |")
        print("| --- | --- | --- | --- | --- |")
        for sg in X["by_segment"]:
            print(f"| {sg['segment']} | {sg['last_stat_utc']} | {sg['skipped'] or '无'} | {fmt(sg.get('skipped_total'))} | {sg['pool']} |")

    K = R["crosscheck"]
    print(f"\n### 与 summary.json 交叉核对（来源：{K.get('source')}）\n")
    if "warnings" in K:
        print(f"- 自动检查 {K['warnings']['count']} 条：{K['warnings']['by_category']}；与仪器有关的 {K['warnings']['instrument_related']} 条")
    print(f"- 比对 {len(K.get('comparisons', {}))} 项，不一致 {K.get('mismatch_count', 0)} 项：{K.get('mismatches') or '无'}")
    if K.get("mismatches"):
        print()
        jr = (K.get("judge_rotation") or {}).get("explained") or {}
        print("| 项 | summary.json | 本模块 | judge 轮转能否解释 |")
        print("| --- | --- | --- | --- |")
        for k in K["mismatches"][:30]:
            v = K["comparisons"][k]
            e = jr.get(k)
            ex = "—" if e is None else (("能（漏读 %s 条）" % fmt(e["late"])) if "late" in e else "能（按 summary 读到的记录重数）") if e["explained"] else "不能"
            print(f"| {k} | {v['summary']} | {v['computed']} | {ex} |")
        jrot = K.get("judge_rotation") or {}
        if jrot.get("late_judge_files"):
            print(f"\nsummary.json 生成于 {jrot['summary_generated_hour_utc']} 这一小时；该小时及以后的 judge 文件 {jrot['late_judge_files']} 个"
                  f"（{', '.join(jrot['late_judge_file_hours'])}），其中生成时刻之前写入的 req {fmt(jrot['late_req_before_generated'])} 条。"
                  f"judge 相关的不一致是否都能由“这些文件没被读到”解释：{'是' if jrot.get('all_judge_mismatches_explained') else '否'}")


# ---------------------------------------------------------------- 主流程

def run(db_path, out_dir, summary_path=None, formal_start="auto", markdown=False, write=True, check_plans=False, db_out=None,
        preflight_path=None):
    db = DB(db_path, check_plans=check_plans)
    if db_out is not None:
        db_out.append(db)
    wl_source = check_whitelist(db)
    for t in ("att", "req"):
        if not db.has_table(t):
            raise SystemExit("库里没有 %s 表，不是 ingest.py 建的库" % t)
    W = segments_and_window(db, formal_start)
    R = {"module": MODULE, "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "ingest_version": db.meta("ingest_version"), "whitelist_source": wl_source,
         "definitions": DEFINITIONS}
    R["window"] = {k: v for k, v in W.items() if not k.startswith("_")}
    build_reconciliation(db)          # TEMP 表 aj / rd：探测器尝试与 judge 请求按 nonce 对账
    R["n"] = denominators(db)
    R["controls"] = controls(db, W)
    R["invariants"] = invariants(db, W)
    R["rate"] = rate(db, W, R["n"])
    R["runtime"] = runtime(db, W)
    R["backlog"] = backlog(db, W)
    R["evidence"] = evidence(db)
    R["snapshots"] = snapshots(db, W)
    R["excluded"] = excluded(db, W)
    spath, ssource = find_summary(db, summary_path)
    R["crosscheck"] = crosscheck(db, spath, ssource, R)
    R["preflight"] = preflight(*find_preflight(db, preflight_path))
    pf_self = R["preflight"].get("仪器自检") or {}
    pf_end = R["preflight"].get("结论") or {}
    files_r = R["runtime"].get("files") or {}
    R["verdict"] = {
        "any_invariant_violation": R["invariants"]["summary"]["any_violation"],
        "node_egress_not_self_determinable": R["invariants"]["node_egress_not_self"]["determinable"],
        "node_egress_not_self_status": R["invariants"]["node_egress_not_self"]["status"],
        "tls_ok_but_http_failed_content_level": R["invariants"]["tls_ok_but_http_failed"]["content_level"],
        "tls_ok_but_http_failed_transport_level": R["invariants"]["tls_ok_but_http_failed"]["transport_level"],
        "version_unique": W["version_unique"],
        "config_unique": R["invariants"]["config_unique"].get("all_unique"),
        "segments_without_stop": W["segments_without_stop"],
        "interruptions_without_stop": W["interruptions_without_stop"],
        "loopback_fail_minutes_total": R["controls"]["loopback_fail_minutes_total"],
        "loopback_fail_minutes_to_next_ok_total": R["controls"]["loopback_fail_minutes_to_next_ok_total"],
        "unexplained_stat_gaps": R["runtime"].get("stat", {}).get("gaps_unexplained"),
        "unexplained_idle_gaps": R["rate"]["idle_gaps_unexplained"],
        "unexplained_missing_hours": {p: files_r[p]["missing_hours_unexplained"] for p in ("probe", "judge", "snap") if p in files_r} or None,
        "rate_minutes_over_limit": R["rate"]["minutes_over_limit"]["minutes"],
        "evidence_missing_attempts": R["evidence"]["der"]["attempts_missing_file"] + R["evidence"]["body"]["attempts_missing_file"],
        "crosscheck_mismatches": R["crosscheck"].get("mismatch_count"),
        "preflight_selftest_mismatches": pf_self.get("不符"),
        "preflight_failures": pf_end.get("失败"),
        "note": "每项的分子分母和口径见对应小节与 definitions",
    }
    text = json.dumps(R, ensure_ascii=False, indent=1, sort_keys=False)
    assert_clean(text, db)
    if write:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "instrument.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
        print("已写出 %s（%d 字节）" % (path, len(text.encode("utf-8"))), file=sys.stderr)
    if markdown:
        print_markdown(R)
    return R


# ---------------------------------------------------------------- 自检

def _synthetic_db(path):
    """最小合成库：只建本模块用到的表和列（列名与 SCHEMA.md 一致），构造每条检查都会触发的数据。"""
    con = sqlite3.connect(path)
    c = con.cursor()
    c.executescript("""
    CREATE TABLE att (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, kind TEXT, arm TEXT, nonce TEXT,
                      tcp_ok INTEGER, tls_ok INTEGER, class TEXT, ip TEXT, ev TEXT, http_ev TEXT, ms INTEGER, cand_kind TEXT, cand_ip TEXT, prefix24 TEXT,
                      http_len INTEGER, http_pre INTEGER);
    CREATE TABLE req (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, remote TEXT, tls INTEGER, hello_fp TEXT, method TEXT, nonce TEXT, req_canary TEXT);
    CREATE TABLE req_header (rid INTEGER PRIMARY KEY, req_rid INTEGER, nonce TEXT, seq INTEGER, name TEXT, value TEXT);
    CREATE TABLE noise (rid INTEGER PRIMARY KEY, ts_epoch REAL);
    CREATE TABLE tls_fail (rid INTEGER PRIMARY KEY, ts_epoch REAL, hello_fp TEXT);
    CREATE TABLE req_dropped (rid INTEGER PRIMARY KEY, ts_epoch REAL, n INTEGER);
    CREATE TABLE noise_dropped (rid INTEGER PRIMARY KEY, ts_epoch REAL, n INTEGER);
    CREATE TABLE npre (rid INTEGER PRIMARY KEY, ts_epoch REAL, round INTEGER, node TEXT, tcp_ok INTEGER, class TEXT);
    CREATE TABLE nround (rid INTEGER PRIMARY KEY, ts_epoch REAL, round INTEGER, known INTEGER, listed INTEGER, supported INTEGER, backoff INTEGER,
                         tcp_ok INTEGER, probed INTEGER, ok_strict INTEGER, ok_linked INTEGER, bad_config INTEGER, batches INTEGER, ms INTEGER, err TEXT);
    CREATE TABLE stat (rid INTEGER PRIMARY KEY, ts_epoch REAL, up_min REAL, visits INTEGER, records INTEGER, pool TEXT);
    CREATE TABLE stat_pool (rid INTEGER PRIMARY KEY, stat_rid INTEGER, ts_epoch REAL, key TEXT, value INTEGER);
    CREATE TABLE start (rid INTEGER PRIMARY KEY, ts_epoch REAL, resumed_candidates INTEGER, load_err TEXT, http_port INTEGER, https_port INTEGER,
                        probe TEXT, payload_sha256 TEXT, judge_host_sha8 TEXT, judge_ip_sha8 TEXT);
    CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts_epoch REAL, visits INTEGER);
    CREATE TABLE version (rid INTEGER PRIMARY KEY, ts_epoch REAL, version TEXT);
    CREATE TABLE error (rid INTEGER PRIMARY KEY, ts_epoch REAL, what TEXT, err TEXT);
    CREATE TABLE visit (rid INTEGER PRIMARY KEY, ts_epoch REAL, visit TEXT, cand TEXT, "group" INTEGER, state TEXT, next_min REAL, aborted INTEGER);
    CREATE TABLE snap (rid INTEGER PRIMARY KEY, ts_epoch REAL, src TEXT, label TEXT, status INTEGER, err TEXT, n INTEGER, base INTEGER, agg INTEGER, changed INTEGER);
    CREATE TABLE nsnap (rid INTEGER PRIMARY KEY, ts_epoch REAL, src TEXT, status INTEGER, err TEXT, n INTEGER, base INTEGER, changed INTEGER);
    CREATE TABLE agg_sample (rid INTEGER PRIMARY KEY, ts_epoch REAL, src TEXT, sample INTEGER);
    CREATE TABLE evidence (hash TEXT, ext TEXT, bytes INTEGER, path TEXT);
    CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, prefix TEXT, hour TEXT, compressed INTEGER, status TEXT, records INTEGER, bad_lines INTEGER);
    CREATE TABLE file_kind (file_id INTEGER, k TEXT, n INTEGER);
    CREATE TABLE misc (rid INTEGER PRIMARY KEY, k TEXT);
    CREATE TABLE bad_line (rid INTEGER PRIMARY KEY, why TEXT);
    CREATE TABLE meta (key TEXT, value TEXT);
    CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_leaf (leaf TEXT, source TEXT, n INTEGER);
    """)
    T0 = dt.datetime(2026, 11, 6, 0, 0, tzinfo=dt.timezone.utc).timestamp()
    M = 60.0
    JUDGE_IP = "203.0.113.9"
    # 两个运行段：A [0, 120 min]，B [130, 240 min]；中断 10 分钟
    c.execute("INSERT INTO start VALUES (NULL, ?, 0, '', 80, 443, ?, ?, 'aaaaaaaa', 'bbbbbbbb')",
              (T0, json.dumps({"conn_per_sec": 40, "snapshot_min": 10, "alive_interval_min": 20}), '{"h":"x","j":"y","b":"z"}'))
    c.execute("INSERT INTO start VALUES (NULL, ?, 50, '', 80, 443, ?, ?, 'aaaaaaaa', 'bbbbbbbb')",
              (T0 + 130 * M, json.dumps({"conn_per_sec": 40, "snapshot_min": 10, "alive_interval_min": 20}), '{"h":"x","j":"y","b":"z"}'))
    c.execute("INSERT INTO stop VALUES (NULL, ?, 100)", (T0 + 120 * M,))
    c.execute("INSERT INTO stop VALUES (NULL, ?, 80)", (T0 + 240 * M,))
    c.execute("INSERT INTO version VALUES (NULL, ?, '0.1.1-test')", (T0 - 0.5,))
    c.execute("INSERT INTO version VALUES (NULL, ?, '0.1.1-test')", (T0 + 130 * M - 0.5,))
    c.execute("INSERT INTO self_ips VALUES (?, 'start.judge_ip', 2)", (JUDGE_IP,))
    c.execute("INSERT INTO self_names VALUES ('judge.invalid', 'start.judge_host', 2)")
    c.execute("INSERT INTO self_leaf VALUES ('leafhash', 'control_ok', 10)")
    nonce_seq = [0]

    def nonce():
        nonce_seq[0] += 1
        return "n%06d" % nonce_seq[0]

    def att(ts, cand, kind, proto, dst, cls, nonce_v=None, tls_ok=None, ip=None, ev=None, http_ev=None, arm=None, http_len=None, http_pre=None):
        c.execute("""INSERT INTO att (rid, ts, ts_epoch, visit, cand, proto, dst, kind, arm, nonce, tcp_ok, tls_ok, class, ip, ev, http_ev, ms,
                                      cand_kind, cand_ip, prefix24, http_len, http_pre)
                     VALUES (NULL, ?, ?, 'v', ?, ?, ?, 'h', ?, ?, 1, ?, ?, ?, ?, ?, 5, ?, ?, ?, ?, ?)""",
                  (iso_minute(ts), ts, cand, proto, dst, arm, nonce_v, tls_ok, cls, ip, ev, http_ev, kind,
                   cand.split(":")[0] if kind == "proxy" else None, None, http_len, http_pre))

    BASE_FP = "aaaa1111bbbb2222"

    def req(ts, nonce_v, remote, tls, fp=None, canary="ok", headers=None, method="GET"):
        c.execute("INSERT INTO req VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)", (iso_minute(ts), ts, remote, tls, fp if tls else None, method, nonce_v, canary))
        rid = c.lastrowid
        hs = headers if headers is not None else [("Accept", SENT_HEADERS["Accept"]), ("Accept-Encoding", "identity"), ("Accept-Language", "en-US,en;q=0.9"),
                                                  ("Connection", "close"), ("Cookie", "pc=CANARY"), ("User-Agent", SENT_HEADERS["User-Agent"]), ("X-Probe-Canary", "CANARY")]
        for i, (k, v) in enumerate(hs):
            c.execute("INSERT INTO req_header VALUES (NULL, ?, ?, ?, ?, ?)", (rid, nonce_v, i, k, v))

    # 对照：段 A 每分钟（0..119），段 B 每分钟（130..239）；观察者每 5 分钟
    for seg_start, seg_min in ((0, 120), (130, 110)):
        for i in range(seg_min):
            ts = T0 + (seg_start + i) * M
            minute = seg_start + i
            # 段 A 里 control:public 60..69 分钟缺失（没按时运行的空洞）
            for cand in ("control:loopback", "control:public"):
                if cand == "control:public" and 60 <= minute <= 69:
                    continue
                for dst, tls in (("judge_http", 0), ("judge_tls", 1)):
                    fail = cand == "control:loopback" and dst == "judge_tls" and 30 <= minute <= 32
                    nv = nonce()
                    if fail:
                        att(ts + 0.1, cand, "control", "direct", dst, "tls_eof", nv, 0)
                    else:
                        att(ts + 0.1, cand, "control", "direct", dst, "ok", nv, tls, ip=JUDGE_IP if cand == "control:public" else "127.0.0.1")
                        req(ts + 0.15, nv, JUDGE_IP if cand == "control:public" else "127.0.0.1", tls, BASE_FP)
            if i % 5 == 0:
                for name in ("obs:kv", "obs:plain"):
                    att(ts + 0.3, "control:observer", "control", "direct", name, "tcp_other")
    # 代理：正常 ok（seen）
    t = T0 + 10 * M
    nv = nonce(); att(t, "198.51.100.1:8080", "proxy", "connect", "judge_tls", "ok", nv, 1, ip="198.51.100.1"); req(t + 1, nv, "198.51.100.1", 1, BASE_FP)
    # 违反 1：ok 但 judge 没收到（早于 horizon）
    nv = nonce(); att(t + 5, "198.51.100.2:8080", "proxy", "forward", "judge_http", "ok", nv, None, ip="198.51.100.2")
    # 余量内无法判定：judge 最后一条记录在 T0+240min；这条在最后 5 秒内
    nv = nonce(); att(T0 + 240 * M - 5, "198.51.100.3:8080", "proxy", "forward", "judge_http", "ok", nv, None)
    # 违反 2：TLS 校验通过但 judge 收到的请求多了一个 Via 头
    nv = nonce(); att(t + 10, "198.51.100.4:1080", "proxy", "socks5", "judge_tls", "ok", nv, 1, ip="198.51.100.4")
    req(t + 11, nv, "198.51.100.4", 1, BASE_FP, headers=[("Accept", SENT_HEADERS["Accept"]), ("Accept-Encoding", "identity"), ("Accept-Language", "en-US,en;q=0.9"),
                                                        ("Connection", "close"), ("Cookie", "pc=CANARY"), ("User-Agent", SENT_HEADERS["User-Agent"]),
                                                        ("Via", "1.1 proxy"), ("X-Probe-Canary", "CANARY")])
    # 违反 3：TLS 校验通过但指纹不同
    nv = nonce(); att(t + 20, "198.51.100.5:8080", "proxy", "connect", "judge_tls", "ok", nv, 1, ip="198.51.100.5"); req(t + 21, nv, "198.51.100.5", 1, "cccc3333dddd4444")
    # 明文代理改了 UA（被测行为，不是仪器问题；进 reference）
    nv = nonce(); att(t + 30, "198.51.100.6:3128", "proxy", "forward", "judge_http", "ok", nv, None, ip="198.51.100.6")
    req(t + 31, nv, "198.51.100.6", 0, headers=[("Accept", SENT_HEADERS["Accept"]), ("Accept-Encoding", "identity"), ("Accept-Language", "en-US,en;q=0.9"),
                                               ("Cookie", "pc=CANARY"), ("User-Agent", "curl/8"), ("X-Probe-Canary", "CANARY")])
    # 违反 5：回显地址与日志不一致
    nv = nonce(); att(t + 40, "198.51.100.7:8080", "proxy", "connect", "judge_tls", "ok", nv, 1, ip="198.51.100.77"); req(t + 41, nv, "198.51.100.7", 1, BASE_FP)
    # 重放：同一 nonce 两份
    nv = nonce(); att(t + 50, "198.51.100.8:8080", "proxy", "forward", "judge_http", "ok", nv, None, ip="198.51.100.8")
    # 最早那份的 Accept 头出现两次、后一个是 */*：derive.go 取最后一个 → accept_changed（进 reference 的 tamper）
    req(t + 51, nv, "198.51.100.8", 0, headers=[("Accept", SENT_HEADERS["Accept"]), ("Accept-Encoding", "identity"), ("Accept-Language", "en-US,en;q=0.9"),
                                               ("Connection", "close"), ("Cookie", "pc=CANARY"), ("User-Agent", SENT_HEADERS["User-Agent"]),
                                               ("X-Probe-Canary", "CANARY"), ("Accept", "*/*")])
    req(t + 52, nv, "198.51.100.8", 0)
    # 节点：正常（出口是别处）、违反 4（出口是本机）
    nv = nonce(); att(t + 60, "abcdefabcdef", "node", "node", "judge_tls", "ok", nv, 1, ip="192.0.2.50", arm="strict"); req(t + 61, nv, "192.0.2.50", 1, BASE_FP)
    nv = nonce(); att(t + 70, "123456789abc", "node", "node", "judge_tls", "ok", nv, 1, ip=JUDGE_IP, arm="as_linked"); req(t + 71, nv, JUDGE_IP, 1, BASE_FP)
    # 证据：ev 找不到文件；http_ev 找得到
    att(t + 80, "198.51.100.9:8080", "proxy", "connect", "judge_tls", "tls_cert_invalid", None, 0, ev="deadbeef01")
    att(t + 81, "198.51.100.9:8080", "proxy", "connect", "judge_tls", "tls_cert_invalid", None, 0, ev="deadbeef01")
    att(t + 82, "198.51.100.10:8080", "proxy", "forward", "judge_http", "http_body_mismatch", None, None, http_ev="cafe0001")
    att(t + 83, "198.51.100.11:8080", "proxy", "forward", "judge_http", "http_body_mismatch", None, None, http_ev="cafe0002")
    c.execute("INSERT INTO evidence VALUES ('cafe0001', 'body', 100, 'x')")
    c.execute("INSERT INTO evidence VALUES ('orphan01', 'der', 100, 'x')")
    # TLS 校验通过后 HTTP 失败：内容层一次（judge 收到了，正文不符）、连接层一次（超时）
    nv = nonce(); att(t + 84, "198.51.100.14:8080", "proxy", "connect", "judge_tls", "http_body_mismatch", nv, 1, ip="198.51.100.14",
                      http_len=2784, http_pre=10)
    req(t + 85, nv, "198.51.100.14", 1, BASE_FP)
    nv = nonce(); att(t + 86, "198.51.100.15:8080", "proxy", "connect", "judge_tls", "http_timeout", nv, 1)
    # 正文被截断（收到的 1000 字节恰是期望 2784 字节的前缀）：归“截断”，不算内容层
    nv = nonce(); att(t + 87, "198.51.100.16:8080", "proxy", "connect", "judge_tls", "http_body_mismatch", nv, 1, http_len=1000, http_pre=1000)
    c.execute("INSERT OR REPLACE INTO meta VALUES ('payload_len', ?)", (json.dumps({"h": {"len": 2784, "n_ok": 1, "distinct_lens": 1}}),))
    # canceled（不算连接）
    att(t + 90, "198.51.100.12:8080", "proxy", "connect", "judge_tls", "canceled")
    att(t + 91, "198.51.100.12:8080", "proxy", "connect", "judge_tls", "canceled")
    # 速率：第 100 分钟塞 2401 条 att → 40.02/s，超过上限
    for i in range(2401):
        att(T0 + 100 * M + i * (60.0 / 2401), "198.51.100.13:8080", "proxy", "forward", "judge_http", "tcp_refused")
    # 空闲空洞：段 B 的 180..190 分钟没有任何连接（对照也缺）——删掉这些分钟的对照
    c.execute("DELETE FROM att WHERE ts_epoch >= ? AND ts_epoch < ?", (T0 + 180 * M, T0 + 191 * M))
    c.execute("DELETE FROM req WHERE ts_epoch >= ? AND ts_epoch < ?", (T0 + 180 * M, T0 + 191 * M))
    # npre：3 条有 tcp，2 条没有
    for i, (cls, tcp) in enumerate((("ok", 1), ("ok", 1), ("tcp_refused", 0), ("dns_nxdomain", None), ("skip_ipv6", None))):
        c.execute("INSERT INTO npre VALUES (NULL, ?, 1, ?, ?, ?)", (T0 + 2 * M + i, "node%02d" % i, tcp, cls))
    c.execute("INSERT INTO npre VALUES (NULL, ?, 2, 'node00', 1, 'ok')", (T0 + 62 * M,))
    # nround：段 A 两轮（第一轮 80 分钟），段 B 一轮
    c.execute("INSERT INTO nround VALUES (NULL, ?, 1, 10, 10, 9, 0, 8, 8, 4, 1, 0, 1, ?, NULL)", (T0 + 1 * M, 80 * 60000))
    c.execute("INSERT INTO nround VALUES (NULL, ?, 2, 10, 10, 9, 2, 6, 6, 4, 1, 0, 1, ?, NULL)", (T0 + 85 * M, 7 * 60000))
    c.execute("INSERT INTO nround VALUES (NULL, ?, 1, 10, 10, 9, 0, 8, 8, 4, 1, 0, 1, ?, 'sing-box 启动后退出')", (T0 + 131 * M, 9 * 60000))
    # stat：段 A 每 5 分钟（5..120），其中 50、55 两条缺（15 分钟空洞，非重启）；一条 up_min 错 5 分钟；段 B 每 5 分钟
    def stat(ts, up, skipped):
        pool = {"total": 100, "listed": 95, "working": 20, "open": 10, "dead": 70, "dropped": 0, "aggregator_sample": 10}
        pool.update({"skipped_" + k: v for k, v in skipped.items()})
        c.execute("INSERT INTO stat VALUES (NULL, ?, ?, 10, 100, ?)", (ts, up, json.dumps(pool)))
        rid = c.lastrowid
        for k, v in pool.items():
            c.execute("INSERT INTO stat_pool VALUES (NULL, ?, ?, ?, ?)", (rid, ts, k, v))
    for m in range(5, 121, 5):
        if m in (50, 55):
            continue
        stat(T0 + m * M, m + (5 if m == 25 else 0), {"skip_port": 4, "private": 2})
    for m in range(135, 241, 5):
        stat(T0 + m * M, m - 130, {"skip_port": 4, "private": 2, "self": 1})
    # error
    c.execute("INSERT INTO error VALUES (NULL, ?, '程序错误: 探访 198.51.100.99:8080', 'x')", (T0 + 3 * M,))
    c.execute("INSERT INTO error VALUES (NULL, ?, 'save state', 'x')", (T0 + 4 * M,))
    # visit：C1 working 准时；C2 working 迟到 2.5 倍（第 0 小时）；C3 跨中断；C4 dead；aborted 的一条
    def visit(ts, cand, state, next_min, aborted=None, grp=None):
        c.execute("INSERT INTO visit VALUES (NULL, ?, 'v', ?, ?, ?, ?, ?)", (ts, cand, grp, state, next_min, aborted))
    for i in range(6):
        visit(T0 + i * 20 * M, "198.51.100.1:8080", "working", 20.0)
    visit(T0 + 0 * M, "198.51.100.4:1080", "working", 20.0)
    visit(T0 + 50 * M, "198.51.100.4:1080", "working", 20.0)
    visit(T0 + 70 * M, "198.51.100.4:1080", "working", 20.0)
    visit(T0 + 110 * M, "198.51.100.5:8080", "working", 20.0)   # 下一次在中断之后 → 这对不算
    visit(T0 + 140 * M, "198.51.100.5:8080", "working", 20.0)
    visit(T0 + 160 * M, "198.51.100.5:8080", "working", 20.0)
    visit(T0 + 1 * M, "198.51.100.9:8080", "dead", 30.0)
    visit(T0 + 61 * M, "198.51.100.9:8080", "dead", 60.0)
    visit(T0 + 2 * M, "198.51.100.2:8080", "open", 120.0, aborted=1)   # aborted 不算
    visit(T0 + 3 * M, "198.51.100.2:8080", "open", 120.0)
    visit(T0 - 30 * M, "198.51.100.1:8080", "working", 20.0)   # 正式起点之前（试运行）
    # snap：常规 synthetic/listA http：段 A 13 次（1 次失败、1 次 304）、段 B 12 次；聚合器 synthetic/aggZ 每段 1 次
    for seg_start, n in ((0, 13), (130, 12)):
        for i in range(n):
            ts = T0 + (seg_start + i * 10) * M
            if seg_start == 0 and i == 3:
                c.execute("INSERT INTO snap VALUES (NULL, ?, 'synthetic/listA', 'http', 500, 'HTTP 500', NULL, NULL, NULL, NULL)", (ts,))
            elif seg_start == 0 and i == 4:
                c.execute("INSERT INTO snap VALUES (NULL, ?, 'synthetic/listA', 'http', 304, NULL, NULL, NULL, NULL, NULL)", (ts,))
            else:
                c.execute("INSERT INTO snap VALUES (NULL, ?, 'synthetic/listA', 'http', 200, NULL, 100, ?, NULL, 1)", (ts, 1 if i == 0 else None))
        c.execute("INSERT INTO snap VALUES (NULL, ?, 'synthetic/aggZ', 'http', 200, NULL, 5000, 1, 1, 1)", (T0 + seg_start * M + 1,))
    c.execute("INSERT INTO agg_sample VALUES (NULL, ?, 'synthetic/aggZ', 4)", (T0 + 1,))
    # nsnap：5 次
    for i in range(5):
        c.execute("INSERT INTO nsnap VALUES (NULL, ?, 'synthetic/sub', 200, NULL, 10, ?, ?)", (T0 + i * 30 * M, 1 if i == 0 else None, 1 if i < 2 else None))
    # files / file_kind / meta
    for i, (name, prefix, hour) in enumerate((("probe-20261106-00.jsonl.gz", "probe", "20261106-00"), ("probe-20261106-01.jsonl.gz", "probe", "20261106-01"),
                                              ("probe-20261106-03.jsonl", "probe", "20261106-03"), ("judge-20261106-00.jsonl.gz", "judge", "20261106-00"),
                                              ("snap-20261106-00.jsonl", "snap", "20261106-00"))):
        c.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?, 'read', 10, 0)", (i + 1, name, prefix, hour, 1 if name.endswith(".gz") else 0))
    c.execute("INSERT INTO files VALUES (99, 'probe-20261106-01.jsonl', 'probe', '20261106-01', 0, 'duplicate_skipped', 10, 0)")
    att_n = c.execute("SELECT COUNT(*) FROM att").fetchone()[0]
    c.execute("INSERT INTO file_kind VALUES (1, 'att', ?)", (att_n,))
    c.execute("INSERT INTO file_kind VALUES (1, 'visit', 14)")
    c.execute("INSERT INTO file_kind VALUES (4, 'req', ?)", (c.execute("SELECT COUNT(*) FROM req").fetchone()[0],))
    c.execute("INSERT INTO meta VALUES ('ingest_version', 'selftest')")
    c.execute("INSERT INTO meta VALUES ('judge_leaf_observed_count', '1')")
    c.execute("INSERT INTO meta VALUES ('judge_leaf_tls_ok_extra_count', '0')")
    c.execute("INSERT INTO meta VALUES ('evidence_files', '2')")
    c.execute("INSERT INTO meta VALUES ('duplicate_hour_files', '[{\"skipped\":\"probe-20261106-01.jsonl\",\"lines\":10,\"read_records\":10}]')")
    c.execute("INSERT INTO meta VALUES ('unknown_fields', '{}')")
    c.execute("INSERT INTO meta VALUES ('misplaced_kinds', '{}')")
    c.execute("INSERT INTO meta VALUES ('summary_json', ?)", (json.dumps({"generated": "x", "records": {"att": att_n, "visit": 14}, "judge": {"req": 1}}),))
    c.execute("INSERT INTO noise_dropped VALUES (NULL, ?, 3)", (T0 + 5 * M,))
    c.execute("INSERT INTO tls_fail VALUES (NULL, ?, 'ffff9999eeee8888')", (T0 + 6 * M,))
    c.execute("INSERT INTO tls_fail VALUES (NULL, ?, ?)", (T0 + 7 * M, BASE_FP))
    # 建与 ingest.py 相同的索引（表或列不存在的跳过），让自检里的查询计划与真实库一致
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import ingest  # noqa: E402
        for ddl in ingest.INDEXES:
            try:
                c.execute(ddl)
            except sqlite3.OperationalError:
                pass
    except ImportError:
        pass
    con.commit()
    con.close()
    return T0


def _variant(src, dst, sqls):
    """复制合成库并执行几条修改语句，造出崩溃、配置缺项、NAT 等情形。"""
    import shutil
    shutil.copyfile(src, dst)
    con = sqlite3.connect(dst)
    for sql, params in sqls:
        con.execute(sql, params)
    con.commit()
    con.close()
    return dst


def selftest():
    tmp = tempfile.mkdtemp(prefix="m_instrument_selftest_")
    db_path = os.path.join(tmp, "synthetic.sqlite")
    _synthetic_db(db_path)
    # 一份 summary.json，覆盖交叉核对的分支。故意留三处不一致：judge.req=1、pool 只给两个键、没给“TLS 内不同”这条 finding
    con = sqlite3.connect(db_path)
    att_n = con.execute("SELECT COUNT(*) FROM att").fetchone()[0]
    con.close()
    summ = os.path.join(tmp, "summary.json")
    with open(summ, "w", encoding="utf-8") as fh:
        json.dump({"generated": "x", "warnings": ["直连第二观察者全部失败：x", "仪器异常：TLS 内的请求到达 judge 时与发出时不同：1 次"],
                   "records": {"att": att_n, "visit": 14}, "judge": {"req": 1, "noise": 3},
                   # 回环：段 A 120 + 段 B 110 − 空闲空洞删掉的 11 = 219；公网再减 60..69 的 10 = 209；观察者 24 + 22 − 3 = 43
                   "control": {"control:loopback judge_http": {"ok": 219, "total": 219}, "control:loopback judge_tls": {"ok": 216, "total": 219},
                               "control:public judge_http": {"ok": 209, "total": 209}, "control:public judge_tls": {"ok": 209, "total": 209},
                               "control:observer obs:kv": {"ok": 0, "total": 43}, "control:observer obs:plain": {"ok": 0, "total": 43},
                               # 观察者名写成主机名：键要归一化成 obs:<观察者>，主机名不能进输出
                               "control:observer obs:echo.example.org": {"ok": 0, "total": 0}},
                   "rate": {"attempts_per_sec_avg": "0.1", "attempts_per_sec_peak_minute": "40.1", "configured_conn_per_sec": 40},
                   "snapshots": [{"src": "synthetic/listA", "fetches": 25, "failed": 1, "changed": 23}, {"src": "synthetic/aggZ", "fetches": 2, "failed": 0, "changed": 2}],
                   "nodes": {"subscriptions": [{"src": "synthetic/sub", "fetches": 5, "failed": 0, "changed": 2}], "precheck": {"ok": 2, "tcp_refused": 1, "dns_nxdomain": 1, "skip_ipv6": 1}},
                   "pool": {"total": 100, "skipped_self": 1},
                   "findings": {"探测器认为成功，但 judge 没收到请求": {"attempts": 1, "candidates": 1},
                                "仪器异常：节点探测的流量从本机直接出去了": {"attempts": 1, "candidates": 1},
                                "响应头里回显的地址与 judge 日志不一致": {"attempts": 1, "candidates": 1},
                                "同一请求被 judge 收到多次（重放）": {"attempts": 1, "candidates": 1}}}, fh, ensure_ascii=False)
    pfl = os.path.join(tmp, "preflight.txt")
    with open(pfl, "w", encoding="utf-8") as fh:
        fh.write("预检  2026-11-05T23:58:00Z\n\n测量机\n  通过  judge 主机名 judge.example.org，公网地址 192.0.2.10\n\n"
                 "sing-box\n  通过  sing-box version 1.14.4，接受探测器生成的配置\n仪器自检\n  通过  共核对 199 项，0 项不符\n"
                 "结论：0 项失败，1 项注意\n")
    dbs = []
    res = run(db_path, os.path.join(tmp, "out"), summary_path=summ, markdown=False, write=True, check_plans=True, db_out=dbs,
              preflight_path=pfl)
    failures = []
    n_asserts = [0]

    def expect(name, got, want):
        n_asserts[0] += 1
        if got != want:
            failures.append("%s: 得到 %r，期望 %r" % (name, got, want))

    W = res["window"]
    expect("运行段数", len(W["segments"]), 2)
    expect("中断数", len(W["interruptions"]), 1)
    expect("中断分钟", W["interruptions"][0]["minutes"], 10.0)
    expect("中断以 stop 结束", W["interruptions"][0]["ended_by_stop"], True)
    expect("没有 stop 的运行段", W["segments_without_stop"], 0)
    expect("运行合计分钟", W["uptime_minutes_total"], 230.0)
    expect("版本唯一", W["version_unique"], True)
    expect("正式起点", W["formal_start_utc"], "2026-11-06T00:00Z")
    pf = res.get("preflight") or {}
    expect("预检时间", pf.get("预检时间"), "2026-11-05T23:58:00Z")
    expect("仪器自检", pf.get("仪器自检"), {"状态": "通过", "核对": 199, "不符": 0})
    expect("预检里的 sing-box 版本", pf.get("sing-box 版本"), "1.14.4")
    expect("预检结论", pf.get("结论"), {"失败": 0, "注意": 1})
    pf_text = json.dumps(res, ensure_ascii=False)
    expect("预检报告里的主机名和地址不进输出", ("judge.example.org" in pf_text) or ("192.0.2.10" in pf_text), False)
    expect("verdict：仪器自检不符", res["verdict"]["preflight_selftest_mismatches"], 0)
    expect("verdict：预检失败", res["verdict"]["preflight_failures"], 0)
    pf_bad = os.path.join(tmp, "preflight_bad.txt")
    with open(pf_bad, "w", encoding="utf-8") as fh:
        fh.write("预检  2026-11-05T23:58:00Z\n仪器自检\n  失败  对照代理 x：期望 a，得到 b\n    共核对 199 项，1 项不符\n结论：1 项失败，0 项注意\n")
    expect("仪器自检不通过时的汇总行（没有状态词）", preflight(pf_bad, "argument").get("仪器自检"), {"状态": None, "核对": 199, "不符": 1})
    C = res["controls"]
    lo = C["items"]["control:loopback judge_tls"]
    expect("回环 TLS 总数", lo["成功率"]["den"], 219)          # 120 + 110 − 空闲空洞里删掉的 11
    expect("回环 TLS 失败", lo["成功率"]["den"] - lo["成功率"]["num"], 3)
    expect("回环 TLS 期望", lo["期望次数"], 232)                # (120+1) + (110+1)
    expect("观察者成功率", C["items"]["control:observer obs:kv"]["成功率"]["pct"], 0.0)
    expect("观察者期望", C["items"]["control:observer obs:kv"]["期望次数"], 48)   # 24 + 23 + 2（每段启动立即一次）
    expect("失败时段数（回环 TLS 一段 + 两个观察者各一段）", C["fail_spans_count"], 3)
    lo_span = [s for s in C["fail_spans"] if s["item"] == "control:loopback judge_tls"]
    expect("回环 TLS 失败时段", [(s["attempts"], s["span_minutes"], s["from_utc"], s["to_utc"]) for s in lo_span],
           [(3, 2.0, "2026-11-06T00:30Z", "2026-11-06T00:32Z")])
    expect("回环合并失败分钟段", C["loopback_fail_spans"], [{"from_utc": "2026-11-06T00:30Z", "to_utc": "2026-11-06T00:32Z", "minutes": 3,
                                                       "failed_attempts": 3, "attempts": 6}])
    expect("回环合并失败分钟合计", C["loopback_fail_minutes_total"], 3)
    # 算到下一次成功：00:30:00.1 失败 … 00:33:00.1 成功 → 3.0 分钟，止点向上取整到 00:34
    expect("回环失败到下一次成功", C["loopback_fail_spans_to_next_ok"], [{"from_utc": "2026-11-06T00:30Z", "to_utc": "2026-11-06T00:34Z",
                                                                  "minutes": 3.0, "failed_attempts": 3}])
    gaps = C["schedule_gaps"]
    # 公网 60..69 缺失（2 项，非重启）；空闲空洞 180..190 删掉了对照（4 项非重启 + 观察者 2 项非重启，观察者 175→195 = 20 分钟 > 15）；重启 120→130（4 项，观察者 115→130 = 15 分钟不超过 3 倍周期）
    expect("没按时运行", sorted((g["item"], g["explained_by_restart"]) for g in gaps),
           sorted([("control:public judge_http", False), ("control:public judge_tls", False),
                   ("control:loopback judge_http", True), ("control:loopback judge_tls", True), ("control:public judge_http", True), ("control:public judge_tls", True),
                   ("control:loopback judge_http", False), ("control:loopback judge_tls", False), ("control:public judge_http", False), ("control:public judge_tls", False),
                   ("control:observer obs:kv", False), ("control:observer obs:plain", False)]))
    expect("没按时运行：重启解释不了的", C["schedule_gaps_unexplained"], 8)
    I = res["invariants"]
    expect("judge 收到：违反", I["judge_received"]["violations"], 1)
    expect("judge 收到：余量内", I["judge_received"]["undeterminable_within_lag"], 1)
    expect("judge 收到：按类别", I["judge_received"]["by_kind_violations"], {"proxy": 1})
    expect("TLS 内一致：违反", I["tls_request_identical"]["violations"], 1)
    expect("TLS 内一致：多出的头", [a["header"] for a in I["tls_request_identical"]["added_header_names"]], ["Via"])
    expect("TLS 内一致：参考 tamper（含 Accept 重复取最后一个）", I["tls_request_identical"]["reference_all_ok_seen"]["tamper"], 2)
    expect("指纹：基线", I["tls_hello_fingerprint"]["baseline_fps"], ["aaaa1111bbbb2222"])
    expect("指纹：违反", I["tls_hello_fingerprint"]["violations"], 1)
    expect("指纹：其他指纹", [(o["hello_fp"], o["attempts"]) for o in I["tls_hello_fingerprint"]["other_fps"]], [("cccc3333dddd4444", 1)])
    expect("指纹：tls_fail 基线数", I["tls_hello_fingerprint"]["tls_fail_fps"]["with_baseline_fp"], 1)
    expect("节点出口：违反", I["node_egress_not_self"]["violations"], 1)
    expect("节点出口：按 arm", I["node_egress_not_self"]["by_arm_violations"], {"as_linked": 1})
    expect("节点出口：分母", I["node_egress_not_self"]["denominator_node_ok_seen_attempts"], 2)
    expect("节点出口：本机地址来源", I["node_egress_not_self"]["self_ip_sources_used"], ["start.judge_ip"])
    expect("节点出口：可判定（没有 NAT）", (I["node_egress_not_self"]["determinable"], I["node_egress_not_self"]["status"].startswith("可判定（公网对照的对端地址都等于")),
           (True, True))
    expect("节点出口：NAT 信号（没有实测对端地址行）", I["node_egress_not_self"]["judge_remote_public_equals_judge_ip"], None)
    tf = I["tls_ok_but_http_failed"]
    expect("TLS 通过后 HTTP 失败", (tf["by_class"], tf["content_level"], tf["transport_level"], tf["content_level_by_kind"]),
           ({"http_body_mismatch": 2, "http_timeout": 1}, 1, 1, {"proxy": 1}))
    expect("TLS 通过后正文被截断单列", (tf["body_truncated"], tf["attempts"]), (1, 3))
    expect("TLS 通过后 HTTP 失败进 verdict", res["verdict"]["tls_ok_but_http_failed_content_level"], 1)
    expect("回显：违反", I["echo_matches_log"]["violations"], 1)
    expect("对照原样：违反", I["control_request_intact"]["violations"], 0)
    expect("对照原样：公网 NAT", I["control_request_intact"]["control_public_remote_not_judge_ip"], 0)
    expect("配置唯一", I["config_unique"]["all_unique"], True)
    expect("配置 conn_per_sec", I["config_unique"]["conn_per_sec_values"], [40])
    expect("任何违反", I["summary"]["any_violation"], True)
    RT = res["rate"]
    expect("速率：canceled 排除", RT["canceled_att_excluded"], 2)
    expect("速率：npre 排除", RT["npre_without_tcp_excluded"], 2)
    expect("速率：npre 连接", RT["npre_connections"], 4)
    expect("速率：峰值分钟", RT["per_sec_peak_minute"], round((2401 + 6) / 60.0, 2))   # 第 100 分钟还有 4 条 judge 对照 + 2 条观察者对照
    expect("速率：超限分钟", RT["minutes_over_limit"]["minutes"], 1)
    expect("速率：分位个数", len(RT["per_sec_minute_quantiles_p50_p90_p99"]), 3)
    # 段 A 最后的连接在第 119 分钟、段 B 从 130 开始 → 空 10 分钟（重启）；180..190 共 11 分钟被删掉（非重启）
    expect("速率：空闲空洞", [(g["minutes"], g["explained_by_restart"]) for g in RT["idle_gaps"]], [(10, True), (11, False)])
    expect("速率：summary 口径峰值", RT["summary_go_style_att_only"]["attempts_per_sec_peak_minute"], "40.1")
    U = res["runtime"]
    expect("stat 条数", U["stat"]["records"], 22 + 22)
    expect("stat 空洞", [(g["minutes"], g["explained_by_restart"]) for g in U["stat"]["gaps"]], [(15.0, False), (15.0, True)])
    expect("stat up_min 不一致", U["stat"]["up_min_inconsistent"], 1)
    expect("error 归一化", U["errors"]["by_what"], {"程序错误: 探访 <候选>": 1, "save state": 1})
    # 02 时：02:00–02:10 是中断，02:10 以后在运行，整小时不在中断里
    expect("files 缺小时", U["files"]["probe"]["missing_hours"], [{"hour": "20261106-02", "explained_by_restart": False}])
    expect("files 缺小时：重启解释不了", U["files"]["probe"]["missing_hours_unexplained"], 1)
    expect("files 状态", U["files"]["probe"]["status_counts"], {"read": 3, "duplicate_skipped": 1})
    B = res["backlog"]
    rv = B["revisit_ratio"]
    expect("积压：跨中断排除", rv["pairs_excluded_spanning_interruption"], 1)
    pf = res["backlog"]["pool_at_first_stat"]
    expect("启动时的候选池", (pf["utc"], pf["pool"]["total"], pf["pool_total_max"]), ("2026-11-06T00:05Z", 100, 100))
    expect("积压：试运行排除（对子）", rv["pairs_before_formal_start_excluded"], 1)
    expect("积压：试运行探访条数", rv["visits_before_formal_start"], 1)
    expect("积压：区间外的小时", rv["hours_out_of_band"], {"working": [], "open": [], "dead": []})
    expect("积压：p90 超过 2 的小时（working）", {k: rv["hours_p90_over_2"]["working"][k] for k in ("hours", "hour_list", "max_p90", "max_p90_hour")},
           {"hours": 1, "hour_list": [0], "max_p90": 2.5, "max_p90_hour": 0})
    h0 = {h["hour"]: h for h in rv["by_hour"]}
    expect("积压：第 0 小时 working 对子", h0[0]["working"]["pairs"], 5)   # C1 三对（0,20,40 → 下一次）+ C2 两对（0→50、50→70）
    expect("积压：第 0 小时 working 中位数", h0[0]["working"]["median"], 1.0)   # 1, 1, 1, 2.5, 1 → 1.0
    expect("积压：第 0 小时 working p90", h0[0]["working"]["p90"], 2.5)
    expect("积压：第 0 小时 dead", h0[0]["dead"], {"pairs": 1, "median": 2.0, "p90": 2.0})
    expect("积压：恢复小时", rv["recovered_hour"], {"working": 0, "open": None, "dead": None})
    expect("积压：第 1 小时 working 对子", h0[1]["working"]["pairs"], 2)   # C1 60→80、80→100
    nr = B["node_rounds"]
    expect("节点轮次数", nr["count"], 3)
    expect("节点第一轮分钟", nr["first_round_minutes"], 80.0)
    expect("节点轮次段号", [r["segment"] for r in nr["rounds"]], [1, 1, 2])
    expect("节点轮次出错", nr["rounds_with_error"], 1)
    E = res["evidence"]
    expect("证据 der 缺失尝试", E["der"]["attempts_missing_file"], 2)
    expect("证据 der 缺失哈希", E["der"]["distinct_hashes_missing_file"], 1)
    expect("证据 body 缺失", E["body"]["attempts_missing_file"], 1)
    expect("证据孤儿", E["orphan_files_not_referenced"], {"der": 1, "body": 0})
    expect("证据去重哈希", (E["der"]["distinct_hashes_referenced"], E["body"]["distinct_hashes_referenced"]), (1, 2))
    expect("证据按类别", E["by_kind"]["proxy"]["der"], {"attempts_with_ev": 2, "distinct_hashes": 1, "attempts_missing_file": 2, "distinct_hashes_missing_file": 1})
    S = res["snapshots"]
    fa = [f for f in S["lists"]["files"] if f["src"] == "synthetic/listA"][0]
    expect("快照 listA 抓取", fa["fetches"], 25)
    expect("快照 listA 失败", fa["failed"], 1)
    expect("快照 listA 304", fa["status_304"], 1)
    expect("快照 listA 期望", fa["expected_fetches"], 13 + 12)
    expect("快照 listA 首次", fa["base_snapshots"], 2)
    fz = [f for f in S["lists"]["files"] if f["src"] == "synthetic/aggZ"][0]
    expect("快照 aggZ 期望", fz["expected_fetches"], 2)
    expect("快照抓取空洞", S["lists"]["fetch_gaps_count"], 0)
    expect("聚合器抽样记录", S["aggregator_samples"]["synthetic/aggZ"]["records"], 1)
    expect("订阅抓取", S["subscriptions"]["subs"][0]["fetches"], 5)
    expect("订阅期望", S["subscriptions"]["expected_fetches"], 5 + 4)
    X = res["excluded"]
    expect("排除：段 1", X["by_segment"][0]["skipped"], {"skip_port": 4, "private": 2})
    expect("排除：段 2", X["by_segment"][1]["skipped"], {"skip_port": 4, "private": 2, "self": 1})
    expect("排除：原因", X["skipped_reasons_seen"], ["private", "self", "skip_port"])
    K = res["crosscheck"]
    expect("交叉：来源", K["source"], "argument")
    expect("交叉：警告归类", K["warnings"]["by_category"], {"直连第二观察者全部失败": 1, "仪器异常": 1})
    expect("交叉：警告仪器相关", K["warnings"]["instrument_related"], 1)
    expect("交叉：control 回环 http", K["comparisons"]["control.control:loopback judge_http"]["match"], True)
    expect("交叉：rate 峰值", K["comparisons"]["rate.attempts_per_sec_peak_minute"]["match"], True)
    expect("交叉：snapshots fetches", K["comparisons"]["snapshots.synthetic/listA.fetches"]["match"], True)
    expect("交叉：precheck", K["comparisons"]["nodes.precheck.ok"]["match"], True)
    expect("交叉：pool skipped_self", K["comparisons"]["pool.skipped_self"]["match"], True)
    expect("交叉：findings 没收到", K["comparisons"]["findings.探测器认为成功，但 judge 没收到请求.attempts"]["match"], True)
    expect("交叉：findings 节点出口", K["comparisons"]["findings.仪器异常：节点探测的流量从本机直接出去了.candidates"]["match"], True)
    expect("交叉：findings TLS 内不同（summary 没给 → 0 vs 2）", K["comparisons"]["findings.仪器异常：TLS 内的请求到达 judge 时与发出时不同.attempts"],
           {"summary": 0, "computed": 2, "match": False})
    expect("交叉：故意不一致 judge.req", K["comparisons"]["judge.req"]["match"], False)
    expect("交叉：pool.total", K["comparisons"]["pool.total"]["match"], True)
    # 合成的 summary.json 故意只给了部分 pool 键和 judge.req=1：除这些和 summary 没给的 findings 外，其余都应一致
    unexpected = [k for k in K["mismatches"] if not (k.startswith("pool.") or k == "judge.req" or k.startswith("findings.仪器异常：TLS")
                                                     or k == "rate.attempts_per_sec_avg")]
    expect("交叉：意料之外的不一致项", unexpected, [])
    expect("交叉：pool 只给的两个键一致", [K["comparisons"]["pool.total"]["match"], K["comparisons"]["pool.skipped_self"]["match"]], [True, True])
    expect("配置：探测配置无差异", I["config_unique"]["probe_config_keys_differing"], [])
    expect("配置：调度配置没变", I["config_unique"]["schedule_config_changed"], False)
    expect("交叉：不一致项里没有 control", [k for k in K["mismatches"] if k.startswith("control.")], [])
    expect("交叉：不一致项里没有 snapshots", [k for k in K["mismatches"] if k.startswith("snapshots.")], [])
    expect("交叉：不一致项里没有 precheck", [k for k in K["mismatches"] if k.startswith("nodes.precheck")], [])
    expect("交叉：带点号的观察者键已归一化", K["comparisons"].get("control.control:observer obs:<观察者>"),
           {"summary": {"ok": 0, "total": 0}, "computed": {"ok": 0, "total": 0}, "match": True})
    # summary.go 口径：五条都不含对照组；节点出口只看 judge_tls 与 start.judge_ip
    expect("交叉：summary.go 口径", K["findings_summary_go_caliber"],
           {"探测器认为成功，但 judge 没收到请求": {"attempts": 1, "candidates": 1},
            "仪器异常：TLS 内的请求到达 judge 时与发出时不同": {"attempts": 2, "candidates": 2},
            "仪器异常：节点探测的流量从本机直接出去了": {"attempts": 1, "candidates": 1},
            "响应头里回显的地址与 judge 日志不一致": {"attempts": 1, "candidates": 1},
            "同一请求被 judge 收到多次（重放）": {"attempts": 1, "candidates": 1}})
    # 查询计划：相关子查询里不许整表扫 att；att 整表（或整个 nonce 索引）恰好三遍
    pdb = dbs[0]
    expect("计划：相关子查询里整表扫 att", pdb.correlated_att_scans, [])
    expect("计划：整表扫 att 的语句数", len(pdb.att_full_scans), 3)
    # 恢复小时的规则：取最后一个区间外的小时 + 1，不取第一个区间内的小时
    def mh(*pm):
        return {h: ({"pairs": p, "median": m} if p else None) for h, (p, m) in enumerate(pm)}
    expect("恢复：第 0 小时正常、1-2 小时积压", recovered_hour(mh((6, 1.0), (10, 2.0), (10, 1.5), (3, 1.0), (10, 1.02)))[0], 3)
    expect("恢复：区间外的小时", [o["hour"] for o in recovered_hour(mh((6, 1.0), (10, 2.0), (10, 1.5), (3, 1.0), (10, 1.02)))[1]], [1, 2])
    expect("恢复：一直正常", recovered_hour(mh((3, 2.0), (10, 1.0), (10, 0.95)))[0], 0)
    expect("恢复：到最后都没恢复", recovered_hour(mh((10, 2.0), (10, 1.0), (10, 1.6), (2, 1.0)))[0], None)
    expect("恢复：没有够数的小时", recovered_hour(mh((2, 2.0), (4, 1.0)))[0], None)
    expect("观察者键归一化", norm_control_key("control:observer obs:ip.example.net"), "control:observer obs:<观察者>")
    with open(os.path.join(tmp, "out", "instrument.json"), encoding="utf-8") as fh:
        text = fh.read()
    expect("输出里没有 ip:port", bool(HOSTPORT_RE.search(text)), False)
    expect("输出里没有 judge IP", "203.0.113.9" in text, False)
    expect("输出里没有 judge 主机名", "judge.invalid" in text, False)
    expect("输出里没有候选地址", "198.51.100" in text, False)
    expect("输出里没有观察者主机名", "example.org" in text, False)
    # 没有 summary.json、也没有 cands 的路径：meta_only
    res2 = run(db_path, os.path.join(tmp, "out2"), summary_path=None, markdown=True, write=False)
    expect("交叉：meta_only", res2["crosscheck"]["source"], "meta_only")
    expect("交叉：meta_only records.att", res2["crosscheck"]["comparisons"]["records.att"]["match"], True)
    expect("交叉：meta_only 不比 control / findings", [k for k in res2["crosscheck"]["comparisons"] if k.startswith(("control.", "findings."))], [])

    # 崩溃重启：删掉第一条 stop（进程被杀时没有 stop）。中断应照样找出来（段末取崩溃前最后一条记录：120 分钟的 stat / snap），
    # 空洞都由重启解释，跨崩溃的探访对（110 → 140 分钟）不进积压
    crash = _variant(db_path, os.path.join(tmp, "crash.sqlite"), [("DELETE FROM stop WHERE ts_epoch < (SELECT MIN(ts_epoch) + 1 FROM stop)", ())])
    rc = run(crash, os.path.join(tmp, "out_crash"), summary_path=None, write=False)
    Wc = rc["window"]
    expect("崩溃：中断", [(i["minutes"], i["ended_by_stop"]) for i in Wc["interruptions"]], [(10.0, False)])
    expect("崩溃：中断分钟合计", Wc["interruption_minutes_total"], 10.0)
    expect("崩溃：没有 stop 的中断", Wc["interruptions_without_stop"], 1)
    expect("崩溃：没有 stop 的运行段", Wc["segments_without_stop"], 1)
    expect("崩溃：运行合计分钟", Wc["uptime_minutes_total"], 230.0)
    expect("崩溃：stat 空洞", [(g["minutes"], g["explained_by_restart"]) for g in rc["runtime"]["stat"]["gaps"]], [(15.0, False), (15.0, True)])
    expect("崩溃：stat 期望（崩溃没有最后一条 stat）", rc["runtime"]["stat"]["expected_records"], 25 + 23 - 2 + 1)
    expect("崩溃：空闲空洞", [(g["minutes"], g["explained_by_restart"]) for g in rc["rate"]["idle_gaps"]], [(10, True), (11, False)])
    expect("崩溃：对照空洞重启解释不了的", rc["controls"]["schedule_gaps_unexplained"], 8)
    expect("崩溃：跨崩溃的探访对", rc["backlog"]["revisit_ratio"]["pairs_excluded_spanning_interruption"], 1)
    expect("崩溃：第 1 小时 working 对子", {h["hour"]: h for h in rc["backlog"]["revisit_ratio"]["by_hour"]}[1]["working"]["pairs"], 2)

    # start.probe 缺 conn_per_sec / snapshot_min（或整个为 NULL）：用默认值并标出来，不能抛异常
    nolim = _variant(db_path, os.path.join(tmp, "nolimit.sqlite"),
                     [("UPDATE start SET probe = ? WHERE rid = 1", ('{"snapshot_min":10}',)), ("UPDATE start SET probe = NULL WHERE rid = 2", ())])
    rn = run(nolim, os.path.join(tmp, "out_nolimit"), summary_path=None, write=False)
    expect("缺配置：速率上限取默认", (rn["rate"]["configured_conn_per_sec"], rn["rate"]["configured_from_default"], rn["rate"]["configured_values_seen"]),
           (DEFAULT_CONN_PER_SEC, True, []))
    expect("缺配置：snapshot_min", (rn["snapshots"]["lists"]["snapshot_min"], rn["snapshots"]["lists"]["snapshot_min_values_seen"]), (10, [10]))

    # NAT：公网对照在 judge 日志里的对端地址是内网地址；一个节点的出口正是这个内网地址（流量从本机直接出去了）
    nat_sqls = [("UPDATE req SET remote = '10.0.0.5' WHERE nonce IN (SELECT nonce FROM att WHERE cand = 'control:public')", ()),
                ("UPDATE att SET ip = '10.0.0.5' WHERE cand = 'control:public' AND ip IS NOT NULL", ()),
                ("INSERT INTO att (ts, ts_epoch, visit, cand, proto, dst, kind, arm, nonce, tcp_ok, tls_ok, class, ip, ms, cand_kind) "
                 "VALUES ('x', (SELECT MIN(ts_epoch) + 600 FROM att), 'v', 'fedcbafedcba', 'node', 'judge_http', 'h', 'strict', 'natnode', 1, NULL, 'ok', '10.0.0.5', 5, 'node')", ()),
                ("INSERT INTO req (ts, ts_epoch, remote, tls, hello_fp, method, nonce, req_canary) "
                 "VALUES ('x', (SELECT MIN(ts_epoch) + 601 FROM att), '10.0.0.5', 0, NULL, 'GET', 'natnode', 'ok')", ())]
    nat = _variant(db_path, os.path.join(tmp, "nat.sqlite"),
                   nat_sqls + [("INSERT INTO self_ips VALUES ('10.0.0.5', 'judge_remote:control:public', 418)", ())])
    rt_ = run(nat, os.path.join(tmp, "out_nat"), summary_path=summ, write=True)
    ne = rt_["invariants"]["node_egress_not_self"]
    expect("NAT：节点出口违反（含实测对端地址）", (ne["violations"], ne["nodes_involved"], ne["determinable"]), (2, 2, True))
    expect("NAT：本机地址来源", ne["self_ip_sources_used"], ["judge_remote:control:public", "start.judge_ip"])
    expect("NAT：信号", ne["judge_remote_public_equals_judge_ip"], False)
    expect("NAT：公网对照对端不是配置 IP", rt_["invariants"]["control_request_intact"]["control_public_remote_not_judge_ip"], 418)
    expect("NAT：summary.go 口径只认 start.judge_ip、只看 judge_tls",
           rt_["crosscheck"]["findings_summary_go_caliber"]["仪器异常：节点探测的流量从本机直接出去了"], {"attempts": 1, "candidates": 1})
    nat2 = _variant(db_path, os.path.join(tmp, "nat_noremote.sqlite"), nat_sqls)
    r2 = run(nat2, os.path.join(tmp, "out_nat2"), summary_path=None, write=False)
    ne2 = r2["invariants"]["node_egress_not_self"]
    expect("NAT 但缺实测对端地址：无法判定", (ne2["determinable"], ne2["status"].startswith("无法判定"), r2["verdict"]["node_egress_not_self_determinable"]),
           (False, True, False))
    with open(os.path.join(tmp, "out_nat", "instrument.json"), encoding="utf-8") as fh:
        expect("NAT：输出里没有内网地址", "10.0.0.5" in fh.read(), False)

    # 复测间隔比按候选密集的 /24 分开：10.0.0 有 101 个候选（状态文件 100 个 + 只在尝试记录里的 1 个）→ 密集；
    # 10.0.1 只有 1 个候选；prefix24 为空的对子算“其他 /24”
    dpath = os.path.join(tmp, "dense_split.sqlite")
    con = sqlite3.connect(dpath)
    con.execute("CREATE TABLE cands (key TEXT, prefix24 TEXT)")
    con.execute("CREATE TABLE att (cand TEXT, prefix24 TEXT, cand_kind TEXT)")
    con.executemany("INSERT INTO cands VALUES (?, '10.0.0')", [("c%d" % i,) for i in range(100)])
    con.execute("INSERT INTO cands VALUES ('d0', '10.0.1')")
    con.executemany("INSERT INTO att VALUES (?, ?, ?)", [("c0", "10.0.0", "proxy"), ("c100", "10.0.0", "proxy"), ("n1", "10.0.1", "node")])
    con.execute("CREATE TABLE vpair (state TEXT, hour INTEGER, ratio REAL, prefix24 TEXT)")
    con.executemany("INSERT INTO vpair VALUES ('dead', 0, ?, ?)",
                    [(3.0, "10.0.0"), (1.0, "10.0.0"), (1.0, "10.0.1"), (1.0, "10.0.1"), (1.0, "10.0.1"), (1.0, "10.0.1"), (5.0, None)])
    con.commit()
    con.close()
    ds = revisit_by_dense(DB(dpath))
    expect("密集分解：密集 /24 个数", ds["dense_prefixes"], 1)
    expect("密集分解：dead", ds["by_state"]["dead"],
           {"密集 /24": {"对子": 2, "间隔比超过 2 的对子": {"num": 1, "den": 2, "pct": 50.0}},
            "其他 /24": {"对子": 5, "间隔比超过 2 的对子": {"num": 1, "den": 5, "pct": 20.0}}})
    expect("密集分解：去掉密集后 p90 超过 2 的小时", {k: ds["hours_p90_over_2_excluding_dense"]["dead"][k] for k in ("hours", "hour_list", "max_p90")},
           {"hours": 1, "hour_list": [0], "max_p90": 5.0})
    expect("密集分解：没有 cands 表时为 None", rv.get("by_dense_24"), None)
    if failures:
        print("自检失败：\n  " + "\n  ".join(failures), file=sys.stderr)
        print("合成库与输出留在 %s" % tmp, file=sys.stderr)
        return 1
    print("自检通过（%d 项断言）。合成库与输出在 %s" % (n_asserts[0], tmp), file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="仪器核对（PROTOCOL“对照与自检”“正式测量的起止”）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 instrument.json")
    ap.add_argument("--summary", help="fieldtest 自带的 summary.json；不给就找入库时数据目录里的那份")
    ap.add_argument("--preflight", help="测量机上的 preflight.txt；不给就找入库时数据目录里的那份")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--formal-start", default="auto", help="auto（按 PROTOCOL 规则）/ first（第一条 start）/ 带时区的 ISO 时间")
    ap.add_argument("--selftest", action="store_true", help="在临时目录里建合成库并核对预期值")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    run(args.db, args.out, summary_path=args.summary, formal_start=args.formal_start, markdown=args.markdown,
        preflight_path=args.preflight)


if __name__ == "__main__":
    main()
