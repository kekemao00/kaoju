#!/usr/bin/env python3
"""“中间人”的细分（第一阶段 1B，PROTOCOL 第 1.2 版“指标定义”表的“中间人”行和“‘中间人’的细分”一节）：
隧道里 TLS 握手拿到的证书不是 judge 的尝试，总数照原定义，再按证书上的名字和证书链分成三层；
tls_pin_mismatch 单列；同一张叶子证书出现在多少个代理、多少个 /24 上按证书汇总。

用法：
    python3 m_mitm.py --db <sqlite> --out <目录> [--markdown] [--data <数据目录>] [--roots <PEM>] [--roots-note <文字>]
                      [--certcheck <二进制|go>] [--certcheck-batch 2000] [--summary <summary.json>]
                      [--formal-start auto|first|<带时区的 ISO 时间>] [--formal-end none|72h|<带时区的 ISO 时间>]
                      [--dense-threshold 100] [--guard <不许出现在输出里的字符串> ...]
    python3 m_mitm.py --selftest

只读 ingest.py 建好的库（mode=ro，中间表都建在 TEMP 库里），结果写到 <目录>/mitm.json；
加 --markdown 时把主要表格以 Markdown 打印到标准输出。每个比例都给分子、分母和口径，百分比保留一位小数。
证书链的校验由同目录的 certcheck/（只用 Go 标准库）完成：本模块按 (证据文件, 尝试时刻) 分批调用它，把结果并回 att。
--data 指向解包后的上层目录（里面是 fieldtest/）时自动进入 fieldtest/，与 ingest.py main() 相同。
输出前按 SCHEMA.md 的可输出列白名单核对本模块用到的列，写出前再对文本做一次“不许出现地址和 judge 身份”的断言
（最后一道保险，不是放行手段）。

口径（PROTOCOL 第 1.2 版；没说清的地方，取的解释写在 DEFINITIONS 和各函数注释里）：

- 中间人（总数，原定义）：att 里 proto 不是 tlsproxy、tls_class='tls_cert_invalid' 的尝试（wire.go TLS()：
  tls.CertificateVerificationError）。主口径只算代理（cand_kind='proxy'）、目的地 judge_tls；节点（proto='node'）和
  第二观察者（dst 以 obs: 开头）另列；对照组不应出现（作为仪器检查报告）。summary.go integrity() 的中间人发现
  把代理和节点、所有目的地都算在一起，交叉核对时按它的口径重算。
- tls_pin_mismatch（证书链有效但公钥不是 judge 的）单列，不并入中间人。
- 三层细分（只用 att 的 tls_detail、tls_subj、ev 和 evidence/ 里的证书链，与 PROTOCOL 一致）：
    冒充 judge      tls_detail_enum='unknown_authority'（Go 先查有效期再查主机名最后建链，所以名字已经核对过是 judge 的）；
                    或其他 detail 但存下的叶子证书的 SAN（没有 SAN 时看 CN）含 judge 的主机名（精确匹配，或通配符按 Go 规则匹配一层）。
    被送到别的网站   名字不是 judge 的；存下的证书链用公共根证书、按尝试发生的时刻校验、不看主机名，校验通过。
    去向不明         名字不是 judge 的；证书链校验不过（自签、过期、签发者不认识、没发中间证书）。
    证据未存（无法判链） 证书链没存下来（探测器没拿到链、证据库超限没存）或文件解析不了的尝试：只能按 tls_subj 的 CN 判名字，
                    判不了证书链，单独计数，不并入“被送到别的网站”和“去向不明”。
                    本模块取的解释：detail='unknown_authority' 的尝试不需要证书链就满足“冒充 judge”的第一条判据，所以即使证据没存下
                    也归入冒充 judge（并给出“其中证据未存”的数目）；其余没存下的尝试才进这一层。
- 候选层面：一个候选可能在不同尝试里落入不同层，所以给两种：各层的候选数（不互斥）和“按候选取最严重一层”
  （冒充 judge > 去向不明 > 被送到别的网站 > 证据未存 > 未校验；这是本模块的排序，PROTOCOL 没规定）。
- 比例：PROTOCOL“与文献对账”里的预期范围是“证书被替换的代理占可用隧道代理”。本模块的分母取两种：
  “隧道建立过的候选”（socks5/socks4/connect 到 judge_tls 的握手通过过，hs_ok=1；中间人代理的隧道从客户端看是建立了的）、
  “隧道曾可用或遇到中间人的候选”（class='ok' 过的候选 ∪ 中间人候选）。两种都给。
- 去掉“候选超过 100 个的 /24”的一组结果照 PROTOCOL 1.2 版另给。
- 正式起点：PROTOCOL“正式测量的起止”，规则与 m_availability 相同（含 load_err 的处理）；交叉核对 summary.json 时不裁。
  中断时段（stops / interruptions）照 m_availability 报告。72 小时的终点总是给出，默认不截断（与其他模块一致），--formal-end 72h 时截断。

证书链校验（certcheck/main.go）：crypto/x509 Certificate.Verify，根证书 = --roots 指定的 PEM（默认 /etc/ssl/certs/ca-certificates.crt，
Debian/Ubuntu 的 ca-certificates 包，Mozilla 根库的打包；文件名、sha256、证书数、包版本和包 changelog 里的 Mozilla 根库版本都写进输出，
报告要写明），中间证书 = 文件里叶子之后的证书（不联网补全），时刻 = 尝试的 ts。
校验粒度：每个证据文件只在它被引用的最早时刻 tmin 和最晚时刻 tmax 各校验一次；两次结果相同，并且文件里任何一张证书的有效期边界
（以及校验通过时所建链上、含根证书库里的根的最早 NotAfter）都不落在 [tmin, tmax] 内，就用这一结果代表这个文件的全部尝试；
否则按每次尝试的精确时刻逐一重算（“按尝试发生的时刻校验”到秒）。x509 校验结果只通过有效期随时刻变化，所以两者等价
（唯一没覆盖的情形是根证书库里某张不在所建链上的根，生效和过期都落在 [tmin, tmax] 这至多 72 小时里；Mozilla 根库没有这样的根），
而校验次数不超过 2 × 文件数（加上少数要重算的文件的尝试数）。

设计要点（真实数据有一千多万条 att）：
- 对 att 的大扫描只有两遍：一遍顺序扫描（NOT INDEXED；tls_class 没有索引，走 att_ts 等于全表扫再逐行回表）把 tls_class 为
  tls_cert_invalid / tls_pin_mismatch 的全部行抽成 TEMP 表 tx（不加起点、种类、协议过滤；量级是中间人尝试数加少量 tlsproxy），
  中间人表 m、钉扎表 p、对照组与 tlsproxy 的检查、与 summary.json 的对账都从 tx 过滤；
  另一遍走 att(proto, dst, class) 索引，把隧道协议到 judge_tls 的代理尝试按 (候选, 协议, 小时) 聚合成 TEMP 表 tch，
  分母表 tc、按协议、按小时都从 tch 汇总。节点一节只读 proto='node' 的索引区间。
- 证书校验按证据文件分批（默认每批 2,000 次校验）交给 certcheck，边读结果边写 TEMP 表；文件清单和要重算的尝试都用游标逐行取，
  不整体读进内存。之后全部指标都是对 TEMP 表的 SQL 聚合，内存由 SQLite 页缓存主导。只用 Python 3.10+ 标准库。
"""
import argparse
import atexit
import datetime as dt
import gzip
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pubdb  # noqa: E402  真实库与公开库之间的接缝（PUBLIC.md）

MODULE = "m_mitm"
OUTPUT_NAME = "mitm.json"
PROTOCOL_VERSION = "1.2"
DENSE_THRESHOLD = 100   # PROTOCOL 1.2“候选密集的地址段”：候选超过 100 个的 /24
TOP_LEAVES = 20         # 按叶子证书汇总时列出的前几张
TOP_PREFIXES = 20       # 中间人候选按 /24 汇总时列出的前几个
DEFAULT_ROOTS = "/etc/ssl/certs/ca-certificates.crt"
CERTCHECK_BATCH = 2000  # 每次调用 certcheck 的校验次数上限：一行输出约 0.5–1 KB，一批的标准输出约 2 MB，内存与数据规模无关
FORMAL_HOURS = 72       # PROTOCOL“正式测量的起止”：跑满 72 小时
FE_NONE = 1e300         # 不截断时的终点（SQL 里统一写 ts_epoch < ?）
TUNNEL_PROTOS = ("socks5", "socks4", "connect")   # 在隧道里对 judge 做 TLS 握手的协议（attempt.go run()）
CERTCHECK_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certcheck")
CERTCHECK_FEATURES = ("noleaf", "bounds", "chains_not_after")   # certcheck/main.go 的 features；旧版二进制没有，拒绝使用

L_JUDGE = "冒充 judge"
L_OTHER = "被送到别的网站"
L_UNKNOWN = "去向不明"
L_NOEV = "证据未存（无法判链）"
L_UNCHECKED = "未校验"
LAYERS = [L_JUDGE, L_OTHER, L_UNKNOWN, L_NOEV, L_UNCHECKED]
# “按候选取最严重一层”的排序（本模块的解释）
SEVERITY = {L_JUDGE: 0, L_UNKNOWN: 1, L_OTHER: 2, L_NOEV: 3, L_UNCHECKED: 4}

# Go 1.24.7 crypto/x509 verify.go 的 InvalidReason 顺序；tls_detail_enum 里 invalid_<n> 的 n 就是它
INVALID_REASONS = ["NotAuthorizedToSign", "Expired", "CANotAuthorizedForThisName", "TooManyIntermediates", "IncompatibleUsage",
                   "NameMismatch", "NameConstraintsWithoutSANs", "UnconstrainedName", "TooManyConstraints",
                   "CANotAuthorizedForExtKeyUsage", "NoValidChains"]

# 本模块在 SELECT 列表或 GROUP BY 里用到、并且会进入输出（作为维度或被聚合的值）的列。
# 连接用的键（att.cand、att.ev、att.tls_leaf、att.tls_subj、evidence.hash/path、self_leaf.leaf、self_names.name）
# 只在库内做 JOIN 或判等，不进入输出，所以不在这里；att.cand、att.cand_ip 另外只出现在 COUNT(DISTINCT …) 里（只输出个数，不输出值）。
# start.load_err 只作“是否非空”的布尔判断（与 m_availability 相同），原文不进输出，所以也不在这里。
OUTPUT_COLUMNS = {
    "att": ["proto", "dst", "arm", "tcp_ok", "hs_ok", "hs_class", "tls_ok", "tls_class", "tls_detail_enum", "tls_self", "class",
            "cand_kind", "prefix24", "ts_epoch"],
    "cands": ["prefix24", "visits"],
    "evidence": ["ext", "bytes"],
    "start": ["resumed_candidates", "ts_epoch"],
    "stop": ["ts_epoch"],
    "stat": ["ts_epoch"],
    "version": ["version", "ts_epoch"],
    "visit": ["ts_epoch"],
    "meta": ["ingest_version", "first_ts", "last_ts", "evidence_files", "evidence_bytes", "judge_leaf_observed_count", "state_cands"],
}

DEFINITIONS = {
    "中间人（总数）": "隧道里 TLS 握手拿到的证书不是 judge 的：att 里 proto≠tlsproxy 且 tls_class='tls_cert_invalid'（wire.go TLS()）。"
               "主口径只算代理（cand_kind='proxy'）、目的地 judge_tls、正式起点之后、非 canceled 的尝试；节点和第二观察者另列。"
               "PROTOCOL“指标定义”表“中间人”行",
    "原定义总数": "照 PROTOCOL“指标定义”表“中间人”行的原定义，不区分代理/节点/目的地：正式起点之后、非 canceled、proto≠tlsproxy、"
             "tls_class='tls_cert_invalid' 的全部尝试（对照组 cand_kind='control' 不是隧道，不算，另作仪器检查）。"
             "total.原定义总数 一节给出它和按 代理→judge_tls / 代理→第二观察者 / 代理→其他目的地 / 节点 的拆分，四项相加等于总数。"
             "与 summary.json 对账（crosscheck）时按 summary.go 的口径另算：不裁正式起点",
    "tls_pin_mismatch": "证书链按 judge 的信任根校验通过、叶子公钥却不是 judge 的（wire.go errPin）。单列，不并入中间人。PROTOCOL“一次尝试”第 3 步",
    "冒充 judge": "叶子证书上的名字是 judge 的主机名：tls_detail_enum='unknown_authority'（Go 先查有效期、再查主机名、最后建链，"
              "所以名字已核对过）；或其他 detail 但存下的叶子证书的 SAN（没有 SAN 时看 CN）含 judge 主机名（精确，或通配符按 Go 规则匹配一层）。"
              "判名字用库里 self_names（start.judge_host）的值，不输出主机名。detail='unknown_authority' 不需要证书链就满足第一条判据，"
              "所以证据没存下也算（给出“其中证据未存”）。PROTOCOL 1.2“‘中间人’的细分”",
    "被送到别的网站": "名字不是 judge 的；存下的证书链用公共根证书（--roots）、按尝试发生的时刻、不看主机名校验（certcheck：x509 Verify，"
                "DNSName 为空，Intermediates=文件里叶子之后的证书，不联网补全），校验通过。PROTOCOL 1.2“‘中间人’的细分”",
    "去向不明": "名字不是 judge 的；证书链校验不过。再按错误类别细分：self_signed（自签）、unknown_authority_leaf_only（只发了叶子，私有 CA 或没发中间证书，"
            "离线分不出）、unknown_authority（发了链但链顶不在公共根库）、expired / not_yet_valid / expired_intermediate、invalid_<原因>。"
            "PROTOCOL 1.2“‘中间人’的细分”",
    "证据未存（无法判链）": "证书链没存下来（att.ev 为空：探测器没拿到链；或 ev 不在 evidence/ 里：证据库超限，每个代理最多 12 份、总共 1 GB，rec.go Evidence.Put）"
                   "或文件解析不了的尝试。只能按 tls_subj 的 CN 判名字（CN 是 / 不是 judge 主机名 / 没有 subj），判不了证书链，单独计数，"
                   "不并入前两层。detail='unknown_authority' 的除外（已按判据归入冒充 judge）。PROTOCOL 1.2“‘中间人’的细分”",
    "未校验": "证据存下了但本次运行没有校验：没有数据目录（--data 或 meta.data_dir 下没有 evidence/，也没有 fieldtest/evidence/）或 certcheck 不可用。"
            "正常运行应为 0；不为 0 时标准错误输出有警告，Markdown 第一行标出“证书链未校验”",
    "按候选取最严重一层": "一个候选的多次中间人尝试可能落入不同层；按 冒充 judge > 去向不明 > 被送到别的网站 > 证据未存 > 未校验 取最严重的一层。"
                   "这是本模块的排序，PROTOCOL 没规定。各层的候选数（不互斥）也一并给出",
    "隧道建立过的候选": "正式起点后，socks5/socks4/connect 到 judge_tls 的尝试里至少一次握手通过（hs_ok=1）的代理候选。"
                 "中间人代理的隧道从客户端看是建立了的，所以它在分母里。作为“证书被替换的代理占可用隧道代理”（PROTOCOL“与文献对账”）的分母之一",
    "隧道曾可用或遇到中间人的候选": "class='ok' 过的隧道候选 ∪ 中间人候选。另一种分母：Mani 等的 9,625 是“支持 HTTPS 的代理”，这个口径更接近“能走通 HTTPS 的代理”",
    "到达 TLS 阶段的尝试": "socks5/socks4/connect 到 judge_tls 的尝试里 tls_ok=1 或 tls_class 非空的（握手通过、开始在隧道里做 TLS）。中间人尝试占它的比例是按尝试计的版本",
    "按叶子证书汇总": "同一张叶子证书（tls_leaf 相同）出现在多少个不同代理、多少个 /24 上（PROTOCOL 1.2：看是不是同一个运营者）。"
               "只给签发者/主题的组织名（O，含 judge 身份或地址时隐去）和计数，不给证书哈希、CN、SAN 或代理地址。前 20 张按候选数、尝试数排序。"
               "候选按 ip:port 计；PROTOCOL 1.2“候选密集的地址段”指出一个运营者可以在几个 IP 上挂上万个端口，所以另给按不同 IP 计的数"
               "（COUNT(DISTINCT cand_ip)，只输出个数）",
    "公共根校验（按叶子）": "按叶子汇总时这一张叶子的证书链校验结论：证据未存（这张叶子的尝试都没存下证书链）/ 证据解析不了 / 未校验（存了但本次没跑 certcheck）/"
                   "公共根校验通过 / 校验不过；结果不一致时分开说：同一份证据文件在不同时刻结果不同 → 随时刻不同（跨过有效期边界）；"
                   "不同证据文件（叶子相同、所发的链不同，例如有没有中间证书）结果不同 → 随所发的链不同；两样都有 → 随所发的链和时刻都不同",
    "候选密集的 /24": "状态文件里候选数超过阈值（默认 100）的 /24（没有状态文件时按 visit ∪ list_event 里出现过的候选数）。"
                  "各比例另给一组去掉这些 /24 里全部候选后的结果。PROTOCOL 1.2“候选密集的地址段”",
    "正式起点": "PROTOCOL“正式测量的起止”：默认取第一条 start；若之后有 resumed_candidates=0 且 load_err 为空的 start（状态被清空）或版本变了，"
             "取最后一次这样的 start，之前的数据是试运行，不并入。load_err 非空的 start（状态文件读不出来）按崩溃后重启处理，不改变正式起点。"
             "规则与 m_availability.observation_window 相同。可用 --formal-start 覆盖。交叉核对 summary.json 时不裁（summary.go 不区分试运行）",
    "正式结束（72 小时）": "PROTOCOL“正式测量的起止”：从正式起点跑满 72 小时。window.formal_end_72h_utc = 正式起点 + 72 小时，"
                   "window.after_72h 给出这一刻之后的尝试数。默认（--formal-end none）各表不按它截断，与 m_availability 等模块一致；"
                   "是否截断要各模块一起定，定了用 --formal-end 72h（区间取 [正式起点, 正式起点 + 72 小时)）",
    "中断": "PROTOCOL“正式测量的起止”要求写明中断的时段：正式起点之后每条 start 之前的空档。上一条 start 与它之间有 stop 的从最后一条 stop 算起（正常停止），"
          "否则从这段时间里最后一条 visit/att/stat 记录算起（崩溃重启）。与 m_availability.observation_window 相同",
    "校验时刻": "按尝试的 ts（UTC）校验。每个证据文件先在它被引用的最早和最晚时刻各校验一次；两次结果（是否通过、错误类别、链长、链顶组织）相同，"
             "并且文件里任何证书的有效期边界、以及校验通过时所建链上（含根证书库里的根）最早的 NotAfter 都不落在 [最早, 最晚] 内，"
             "就用这一结果代表这个文件的全部尝试；否则按每次尝试的精确时刻逐一重算（输出里 refined_files / refined_jobs 是重算的文件数和校验次数）。"
             "Go 的有效期判断是 NotBefore ≤ 时刻 ≤ NotAfter（crypto/x509 isValid），边界取闭区间",
    "公共根证书": "--roots 的 PEM 文件（默认 Debian/Ubuntu 的 ca-certificates 包，Mozilla 根库的打包）。输出里给文件名（不给本机目录）、sha256、证书数、"
             "包版本，以及从包的 changelog 里读到的最近一次“Update Mozilla certificate authority bundle to version …”；读不到时由 --roots-note 填写。"
             "Debian/Ubuntu 的包可能在 Mozilla 根库之外另行删减（changelog 里的 blacklist），以 sha256 和证书数为准。报告要写明是哪一版",
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


def iso_hour(epoch):
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%HZ")


def iso_exact(epoch):
    """给 certcheck 的时刻：RFC 3339，带小数秒，UTC。不进输出。"""
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


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
    """比例的 Markdown 写法：分子/分母（百分比）。"""
    return f"{fmt(r['num'])}/{fmt(r['den'])}（{fmt(r['pct'], '%')}）"


def layer_sql_case(col="layer"):
    """SQL 里把层名映射成严重程度（越小越严重）。"""
    return "CASE %s %s ELSE 9 END" % (col, " ".join("WHEN '%s' THEN %d" % (k, v) for k, v in SEVERITY.items()))


# ---------------------------------------------------------------- RFC 2253 的 DN 与主机名匹配
#
# att.tls_subj / tls_issuer 是 Go pkix.Name.String() 的结果（wire.go describe()，截到 120 字符）：
# RFC 2253 写法，RDN 之间用逗号；同一个 RDN 里的多个属性（多值 RDN）用未转义的 + 连接；
# 值里的 , + " \ < > ; 用反斜杠转义（Go crypto/x509/pkix RDNSequence.String）。

def dn_parts(s):
    """把 "CN=a\\,b,O=c" 拆成 [("CN","a,b"),("O","c")]；多值 RDN "CN=x+OU=y" 拆成 [("CN","x"),("OU","y")]。
    逗号和未转义的 + 都是属性之间的分隔（本模块只按属性名取值，不需要保留 RDN 的分组）。截断造成的残缺最后一项照样返回。"""
    out = []
    if not s:
        return out
    buf, esc, items = [], False, []
    for ch in s:
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch in ",+":
            items.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    items.append("".join(buf))
    for it in items:
        if "=" in it:
            k, v = it.split("=", 1)
            out.append((k.strip().upper(), v.strip()))
    return out


def dn_get(s, attr):
    return [v for k, v in dn_parts(s) if k == attr.upper()]


def name_matches(name, hosts, ips):
    """证书上的一个名字（SAN dNSName 或 CN）是不是 judge 的主机名。
    精确匹配（不分大小写，去掉末尾的点）；通配符只匹配一层标签（Go crypto/x509 的规则）；judge 配置成 IP 时与 IP 比。"""
    if not name:
        return False
    n = name.strip().lower().rstrip(".")
    for h in hosts:
        h = h.strip().lower().rstrip(".")
        if not h:
            continue
        if n == h:
            return True
        if n.startswith("*.") and "." in h and h.split(".", 1)[1] == n[2:]:
            return True
    return n in {ip.strip().lower() for ip in ips}


# ---------------------------------------------------------------- 库

class DB:
    def __init__(self, path):
        # mode=ro：库文件只读；临时表都建在 TEMP 库里（query_only 会连 TEMP 表一起禁掉，所以不用它）
        self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        self.con.execute("PRAGMA cache_size = -262144")  # 256 MB 页缓存，内存不随记录数增长
        self.con.execute("PRAGMA temp_store = FILE")

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

    def columns(self, table):
        return [r[1] for r in self.q("PRAGMA table_info(%s)" % table)]

    def has_column(self, table, col):
        return col in self.columns(table)

    def has_index(self, name):
        return self.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", (name,)) > 0

    def meta(self, key):
        if not self.has_table("meta"):
            return None
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))


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


# ---------------------------------------------------------------- 观察窗口与密集 /24（与其他模块相同）

def last_activity_between(db, lo, hi):
    """(lo, hi) 开区间里最后一条 visit / att / stat 记录的时刻；没有就返回 None。与 m_availability.last_activity_between 相同。"""
    best = None
    for t in ("visit", "att", "stat"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s WHERE ts_epoch > ? AND ts_epoch < ?" % t, (lo, hi))
            if v is not None and (best is None or v > best):
                best = v
    return best


def observation_window(db, formal_start_arg, formal_end_arg="none"):
    """正式起点、结束时刻、重启与中断，以及 72 小时的终点（PROTOCOL“正式测量的起止”）。
    起点规则、stops / interruptions 的算法照搬 m_availability.observation_window（含 load_err 的处理），保证各模块的正式起点一致；
    没有 start 记录时 m_availability 取第一条 visit，这里也一样（没有 visit 再退到第一条 att）。
    72 小时的终点：formal_end_72h = 正式起点 + 72 小时，总是给出；--formal-end none（默认）时各表不按它截断，
    与 m_availability 一致（PROTOCOL 说“跑满 72 小时”，没说之后的数据丢弃；要截断须各模块一起改），72h 时按 [起点, 起点 + 72 小时) 截断。"""
    warnings = []
    start_cols = db.columns("start") if db.has_table("start") else []
    if start_cols:
        load_err_sel = "COALESCE(load_err, '')" if "load_err" in start_cols else "''"
        starts = db.q("SELECT ts_epoch, COALESCE(resumed_candidates, 0), %s FROM start ORDER BY ts_epoch" % load_err_sel)
        if "load_err" not in start_cols:
            warnings.append("start 表没有 load_err 列，无法区分“清空状态”与“状态文件读不出来”，resumed_candidates=0 一律按清空处理")
    else:
        starts = []
    stops = [r[0] for r in db.q("SELECT ts_epoch FROM stop ORDER BY ts_epoch")] if db.has_table("stop") else []
    versions = db.q("SELECT ts_epoch, version FROM version ORDER BY ts_epoch") if db.has_table("version") else []
    ends = []
    for t in ("visit", "att", "stop"):
        if db.has_table(t):
            v = db.scalar("SELECT MAX(ts_epoch) FROM %s" % t)
            if v is not None:
                ends.append(v)
    end = max(ends) if ends else None
    first_visit = db.scalar("SELECT MIN(ts_epoch) FROM visit") if db.has_table("visit") else None
    if first_visit is None:
        first_visit = db.scalar("SELECT MIN(ts_epoch) FROM att")
    rule = []
    if starts:
        fs = starts[0][0]
        rule.append("第一条 start")
        for st in starts[1:]:
            if st[2] != "":
                warnings.append("%s 的 start 带 load_err（状态文件读不出来，resumed_candidates=%d）：按崩溃后重启处理，不当作清空状态，不改变正式起点"
                                % (iso_minute(st[0]), st[1]))
        cleared = [st for st in starts[1:] if st[1] == 0 and st[2] == ""]
        if cleared:
            fs = cleared[-1][0]
            rule.append("之后有 resumed_candidates=0 且 load_err 为空的 start（状态被清空）：取最后一次")
        if len({v for _, v in versions}) > 1:
            change = None
            for i in range(1, len(versions)):
                if versions[i][1] != versions[i - 1][1]:
                    change = versions[i][0]
            after = [st[0] for st in starts if st[0] >= change - 1]  # version 与 start 几乎同时写，留 1 秒余量
            if after and after[0] > fs:
                fs = after[0]
                rule.append("版本变过：取最后一次版本变化之后的第一条 start")
    else:
        fs = first_visit
        rule.append("没有 start 记录：取第一条 visit（没有 visit 时取第一条 att）")
    if formal_start_arg and formal_start_arg != "auto":
        if formal_start_arg == "first":
            fs = starts[0][0] if starts else first_visit
            rule = ["--formal-start first"]
        else:
            fs = parse_iso(formal_start_arg)
            rule = ["--formal-start 指定"]
    if fs is None:
        fs = 0.0
        rule.append("库里没有 visit 也没有 att，起点取 0")
    if starts and fs > starts[0][0]:
        warnings.append("正式起点不是第一条 start：从 %s 挪到 %s（晚 %.1f 小时），之前的尝试按试运行丢弃"
                        % (iso_minute(starts[0][0]), iso_minute(fs), (fs - starts[0][0]) / 3600.0))

    # 中断：正式起点之后的每条 start 之前的空档（m_availability 同一算法）
    interruptions = []
    for i in range(1, len(starts)):
        st, prev = starts[i][0], starts[i - 1][0]
        if st <= fs:
            continue  # 试运行与正式起点之间的空档不算中断
        between = [x for x in stops if prev < x < st]
        if between:
            begin, kind, note = between[-1], "stop", "stop 记录到下一条 start"
        else:
            begin = last_activity_between(db, prev, st)
            kind = "crash"
            if begin is None:
                begin, note = prev, "没有 stop 记录，这段时间也没有任何 visit/att/stat 记录：从上一条 start 算起"
            else:
                note = "没有 stop 记录：从崩溃前最后一条 visit/att/stat 记录算起"
        interruptions.append({"kind": kind, "from_utc": iso_minute(begin), "start_utc": iso_minute(st),
                              "minutes": round((st - begin) / 60.0, 1), "load_err_present": starts[i][2] != "", "note": note})
    n_crash = sum(1 for x in interruptions if x["kind"] == "crash")
    if n_crash:
        warnings.append("有 %d 次没有 stop 记录的重启（崩溃），PROTOCOL 要求报告里写明中断时段" % n_crash)

    # 72 小时的终点
    fe72 = fs + FORMAL_HOURS * 3600.0
    fea = (formal_end_arg or "none").strip()
    if fea == "none":
        fe, fe_rule = None, "不截断（--formal-end none，默认；与 m_availability 一致）"
    elif fea == "72h":
        fe, fe_rule = fe72, "--formal-end 72h：各表只用 [正式起点, 正式起点 + 72 小时) 内的尝试"
    else:
        fe, fe_rule = parse_iso(fea), "--formal-end 指定：各表只用 [正式起点, 指定时刻) 内的尝试"
    after = {
        "att 记录": int(db.scalar("SELECT COUNT(*) FROM att WHERE ts_epoch >= ?", (fe72,)) or 0),
        # +proto / +dst：不让规划器为这几个条件走 att(proto, dst, class)（那是全部隧道尝试的一遍），只走 att_ts 的 72 小时之后那一段
        "其中隧道协议→judge_tls 的代理尝试": int(db.scalar(
            """SELECT COUNT(*) FROM att WHERE ts_epoch >= ? AND +proto IN ('socks5', 'socks4', 'connect') AND +dst = 'judge_tls'
               AND cand_kind = 'proxy' AND (class IS NULL OR class NOT LIKE '%canceled%')""", (fe72,)) or 0),
    }
    if after["att 记录"]:
        warnings.append("正式起点 72 小时之后还有 %d 条 att（%s）" % (after["att 记录"], fe_rule))
    return {
        "formal_start_utc": iso_minute(fs), "formal_start_rule": "；".join(rule), "end_utc": iso_minute(end),
        "hours": round((end - fs) / 3600.0, 2) if end is not None else None,
        "formal_end_72h_utc": iso_minute(fe72),
        "formal_end_applied_utc": iso_minute(fe), "formal_end_rule": fe_rule,
        "hours_in_tables": (round((min(end, fe) - fs) / 3600.0, 2) if fe is not None else round((end - fs) / 3600.0, 2)) if end is not None else None,
        "after_72h": after,
        "starts": [{"utc": iso_minute(st[0]), "resumed_candidates": st[1], "load_err_present": st[2] != ""} for st in starts],
        "stops": [iso_minute(x) for x in stops],
        "versions": sorted({v for _, v in versions}),
        "interruptions": interruptions,
        "interruption_minutes_total": round(sum(x["minutes"] for x in interruptions), 1),
        "interruptions_by_kind": {"stop": len(interruptions) - n_crash, "crash": n_crash},
        "trial_run_attempts_before_formal_start": int(db.scalar("SELECT COUNT(*) FROM att WHERE ts_epoch < ?", (fs,)) or 0),
        "warnings": warnings,
        "_fs": fs, "_end": end, "_fe": (fe if fe is not None else FE_NONE),
    }


def build_dense(db, threshold):
    """TEMP 表 dense(prefix24, cands, visited)：候选超过阈值的 /24。有状态文件按“状态文件 ∪ 尝试记录里的代理候选”数
    （与 m_availability、m_integrity、report_tables 的点名规则同一口径，决策 D14），visited = 有尝试记录的候选；
    没有状态文件就按 visit ∪ list_event 里出现过的候选。"""
    db.x("DROP TABLE IF EXISTS dense")
    if db.has_table("cands"):
        att_part = (" UNION ALL SELECT DISTINCT cand, prefix24, 1 FROM att WHERE cand_kind = 'proxy' AND prefix24 IS NOT NULL"
                    if db.has_table("att") else "")
        db.x("""CREATE TEMP TABLE dense AS
                SELECT prefix24, COUNT(*) AS cands, SUM(in_att) AS visited FROM (
                  SELECT cand, MAX(prefix24) AS prefix24, MAX(in_att) AS in_att FROM (
                    SELECT key AS cand, prefix24, 0 AS in_att FROM cands WHERE prefix24 IS NOT NULL%s)
                  GROUP BY cand)
                GROUP BY prefix24 HAVING COUNT(*) > ?""" % att_part, (threshold,))
        basis = "状态文件 cands ∪ 尝试记录里的代理候选（att，含试运行）：下榜超过 24 小时的候选会从状态文件里丢掉，只数状态文件会漏掉它们"
    else:
        parts = []
        if db.has_table("visit"):
            parts.append("SELECT cand, prefix24 FROM visit WHERE prefix24 IS NOT NULL")
        if db.has_table("list_event"):
            parts.append("SELECT cand, prefix24 FROM list_event WHERE prefix24 IS NOT NULL")
        if not parts:
            parts.append("SELECT cand, prefix24 FROM att WHERE prefix24 IS NOT NULL")
        visited = "SUM(cand IN (SELECT cand FROM visit))" if db.has_table("visit") else "NULL"
        db.x("""CREATE TEMP TABLE dense AS
                SELECT prefix24, COUNT(*) AS cands, %s AS visited
                FROM (%s) GROUP BY prefix24 HAVING COUNT(*) > ?""" % (visited, " UNION ".join(parts)), (threshold,))
        basis = "visit ∪ list_event 里出现过的候选（没有状态文件）"
    rows = db.q("SELECT prefix24, cands, visited FROM dense ORDER BY cands DESC")
    return {"threshold": threshold, "basis": basis, "count": len(rows),
            "prefixes": [{"prefix24": p, "候选": int(c), "有尝试记录（含试运行）": (int(v) if v is not None else None)} for p, c, v in rows]}


# ---------------------------------------------------------------- judge 的身份（只在库内判等，不输出）

def judge_identity(db):
    """judge 的主机名和公网 IP：按 SCHEMA“judge 的身份从哪里取”，首选 start.* 行；没有就退到别的来源。"""
    hosts, ips = [], []
    if db.has_table("self_names"):
        hosts = [r[0] for r in db.q("SELECT DISTINCT name FROM self_names WHERE source='start.judge_host' AND name IS NOT NULL")]
        if not hosts:
            hosts = [r[0] for r in db.q("SELECT DISTINCT name FROM self_names WHERE name IS NOT NULL")]
    if db.has_table("self_ips"):
        ips = [r[0] for r in db.q("SELECT DISTINCT ip FROM self_ips WHERE source='start.judge_ip' AND ip IS NOT NULL")]
        if not ips:
            ips = [r[0] for r in db.q("SELECT DISTINCT ip FROM self_ips WHERE ip IS NOT NULL")]
    return hosts, ips


# ---------------------------------------------------------------- 中间表

def build_tx(db):
    """TEMP 表 tx：att 里 tls_class 为 tls_cert_invalid 或 tls_pin_mismatch 的全部行（不加起点、种类、协议、目的地过滤）。
    一遍顺序扫描：tls_class 没有索引；不写 ts_epoch 条件，并用 NOT INDEXED 禁止走 att_ts（起点在最前，走它等于全表扫一遍再逐行回表）。
    之后 m、p、对照组与 tlsproxy 的检查、与 summary.json 的对账都从这张小表过滤。量级是中间人尝试数加少量 tlsproxy
    （tlsproxy 只在标成 https 的条目的完整探访里试一次，prober.go Visit）。"""
    db.x("DROP TABLE IF EXISTS tx")
    db.x("""CREATE TEMP TABLE tx AS
            SELECT rid, cand, cand_kind, cand_ip, prefix24, proto, dst, arm, ts_epoch, tls_class,
                   COALESCE(tls_detail_enum, 'other') AS detail, ev, tls_leaf, tls_subj, tls_issuer, COALESCE(tls_self, 0) AS tls_self,
                   (class IS NOT NULL AND class LIKE '%canceled%') AS canceled
            FROM att NOT INDEXED
            WHERE tls_class IN ('tls_cert_invalid', 'tls_pin_mismatch')""")
    return db.scalar("SELECT COUNT(*) FROM tx")


def build_mitm_table(db, fs, fe=FE_NONE):
    """TEMP 表 m：正式起点后（fe 截断时到 fe 为止）、非 canceled、proto≠tlsproxy、非对照组的 tls_cert_invalid 尝试（代理、节点、观察者目的地都在，
    各节再按 cand_kind / dst 过滤）。ev_state：none（探测器没拿到链）/ missing（ev 不在 evidence 表里：证据库超限没存）/ stored。
    从 tx 过滤，不再扫 att；tx 还没建（m_literature 直接调用本函数时）就先建。fe 默认不截断，旧的两参数调用 build_mitm_table(db, fs) 照旧可用。"""
    if not db.scalar("SELECT COUNT(*) FROM sqlite_temp_master WHERE type = 'table' AND name = 'tx'"):
        build_tx(db)
    db.x("DROP TABLE IF EXISTS m")
    has_ev = db.has_table("evidence")
    has_leaf = db.has_table("self_leaf")
    ev_join = "LEFT JOIN evidence e ON e.hash = t.ev AND e.ext = 'der'" if has_ev else ""
    ev_state = ("CASE WHEN t.ev IS NULL THEN 'none' WHEN e.hash IS NULL THEN 'missing' ELSE 'stored' END" if has_ev
                else "CASE WHEN t.ev IS NULL THEN 'none' ELSE 'missing' END")
    ev_path = "e.path" if has_ev else "NULL"
    leaf_is_judge = ("COALESCE(t.tls_leaf IN (SELECT leaf FROM self_leaf WHERE source = 'control_ok'), 0)" if has_leaf else "0")
    db.x("""CREATE TEMP TABLE m AS
            SELECT t.rid, t.cand, t.cand_kind, t.cand_ip, t.prefix24, t.proto, t.dst, t.arm, t.ts_epoch,
                   t.detail, t.ev, t.tls_leaf, t.tls_subj, t.tls_issuer, t.tls_self,
                   %s AS ev_state, %s AS ev_path, %s AS leaf_is_judge
            FROM tx t %s
            WHERE t.tls_class = 'tls_cert_invalid' AND t.proto != 'tlsproxy' AND COALESCE(t.cand_kind, '') != 'control'
              AND t.ts_epoch >= ? AND t.ts_epoch < ? AND NOT t.canceled""" % (ev_state, ev_path, leaf_is_judge, ev_join), (fs, fe))
    db.x("CREATE INDEX m_ev ON m(ev, ts_epoch)")
    db.x("CREATE INDEX m_cand ON m(cand)")
    return db.scalar("SELECT COUNT(*) FROM m")


def build_pin_table(db, fs, fe=FE_NONE):
    """TEMP 表 p：tls_pin_mismatch 的尝试，同样的过滤，从 tx 取。"""
    db.x("DROP TABLE IF EXISTS p")
    has_leaf = db.has_table("self_leaf")
    leaf_is_judge = ("COALESCE(t.tls_leaf IN (SELECT leaf FROM self_leaf WHERE source = 'control_ok'), 0)" if has_leaf else "0")
    db.x("""CREATE TEMP TABLE p AS
            SELECT t.rid, t.cand, t.cand_kind, t.prefix24, t.proto, t.dst, t.ts_epoch, t.tls_leaf, %s AS leaf_is_judge
            FROM tx t
            WHERE t.tls_class = 'tls_pin_mismatch' AND t.proto != 'tlsproxy' AND COALESCE(t.cand_kind, '') != 'control'
              AND t.ts_epoch >= ? AND t.ts_epoch < ? AND NOT t.canceled""" % leaf_is_judge, (fs, fe))
    return db.scalar("SELECT COUNT(*) FROM p")


def build_cand_table(db, fs, fe):
    """TEMP 表 tch：正式起点后 socks5/socks4/connect→judge_tls 的代理尝试按 (候选, 协议, 小时) 聚合的各阶段计数；
    TEMP 表 tc：tch 再按候选汇总，每个代理候选一行。按协议（by_proto）和按小时（hourly）也从 tch 汇总，对 att 只扫这一遍。
    走 att(proto, dst, class) 索引（INDEXED BY；ts_epoch 写成 +ts_epoch，免得规划器改走 att_ts 或为了 GROUP BY cand 走 att_cand_ts，
    那两条都等于全表扫再逐行回表）。"""
    db.x("DROP TABLE IF EXISTS tch")
    hint = "INDEXED BY att_proto_dst_class" if db.has_index("att_proto_dst_class") else ""
    db.x("""CREATE TEMP TABLE tch AS
            SELECT cand, prefix24, proto, CAST(ts_epoch / 3600 AS INTEGER) * 3600 AS hour_epoch,
                   COUNT(*) AS attempts,
                   SUM(COALESCE(tcp_ok, 0) = 1) AS tcp_ok,
                   SUM(COALESCE(hs_ok, 0) = 1) AS hs_ok,
                   SUM(COALESCE(tls_ok, 0) = 1 OR tls_class IS NOT NULL) AS tls_reached,
                   SUM(COALESCE(tls_ok, 0) = 1) AS tls_ok,
                   SUM(class = 'ok') AS ok,
                   SUM(tls_class = 'tls_cert_invalid') AS mitm,
                   SUM(tls_class = 'tls_pin_mismatch') AS pin
            FROM att %s
            WHERE proto IN ('socks5', 'socks4', 'connect') AND dst = 'judge_tls' AND cand_kind = 'proxy'
              AND +ts_epoch >= ? AND +ts_epoch < ? AND (class IS NULL OR class NOT LIKE '%%canceled%%')
            GROUP BY cand, prefix24, proto, hour_epoch""" % hint, (fs, fe))
    db.x("DROP TABLE IF EXISTS tc")
    db.x("""CREATE TEMP TABLE tc AS
            SELECT cand, prefix24, SUM(attempts) AS attempts, SUM(tcp_ok) AS tcp_ok, SUM(hs_ok) AS hs_ok, SUM(tls_reached) AS tls_reached,
                   SUM(tls_ok) AS tls_ok, SUM(ok) AS ok, SUM(mitm) AS mitm, SUM(pin) AS pin
            FROM tch GROUP BY cand, prefix24""")
    db.x("CREATE INDEX tc_cand ON tc(cand)")
    db.x("CREATE INDEX tc_prefix ON tc(prefix24)")


# ---------------------------------------------------------------- 证书链校验（certcheck）

_BUILT_CERTCHECK = {}   # 本进程里 go build 出来的 certcheck，只编一次


def resolve_certcheck(arg):
    """certcheck 怎么跑：--certcheck 给了二进制路径就用它；给 'go' 或没给时，优先同目录下已编译的 certcheck/certcheck，
    否则在 certcheck/ 目录里 go build 一次到临时目录（需要 PATH 里有 go；分批调用时不必每批都 go run 重新链接），进程退出时删掉。
    返回 (argv 前缀, 工作目录, 说明) 或 (None, None, 原因)。说明里只有文件名，不含本机目录。"""
    if arg and arg != "go":
        if os.path.isfile(arg) and os.access(arg, os.X_OK):
            return [os.path.abspath(arg)], None, "二进制 " + os.path.basename(arg)
        return None, None, "--certcheck 指定的文件不存在或不可执行"
    built = os.path.join(CERTCHECK_DIR, "certcheck")
    if arg != "go" and os.path.isfile(built) and os.access(built, os.X_OK):
        return [built], None, "二进制 certcheck/certcheck"
    if "go" in _BUILT_CERTCHECK:
        return [_BUILT_CERTCHECK["go"]], None, "go build certcheck/（本次运行编译）"
    if shutil.which("go") and os.path.isfile(os.path.join(CERTCHECK_DIR, "main.go")):
        tmp = tempfile.mkdtemp(prefix="m_mitm_certcheck_")
        atexit.register(shutil.rmtree, tmp, True)
        exe = os.path.join(tmp, "certcheck")
        proc = subprocess.run(["go", "build", "-o", exe, "."], cwd=CERTCHECK_DIR, capture_output=True, text=True)
        if proc.returncode != 0 or not os.path.isfile(exe):
            return None, None, "go build certcheck/ 失败：" + proc.stderr.strip()[:300]
        _BUILT_CERTCHECK["go"] = exe
        return [exe], None, "go build certcheck/（本次运行编译）"
    return None, None, "没有已编译的 certcheck，PATH 里也没有 go"


class CertChecker:
    """分批调用 certcheck -stdin。每批最多 batch 次校验：输入、标准输出和解析后的结果都只有一批那么大，与证据规模无关。
    每批的第一行是根证书信息，各批必须一致（运行中根证书文件被换掉就停）。"""

    def __init__(self, prefix, cwd, roots, batch):
        # 至少 2：同一文件的 tmin、tmax 两次校验要在同一批里
        self.prefix, self.cwd, self.roots, self.batch = prefix, cwd, roots, max(2, int(batch))
        self.head = None
        self.calls = 0
        self.jobs = 0
        self.read_errors = 0   # 全部批次里读不了的行（含 tmax 和重算的；第一遍按文件另计）

    def run(self, jobs):
        """jobs 是 [(绝对路径, 时刻 epoch, 要不要叶子描述)]，不超过 batch 条。返回与 jobs 顺序一致的 cert 行（dict）。"""
        if not jobs:
            return []
        if len(jobs) > self.batch:
            raise SystemExit("内部错误：一批 %d 次校验，超过上限 %d" % (len(jobs), self.batch))
        parts = []
        for path, t, want_leaf in jobs:
            if "\t" in path or "\n" in path:
                raise SystemExit("证据文件路径里有制表符或换行，certcheck -stdin 无法表示")
            parts.append("%s\t%s%s\n" % (path, iso_exact(t), "" if want_leaf else "\tnoleaf"))
        proc = subprocess.run(self.prefix + ["-roots", self.roots, "-stdin"], input="".join(parts), capture_output=True, text=True, cwd=self.cwd)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        if proc.returncode != 0 or not lines:
            raise SystemExit("certcheck 运行失败（退出码 %d）：%s" % (proc.returncode, proc.stderr.strip()[:500]))
        head = json.loads(lines[0])
        if head.get("k") != "roots":
            raise SystemExit("certcheck 的第一行不是 roots 信息")
        if head.get("err"):
            raise SystemExit("certcheck 读根证书失败：%s" % head["err"])
        missing = [f for f in CERTCHECK_FEATURES if f not in (head.get("features") or [])]
        if missing:
            raise SystemExit("certcheck 二进制太旧（缺 %s），请用 certcheck/ 重新编译（go build -o certcheck .）" % "、".join(missing))
        if self.head is None:
            self.head = head
        elif (head.get("sha256"), head.get("certs")) != (self.head.get("sha256"), self.head.get("certs")):
            raise SystemExit("根证书文件在运行中变了（两批 certcheck 的 sha256 不同），结果不可比，停止")
        rows = [json.loads(ln) for ln in lines[1:]]
        if len(rows) != len(jobs):
            raise SystemExit("certcheck 返回 %d 行，期望 %d 行" % (len(rows), len(jobs)))
        self.calls += 1
        self.jobs += len(jobs)
        self.read_errors += sum(1 for r in rows if r.get("read_error"))
        return rows


def roots_package_version(roots_path):
    """根证书包的版本（报告要写明是哪一版 Mozilla 根库）。只在用系统的 ca-certificates 时问 dpkg；问不到就 null。"""
    if not roots_path.startswith("/etc/ssl/") or not shutil.which("dpkg-query"):
        return None, None
    try:
        out = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "ca-certificates"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip(), "dpkg-query ca-certificates"
    except Exception:
        pass
    return None, None


CA_CHANGELOGS = ("/usr/share/doc/ca-certificates/changelog.Debian.gz", "/usr/share/doc/ca-certificates/changelog.gz")
_MOZ_RE = re.compile(r"Mozilla\s+certificate\s+authority\s+bundle\s+to\s+version\s+([0-9]+(?:\.[0-9]+)+)")


def mozilla_bundle_version(roots_path):
    """ca-certificates 包打包的 Mozilla 根库版本：包的 changelog（Debian 格式，新的在前）里最近一条
    “Update Mozilla certificate authority bundle to version X”。只在用系统的 ca-certificates 时读；读不到返回 (None, None)，
    由 --roots-note 补。返回 (版本, 依据)。依据里给出这条记录所在的包版本，与 dpkg 的包版本对照：两者不同说明之后的包版本没再换根库，
    但可能另有删减（blacklist），以 sha256 和证书数为准。"""
    if not roots_path.startswith("/etc/ssl/"):
        return None, None
    for path in CA_CHANGELOGS:
        if not os.path.isfile(path):
            continue
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                entry, buf = None, []
                for line in f:
                    m = re.match(r"^ca-certificates \(([^)]+)\)", line)
                    if m:
                        if entry is not None:
                            hit = _MOZ_RE.search(" ".join(buf))
                            if hit:
                                return hit.group(1), "%s 里最近一条“Update Mozilla certificate authority bundle”（包版本 %s 的条目）" % (os.path.basename(path), entry)
                        entry, buf = m.group(1), []
                    else:
                        buf.append(line.strip())
                if entry is not None:
                    hit = _MOZ_RE.search(" ".join(buf))
                    if hit:
                        return hit.group(1), "%s 里最近一条“Update Mozilla certificate authority bundle”（包版本 %s 的条目）" % (os.path.basename(path), entry)
        except Exception:
            pass
        break
    return None, None


def parse_rfc3339(s):
    if not s:
        return None
    try:
        return parse_iso(s)
    except Exception:
        return None


def resolve_evidence_root(data_dir):
    """证据文件的根目录：data_dir 下有 evidence/ 就用它；没有而 data_dir/fieldtest/ 下有，就用 data_dir/fieldtest
    （解包后的上层目录，与 ingest.py main() 的回退相同）。返回 (目录, 说明)；不可用时目录为 None。说明里不含本机路径。"""
    if not data_dir:
        return None, "没有数据目录（--data 没给，库里也没有 meta.data_dir）"
    if os.path.isdir(os.path.join(data_dir, "evidence")):
        return data_dir, None
    sub = os.path.join(data_dir, "fieldtest")
    if os.path.isdir(os.path.join(sub, "evidence")):
        return sub, "数据目录下没有 evidence/，自动进入了 fieldtest/ 子目录（与 ingest.py 相同）"
    return None, "数据目录下没有 evidence/，也没有 fieldtest/evidence/"


def _vkey(v):
    """校验结果里决定分层和细分输出的部分：是否通过、错误类别、链长、链顶组织。"""
    v = v or {}
    return (bool(v.get("ok")), v.get("err_class"), v.get("chain_len"), v.get("root_org"))


def _chk_row(ev, t, v):
    return (ev, t, 1 if v.get("ok") else 0, v.get("err_class"), v.get("chain_len"), v.get("root_org"))


LEAFINFO_COLS = ["ev", "parse_ok", "n_certs", "leaf_sha256", "name_judge", "name_basis", "san_n", "self_signed", "is_ca",
                 "not_before_epoch", "not_after_epoch", "chain_nb_epoch", "chain_na_epoch", "subject_org", "issuer_org",
                 "public_key", "sig_alg", "problem"]
CHK_COLS = ["ev", "ts_epoch", "ok", "err_class", "chain_len", "root_org"]


def _create_chain_tables(db):
    db.x("DROP TABLE IF EXISTS leafinfo")
    db.x("""CREATE TEMP TABLE leafinfo (ev TEXT PRIMARY KEY, parse_ok INTEGER, n_certs INTEGER, leaf_sha256 TEXT, name_judge INTEGER,
            name_basis TEXT, san_n INTEGER, self_signed INTEGER, is_ca INTEGER, not_before_epoch REAL, not_after_epoch REAL,
            chain_nb_epoch REAL, chain_na_epoch REAL, subject_org TEXT, issuer_org TEXT, public_key TEXT, sig_alg TEXT, problem TEXT)""")
    db.x("DROP TABLE IF EXISTS chk")
    db.x("CREATE TEMP TABLE chk (ev TEXT, ts_epoch REAL, ok INTEGER, err_class TEXT, chain_len INTEGER, root_org TEXT)")
    db.x("CREATE INDEX chk_key ON chk(ev, ts_epoch)")


def _chain_scope(db):
    """记下、取回证书链校验结果时的范围标记：时间窗不同，m 里的尝试不同，要校验的时刻也就不同。"""
    return "fs=%r;fe=%r" % (getattr(db, "fs", None), getattr(db, "fe", None))


def verify_chains(db, data_dir, roots, certcheck_arg, hosts, ips, batch=CERTCHECK_BATCH, roots_note=None):
    """证书链校验的入口，结果在 TEMP 表 leafinfo、chk 和返回的 certcheck 一节里（见 _verify_chain_files）。

    真实库：读证据文件、调 certcheck；设了 PHASE1B_RECORD 时把两张表和返回值记下来（pubdb.Recorder）。
    公开库：证据文件不在，取回导出时记下的结果（PUBLIC.md“随库带上的中间结果”）。只带了默认时间窗那一次的，换了窗口会报错停下。
    leafinfo 在公开库里有三处与真实库不同，都不进本模块的任何输出：有效期只留长度（not_before_epoch 归零）、
    chain_nb_epoch / chain_na_epoch 为空、problem 只留“有没有”。"""
    scope = _chain_scope(db)
    if pubdb.is_public(db.con):
        _create_chain_tables(db)
        db.many("INSERT INTO leafinfo VALUES (%s)" % ",".join("?" * len(LEAFINFO_COLS)), pubdb.replay_rows(db.con, "chains_leafinfo", scope))
        db.many("INSERT INTO chk VALUES (%s)" % ",".join("?" * len(CHK_COLS)), pubdb.replay_rows(db.con, "chains_chk", scope))
        info = pubdb.replay_json(db.con, "chains_info", scope)
        n_stored = int(db.scalar("SELECT COUNT(DISTINCT ev) FROM m WHERE ev_state = 'stored'") or 0)
        if n_stored != info.get("stored_files"):
            raise SystemExit("公开库带的证书链校验结果与这次要校验的文件数对不上（库里 %r 个，这次 %d 个）：换了参数？见 PUBLIC.md"
                             % (info.get("stored_files"), n_stored))
        note = pubdb.replay_json(db.con, "chains_roots_note", scope, missing_ok=True)
        if note is not None and info.get("roots") is not None:
            info["roots"]["roots_note"] = note
        return info
    info = _verify_chain_files(db, data_dir, roots, certcheck_arg, hosts, ips, batch=batch, roots_note=roots_note)
    rec = pubdb.Recorder()
    if rec.on:
        core = json.loads(json.dumps(info))     # roots_note 是调用方给的说明（m_literature 不给），单独记，两个模块记下的其余内容必须相同
        if core.get("roots") is not None:
            core["roots"]["roots_note"] = None
        rec.put_rows("chains_leafinfo", LEAFINFO_COLS, db.q("SELECT * FROM leafinfo ORDER BY rowid"), scope)
        rec.put_rows("chains_chk", CHK_COLS, db.q("SELECT * FROM chk ORDER BY rowid"), scope)
        rec.put_json("chains_info", core, scope)
        if roots_note is not None:
            rec.put_json("chains_roots_note", roots_note, scope)
        rec.close()
    return info


def _verify_chain_files(db, data_dir, roots, certcheck_arg, hosts, ips, batch=CERTCHECK_BATCH, roots_note=None):
    """对 m 里存下了证书链的尝试做校验。结果进 TEMP 表 leafinfo（每个证据文件一行，与时刻无关）和
    chk（ts_epoch 为空的一行代表这个文件的全部尝试；要重算的文件每个不同尝试时刻一行）。返回给输出用的 certcheck 一节。

    粒度（DEFINITIONS“校验时刻”）：每个文件在 tmin、tmax 各校验一次；两端结果相同、且没有有效期边界落在 [tmin, tmax] 内，
    就一行代表全部；否则把文件记进 TEMP 表 refine_ev，第二遍按每个不同的尝试时刻重算。
    内存：文件清单（TEMP 表 evf）和重算清单都用游标逐行取；certcheck 按批调用（每批不超过 batch 次校验），结果边读边写 TEMP 表。
    leaf 描述每个文件只要一次：只有 tmin 那一次让 certcheck 输出叶子，其余都带 noleaf。"""
    _create_chain_tables(db)
    db.x("DROP TABLE IF EXISTS refine_ev")
    db.x("CREATE TEMP TABLE refine_ev (ev TEXT PRIMARY KEY, path TEXT)")

    info = {"tool": None, "go_version": None, "roots": None, "evidence_dir_available": False, "evidence_dir_note": None, "verified": False,
            "stored_files": 0, "batch_size": max(2, int(batch)), "certcheck_calls": 0, "jobs": 0, "jobs_first_pass": 0,
            "refined_files": 0, "refined_jobs": 0, "refine_reasons": {"两端结果不同": 0, "有效期边界落在 [tmin, tmax] 内（两端结果相同）": 0},
            "read_errors": 0, "parse_errors": 0, "unverified_reason": None, "note": None}
    n_stored = db.scalar("SELECT COUNT(DISTINCT ev) FROM m WHERE ev_state = 'stored'") or 0
    info["stored_files"] = int(n_stored)
    if n_stored == 0:
        info["note"] = "没有存下证书链的中间人尝试，无需校验"
        return info
    ev_root, ev_note = resolve_evidence_root(data_dir)
    info["evidence_dir_note"] = ev_note
    if ev_root is None:
        info["unverified_reason"] = "%s（--data 或 meta.data_dir）" % ev_note
        info["note"] = "证书链未校验：" + info["unverified_reason"]
        print("警告：%d 个存下的证据文件没有校验——%s；这些尝试归“%s”" % (n_stored, ev_note, L_UNCHECKED), file=sys.stderr)
        return info
    info["evidence_dir_available"] = True
    prefix, cwd, how = resolve_certcheck(certcheck_arg)
    if prefix is None:
        info["unverified_reason"] = "certcheck 不可用（%s）" % how
        info["note"] = "证书链未校验：" + info["unverified_reason"]
        print("警告：%d 个存下的证据文件没有校验——certcheck 不可用（%s）；这些尝试归“%s”" % (n_stored, how, L_UNCHECKED), file=sys.stderr)
        return info
    info["tool"] = how
    cc = CertChecker(prefix, cwd, roots, batch)

    db.x("DROP TABLE IF EXISTS evf")
    db.x("""CREATE TEMP TABLE evf AS SELECT ev, MAX(ev_path) AS path, MIN(ts_epoch) AS tmin, MAX(ts_epoch) AS tmax
            FROM m WHERE ev_state = 'stored' GROUP BY ev""")

    def leaf_row(ev, r):
        leaf = r.get("leaf")
        if leaf:
            names = list(leaf.get("san_dns") or [])
            basis = "leaf_san"
            if not names and not leaf.get("san_ip"):
                names = [leaf.get("cn") or ""]
                basis = "leaf_cn"
            judge = any(name_matches(n, hosts, ips) for n in names) or any(name_matches(ip, hosts, ips) for ip in (leaf.get("san_ip") or []))
            return (ev, 1, r.get("n_certs"), leaf.get("sha256"), 1 if judge else 0, basis,
                    len(leaf.get("san_dns") or []) + len(leaf.get("san_ip") or []),
                    1 if leaf.get("self_signed") else 0, 1 if leaf.get("is_ca") else 0,
                    parse_rfc3339(leaf.get("not_before")), parse_rfc3339(leaf.get("not_after")),
                    parse_rfc3339(r.get("chain_not_before")), parse_rfc3339(r.get("chain_not_after")),
                    json.dumps(leaf.get("subject_org") or [], ensure_ascii=False),
                    json.dumps(leaf.get("issuer_org") or [], ensure_ascii=False),
                    leaf.get("public_key"), leaf.get("sig_alg"), r.get("parse_error"))
        return (ev, 0, r.get("n_certs") or 0, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                r.get("read_error") or r.get("parse_error") or "no certificate")

    def first_pass(files):
        jobs = []
        for ev, path, tmin, tmax in files:
            full = os.path.join(ev_root, path)
            jobs.append((full, tmin, True))
            if tmax > tmin:
                jobs.append((full, tmax, False))
        rows = cc.run(jobs)
        i = 0
        leaf_rows, chk_rows, refine_rows = [], [], []
        for ev, path, tmin, tmax in files:
            ra = rows[i]
            i += 1
            rb = None
            if tmax > tmin:
                rb = rows[i]
                i += 1
            if ra.get("read_error"):
                info["read_errors"] += 1
            if ra.get("parse_error"):
                info["parse_errors"] += 1
            leaf_rows.append(leaf_row(ev, ra))
            va = ra.get("verify")
            if va is None:
                continue  # 读不了或一张证书也解析不出来：没有校验结果，分层时归“证据未存（无法判链）”
            if rb is None:
                chk_rows.append(_chk_row(ev, None, va))
                continue
            vb = rb.get("verify") or {}
            bounds = [parse_rfc3339(b) for b in (ra.get("bounds") or [])]
            bounds += [parse_rfc3339(va.get("chains_not_after")), parse_rfc3339(vb.get("chains_not_after"))]
            if _vkey(va) != _vkey(vb):
                info["refine_reasons"]["两端结果不同"] += 1
                refine_rows.append((ev, os.path.join(ev_root, path)))
            elif any(b is not None and tmin <= b <= tmax for b in bounds):
                info["refine_reasons"]["有效期边界落在 [tmin, tmax] 内（两端结果相同）"] += 1
                refine_rows.append((ev, os.path.join(ev_root, path)))
            else:
                chk_rows.append(_chk_row(ev, None, va))
        db.many("INSERT INTO leafinfo VALUES (%s)" % ",".join("?" * 18), leaf_rows)
        db.many("INSERT INTO chk VALUES (?,?,?,?,?,?)", chk_rows)
        db.many("INSERT INTO refine_ev VALUES (?,?)", refine_rows)

    # 第一遍：每个文件在 tmin、tmax 各一次。按文件凑批，同一文件的两次校验在同一批里
    files, njobs = [], 0
    for row in db.con.execute("SELECT ev, path, tmin, tmax FROM evf ORDER BY ev"):
        need = 1 if row[3] <= row[2] else 2
        if files and njobs + need > cc.batch:
            first_pass(files)
            files, njobs = [], 0
        files.append(row)
        njobs += need
    if files:
        first_pass(files)
    info["jobs_first_pass"] = cc.jobs

    # 第二遍：要重算的文件，按每个不同的尝试时刻
    def exact_pass(batch_rows):
        rows = cc.run([(full, t, False) for _ev, full, t in batch_rows])
        out = []
        for (ev, _full, t), r in zip(batch_rows, rows):
            v = r.get("verify")
            if v is not None:
                out.append(_chk_row(ev, t, v))
        db.many("INSERT INTO chk VALUES (?,?,?,?,?,?)", out)

    pending = []
    for row in db.con.execute("""SELECT DISTINCT r.ev, r.path, m.ts_epoch FROM refine_ev r JOIN m ON m.ev = r.ev
                                 WHERE m.ev_state = 'stored' ORDER BY r.ev, m.ts_epoch"""):
        pending.append(row)
        if len(pending) >= cc.batch:
            exact_pass(pending)
            pending = []
    if pending:
        exact_pass(pending)
    info["refined_files"] = int(db.scalar("SELECT COUNT(*) FROM refine_ev") or 0)
    info["refined_jobs"] = cc.jobs - info["jobs_first_pass"]
    info["jobs"] = cc.jobs
    info["certcheck_calls"] = cc.calls
    info["read_errors_all_jobs"] = cc.read_errors
    info["verified"] = True

    head = cc.head or {}
    pkg_ver, pkg_src = roots_package_version(roots)
    moz_ver, moz_src = mozilla_bundle_version(roots)
    info["go_version"] = head.get("go_version")
    info["roots"] = {
        "file": os.path.basename(head.get("path") or roots),   # 只给文件名，不给本机目录（--roots 可能在用户目录下）
        "sha256": head.get("sha256"), "certs": head.get("certs"),
        "package_version": pkg_ver, "package_version_source": pkg_src,
        "mozilla_bundle_version": moz_ver, "mozilla_bundle_version_source": moz_src,
        "roots_note": roots_note,
        "note": ("Mozilla 根库的版本从 ca-certificates 包的 changelog 自动读出；包可能另有删减（blacklist），以 sha256 和证书数为准"
                 if moz_ver else "没读到 Mozilla 根库的版本：须从 ca-certificates 包的 changelog 抄录，用 --roots-note 填进来"),
    }
    if info["read_errors"] or cc.read_errors:
        print("警告：%d 个证据文件读不了、全部批次共 %d 次读不了（数据目录与建库时的不是同一份？），这些尝试归“证据未存（无法判链）”"
              % (info["read_errors"], cc.read_errors), file=sys.stderr)
    return info


def build_subj_names(db, hosts, ips):
    """TEMP 表 subjname：每个不同的 tls_subj 一行，CN 是不是 judge 的主机名（证据没存下时只能靠它）。tls_subj 截到 120 字符，CN 可能被截断。"""
    db.x("DROP TABLE IF EXISTS subjname")
    db.x("CREATE TEMP TABLE subjname (subj TEXT PRIMARY KEY, has_cn INTEGER, cn_judge INTEGER, subject_org TEXT)")
    rows = []
    for (subj,) in db.q("SELECT DISTINCT tls_subj FROM m WHERE tls_subj IS NOT NULL"):
        cns = dn_get(subj, "CN")
        orgs = dn_get(subj, "O")
        rows.append((subj, 1 if cns else 0, 1 if any(name_matches(c, hosts, ips) for c in cns) else 0, json.dumps(orgs, ensure_ascii=False)))
    db.many("INSERT INTO subjname VALUES (?,?,?,?)", rows)
    db.x("DROP TABLE IF EXISTS issuername")
    db.x("CREATE TEMP TABLE issuername (issuer TEXT PRIMARY KEY, issuer_org TEXT)")
    db.many("INSERT INTO issuername VALUES (?,?)",
            [(iss, json.dumps(dn_get(iss, "O"), ensure_ascii=False)) for (iss,) in db.q("SELECT DISTINCT tls_issuer FROM m WHERE tls_issuer IS NOT NULL")])


def classify(db):
    """TEMP 表 mc：m 并上证书信息与校验结果，算出 layer（三层细分）、name_judge（名字是不是 judge 的）、name_basis（判名字的依据）、
    ev_reason（证据为何不可用）。判据见模块文档和 DEFINITIONS。"""
    db.x("DROP TABLE IF EXISTS mc")
    db.x("""CREATE TEMP TABLE mc AS
            SELECT m.*,
                   li.parse_ok, li.leaf_sha256, li.name_judge AS li_name_judge, li.name_basis AS li_basis, li.san_n,
                   li.self_signed AS li_self, li.is_ca, li.not_before_epoch, li.not_after_epoch, li.n_certs,
                   li.subject_org AS li_subject_org, li.issuer_org AS li_issuer_org, li.public_key, li.sig_alg,
                   c.ok AS v_ok, c.err_class AS v_class, c.chain_len, c.root_org,
                   sn.has_cn, sn.cn_judge, sn.subject_org AS sn_subject_org, isn.issuer_org AS sn_issuer_org
            FROM m
            LEFT JOIN leafinfo li ON li.ev = m.ev AND m.ev_state = 'stored'
            LEFT JOIN chk c ON c.ev = m.ev AND (c.ts_epoch IS NULL OR c.ts_epoch = m.ts_epoch)
            LEFT JOIN subjname sn ON sn.subj = m.tls_subj
            LEFT JOIN issuername isn ON isn.issuer = m.tls_issuer""")
    db.x("DROP TABLE IF EXISTS mcl")
    db.x("""CREATE TEMP TABLE mcl AS
            SELECT *,
              CASE
                WHEN detail = 'unknown_authority' THEN '%(judge)s'
                WHEN ev_state = 'stored' AND parse_ok = 1 AND li_name_judge = 1 THEN '%(judge)s'
                WHEN ev_state = 'stored' AND parse_ok = 1 AND v_ok = 1 THEN '%(other)s'
                WHEN ev_state = 'stored' AND parse_ok = 1 AND v_ok = 0 THEN '%(unknown)s'
                WHEN ev_state = 'stored' AND parse_ok IS NULL THEN '%(unchecked)s'
                ELSE '%(noev)s'
              END AS layer,
              CASE
                WHEN detail = 'unknown_authority' THEN 1
                WHEN ev_state = 'stored' AND parse_ok = 1 THEN li_name_judge
                WHEN has_cn = 1 THEN cn_judge
                ELSE NULL
              END AS name_judge,
              CASE
                WHEN detail = 'unknown_authority' THEN 'detail'
                WHEN ev_state = 'stored' AND parse_ok = 1 THEN li_basis
                WHEN has_cn = 1 THEN 'subj_cn'
                ELSE 'none'
              END AS name_basis,
              CASE
                WHEN ev_state = 'none' THEN '探测器没拿到证书链'
                WHEN ev_state = 'missing' THEN '证据库超限没存'
                WHEN ev_state = 'stored' AND parse_ok = 0 THEN '文件读不了或解析不了'
                WHEN ev_state = 'stored' AND parse_ok IS NULL THEN '未校验'
                ELSE '已存并解析'
              END AS ev_reason
            FROM mc""" % {"judge": L_JUDGE, "other": L_OTHER, "unknown": L_UNKNOWN, "unchecked": L_UNCHECKED, "noev": L_NOEV})
    db.x("CREATE INDEX mcl_cand ON mcl(cand)")
    db.x("CREATE INDEX mcl_leaf ON mcl(tls_leaf)")
    db.x("CREATE INDEX mcl_prefix ON mcl(prefix24)")


# ---------------------------------------------------------------- 聚合

PROXY = "cand_kind = 'proxy' AND dst = 'judge_tls'"


def dense_where(exclude):
    return " AND prefix24 NOT IN (SELECT prefix24 FROM dense)" if exclude else ""


def counts(db, exclude_dense=False):
    """分母与总数。"""
    dw = dense_where(exclude_dense)
    tot = db.one("""SELECT COUNT(*), COALESCE(SUM(attempts), 0), COALESCE(SUM(hs_ok), 0), COALESCE(SUM(tls_reached), 0), COALESCE(SUM(tls_ok), 0),
                           COALESCE(SUM(ok), 0), COALESCE(SUM(mitm), 0), COALESCE(SUM(pin), 0),
                           SUM(hs_ok > 0), SUM(tls_reached > 0), SUM(ok > 0), SUM(mitm > 0), SUM(pin > 0), SUM(ok > 0 OR mitm > 0),
                           COUNT(DISTINCT prefix24)
                    FROM tc WHERE 1=1 %s""" % dw)
    (n_cands, a_all, a_hs, a_tls, a_tlsok, a_ok, a_mitm, a_pin, c_hs, c_tls, c_ok, c_mitm, c_pin, c_ok_or_mitm, n_pref) = [int(v or 0) for v in tot]
    m_tot = db.one("SELECT COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT prefix24), COUNT(DISTINCT tls_leaf), SUM(leaf_is_judge) FROM mcl WHERE %s %s" % (PROXY, dw))
    return {
        "探访过隧道协议的候选（socks5/socks4/connect→judge_tls 有尝试）": n_cands,
        "其中不同 /24": n_pref,
        "尝试（socks5/socks4/connect→judge_tls，非 canceled）": a_all,
        "尝试：握手通过（hs_ok=1，隧道建立）": a_hs,
        "尝试：到达 TLS 阶段（tls_ok=1 或 tls_class 非空）": a_tls,
        "尝试：TLS 校验通过（tls_ok=1）": a_tlsok,
        "尝试：走完全部阶段（class='ok'）": a_ok,
        "尝试：中间人（tls_cert_invalid）": a_mitm,
        "尝试：tls_pin_mismatch": a_pin,
        "候选：隧道建立过（hs_ok=1 过）": c_hs,
        "候选：到达过 TLS 阶段": c_tls,
        "候选：隧道曾可用（class='ok' 过）": c_ok,
        "候选：遇到过中间人": c_mitm,
        "候选：遇到过 tls_pin_mismatch": c_pin,
        "候选：隧道曾可用或遇到过中间人": c_ok_or_mitm,
        "中间人尝试（TEMP 表 mcl，代理、judge_tls）": int(m_tot[0] or 0),
        "中间人候选": int(m_tot[1] or 0),
        "中间人候选所在的 /24": int(m_tot[2] or 0),
        "中间人尝试里不同的叶子证书": int(m_tot[3] or 0),
        "仪器检查：中间人尝试里叶子等于 judge 自己证书的（应为 0）": int(m_tot[4] or 0),
    }


def ratios(db, n):
    return {
        "中间人尝试 / 到达 TLS 阶段的尝试": ratio(n["尝试：中间人（tls_cert_invalid）"], n["尝试：到达 TLS 阶段（tls_ok=1 或 tls_class 非空）"]),
        "中间人候选 / 隧道建立过的候选": ratio(n["候选：遇到过中间人"], n["候选：隧道建立过（hs_ok=1 过）"]),
        "中间人候选 / 隧道曾可用或遇到过中间人的候选": ratio(n["候选：遇到过中间人"], n["候选：隧道曾可用或遇到过中间人"]),
        "tls_pin_mismatch 候选 / 隧道建立过的候选": ratio(n["候选：遇到过 tls_pin_mismatch"], n["候选：隧道建立过（hs_ok=1 过）"]),
        "PROTOCOL 预期范围（证书被替换的代理占可用隧道代理）": "0% 到 5%（Mani 等 1.06%）；对账用哪一层待定，三层和总数都报告",
    }


def layer_block(db, exclude_dense=False):
    """三层细分：尝试数、候选数（不互斥）、按候选取最严重一层；各自带占中间人总数的比例。"""
    dw = dense_where(exclude_dense)
    total_a = int(db.scalar("SELECT COUNT(*) FROM mcl WHERE %s %s" % (PROXY, dw)) or 0)
    total_c = int(db.scalar("SELECT COUNT(DISTINCT cand) FROM mcl WHERE %s %s" % (PROXY, dw)) or 0)
    rows = db.q("SELECT layer, COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT prefix24), COUNT(DISTINCT tls_leaf) FROM mcl WHERE %s %s GROUP BY layer" % (PROXY, dw))
    by = {r[0]: r for r in rows}
    worst = db.q("""SELECT sev, COUNT(*) FROM (SELECT cand, MIN(%s) AS sev FROM mcl WHERE %s %s GROUP BY cand) GROUP BY sev"""
                 % (layer_sql_case(), PROXY, dw))
    sev_name = {v: k for k, v in SEVERITY.items()}
    worst_by = {sev_name.get(s, "?"): int(c) for s, c in worst}
    out = {"中间人尝试": total_a, "中间人候选": total_c, "layers": {}}
    for L in LAYERS:
        r = by.get(L)
        a, c, pfx, leaves = (int(r[1]), int(r[2]), int(r[3]), int(r[4])) if r else (0, 0, 0, 0)
        out["layers"][L] = {
            "尝试": ratio(a, total_a), "候选（不互斥）": ratio(c, total_c), "候选（最严重一层）": ratio(worst_by.get(L, 0), total_c),
            "不同 /24": pfx, "不同叶子证书": leaves,
        }
    # 冒充 judge 里证据没存下的（只靠 detail 判定）
    out["冒充 judge 其中证据未存（只靠 detail=unknown_authority 判定）"] = ratio(
        db.scalar("SELECT COUNT(*) FROM mcl WHERE %s %s AND layer = ? AND ev_state != 'stored'" % (PROXY, dw), (L_JUDGE,)),
        out["layers"][L_JUDGE]["尝试"]["num"])
    out["冒充 judge 按判据"] = {
        k: int(v) for k, v in db.q("SELECT name_basis, COUNT(*) FROM mcl WHERE %s %s AND layer = ? GROUP BY name_basis" % (PROXY, dw), (L_JUDGE,))}
    return out


def detail_matrix(db):
    """tls_detail_enum × 层（尝试数）。invalid_<n> 的 n 翻译成 Go 的原因名。"""
    rows = db.q("SELECT detail, layer, COUNT(*), COUNT(DISTINCT cand) FROM mcl WHERE %s GROUP BY detail, layer ORDER BY detail, layer" % PROXY)
    out = {}
    for detail, layer, a, c in rows:
        d = out.setdefault(detail, {"原因名": invalid_name(detail), "尝试": 0, "候选": 0, "按层": {}})
        d["尝试"] += int(a)
        d["按层"][layer] = {"尝试": int(a), "候选": int(c)}
    for detail in out:
        out[detail]["候选"] = int(db.scalar("SELECT COUNT(DISTINCT cand) FROM mcl WHERE %s AND detail = ?" % PROXY, (detail,)) or 0)
    return out


def invalid_name(detail):
    if detail == "unknown_authority":
        return "x509.UnknownAuthorityError（有效期和主机名都过了，链不认识）"
    if detail == "hostname_mismatch":
        return "x509.HostnameError（没过期，名字不是 judge 的）"
    if detail.startswith("invalid_"):
        try:
            n = int(detail.split("_", 1)[1])
            return "x509.CertificateInvalidError(%s)" % (INVALID_REASONS[n] if 0 <= n < len(INVALID_REASONS) else n)
        except ValueError:
            return "x509.CertificateInvalidError"
    return "其他 x509 错误类型（detail 是错误原文，不输出）"


def verify_classes(db):
    """证书链校验结果的分布（存下并解析成功的尝试），以及去向不明里各错误类别。"""
    rows = db.q("""SELECT layer, COALESCE(v_class, '(未校验)'), COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT ev)
                   FROM mcl WHERE %s AND ev_state = 'stored' AND parse_ok = 1 GROUP BY layer, v_class ORDER BY layer, 3 DESC""" % PROXY)
    out = {}
    for layer, cls, a, c, e in rows:
        out.setdefault(layer, {})[cls] = {"尝试": int(a), "候选": int(c), "不同证据文件": int(e)}
    roots = db.q("""SELECT COALESCE(root_org, '(未知)'), COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT tls_leaf) FROM mcl
                    WHERE %s AND layer = ? GROUP BY root_org ORDER BY 2 DESC LIMIT 20""" % PROXY, (L_OTHER,))
    return {
        "按层 × 校验错误类别": out,
        "被送到别的网站：链顶的公共根（组织名，前 20）": [
            {"根证书组织": safe_text(r[0]), "尝试": int(r[1]), "候选": int(r[2]), "不同叶子证书": int(r[3])} for r in roots],
        "自签（tls_self=1，探测器记的）": {
            "尝试": int(db.scalar("SELECT COUNT(*) FROM mcl WHERE %s AND tls_self = 1" % PROXY) or 0),
            "候选": int(db.scalar("SELECT COUNT(DISTINCT cand) FROM mcl WHERE %s AND tls_self = 1" % PROXY) or 0),
            "与 certcheck 的 self_signed 不一致的尝试（应为 0）": int(db.scalar(
                "SELECT COUNT(*) FROM mcl WHERE %s AND parse_ok = 1 AND li_self IS NOT NULL AND li_self != tls_self" % PROXY) or 0),
        },
        "叶子证书是 CA 证书的尝试": int(db.scalar("SELECT COUNT(*) FROM mcl WHERE %s AND is_ca = 1" % PROXY) or 0),
        "公钥类型（存下的叶子）": {k: int(v) for k, v in db.q(
            "SELECT COALESCE(public_key, '(未知)'), COUNT(DISTINCT ev) FROM mcl WHERE %s AND parse_ok = 1 GROUP BY public_key ORDER BY 2 DESC" % PROXY)},
    }


def no_evidence_block(db):
    """证据没存下的尝试：原因 × 名字判断（只按 tls_subj 的 CN）。"""
    rows = db.q("""SELECT ev_reason, CASE WHEN name_basis = 'detail' THEN 'detail=unknown_authority（已归入冒充 judge）'
                                          WHEN has_cn = 1 AND cn_judge = 1 THEN 'CN 是 judge 主机名'
                                          WHEN has_cn = 1 THEN 'CN 不是 judge 主机名'
                                          WHEN tls_subj IS NOT NULL THEN 'subj 里没有 CN'
                                          ELSE '没有 subj' END, detail, COUNT(*), COUNT(DISTINCT cand)
                   FROM mcl WHERE %s AND ev_state != 'stored' GROUP BY 1, 2, 3 ORDER BY 1, 2, 3""" % PROXY)
    out = {}
    for reason, name, detail, a, c in rows:
        d = out.setdefault(reason, {})
        d.setdefault(name, {"尝试": 0, "候选": 0, "按 detail": {}})
        d[name]["尝试"] += int(a)
        d[name]["按 detail"][detail] = int(a)
    for reason in out:
        for name in out[reason]:
            out[reason][name]["候选"] = int(db.scalar(
                """SELECT COUNT(DISTINCT cand) FROM mcl WHERE %s AND ev_state != 'stored' AND ev_reason = ? AND
                   CASE WHEN name_basis = 'detail' THEN 'detail=unknown_authority（已归入冒充 judge）'
                        WHEN has_cn = 1 AND cn_judge = 1 THEN 'CN 是 judge 主机名'
                        WHEN has_cn = 1 THEN 'CN 不是 judge 主机名'
                        WHEN tls_subj IS NOT NULL THEN 'subj 里没有 CN' ELSE '没有 subj' END = ?""" % PROXY, (reason, name)) or 0)
    unreadable = db.q("SELECT COUNT(*), COUNT(DISTINCT ev) FROM mcl WHERE %s AND ev_state = 'stored' AND parse_ok = 0" % PROXY)[0]
    return {"按原因 × 名字": out,
            "全部": ratio(db.scalar("SELECT COUNT(*) FROM mcl WHERE %s AND ev_state != 'stored'" % PROXY),
                        db.scalar("SELECT COUNT(*) FROM mcl WHERE %s" % PROXY)),
            "存下了但读不了或解析不了": {"尝试": int(unreadable[0] or 0), "不同证据文件": int(unreadable[1] or 0)}}


def by_proto(db):
    """按协议：从 tch（(候选, 协议, 小时) 聚合）汇总，不再扫 att。一个候选在某协议下任一小时到达过 TLS 阶段 / 遇到过中间人就算一次。"""
    rows = db.q("""SELECT proto, SUM(tls_reached), SUM(mitm), SUM(pin), COUNT(DISTINCT CASE WHEN tls_reached > 0 THEN cand END),
                          COUNT(DISTINCT CASE WHEN mitm > 0 THEN cand END)
                   FROM tch GROUP BY proto ORDER BY proto""")
    out = {}
    for proto, tls, mitm, pin, c_tls, c_mitm in rows:
        out[proto] = {"到达 TLS 阶段的尝试": int(tls or 0), "中间人尝试": ratio(mitm, tls), "tls_pin_mismatch 尝试": int(pin or 0),
                      "到达 TLS 阶段的候选": int(c_tls or 0), "中间人候选": ratio(c_mitm, c_tls)}
        layers = db.q("SELECT layer, COUNT(*) FROM mcl WHERE %s AND proto = ? GROUP BY layer" % PROXY, (proto,))
        out[proto]["中间人按层（尝试）"] = {k: int(v) for k, v in layers}
    return out


def safe_text(s, maxlen=60):
    """组织名之类的自由文本进输出前的处理：空→null；含地址、judge 身份、邮箱样式的隐去；截断。"""
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    if HOSTPORT_RE.search(s) or IPV4_RE.search(s) or "@" in s:
        return "(含地址，已隐去)"
    for h in GUARD_NAMES:
        if h and h.lower() in s.lower():
            return "(含 judge 身份，已隐去)"
    return s[:maxlen]


ORG_MIN_IPS = 5   # 证书上的组织名至少出现在这么多个不同代理 IP 上才输出
ORG_HIDDEN = "（出现在不到 %d 个 IP 上的组织名，不列出）"


def org_ip_counts(db):
    """中间人证书（代理）上每个组织名（叶子的主题/签发者 O）出现在多少个不同的代理 IP 上。
    只在一两个 IP 上出现的组织名，配上首末时刻和证书特征，能把一家真实机构和一个具体的代理对上号（仓库公开），所以按 IP 数设门槛。"""
    seen = {}
    for ip, a, b, c, d in db.q("""SELECT DISTINCT cand_ip, li_subject_org, li_issuer_org, sn_subject_org, sn_issuer_org
                                  FROM mcl WHERE %s""" % PROXY):
        for t in (a, b, c, d):
            if not t:
                continue
            try:
                arr = json.loads(t)
            except Exception:
                continue
            for name in arr:
                if name:
                    seen.setdefault(name, set()).add(ip)
    return {k: len(v) for k, v in seen.items()}


def orgs_text(json_text, ip_counts=None, min_ips=None):
    """leafinfo / subjname 里的组织名 JSON 数组 → 可输出文本。给了 ip_counts 时，出现在不到 min_ips 个 IP 上的组织名换成 ORG_HIDDEN。"""
    if not json_text:
        return None
    try:
        arr = json.loads(json_text)
    except Exception:
        return None
    out = []
    for a in arr:
        if not a:
            continue
        if ip_counts is not None and ip_counts.get(a, 0) < (min_ips or 0):
            t = ORG_HIDDEN % min_ips
        else:
            t = safe_text(a)
        if t and t not in out:
            out.append(t)
    return " / ".join(out) if out else None


BUCKETS = "CASE WHEN n = 1 THEN '1' WHEN n <= 5 THEN '2-5' WHEN n <= 20 THEN '6-20' WHEN n <= 100 THEN '21-100' ELSE '>100' END"
BUCKET_ORDER = {"1": 0, "2-5": 1, "6-20": 2, "21-100": 3, ">100": 4}


def leaf_verdict(db, leaf, stored, parsed_any, vmax, vmin):
    """按叶子汇总时“公共根校验”一栏（DEFINITIONS“公共根校验（按叶子）”）。结果不一致时按证据文件区分原因：
    同一文件在不同时刻结果不同 → 随时刻；不同文件结果不同 → 随所发的链。"""
    if not stored:
        return "证据未存"
    if vmax is None:
        return "未校验" if parsed_any is None else "证据解析不了"
    if vmax == vmin:
        return "公共根校验通过" if vmax == 1 else "校验不过"
    per_ev = db.q("""SELECT MIN(v_ok), MAX(v_ok) FROM mcl WHERE %s AND tls_leaf = ? AND v_ok IS NOT NULL GROUP BY ev""" % PROXY, (leaf,))
    by_time = any(a != b for a, b in per_ev)
    by_chain = len({(a, b) for a, b in per_ev}) > 1
    if by_time and by_chain:
        return "随所发的链和时刻都不同"
    if by_time:
        return "随时刻不同（跨过有效期边界）"
    return "随所发的链不同"


def leaves_block(db, top, min_org_ips=None):
    """按叶子证书（tls_leaf）汇总：出现在多少个代理（ip:port）、多少个不同 IP、多少个 /24；前 top 张只给组织名和计数。
    按 IP 计是因为 PROTOCOL 1.2“候选密集的地址段”：一个运营者可以在几个 IP 上挂上万个端口，按 ip:port 计会夸大规模。
    组织名只列出现在至少 min_org_ips 个不同代理 IP 上的（org_ip_counts）。"""
    min_org_ips = ORG_MIN_IPS if min_org_ips is None else min_org_ips
    oc = org_ip_counts(db)
    per_leaf = """SELECT tls_leaf, COUNT(DISTINCT cand) AS cands, COUNT(DISTINCT cand_ip) AS ips, COUNT(DISTINCT prefix24) AS prefixes, COUNT(*) AS attempts
                  FROM mcl WHERE %s AND tls_leaf IS NOT NULL GROUP BY tls_leaf""" % PROXY
    stats = db.one("""SELECT COUNT(*), SUM(cands >= 2), SUM(ips >= 2), SUM(prefixes >= 2), SUM(cands >= 10), SUM(ips >= 10), MAX(cands), MAX(ips)
                      FROM (%s)""" % per_leaf)
    hist_c = db.q("SELECT %s AS b, COUNT(*), SUM(cands), SUM(attempts) FROM (SELECT cands AS n, cands, attempts FROM (%s)) GROUP BY b"
                  % (BUCKETS, per_leaf))
    hist_i = db.q("SELECT %s AS b, COUNT(*), SUM(ips), SUM(cands), SUM(attempts) FROM (SELECT ips AS n, ips, cands, attempts FROM (%s)) GROUP BY b"
                  % (BUCKETS, per_leaf))
    rows = db.q("""SELECT tls_leaf, COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT prefix24), MIN(ts_epoch), MAX(ts_epoch),
                          MAX(name_judge), MAX(tls_self), MAX(li_self), MAX(v_ok), MIN(v_ok),
                          MAX(li_subject_org), MAX(li_issuer_org), MAX(sn_subject_org), MAX(sn_issuer_org),
                          MAX(not_before_epoch), MAX(not_after_epoch), MAX(san_n), MAX(n_certs), MAX(root_org), MAX(public_key), MAX(sig_alg),
                          MAX(ev_state = 'stored'), GROUP_CONCAT(DISTINCT proto), GROUP_CONCAT(DISTINCT detail),
                          COUNT(DISTINCT cand_ip), COUNT(DISTINCT CASE WHEN ev_state = 'stored' THEN ev END), SUM(ev_state != 'stored'),
                          MAX(parse_ok)
                   FROM mcl WHERE %s AND tls_leaf IS NOT NULL GROUP BY tls_leaf
                   ORDER BY 3 DESC, 2 DESC, 4 DESC LIMIT ?""" % PROXY, (top,))
    out_rows = []
    for i, r in enumerate(rows, 1):
        (leaf, a, c, pfx, t0, t1, nj, tself, lself, vmax, vmin, lso, lio, sso, sio, nb, na, san_n, ncerts, root_org, pk, sig, stored, protos, details,
         n_ip, n_ev, a_noev, parsed_any) = r
        layers = {k: int(v) for k, v in db.q("SELECT layer, COUNT(*) FROM mcl WHERE %s AND tls_leaf = ? GROUP BY layer" % PROXY, (leaf,))}
        out_rows.append({
            "序号": i,
            "候选": int(c), "不同 IP": int(n_ip), "不同 /24": int(pfx), "尝试": int(a),
            "协议": sorted((protos or "").split(",")),
            "detail": sorted((details or "").split(",")),
            "首次（小时）": iso_hour(t0), "末次（小时）": iso_hour(t1),
            "名字是 judge 的": (None if nj is None else bool(nj)),
            "自签": bool(tself) if lself is None else bool(lself),
            "证书链已存": bool(stored),
            "证据未存的尝试": int(a_noev or 0),
            "不同证书链文件（已存）": int(n_ev or 0),
            "公共根校验": leaf_verdict(db, leaf, stored, parsed_any, vmax, vmin),
            "链顶公共根（组织）": safe_text(root_org),
            "主题组织（O）": orgs_text(lso, oc, min_org_ips) or orgs_text(sso, oc, min_org_ips),
            "签发者组织（O）": orgs_text(lio, oc, min_org_ips) or orgs_text(sio, oc, min_org_ips),
            "有效期（天）": (round((na - nb) / 86400.0, 1) if nb is not None and na is not None else None),
            "SAN 条数": (int(san_n) if san_n is not None else None),
            "文件里的证书数": (int(ncerts) if ncerts is not None else None),
            "公钥": pk, "签名算法": sig,
            "按层（尝试）": layers,
        })
    return {
        "不同叶子证书": int(stats[0] or 0),
        "出现在 ≥2 个候选上的": int(stats[1] or 0),
        "出现在 ≥2 个不同 IP 上的": int(stats[2] or 0),
        "出现在 ≥2 个 /24 上的": int(stats[3] or 0),
        "出现在 ≥10 个候选上的": int(stats[4] or 0),
        "出现在 ≥10 个不同 IP 上的": int(stats[5] or 0),
        "单张证书最多出现在多少个候选上": int(stats[6] or 0),
        "单张证书最多出现在多少个不同 IP 上": int(stats[7] or 0),
        "按候选数分桶（证书张数 / 候选数 / 尝试数）": {b: {"证书": int(n), "候选": int(c), "尝试": int(a)}
                                       for b, n, c, a in sorted(hist_c, key=lambda r: BUCKET_ORDER.get(r[0], 9))},
        "按不同 IP 数分桶（证书张数 / 不同 IP 数 / 候选数 / 尝试数）": {b: {"证书": int(n), "不同 IP": int(ip), "候选": int(c), "尝试": int(a)}
                                                  for b, n, ip, c, a in sorted(hist_i, key=lambda r: BUCKET_ORDER.get(r[0], 9))},
        "前 %d 张（按候选数、尝试数）" % top: out_rows,
        "说明": "只给组织名和计数；证书哈希、CN、SAN、代理地址都不输出（白名单规则）。组织名只列出现在至少 %d 个不同代理 IP 上的，"
                "其余写“%s”：只在一两个 IP 上出现的组织名能把一家真实机构和一个具体的代理对上号。"
                "候选按 ip:port 计，“不同 IP”是 COUNT(DISTINCT cand_ip)，只输出个数" % (min_org_ips, ORG_HIDDEN % min_org_ips),
        "组织名门槛（不同代理 IP 数）": min_org_ips,
    }


def prefixes_block(db, top):
    """中间人候选按 /24 汇总：前 top 个 /24 的中间人候选数、该 /24 隧道建立过的候选数、状态文件里的候选总数、各层尝试数。"""
    have_cands = db.has_table("cands")
    cands_sub = "(SELECT COUNT(*) FROM cands c WHERE c.prefix24 = x.prefix24)" if have_cands else "NULL"
    rows = db.q("""SELECT x.prefix24, x.mitm_cands, x.attempts, x.leaves,
                          (SELECT COUNT(*) FROM tc WHERE tc.prefix24 = x.prefix24 AND tc.hs_ok > 0),
                          %s, x.prefix24 IN (SELECT prefix24 FROM dense), x.mitm_ips
                   FROM (SELECT prefix24, COUNT(DISTINCT cand) AS mitm_cands, COUNT(*) AS attempts, COUNT(DISTINCT tls_leaf) AS leaves,
                                COUNT(DISTINCT cand_ip) AS mitm_ips
                         FROM mcl WHERE %s AND prefix24 IS NOT NULL GROUP BY prefix24) x
                   ORDER BY x.mitm_cands DESC, x.attempts DESC LIMIT ?""" % (cands_sub, PROXY), (top,))
    out = []
    for pfx, mc, a, leaves, tunnel, total, dense, mips in rows:
        layers = {k: int(v) for k, v in db.q("SELECT layer, COUNT(*) FROM mcl WHERE %s AND prefix24 = ? GROUP BY layer" % PROXY, (pfx,))}
        out.append({"prefix24": pfx, "中间人候选": int(mc), "中间人候选的不同 IP": int(mips or 0), "隧道建立过的候选": int(tunnel or 0),
                    "状态文件里的候选": (int(total) if total is not None else None),
                    "中间人尝试": int(a), "不同叶子证书": int(leaves), "候选密集": bool(dense), "按层（尝试）": layers})
    n_pfx = int(db.scalar("SELECT COUNT(DISTINCT prefix24) FROM mcl WHERE %s" % PROXY) or 0)
    return {"中间人候选所在的不同 /24": n_pfx, "前 %d 个（按中间人候选数）" % top: out}


def nodes_block(db):
    """节点（proto='node'）的中间人尝试：按 arm 和层。节点的 ev 以节点标识为 owner，同样可能超限。"""
    sel = "cand_kind = 'node' AND dst = 'judge_tls'"
    total = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM mcl WHERE %s" % sel)
    out = {"中间人尝试": int(total[0] or 0), "不同节点": int(total[1] or 0), "按 arm": {}, "按层": {}}
    for arm, a, c in db.q("SELECT COALESCE(arm, '(无)'), COUNT(*), COUNT(DISTINCT cand) FROM mcl WHERE %s GROUP BY arm" % sel):
        out["按 arm"][arm] = {"尝试": int(a), "节点": int(c)}
    for layer, a, c in db.q("SELECT layer, COUNT(*), COUNT(DISTINCT cand) FROM mcl WHERE %s GROUP BY layer" % sel):
        out["按层"][layer] = {"尝试": int(a), "节点": int(c)}
    out["节点到 judge_tls 的尝试里到达 TLS 阶段的"] = int(db.scalar(
        """SELECT COUNT(*) FROM att WHERE proto = 'node' AND dst = 'judge_tls' AND +ts_epoch >= ? AND +ts_epoch < ?
           AND (COALESCE(tls_ok, 0) = 1 OR tls_class IS NOT NULL) AND (class IS NULL OR class NOT LIKE '%canceled%')""", (db.fs, db.fe)) or 0)
    return out


def original_total(db):
    """原定义总数（DEFINITIONS“原定义总数”）：m 的全部行——正式起点后、非 canceled、proto≠tlsproxy、非对照组的 tls_cert_invalid，
    不分代理/节点/目的地；再按 代理→judge_tls（主口径）/ 代理→第二观察者 / 代理→其他目的地 / 节点 拆开，各项相加等于总数。"""
    cat = """CASE WHEN cand_kind = 'proxy' AND dst = 'judge_tls' THEN '代理→judge_tls（主口径）'
                  WHEN cand_kind = 'proxy' AND dst LIKE 'obs:%' THEN '代理→第二观察者'
                  WHEN cand_kind = 'proxy' THEN '代理→其他目的地'
                  WHEN cand_kind = 'node' THEN '节点'
                  ELSE '其他（cand_kind 不是 proxy/node）' END"""
    tot = db.one("SELECT COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT CASE WHEN cand_kind = 'proxy' THEN cand_ip END) FROM m")
    parts = {k: {"尝试": int(a), "候选": int(c)} for k, a, c in db.q("SELECT %s AS k, COUNT(*), COUNT(DISTINCT cand) FROM m GROUP BY k ORDER BY k" % cat)}
    return {
        "尝试": int(tot[0] or 0),
        "候选（代理按 ip:port，节点按节点标识）": int(tot[1] or 0),
        "其中代理的不同 IP": int(tot[2] or 0),
        "按种类与目的地": parts,
        "口径": "正式起点后、非 canceled、proto≠tlsproxy、cand_kind≠control、tls_class='tls_cert_invalid'（PROTOCOL“指标定义”表“中间人”行的原定义）",
    }


def pin_block(db):
    rows = db.q("SELECT proto, COUNT(*), COUNT(DISTINCT cand) FROM p WHERE cand_kind = 'proxy' AND dst = 'judge_tls' GROUP BY proto")
    tot = db.one("SELECT COUNT(*), COUNT(DISTINCT cand), COUNT(DISTINCT prefix24), COUNT(DISTINCT tls_leaf), SUM(leaf_is_judge) FROM p WHERE cand_kind = 'proxy' AND dst = 'judge_tls'")
    return {
        "尝试": int(tot[0] or 0), "候选": int(tot[1] or 0), "不同 /24": int(tot[2] or 0), "不同叶子证书": int(tot[3] or 0),
        "仪器检查：叶子等于 judge 自己证书的（应为 0，否则是 SPKI 钉扎配置错）": int(tot[4] or 0),
        "按协议": {proto: {"尝试": int(a), "候选": int(c)} for proto, a, c in rows},
        "节点的 tls_pin_mismatch 尝试": int(db.scalar("SELECT COUNT(*) FROM p WHERE cand_kind = 'node'") or 0),
        "含义": "证书链按 judge 的信任根有效、公钥却不是 judge 的：要么有人拿到了 judge 主机名的公开证书（严重），要么 judge 换了证书而探测器的钉扎没更新（仪器）；"
              "两者在数据里分不开，报告时逐条核对时间与 self_leaf 的换证时刻",
    }


def hourly(db):
    """每小时：到达 TLS 阶段的尝试、中间人尝试与候选、tls_pin_mismatch。从 tch 汇总（tch 每行是一个候选、一个协议、一个小时）。"""
    rows = db.q("""SELECT hour_epoch, SUM(tls_reached), SUM(mitm), COUNT(DISTINCT CASE WHEN mitm > 0 THEN cand END), SUM(pin),
                          COUNT(DISTINCT CASE WHEN tls_reached > 0 THEN cand END)
                   FROM tch GROUP BY hour_epoch ORDER BY hour_epoch""")
    return [{"小时": iso_hour(h), "到达 TLS 阶段的尝试": int(t or 0), "中间人尝试": int(m or 0), "中间人候选": int(mc or 0),
             "到达 TLS 阶段的候选": int(tc or 0), "tls_pin_mismatch": int(pin or 0), "中间人尝试占比": pct(m or 0, t or 0)}
            for h, t, m, mc, pin, tc in rows]


def checks(db, n):
    """仪器与数据的自检：对照组不应有中间人；观察者目的地的中间人另计；judge 叶子只应有一张；ev 与 evidence 表的覆盖。"""
    out = {}
    # 对照组、tlsproxy 两条从 tx（tls_class 两类的全部行）过滤，不再扫 att
    out["对照组的 tls_cert_invalid 尝试（应为 0）"] = int(db.scalar(
        "SELECT COUNT(*) FROM tx WHERE cand_kind = 'control' AND tls_class = 'tls_cert_invalid' AND ts_epoch >= ? AND ts_epoch < ?", (db.fs, db.fe)) or 0)
    out["对照组的 tls_pin_mismatch 尝试（应为 0）"] = int(db.scalar(
        "SELECT COUNT(*) FROM tx WHERE cand_kind = 'control' AND tls_class = 'tls_pin_mismatch' AND ts_epoch >= ? AND ts_epoch < ?", (db.fs, db.fe)) or 0)
    obs = db.one("SELECT COUNT(*), COUNT(DISTINCT cand) FROM m WHERE cand_kind = 'proxy' AND dst LIKE 'obs:%'")
    out["第二观察者目的地的 tls_cert_invalid（不在主口径里）"] = {"尝试": int(obs[0] or 0), "候选": int(obs[1] or 0)}
    other = db.one("SELECT COUNT(*) FROM m WHERE cand_kind = 'proxy' AND dst != 'judge_tls' AND dst NOT LIKE 'obs:%'")
    out["代理到其他目的地的 tls_cert_invalid（应为 0）"] = int(other[0] or 0)
    out["tlsproxy 的 tls_cert_invalid（对代理端口按 IP 校验，几乎必然失败，不算中间人）"] = int(db.scalar(
        "SELECT COUNT(*) FROM tx WHERE proto = 'tlsproxy' AND tls_class = 'tls_cert_invalid' AND ts_epoch >= ? AND ts_epoch < ?", (db.fs, db.fe)) or 0)
    out["judge 叶子证书观测到的张数（meta.judge_leaf_observed_count，应为 1）"] = db.meta("judge_leaf_observed_count")
    cov = db.one("SELECT COUNT(*), SUM(ev IS NOT NULL), SUM(ev_state = 'stored'), SUM(ev_state = 'missing'), COUNT(DISTINCT ev), COUNT(DISTINCT CASE WHEN ev_state = 'stored' THEN ev END) FROM m WHERE %s" % PROXY)
    out["证据覆盖（代理、judge_tls）"] = {
        "中间人尝试": int(cov[0] or 0), "att.ev 非空": int(cov[1] or 0), "ev 在 evidence/ 里": int(cov[2] or 0),
        "ev 非空但 evidence/ 里没有（证据库超限）": int(cov[3] or 0), "不同 ev": int(cov[4] or 0), "不同 ev 且已存": int(cov[5] or 0),
    }
    if db.has_table("evidence"):
        ev = db.one("SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM evidence WHERE ext = 'der'")
        out["evidence/ 里的 .der 文件"] = {"个数": int(ev[0] or 0), "字节": int(ev[1] or 0)}
        out["evidence/ 里没有任何中间人尝试引用的 .der 文件（tlsproxy 或节点或试运行留下的）"] = int(db.scalar(
            "SELECT COUNT(*) FROM evidence WHERE ext = 'der' AND hash NOT IN (SELECT ev FROM m WHERE ev IS NOT NULL)") or 0)
    out["中间人尝试里 tls_leaf 为空的（应为 0）"] = int(db.scalar("SELECT COUNT(*) FROM m WHERE tls_leaf IS NULL") or 0)
    out["仪器检查：中间人尝试里叶子等于 judge 自己证书的（应为 0）"] = n["仪器检查：中间人尝试里叶子等于 judge 自己证书的（应为 0）"]
    out["tls_detail_enum='other' 的中间人尝试（x509 其他错误类型）"] = int(db.scalar("SELECT COUNT(*) FROM m WHERE detail = 'other'") or 0)
    return out


def crosscheck_summary(db, path):
    """与 fieldtest 自带 summary.json 的 findings 对账。summary.go integrity()：代理和节点、所有目的地、不裁正式起点、跳过 canceled、
    proto≠tlsproxy；candidates 是 who 的个数（节点带 "node " 前缀，与代理不会重名）。"""
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
    except Exception as e:
        return {"error": "读 summary.json 失败：%s" % e.__class__.__name__}
    findings = s.get("findings") or {}
    out = {"summary_generated": s.get("generated"), "items": {}}

    def put(key, want_a, want_c, got_a, got_c):
        out["items"][key] = {"summary.attempts": want_a, "ours.attempts": got_a, "attempts_match": (want_a == got_a) if want_a is not None else None,
                             "summary.candidates": want_c, "ours.candidates": got_c, "candidates_match": (want_c == got_c) if want_c is not None else None}

    # 从 tx（att 里 tls_class 两类的全部行，不裁起点）过滤，不再扫 att
    f = findings.get("隧道里的证书不是 judge 的（中间人）") or {}
    got = db.one("""SELECT COUNT(*), COUNT(DISTINCT cand) FROM tx WHERE tls_class = 'tls_cert_invalid' AND proto != 'tlsproxy'
                    AND COALESCE(cand_kind, '') != 'control' AND NOT canceled""")
    put("隧道里的证书不是 judge 的（中间人）", f.get("attempts"), f.get("candidates"), int(got[0] or 0), int(got[1] or 0))
    f = findings.get("证书链有效但公钥不是 judge 的") or {}
    got = db.one("""SELECT COUNT(*), COUNT(DISTINCT cand) FROM tx WHERE tls_class = 'tls_pin_mismatch'
                    AND COALESCE(cand_kind, '') != 'control' AND NOT canceled""")
    put("证书链有效但公钥不是 judge 的", f.get("attempts"), f.get("candidates"), int(got[0] or 0), int(got[1] or 0))
    out["note"] = ("summary.go 不裁正式起点、把节点算在内，这里按它的口径重算；本模块主口径（代理、judge_tls、正式起点后）在 total.中间人，"
                   "原定义（代理+节点+全部目的地，正式起点后）在 total.原定义总数")
    return out


# ---------------------------------------------------------------- 输出前的断言

IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?!\d|\.\d|/24)")
HOSTPORT_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}:\d{1,5}")
GUARD_NAMES = []   # run() 填入 judge 的主机名与 IP（和 --guard 给的字符串），供 safe_text 用；不进输出


def assert_clean(text, db, extra_guards=()):
    """最后一道保险：输出文本里不许有 ip:port、不带 /24 的 IPv4、judge 的主机名或 IP、邮箱样式的 @、证书哈希样式的 64 位十六进制、
    本机路径（--db / --data / --out / --certcheck / --roots 的目录）和 --guard 给的字符串。这是断言，不是放行手段。
    judge 的身份只从库里的 self_names / self_ips 取（夹具库里就是夹具的主机名和回环地址），源码里不写任何具体的主机名或地址。"""
    bad = []
    # 两个已知的、不是地址也不是哈希的值先摘掉再查：根证书文件的 sha256（公开文件）和 ca-certificates 的包版本
    # （形如 20260816ubuntu0.24.04.1，尾部长得像 IPv4）。其余一律按规则判
    allowed = set()
    try:
        d = json.loads(text)
        r = ((d.get("certcheck") or {}).get("roots") or {})
        for k in ("sha256", "package_version"):
            if r.get(k):
                allowed.add(str(r[k]))
    except Exception:
        pass
    scan = text
    for v in allowed:
        scan = scan.replace(v, "")
    if HOSTPORT_RE.search(scan):
        bad.append("ip:port")
    if IPV4_RE.search(scan):
        bad.append("不带 /24 的 IPv4")
    for table, col in (("self_names", "name"), ("self_ips", "ip")):
        if db.has_table(table):
            for (v,) in db.q("SELECT DISTINCT %s FROM %s" % (col, table)):
                if v and v.lower() in text.lower():
                    bad.append("judge 身份（%s）" % table)
                    break
    if "@" in text:
        bad.append("@（邮箱样式）")
    for g in extra_guards:
        if g and g.lower() in text.lower():
            bad.append("--guard 或本机路径")
            break
    # 64 位十六进制 = 证书 / 证据哈希；根证书文件的 sha256 已摘掉，剩下的都不许出现
    if re.search(r"\b[0-9a-f]{64}\b", scan):
        bad.append("64 位十六进制哈希")
    if bad:
        raise SystemExit("输出含不许出现的内容：%s；已拒绝写出" % "、".join(bad))


# ---------------------------------------------------------------- Markdown

def print_markdown(res):
    w = res["window"]
    n = res["n"]
    cc = res["certcheck"]
    if cc.get("stored_files") and not cc.get("verified"):
        print(f"> **证书链未校验**：{cc.get('unverified_reason')}。{fmt(cc.get('stored_files'))} 个存下的证据文件对应的尝试归“{L_UNCHECKED}”，"
              f"“被送到别的网站”和“去向不明”两层不完整，不能用于报告。\n")
    print("### “中间人”的细分（PROTOCOL 第 1.2 版；细分是看过试运行数据以后加的，总数照原定义）\n")
    print(f"- 正式起点 {w['formal_start_utc']}（{w['formal_start_rule']}），结束 {w['end_utc']}，共 {fmt(w['hours'])} 小时；"
          f"正式起点之前的试运行尝试 {fmt(w['trial_run_attempts_before_formal_start'])} 次")
    print(f"- 72 小时的终点 {w['formal_end_72h_utc']}，之后的 att {fmt(w['after_72h']['att 记录'])} 条；{w['formal_end_rule']}")
    if w["interruptions"]:
        segs = "；".join(f"{x['from_utc']} 到 {x['start_utc']}（{x['kind']}，{fmt(x['minutes'])} 分钟）" for x in w["interruptions"])
        print(f"- 中断 {len(w['interruptions'])} 次，共 {fmt(w['interruption_minutes_total'])} 分钟：{segs}")
    else:
        print("- 正式起点之后没有中断（没有再次 start）")
    for x in w.get("warnings") or []:
        print(f"- 注意：{x}")
    ot = res["total"]["原定义总数"]
    print(f"- 原定义总数（代理+节点+全部目的地，正式起点后，proto≠tlsproxy）：尝试 {fmt(ot['尝试'])}，候选 {fmt(ot['候选（代理按 ip:port，节点按节点标识）'])}；"
          + "，".join(f"{k} {fmt(v['尝试'])} 次 / {fmt(v['候选'])} 个" for k, v in ot["按种类与目的地"].items()))
    print(f"- 隧道协议（socks5/socks4/connect→judge_tls）的尝试 {fmt(n['尝试（socks5/socks4/connect→judge_tls，非 canceled）'])}，"
          f"其中到达 TLS 阶段 {fmt(n['尝试：到达 TLS 阶段（tls_ok=1 或 tls_class 非空）'])}，TLS 校验通过 {fmt(n['尝试：TLS 校验通过（tls_ok=1）'])}，"
          f"中间人 {fmt(n['尝试：中间人（tls_cert_invalid）'])}，tls_pin_mismatch {fmt(n['尝试：tls_pin_mismatch'])}")
    ever_ok = n["候选：隧道曾可用（class='ok' 过）"]
    print(f"- 候选：隧道建立过 {fmt(n['候选：隧道建立过（hs_ok=1 过）'])}，隧道曾可用 {fmt(ever_ok)}，"
          f"遇到过中间人 {fmt(n['候选：遇到过中间人'])}（{fmt(n['中间人候选所在的 /24'])} 个 /24，{fmt(n['中间人尝试里不同的叶子证书'])} 张不同叶子证书）")
    r = res["total"]["ratios"]["all"]
    print(f"- 中间人尝试 / 到达 TLS 阶段的尝试 {rfmt(r['中间人尝试 / 到达 TLS 阶段的尝试'])}；"
          f"中间人候选 / 隧道建立过的候选 {rfmt(r['中间人候选 / 隧道建立过的候选'])}；"
          f"中间人候选 / 隧道曾可用或遇到过中间人的候选 {rfmt(r['中间人候选 / 隧道曾可用或遇到过中间人的候选'])}（预期 0% 到 5%）")
    roots = cc.get("roots") or {}
    print(f"- 证书链校验：{cc.get('tool') or '未运行'}（{cc.get('note') or 'Go ' + str(cc.get('go_version'))}）；"
          f"公共根证书 {roots.get('file') or '—'}，{fmt(roots.get('certs'))} 张，包版本 {roots.get('package_version') or '未知'}，"
          f"Mozilla 根库 {roots.get('mozilla_bundle_version') or '未知（' + str(roots.get('note')) + '）'}"
          + (f"，备注 {roots.get('roots_note')}" if roots.get("roots_note") else "")
          + f"，sha256 {str(roots.get('sha256') or '')[:16]}…；{fmt(cc.get('stored_files'))} 个证据文件，校验 {fmt(cc.get('jobs'))} 次"
          f"（{fmt(cc.get('certcheck_calls'))} 批），其中按精确时刻重算 {fmt(cc.get('refined_files'))} 个文件、{fmt(cc.get('refined_jobs'))} 次")
    for key, title in (("all", "全部"), ("excluding_dense", "去掉候选超过 %d 个的 /24" % res["dense_prefixes"]["threshold"])):
        lb = res["layers"][key]
        if key == "excluding_dense" and not res["dense_prefixes"]["count"]:
            continue
        print(f"\n#### 三层细分（{title}；中间人尝试 {fmt(lb['中间人尝试'])}，候选 {fmt(lb['中间人候选'])}）\n")
        print("| 层 | 尝试 | 候选（不互斥） | 候选（最严重一层） | 不同 /24 | 不同叶子证书 |")
        print("| --- | --- | --- | --- | --- | --- |")
        for L in LAYERS:
            x = lb["layers"][L]
            if x["尝试"]["num"] == 0 and L in (L_UNCHECKED,):
                continue
            print(f"| {L} | {rfmt(x['尝试'])} | {rfmt(x['候选（不互斥）'])} | {rfmt(x['候选（最严重一层）'])} | {fmt(x['不同 /24'])} | {fmt(x['不同叶子证书'])} |")
        print(f"\n冒充 judge 里证据未存、只靠 detail=unknown_authority 判定的：{rfmt(lb['冒充 judge 其中证据未存（只靠 detail=unknown_authority 判定）'])}")
    print("\n#### tls_detail × 层（尝试）\n")
    print("| detail | Go 的含义 | 尝试 | 候选 | 按层 |")
    print("| --- | --- | --- | --- | --- |")
    for d, x in res["layers"]["detail_x_layer"].items():
        cells = "，".join(f"{L} {fmt(v['尝试'])}" for L, v in x["按层"].items())
        print(f"| {d} | {x['原因名']} | {fmt(x['尝试'])} | {fmt(x['候选'])} | {cells} |")
    vc = res["layers"]["verify_classes"]["按层 × 校验错误类别"]
    if vc:
        print("\n#### 证书链校验结果（存下并解析成功的尝试）\n")
        print("| 层 | 错误类别 | 尝试 | 候选 | 不同证据文件 |")
        print("| --- | --- | --- | --- | --- |")
        for L, classes in vc.items():
            for cls, v in classes.items():
                print(f"| {L} | {cls} | {fmt(v['尝试'])} | {fmt(v['候选'])} | {fmt(v['不同证据文件'])} |")
    ne = res["layers"]["no_evidence"]["按原因 × 名字"]
    if ne:
        print("\n#### 证据没存下的尝试（只按 tls_subj 的 CN 判名字）\n")
        print("| 原因 | 名字 | 尝试 | 候选 |")
        print("| --- | --- | --- | --- |")
        for reason, names in ne.items():
            for name, v in names.items():
                print(f"| {reason} | {name} | {fmt(v['尝试'])} | {fmt(v['候选'])} |")
    pin = res["total"]["tls_pin_mismatch"]
    print(f"\ntls_pin_mismatch（单列）：尝试 {fmt(pin['尝试'])}，候选 {fmt(pin['候选'])}，不同叶子 {fmt(pin['不同叶子证书'])}")
    lv = res["leaves"]
    top_key = [k for k in lv if k.startswith("前 ")][0]
    print(f"\n#### 按叶子证书汇总（不同叶子 {fmt(lv['不同叶子证书'])}，出现在 ≥2 个候选上的 {fmt(lv['出现在 ≥2 个候选上的'])}，"
          f"≥2 个不同 IP 的 {fmt(lv['出现在 ≥2 个不同 IP 上的'])}，≥2 个 /24 的 {fmt(lv['出现在 ≥2 个 /24 上的'])}）\n")
    print("| # | 候选 | 不同 IP | /24 | 尝试 | 协议 | 名字是 judge 的 | 自签 | 公共根校验 | 主题组织 | 签发者组织 | 有效期（天） | 按层 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in lv[top_key]:
        layers = "，".join(f"{L} {fmt(v)}" for L, v in r["按层（尝试）"].items())
        nj = "—" if r["名字是 judge 的"] is None else ("是" if r["名字是 judge 的"] else "否")
        print(f"| {r['序号']} | {fmt(r['候选'])} | {fmt(r['不同 IP'])} | {fmt(r['不同 /24'])} | {fmt(r['尝试'])} | {'/'.join(r['协议'])} | {nj} | {'是' if r['自签'] else '否'} | "
              f"{r['公共根校验']} | {r['主题组织（O）'] or '—'} | {r['签发者组织（O）'] or '—'} | {fmt(r['有效期（天）'])} | {layers} |")
    px = res["prefixes"]
    top_key = [k for k in px if k.startswith("前 ")][0]
    if px[top_key]:
        print(f"\n#### 中间人候选按 /24（不同 /24 共 {fmt(px['中间人候选所在的不同 /24'])}）\n")
        print("| /24 | 中间人候选 | 其中不同 IP | 隧道建立过的候选 | 状态文件里的候选 | 中间人尝试 | 不同叶子 | 候选密集 | 按层 |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in px[top_key]:
            layers = "，".join(f"{L} {fmt(v)}" for L, v in r["按层（尝试）"].items())
            print(f"| {r['prefix24']} | {fmt(r['中间人候选'])} | {fmt(r['中间人候选的不同 IP'])} | {fmt(r['隧道建立过的候选'])} | {fmt(r['状态文件里的候选'])} | {fmt(r['中间人尝试'])} | "
                  f"{fmt(r['不同叶子证书'])} | {'是' if r['候选密集'] else '否'} | {layers} |")
    nd = res["nodes"]
    print(f"\n节点：中间人尝试 {fmt(nd['中间人尝试'])}，不同节点 {fmt(nd['不同节点'])}，按层 "
          + ("，".join(f"{L} {fmt(v['尝试'])}" for L, v in nd["按层"].items()) or "—"))
    if res.get("crosscheck"):
        print("\n#### 与 summary.json 对账（按 summary.go 的口径重算）\n")
        def verdict(m):
            return "（summary 里没有这一项）" if m is None else ("（一致）" if m else "（不一致）")
        for k, v in res["crosscheck"].get("items", {}).items():
            print(f"- {k}：尝试 summary {fmt(v['summary.attempts'])} / 本模块 {fmt(v['ours.attempts'])}{verdict(v['attempts_match'])}；"
                  f"候选 summary {fmt(v['summary.candidates'])} / 本模块 {fmt(v['ours.candidates'])}{verdict(v['candidates_match'])}")


# ---------------------------------------------------------------- 主流程

def path_guards(*paths):
    """本机路径（及其目录）不许出现在输出里：--roots 可能在用户目录下、--data 可能带用户名。太短的不算（免得误伤正文）。"""
    out = set()
    for p in paths:
        if not p:
            continue
        ap = os.path.abspath(p)
        for x in (ap, os.path.dirname(ap)):
            if len(x) >= 8 and x not in ("/usr/share", "/etc/ssl/certs", "/usr/local", "/usr/bin"):
                out.add(x)
    return sorted(out)


def run(db_path, out_dir, data_dir=None, roots=DEFAULT_ROOTS, certcheck_arg=None, summary_path=None, formal_start="auto",
        dense_threshold=DENSE_THRESHOLD, top_leaves=TOP_LEAVES, top_prefixes=TOP_PREFIXES, markdown=False, write=True,
        formal_end="none", batch_size=CERTCHECK_BATCH, roots_note=None, guards=()):
    db = DB(db_path)
    wl_source = check_whitelist(db)
    if not db.has_table("att"):
        raise SystemExit("库里没有 att 表")
    for col in ("tls_detail_enum", "cand_kind", "prefix24", "cand_ip"):
        if not db.has_column("att", col):
            raise SystemExit("att 表没有派生列 %s，需要 ingest.py 第 3 版以上建的库" % col)
    win = observation_window(db, formal_start, formal_end)
    fs, _end, fe = win.pop("_fs"), win.pop("_end"), win.pop("_fe")
    db.fs, db.fe = fs, fe
    for x in win["warnings"]:
        print("警告：" + x, file=sys.stderr)
    hosts, ips = judge_identity(db)
    GUARD_NAMES[:] = [h for h in hosts + ips + list(guards) if h]
    if not hosts:
        print("警告：库里没有 judge 的主机名（self_names），“名字是 judge 的”只能靠 detail=unknown_authority 判定", file=sys.stderr)
    if data_dir is None:
        data_dir = db.meta("data_dir")
    extra_guards = list(guards) + path_guards(db_path, data_dir, out_dir, roots,
                                              certcheck_arg if certcheck_arg and certcheck_arg != "go" else None)
    res = {
        "module": MODULE, "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol_version": PROTOCOL_VERSION, "whitelist_source": wl_source,
        "db_meta": {k: db.meta(k) for k in ("ingest_version", "first_ts", "last_ts", "evidence_files", "evidence_bytes", "judge_leaf_observed_count", "state_cands")},
        "definitions": DEFINITIONS,
        "note": "“中间人”的细分是 PROTOCOL 第 1.2 版看过试运行数据以后加的；总数照原定义报告，细分另列，不替换总数。",
        "window": win,
        "judge_identity_available": {"主机名": len(hosts) > 0, "公网 IP": len(ips) > 0, "主机名个数（多于 1 说明中途改过配置）": len(hosts)},
    }
    res["dense_prefixes"] = build_dense(db, dense_threshold)
    n_tx = build_tx(db)
    n_m = build_mitm_table(db, fs, fe)
    build_pin_table(db, fs, fe)
    build_cand_table(db, fs, fe)
    win["after_72h"]["其中中间人尝试（原定义，代理+节点+全部目的地）"] = int(db.scalar(
        """SELECT COUNT(*) FROM tx WHERE tls_class = 'tls_cert_invalid' AND proto != 'tlsproxy' AND COALESCE(cand_kind, '') != 'control'
           AND NOT canceled AND ts_epoch >= ?""", (fs + FORMAL_HOURS * 3600.0,)) or 0)
    res["scan"] = {"tx（att 里 tls_class 为 tls_cert_invalid / tls_pin_mismatch 的全部行）": int(n_tx or 0),
                   "tch（隧道协议→judge_tls 的代理尝试按 候选×协议×小时 聚合）": int(db.scalar("SELECT COUNT(*) FROM tch") or 0)}
    if n_m == 0:
        print("正式起点之后没有任何中间人尝试，各表为空", file=sys.stderr)
    res["certcheck"] = verify_chains(db, data_dir, roots, certcheck_arg, hosts, ips, batch=batch_size, roots_note=roots_note)
    build_subj_names(db, hosts, ips)
    classify(db)

    n_all = counts(db, False)
    n_dense = counts(db, True)
    res["n"] = n_all
    res["total"] = {
        "原定义总数": original_total(db),
        "中间人": {"口径": "主口径：代理、目的地 judge_tls、正式起点后（原定义总数的一部分）",
                "尝试": n_all["尝试：中间人（tls_cert_invalid）"], "候选": n_all["候选：遇到过中间人"],
                "候选的不同 IP": int(db.scalar("SELECT COUNT(DISTINCT cand_ip) FROM mcl WHERE %s" % PROXY) or 0),
                "不同 /24": n_all["中间人候选所在的 /24"],
                "不同叶子证书": n_all["中间人尝试里不同的叶子证书"], "按协议": by_proto(db)},
        "tls_pin_mismatch": pin_block(db),
        "ratios": {"all": ratios(db, n_all), "excluding_dense": ratios(db, n_dense)},
        "n_excluding_dense": n_dense,
    }
    res["layers"] = {
        "all": layer_block(db, False), "excluding_dense": layer_block(db, True),
        "detail_x_layer": detail_matrix(db), "verify_classes": verify_classes(db), "no_evidence": no_evidence_block(db),
        "name_basis": {k: int(v) for k, v in db.q("SELECT name_basis, COUNT(*) FROM mcl WHERE %s GROUP BY name_basis" % PROXY)},
        "name_judge": {("是" if k == 1 else "否" if k == 0 else "判不了"): int(v) for k, v in db.q("SELECT name_judge, COUNT(*) FROM mcl WHERE %s GROUP BY name_judge" % PROXY)},
    }
    res["leaves"] = leaves_block(db, top_leaves)
    res["prefixes"] = prefixes_block(db, top_prefixes)
    res["nodes"] = nodes_block(db)
    res["hourly"] = hourly(db)
    res["checks"] = checks(db, n_all)
    if summary_path:
        res["crosscheck"] = crosscheck_summary(db, summary_path)

    text = json.dumps(res, ensure_ascii=False, indent=1, sort_keys=False)
    assert_clean(text, db, extra_guards)
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

SELFTEST_HOST = "judge.selftest.invalid"
SELFTEST_IP = "203.0.113.7"          # TEST-NET-3
SELFTEST_T0 = "2026-11-07T00:30:00Z"  # 合成证书的基准时刻（有效期边界落在半点上，用来测“按时刻校验”的精确重算）
JUDGE_LEAF = "9" * 64


def _synthetic_db(path, gen):
    """最小合成库，只建本模块用到的列。gen 是 certcheck -gen 的输出（证据文件的哈希和路径）。场景见各行注释；预期值在 selftest() 里断言。
    地址只用文档保留段（TEST-NET-1/2、基准测试段 198.18.0.0/15）。"""
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE att (rid INTEGER PRIMARY KEY, file_id INTEGER, ts TEXT, ts_epoch REAL, visit TEXT, cand TEXT, proto TEXT, dst TEXT, kind TEXT, arm TEXT,
        nonce TEXT, tcp_ok INTEGER, hs_ok INTEGER, hs_class TEXT, tls_ok INTEGER, tls_class TEXT, tls_detail TEXT, tls_leaf TEXT, tls_subj TEXT,
        tls_issuer TEXT, tls_self INTEGER, class TEXT, ev TEXT, ms INTEGER, cand_kind TEXT, cand_ip TEXT, cand_port INTEGER, prefix24 TEXT,
        tls_detail_enum TEXT, raw TEXT);
    CREATE INDEX att_proto_dst_class ON att(proto, dst, class);
    CREATE TABLE visit (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, cand TEXT, prefix24 TEXT, aborted INTEGER);
    CREATE TABLE evidence (hash TEXT PRIMARY KEY, ext TEXT, bytes INTEGER, path TEXT);
    CREATE TABLE self_leaf (leaf TEXT, source TEXT, n INTEGER, first_ts TEXT, last_ts TEXT);
    CREATE TABLE self_names (name TEXT, source TEXT, n INTEGER);
    CREATE TABLE self_ips (ip TEXT, source TEXT, n INTEGER);
    CREATE TABLE start (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, resumed_candidates INTEGER);
    CREATE TABLE stop (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL);
    CREATE TABLE version (rid INTEGER PRIMARY KEY, ts TEXT, ts_epoch REAL, version TEXT);
    CREATE TABLE cands (rid INTEGER PRIMARY KEY, key TEXT, ip TEXT, port INTEGER, prefix24 TEXT, visits INTEGER);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    """)
    T0 = parse_iso(SELFTEST_T0)
    H = 3600.0
    D = 86400.0
    con.execute("INSERT INTO self_names VALUES (?, 'start.judge_host', 1)", (SELFTEST_HOST,))
    con.execute("INSERT INTO self_ips VALUES (?, 'start.judge_ip', 1)", (SELFTEST_IP,))
    con.execute("INSERT INTO self_leaf VALUES (?, 'control_ok', 5, NULL, NULL)", (JUDGE_LEAF,))
    con.execute("INSERT INTO start VALUES (1, ?, ?, 0)", (iso_exact(T0 - 80 * H), T0 - 80 * H))   # 试运行
    con.execute("INSERT INTO start VALUES (2, ?, ?, 0)", (iso_exact(T0 - 72 * H), T0 - 72 * H))   # 状态清空：正式起点
    con.execute("INSERT INTO version VALUES (1, ?, ?, '0.1.1-test')", (iso_exact(T0 - 80 * H), T0 - 80 * H))
    con.execute("INSERT INTO version VALUES (2, ?, ?, '0.1.1-test')", (iso_exact(T0 - 72 * H), T0 - 72 * H))
    con.execute("INSERT INTO stop VALUES (1, ?, ?)", (iso_exact(T0 + H), T0 + H))
    con.execute("INSERT INTO start VALUES (3, ?, ?, 30)", (iso_exact(T0 + H + 600), T0 + H + 600))   # 正常停止后 10 分钟重启：中断 10 分钟
    con.execute("INSERT INTO meta VALUES ('data_dir', ?)", (gen["dir"],))
    con.execute("INSERT INTO meta VALUES ('ingest_version', '3')")
    con.execute("INSERT INTO meta VALUES ('judge_leaf_observed_count', '1')")
    for name, c in gen["chains"].items():
        con.execute("INSERT INTO evidence VALUES (?, 'der', ?, ?)", (c["hash"], 400, c["path"]))
    ch = {name: c["hash"] for name, c in gen["chains"].items()}
    leaf = {name: c.get("leaf") or ("c" * 64) for name, c in gen["chains"].items()}

    # 密集 /24：198.18.0.0/24 里 150 个候选；其他 /24 只有几个
    rows = []
    for i in range(150):
        rows.append(("198.18.0.%d:%d" % (i % 250 + 1, 10000 + i), "198.18.0.%d" % (i % 250 + 1), 10000 + i, "198.18.0.0/24", 1))
    for i in range(1, 30):
        rows.append(("198.51.100.%d:8080" % i, "198.51.100.%d" % i, 8080, "198.51.100.0/24", 1))
    for i in range(1, 10):
        rows.append(("192.0.2.%d:8080" % i, "192.0.2.%d" % i, 8080, "192.0.2.0/24", 1))
    con.executemany("INSERT INTO cands (key, ip, port, prefix24, visits) VALUES (?,?,?,?,?)", rows)

    def key(net, i, port=8080):
        return "%s.%d:%d" % (net, i, port), "%s.0/24" % net

    rid = [0]

    def a(t, cand, proto, dst, cls, tcp=1, hs_ok=1, hs_class=None, tls_ok=None, tls_class=None, de=None, leaf_=None, subj=None, issuer=None,
          tls_self=None, ev=None, kind="proxy", arm=None):
        rid[0] += 1
        if kind == "proxy":
            cand_key, pfx = cand
            ip = cand_key.split(":")[0]
            port = int(cand_key.split(":")[1])
        else:
            cand_key, pfx, ip, port = cand, None, None, None
        con.execute("""INSERT INTO att (rid, ts, ts_epoch, visit, cand, proto, dst, arm, tcp_ok, hs_ok, hs_class, tls_ok, tls_class, tls_detail, tls_leaf,
                       tls_subj, tls_issuer, tls_self, class, ev, ms, cand_kind, cand_ip, cand_port, prefix24, tls_detail_enum, raw)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (rid[0], iso_exact(t), t, "v%d" % rid[0], cand_key, proto, dst, arm, tcp, hs_ok, hs_class, tls_ok, tls_class, de, leaf_,
                     subj, issuer, tls_self, cls, ev, 100, kind, ip, port, pfx, de if tls_class == "tls_cert_invalid" else None, "{}"))

    MITM = "tls_cert_invalid"
    JS = "CN=%s,O=Synthetic MITM" % SELFTEST_HOST
    c = {i: key("198.51.100", i) for i in range(1, 30)}
    d = {i: key("192.0.2", i) for i in range(1, 10)}
    dense_c = key("198.18.0", 5, 10004)
    # 1 冒充 judge（detail）：自签、SAN=judge、链已存
    a(T0, c[1], "socks5", "judge_tls", MITM, tls_class=MITM, de="unknown_authority", leaf_=leaf["judge_selfsigned"], subj=JS, issuer=JS, tls_self=1, ev=ch["judge_selfsigned"])
    # 2 冒充 judge（存下的叶子 SAN）：已过期，detail=invalid_1
    a(T0, c[2], "connect", "judge_tls", MITM, tls_class=MITM, de="invalid_1", leaf_=leaf["judge_expired"], subj=JS, issuer=JS, tls_self=1, ev=ch["judge_expired"])
    # 3 冒充 judge（通配符 SAN 覆盖 judge 主机名）
    a(T0, c[3], "socks4", "judge_tls", MITM, tls_class=MITM, de="invalid_1", leaf_=leaf["wildcard_expired"], subj="CN=*.selftest.invalid,O=Synthetic MITM",
      issuer="CN=*.selftest.invalid,O=Synthetic MITM", tls_self=1, ev=ch["wildcard_expired"])
    # 4 被送到别的网站：合成中间证书签发、链完整、有效（两次尝试）
    for k in range(2):
        a(T0 + k * 600, c[4], "socks5", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_valid_chain"], subj="CN=other.example,O=Other Site Ltd",
          issuer="CN=Synthetic Test Intermediate,O=Synthetic Roots", tls_self=0, ev=ch["other_valid_chain"])
    # 4 同一张叶子、另一份证据文件（只发了叶子、没发中间证书）：校验不过 → 去向不明；这张叶子的“公共根校验”应是“随所发的链不同”
    a(T0 + 1200, c[4], "socks5", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_valid_chain"], subj="CN=other.example,O=Other Site Ltd",
      issuer="CN=Synthetic Test Intermediate,O=Synthetic Roots", tls_self=0, ev=ch["other_valid_leaf_only"])
    # 5 去向不明：别的名字、自签
    a(T0, c[5], "connect", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_selfsigned"], subj="CN=other2.example,O=Other2",
      issuer="CN=other2.example,O=Other2", tls_self=1, ev=ch["other_selfsigned"])
    # 6/7 同一证书不同时刻：在 T0 过期（去向不明）、在 T0-36h 有效（别的网站）
    a(T0, c[6], "socks5", "judge_tls", MITM, tls_class=MITM, de="invalid_1", leaf_=leaf["other_expired_then_valid"], subj="CN=other3.example,O=Other3",
      issuer="CN=Synthetic Test Root,O=Synthetic Roots", tls_self=0, ev=ch["other_expired_then_valid"])
    a(T0 - 36 * H, c[7], "socks5", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_expired_then_valid"], subj="CN=other3.example,O=Other3",
      issuer="CN=Synthetic Test Root,O=Synthetic Roots", tls_self=0, ev=ch["other_expired_then_valid"])
    # 23 同一小时跨过有效期边界（T0-24h = 2026-11-06T00:30Z）：00:10 有效、00:50 过期 → 必须按精确时刻重算
    a(T0 - 24 * H - 20 * 60, c[23], "connect", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_expired_then_valid"], subj="CN=other3.example,O=Other3",
      issuer="CN=Synthetic Test Root,O=Synthetic Roots", tls_self=0, ev=ch["other_expired_then_valid"])
    a(T0 - 24 * H + 20 * 60, c[23], "connect", "judge_tls", MITM, tls_class=MITM, de="invalid_1", leaf_=leaf["other_expired_then_valid"], subj="CN=other3.example,O=Other3",
      issuer="CN=Synthetic Test Root,O=Synthetic Roots", tls_self=0, ev=ch["other_expired_then_valid"])
    # 23 恰好在 NotAfter 那一刻（T0-24h）：Go 的 isValid 是 NotBefore ≤ 时刻 ≤ NotAfter，这一刻仍有效 → 被送到别的网站
    a(T0 - 24 * H, c[23], "connect", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_expired_then_valid"], subj="CN=other3.example,O=Other3",
      issuer="CN=Synthetic Test Root,O=Synthetic Roots", tls_self=0, ev=ch["other_expired_then_valid"])
    # 8 去向不明：只发了叶子
    a(T0, c[8], "socks5", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_leaf_only"], subj="CN=other4.example,O=Other4",
      issuer="CN=Synthetic Test Intermediate,O=Synthetic Roots", tls_self=0, ev=ch["other_leaf_only"])
    # 9 去向不明：没有 SAN 只有 CN、自签
    a(T0, c[9], "socks5", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_no_san"], subj="CN=other5.example,O=Other5",
      issuer="CN=other5.example,O=Other5", tls_self=1, ev=ch["other_no_san"])
    # 10 证据未存（ev 为空）：CN 不是 judge
    a(T0, c[10], "socks5", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_="a" * 64, subj="CN=other6.example,O=Other6", issuer="CN=Some CA,O=Some CA Inc", tls_self=0)
    # 11 冒充 judge（detail）但证据库超限没存
    a(T0, c[11], "connect", "judge_tls", MITM, tls_class=MITM, de="unknown_authority", leaf_="b" * 64, subj=JS, issuer=JS, tls_self=1, ev="f" * 64)
    # 12 证据未存：CN 是 judge、detail=invalid_1（名字像 judge 但判不了链）
    a(T0, c[12], "socks5", "judge_tls", MITM, tls_class=MITM, de="invalid_1", leaf_="d" * 64, subj="CN=%s,O=Whoever" % SELFTEST_HOST, issuer="CN=X,O=Y", tls_self=0, ev="e" * 64)
    # 13 证据存了但解析不了（junk）
    a(T0, c[13], "socks5", "judge_tls", MITM, tls_class=MITM, de="hostname_mismatch", leaf_="1" * 64, subj="CN=other7.example", issuer="CN=other7.example", tls_self=1, ev=ch["junk"])
    # 14 detail=other，没有 subj，ev 为空
    a(T0, c[14], "socks5", "judge_tls", MITM, tls_class=MITM, de="other", leaf_="2" * 64)
    # 15 同一张叶子（judge_selfsigned）出现在另一个 /24 的候选上
    a(T0 + H, d[1], "socks5", "judge_tls", MITM, tls_class=MITM, de="unknown_authority", leaf_=leaf["judge_selfsigned"], subj=JS, issuer=JS, tls_self=1, ev=ch["judge_selfsigned"])
    # 16 密集 /24 里的候选，同一张叶子
    a(T0, dense_c, "socks5", "judge_tls", MITM, tls_class=MITM, de="unknown_authority", leaf_=leaf["judge_selfsigned"], subj=JS, issuer=JS, tls_self=1, ev=ch["judge_selfsigned"])
    # 17 tls_pin_mismatch
    a(T0, c[17], "connect", "judge_tls", "tls_pin_mismatch", tls_class="tls_pin_mismatch", de="certificate chain is valid but ...", leaf_="p" * 64, subj="CN=x", issuer="CN=y", tls_self=0)
    # 18 tlsproxy 的 tls_cert_invalid：不算中间人
    a(T0, c[18], "tlsproxy", "self", MITM, hs_ok=None, tls_class=MITM, de="hostname_mismatch", leaf_="3" * 64, subj="CN=proxy", issuer="CN=proxy", tls_self=1, ev="4" * 64)
    # 节点：去向不明
    a(T0, "0123456789ab", "node", "judge_tls", MITM, hs_ok=None, tls_class=MITM, de="hostname_mismatch", leaf_=leaf["other_selfsigned"], subj="CN=other2.example,O=Other2",
      issuer="CN=other2.example,O=Other2", tls_self=1, ev=ch["other_selfsigned"], kind="node", arm="strict")
    # 对照组：通过
    a(T0, "control:loopback", "direct", "judge_tls", "ok", hs_ok=None, tls_ok=1, leaf_=JUDGE_LEAF, kind="control")
    # canceled：没有发起连接
    a(T0, c[19], "socks5", "judge_tls", "canceled", tcp=None, hs_ok=None)
    # 试运行（正式起点之前）：不算
    a(T0 - 76 * H, c[19], "socks5", "judge_tls", MITM, tls_class=MITM, de="unknown_authority", leaf_=leaf["judge_selfsigned"], subj=JS, issuer=JS, tls_self=1, ev=ch["judge_selfsigned"])
    # 可用的隧道：c20、c21（c21 两次），c4 也有一次 ok
    a(T0, c[20], "socks5", "judge_tls", "ok", tls_ok=1, leaf_=JUDGE_LEAF)
    a(T0, c[21], "connect", "judge_tls", "ok", tls_ok=1, leaf_=JUDGE_LEAF)
    a(T0 + H, c[21], "connect", "judge_tls", "ok", tls_ok=1, leaf_=JUDGE_LEAF)
    a(T0 + 2 * H, c[4], "socks5", "judge_tls", "ok", tls_ok=1, leaf_=JUDGE_LEAF)
    # 握手失败：没到 TLS 阶段
    a(T0, c[22], "socks5", "judge_tls", "hs_timeout", hs_ok=None, hs_class="hs_timeout")
    # 隧道里不是 TLS
    a(T0, c[24], "connect", "judge_tls", "tls_not_tls", tls_class="tls_not_tls", de="first record does not look like a TLS handshake")
    # 第二观察者目的地的 tls_cert_invalid：另计
    a(T0, c[25], "socks5", "obs:o1", MITM, tls_class=MITM, de="hostname_mismatch", leaf_="5" * 64, subj="CN=z", issuer="CN=z", tls_self=1)
    con.commit()
    con.close()


def _der_len(b):
    """开头那个 DER SEQUENCE 的总长度（含头），与 certcheck derLen 相同；解析不了返回 0。"""
    if len(b) < 2 or b[0] != 0x30:
        return 0
    n = b[1]
    if n < 0x80:
        return 2 + n
    k = n & 0x7F
    if k == 0 or k > 4 or len(b) < 2 + k:
        return 0
    return 2 + k + int.from_bytes(b[2:2 + k], "big")


def selftest():
    tmp = tempfile.mkdtemp(prefix="m_mitm_selftest_")
    prefix, cwd, how = resolve_certcheck(None)
    if prefix is None:
        print("自检需要 certcheck：" + how, file=sys.stderr)
        return 2
    gen_dir = os.path.join(tmp, "data")
    proc = subprocess.run(prefix + ["-gen", gen_dir, "-at", SELFTEST_T0, "-host", SELFTEST_HOST], capture_output=True, text=True, cwd=cwd)
    if proc.returncode != 0:
        print("certcheck -gen 失败：" + proc.stderr, file=sys.stderr)
        return 2
    gen = json.loads(proc.stdout.strip().splitlines()[-1])
    gen["dir"] = gen_dir
    # 同一张叶子、另一份证据文件：取 other_valid_chain 文件里的第一张证书（叶子），不带中间证书
    import hashlib
    with open(os.path.join(gen_dir, gen["chains"]["other_valid_chain"]["path"]), "rb") as f:
        full = f.read()
    leaf_der = full[:_der_len(full)]
    h = hashlib.sha256(leaf_der).hexdigest()
    rel = os.path.join("evidence", h[:2], h + ".der")
    os.makedirs(os.path.join(gen_dir, "evidence", h[:2]), exist_ok=True)
    with open(os.path.join(gen_dir, rel), "wb") as f:
        f.write(leaf_der)
    gen["chains"]["other_valid_leaf_only"] = {"hash": h, "leaf": gen["chains"]["other_valid_chain"]["leaf"], "path": rel,
                                             "meaning": "other_valid_chain 的叶子单独一份（没发中间证书）"}
    db_path = os.path.join(tmp, "synthetic.sqlite")
    _synthetic_db(db_path, gen)
    # 组织名门槛：合成数据只有几个 IP，主流程里关掉门槛核对计数本身；门槛的取舍在下面单独核对
    global ORG_MIN_IPS
    ORG_MIN_IPS = 1
    res = run(db_path, os.path.join(tmp, "out"), roots=gen["roots"], markdown=False, write=True)
    failures = []
    n_asserts = [0]

    def expect(name, got, want):
        n_asserts[0] += 1
        if got != want:
            failures.append("%s: 得到 %r，期望 %r" % (name, got, want))

    # RFC 2253：多值 RDN 和转义
    expect("dn_parts 多值 RDN", dn_parts("CN=judge.example+OU=x,O=y"), [("CN", "judge.example"), ("OU", "x"), ("O", "y")])
    expect("dn_parts 转义的 + 和 ,", dn_parts("CN=a\\+b\\,c,O=d"), [("CN", "a+b,c"), ("O", "d")])
    expect("多值 RDN 里的 CN 判为 judge", name_matches(dn_get("CN=%s+OU=x,O=y" % SELFTEST_HOST, "CN")[0], [SELFTEST_HOST], []), True)

    w = res["window"]
    expect("正式起点", w["formal_start_utc"], "2026-11-04T00:30Z")
    expect("72 小时终点", w["formal_end_72h_utc"], "2026-11-07T00:30Z")
    expect("默认不截断", w["formal_end_applied_utc"], None)
    expect("中断次数", len(w["interruptions"]), 1)
    expect("中断分钟", w["interruption_minutes_total"], 10.0)
    expect("中断种类", w["interruptions_by_kind"], {"stop": 1, "crash": 0})
    n = res["n"]
    # 隧道协议→judge_tls 的代理尝试（非 canceled、正式起点后）：
    # 中间人 21（1,2,3,4×3,5,6,7,23×3,8,9,10,11,12,13,14,15,16）+ pin 1 + ok 4 + hs_timeout 1 + tls_not_tls 1 = 28
    expect("尝试总数", n["尝试（socks5/socks4/connect→judge_tls，非 canceled）"], 28)
    expect("中间人尝试", n["尝试：中间人（tls_cert_invalid）"], 21)
    expect("到达 TLS 阶段", n["尝试：到达 TLS 阶段（tls_ok=1 或 tls_class 非空）"], 27)
    expect("pin 尝试", n["尝试：tls_pin_mismatch"], 1)
    expect("中间人候选", n["候选：遇到过中间人"], 17)
    expect("隧道建立过的候选", n["候选：隧道建立过（hs_ok=1 过）"], 17 + 1 + 2 + 1)   # 中间人 17 + pin c17 + ok c20 c21 + tls_not_tls c24（c4 已在中间人里）
    expect("曾可用的候选", n["候选：隧道曾可用（class='ok' 过）"], 3)
    expect("曾可用或中间人", n["候选：隧道曾可用或遇到过中间人"], 19)
    expect("叶子等于 judge（应 0）", n["仪器检查：中间人尝试里叶子等于 judge 自己证书的（应为 0）"], 0)
    L = res["layers"]["all"]["layers"]
    expect("冒充 judge 尝试", L[L_JUDGE]["尝试"]["num"], 6)
    expect("被送到别的网站 尝试（c4×2、c7、c23 早和恰在 NotAfter）", L[L_OTHER]["尝试"]["num"], 5)
    expect("去向不明 尝试（c4 只发叶子、c5、c6、c23 晚、c8、c9）", L[L_UNKNOWN]["尝试"]["num"], 6)
    expect("证据未存 尝试", L[L_NOEV]["尝试"]["num"], 4)
    expect("未校验 尝试", L[L_UNCHECKED]["尝试"]["num"], 0)
    expect("冒充 judge 候选", L[L_JUDGE]["候选（不互斥）"]["num"], 6)
    expect("别的网站 候选", L[L_OTHER]["候选（不互斥）"]["num"], 3)
    expect("去向不明 候选", L[L_UNKNOWN]["候选（不互斥）"]["num"], 6)
    expect("去向不明 最严重（c4、c23 归这里）", L[L_UNKNOWN]["候选（最严重一层）"]["num"], 6)
    expect("别的网站 最严重（只剩 c7）", L[L_OTHER]["候选（最严重一层）"]["num"], 1)
    expect("冒充 judge 其中证据未存", res["layers"]["all"]["冒充 judge 其中证据未存（只靠 detail=unknown_authority 判定）"]["num"], 1)
    expect("冒充 judge 按判据", res["layers"]["all"]["冒充 judge 按判据"], {"detail": 4, "leaf_san": 2})
    Ld = res["layers"]["excluding_dense"]["layers"]
    expect("去密集后冒充 judge 尝试", Ld[L_JUDGE]["尝试"]["num"], 5)
    expect("去密集后中间人候选", res["layers"]["excluding_dense"]["中间人候选"], 16)
    expect("密集 /24 个数", res["dense_prefixes"]["count"], 1)
    vc = res["layers"]["verify_classes"]["按层 × 校验错误类别"]
    expect("去向不明 self_signed", vc[L_UNKNOWN]["self_signed"]["尝试"], 2)
    expect("去向不明 expired", vc[L_UNKNOWN]["expired"]["尝试"], 2)
    expect("去向不明 leaf_only", vc[L_UNKNOWN]["unknown_authority_leaf_only"]["尝试"], 2)
    expect("别的网站 ok", vc[L_OTHER]["ok"]["尝试"], 5)
    expect("冒充 judge 的校验类别", sorted(vc[L_JUDGE].keys()), ["expired", "self_signed"])
    ne = res["layers"]["no_evidence"]["按原因 × 名字"]
    expect("未存：ev 空 CN 非 judge", ne["探测器没拿到证书链"]["CN 不是 judge 主机名"]["尝试"], 1)
    expect("未存：ev 空 无 subj", ne["探测器没拿到证书链"]["没有 subj"]["尝试"], 1)
    expect("未存：超限 CN 是 judge", ne["证据库超限没存"]["CN 是 judge 主机名"]["尝试"], 1)
    expect("未存：超限 detail", ne["证据库超限没存"]["detail=unknown_authority（已归入冒充 judge）"]["尝试"], 1)
    expect("未存：解析不了", res["layers"]["no_evidence"]["存下了但读不了或解析不了"]["尝试"], 1)
    cc = res["certcheck"]
    # 第一遍：每个文件 tmin 一次，tmin<tmax 的再加 tmax 一次。judge_selfsigned、other_valid_chain、other_expired_then_valid 三个文件各两次，
    # 其余 7 个（judge_expired、wildcard_expired、other_selfsigned、other_leaf_only、other_no_san、junk、other_valid_leaf_only）各一次 = 13
    expect("certcheck 第一遍校验次数", cc["jobs_first_pass"], 13)
    # other_expired_then_valid 的 NotAfter（T0-24h）落在它的 [T0-36h, T0] 内：按 5 个不同时刻逐一重算
    expect("certcheck 重算文件", cc["refined_files"], 1)
    expect("certcheck 重算次数", cc["refined_jobs"], 5)
    expect("certcheck parse_errors", cc["parse_errors"], 1)
    expect("certcheck 文件数（含解析不了的 junk）", cc["stored_files"], 10)
    expect("根证书只给文件名", cc["roots"]["file"], "roots.pem")
    expect("根证书不给目录", gen_dir in json.dumps(cc, ensure_ascii=False), False)
    lv = res["leaves"]
    expect("组织名门槛：出现在够多 IP 上的照列", orgs_text('["Big Org", "Tiny Org"]', {"Big Org": 7, "Tiny Org": 1}, 5),
           "Big Org / " + ORG_HIDDEN % 5)
    expect("组织名门槛：都不够时只写一次", orgs_text('["A", "B"]', {"A": 1, "B": 2}, 5), ORG_HIDDEN % 5)
    expect("组织名门槛：不给计数时照列", orgs_text('["A"]'), "A")
    expect("不同叶子", lv["不同叶子证书"], 13)   # 8 张合成（junk 的叶子是 '1'*64）+ 10,11,12,14 的 4 张假哈希 = 不同 tls_leaf 数
    top = lv["前 %d 张（按候选数、尝试数）" % TOP_LEAVES]
    # 排序：候选数、尝试数、/24 数。other_expired_then_valid（3 候选 5 尝试）排在 judge_selfsigned（3 候选 3 尝试）前面
    expect("第一张叶子候选数", top[0]["候选"], 3)
    expect("第一张叶子尝试数", top[0]["尝试"], 5)
    expect("第一张叶子随时刻不同", top[0]["公共根校验"], "随时刻不同（跨过有效期边界）")
    expect("第一张叶子链顶公共根", top[0]["链顶公共根（组织）"], "Synthetic Roots")
    expect("第一张叶子不同 IP", top[0]["不同 IP"], 3)
    mitm_leaf = [r for r in top if r["主题组织（O）"] == "Synthetic MITM" and r["候选"] == 3]
    expect("judge_selfsigned 这张叶子只有一行", len(mitm_leaf), 1)
    if mitm_leaf:
        expect("judge_selfsigned /24 数", mitm_leaf[0]["不同 /24"], 3)
        expect("judge_selfsigned 名字是 judge", mitm_leaf[0]["名字是 judge 的"], True)
        expect("judge_selfsigned 自签", mitm_leaf[0]["自签"], True)
        expect("judge_selfsigned 校验不过", mitm_leaf[0]["公共根校验"], "校验不过")
        expect("judge_selfsigned 按层", mitm_leaf[0]["按层（尝试）"], {L_JUDGE: 3})
    other_leaf = [r for r in top if r["主题组织（O）"] == "Other Site Ltd"]
    expect("other_valid_chain 这张叶子只有一行", len(other_leaf), 1)
    if other_leaf:
        expect("同一叶子两份证据：随所发的链不同", other_leaf[0]["公共根校验"], "随所发的链不同")
        expect("同一叶子两份证据：文件数", other_leaf[0]["不同证书链文件（已存）"], 2)
    noev_leaf = [r for r in top if r["主题组织（O）"] == "Other6"]
    expect("证据未存的叶子", [r["公共根校验"] for r in noev_leaf], ["证据未存"])
    junk_leaf = [r for r in top if r["签发者组织（O）"] is None and r["证书链已存"] and r["文件里的证书数"] == 0]
    expect("解析不了的叶子", [r["公共根校验"] for r in junk_leaf], ["证据解析不了"])
    expect("≥2 候选的叶子", lv["出现在 ≥2 个候选上的"], 2)   # judge_selfsigned（3）、other_expired_then_valid（3）
    expect("≥2 IP 的叶子", lv["出现在 ≥2 个不同 IP 上的"], 2)
    px = res["prefixes"]["前 %d 个（按中间人候选数）" % TOP_PREFIXES]
    expect("第一个 /24", px[0]["prefix24"], "198.51.100.0/24")
    expect("第一个 /24 中间人候选", px[0]["中间人候选"], 15)
    expect("第一个 /24 中间人候选的不同 IP", px[0]["中间人候选的不同 IP"], 15)
    expect("第一个 /24 状态文件候选", px[0]["状态文件里的候选"], 29)
    expect("密集 /24 标记", [p["候选密集"] for p in px if p["prefix24"] == "198.18.0.0/24"], [True])
    expect("节点中间人", res["nodes"]["中间人尝试"], 1)
    expect("节点层", res["nodes"]["按层"][L_UNKNOWN]["尝试"], 1)
    expect("pin 候选", res["total"]["tls_pin_mismatch"]["候选"], 1)
    expect("观察者另计", res["checks"]["第二观察者目的地的 tls_cert_invalid（不在主口径里）"]["尝试"], 1)
    expect("tlsproxy 排除", res["checks"]["tlsproxy 的 tls_cert_invalid（对代理端口按 IP 校验，几乎必然失败，不算中间人）"], 1)
    expect("对照组 0", res["checks"]["对照组的 tls_cert_invalid 尝试（应为 0）"], 0)
    # 原定义总数：代理→judge_tls 21 + 第二观察者 1 + 节点 1 = 23；候选 17 + c25 + 节点 = 19
    ot = res["total"]["原定义总数"]
    expect("原定义总数 尝试", ot["尝试"], 23)
    expect("原定义总数 候选", ot["候选（代理按 ip:port，节点按节点标识）"], 19)
    expect("原定义总数 拆分相加", sum(v["尝试"] for v in ot["按种类与目的地"].values()), 23)
    expect("原定义总数 节点", ot["按种类与目的地"]["节点"]["尝试"], 1)
    # socks5：1、4×3、6、7、8、9、10、12、13、14、15、16 = 14；connect：2、5、11、23×3 = 6；socks4：3 = 1
    expect("按协议 socks5 中间人", res["total"]["中间人"]["按协议"]["socks5"]["中间人尝试"]["num"], 14)
    expect("按协议 connect 中间人", res["total"]["中间人"]["按协议"]["connect"]["中间人尝试"]["num"], 6)
    expect("按协议 socks4 中间人", res["total"]["中间人"]["按协议"]["socks4"]["中间人尝试"]["num"], 1)
    expect("小时数", len(res["hourly"]), 5)  # T0-76h 在起点前；T0-36h、T0-24h、T0、T0+1h、T0+2h
    expect("每小时中间人相加", sum(h["中间人尝试"] for h in res["hourly"]), 21)
    # 与 summary.json 对账的口径（不裁起点）：从 tx 过滤，含试运行那一次和节点、观察者 → 23 + 1 = 24
    got = DB(db_path).scalar("""SELECT COUNT(*) FROM att WHERE tls_class = 'tls_cert_invalid' AND proto != 'tlsproxy'
                                AND COALESCE(cand_kind, '') != 'control' AND (class IS NULL OR class NOT LIKE '%canceled%')""")
    expect("tx 与直接查 att 一致（summary 口径）", got, 24)
    text = json.dumps(res, ensure_ascii=False)
    expect("输出不含 judge 主机名", SELFTEST_HOST in text, False)
    expect("输出不含 judge IP", SELFTEST_IP in text, False)
    expect("输出不含 ip:port", bool(HOSTPORT_RE.search(text)), False)
    expect("输出不含本机目录", tmp in text, False)

    # 分批：每批 3 次校验，结果必须与默认一致
    res_b = run(db_path, os.path.join(tmp, "out_b"), roots=gen["roots"], markdown=False, write=False, batch_size=3)
    expect("分批：各层一致", res_b["layers"]["all"], res["layers"]["all"])
    expect("分批：校验类别一致", res_b["layers"]["verify_classes"], res["layers"]["verify_classes"])
    expect("分批：叶子汇总一致", res_b["leaves"], res["leaves"])
    expect("分批：校验次数一致", (res_b["certcheck"]["jobs_first_pass"], res_b["certcheck"]["refined_jobs"]), (13, 5))
    expect("分批：调用次数", res_b["certcheck"]["certcheck_calls"], 5 + 2)   # 第一遍 13 次按文件凑批（每批 ≤3）= 5 批；重算 5 次 = 2 批

    # 截断到 72 小时：[T0-72h, T0)，只剩 c7（T0-36h）和 c23 的三次
    res_c = run(db_path, os.path.join(tmp, "out_c"), roots=gen["roots"], markdown=False, write=False, formal_end="72h")
    expect("截断：终点", res_c["window"]["formal_end_applied_utc"], "2026-11-07T00:30Z")
    expect("截断：中间人尝试", res_c["n"]["尝试：中间人（tls_cert_invalid）"], 4)
    expect("截断：别的网站", res_c["layers"]["all"]["layers"][L_OTHER]["尝试"]["num"], 3)
    expect("截断：去向不明", res_c["layers"]["all"]["layers"][L_UNKNOWN]["尝试"]["num"], 1)
    expect("截断：72 小时后的中间人（原定义）", res_c["window"]["after_72h"]["其中中间人尝试（原定义，代理+节点+全部目的地）"], 19)

    # 没有数据目录时：全部存下的尝试归“未校验”
    res2 = run(db_path, os.path.join(tmp, "out2"), data_dir=os.path.join(tmp, "nonexistent"), roots=gen["roots"], markdown=False, write=False)
    # 存下的（evidence 表里有的，含 junk）17 次里，detail=unknown_authority 的 3 次（1、15、16）仍按判据归冒充 judge，其余 14 次未校验
    expect("无数据目录：未校验", res2["layers"]["all"]["layers"][L_UNCHECKED]["尝试"]["num"], 14)
    expect("无数据目录：冒充 judge 仍按 detail", res2["layers"]["all"]["layers"][L_JUDGE]["尝试"]["num"], 4)
    expect("无数据目录：verified", res2["certcheck"]["verified"], False)
    # --data 指向上层目录（里面是 fieldtest/）：自动进入 fieldtest/，与 ingest.py 相同
    parent = os.path.join(tmp, "parent")
    os.makedirs(parent)
    os.symlink(gen_dir, os.path.join(parent, "fieldtest"))
    res3 = run(db_path, os.path.join(tmp, "out3"), data_dir=parent, roots=gen["roots"], markdown=False, write=False)
    expect("上层目录：自动进入 fieldtest/", res3["layers"]["all"], res["layers"]["all"])
    expect("上层目录：说明", bool(res3["certcheck"]["evidence_dir_note"]), True)
    # Markdown 打印不抛异常；未校验时第一行标出
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_markdown(res)
    expect("Markdown 有表格", "| 层 |" in buf.getvalue(), True)
    expect("Markdown 不含 judge 主机名", SELFTEST_HOST in buf.getvalue(), False)
    expect("Markdown 校验过时不标未校验", buf.getvalue().startswith("> **证书链未校验**"), False)
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        print_markdown(res2)
    expect("Markdown 未校验时第一行标出", buf2.getvalue().startswith("> **证书链未校验**"), True)
    # 断言：--guard 给的字符串出现在输出里就拒绝写出
    try:
        assert_clean(json.dumps({"x": "Synthetic MITM"}, ensure_ascii=False), DB(db_path), ["synthetic mitm"])
        expect("--guard 生效", "没拦住", "拦住")
    except SystemExit:
        expect("--guard 生效", "拦住", "拦住")

    print("自检：%d 条断言，%d 条失败；合成库和输出在 %s" % (n_asserts[0], len(failures), tmp))
    for f in failures:
        print("  失败 " + f)
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description="“中间人”的细分（PROTOCOL 1.2“指标定义”表“中间人”行、“‘中间人’的细分”一节）")
    ap.add_argument("--db", help="ingest.py 建的 SQLite 库（只读）")
    ap.add_argument("--out", help="输出目录，写 %s" % OUTPUT_NAME)
    ap.add_argument("--data", help="数据目录（含 evidence/；指向解包后的上层目录时自动进入 fieldtest/）；默认取库里 meta.data_dir")
    ap.add_argument("--roots", default=DEFAULT_ROOTS, help="公共根证书 PEM，默认 %s；输出里只写文件名" % DEFAULT_ROOTS)
    ap.add_argument("--roots-note", help="根证书库的说明（例如“Mozilla 根库 2.90，ca-certificates 20260816ubuntu0.24.04.1”），原样写进输出；"
                                         "读不到包 changelog 时用它写明 Mozilla 根库的版本")
    ap.add_argument("--certcheck", help="certcheck 二进制的路径，或 'go'（在 certcheck/ 下 go build 一次）；默认先找已编译的 certcheck/certcheck，再试 go build")
    ap.add_argument("--certcheck-batch", type=int, default=CERTCHECK_BATCH, help="每次调用 certcheck 的校验次数上限（至少 2），默认 %d" % CERTCHECK_BATCH)
    ap.add_argument("--formal-end", default="none", help="none（默认，不截断，与其他模块一致）/ 72h（[正式起点, 正式起点 + 72 小时)）/ 带时区的 ISO 时间")
    ap.add_argument("--guard", action="append", default=[], help="另外不许出现在输出里的字符串（可重复；不写进源码的保险，例如 judge 的主机名）")
    ap.add_argument("--summary", help="fieldtest 自带的 summary.json，给了就与 findings 对账")
    ap.add_argument("--markdown", action="store_true", help="把主要表格以 Markdown 打印到标准输出")
    ap.add_argument("--formal-start", default="auto", help="auto（按 PROTOCOL 规则）/ first（第一条 start）/ 带时区的 ISO 时间")
    ap.add_argument("--dense-threshold", type=int, default=DENSE_THRESHOLD, help="“候选密集的 /24”的阈值，默认 100")
    ap.add_argument("--top-leaves", type=int, default=TOP_LEAVES, help="按叶子证书汇总时列出的前几张，默认 20")
    ap.add_argument("--top-prefixes", type=int, default=TOP_PREFIXES, help="中间人候选按 /24 列出的前几个，默认 20")
    ap.add_argument("--selftest", action="store_true", help="用 certcheck -gen 的合成证书和合成库核对预期值")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.db or not args.out:
        ap.error("需要 --db 和 --out")
    run(args.db, args.out, data_dir=args.data, roots=args.roots, certcheck_arg=args.certcheck, summary_path=args.summary,
        formal_start=args.formal_start, dense_threshold=args.dense_threshold, top_leaves=args.top_leaves, top_prefixes=args.top_prefixes,
        markdown=args.markdown, formal_end=args.formal_end, batch_size=args.certcheck_batch, roots_note=args.roots_note, guards=args.guard)


if __name__ == "__main__":
    main()
