#!/usr/bin/env python3
"""核对端到端测试的产物。用法：e2e_check.py <工作目录>

夹具的行为是已知的，所以汇总里应该出现什么也是已知的。
每个夹具逐次尝试的判定由仪器自检（internal/selftest）核对；
这里核对的是整条流程：快照、调度、重启续跑、judge 对账、汇总、打包。
"""
import json
import os
import re
import sys
import tarfile

w = sys.argv[1]
s = json.load(open(os.path.join(w, "data", "summary.json"), encoding="utf-8"))
ready = open(os.path.join(w, "fixtures.out"), encoding="utf-8").read()
n_fixtures = int(re.search(r"fixtures=(\d+)", ready).group(1))
n_nodes = int(re.search(r"nodes=(\d+)", ready).group(1))

bad = []


def check(ok, what):
    print(("  通过  " if ok else "  失败  ") + what)
    if not ok:
        bad.append(what)


print("端到端核对")
rec = s["records"]
check(rec.get("start") == 2 and rec.get("stop") == 2, "探测器启动两次，两次都正常收尾")
check(rec.get("agg_sample") == 1, "重启后沿用原来的聚合器抽样，没有重抽")

# 布景里的观察者主机名只有夹具认得，直连一定失败；除此之外不应有别的警告
other = [x for x in s.get("warnings") or [] if "直连第二观察者" not in x]
check(not other, "自动检查没有报布景以外的问题 %s" % other)

for name, c in s["control"].items():
    if "observer" in name:
        continue
    check(c["total"] > 0 and c["ok"] == c["total"], "对照 %s 全部成功（%d/%d）" % (name, c["ok"], c["total"]))

for row in s["snapshots"] + s["nodes"]["subscriptions"]:
    check(row["fetches"] > 0 and row["failed"] == 0, "来源 %s 抓取 %d 次，没有失败" % (row["src"], row["fetches"]))

reg, agg = s["funnel"]["regular"], s["funnel"]["aggregator_sample"]
check(reg["seen"] == n_fixtures, "常规列表的 %d 个夹具都探访过（%d）" % (n_fixtures, reg["seen"]))
check(20 <= reg["working"] < n_fixtures, "可用的夹具数在预期范围内（%d）" % reg["working"])
check(agg["seen"] == 25 and agg["working"] == 0, "聚合器抽样 25 个，都是没人监听的地址")
gone = s["pool"]["total"] - s["pool"]["listed"]
check(gone == 3, "中途撤掉的 3 个条目记成了下榜（%d）" % gone)

want = [
    "隧道里的证书不是 judge 的",
    "正文被局部改动",
    "正文被整页替换",
    "正文被截断",
    "正文正确但不是这次请求的应答",
    "同一请求被 judge 收到多次",
    "请求头被改动",
    "请求头里带出了探测器的地址",
    "出口地址与列表里的地址不同",
]
for k in want:
    hit = [f for f in s["findings"] if f.startswith(k)]
    check(bool(hit), "发现了“%s”" % k)

n = s["nodes"]
check(n["known"] == n_nodes, "节点只数一次，重启不重复计数（%d）" % n["known"])
check(n["unsupported"] == {"transport_xhttp": 1}, "xhttp 节点报告为 sing-box 连不了 %s" % n["unsupported"])
ok = n["ok"]
check(
    all("strict" in ok.get(k, {}) for k in ("ss", "vmess", "vless")),
    "ss、vmess、vless 节点通过严格校验 %s" % sorted(ok),
)
check(ok.get("trojan") == {"as_linked_only": 1}, "自签证书的 trojan 节点只在跳过校验时可用")

check(s["judge"]["req"] > 0, "judge 自己的日志里有请求记录（%d）" % s["judge"]["req"])
ev = os.listdir(os.path.join(w, "data", "evidence"))
check(len(ev) > 0, "证据目录里有被改动的正文或证书链（%d 项）" % len(ev))

names = tarfile.open(os.path.join(w, "pack.tar.gz")).getnames()
leak = [x for x in names if re.search(r"(^|/)(secret|judge-key\.pem|local)(/|$)", x)]
check(len(names) > 3 and not leak, "数据包里没有密钥、私钥和节点原始链接 %s" % leak)

if bad:
    print("结论：%d 项失败" % len(bad))
    sys.exit(1)
print("结论：全部通过")
