#!/usr/bin/env python3
"""把普查结果整理成报告里用到的数字和 Markdown 表格，避免手抄出错。

用法：python3 report_tables.py
"""
import json
import pathlib

OUT = pathlib.Path(__file__).parent / "out"


def fmt(v, suffix=""):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:,.1f}{suffix}"
    return f"{v:,}{suffix}"


def interval(mins):
    if mins is None:
        return "—"
    if mins < 90:
        return f"{mins:.0f} 分钟"
    return f"{mins / 60:.1f} 小时"


def main():
    d = json.loads((OUT / "census_summary.json").read_text(encoding="utf-8"))
    by = {s["name"]: s for s in d["sources"]}
    core = sorted(d["core_sources"], key=lambda n: -by[n]["latest_size"])
    agg = sorted(d["aggregators"], key=lambda n: by[n]["latest_size"])

    print("### 常规列表\n")
    print("| 来源 | 最新条目 | 实测更新间隔 | 每次更新换掉 | 30 天内出现过 | 离榜后又回来 | 独占条目 | 被哪个常规列表包含得最多 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for n in core:
        s = by[n]
        if s["has_history"]:
            cells = [interval(s.get("median_interval_min")), fmt(s.get("median_turnover_pct"), "%"),
                     fmt(s.get("union_size")), fmt(s.get("relist_pct_of_exited"), "%")]
        else:
            note = "列表文件 30 天未变" if s["repo_commits_in_clone"] > 10 else "无历史"
            cells = [note, "—", "—", "—"]
        ov = d["overlap_pct_row_in_col"][n]
        best = max((ov[b], b) for b in core if b != n and ov[b] is not None)
        partner = f"{best[1].split('/')[0]} {fmt(best[0], '%')}"
        print(f"| {n} | {fmt(s['latest_size'])} | " + " | ".join(cells)
              + f" | {fmt(s.get('exclusive_vs_core'))}（{fmt(s.get('exclusive_vs_core_pct'), '%')}） | {partner} |")

    print("\n### 聚合器\n")
    print("| 来源 | 最新条目 | 其中 Cloudflare 的 IP | 独占条目（对全部 18 个来源） |")
    print("| --- | --- | --- | --- |")
    for n in agg:
        s = by[n]
        print(f"| {n} | {fmt(s['latest_size'])} | {fmt(s['cloudflare_ip_share_pct'], '%')} | "
              f"{fmt(s['exclusive_latest'])}（{fmt(s['exclusive_latest_pct'], '%')}） |")

    p = d["pool"]
    print("\n### 汇总数字\n")
    print(f"- 常规列表 {len(core)} 个：各列表条目数相加 {p['sum_of_list_sizes_core']:,}，去重后 {p['unique_entries_core']:,}"
          f"（{100 * p['unique_entries_core'] / p['sum_of_list_sizes_core']:.1f}%）；"
          f"其中 {p['core_entries_in_2plus_sources']:,} 条"
          f"（{100 * p['core_entries_in_2plus_sources'] / p['unique_entries_core']:.1f}%）至少出现在两个列表里")
    print(f"- 全部 18 个来源：相加 {p['sum_of_list_sizes_all']:,}，去重后 {p['unique_entries_all']:,}")
    pl = d["protocol_label"]
    print(f"- 协议标签：{pl['entries_in_2plus_core_sources']:,} 条多源条目里 {pl['label_disagree']:,} 条"
          f"（{pl['disagree_pct']}%）被不同来源标成不同协议族")
    for key, label in (("core_union", "常规列表并集"), ("all_union", "全部来源并集")):
        nw = d["network"][key]
        print(f"- {label}：{nw['entries']:,} 条，{nw['distinct_ips']:,} 个 IP，{nw['distinct_asn']:,} 个自治系统，"
              f"前 10 个自治系统占 {nw['top10_asn_share_pct']}% 的 IP，Cloudflare 占 {nw['cloudflare_ip_share_pct']}%；"
              f"前五国家 " + "、".join(f"{c['cc']} {c['share_pct']}%" for c in nw["top_countries"][:5]))

    print("\n### 声称的更新频率与 git 实测\n")
    for n in ("proxifly/free-proxy-list", "Zaeem20/FREE_PROXIES_LIST", "iplocate/free-proxy-list",
              "TheSpeedX/PROXY-List", "roosterkid/openproxylist", "zloi-user/hideip.me", "hookzof/socks5_list",
              "vakhov/fresh-proxy-list", "mmpx12/proxy-list", "officialputuid/KangProxy"):
        s = by[n]
        print(f"- {n}: 仓库提交 {s['repo_commits_in_clone']}，改动列表的提交 {s['list_commits']}，快照 {s['snapshots']}，"
              f"中位间隔 {interval(s.get('median_interval_min'))}，最长间隔 {fmt(s.get('max_gap_h'))} 小时，"
              f"规模 {fmt(s.get('min_size'))}–{fmt(s.get('max_size'))}")

    print("\n### 在榜时长（窗口内新到条目）\n")
    print("| 来源 | 新到条目/天 | 连续在榜中位数（小时） | 24 小时后仍连续在榜 | 首末跨度中位数（小时） | 7 天后仍会出现 |")
    print("| --- | --- | --- | --- | --- | --- |")
    for n in core + agg:
        s = by[n]
        if not s["has_history"]:
            continue
        km, sp = s["km_survival_pct"], s["span_survival_pct"]
        print(f"| {n} | {fmt(s['arrivals_per_day'])} | {fmt(s['km_median_h'])} | {fmt(km['24h'], '%')} | "
              f"{fmt(s['span_median_h'])} | {fmt(sp['168h'], '%')} |")

    print("\n### 数据质量（最新快照）\n")
    for n in core + agg:
        q = by[n]["quality_latest"]
        bad = {k: q.get(k, 0) for k in ("garbage", "hostname", "no_port", "duplicate", "bad_range", "with_credentials")}
        bad["non_global"] = by[n]["non_global_entries"]
        if any(bad.values()):
            print(f"- {n}: 行数 {q.get('lines', 0):,}；" + "，".join(f"{k}={v:,}" for k, v in bad.items() if v))

    print("\n### 先后关系（共同新到条目最多的几对）\n")
    for r in d["precedence"][:12]:
        print(f"- {r['a']} 对 {r['b']}: 共同新到 {r['shared_arrivals']:,}，前者先列出 {r['a_first_pct']}%，"
              f"后者先 {r['b_first_pct']}%，前者领先中位数 {r['median_lead_h_a_over_b']} 小时")

    nd = json.loads((OUT / "nodes_summary.json").read_text(encoding="utf-8"))
    np_ = nd["pool"]
    print("\n### 节点订阅\n")
    print(f"- 11 个订阅相加 {np_['sum_of_sizes']:,} 个节点，去重后 {np_['unique_nodes']:,}"
          f"（{100 * np_['unique_nodes'] / np_['sum_of_sizes']:.1f}%），{np_['unique_endpoints']:,} 个端点，"
          f"{np_['unique_hosts']:,} 个主机")
    tot = np_["unique_nodes"]
    print("- 协议构成：" + "、".join(f"{k} {v:,}（{100 * v / tot:.1f}%）" for k, v in list(np_["by_scheme"].items())[:6]))
    print(f"- TLS 类节点 {np_['tls_nodes']:,} 个，其中 {np_['tls_insecure_flag']:,} 个（{np_['tls_insecure_pct']}%）要求跳过证书校验")
    print(f"- IP 形式的主机 {np_['ip_literal_hosts']:,} 个，归属前几位："
          + "、".join(f"{a['name']} {a['share_pct']}%" for a in np_["top_asn_of_ip_hosts"][:5]))
    tr = nd["transport"]
    n3 = tr["nodes_vless_vmess_trojan"]
    print(f"- vless、vmess、trojan 共 {n3:,} 个节点的传输方式："
          + "、".join(f"{k} {v:,}（{100 * v / n3:.1f}%）" for k, v in list(tr["total"].items())[:6]))
    nis = tr["not_in_singbox"]
    print(f"- 其中 sing-box 没有的传输方式 {nis['nodes']:,} 个（占这三种协议的 {nis['pct_of_vless_vmess_trojan']}%，"
          f"占全部节点的 {nis['pct_of_all_nodes']}%）：" + "、".join(f"{k} {v:,}" for k, v in nis["by_transport"].items()))
    oor = tr["out_of_reach_for_singbox"]
    print(f"- vless 节点里 encryption 不是 none 的 {tr['vless_encryption_not_none']:,} 个，sing-box 同样连不了；"
          f"与传输方式合计，sing-box 够不着的节点 {oor['nodes']:,} 个（占这三种协议的 {oor['pct_of_vless_vmess_trojan']}%，"
          f"占全部节点的 {oor['pct_of_all_nodes']}%）")
    print(f"- 使用 REALITY 的节点 {tr['reality_nodes']:,} 个，使用 vision 流控的 {tr['vision_flow_nodes']:,} 个")
    print("\n| 订阅 | 去重后节点 | 独占 | TLS 类节点里要求跳过证书校验 |")
    print("| --- | --- | --- | --- |")
    for s in nd["sources"]:
        print(f"| {s['name']} | {s['unique_nodes']:,} | {fmt(s['exclusive_pct'], '%')} | {fmt(s['tls_insecure_pct'], '%')} |")


if __name__ == "__main__":
    main()
