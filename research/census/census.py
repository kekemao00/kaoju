#!/usr/bin/env python3
"""来源普查：从 GitHub 代理列表仓库的 git 历史重建条目时间线，并做跨源对比。

只用标准库。输入是按 sources.json 克隆好的仓库（见 fetch_history.sh）。

口径说明（重要）：
- “条目”指规范化后的 IPv4:端口。主机名、IPv6、缺端口的行不计入条目，单独计数；
  带账号密码的行取其 IPv4:端口，并另行计数。
- “在榜”只表示该条目出现在列表文件里，不等于代理可用。可用性要靠实测。
- 时间线只对保留了 git 历史的仓库有效；每次更新都重写历史的仓库只有最新快照。

用法：
  python3 census.py --hist-dir <克隆目录> --ipdb-dir <ASN/国家库目录> --out out/
"""
from __future__ import annotations

import argparse
import bisect
import collections
import csv
import ipaddress
import json
import pathlib
import re
import statistics
import subprocess
import sys
import time

LINE_RE = re.compile(
    r"^\s*(?:(?P<scheme>[a-zA-Z0-9+.-]+)://)?(?:(?P<cred>[^@/\s]+)@)?"
    r"(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(?P<port>\d{1,5})(?!\d))?(?P<rest>.*)$"
)
FAST_RE = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})")
HOSTNAME_RE = re.compile(r"^\s*(?:[a-zA-Z0-9+.-]+://)?(?:[^@/\s]+@)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}:\d{1,5}")

KM_HORIZONS_H = [1, 6, 24, 72, 168]


# ---------------------------------------------------------------- parsing

def parse_blob(text: str):
    """返回 (条目集合, 质量计数)。"""
    entries = set()
    q = collections.Counter()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        q["lines"] += 1
        fm = FAST_RE.fullmatch(line)
        if fm:
            a, b, c, d, p = (int(x) for x in fm.groups())
            if a > 255 or b > 255 or c > 255 or d > 255 or not (1 <= p <= 65535):
                q["bad_range"] += 1
                continue
            key = f"{a}.{b}.{c}.{d}:{p}"
            if key in entries:
                q["duplicate"] += 1
            else:
                entries.add(key)
            continue
        m = LINE_RE.match(line)
        if not m:
            if HOSTNAME_RE.match(line):
                q["hostname"] += 1
            else:
                q["garbage"] += 1
            continue
        if m.group("cred"):
            q["with_credentials"] += 1
        host, port = m.group("host"), m.group("port")
        if port is None:
            q["no_port"] += 1
            continue
        try:
            octets = [int(x) for x in host.split(".")]
            p = int(port)
        except ValueError:
            q["garbage"] += 1
            continue
        if any(o > 255 for o in octets) or not (1 <= p <= 65535):
            q["bad_range"] += 1
            continue
        key = f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}:{p}"
        if key in entries:
            q["duplicate"] += 1
            continue
        entries.add(key)
    return entries, q


def is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------- git access

class Repo:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.proc = subprocess.Popen(
            ["git", "-C", str(path), "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    def commits(self, paths):
        out = subprocess.run(
            ["git", "-C", str(self.path), "log", "--first-parent", "--reverse",
             "--format=%H %ct", "--", *paths],
            check=True, capture_output=True, text=True,
        ).stdout
        res = []
        for line in out.splitlines():
            h, ct = line.split()
            res.append((h, int(ct)))
        return res

    def total_commits(self):
        out = subprocess.run(["git", "-C", str(self.path), "rev-list", "--count", "HEAD"],
                             check=True, capture_output=True, text=True).stdout
        return int(out.strip())

    def blob(self, commit: str, path: str):
        self.proc.stdin.write(f"{commit}:{path}\n".encode())
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().decode()
        if header.rstrip().endswith("missing"):
            return None
        size = int(header.split()[2])
        data = self.proc.stdout.read(size)
        self.proc.stdout.read(1)  # trailing newline
        return data.decode("utf-8", errors="replace")

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


# ---------------------------------------------------------------- IP database

class RangeDB:
    def __init__(self, csv_path: pathlib.Path, value_cols):
        self.starts, self.ends, self.values = [], [], []
        with csv_path.open(newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                self.starts.append(int(ipaddress.IPv4Address(row[0])))
                self.ends.append(int(ipaddress.IPv4Address(row[1])))
                self.values.append(tuple(row[i] for i in value_cols))

    def lookup(self, ip: str):
        n = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and n <= self.ends[i]:
            return self.values[i]
        return None


# ---------------------------------------------------------------- statistics

def km_survival(durations, events, horizons_s):
    """Kaplan–Meier。durations 秒；events True=观察到离榜。返回 (中位数秒或 None, {时限: 生存率})。"""
    n = len(durations)
    if n == 0:
        return None, {h: None for h in horizons_s}
    order = sorted(range(n), key=lambda i: durations[i])
    at_risk = n
    s = 1.0
    curve = []  # (t, S(t)) 在事件时间点之后的值
    i = 0
    while i < n:
        t = durations[order[i]]
        d = c = 0
        while i < n and durations[order[i]] == t:
            if events[order[i]]:
                d += 1
            else:
                c += 1
            i += 1
        if d:
            s *= 1 - d / at_risk
            curve.append((t, s))
        at_risk -= d + c
    median = next((t for t, sv in curve if sv <= 0.5), None)

    def s_at(h):
        val = 1.0
        for t, sv in curve:
            if t <= h:
                val = sv
            else:
                break
        return val

    return median, {h: s_at(h) for h in horizons_s}


def pct(x):
    return None if x is None else round(100 * x, 1)


# ---------------------------------------------------------------- per-source

BURST_SECONDS = 120  # 同一轮更新里分多次提交的，合并成一次快照


def coalesce(commits):
    """保持 git 给出的拓扑顺序；时间戳取单调不减；相隔不超过 BURST_SECONDS 的提交只留最后一个。"""
    out = []
    t_mono = None
    for h, ct in commits:
        t_mono = ct if t_mono is None else max(t_mono, ct)
        if out and t_mono - out[-1][1] <= BURST_SECONDS:
            out[-1] = (h, t_mono)
        else:
            out.append((h, t_mono))
    return out


def process_source(src, hist_dir: pathlib.Path, families):
    repo_path = hist_dir / src["dir"]
    repo = Repo(repo_path)
    paths = list(src["files"].values())
    raw_commits = repo.commits(paths)
    commits = coalesce(raw_commits)
    repo_commits = repo.total_commits()

    # entry -> [first_ts, first_run_end_ts|None, relist_count, last_seen_ts]
    state = {}
    prev = set()
    prev_t = None
    sizes, turnovers, times = [], [], []
    latest_by_proto = {}
    latest_quality = collections.Counter()
    cache = {}  # path -> (text, entries, quality)
    t_start = time.time()

    for commit, ct in commits:
        by_proto = {}
        quality = collections.Counter()
        for proto, path in src["files"].items():
            text = repo.blob(commit, path)
            if text is None:
                by_proto[proto] = set()
                continue
            hit = cache.get(path)
            if hit is not None and hit[0] == text:
                entries, q = hit[1], hit[2]
            else:
                entries, q = parse_blob(text)
                cache[path] = (text, entries, q)
            by_proto[proto] = entries
            quality.update(q)
        cur = set().union(*by_proto.values()) if by_proto else set()
        if not cur and prev:
            # 空快照（生成失败）：记为一次快照，但不把它当成全部离榜
            times.append(ct)
            sizes.append(0)
            continue
        new = cur - prev
        gone = prev - cur
        for e in new:
            st = state.get(e)
            if st is None:
                state[e] = [ct, None, 0, ct]
            else:
                st[2] += 1
        for e in gone:
            st = state[e]
            if st[1] is None:
                st[1] = ct
            st[3] = prev_t
        if prev_t is not None and cur:
            turnovers.append(len(new) / len(cur))
        times.append(ct)
        sizes.append(len(cur))
        prev, prev_t = cur, ct
        latest_by_proto, latest_quality = by_proto, quality
    repo.close()
    for e in prev:
        state[e][3] = prev_t

    n_snap = len(times)
    res = {
        "name": src["name"],
        "repo_commits_in_clone": repo_commits,
        "list_commits": len(raw_commits),
        "snapshots": n_snap,
        "first_ts": times[0] if times else None,
        "last_ts": times[-1] if times else None,
        "latest_size": len(prev),
        "latest_by_proto": {p: len(s) for p, s in latest_by_proto.items()},
        "quality_latest": dict(latest_quality),
        "has_history": n_snap >= 10,
        "elapsed_s": round(time.time() - t_start, 1),
    }
    latest_family = collections.defaultdict(set)
    for proto, s in latest_by_proto.items():
        latest_family[families[proto]] |= s

    if n_snap >= 2:
        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        res["median_interval_min"] = round(statistics.median(gaps) / 60, 1) if gaps else None
        res["max_gap_h"] = round(max(gaps) / 3600, 1) if gaps else None
        res["window_days"] = round((times[-1] - times[0]) / 86400, 1)
        nz = [s for s in sizes if s]
        res["median_size"] = int(statistics.median(nz)) if nz else 0
        res["min_size"], res["max_size"] = (min(nz), max(nz)) if nz else (0, 0)
        res["empty_snapshots"] = sizes.count(0)
        res["median_turnover_pct"] = pct(statistics.median(turnovers)) if turnovers else None
        res["union_size"] = len(state)

    if res["has_history"]:
        t0, t_end = times[0], times[-1]
        horizons = [h * 3600 for h in KM_HORIZONS_H]
        run_d, run_e, span_d, span_e = [], [], [], []
        relisted = exited = 0
        for e, (first, run_end, relist, last_seen) in state.items():
            if first <= t0:
                continue  # 左截断：窗口开始时已在榜，起点未知
            # 连续在榜：到首次缺席为止
            if run_end is None:
                run_d.append(t_end - first)
                run_e.append(False)
            else:
                run_d.append(run_end - first)
                run_e.append(True)
                exited += 1
                if relist:
                    relisted += 1
            # 首末跨度：到最后一次在榜为止（中间缺席不算离开）
            span_d.append(last_seen - first)
            span_e.append(last_seen < t_end)
        median, surv = km_survival(run_d, run_e, horizons)
        s_median, s_surv = km_survival(span_d, span_e, horizons)
        res["arrivals"] = len(run_d)
        res["arrivals_per_day"] = round(len(run_d) / max((t_end - t0) / 86400, 1e-9), 1)
        res["km_median_h"] = None if median is None else round(median / 3600, 1)
        res["km_survival_pct"] = {f"{h}h": pct(surv[h * 3600]) for h in KM_HORIZONS_H}
        res["span_median_h"] = None if s_median is None else round(s_median / 3600, 1)
        res["span_survival_pct"] = {f"{h}h": pct(s_surv[h * 3600]) for h in KM_HORIZONS_H}
        res["relist_pct_of_exited"] = pct(relisted / exited) if exited else None
        res["size_series"] = [[t, s] for t, s in zip(times, sizes)][:: max(1, n_snap // 120)]

    first_seen = {e: st[0] for e, st in state.items()} if res["has_history"] else {}
    return res, prev, dict(latest_family), first_seen, (times[0] if times else None)


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hist-dir", required=True, type=pathlib.Path)
    ap.add_argument("--ipdb-dir", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--config", default=pathlib.Path(__file__).with_name("sources.json"), type=pathlib.Path)
    args = ap.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    families = cfg["families"]
    args.out.mkdir(parents=True, exist_ok=True)

    summaries, latest, latest_family, first_seen, t0s = [], {}, {}, {}, {}
    for src in cfg["sources"]:
        print(f"[census] {src['name']} ...", file=sys.stderr, flush=True)
        res, cur, fam, fs, t0 = process_source(src, args.hist_dir, families)
        summaries.append(res)
        latest[src["name"]] = cur
        latest_family[src["name"]] = fam
        first_seen[src["name"]] = fs
        t0s[src["name"]] = t0
        print(f"         snapshots={res['snapshots']} latest={res['latest_size']} ({res['elapsed_s']}s)",
              file=sys.stderr, flush=True)
    names = [s["name"] for s in summaries]

    # ---- 质量：非全球可路由地址
    for s in summaries:
        cur = latest[s["name"]]
        s["non_global_entries"] = sum(1 for e in cur if not is_global(e.rsplit(":", 1)[0]))

    # ---- 跨源：包含度矩阵与独占条目（最新快照）
    counts = collections.Counter()
    for n in names:
        counts.update(latest[n])
    union_all = set(counts)
    overlap = {}
    for a in names:
        row = {}
        for b in names:
            if not latest[a]:
                row[b] = None
            else:
                row[b] = round(100 * len(latest[a] & latest[b]) / len(latest[a]), 1)
        overlap[a] = row
    for s in summaries:
        n = s["name"]
        partners = [(overlap[n][b], b) for b in names if b != n and overlap[n][b] is not None]
        if partners:
            best = max(partners)
            s["most_contained_in"], s["most_contained_pct"] = best[1], best[0]
        s["exclusive_latest"] = sum(1 for e in latest[n] if counts[e] == 1)
        s["exclusive_latest_pct"] = pct(s["exclusive_latest"] / len(latest[n])) if latest[n] else None

    # 聚合型来源：最新快照条目数 > 10 万，或包含了至少 3 个其他来源的 90% 以上
    mega = []
    for b in names:
        swallowed = sum(1 for a in names if a != b and latest[a] and len(latest[a]) >= 50
                        and len(latest[a] & latest[b]) / len(latest[a]) >= 0.9)
        if len(latest[b]) > 100_000 or swallowed >= 3:
            mega.append(b)
    core = [n for n in names if n not in mega]
    counts_core = collections.Counter()
    for n in core:
        counts_core.update(latest[n])
    for s in summaries:
        n = s["name"]
        s["is_aggregator"] = n in mega
        if n in core:
            s["exclusive_vs_core"] = sum(1 for e in latest[n] if counts_core[e] == 1)
            s["exclusive_vs_core_pct"] = pct(s["exclusive_vs_core"] / len(latest[n])) if latest[n] else None

    # ---- 协议标签不一致（同一 IP:端口在不同来源被标成不同协议族）
    fam_labels = collections.defaultdict(lambda: collections.defaultdict(set))
    for n in core:
        for fam, entries in latest_family[n].items():
            for e in entries:
                fam_labels[e][n].add(fam)
    multi = disagree = 0
    for e, by_src in fam_labels.items():
        if len(by_src) < 2:
            continue
        multi += 1
        label_sets = {frozenset(v) for v in by_src.values()}
        if len(label_sets) > 1:
            disagree += 1

    # ---- 先后关系：有历史的来源两两比较“谁先列出”
    hist_names = [s["name"] for s in summaries if s["has_history"]]
    precedence = []
    margin = 24 * 3600
    for i, a in enumerate(hist_names):
        for b in hist_names[i + 1:]:
            fa, fb = first_seen[a], first_seen[b]
            start = max(t0s[a], t0s[b]) + margin
            leads = []
            for e in fa.keys() & fb.keys():
                ta, tb = fa[e], fb[e]
                if ta >= start and tb >= start:
                    leads.append(tb - ta)  # 正数 = a 先
            if len(leads) >= 100:
                a_first = sum(1 for x in leads if x > 0)
                b_first = sum(1 for x in leads if x < 0)
                precedence.append({
                    "a": a, "b": b, "shared_arrivals": len(leads),
                    "a_first_pct": pct(a_first / len(leads)), "b_first_pct": pct(b_first / len(leads)),
                    "median_lead_h_a_over_b": round(statistics.median(leads) / 3600, 2),
                })
    precedence.sort(key=lambda r: -r["shared_arrivals"])

    # ---- 窗口内的独占到达（只在一个有历史的来源出现过，且不在任何来源的最新快照里出现第二次）
    seen_in = collections.Counter()
    for n in hist_names:
        seen_in.update(first_seen[n].keys())
    for n in names:
        if n not in hist_names:
            seen_in.update(latest[n])
    for s in summaries:
        n = s["name"]
        if s["has_history"]:
            arr = [e for e, t in first_seen[n].items() if t > t0s[n]]
            only = sum(1 for e in arr if seen_in[e] == 1)
            s["window_exclusive_arrivals_pct"] = pct(only / len(arr)) if arr else None

    # ---- 网络集中度
    asn_db = RangeDB(next(args.ipdb_dir.glob("**/asn-ipv4.csv")), (2, 3))
    cc_db = RangeDB(next(args.ipdb_dir.glob("**/geo-whois-asn-country-ipv4.csv")), (2,))

    def concentration(entries):
        ips = {e.rsplit(":", 1)[0] for e in entries}
        asn = collections.Counter()
        cc = collections.Counter()
        for ip in ips:
            a = asn_db.lookup(ip)
            asn[a if a else ("?", "未匹配")] += 1
            c = cc_db.lookup(ip)
            cc[c[0] if c else "?"] += 1
        total = len(ips) or 1
        # 次数相同的按名称排，保证每次运行的结果一样
        top_asn = sorted(asn.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        return {
            "entries": len(entries), "distinct_ips": len(ips),
            "distinct_slash24": len({ip.rsplit(".", 1)[0] for ip in ips}),
            "distinct_asn": len(asn),
            "top10_asn_share_pct": round(100 * sum(c for _, c in top_asn) / total, 1),
            "top_asn": [{"asn": a[0], "name": a[1], "ips": c, "share_pct": round(100 * c / total, 1)}
                        for a, c in top_asn],
            "top_countries": [{"cc": k, "ips": c, "share_pct": round(100 * c / total, 1)}
                              for k, c in sorted(cc.items(), key=lambda kv: (-kv[1], kv[0]))[:8]],
            "cloudflare_ip_share_pct": round(100 * asn.get(("13335", "Cloudflare, Inc."), 0) / total, 1),
        }

    union_core = set(counts_core)
    net = {"core_union": concentration(union_core), "all_union": concentration(union_all)}
    for s in summaries:
        c = concentration(latest[s["name"]])
        s["distinct_ips"] = c["distinct_ips"]
        s["distinct_asn"] = c["distinct_asn"]
        s["top10_asn_share_pct"] = c["top10_asn_share_pct"]
        s["cloudflare_ip_share_pct"] = c["cloudflare_ip_share_pct"]
        s["top_asn_name"] = c["top_asn"][0]["name"] if c["top_asn"] else None
        s["top_asn_share_pct"] = c["top_asn"][0]["share_pct"] if c["top_asn"] else None

    result = {
        "generated_at": int(time.time()),
        "config": {"window_since": cfg["window_since"], "snapshot_date": cfg["snapshot_date"]},
        "sources": summaries,
        "aggregators": mega,
        "core_sources": core,
        "pool": {
            "sum_of_list_sizes_all": sum(len(latest[n]) for n in names),
            "unique_entries_all": len(union_all),
            "sum_of_list_sizes_core": sum(len(latest[n]) for n in core),
            "unique_entries_core": len(union_core),
            "core_entries_in_2plus_sources": sum(1 for c in counts_core.values() if c >= 2),
        },
        "protocol_label": {"entries_in_2plus_core_sources": multi, "label_disagree": disagree,
                           "disagree_pct": pct(disagree / multi) if multi else None},
        "overlap_pct_row_in_col": overlap,
        "precedence": precedence[:40],
        "network": net,
    }
    (args.out / "census_summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")

    with (args.out / "overlap_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["row_contained_in_col_pct"] + names)
        for a in names:
            w.writerow([a] + [overlap[a][b] for b in names])

    cols = ["name", "is_aggregator", "has_history", "repo_commits_in_clone", "list_commits", "snapshots",
            "window_days", "median_interval_min", "max_gap_h",
            "latest_size", "median_size", "min_size", "max_size", "union_size", "median_turnover_pct",
            "arrivals_per_day", "km_median_h", "span_median_h", "relist_pct_of_exited", "exclusive_latest", "exclusive_latest_pct",
            "exclusive_vs_core", "exclusive_vs_core_pct", "window_exclusive_arrivals_pct",
            "distinct_ips", "distinct_asn", "top10_asn_share_pct", "cloudflare_ip_share_pct",
            "top_asn_name", "top_asn_share_pct", "non_global_entries", "empty_snapshots"]
    with (args.out / "sources_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols + [f"km_s_{h}h_pct" for h in KM_HORIZONS_H]
                   + [f"span_s_{h}h_pct" for h in KM_HORIZONS_H]
                   + ["q_lines", "q_garbage", "q_hostname", "q_no_port", "q_duplicate", "q_bad_range"])
        for s in summaries:
            km = s.get("km_survival_pct", {})
            sp = s.get("span_survival_pct", {})
            q = s.get("quality_latest", {})
            w.writerow([s.get(c) for c in cols] + [km.get(f"{h}h") for h in KM_HORIZONS_H]
                       + [sp.get(f"{h}h") for h in KM_HORIZONS_H]
                       + [q.get(k, 0) for k in ("lines", "garbage", "hostname", "no_port", "duplicate", "bad_range")])
    print(f"[census] wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
