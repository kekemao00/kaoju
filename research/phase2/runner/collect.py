#!/usr/bin/env python3
"""把各列的运行记录汇总成两个进仓库的文件。

    collect.py [--out research/phase2/out]

- <out>/pcap_check.json：每列抓包核对的结论（PROTOCOL.md“抓包核对”一节说的那个文件）。
  数的是 <out>/raw/<列>.jsonl.gz 里每次运行的 pcap_check、tcpdump、driver、runner_errors 字段。
- <out>/versions.json：<out>/versions.d/<列>.json 合在一起。各列是分几次跑的，
  每列的版本信息（含那次运行的环境）各自存在 versions.d 里，这里只做合并，不改内容。

只用标准库。输出是确定的：同样的输入，逐字节相同。
"""

import argparse
import gzip
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def read_raw(path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def pcap_summary(recs):
    """一列的小结。status 之外的数都只数实际运行了的（没被 only 跳过的）。"""
    out = {
        "runs": 0, "skipped": 0,
        "status": {}, "tcpdump_dropped_runs": 0, "runner_error_runs": 0,
        "driver_timeout_runs": 0, "driver_nonzero_exit_runs": 0,
        "conns_compared": 0, "fields_compared": 0, "fields_mismatched": 0,
        "not_ok": [],
    }
    for rec in recs:
        if rec.get("skipped"):
            out["skipped"] += 1
            continue
        out["runs"] += 1
        pc = rec.get("pcap_check") or {}
        status = pc.get("status") or "none"
        out["status"][status] = out["status"].get(status, 0) + 1
        out["conns_compared"] += len(pc.get("conns") or [])
        fields = pc.get("fields") or {}
        out["fields_compared"] += fields.get("compared") or 0
        out["fields_mismatched"] += len(fields.get("mismatched") or [])
        if (rec.get("tcpdump") or {}).get("dropped"):
            out["tcpdump_dropped_runs"] += 1
        if rec.get("runner_errors"):
            out["runner_error_runs"] += 1
        drv = rec.get("driver") or {}
        if drv.get("timeout"):
            out["driver_timeout_runs"] += 1
        elif drv.get("exit") not in (0, None):
            out["driver_nonzero_exit_runs"] += 1
        if status not in ("ok", "prefix"):
            out["not_ok"].append({"case": rec.get("case"), "repeat": rec.get("repeat"), "status": status,
                                  "problems": (pc.get("problems") or [])[:5]})
    out["status"] = dict(sorted(out["status"].items()))
    return out


def collect_pcap(raw_dir):
    cols = {}
    for name in sorted(os.listdir(raw_dir)):
        if name.endswith(".jsonl.gz"):
            cols[name[: -len(".jsonl.gz")]] = pcap_summary(read_raw(os.path.join(raw_dir, name)))
    total = {"runs": 0, "skipped": 0, "status": {}}
    for s in cols.values():
        total["runs"] += s["runs"]
        total["skipped"] += s["skipped"]
        for k, n in s["status"].items():
            total["status"][k] = total["status"].get(k, 0) + n
    total["status"] = dict(sorted(total["status"].items()))
    return {"note": "由 runner/collect.py 从 raw/ 数出来；ok 是逐字节相同，prefix 是抓包多出仪器关连接之后的字节（见 PROTOCOL.md）",
            "columns": cols, "total": total}


def collect_versions(vdir):
    variants = {}
    for name in sorted(os.listdir(vdir)):
        if name.endswith(".json"):
            with open(os.path.join(vdir, name), encoding="utf-8") as fh:
                variants[name[: -len(".json")]] = json.load(fh)
    return {"note": "由 runner/collect.py 从 versions.d/ 合并；每列的 env 是那一列正式运行时的环境", "variants": variants}


def dump(obj, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="汇总抓包核对的结论和各列的版本")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(HERE), "out"))
    args = ap.parse_args(argv)
    raw_dir = os.path.join(args.out, "raw")
    if not os.path.isdir(raw_dir):
        print("collect: 没有 %s" % raw_dir, file=sys.stderr)
        return 2
    pc = collect_pcap(raw_dir)
    dump(pc, os.path.join(args.out, "pcap_check.json"))
    print("collect: %d 列，%d 次运行，核对结论 %s" % (len(pc["columns"]), pc["total"]["runs"],
                                             json.dumps(pc["total"]["status"], ensure_ascii=False)))
    vdir = os.path.join(args.out, "versions.d")
    if os.path.isdir(vdir):
        dump(collect_versions(vdir), os.path.join(args.out, "versions.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
