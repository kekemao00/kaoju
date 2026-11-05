#!/usr/bin/env python3
"""把普查脚本的解析结果按文件打印成 JSON，供实测工具的 Go 解析器逐个文件核对。

用法：python3 parse_check.py --hist-dir <克隆目录>
输出：{"<目录>/<文件>": {"n": 条目数, "sha256": 排序后条目的哈希, "q": 质量计数}}
"""
import argparse
import hashlib
import json
import pathlib

import census


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hist-dir", required=True, type=pathlib.Path)
    args = ap.parse_args()
    cfg = json.loads((pathlib.Path(__file__).parent / "sources.json").read_text(encoding="utf-8"))
    out = {}
    for src in cfg["sources"]:
        for rel in src["files"].values():
            p = args.hist_dir / src["dir"] / rel
            if not p.exists():
                continue
            entries, q = census.parse_blob(p.read_bytes().decode("utf-8", errors="replace"))
            digest = hashlib.sha256("\n".join(sorted(entries)).encode()).hexdigest()
            out[f"{src['dir']}/{rel}"] = {"n": len(entries), "sha256": digest, "q": dict(q)}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
