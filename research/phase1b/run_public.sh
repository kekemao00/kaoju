#!/usr/bin/env bash
# 在公开库上重算 1B 的全部输出（决策 D16，PUBLIC.md）。第三方用这一条命令复现 out/。
#
# 用法：
#   ./run_public.sh <公开库.sqlite> <输出目录>
#
#   <公开库.sqlite>  发布的脱敏库（pub_export.py 导出的；解压以后的 .sqlite 文件）
#   <输出目录>       模块输出写到这里；不许是本目录的 out/（那是要拿来比对的仓库版本）
#
# 跑完以后与仓库里的 out/ 比对（只允许 PUBLIC.md“必然不同的字段”里列出的差别）：
#   python3 pub_check.py compare <输出目录> out/
#
# 与 run_all.sh 的区别：不入库（公开库就是入库以后的样子）；不读证据文件、不调 certcheck、不读 AWS 地址段——
# 这几处的结果随公开库带着（pub_* 表），模块在公开库上自动改从库里取（pubdb.py）。summary.json 和 preflight.txt
# 的脱敏版本也在库里（pub_file 表），这里先取出来放进临时的“数据目录”。
# 公开库只带了默认参数那一次运行的中间结果，所以不支持 FORMAL_START（换了正式起点，模块会报错停下）。
#
# 可选环境变量：PYTHON（默认 python3，需要 3.10 以上，只用标准库）
set -euo pipefail
export LC_NUMERIC=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 2
}
[[ $# -eq 2 ]] || usage
[[ -n "${FORMAL_START:-}" ]] && { echo "公开库不支持 FORMAL_START（只带了默认起点那一次的中间结果）" >&2; exit 2; }

DB="$1"
[[ -f "$DB" ]] || { echo "找不到公开库：$DB" >&2; exit 2; }
DB="$(cd "$(dirname "$DB")" && pwd)/$(basename "$DB")"
mkdir -p "$2"
OUT="$(cd "$2" && pwd)"
[[ "$OUT" == "$HERE/out" ]] && { echo "输出目录不能是 $HERE/out（那是要比对的仓库版本）" >&2; exit 2; }

"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || { echo "需要 Python 3.10 以上：$("$PY" --version 2>&1)" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
DATA="$TMP/data"
mkdir -p "$DATA"

# 确认是公开库，取出 summary.json、preflight.txt
"$PY" - "$DB" "$DATA" <<'EOF'
import os, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
row = con.execute("SELECT value FROM meta WHERE key = 'public_version'").fetchone()
if not row or not row[0]:
    raise SystemExit("这不是 pub_export.py 导出的公开库（meta 里没有 public_version）。真实库用 run_all.sh")
for name, content in con.execute("SELECT name, content FROM pub_file ORDER BY name"):
    if os.path.basename(name) != name:
        raise SystemExit("pub_file 里的文件名不对：%r" % name)
    with open(os.path.join(sys.argv[2], name), "w", encoding="utf-8") as f:
        f.write(content)
print("公开库第 %s 版；取出 %s" % (row[0], "、".join(sorted(os.listdir(sys.argv[2]))) or "（没有文件）"), file=sys.stderr)
EOF

SUMMARY_OPT=()
[[ -f "$DATA/summary.json" ]] && SUMMARY_OPT=(--summary "$DATA/summary.json")
PREFLIGHT_OPT=()
[[ -f "$DATA/preflight.txt" ]] && PREFLIGHT_OPT=(--preflight "$DATA/preflight.txt")

for key in instrument availability lifetime freshness labels integrity mitm nodes literature posthoc; do
    rm -f "$OUT/$key.json"
done
rm -f "$OUT/report.md" "$OUT/rotation_check.json"

T_ALL=$(date +%s.%N)
step() {
    local name="$1"; shift
    echo "==> [$name] $(date -u +%H:%M:%SZ)" >&2
    "$@"
}

# 与 run_all.sh 相同的顺序和参数；--data 指向只有 summary.json、preflight.txt 的临时目录（没有 evidence/）。
# preflight.txt 用 --preflight 给（真实库上是按 meta.data_dir 找到的，所以 instrument.json 里 preflight 的 source 必然不同）
step instrument   "$PY" "$HERE/m_instrument.py"   --db "$DB" --out "$OUT" "${PREFLIGHT_OPT[@]}" "${SUMMARY_OPT[@]}"
step availability "$PY" "$HERE/m_availability.py" --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}"
step lifetime     "$PY" "$HERE/m_lifetime.py"     --db "$DB" --out "$OUT"
step freshness    "$PY" "$HERE/m_freshness.py"    --db "$DB" --out "$OUT"
step labels       "$PY" "$HERE/m_labels.py"       --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}"
step integrity    "$PY" "$HERE/m_integrity.py"    --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}"
step mitm         "$PY" "$HERE/m_mitm.py"         --db "$DB" --out "$OUT" --data "$DATA" "${SUMMARY_OPT[@]}"
step nodes        "$PY" "$HERE/m_nodes.py"        --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}"
step literature   "$PY" "$HERE/m_literature.py"   --db "$DB" --out "$OUT" --data "$DATA" "${SUMMARY_OPT[@]}"
step posthoc      "$PY" "$HERE/m_posthoc.py"      --db "$DB" --out "$OUT" --data "$DATA"
step report bash -c '"$1" "$2" --out-dir "$3" --db "$4" --write "$3/report.md" --strict >/dev/null' _ \
    "$PY" "$HERE/report_tables.py" "$OUT" "$DB"
if [[ -f "$DATA/summary.json" ]]; then
    step rotation "$PY" "$HERE/crosscheck_as_summary_saw.py" --db "$DB" --summary "$DATA/summary.json" --data "$DATA" \
        --before-dir "$OUT" --write "$OUT/rotation_check.json"
fi

printf '合计 %.0f 秒。输出：%s\n与仓库版本比对：%s %s compare %s %s\n' \
    "$(awk -v a="$T_ALL" -v b="$(date +%s.%N)" 'BEGIN{print b-a}')" "$OUT" "$PY" "$HERE/pub_check.py" "$OUT" "$HERE/out" >&2
