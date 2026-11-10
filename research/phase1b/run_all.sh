#!/usr/bin/env bash
# 第一阶段 1B 实测数据的全套分析：入库 → 九个指标模块 → 事后分析（决策 D14）→ 报告表格。任何一步失败就停。
#
# 用法：
#   ./run_all.sh [--force | --skip-ingest] <数据目录> <state.json.gz> <sqlite 路径>
#
#   <数据目录>       解包后的 fieldtest/ 目录（指向它的上一层也行，ingest.py 会自动进入 fieldtest/）
#   <state.json.gz>  探测器的状态文件；写 - 表示不单独给（有同名文件在数据目录里就用它，没有就跳过 cands 表）
#   <sqlite 路径>    入库生成的 SQLite 文件，不要放进仓库（本脚本和 ingest.py 都会拒绝；仓库根的 .gitignore 也排除 *.sqlite 和原始记录文件）
#   --force          库已存在时删掉重建（不加时库已存在就报错停下）
#   --skip-ingest    库已存在时直接用它，不重新入库（只改了分析模块、没换数据时省时间）
#
# 可选环境变量：
#   PYTHON      Python 解释器（默认 python3，需要 3.10 以上，只用标准库）
#   CERTCHECK   预编译的 certcheck 二进制；不给就在临时目录里 go build 一次（需要 Go 1.24），运行结束删掉
#   ROOTS       公共根证书 PEM（默认 /etc/ssl/certs/ca-certificates.crt），中间人细分“被送到别的网站”用
#   ROOTS_NOTE  根证书库的说明，原样写进 mitm.json（读不到包版本时用它写明 Mozilla 根库是哪一版）
#   FORMAL_START  正式起点（带时区的 ISO 时间）；不给时各模块按 PROTOCOL“正式测量的起止”自己推，
#                 给了就传给所有模块（lifetime/freshness 用 --since，其余用 --formal-start）
#   AWS_RANGES  AWS 公布的 ip-ranges.json（可选，https://ip-ranges.amazonaws.com/ip-ranges.json 下载）。给了 m_posthoc
#               就数中间人 IP 有多少落在 AWS 地址段里，文件的 syncToken 和 createDate 写进 posthoc.json；不给就不数
#
# 输出只写到本目录的 out/：九个模块和事后分析各一个 JSON，外加 report.md（report_tables.py 的输出）。开始跑模块之前先删掉
# out/ 里上一次生成的这十一个文件和 rotation_check.json，免得中途失败时新旧结果混在一起。每个模块写出前都会检查输出里没有 judge 的主机名/地址、
# 单个代理的 ip:port、节点链接和凭据；report_tables.py 写 report.md 前再用库里的身份表查一遍。
# 需要 bash 4.4 以上（空数组配合 set -u）。
set -euo pipefail
export LC_NUMERIC=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/out"
PY="${PYTHON:-python3}"

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 2
}

MODE=""
while [[ $# -gt 0 && "$1" == --* ]]; do
    case "$1" in
        --force) MODE="force" ;;
        --skip-ingest) MODE="skip" ;;
        -h|--help) usage ;;
        *) echo "未知选项：$1" >&2; usage ;;
    esac
    shift
done
[[ $# -eq 3 ]] || usage

DATA_ARG="$1"
STATE_ARG="$2"
DB="$3"

[[ -d "$DATA_ARG" ]] || { echo "数据目录不存在：$DATA_ARG" >&2; exit 2; }
DATA="$(cd "$DATA_ARG" && pwd)"
# 与 ingest.py main() 相同的规则：目录里没有按小时切分的记录文件、却有 fieldtest/ 子目录，就进去
if ! compgen -G "$DATA/probe-*.jsonl*" >/dev/null && [[ -d "$DATA/fieldtest" ]]; then
    DATA="$DATA/fieldtest"
fi
compgen -G "$DATA/probe-*.jsonl*" >/dev/null || { echo "数据目录里没有 probe-*.jsonl(.gz)：$DATA" >&2; exit 2; }

STATE_OPT=()
if [[ "$STATE_ARG" != "-" ]]; then
    [[ -f "$STATE_ARG" ]] || { echo "找不到状态文件：$STATE_ARG" >&2; exit 2; }
    STATE_OPT=(--state "$STATE_ARG")
fi

# 库不许落在仓库里（仓库根的 .gitignore 挡住了 *.sqlite / *.db，这里按路径再挡一次，别的扩展名也挡得住）
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
DB_DIR="$(mkdir -p "$(dirname "$DB")" && cd "$(dirname "$DB")" && pwd)"
DB="$DB_DIR/$(basename "$DB")"
case "$DB_DIR/" in
    "$REPO_ROOT"/*) echo "SQLite 库不要放在仓库里：$DB" >&2; exit 2 ;;
esac

SUMMARY_OPT=()
if [[ -f "$DATA/summary.json" ]]; then
    SUMMARY_OPT=(--summary "$DATA/summary.json")
else
    echo "注意：数据目录里没有 summary.json，跳过与 fieldtest 自带汇总的交叉核对" >&2
fi

FS_OPT=()
SINCE_OPT=()
if [[ -n "${FORMAL_START:-}" ]]; then
    FS_OPT=(--formal-start "$FORMAL_START")
    SINCE_OPT=(--since "$FORMAL_START")
fi

ROOTS_OPT=()
[[ -n "${ROOTS:-}" ]] && ROOTS_OPT=(--roots "$ROOTS")
ROOTS_NOTE_OPT=()
[[ -n "${ROOTS_NOTE:-}" ]] && ROOTS_NOTE_OPT=(--roots-note "$ROOTS_NOTE")
AWS_OPT=()
if [[ -n "${AWS_RANGES:-}" ]]; then
    [[ -f "$AWS_RANGES" ]] || { echo "找不到 AWS_RANGES：$AWS_RANGES" >&2; exit 2; }
    AWS_OPT=(--aws-ranges "$AWS_RANGES")
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

T_ALL=$(date +%s.%N)
TIMES=()
step() {  # step <名字> <命令...>：计时运行，失败时 set -e 让整个脚本停下
    local name="$1"; shift
    local t0 t1
    echo "==> [$name] $(date -u +%H:%M:%SZ)" >&2
    t0=$(date +%s.%N)
    "$@"
    t1=$(date +%s.%N)
    TIMES+=("$(printf '%-12s %8.1f 秒' "$name" "$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}')")")
}

# 库在不在、要不要重建，先决定好再开始干活
if [[ -e "$DB" ]]; then
    case "$MODE" in
        skip) INGEST=skip ;;
        force) INGEST=force ;;
        *) echo "库已存在：$DB。加 --force 重建，或 --skip-ingest 沿用。" >&2; exit 2 ;;
    esac
else
    [[ "$MODE" == "skip" ]] && { echo "--skip-ingest 但库不存在：$DB" >&2; exit 2; }
    INGEST=new
fi

"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || { echo "需要 Python 3.10 以上：$("$PY" --version 2>&1)" >&2; exit 2; }

# certcheck：中间人细分要用的证书链校验小工具（只用 Go 标准库）。编一次，m_mitm 和 m_literature 共用
if [[ -n "${CERTCHECK:-}" ]]; then
    [[ -x "$CERTCHECK" ]] || { echo "CERTCHECK 不可执行：$CERTCHECK" >&2; exit 2; }
    CC="$CERTCHECK"
else
    command -v go >/dev/null || { echo "找不到 go：装 Go 1.24，或用 CERTCHECK= 指定预编译的 certcheck" >&2; exit 2; }
    CC="$TMP/certcheck"
    step certcheck bash -c 'cd "$1" && go build -o "$2" .' _ "$HERE/certcheck" "$CC"
fi

# 1. 入库
case "$INGEST" in
    skip) echo "==> [ingest] 跳过：沿用已有的库 $DB" >&2 ;;
    force) step ingest "$PY" "$HERE/ingest.py" --data "$DATA" --db "$DB" "${STATE_OPT[@]}" --force ;;
    new) step ingest "$PY" "$HERE/ingest.py" --data "$DATA" --db "$DB" "${STATE_OPT[@]}" ;;
esac

mkdir -p "$OUT"
for key in instrument availability lifetime freshness labels integrity mitm nodes literature posthoc; do
    rm -f "$OUT/$key.json"
done
rm -f "$OUT/report.md" "$OUT/rotation_check.json"   # rotation_check.json 由 crosscheck_as_summary_saw.py 在这之后单独生成，旧的不留

# 2. 九个指标模块。仪器核对放第一个：它说数据不可信，后面的数字都要打问号（只报告，不拦）
step instrument   "$PY" "$HERE/m_instrument.py"   --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}" "${FS_OPT[@]}"
step availability "$PY" "$HERE/m_availability.py" --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}" "${FS_OPT[@]}"
step lifetime     "$PY" "$HERE/m_lifetime.py"     --db "$DB" --out "$OUT" "${SINCE_OPT[@]}"
step freshness    "$PY" "$HERE/m_freshness.py"    --db "$DB" --out "$OUT" "${SINCE_OPT[@]}"
step labels       "$PY" "$HERE/m_labels.py"       --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}" "${FS_OPT[@]}"
step integrity    "$PY" "$HERE/m_integrity.py"    --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}" "${FS_OPT[@]}"
step mitm         "$PY" "$HERE/m_mitm.py"         --db "$DB" --out "$OUT" --data "$DATA" --certcheck "$CC" \
                  "${ROOTS_OPT[@]}" "${ROOTS_NOTE_OPT[@]}" "${SUMMARY_OPT[@]}" "${FS_OPT[@]}"
step nodes        "$PY" "$HERE/m_nodes.py"        --db "$DB" --out "$OUT" "${SUMMARY_OPT[@]}" "${FS_OPT[@]}"
step literature   "$PY" "$HERE/m_literature.py"   --db "$DB" --out "$OUT" --data "$DATA" --certcheck "$CC" \
                  "${ROOTS_OPT[@]}" "${SUMMARY_OPT[@]}" "${FS_OPT[@]}"
# 事后分析（看过数据以后加的，决策 D14）：按 IP 重算、拆开整页替换、经 Cloudflare 转发的请求、中间人 IP 的两群
step posthoc      "$PY" "$HERE/m_posthoc.py"      --db "$DB" --out "$OUT" --data "$DATA" "${AWS_OPT[@]}" "${FS_OPT[@]}"

# 3. 报告表格：写 out/report.md（先写临时文件，检查通过才换上）。--strict：缺键、PROTOCOL 常量对不上都算失败
step report bash -c '"$1" "$2" --out-dir "$3" --db "$4" --write "$3/report.md" --strict >/dev/null' _ \
    "$PY" "$HERE/report_tables.py" "$OUT" "$DB"

T_END=$(date +%s.%N)
{
    echo
    echo "各步用时："
    for t in "${TIMES[@]}"; do echo "  $t"; done
    printf '  %-12s %8.1f 秒\n' "合计" "$(awk -v a="$T_ALL" -v b="$T_END" 'BEGIN{print b-a}')"
    echo "输出：$OUT"
    echo
} >&2
# 终端上只给预期范围那一张表，全文在 out/report.md
sed -n '/^## 三、/,/^## 四、/p' "$OUT/report.md" | sed '$d'
