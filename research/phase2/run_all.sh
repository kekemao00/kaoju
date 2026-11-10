#!/usr/bin/env bash
# 第 2 阶段的全链路：构建仪器 → 仪器的测试 → 运行器和驱动的单元测试 → 取数 → 提取事实 → 矩阵 → 仪器自检。
# 任何一步失败就停，退出码非 0。口径见 PROTOCOL.md，各步的细节见 runner/README.md。
#
#   ./run_all.sh [--variants 列,列] [--repeats N] [--out 目录] [--tcpdump '命令']
#
# 四个参数原样传给 runner/run.py（都不写时：注册表里的全部列、cases.json 里的遍数、out/、tcpdump）。
# --out 同时是 derive.py、matrix.py、selfcheck.py 读写的目录。
#
# 最后一步的仪器自检（runner/selfcheck.py）读的是 <out> 里 rawref 一列的数据：
# --variants 里没有 rawref 时，用的是 <out> 里以前留下的 rawref 数据；一次都没跑过就不通过。
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
start_dir="$PWD"

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

variants=""
out=""
run_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --variants | --repeats | --out | --tcpdump)
      if [ $# -lt 2 ]; then
        echo "run_all: $1 后面缺一个值" >&2
        exit 2
      fi
      name="$1"
      value="$2"
      shift 2
      ;;
    --variants=* | --repeats=* | --out=* | --tcpdump=*)
      name="${1%%=*}"
      value="${1#*=}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "run_all: 不认识的参数 $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  case "$name" in
    --variants)
      variants="$value"
      run_args+=(--variants "$value")
      ;;
    --out) out="$value" ;;
    *) run_args+=("$name" "$value") ;;
  esac
done

# --out 相对于调用时所在的目录；默认与 run.py 相同
if [ -z "$out" ]; then
  out="$here/out"
elif [ "${out#/}" = "$out" ]; then
  out="$start_dir/$out"
fi

step() {
  printf '\n==> %s\n' "$*"
}

cd "$here"

# 构建到临时目录，不动 harness/ 下的文件；结束时删掉
build_dir="$(mktemp -d "${TMPDIR:-/tmp}/kaoju-p2-build.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT
obsproxy="$build_dir/obsproxy"

step "1/7 构建 obsproxy"
(cd harness && go build -trimpath -o "$obsproxy" .)
"$obsproxy" version

step "2/7 obsproxy：gofmt、go vet、go test -race"
(
  cd harness
  unformatted="$(gofmt -l .)"
  if [ -n "$unformatted" ]; then
    echo "run_all: gofmt 不干净：" >&2
    echo "$unformatted" >&2
    exit 1
  fi
  go vet ./...
  go test -race -count=1 ./...
)

step "3/7 运行器和驱动的单元测试"
python3 -m unittest discover -s runner -p 'test_*.py'
for d in drivers/*/; do
  if compgen -G "${d}test_*.py" >/dev/null; then
    python3 -m unittest discover -s "$d" -p 'test_*.py'
  fi
done

step "4/7 取数（runner/run.py）"
python3 runner/run.py --obsproxy "$obsproxy" --out "$out" ${run_args[@]+"${run_args[@]}"}

step "5/7 提取事实（runner/derive.py）"
python3 runner/derive.py --raw "$out/raw" --out "$out/observations"

step "6/7 矩阵（runner/matrix.py）"
python3 runner/matrix.py --observations "$out/observations" --out "$out"

step "7/7 仪器自检（runner/selfcheck.py）"
if [ -n "$variants" ] && [[ ",$variants," != *",rawref,"* ]]; then
  echo "run_all: 注意：这次没有跑 rawref，自检用的是 $out 里以前留下的 rawref 数据" >&2
fi
python3 runner/selfcheck.py --out "$out"

printf '\nrun_all: 全部通过。输出在 %s\n' "$out"
