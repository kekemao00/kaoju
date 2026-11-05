#!/bin/sh
# 端到端测试：夹具、judge、探测器照正式流程在本机跑一遍，大约 5 分钟。
#   SINGBOX=/path/to/sing-box ./test/e2e.sh [工作目录]
# 只连接 127.0.0.0/8。退出码 0 表示每一步都成功，并且汇总通过 test/e2e_check.py 的核对。
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
: "${SINGBOX:?要设置 SINGBOX，指向 sing-box 1.14.4 的可执行文件}"
W=${1:-$(mktemp -d)}
mkdir -p "$W/bin"
cd "$HERE"
go build ${E2E_BUILD_FLAGS:-} -o "$W/bin/fieldtest" ./cmd/fieldtest
go build ${E2E_BUILD_FLAGS:-} -o "$W/bin/fixtures" ./cmd/fixtures
FT="$W/bin/fieldtest"
FX=
JG=
cleanup() {
	[ -n "$FX" ] && kill "$FX" 2>/dev/null || true
	[ -n "$JG" ] && kill "$JG" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap cleanup EXIT

"$W/bin/fixtures" -dir "$W" -sing-box "$SINGBOX" >"$W/fixtures.out" 2>&1 &
FX=$!
i=0
until grep -q '^ready' "$W/fixtures.out"; do
	i=$((i + 1))
	if [ "$i" -gt 150 ]; then
		echo "夹具没有就绪" >&2
		cat "$W/fixtures.out" >&2
		exit 1
	fi
	sleep 0.2
done
cat "$W/fixtures.out"
BASE=$(sed -n 's/^ready base=\([^ ]*\).*/\1/p' "$W/fixtures.out")

"$FT" judge -c "$W/fieldtest.json" >"$W/judge.out" 2>&1 &
JG=$!
sleep 1

step() {
	name=$1
	shift
	if "$@" >"$W/$name.out" 2>&1; then
		echo "$name: 通过"
	else
		echo "$name: 失败，输出如下" >&2
		tail -n 40 "$W/$name.out" >&2
		exit 1
	fi
}
export FIELDTEST_ALLOW_LOCAL=1 SSL_CERT_FILE="$W/obs-ca.pem"
# 布景里的主机名（judge.test、obs1.test、obs2.test）只有夹具认得，本机解析不了，
# 所以预检一定报失败。这里只核对与布景无关的几项。
"$FT" preflight -c "$W/fieldtest.json" -no-selftest >"$W/preflight.out" 2>&1 || true
for want in 'judge 正在运行' '从本机访问自己的公网地址（HTTPS）正常' '列表和订阅都抓得到' '接受探测器生成的配置'; do
	if ! grep -q "$want" "$W/preflight.out"; then
		echo "preflight: 失败，缺少“$want”" >&2
		cat "$W/preflight.out" >&2
		exit 1
	fi
done
echo "preflight: 通过"
# 第一轮跑到 100 秒时，从“公开列表”里撤掉 3 个条目，用来核对下榜的记录
(sleep 100 && curl -fsS "$BASE/drop?label=http&n=3" >"$W/drop.out") &
step probe1 "$FT" probe -c "$W/fieldtest.json" -hours 0.055
# 第二轮核对重启后接着上次的状态跑
step probe2 "$FT" probe -c "$W/fieldtest.json" -hours 0.02
step summary "$FT" summary -c "$W/fieldtest.json"
step pack "$FT" pack -c "$W/fieldtest.json" -o "$W/pack.tar.gz"
cat "$W/summary.out"
python3 "$HERE/test/e2e_check.py" "$W"
