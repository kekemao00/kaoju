#!/bin/sh
# go 这一列的驱动入口：缺二进制时现场构建，然后执行。
#
#   sh drivers/go/run.sh <用例.json> <结果.json>
#   sh drivers/go/run.sh --versions
#
# 二进制按“源码 + go 版本”的哈希缓存在本目录的 .build/ 下（不进仓库）；那里写不了就放到 TMPDIR。
# 构建用的 GOCACHE、GOPATH 指到 TMPDIR 下（run.py 的干净环境里没有这两个变量，HOME 是每次运行专用的目录）。
# 构建只用标准库，不联网：GOPROXY=off、GOTOOLCHAIN=local，不下载任何东西。
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=${TMPDIR:-/tmp}

key=$( { go version; cat "$here/go.mod" "$here"/*.go; } | sha256sum | cut -c1-16)
cache="$here/.build"
if ! mkdir -p "$cache" 2>/dev/null || ! [ -w "$cache" ]; then
	cache="$tmp/kaoju-go-driver"
	mkdir -p "$cache"
fi
bin="$cache/driver-$key"

if ! [ -x "$bin" ]; then
	part="$bin.$$.tmp"
	(
		cd "$here"
		GOCACHE="$tmp/kaoju-go-driver-gocache" \
		GOPATH="$tmp/kaoju-go-driver-gopath" \
		GOPROXY=off GOTOOLCHAIN=local GOFLAGS= \
			go build -trimpath -buildvcs=false -o "$part" . >&2
	)
	mv -f "$part" "$bin" # 同一个文件系统里改名是原子的，并发构建时后到的覆盖先到的，内容相同
	rm -rf "$tmp/kaoju-go-driver-gocache" "$tmp/kaoju-go-driver-gopath" 2>/dev/null || true
fi

exec "$bin" "$@"
