#!/bin/sh
# 构建部署包：两种架构的 fieldtest、安装脚本、说明和全部源码。
#   ./deploy/build-bundle.sh [输出目录]
# 产物是 <输出目录>/fieldtest-bundle.tar.gz。只需要 Go 工具链，没有第三方依赖。
# 同一份源码、同一个 Go 版本、同一个 VERSION，构建出的二进制逐字节相同。
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$HERE/dist"}
VERSION=${VERSION:-"0.1.0-$(date -u +%Y%m%d)"}
B="$OUT/fieldtest-bundle"
rm -rf "$B"
mkdir -p "$B/bin" "$B/deploy" "$B/src"
cd "$HERE"
for arch in amd64 arm64; do
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.version=$VERSION" -o "$B/bin/fieldtest-linux-$arch" ./cmd/fieldtest
done
cp README.md PROTOCOL.md "$B/"
cp deploy/install.sh deploy/uninstall.sh deploy/fieldtest-judge.service deploy/fieldtest-probe.service "$B/deploy/"
cp -r go.mod cmd internal "$B/src/"
cat > "$B/NOTICE" <<NOTICE
fieldtest $VERSION

第一阶段 1B 的实测工具，源码在 src/ 目录，只依赖 Go 标准库。
所属项目的许可证是 GPL-3.0-or-later，许可证全文随仓库提供。

本包不含 sing-box。安装脚本从 sing-box 的官方发布页下载 1.14.4 版并核对 SHA-256：
https://github.com/SagerNet/sing-box/releases/tag/v1.14.4
sing-box 按 GPL-3.0-or-later 发布。
NOTICE
(cd "$B" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
tar -C "$OUT" -czf "$OUT/fieldtest-bundle.tar.gz" fieldtest-bundle
ls -l "$OUT/fieldtest-bundle.tar.gz"
echo "版本 $VERSION"
