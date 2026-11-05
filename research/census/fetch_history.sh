#!/usr/bin/env bash
# 复现来源普查所需的全部输入：列表仓库的 git 历史、节点订阅仓库的最新快照、离线 ASN/国家库。
# 用法：./fetch_history.sh <工作目录> [起始日期，默认 2026-10-06]
# 只做 git clone 和 npm pack，不连接任何代理。
set -euo pipefail

WORK="${1:?用法: fetch_history.sh <工作目录> [起始日期]}"
SINCE="${2:-2026-10-06}"
mkdir -p "$WORK/hist" "$WORK/nodes" "$WORK/ipdb"
export GIT_LFS_SKIP_SMUDGE=1

dirname_of() { echo "$1" | sed 's|/|__|'; }

clone_hist() {  # 保留 SINCE 以来的提交历史
  local r="$1" d; d="$WORK/hist/$(dirname_of "$r")"
  [ -d "$d/.git" ] && return 0
  git clone --quiet --single-branch --no-tags --shallow-since="$SINCE" "https://github.com/$r.git" "$d" \
    || echo "克隆失败: $r" >&2
}

clone_latest() {  # 只要最新快照
  local r="$1" d; d="$WORK/nodes/$(dirname_of "$r")"
  [ -d "$d/.git" ] && return 0
  git clone --quiet --depth 1 "https://github.com/$r.git" "$d" || echo "克隆失败: $r" >&2
}

# 1) HTTP / SOCKS 列表（与 sources.json 一致）
for r in \
  TheSpeedX/PROXY-List monosans/proxy-list proxifly/free-proxy-list roosterkid/openproxylist \
  mmpx12/proxy-list hookzof/socks5_list vakhov/fresh-proxy-list zloi-user/hideip.me \
  Zaeem20/FREE_PROXIES_LIST officialputuid/KangProxy iplocate/free-proxy-list sunny9577/proxy-scraper \
  Vann-Dev/proxy-list dpangestuw/Free-Proxy xyzs996/free-proxy-health-list ErcinDedeoglu/proxies \
  SevenworksDev/proxy-list gfpcom/free-proxy-list; do
  clone_hist "$r"
done
# gfpcom 的列表文件放在 wiki 仓库里
[ -d "$WORK/hist/gfpcom__free-proxy-list.wiki/.git" ] || \
  git clone --quiet --single-branch --no-tags --shallow-since="$SINCE" \
    https://github.com/gfpcom/free-proxy-list.wiki.git "$WORK/hist/gfpcom__free-proxy-list.wiki"

# 2) 节点订阅（与 nodes_census.py 的 SOURCES 一致）
for r in \
  barry-far/V2ray-config MatinGhanbari/v2ray-configs mahdibland/V2RayAggregator mheidari98/.proxy \
  peasoft/NoMoreWalls chengaopan/AutoMergePublicNodes mfuu/v2ray aiboboxx/v2rayfree \
  Pawdroid/Free-servers snakem982/proxypool; do
  clone_latest "$r"
done
mkdir -p "$WORK/nodes/roosterkid__openproxylist"
cp "$WORK/hist/roosterkid__openproxylist/V2RAY_RAW.txt" "$WORK/nodes/roosterkid__openproxylist/"

# 3) 离线 IP 库（ASN：CC BY 4.0，RouteViews / DB-IP / NRO；国家：CC0）
( cd "$WORK/ipdb" && npm pack --silent @ip-location-db/asn @ip-location-db/geo-whois-asn-country \
  && for t in *.tgz; do mkdir -p "x_${t%.tgz}" && tar -xzf "$t" -C "x_${t%.tgz}"; done )

echo "完成。接着运行："
echo "  python3 census.py --hist-dir $WORK/hist --ipdb-dir $WORK/ipdb --out out/"
echo "  python3 nodes_census.py --nodes-dir $WORK/nodes --ipdb-dir $WORK/ipdb --out out/"
