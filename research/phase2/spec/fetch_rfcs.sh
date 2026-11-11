#!/usr/bin/env bash
# 把规范部分用到的 RFC 纯文本取到指定目录，并核对 rfc_sha256.txt 里登记的 SHA-256。
# RFC 文本不进仓库；check_quotes.py 用 --rfc-dir 或环境变量 KAOJU_RFC_DIR 指向这个目录。
#
# 用法：
#   ./fetch_rfcs.sh [--from auto|rfc-editor|apt] [--debs 目录] [--sha256-file 文件] 目标目录
#
#   --from rfc-editor   从 https://www.rfc-editor.org/rfc/rfcNNNN.txt 下载（CI 上用）。
#   --from apt          从 Ubuntu 的 doc-rfc 系列软件包里取：apt-get download 之后只解出要的文件，
#                       不安装，不需要 root（访问不了 rfc-editor 的机器上用）。
#   --from auto         默认。先试 rfc-editor，有文件下载不下来或哈希不对，就改用 apt 取剩下的。
#   --debs 目录          apt 来源不下载，用这个目录里已经有的 .deb；没有写 --from 时等于 --from apt。
#   --sha256-file 文件   哈希的登记，默认是本脚本旁边的 rfc_sha256.txt。
#
# 取哪些 RFC 由登记文件决定（sha256sum 的格式，每行“SHA-256  rfcNNNN.txt”）。
# 目标目录里已经有、哈希也对的文件不重取。取到的文件哈希不对就不放进去，
# 那一份留在 目标目录/rfcNNNN.txt.rejected 供查看；最后还有文件没就绪，脚本以 1 退出。
#
# 环境变量：
#   KAOJU_RFC_BASE_URL   rfc-editor 来源的地址前缀，默认 https://www.rfc-editor.org/rfc
#   KAOJU_RFC_PACKAGES   apt 来源依次尝试的软件包，默认 "doc-rfc-std doc-rfc-std-proposed doc-rfc-old-std"
#                        （要的文件都齐了就不再下载后面的）
#
# 退出码：0 全部就绪且哈希一致；1 有文件取不到或哈希不一致；2 用法不对或缺工具。
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
from=""
debs=""
registry="$here/rfc_sha256.txt"
dest=""

die() { local code="$1"; shift; echo "fetch_rfcs.sh：$*" >&2; exit "$code"; }
usage() { sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --from) [ $# -ge 2 ] || usage; from="$2"; shift 2 ;;
    --debs) [ $# -ge 2 ] || usage; debs="$2"; shift 2 ;;
    --sha256-file) [ $# -ge 2 ] || usage; registry="$2"; shift 2 ;;
    -h|--help) usage ;;
    -*) echo "不认识的参数：$1" >&2; usage ;;
    *) [ -z "$dest" ] || usage; dest="$1"; shift ;;
  esac
done
[ -n "$dest" ] || usage
if [ -z "$from" ]; then
  if [ -n "$debs" ]; then from="apt"; else from="auto"; fi
fi
case "$from" in auto|rfc-editor|apt) ;; *) die 2 "--from 只能是 auto、rfc-editor 或 apt" ;; esac
[ -z "$debs" ] || [ -d "$debs" ] || die 2 "--debs 指的目录不存在：$debs"
[ -z "$debs" ] || [ "$from" != "rfc-editor" ] || die 2 "--debs 只用于 apt 来源"
[ -f "$registry" ] || die 2 "找不到哈希登记：$registry"

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die 2 "需要 sha256sum 或 shasum"
fi

# 读登记：names[i] 是文件名，sums[i] 是登记的哈希
names=()
sums=()
while read -r sum name || [ -n "${sum:-}" ]; do
  [ -n "${sum:-}" ] || continue
  name="${name#\*}"
  if ! [[ "$sum" =~ ^[0-9a-f]{64}$ && "$name" =~ ^rfc[0-9]+\.txt$ ]]; then
    die 2 "$registry 里有一行不是“SHA-256  rfcNNNN.txt”：$sum $name"
  fi
  names+=("$name")
  sums+=("$sum")
done < "$registry"
[ ${#names[@]} -gt 0 ] || die 2 "$registry 是空的"

mkdir -p "$dest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# pending：目标目录里还没有、或者哈希不对的文件的下标
pending=()
refresh_pending() {
  pending=()
  local i f
  for i in "${!names[@]}"; do
    f="$dest/${names[$i]}"
    if [ -f "$f" ] && [ ! -L "$f" ] && [ "$(sha256_of "$f")" = "${sums[$i]}" ]; then
      continue
    fi
    pending+=("$i")
  done
}

# accept 下标 候选文件 来源：哈希对就放进目标目录，不对就留作 .rejected
accept() {
  local i="$1" cand="$2" src="$3" name="${names[$1]}" got
  got="$(sha256_of "$cand")"
  if [ "$got" = "${sums[$i]}" ]; then
    chmod 644 "$cand"
    mv -f "$cand" "$dest/$name"
    echo "  $name  取到，哈希一致（$src）"
  else
    chmod 644 "$cand"
    mv -f "$cand" "$dest/$name.rejected"
    echo "  $name  哈希不一致（$src）：登记的是 ${sums[$i]}，取到的是 $got。取到的那份在 $dest/$name.rejected" >&2
  fi
}

# 从 rfc-editor 下载 pending 里的文件。有下载失败的返回 1
fetch_rfc_editor() {
  local base="${KAOJU_RFC_BASE_URL:-https://www.rfc-editor.org/rfc}" i name failed=0
  command -v curl >/dev/null 2>&1 || { echo "  没有 curl，rfc-editor 来源用不了" >&2; return 1; }
  echo "从 $base 下载："
  for i in "${pending[@]}"; do
    name="${names[$i]}"
    if curl -fsSL --retry 2 --connect-timeout 15 --max-time 180 -o "$work/$name" "$base/$name"; then
      accept "$i" "$work/$name" "$base/$name"
    else
      echo "  $name  下载失败：$base/$name" >&2
      rm -f "$work/$name"
      failed=1
      # auto 模式下第一个失败就不再试这个来源，免得每个文件都等到超时
      [ "$from" != "auto" ] || return 1
    fi
  done
  return "$failed"
}

# 从 doc-rfc 系列软件包里取 pending 里的文件
fetch_apt() {
  local pkgs="${KAOJU_RFC_PACKAGES:-doc-rfc-std doc-rfc-std-proposed doc-rfc-old-std}"
  local pkg deb x list alt i name found
  command -v dpkg-deb >/dev/null 2>&1 || { echo "  没有 dpkg-deb，apt 来源用不了" >&2; return 1; }
  if [ -z "$debs" ]; then
    command -v apt-get >/dev/null 2>&1 || { echo "  没有 apt-get，apt 来源用不了（可以用 --debs 指定已有的 .deb）" >&2; return 1; }
    mkdir -p "$work/debs"
  fi
  echo "从软件包里取："
  for pkg in $pkgs; do
    refresh_pending
    [ ${#pending[@]} -gt 0 ] || break
    if [ -n "$debs" ]; then
      deb="$(find "$debs" -maxdepth 1 -type f -name "${pkg}_*.deb" | sort | tail -n 1)"
      [ -n "$deb" ] || { echo "  $debs 里没有 ${pkg}_*.deb，跳过"; continue; }
    else
      # apt-get download 把 .deb 放在当前目录，不安装
      if ! (cd "$work/debs" && apt-get download "$pkg" >/dev/null); then
        echo "  apt-get download $pkg 失败，跳过" >&2
        continue
      fi
      deb="$(find "$work/debs" -maxdepth 1 -type f -name "${pkg}_*.deb" | sort | tail -n 1)"
      [ -n "$deb" ] || { echo "  apt-get download $pkg 没有留下 .deb，跳过" >&2; continue; }
    fi
    echo "  $(basename "$deb")"
    # 先列出包里有哪些要的文件（rfcNNNN.txt 或 rfcNNNN.txt.gz），再只解出这些
    alt=""
    for i in "${pending[@]}"; do
      name="${names[$i]}"
      alt="${alt:+$alt|}${name//./\\.}"
    done
    list="$work/members-$pkg"
    dpkg-deb --fsys-tarfile "$deb" | tar -t | grep -E "/($alt)(\.gz)?\$" > "$list" || true
    [ -s "$list" ] || { rm -f "$work/debs/"*.deb 2>/dev/null || true; continue; }
    x="$work/x-$pkg"
    mkdir -p "$x"
    dpkg-deb --fsys-tarfile "$deb" | tar -x -C "$x" -T "$list"
    for i in "${pending[@]}"; do
      name="${names[$i]}"
      found="$(find "$x" -type f \( -name "$name" -o -name "$name.gz" \) | sort | head -n 1)"
      [ -n "$found" ] || continue
      case "$found" in
        *.gz) gzip -dc "$found" > "$work/$name" ;;
        *) cp "$found" "$work/$name" ;;
      esac
      accept "$i" "$work/$name" "$(basename "$deb")"
    done
    rm -rf "$x"
    [ -n "$debs" ] || rm -f "$work/debs/"*.deb
  done
}

refresh_pending
if [ ${#pending[@]} -eq 0 ]; then
  echo "目标目录里的 ${#names[@]} 个文件都在，哈希与登记一致，不用取：$dest"
  exit 0
fi

case "$from" in
  rfc-editor) fetch_rfc_editor || true ;;
  apt) fetch_apt || true ;;
  auto)
    fetch_rfc_editor || true
    refresh_pending
    if [ ${#pending[@]} -gt 0 ]; then
      echo "rfc-editor 取不全，改用 apt 来源取剩下的"
      fetch_apt || true
    fi
    ;;
esac

refresh_pending
if [ ${#pending[@]} -gt 0 ]; then
  for i in "${pending[@]}"; do
    if [ -e "$dest/${names[$i]}" ]; then
      echo "  ${names[$i]}  目标目录里的那份哈希与登记不一致" >&2
    else
      echo "  ${names[$i]}  没有取到" >&2
    fi
  done
  die 1 "${#pending[@]} 个文件没有就绪（共 ${#names[@]} 个）"
fi
echo "${#names[@]} 个文件全部就绪，哈希与登记一致：$dest"
# 就绪了也要说一声：有的来源给过与登记不一致的文本（可能是这次，也可能是以前留下的）
for name in "${names[@]}"; do
  if [ -e "$dest/$name.rejected" ]; then
    echo "注意：$dest/$name.rejected 是某个来源给出的、与登记不一致的文本，查清以后再删" >&2
  fi
done
