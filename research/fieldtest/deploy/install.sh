#!/bin/sh
# fieldtest 安装脚本。在测量用的服务器上以 root 运行。
#
#   ./deploy/install.sh --host <judge 的域名> --ip <公网 IPv4> --contact <邮箱或网址>
#
# 它做这些事：
#   1. 把 fieldtest 装到 /usr/local/bin
#   2. 下载官方 sing-box 并核对 SHA-256，放到 /opt/fieldtest
#   3. 建一个没有登录权限的用户 fieldtest，数据放在 /var/lib/fieldtest
#   4. 写配置 /etc/fieldtest/fieldtest.json（已有则保留）
#   5. 安装两个 systemd 服务，启动 judge
#   6. 运行预检（含仪器自检）
# 探测不会自动开始，除非加 --start。可以重复运行；已有的配置默认保留。
set -eu

HOST=""
IP=""
CONTACT=""
HTTP=":80"
HTTPS=":443"
HOURS="0"
START=0
RECONF=0

SB_VER="1.14.4"
SB_SHA_amd64="699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"
SB_SHA_arm64="436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"

PREFIX=/opt/fieldtest
DATA=/var/lib/fieldtest
CONF=/etc/fieldtest/fieldtest.json

die() {
	echo "错误: $*" >&2
	exit 1
}

# 机器上有 systemctl 不等于 systemd 在运行（容器里常见），要看 /run/systemd/system
has_systemd() {
	[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

usage() {
	cat <<EOF
用法: $0 --ip <公网 IPv4> [选项]

  --host <域名>      judge 的主机名，探测请求里用它。没有域名可以不填，这时用 IP
  --ip <地址>        这台机器的公网 IPv4（必填）
  --contact <文字>   写在 judge 首页上的联系方式，供想退出测量的人使用
  --http <地址>      judge 的 HTTP 监听地址，默认 :80
  --https <地址>     judge 的 HTTPS 监听地址，默认 :443
  --hours <数字>     探测运行多少小时后自动停止，默认 0（一直运行，手动停止）
  --start            预检没有失败项时，直接开始探测
  --reconfigure      已有配置文件时也重新生成（换端口、换域名时用）
EOF
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--host) HOST="$2"; shift 2 ;;
	--ip) IP="$2"; shift 2 ;;
	--contact) CONTACT="$2"; shift 2 ;;
	--http) HTTP="$2"; shift 2 ;;
	--https) HTTPS="$2"; shift 2 ;;
	--hours) HOURS="$2"; shift 2 ;;
	--start) START=1; shift ;;
	--reconfigure) RECONF=1; shift ;;
	-h | --help) usage ;;
	*) echo "不认识的选项: $1" >&2; usage ;;
	esac
done

[ "$(id -u)" = "0" ] || die "请用 root 运行"
[ -n "$IP" ] || usage
[ -n "$HOST" ] || HOST="$IP"

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "不支持的处理器架构: $(uname -m)" ;;
esac

HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/bin/fieldtest-linux-$ARCH"
[ -f "$BIN" ] || die "找不到 $BIN"

echo "== 1/6 安装 fieldtest"
install -m 0755 "$BIN" /usr/local/bin/fieldtest
/usr/local/bin/fieldtest version

echo "== 2/6 准备 sing-box $SB_VER"
if [ -x "$PREFIX/sing-box/sing-box" ] && "$PREFIX/sing-box/sing-box" version 2>/dev/null | grep -q "version $SB_VER"; then
	echo "已经装好"
else
	mkdir -p "$PREFIX"
	T="sing-box-$SB_VER-linux-$ARCH.tar.gz"
	if [ -f "$HERE/$T" ]; then
		# 服务器访问不了 GitHub 时，可以先把这个压缩包放到包的根目录
		cp "$HERE/$T" "$PREFIX/$T"
	else
		URL="https://github.com/SagerNet/sing-box/releases/download/v$SB_VER/$T"
		echo "下载 $URL"
		if command -v curl >/dev/null 2>&1; then
			curl -fL --retry 3 -o "$PREFIX/$T" "$URL" || die "下载失败。可以手动下载这个文件，放到 $HERE/ 下再运行本脚本"
		elif command -v wget >/dev/null 2>&1; then
			wget -O "$PREFIX/$T" "$URL" || die "下载失败。可以手动下载这个文件，放到 $HERE/ 下再运行本脚本"
		else
			die "需要 curl 或 wget"
		fi
	fi
	eval "WANT=\$SB_SHA_$ARCH"
	GOT=$(sha256sum "$PREFIX/$T" | cut -d' ' -f1)
	[ "$GOT" = "$WANT" ] || die "sing-box 压缩包的 SHA-256 不对: $GOT（应为 $WANT）"
	tar -xzf "$PREFIX/$T" -C "$PREFIX"
	rm -rf "$PREFIX/sing-box"
	mv "$PREFIX/sing-box-$SB_VER-linux-$ARCH" "$PREFIX/sing-box"
	rm -f "$PREFIX/$T"
	chmod -R a+rX "$PREFIX"
	echo "SHA-256 核对通过"
fi

echo "== 3/6 用户与目录"
if ! id fieldtest >/dev/null 2>&1; then
	NOLOGIN=$(command -v nologin || echo /bin/false)
	useradd --system --no-create-home --shell "$NOLOGIN" fieldtest 2>/dev/null ||
		adduser -S -D -H -s "$NOLOGIN" fieldtest || die "建不了用户 fieldtest"
fi
mkdir -p "$DATA" /etc/fieldtest
chown -R fieldtest "$DATA"
chmod 0750 "$DATA"

echo "== 4/6 配置"
if [ -f "$CONF" ] && [ "$RECONF" = "0" ]; then
	echo "保留已有的 $CONF（要重新生成请加 --reconfigure）"
else
	/usr/local/bin/fieldtest init -force -c "$CONF" -host "$HOST" -ip "$IP" -contact "$CONTACT" \
		-http "$HTTP" -https "$HTTPS" -data "$DATA" -hours "$HOURS" -sing-box "$PREFIX/sing-box/sing-box"
fi

echo "== 5/6 服务"
# judge 以普通用户运行，要有绑定 80 和 443 的能力。
# systemd 229 及以上：由服务单元里的 AmbientCapabilities 给，程序文件上不加任何能力。
# 更老的 systemd，或者没有 systemd：给程序文件加上这项能力（setcap）。
SYSTEMD_VER=0
if has_systemd; then
	SYSTEMD_VER=$(systemctl --version 2>/dev/null | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
	[ -n "$SYSTEMD_VER" ] || SYSTEMD_VER=0
fi
if [ "$SYSTEMD_VER" -lt 229 ] && command -v setcap >/dev/null 2>&1; then
	setcap cap_net_bind_service=+ep /usr/local/bin/fieldtest || true
fi
if has_systemd; then
	install -m 0644 "$HERE/deploy/fieldtest-judge.service" /etc/systemd/system/fieldtest-judge.service
	install -m 0644 "$HERE/deploy/fieldtest-probe.service" /etc/systemd/system/fieldtest-probe.service
	if [ "$SYSTEMD_VER" -lt 229 ]; then
		# 老版本不认 AmbientCapabilities；NoNewPrivileges 又会让文件上的能力失效，所以两样都去掉
		sed -i '/^AmbientCapabilities=/d;/^CapabilityBoundingSet=/d;/^NoNewPrivileges=/d' \
			/etc/systemd/system/fieldtest-judge.service
	fi
	systemctl daemon-reload
	systemctl enable fieldtest-judge >/dev/null 2>&1 || true
	systemctl restart fieldtest-judge
	sleep 2
	if ! systemctl is-active --quiet fieldtest-judge; then
		echo "judge 没有起来，最近的日志："
		journalctl -u fieldtest-judge -n 8 --no-pager 2>/dev/null || true
	fi
else
	echo "这台机器没有运行 systemd，服务没有安装。请自己用进程管理工具以 fieldtest 用户运行这两条命令："
	echo "  /usr/local/bin/fieldtest judge -c $CONF"
	echo "  /usr/local/bin/fieldtest probe -c $CONF"
	echo "先把 judge 跑起来，再执行: fieldtest preflight"
fi

echo "== 6/6 预检"
as_user() {
	if command -v runuser >/dev/null 2>&1; then
		runuser -u fieldtest -- "$@"
	else
		su -s /bin/sh fieldtest -c "$*"
	fi
}
PRE=0
as_user /usr/local/bin/fieldtest preflight -c "$CONF" || PRE=1

echo
if [ "$PRE" = "0" ]; then
	if [ "$START" = "1" ] && has_systemd; then
		systemctl enable fieldtest-probe >/dev/null 2>&1 || true
		systemctl restart fieldtest-probe
		echo "预检没有失败项，探测已经开始。30 分钟后执行: fieldtest summary"
	else
		echo "预检没有失败项。接下来："
		echo "  1. 在另一台机器上执行上面那两条 curl，确认都输出 ok"
		echo "  2. 开始探测:  systemctl enable --now fieldtest-probe"
		echo "  3. 30 分钟后:  fieldtest summary"
	fi
else
	echo "预检有失败项，先按上面的提示解决，再执行: fieldtest preflight"
	exit 1
fi
