#!/bin/sh
# 卸载 fieldtest。默认保留数据目录 /var/lib/fieldtest；加 --purge 连数据和用户一起删。
set -eu
[ "$(id -u)" = "0" ] || { echo "请用 root 运行" >&2; exit 1; }
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now fieldtest-probe fieldtest-judge 2>/dev/null || true
	rm -f /etc/systemd/system/fieldtest-probe.service /etc/systemd/system/fieldtest-judge.service
	systemctl daemon-reload || true
fi
rm -f /usr/local/bin/fieldtest
rm -rf /opt/fieldtest /etc/fieldtest
if [ "$PURGE" = "1" ]; then
	rm -rf /var/lib/fieldtest
	userdel fieldtest 2>/dev/null || deluser fieldtest 2>/dev/null || true
	echo "已卸载，数据已删除"
else
	echo "已卸载。数据还在 /var/lib/fieldtest"
fi
