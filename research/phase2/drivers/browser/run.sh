#!/bin/sh
# 浏览器驱动（列 chromium-pw、firefox-pw）的入口：让 Node 找得到 playwright、让 Playwright 找得到浏览器，再启动 driver.mjs。
#
#   sh drivers/browser/run.sh --browser chromium|firefox <用例.json> <结果.json>
#   sh drivers/browser/run.sh --browser chromium|firefox --versions
#
# run.py 的干净环境只留 PATH、HOME、LANG、TMPDIR，不继承 NODE_PATH 和 PLAYWRIGHT_BROWSERS_PATH，
# HOME 又是每次运行专用的目录（Playwright 默认的 ~/.cache/ms-playwright 在那里是空的），所以在这里定：
#
# 模块：
# - 本目录有 node_modules（CI 上 npm ci 装的，版本钉在 package-lock.json）就用它，Node 自己会找到，不用设 NODE_PATH；
# - 否则用全局安装的 playwright：NODE_PATH 设成 npm root -g 的结果（driver.mjs 用 require 加载，ESM 的 import 不看 NODE_PATH）。
#
# 浏览器（PLAYWRIGHT_BROWSERS_PATH 已经设了就不动）：
# - 本目录的 node_modules/playwright-core/.local-browsers 存在（CI 上用 PLAYWRIGHT_BROWSERS_PATH=0 npx playwright install 装的）
#   就设成 0，意思是“浏览器在模块目录里”；
# - 否则 /opt/pw-browsers 存在就指过去（本机的布置）；
# - 都没有就不设，Playwright 用它的默认位置，多半找不到，报错会落进结果文件。
#
# 实际用到的 Playwright 和浏览器版本由 driver.mjs 读出来写进结果。
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! [ -d "$here/node_modules/playwright" ]; then
	root=$(npm root -g 2>/dev/null || true)
	if [ -n "$root" ]; then
		NODE_PATH="$root${NODE_PATH:+:$NODE_PATH}"
		export NODE_PATH
	fi
fi

if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
	if [ -d "$here/node_modules/playwright-core/.local-browsers" ]; then
		PLAYWRIGHT_BROWSERS_PATH=0
		export PLAYWRIGHT_BROWSERS_PATH
	elif [ -d /opt/pw-browsers ]; then
		PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
		export PLAYWRIGHT_BROWSERS_PATH
	fi
fi

exec node "$here/driver.mjs" "$@"
