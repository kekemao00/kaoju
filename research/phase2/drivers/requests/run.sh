#!/bin/sh
# requests 驱动的入口：找到装了 requirements.txt 的解释器再启动 driver.py。
# 顺序：环境变量 KAOJU_REQUESTS_PYTHON → 本目录的 .venv/bin/python → python3。
# run.py 的干净环境不继承外面的变量，所以平时走的是第二条（.venv 不进仓库，可以是符号链接）。
# 实际用到的版本由 driver.py 读出来写进结果，与 requirements.txt 不一致时结果里会标出来。
here=$(dirname "$0")
if [ -n "${KAOJU_REQUESTS_PYTHON:-}" ]; then
    py=$KAOJU_REQUESTS_PYTHON
elif [ -x "$here/.venv/bin/python" ]; then
    py=$here/.venv/bin/python
else
    py=python3
fi
exec "$py" "$here/driver.py" "$@"
