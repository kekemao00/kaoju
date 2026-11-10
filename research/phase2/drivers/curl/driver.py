#!/usr/bin/env python3
"""curl 命令行的驱动（列 curl、curl-anyauth）。

用法：
    driver.py [--variant curl|curl-anyauth] <用例.json> <结果.json>
    driver.py [--variant …] --versions

约定见 research/phase2/PROTOCOL.md 的“驱动”一节。只用 Python 标准库。

做法（都会原样写进结果的 config 和 notes）：

- 一个用例只启动一个 curl 进程，各步之间用 --next，这样连接缓存是同一个，看得到复用。
- parallel 步骤用 --parallel --parallel-max N（这两个选项是全局的，所以带 parallel 的用例里不能再有别的请求步骤）。
- sleep 步骤用 --rate：它规定相邻两次传输“开始时刻”的最小间隔，3000 毫秒写成 20/m。
  它也是全局的，所以只支持“每两个相邻请求之间恰好隔一个时长相同的 sleep”的用例（F01、F02 就是这样）。
- 代理用 -x，凭据用 -U 'user:pass'，不做任何转义；curl-anyauth 另加 --proxy-anyauth。信任测试 CA 用 --cacert。
- 每步的结果从 -w 写到标准错误的一行标记里取（%{json}），正文用 -o、响应头用 -D 落到每步各自的文件。
- 同一个进程里加了 -v --trace-ids：详细输出每行带 [传输号-连接号] 前缀，按传输号切给各步，作为 extra_text 的来源。
  没有前缀的行（curl: (N) …、Warning: …）是不加 -v 时也会打印的，归入 default_text。
"""

import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time

CURL_FIXED = "/usr/bin/curl"
VARIANTS = ("curl", "curl-anyauth")
MARK = "@@KAOJU-END"
BODY_HEAD = 4096
EXTRA_HOW = (
    "-v（加 --trace-ids 以便按传输切分）与 -D：同一个 curl 进程里打开详细输出，并把响应头另存到文件"
)

PREFIX_RE = re.compile(r"^\[(\d+)-(\d+|x)\] ?(.*)$", re.S)
MARK_RE = re.compile(re.escape(MARK) + r" (\S+) (\{.*\})\s*$", re.S)


def curl_path():
    if os.path.exists(CURL_FIXED):
        return CURL_FIXED
    found = shutil.which("curl")
    if not found:
        raise RuntimeError("找不到 curl")
    return found


def curl_versions():
    out = subprocess.run(
        [curl_path(), "--version"], capture_output=True, text=True, timeout=20
    ).stdout
    lines = out.splitlines()
    first = lines[0] if lines else ""
    v = {"curl": None, "curl_version_line": first, "python": platform.python_version()}
    m = re.match(r"curl (\S+)", first)
    if m:
        v["curl"] = m.group(1)
    for tok in first.split():
        if "/" in tok and not tok.startswith("("):
            name, _, ver = tok.partition("/")
            if name in ("libcurl", "OpenSSL", "nghttp2", "zlib"):
                v[name.lower()] = ver
    for ln in lines[1:]:
        key, _, val = ln.partition(":")
        key = key.strip()
        if key == "Release-Date":
            v["release_date"] = val.strip()
        elif key == "Protocols":
            v["protocols"] = val.split()
        elif key == "Features":
            v["features"] = val.split()
    return v


def rate_for(ms):
    """把毫秒数写成 --rate 的参数（每个单位时间内的次数必须是整数）。"""
    for unit_ms, unit in ((1000, "s"), (60000, "m"), (3600000, "h"), (86400000, "d")):
        if ms > 0 and unit_ms % ms == 0:
            return "%d/%s" % (unit_ms // ms, unit)
    return None


def plan(case):
    """把步骤排成 curl 的传输序列。返回 (传输列表, 模式, 额外信息, 不支持的原因)。"""
    steps = case.get("steps", [])
    transfers = []  # 每项是一个请求（或 ws）步骤
    has_parallel = False
    serial_requests = 0
    sleeps = []  # (位置, ms)：位置 = 它前面已有几个请求
    par_n = 0
    for st in steps:
        op = st.get("op")
        if op in ("request", "ws"):
            transfers.append(st)
            serial_requests += 1
        elif op == "parallel":
            has_parallel = True
            kids = st.get("steps", [])
            par_n = max(par_n, len(kids))
            for kid in kids:
                if kid.get("op") not in ("request", "ws"):
                    return [], None, {}, "parallel 里只支持 request 步骤"
                transfers.append(kid)
        elif op == "sleep":
            sleeps.append((len(transfers), int(st.get("ms", 0))))
        else:
            return [], None, {}, "不认识的步骤类型：%r" % (op,)
    info = {}
    if has_parallel:
        if serial_requests or sleeps or sum(1 for s in steps if s.get("op") == "parallel") > 1:
            return (
                [],
                None,
                {},
                "curl 的 --parallel 是全局选项：同一个进程里要么全部并发，要么全部串行，"
                "做不到“一部分步骤并发、另一部分串行”",
            )
        info["parallel_max"] = par_n
        return transfers, "parallel", info, None
    if sleeps:
        ms_set = {ms for _, ms in sleeps}
        positions = [pos for pos, _ in sleeps]
        want = list(range(1, len(transfers)))
        rate = rate_for(next(iter(ms_set))) if len(ms_set) == 1 else None
        if positions != want or rate is None:
            return (
                [],
                None,
                {},
                "curl 命令行没有“等一会儿”的写法，最接近的是全局的 --rate（相邻传输开始时刻的最小间隔）；"
                "它只能表达“每两个相邻请求之间隔同样长的时间”，这个用例的 sleep 安排不是这样",
            )
        info["rate"] = rate
        info["sleep_ms"] = next(iter(ms_set))
    return transfers, "serial", info, None


def build_argv(case, variant, transfers, mode, info, files):
    px = case["proxy"]
    proxy_url = "%s://%s:%s" % (px["scheme"], px["host"], px["port"])
    users = case.get("users", [])
    default_timeout = case.get("timeout_s", 15)
    argv = [curl_path(), "--no-progress-meter", "-v", "--trace-ids"]
    notes = []
    if mode == "parallel":
        argv += ["--parallel", "--parallel-max", str(info["parallel_max"])]
    if info.get("rate"):
        argv += ["--rate", info["rate"]]
    for i, st in enumerate(transfers):
        if i:
            argv.append("--next")
        f = files[st["id"]]
        argv += ["-x", proxy_url]
        if st.get("user") is not None:
            u = users[st["user"]]
            argv += ["-U", "%s:%s" % (u["user"], u["pass"])]
        if variant == "curl-anyauth":
            argv.append("--proxy-anyauth")
        argv += ["--cacert", case["ca_file"]]
        if st.get("follow"):
            argv.append("-L")
        method = st.get("method", "GET")
        if st.get("body_file"):
            argv += [
                "--data-binary",
                "@" + st["body_file"],
                "-H",
                "Content-Type: application/octet-stream",
            ]
            if method != "POST":
                argv += ["-X", method]
        elif method != "GET":
            argv += ["-X", method]
        url = st["url"]
        if re.search(r"[\[\]{}]", url):
            argv.append("--globoff")
            notes.append("步骤 %s 的 URL 里有括号，加了 --globoff" % st["id"])
        argv += [
            "--max-time",
            str(st.get("timeout_s", default_timeout)),
            "-o",
            f["body"],
            "-D",
            f["hdr"],
            "-w",
            "%{stderr}" + MARK + " " + st["id"] + " %{json}\\n",
            url,
        ]
    return argv, notes


def split_stderr(text, transfers):
    """把标准错误切给各步。

    返回 {步骤号: {"json": …, "plain": [不带前缀的行], "verbose": [去掉前缀的详细输出行]}} 和没归属的行。
    """
    per = {st["id"]: {"json": None, "plain": [], "verbose": []} for st in transfers}
    order = [st["id"] for st in transfers]
    xfer_to_step = {}
    pending_plain = []  # 还没遇到标记的无前缀行：归给下一个标记的那一步
    verbose_by_xfer = {}
    orphans = []
    for line in text.split("\n"):
        m = MARK_RE.search(line)
        if m:
            sid = m.group(1)
            before = line[: m.start()]
            if before.strip():
                pending_plain.append(before)
            try:
                js = json.loads(m.group(2))
            except ValueError:
                js = None
            if sid in per:
                per[sid]["json"] = js
                per[sid]["plain"] += pending_plain
                if isinstance(js, dict) and isinstance(js.get("xfer_id"), int):
                    xfer_to_step[js["xfer_id"]] = sid
            else:
                orphans += pending_plain
            pending_plain = []
            continue
        pm = PREFIX_RE.match(line)
        if pm:
            verbose_by_xfer.setdefault(int(pm.group(1)), []).append(pm.group(3))
        elif line.strip():
            pending_plain.append(line)
    orphans += pending_plain
    for xid, lines in sorted(verbose_by_xfer.items()):
        sid = xfer_to_step.get(xid)
        if sid is None and 0 <= xid < len(order) and per[order[xid]]["json"] is None:
            sid = order[xid]  # 没等到标记（比如被杀掉）：传输号按 URL 的先后分配
        if sid is None:
            orphans += ["[%d] %s" % (xid, ln) for ln in lines]
        else:
            per[sid]["verbose"] += lines
    return per, orphans


def read_bytes(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def step_result(st, part, files, proc_note):
    js = part["json"] if isinstance(part["json"], dict) else {}
    body = read_bytes(files["body"])
    hdr = read_bytes(files["hdr"])
    exitcode = js.get("exitcode")
    http_code = js.get("http_code") or 0
    got_marker = bool(js)
    ok = bool(got_marker and exitcode == 0 and http_code > 0)
    status = http_code if http_code > 0 else None
    lines = []
    if got_marker:
        lines.append("http_code（-w '%%{http_code}'）: %03d" % http_code)
        lines.append("退出码（这次传输）: %s" % exitcode)
    else:
        lines.append("这次传输没有结束（curl 没有打印 -w 的输出）")
    if proc_note:
        lines.append(proc_note)
    lines.append("标准错误:")
    lines += part["plain"] if part["plain"] else ["（空）"]
    lines.append("正文前 %d 字节:" % BODY_HEAD)
    if body is None:
        lines.append("（没有正文文件）")
    else:
        lines.append(body[:BODY_HEAD].decode("utf-8", "replace"))
    extra = ["-v 的输出（已去掉 --trace-ids 的前缀）:"]
    extra += part["verbose"] if part["verbose"] else ["（空）"]
    extra.append("-D 存下的响应头:")
    extra.append(hdr.decode("utf-8", "replace") if hdr else "（空）")
    res = {
        "id": st["id"],
        "ok": ok,
        "status": status,
        "body_sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
        "ms": int(round(js["time_total"] * 1000)) if isinstance(js.get("time_total"), (int, float)) else None,
        "default_text": "\n".join(lines),
        "extra_text": "\n".join(extra),
        "extra_how": EXTRA_HOW,
        "curl": {
            k: js.get(k)
            for k in (
                "exitcode",
                "errormsg",
                "http_code",
                "http_connect",
                "http_version",
                "num_connects",
                "num_redirects",
                "num_headers",
                "size_download",
                "size_upload",
                "time_total",
                "url_effective",
                "urlnum",
                "xfer_id",
                "conn_id",
            )
        }
        if got_marker
        else None,
    }
    return res


def run_case(case, variant):
    versions = curl_versions()
    result = {
        "variant": variant,
        "versions": versions,
        "config": None,
        "unsupported": None,
        "steps": [],
        "notes": [],
    }
    transfers, mode, info, why = plan(case)
    if why:
        result["unsupported"] = why
        return result
    work = case["work_dir"]
    os.makedirs(work, exist_ok=True)
    files = {}
    for st in transfers:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", st["id"])
        files[st["id"]] = {
            "body": os.path.join(work, "step-%s.body" % safe),
            "hdr": os.path.join(work, "step-%s.headers" % safe),
        }
    argv, notes = build_argv(case, variant, transfers, mode, info, files)
    result["config"] = shlex.join(argv)
    result["notes"] += notes
    result["notes"].append(
        "切分方法：curl 的 -w 在每次传输结束时往标准错误写一行标记（步骤号加 %{json}）；"
        "-v 的每一行由 --trace-ids 标上 [传输号-连接号]，按传输号归给各步（并发时也成立）；"
        "不带前缀的行（curl: (N) …、Warning: …）紧挨在所属传输的标记之前，归给那一步的 default_text。"
        "[N-x] 这种还没有连接号的行（查找可复用连接的过程）也按传输号归属。"
    )
    result["notes"].append(
        "default_text 不含 %{http_connect}；它和其余 -w 字段另放在每步的 curl 字段里，不参与取值。"
        "--no-progress-meter 只关掉进度表（正文用 -o 存文件时 curl 会往标准错误画进度表），报错和警告照常打印。"
    )
    if info.get("rate"):
        result["notes"].append(
            "sleep %d 毫秒用全局的 --rate %s 实现：它保证相邻两次传输的开始时刻至少相隔这么久"
            "（从上一次的开始算，不是从结束算；上一次传输只有几毫秒，差别可以忽略）。实测间隔以事件里的时刻为准。"
            % (info["sleep_ms"], info["rate"])
        )
    has_ws = any(st.get("op") == "ws" for st in transfers)
    if has_ws and "ws" not in (versions.get("protocols") or []):
        result["unsupported"] = (
            "这个 curl 构建不支持 ws://、wss://（curl --version 的 Protocols 里没有 ws）；"
            "仍然照常试了一次，报错记在步骤里"
        )
    default_timeout = case.get("timeout_s", 15)
    budget = sum(st.get("timeout_s", default_timeout) for st in transfers) + 20
    if info.get("rate"):
        budget += info["sleep_ms"] / 1000.0 * max(0, len(transfers) - 1)
    stdout_path = os.path.join(work, "curl.stdout")
    stderr_path = os.path.join(work, "curl.stderr")
    t0 = time.monotonic()
    killed = False
    exit_code = None
    with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=so, stderr=se, cwd=work)
        try:
            exit_code = proc.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            killed = True
            proc.kill()
            proc.wait()
    elapsed_ms = int(round((time.monotonic() - t0) * 1000))
    text = (read_bytes(stderr_path) or b"").decode("utf-8", "replace")
    per, orphans = split_stderr(text, transfers)
    result["process"] = {"exit": exit_code, "killed_after_s": budget if killed else None, "ms": elapsed_ms}
    if orphans:
        result["notes"].append("标准错误里没能归属到步骤的行：" + " | ".join(orphans)[:2000])
    stdout = read_bytes(stdout_path) or b""
    if stdout:
        result["notes"].append("标准输出不为空（%d 字节），前 200 字节：%r" % (len(stdout), stdout[:200]))
    proc_note = "驱动在 %d 秒后杀掉了 curl 进程" % budget if killed else None
    by_id = {st["id"]: step_result(st, per[st["id"]], files[st["id"]], proc_note) for st in transfers}
    for st in case.get("steps", []):
        op = st.get("op")
        if op in ("request", "ws"):
            result["steps"].append(by_id[st["id"]])
        elif op == "parallel":
            result["steps"].append(
                {
                    "id": st["id"],
                    "op": "parallel",
                    "ok": None,
                    "status": None,
                    "body_sha256": None,
                    "ms": None,
                    "default_text": None,
                    "extra_text": None,
                    "extra_how": None,
                    "children": [k["id"] for k in st.get("steps", [])],
                }
            )
            for kid in st.get("steps", []):
                result["steps"].append(by_id[kid["id"]])
        elif op == "sleep":
            result["steps"].append(
                {
                    "id": st["id"],
                    "op": "sleep",
                    "ok": None,
                    "status": None,
                    "body_sha256": None,
                    "ms": st.get("ms"),
                    "default_text": None,
                    "extra_text": None,
                    "extra_how": None,
                }
            )
    return result


def main(argv):
    args = list(argv)
    variant = None
    versions_only = False
    rest = []
    while args:
        a = args.pop(0)
        if a == "--variant":
            if not args:
                print("--variant 后面要跟列名", file=sys.stderr)
                return 2
            variant = args.pop(0)
        elif a.startswith("--variant="):
            variant = a.split("=", 1)[1]
        elif a == "--versions":
            versions_only = True
        else:
            rest.append(a)
    if versions_only:
        json.dump(curl_versions(), sys.stdout, ensure_ascii=False, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if len(rest) != 2:
        print("用法：driver.py [--variant curl|curl-anyauth] <用例.json> <结果.json>", file=sys.stderr)
        return 2
    with open(rest[0], encoding="utf-8") as fh:
        case = json.load(fh)
    variant = variant or case.get("variant") or "curl"
    if variant not in VARIANTS:
        print("不认识的列名：%s（只支持 %s）" % (variant, "、".join(VARIANTS)), file=sys.stderr)
        return 2
    result = run_case(case, variant)
    tmp = rest[1] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    os.replace(tmp, rest[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
