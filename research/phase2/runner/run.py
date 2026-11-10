#!/usr/bin/env python3
"""第 2 阶段的运行器：对每个（列、用例、第几遍）做一次互相隔离的运行。

用法：
    run.py [--variants curl,requests] [--cases 'A*,B02'] [--repeats N] [--jobs N]
           [--out DIR] [--work DIR] [--keep-pcap] [--tcpdump 'sudo tcpdump'] [--obsproxy PATH]

一次运行的步骤见 README.md；测量口径见 ../PROTOCOL.md。只用 Python 标准库。
"""

import argparse
import concurrent.futures
import datetime
import fcntl
import fnmatch
import gzip
import io
import json
import os
import platform
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback

RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))
P2_DIR = os.path.dirname(RUNNER_DIR)
REPO_DIR = os.path.dirname(os.path.dirname(P2_DIR))
HARNESS_DIR = os.path.join(P2_DIR, "harness")
CASES_PATH = os.path.join(P2_DIR, "cases.json")
REGISTRY_PATH = os.path.join(P2_DIR, "drivers", "registry.json")

# 默认的工作目录：这个工作区的会话临时目录；它不存在时（CI、别的机器）退回系统临时目录。
SCRATCH_ROOT = "/tmp/claude-0/-home-claude/c8383880-e9c9-5186-92ef-d48d2702f2fb/scratchpad"

READY_TIMEOUT_S = 15
TCPDUMP_READY_TIMEOUT_S = 15
SETTLE_S = 0.3
DRIVER_MARGIN_S = 30
STDERR_TAIL = 2000

_live = set()
_live_lock = threading.Lock()
_print_lock = threading.Lock()


def say(msg):
    with _print_lock:
        print(msg, flush=True)


def warn(msg):
    with _print_lock:
        print("警告：" + msg, file=sys.stderr, flush=True)


# ---------- 进程管理 ----------


class PortWindow:
    """端口窗口锁（跨线程、跨进程）。

    obsproxy 的端口由内核随机分配。一次运行停掉 obsproxy 之后、停掉抓包之前，它的端口已经放出去了，
    这时另一次运行的 obsproxy 要是恰好分到同一个端口，前一次的抓包就会录进后一次的流量，
    抓包核对会报出本不存在的不一致。所以“启动 obsproxy 直到它报出端口”和“停 obsproxy 直到停抓包”
    这两段用同一把文件锁互斥：抓包收尾期间，谁都不分配新端口。
    """

    PATH = os.path.join(tempfile.gettempdir(), "kaoju-phase2-ports.lock")

    def __init__(self):
        self.fd = None

    def __enter__(self):
        self.fd = os.open(self.PATH, os.O_RDWR | os.O_CREAT, 0o666)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None
        return False


def spawn(argv, **kw):
    """启动子进程（独立的会话，方便整组杀掉），并登记以便退出时清理。"""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, start_new_session=True, **kw)
    with _live_lock:
        _live.add(proc)
    return proc


def reap(proc):
    with _live_lock:
        _live.discard(proc)


def kill_group(proc, sig=signal.SIGKILL):
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, PermissionError):
            pass


def stop(proc, sig, wait_s):
    """发信号并等退出；不退出就杀掉。返回退出码。"""
    if proc.poll() is None:
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=wait_s)
        except subprocess.TimeoutExpired:
            kill_group(proc)
            proc.wait()
    reap(proc)
    return proc.returncode


def kill_all_live():
    with _live_lock:
        procs = list(_live)
    for proc in procs:
        if proc.poll() is None:
            kill_group(proc)


# ---------- 干净环境 ----------


def clean_env(home, work, extra=None):
    """被测客户端（以及仪器）看到的环境：只有这五个变量，加上注册表里声明的。"""
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": work,
    }
    if extra:
        env.update(extra)
    return env


def fill(text, subst):
    for key, val in subst.items():
        text = text.replace("{" + key + "}", val)
    return text


def driver_argv(entry, subst):
    """注册表里的 cmd：相对路径相对于 research/phase2/，可用 {ca_file} 等模板。"""
    argv = []
    for i, part in enumerate(entry["cmd"]):
        part = fill(str(part), subst)
        if "/" in part and not os.path.isabs(part) and not part.startswith("-"):
            cand = os.path.join(P2_DIR, part)
            if os.path.exists(cand):
                part = cand
        argv.append(part)
    return argv


def driver_env(entry, subst):
    return {str(k): fill(str(v), subst) for k, v in (entry.get("env") or {}).items()}


# ---------- 用例 ----------


def load_registry():
    with open(REGISTRY_PATH, encoding="utf-8") as fh:
        raw = json.load(fh)
    reg = {}
    for name, entry in raw.items():
        if name.startswith("_") or not isinstance(entry, dict) or "cmd" not in entry:
            continue  # 允许放说明性的键
        reg[name] = entry
    return reg


def body_bytes(n):
    """正文：第 i 个字节是 (i*131+7)%251（周期 251）。"""
    period = bytes((i * 131 + 7) % 251 for i in range(251))
    return (period * (n // 251 + 1))[:n]


def substitute(obj, ports):
    if isinstance(obj, str):
        return obj.replace("{origin_http_port}", str(ports["origin_http_port"])).replace(
            "{origin_https_port}", str(ports["origin_https_port"])
        )
    if isinstance(obj, list):
        return [substitute(x, ports) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute(v, ports) for k, v in obj.items()}
    return obj


def add_body_files(steps, run_dir):
    for st in steps:
        if st.get("op") == "parallel":
            add_body_files(st.get("steps", []), run_dir)
        n = st.get("body_bytes")
        if n is not None:
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(st.get("id", "x")))
            path = os.path.join(run_dir, "body-%s.bin" % safe)
            with open(path, "wb") as fh:
                fh.write(body_bytes(int(n)))
            st["body_file"] = path


def runtime_case(case, variant, ports, timeout_s, ca_file, home, driver_work, run_dir):
    rc = substitute(json.loads(json.dumps(case)), ports)
    add_body_files(rc.get("steps", []), run_dir)
    rc["variant"] = variant
    rc["proxy"] = {"scheme": case["proxy"], "host": "127.0.0.1", "port": ports["proxy_port"]}
    rc["ca_file"] = ca_file
    rc["home_dir"] = home
    rc["work_dir"] = driver_work
    rc["origin_http_port"] = ports["origin_http_port"]
    rc["origin_https_port"] = ports["origin_https_port"]
    rc["timeout_s"] = timeout_s
    return rc


def driver_budget(case, timeout_s):
    """驱动的总超时：顶层各步 timeout_s 之和（parallel 算一步，sleep 按它的时长），加 30 秒。"""
    total = 0.0
    for st in case.get("steps", []):
        if st.get("op") == "sleep":
            total += st.get("ms", 0) / 1000.0
        else:
            total += st.get("timeout_s", timeout_s)
    return total + DRIVER_MARGIN_S


# ---------- 抓包核对（容错导入） ----------

_pc_lock = threading.Lock()
_pc_state = {"tried": False, "mod": None, "why": None}


def pcap_check_module():
    with _pc_lock:
        if not _pc_state["tried"]:
            _pc_state["tried"] = True
            if RUNNER_DIR not in sys.path:
                sys.path.insert(0, RUNNER_DIR)
            try:
                import pcap_check  # noqa: PLC0415  另一个文件，可能还没写好

                if not callable(getattr(pcap_check, "check", None)):
                    raise ImportError("pcap_check 里没有 check 函数")
                _pc_state["mod"] = pcap_check
            except Exception as exc:  # 包括语法错误：对方可能写到一半
                _pc_state["why"] = "%s: %s" % (type(exc).__name__, exc)
        return _pc_state["mod"], _pc_state["why"]


def run_pcap_check(pcap_path, events_path):
    mod, why = pcap_check_module()
    if mod is None:
        return {"status": "missing", "why": why}
    try:
        res = mod.check(pcap_path, events_path)
        if not isinstance(res, dict) or "status" not in res:
            return {"status": "error", "problems": ["pcap_check.check 返回的不是约定的结构：%r" % (res,)]}
        return res
    except Exception as exc:
        return {"status": "error", "problems": ["pcap_check.check 抛出 %s: %s" % (type(exc).__name__, exc)]}


# ---------- 一次运行 ----------


def tail(path, n=STDERR_TAIL):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return ""
    return data.decode("utf-8", "replace")[-n:]


def read_ready_line(proc, timeout_s):
    """读 obsproxy 的就绪行。"""
    deadline = time.monotonic() + timeout_s
    buf = b""
    fd = proc.stdout.fileno()
    while b"\n" not in buf:
        left = deadline - time.monotonic()
        if left <= 0:
            raise RuntimeError("obsproxy 在 %d 秒内没有打印就绪行" % timeout_s)
        ready, _, _ = select.select([fd], [], [], left)
        if not ready:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            raise RuntimeError("obsproxy 没有打印就绪行就退出了（退出码 %s）" % proc.poll())
        buf += chunk
    return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))


def wait_tcpdump_listening(proc, err_path, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        text = tail(err_path, 4000)
        if "listening on" in text:
            return
        if proc.poll() is not None:
            raise RuntimeError("tcpdump 启动失败（退出码 %s）：%s" % (proc.returncode, text.strip()[-300:]))
        time.sleep(0.02)
    raise RuntimeError("tcpdump 在 %d 秒内没有打印 listening on" % timeout_s)


def tcpdump_stats(err_path):
    text = tail(err_path, 4000)
    out = {"captured": None, "received": None, "dropped": None}
    for key, pat in (
        ("captured", r"(\d+) packets? captured"),
        ("received", r"(\d+) packets? received by filter"),
        ("dropped", r"(\d+) packets? dropped by kernel"),
    ):
        m = re.search(pat, text)
        if m:
            out[key] = int(m.group(1))
    return out


def read_events(path, errors):
    events = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for no, line in enumerate(fh, 1):
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    errors.append("事件文件第 %d 行不是 JSON" % no)
                    events.append({"ev": "_unparsed", "raw": line[:2000]})
    except OSError as exc:
        errors.append("读不到事件文件：%s" % exc)
    if events:
        if events[0].get("ev") != "start":
            errors.append("事件文件不是以 start 开头")
        if events[-1].get("ev") != "end":
            errors.append("事件文件不是以 end 结尾（仪器没有正常退出）")
    return events


def one_run(ctx, variant, case, repeat):
    """做一次运行，返回一条记录。任何异常都收进记录的 runner_errors。"""
    rec = {
        "variant": variant,
        "case": case["id"],
        "repeat": repeat,
        "ports": None,
        "events": [],
        "result": None,
        "driver": {"exit": None, "timeout": False, "stderr_tail": ""},
        "tcpdump": {"captured": None, "received": None, "dropped": None},
        "pcap_check": None,
        "skipped": None,
        "runner_errors": [],
    }
    only = case.get("only") or []
    if only and variant not in only:
        rec["skipped"] = "only"
        rec["driver"] = None
        rec["tcpdump"] = None
        return rec

    errors = rec["runner_errors"]
    run_dir = os.path.join(ctx["work"], "runs", variant, "%s-r%d" % (case["id"], repeat))
    shutil.rmtree(run_dir, ignore_errors=True)
    os.makedirs(run_dir)
    home = os.path.join(run_dir, "home")
    driver_work = os.path.join(run_dir, "driver")
    os.makedirs(driver_work)
    shutil.copytree(ctx["home_template"], home, symlinks=True)

    profile_path = os.path.join(run_dir, "profile.json")
    events_path = os.path.join(run_dir, "events.jsonl")
    pcap_path = os.path.join(run_dir, "run.pcap")
    case_path = os.path.join(run_dir, "case.json")
    result_path = os.path.join(run_dir, "result.json")
    obs_err = os.path.join(run_dir, "obsproxy.stderr")
    td_err = os.path.join(run_dir, "tcpdump.stderr")
    drv_out = os.path.join(run_dir, "driver.stdout")
    drv_err = os.path.join(run_dir, "driver.stderr")

    timeout_s = case.get("timeout_s", ctx["timeout_s"])
    budget = driver_budget(case, timeout_s)
    obs = td = None
    keep = ctx["keep_pcap"]
    try:
        with open(profile_path, "w", encoding="utf-8") as fh:
            json.dump(case.get("profile", {}), fh, ensure_ascii=False)

        # 1. obsproxy（分配端口的这一段拿端口窗口锁，见 PortWindow）
        with PortWindow():
            with open(obs_err, "wb") as efh:
                obs = spawn(
                    [
                        ctx["obsproxy"],
                        "serve",
                        "-profile",
                        profile_path,
                        "-ca-dir",
                        ctx["ca_dir"],
                        "-events",
                        events_path,
                        "-max-seconds",
                        str(int(budget + 60)),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=efh,
                    cwd=run_dir,
                    env=clean_env(home, run_dir),
                )
            try:
                ports = read_ready_line(obs, READY_TIMEOUT_S)
            except Exception as exc:
                raise RuntimeError("%s；标准错误：%s" % (exc, tail(obs_err, 300).strip()))
        rec["ports"] = {k: ports[k] for k in ("proxy_port", "origin_http_port", "origin_https_port")}

        # 2. tcpdump：只抓这三个端口
        flt = "tcp and (port %d or port %d or port %d)" % (
            ports["proxy_port"],
            ports["origin_http_port"],
            ports["origin_https_port"],
        )
        td_argv = ctx["tcpdump"] + ["-i", "lo", "-n", "--immediate-mode", "-B", "32768", "-U", "-s", "0", "-w", pcap_path, flt]
        try:
            with open(td_err, "wb") as efh:
                td = spawn(td_argv, stdout=subprocess.DEVNULL, stderr=efh, cwd=run_dir)
            wait_tcpdump_listening(td, td_err, TCPDUMP_READY_TIMEOUT_S)
        except Exception as exc:
            errors.append("抓包没有启动：%s" % exc)
            if td is not None:
                stop(td, signal.SIGKILL, 2)
            td = None

        # 3. 运行时用例文件
        rc = runtime_case(case, variant, ports, timeout_s, ctx["ca_file"], home, driver_work, run_dir)
        with open(case_path, "w", encoding="utf-8") as fh:
            json.dump(rc, fh, ensure_ascii=False, indent=1)

        # 4. 驱动，在干净环境里
        entry = ctx["registry"][variant]
        subst = {"ca_file": ctx["ca_file"], "home": home, "work": run_dir, "repo": REPO_DIR}
        argv = driver_argv(entry, subst) + [case_path, result_path]
        env = clean_env(home, run_dir, driver_env(entry, subst))
        t0 = time.monotonic()
        try:
            with open(drv_out, "wb") as ofh, open(drv_err, "wb") as efh:
                drv = spawn(argv, stdout=ofh, stderr=efh, cwd=run_dir, env=env)
            try:
                rec["driver"]["exit"] = drv.wait(timeout=budget)
            except subprocess.TimeoutExpired:
                rec["driver"]["timeout"] = True
            finally:
                kill_group(drv)  # 驱动留下的子进程（浏览器、curl）一并清掉
                if rec["driver"]["timeout"]:
                    drv.wait()
                    rec["driver"]["exit"] = drv.returncode
                reap(drv)
        except OSError as exc:
            errors.append("驱动启动不了：%s" % exc)
        rec["driver"]["ms"] = int(round((time.monotonic() - t0) * 1000))
        rec["driver"]["stderr_tail"] = tail(drv_err)
        try:
            with open(result_path, encoding="utf-8") as fh:
                rec["result"] = json.load(fh)
        except (OSError, ValueError):
            rec["result"] = None  # 驱动崩溃或超时：小结里算在“驱动崩溃”“驱动超时”里，不算运行器出错

        # 5. 收尾：先停仪器，再停抓包
        time.sleep(SETTLE_S)
        with PortWindow():
            code = stop(obs, signal.SIGTERM, 10)
            obs = None
            if code != 0:
                errors.append("obsproxy 的退出码是 %s：%s" % (code, tail(obs_err, 300).strip()))
            time.sleep(SETTLE_S)
            if td is not None:
                stop(td, signal.SIGINT, 10)
                rec["tcpdump"] = tcpdump_stats(td_err)
                td = None
                if rec["tcpdump"]["captured"] is None:
                    errors.append("读不到 tcpdump 的统计：%s" % tail(td_err, 300).strip())

        rec["events"] = read_events(events_path, errors)

        # 6. 抓包核对
        if os.path.exists(pcap_path) and os.path.exists(events_path):
            rec["pcap_check"] = run_pcap_check(pcap_path, events_path)
        else:
            rec["pcap_check"] = {"status": "error", "problems": ["没有抓包文件或事件文件"]}
    except Exception as exc:
        errors.append("%s: %s" % (type(exc).__name__, exc))
        errors.append(traceback.format_exc(limit=3)[-600:])
        keep = True
    finally:
        for proc, sig in ((obs, signal.SIGTERM), (td, signal.SIGINT)):
            if proc is not None:
                try:
                    stop(proc, sig, 5)
                except Exception:
                    pass
        if rec["pcap_check"] is None:
            rec["pcap_check"] = {"status": "error", "problems": ["运行没有走到抓包核对"]}
        # 没通过核对的运行要查原因，抓包留着；其余默认删除
        if rec["pcap_check"].get("status") in ("mismatch", "error"):
            keep = True
        try:
            shutil.rmtree(home, ignore_errors=True)
            if not keep:
                shutil.rmtree(run_dir, ignore_errors=True)
        except Exception:
            pass
    return rec


# ---------- 启动准备 ----------


def run_quiet(argv, env=None, cwd=None, timeout=300):
    return subprocess.run(
        argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout
    )


def prepare(args, work):
    """构建 obsproxy、生成 CA、准备 home 模板。返回上下文。"""
    os.makedirs(work, exist_ok=True)
    if args.obsproxy:
        obsproxy = os.path.abspath(args.obsproxy)
    else:
        obsproxy = os.path.join(work, "obsproxy")
        # 构建需要出网之外的普通环境（GOCACHE 等），不用干净环境
        res = run_quiet(["go", "build", "-trimpath", "-o", obsproxy, "."], cwd=HARNESS_DIR, timeout=600)
        if res.returncode != 0:
            raise SystemExit("构建 obsproxy 失败：\n" + res.stderr)
    ca_dir = os.path.join(work, "ca")
    os.makedirs(ca_dir, exist_ok=True)
    setup_home = os.path.join(work, "setup-home")
    os.makedirs(setup_home, exist_ok=True)
    env = clean_env(setup_home, work)
    res = run_quiet([obsproxy, "gen-ca", "-dir", ca_dir], env=env)
    if res.returncode != 0:
        raise SystemExit("obsproxy gen-ca 失败：\n" + res.stderr)
    ca_file = os.path.join(ca_dir, "ca.pem")

    template = os.path.join(work, "home-template")
    shutil.rmtree(template, ignore_errors=True)
    os.makedirs(template)
    certutil = shutil.which("certutil")
    nss = False
    if certutil:
        nssdb = os.path.join(template, ".pki", "nssdb")
        os.makedirs(nssdb)
        steps = [
            [certutil, "-d", "sql:" + nssdb, "-N", "--empty-password"],
            [certutil, "-d", "sql:" + nssdb, "-A", "-n", "kaoju-phase2-test-ca", "-t", "C,,", "-i", ca_file],
        ]
        nss = True
        for argv in steps:
            res = run_quiet(argv, env=env)
            if res.returncode != 0:
                nss = False
                warn("certutil 失败，Chromium 不会信任测试 CA：%s" % (res.stderr.strip() or res.stdout.strip()))
                break
    else:
        warn("没有 certutil，跳过 NSS 数据库；Chromium 不会信任测试 CA")

    res = run_quiet([obsproxy, "version"], env=env)
    return {
        "work": work,
        "obsproxy": obsproxy,
        "obsproxy_version": res.stdout.strip(),
        "ca_dir": ca_dir,
        "ca_file": ca_file,
        "home_template": template,
        "setup_home": setup_home,
        "nssdb": nss,
    }


def collect_versions(ctx, variants, out_dir):
    path = os.path.join(out_dir, "versions.json")
    doc = {"variants": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            old = json.load(fh)
        if isinstance(old.get("variants"), dict):
            doc["variants"] = old["variants"]  # 没在这次运行里的列保留原记录
    except (OSError, ValueError):
        pass
    subst = {"ca_file": ctx["ca_file"], "home": ctx["setup_home"], "work": ctx["work"], "repo": REPO_DIR}
    for variant in variants:
        entry = ctx["registry"][variant]
        info = {"desc": entry.get("desc"), "cmd": entry["cmd"]}
        try:
            res = run_quiet(
                driver_argv(entry, subst) + ["--versions"],
                env=clean_env(ctx["setup_home"], ctx["work"], driver_env(entry, subst)),
                cwd=ctx["work"],
                timeout=120,
            )
            if res.returncode != 0:
                raise RuntimeError("退出码 %s：%s" % (res.returncode, res.stderr.strip()[-300:]))
            info["versions"] = json.loads(res.stdout)
        except Exception as exc:
            info["versions"] = None
            info["error"] = "%s: %s" % (type(exc).__name__, exc)
            warn("%s 的 --versions 失败：%s" % (variant, info["error"]))
        doc["variants"][variant] = info

    os_name = None
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    td_version = None
    try:
        res = run_quiet(ctx["tcpdump"] + ["--version"], timeout=30)
        td_version = [ln.strip() for ln in (res.stdout + res.stderr).splitlines() if ln.strip()]
    except Exception as exc:
        warn("读不到 tcpdump 的版本：%s" % exc)
    # 不记录主机名、用户名、IP
    doc["env"] = {
        "os": os_name,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "obsproxy": ctx["obsproxy_version"],
        "tcpdump": td_version,
        "nssdb": ctx["nssdb"],
        "run_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    write_atomic(path, (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8"))


# ---------- 输出 ----------


def write_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def load_raw(path):
    recs = {}
    if not os.path.exists(path):
        return recs
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    recs[(rec["case"], rec["repeat"])] = rec
    except (OSError, ValueError, KeyError, EOFError) as exc:
        bad = path + ".bad"
        warn("已有的 %s 读不了（%s），改名为 %s 后重写" % (path, exc, bad))
        os.replace(path, bad)
        return {}
    return recs


def write_raw(path, recs):
    buf = io.BytesIO()
    # mtime 固定为 0、不写文件名：同样的记录得到同样的字节
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz:
        for key in sorted(recs):
            line = json.dumps(recs[key], ensure_ascii=False, separators=(",", ":"))
            gz.write(line.encode("utf-8") + b"\n")
    write_atomic(path, buf.getvalue())


def summarize(variant, recs):
    s = {
        "列": variant,
        "运行": 0,
        "跳过": 0,
        "核对通过": 0,
        "prefix": 0,
        "mismatch": 0,
        "核对出错": 0,
        "无核对器": 0,
        "驱动超时": 0,
        "驱动崩溃": 0,
        "丢包": 0,
        "运行器出错": 0,
    }
    for rec in recs:
        if rec.get("skipped"):
            s["跳过"] += 1
            continue
        s["运行"] += 1
        status = (rec.get("pcap_check") or {}).get("status")
        if status in ("ok", "prefix"):
            s["核对通过"] += 1
            if status == "prefix":
                s["prefix"] += 1
        elif status == "mismatch":
            s["mismatch"] += 1
        elif status == "missing":
            s["无核对器"] += 1
        else:
            s["核对出错"] += 1
        drv = rec.get("driver") or {}
        if drv.get("timeout"):
            s["驱动超时"] += 1
        elif drv.get("exit") != 0 or rec.get("result") is None:
            s["驱动崩溃"] += 1
        td = rec.get("tcpdump") or {}
        # 只看 dropped by kernel。回环网卡上 received by filter 恒为 captured 的两倍（每个包进出各算一次），不是丢包
        if td.get("dropped"):
            s["丢包"] += 1
        if rec.get("runner_errors"):
            s["运行器出错"] += 1
    return s


def print_summary(rows):
    if not rows:
        return
    cols = list(rows[0].keys())

    def width(text):
        return sum(2 if ord(ch) > 0x2E7F else 1 for ch in str(text))

    widths = [max(width(c), max(width(r[c]) for r in rows)) for c in cols]

    def fmt(vals):
        return "  ".join(str(v) + " " * (w - width(v)) for v, w in zip(vals, widths))

    say("")
    say("小结（核对通过 = ok 加 prefix；prefix 一栏是其中的 prefix 数）")
    say(fmt(cols))
    for r in rows:
        say(fmt([r[c] for c in cols]))


# ---------- 主流程 ----------


def parse_args(argv):
    ap = argparse.ArgumentParser(description="第 2 阶段的运行器")
    ap.add_argument("--variants", help="逗号分隔的列名；默认是注册表里的全部")
    ap.add_argument("--cases", help="逗号分隔的用例号，可用通配符，如 'A*,B02'；默认全部")
    ap.add_argument("--repeats", type=int, help="每个用例跑几遍；默认取 cases.json 的 repeats")
    ap.add_argument("--jobs", type=int, default=2, help="同时进行的运行数，默认 2")
    ap.add_argument("--out", default=os.path.join(P2_DIR, "out"), help="输出目录，默认 research/phase2/out")
    ap.add_argument("--work", help="工作目录；默认在临时目录下按时间戳新建")
    ap.add_argument("--keep-pcap", action="store_true", help="保留每次运行的工作目录（含抓包文件）")
    ap.add_argument("--tcpdump", default="tcpdump", help="tcpdump 命令，如 'sudo tcpdump'")
    ap.add_argument("--obsproxy", help="已构建好的 obsproxy；不给就现场构建")
    return ap.parse_args(argv)


def default_work():
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-%d" % os.getpid()
    if os.path.isdir(SCRATCH_ROOT):
        return os.path.join(SCRATCH_ROOT, "p2", "run", stamp)
    return os.path.join(tempfile.gettempdir(), "kaoju-p2", "run", stamp)


def main(argv):
    args = parse_args(argv)
    with open(CASES_PATH, encoding="utf-8") as fh:
        cases_doc = json.load(fh)
    registry = load_registry()

    variants = [v.strip() for v in args.variants.split(",") if v.strip()] if args.variants else list(registry)
    unknown = [v for v in variants if v not in registry]
    if unknown:
        raise SystemExit("注册表（drivers/registry.json）里没有这些列：%s" % "、".join(unknown))
    patterns = [p.strip() for p in args.cases.split(",") if p.strip()] if args.cases else ["*"]
    cases = [c for c in cases_doc["cases"] if any(fnmatch.fnmatchcase(c["id"], p) for p in patterns)]
    if not cases:
        raise SystemExit("没有用例匹配 %s" % args.cases)
    repeats = args.repeats if args.repeats is not None else int(cases_doc.get("repeats", 3))
    if repeats < 1 or args.jobs < 1:
        raise SystemExit("--repeats 和 --jobs 都要大于 0")

    work = os.path.abspath(args.work) if args.work else default_work()
    out_dir = os.path.abspath(args.out)
    say("工作目录：%s" % work)
    say("输出目录：%s" % out_dir)
    ctx = prepare(args, work)
    ctx.update(
        {
            "registry": registry,
            "timeout_s": cases_doc.get("timeout_s", 15),
            "keep_pcap": args.keep_pcap,
            "tcpdump": shlex.split(args.tcpdump),
        }
    )
    if not ctx["tcpdump"] or not shutil.which(ctx["tcpdump"][0]):
        raise SystemExit("找不到 tcpdump 命令：%s" % args.tcpdump)
    _, why = pcap_check_module()
    if why:
        warn("pcap_check 用不了，抓包核对记为 missing：%s" % why)
    say("仪器：%s" % ctx["obsproxy_version"])
    os.makedirs(os.path.join(out_dir, "raw"), exist_ok=True)
    collect_versions(ctx, variants, out_dir)

    tasks = [(v, c, r) for v in variants for c in cases for r in range(1, repeats + 1)]
    say("共 %d 次运行（%d 列 × %d 个用例 × %d 遍），同时 %d 个" % (len(tasks), len(variants), len(cases), repeats, args.jobs))
    done = {v: {} for v in variants}
    interrupted = False
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs)
    futures = {}
    try:
        for v, c, r in tasks:
            futures[pool.submit(one_run, ctx, v, c, r)] = (v, c, r)
        n = 0
        for fut in concurrent.futures.as_completed(futures):
            v, c, r = futures[fut]
            n += 1
            try:
                rec = fut.result()
            except Exception as exc:  # one_run 自己兜了底，这里是最后一道
                rec = {
                    "variant": v,
                    "case": c["id"],
                    "repeat": r,
                    "ports": None,
                    "events": [],
                    "result": None,
                    "driver": {"exit": None, "timeout": False, "stderr_tail": ""},
                    "tcpdump": {"captured": None, "received": None, "dropped": None},
                    "pcap_check": {"status": "error", "problems": ["运行器异常"]},
                    "skipped": None,
                    "runner_errors": ["%s: %s" % (type(exc).__name__, exc)],
                }
            done[v][(rec["case"], rec["repeat"])] = rec
            if rec.get("skipped"):
                state = "跳过（%s）" % rec["skipped"]
            else:
                drv = rec.get("driver") or {}
                state = "核对 %s，驱动 %s" % (
                    (rec.get("pcap_check") or {}).get("status"),
                    "超时" if drv.get("timeout") else "退出码 %s" % drv.get("exit"),
                )
                if rec.get("runner_errors"):
                    state += "，运行器出错：%s" % rec["runner_errors"][0][:200]
            say("[%d/%d] %s %s 第 %d 遍：%s" % (n, len(tasks), v, rec["case"], rec["repeat"], state))
    except KeyboardInterrupt:
        interrupted = True
        warn("被中断：停掉子进程，把已经完成的运行写出去")
        for fut in futures:
            fut.cancel()
        kill_all_live()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        kill_all_live()

    rows = []
    for v in variants:
        path = os.path.join(out_dir, "raw", v + ".jsonl.gz")
        try:
            merged = load_raw(path)
            merged.update(done[v])  # 同一个 用例+遍数 的旧记录被替换
            write_raw(path, merged)
        except Exception as exc:
            warn("写 %s 失败：%s" % (path, exc))
        rows.append(summarize(v, done[v].values()))
    print_summary(rows)
    if not args.keep_pcap:
        for name in ("home-template", "setup-home"):
            shutil.rmtree(os.path.join(work, name), ignore_errors=True)
    if interrupted:
        return 130
    return 1 if any(r["运行器出错"] for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
