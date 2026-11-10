#!/usr/bin/env python3
"""Python requests 的驱动（列 requests）。

用法（平时经 run.sh 启动，它负责找到装了 requirements.txt 的解释器）：
    driver.py <用例.json> <结果.json>
    driver.py --versions

约定见 research/phase2/PROTOCOL.md 的“驱动”一节；写法的出处见本目录的 NOTES.md。

做法（都会原样写进结果的 config 和 notes）：

- 一个用例一个 requests.Session()，从头用到尾，不挂自定义的 HTTPAdapter，不改任何默认值。
- 代理每次请求用 proxies= 传，http、https 两个键是同一个代理 URL；凭据写在代理 URL 里，
  用户名和密码各用 urllib.parse.quote(…, safe='') 转义。换用户就是换 proxies=。
- 信任测试 CA 用 verify=ca_file。超时用用例给的 timeout_s（requests 默认不超时）。
- 重定向保持默认（跟随），不传 allow_redirects。
- POST 把正文文件读成 bytes 用 data= 传，带 Content-Type: application/octet-stream。
- parallel 用标准库线程池共用同一个 Session，各线程在一道栅栏上等齐以后同时发出。
- 串行的步骤同时打开 http.client.HTTPConnection.debuglevel = 1（requests 文档 docs/api.rst 给的调试写法），
  它只往标准输出打印，不改变线上的字节；打印出来的东西是 extra_text。parallel 里不开（标准输出是进程级的，分不开）。
- 任何异常都记进所在的步骤，驱动自己正常退出。
"""

import contextlib
import hashlib
import io
import json
import os
import platform
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

BODY_HEAD = 4096
EXTRA_LINE_MAX = 2000
EXTRA_HOW = (
    "http.client.HTTPConnection.debuglevel = 1（requests 文档 docs/api.rst“Migrating to 1.x”一节给出的调试写法）："
    "标准库把发出的请求头和收到的响应头打印到标准输出，驱动用 contextlib.redirect_stdout 接下来"
)
HERE = os.path.dirname(os.path.abspath(__file__))


def pinned():
    """requirements.txt 里钉的版本：{包名小写: 版本}。"""
    out = {}
    try:
        with open(os.path.join(HERE, "requirements.txt"), encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.split("#", 1)[0].strip()
                if "==" in ln:
                    name, _, ver = ln.partition("==")
                    out[name.strip().lower()] = ver.strip()
    except OSError:
        pass
    return out


def versions():
    import ssl
    from importlib import metadata

    v = {"python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION}
    want = pinned()
    diff = []
    for name in ("requests", "urllib3", "PySocks", "certifi", "charset-normalizer", "idna"):
        try:
            got = metadata.version(name)
        except Exception:  # 没装
            got = None
        v[name] = got
        w = want.get(name.lower())
        if w is not None and got != w:
            diff.append("%s：装的是 %s，requirements.txt 钉的是 %s" % (name, got, w))
    v["matches_requirements_txt"] = not diff
    if diff:
        v["requirements_txt_diff"] = diff
    return v


def proxy_url(px, user):
    """NOTES.md 第 1 节的写法。user 为 None 时不带用户信息；空密码保留冒号。"""
    if user is None:
        return "%s://%s:%s" % (px["scheme"], px["host"], px["port"])
    return "%s://%s:%s@%s:%s" % (
        px["scheme"],
        quote(user["user"], safe=""),
        quote(user["pass"], safe=""),
        px["host"],
        px["port"],
    )


def exc_text(e):
    """异常的类型和消息，沿 __cause__、__context__ 往下走。"""
    out, seen = [], set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        out.append("%s.%s: %s" % (type(e).__module__, type(e).__qualname__, e))
        e = e.__cause__ or e.__context__
    return "\n".join(out)


def clip_extra(text):
    """debuglevel 会把 POST 的正文整个 repr 出来；过长的行截短，其余原样。"""
    lines = []
    for ln in text.split("\n"):
        if len(ln) > EXTRA_LINE_MAX:
            ln = ln[:EXTRA_LINE_MAX] + "…（这一行共 %d 个字符，已截短）" % len(ln)
        lines.append(ln)
    return "\n".join(lines)


def call_text(case, st):
    """这一步实际的调用写法（记进 config）。"""
    method = st.get("method", "GET")
    user = None if st.get("user") is None else case["users"][st["user"]]
    p = proxy_url(case["proxy"], user)
    timeout = st.get("timeout_s", case.get("timeout_s", 15))
    if method == "GET":
        head = "s.get(%r" % st["url"]
    elif method == "POST":
        head = "s.post(%r" % st["url"]
    else:
        head = "s.request(%r, %r" % (method, st["url"])
    args = []
    if st.get("body_file"):
        args.append("data=open(%r, 'rb').read()" % st["body_file"])
        args.append("headers={'Content-Type': 'application/octet-stream'}")
    args.append("proxies={'http': %r, 'https': %r}" % (p, p))
    args.append("verify=%r" % case["ca_file"])
    args.append("timeout=%r" % timeout)
    return head + ", " + ", ".join(args) + ")"


def do_request(session, case, st, capture, gate=None):
    """发一个请求，返回这一步的结果。capture 为真时打开 debuglevel 并接住标准输出。"""
    import http.client

    res = {
        "id": st["id"],
        "op": "request",
        "ok": False,
        "status": None,
        "body_sha256": None,
        "ms": None,
        "default_text": None,
        "extra_text": None,
        "extra_how": None,
    }
    buf = io.StringIO()
    t0 = None
    try:
        with contextlib.ExitStack() as stack:
            if capture:
                stack.enter_context(contextlib.redirect_stdout(buf))
                http.client.HTTPConnection.debuglevel = 1
                stack.callback(setattr, http.client.HTTPConnection, "debuglevel", 0)
            method = st.get("method", "GET")
            user = None if st.get("user") is None else case["users"][st["user"]]
            p = proxy_url(case["proxy"], user)
            kwargs = {
                "proxies": {"http": p, "https": p},
                "verify": case["ca_file"],
                "timeout": st.get("timeout_s", case.get("timeout_s", 15)),
            }
            if st.get("body_file"):
                with open(st["body_file"], "rb") as fh:
                    kwargs["data"] = fh.read()
                kwargs["headers"] = {"Content-Type": "application/octet-stream"}
            if gate is not None:
                try:
                    gate.wait(timeout=10)
                except threading.BrokenBarrierError:
                    pass
            t0 = time.monotonic()
            if method == "GET":
                r = session.get(st["url"], **kwargs)
            elif method == "POST":
                r = session.post(st["url"], **kwargs)
            else:
                r = session.request(method, st["url"], **kwargs)
            body = r.content
            res["ms"] = int(round((time.monotonic() - t0) * 1000))
            lines = ["status_code: %d" % r.status_code, "reason: %s" % r.reason, "url: %s" % r.url]
            for h in r.history:
                lines.append("history: %d %s -> %s" % (h.status_code, h.url, h.headers.get("Location")))
            lines.append("headers:")
            lines += ["%s: %s" % (k, v) for k, v in r.headers.items()]
            lines.append("content（前 %d 字节）:" % BODY_HEAD)
            lines.append(body[:BODY_HEAD].decode("utf-8", "replace"))
            res["ok"] = True
            res["status"] = r.status_code
            res["body_sha256"] = hashlib.sha256(body).hexdigest()
            res["default_text"] = "\n".join(lines)
    except Exception as e:  # 不能只接 requests.RequestException：UnicodeEncodeError 等不是它的子类
        if t0 is not None:
            res["ms"] = int(round((time.monotonic() - t0) * 1000))
        res["ok"] = False
        res["default_text"] = exc_text(e)
    if capture:
        res["extra_text"] = clip_extra(buf.getvalue()) or "（debuglevel = 1 没有打印任何东西）"
        res["extra_how"] = EXTRA_HOW
    return res


def placeholder(st, op, **more):
    d = {
        "id": st["id"],
        "op": op,
        "ok": None,
        "status": None,
        "body_sha256": None,
        "ms": None,
        "default_text": None,
        "extra_text": None,
        "extra_how": None,
    }
    d.update(more)
    return d


def run_case(case):
    result = {
        "variant": case.get("variant") or "requests",
        "versions": None,
        "config": None,
        "unsupported": None,
        "steps": [],
        "notes": [],
    }
    result["versions"] = versions()
    if not result["versions"].get("matches_requirements_txt"):
        result["notes"].append(
            "解释器里装的版本与 requirements.txt 不一致：" + "；".join(result["versions"].get("requirements_txt_diff", []))
        )
    import requests

    cfg = [
        "import requests",
        "from concurrent.futures import ThreadPoolExecutor",
        "s = requests.Session()   # 整个用例只有这一个 Session，默认的 HTTPAdapter，什么都没改",
    ]
    for st in case.get("steps", []):
        op = st.get("op")
        if op == "request":
            cfg.append("%s: r = %s" % (st["id"], call_text(case, st)))
        elif op == "sleep":
            cfg.append("%s: time.sleep(%r)" % (st["id"], st.get("ms", 0) / 1000.0))
        elif op == "parallel":
            kids = st.get("steps", [])
            cfg.append(
                "%s: with ThreadPoolExecutor(max_workers=%d) as ex:   # 各线程等齐以后同时发出" % (st["id"], len(kids))
            )
            for kid in kids:
                cfg.append("    %s: ex.submit(lambda: %s)" % (kid["id"], call_text(case, kid)))
        else:
            cfg.append("%s: （%s：requests 没有对应的接口，没有发出任何东西）" % (st.get("id"), op))
    cfg.append(
        "代理 URL 的写法：scheme://quote(user, safe='')：quote(password, safe='')@host:port（没配凭据的步骤不带用户信息）"
    )
    result["config"] = "\n".join(cfg)
    result["notes"].append(
        "串行步骤发请求时同时打开了 http.client.HTTPConnection.debuglevel = 1，打印的内容在 extra_text；"
        "它只打印，不改变发出的字节。parallel 里的步骤没有开（extra_text 为空）。"
        "extra_text 里超过 %d 个字符的行（POST 正文的 repr）截短了。" % EXTRA_LINE_MAX
    )
    result["notes"].append(
        "default_text：成功时是 r.status_code、r.reason、r.url、r.history（有跳转时）、r.headers、r.content 的前 %d 字节；"
        "失败时是异常的类型和消息，沿 __cause__、__context__ 逐层列出。" % BODY_HEAD
    )

    session = requests.Session()
    try:
        for st in case.get("steps", []):
            op = st.get("op")
            if op == "request":
                result["steps"].append(do_request(session, case, st, True))
            elif op == "sleep":
                time.sleep(st.get("ms", 0) / 1000.0)
                result["steps"].append(placeholder(st, "sleep", ms=st.get("ms")))
            elif op == "parallel":
                kids = st.get("steps", [])
                result["steps"].append(placeholder(st, "parallel", children=[k["id"] for k in kids]))
                bad = [k for k in kids if k.get("op") != "request"]
                if bad or not kids:
                    for k in kids:
                        r = placeholder(k, k.get("op"))
                        r["ok"] = False
                        r["default_text"] = "驱动：parallel 里只支持 request 步骤，这一组没有发出"
                        result["steps"].append(r)
                    continue
                gate = threading.Barrier(len(kids))
                with ThreadPoolExecutor(max_workers=len(kids)) as ex:
                    futures = [ex.submit(do_request, session, case, k, False, gate) for k in kids]
                    for k, f in zip(kids, futures):
                        try:
                            result["steps"].append(f.result())
                        except Exception as e:
                            r = placeholder(k, "request")
                            r["ok"] = False
                            r["default_text"] = exc_text(e)
                            result["steps"].append(r)
            else:
                r = placeholder(st, op)
                r["ok"] = False
                r["default_text"] = "驱动：requests 没有 %s 对应的接口（它只做 HTTP 请求），这一步没有发出任何东西" % op
                result["steps"].append(r)
                if op == "ws" and not result["unsupported"]:
                    result["unsupported"] = "requests 不带 WebSocket 客户端，写不出这个用例的配置"
    finally:
        session.close()
    return result


def main(argv):
    if "--versions" in argv:
        json.dump(versions(), sys.stdout, ensure_ascii=False, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    rest = [a for a in argv if not a.startswith("--")]
    if len(rest) != 2:
        print("用法：driver.py <用例.json> <结果.json>", file=sys.stderr)
        return 2
    with open(rest[0], encoding="utf-8") as fh:
        case = json.load(fh)
    try:
        result = run_case(case)
    except Exception as e:  # 驱动自己的毛病也要落进结果，不能让进程崩掉
        result = {
            "variant": case.get("variant") or "requests",
            "versions": None,
            "config": None,
            "unsupported": None,
            "steps": [],
            "notes": [],
            "driver_error": exc_text(e) + "\n" + traceback.format_exc(),
        }
    tmp = rest[1] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    os.replace(tmp, rest[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
