# 生成 research/phase2/rows.json：矩阵的行表（取数之前写定）。
import json, sys
rows = []
def row(rid, section, title, cases, how, values):
    rows.append({"id": rid, "section": section, "title": title, "cases": cases, "how": how, "values": values})

VIS = "把看得见的按“状态码、原因短语、响应头、正文”的顺序用顿号连起来；一样都看不见写“都看不到”"
VIS_HOW = ("在这一步的 {f} 里找：状态码看 \\b{code}\\b 是否出现；原因短语看 KaojuReasonMarker；"
           "响应头看 KaojuHeaderMarker 或 KaojuStatusMarker；正文看 KaojuBodyMarker。")
SURF = ["拿到 {c} 响应", "报错，提到 {c}", "报错，没提 {c}"]
def surf(c): return [s.format(c=c) for s in SURF]
SURF_HOW = "驱动结果里这一步 ok 为真且 status 等于 {c}，是“拿到 {c} 响应”；ok 为假时看 default_text 里有没有 \\b{c}\\b。其余情况原样写出 status。"

# ---------- 基线 ----------
s = "基线"
row("R01", s, "明文请求到达代理的形式", ["A01"],
    "找到带 k=A01.s1 的请求是怎么到的：代理端口上的 http_request 且 form=absolute；或先有到 80 端口的隧道、请求出现在隧道里的 origin_request；或源站端口上的直连。",
    ["绝对形式", "CONNECT 到 80 端口", "直连", "没到"])
row("R02", s, "明文请求里与连接有关的头", ["A01"],
    "取 R01 找到的那个请求的头，按出现顺序列出名字属于 Proxy-Connection、Connection、Keep-Alive、Via、Forwarded、X-Forwarded-For、TE、Upgrade、Proxy-Authorization 的，写成“名: 值”，用分号加空格连接（Proxy-Authorization 只写名字）。",
    ["（头的列表）", "无"])
row("R03", s, "CONNECT 请求行", ["A02"], "第一个 form=connect 的 http_request：目标、空格、版本。", ["（原样）", "没有 CONNECT"])
row("R04", s, "CONNECT 带的头", ["A02"], "同一个请求的头的名字，原大小写、原顺序，用逗号加空格连接。", ["（原样）"])
row("R05", s, "CONNECT 的 Host 头", ["A02"], "Host 头的值与请求目标逐字节相同是“同目标”。", ["同目标", "不同", "没有"])
row("R06", s, "隧道里客户端发的首包", ["A02"], "第一条隧道的 tunnel_first_bytes 的归类。", ["TLS ClientHello", "明文 HTTP", "其他"])
row("R07", s, "ClientHello 的长度", ["A02"],
    "TLS 记录长度加 5 个字节的记录头。按以太网上一个 TCP 包最多 1460 字节的载荷分两档；3 遍里的最小值和最大值另记在脚注。",
    ["不超过 1460 字节", "超过 1460 字节"])
row("R08", s, "隧道里提供的 ALPN", ["A02"], "ClientHello 里的 ALPN 列表，用逗号连接。", ["（原样）", "无"])
row("R09", s, "源站支持 h2 时实际用的协议", ["A02"], "带 k=A02.s1 的 origin_request 的协议。", ["HTTP/2.0", "HTTP/1.1"])
row("R10", s, "HTTPS 同一个源连续 3 次：隧道数", ["A03"], "tunnel_open 的个数。", ["（整数）"])
row("R11", s, "明文同一个源连续 3 次：代理连接数", ["A04"], "代理端口上 accept 的个数。", ["（整数）"])
row("R12", s, "HTTPS 两个源交替各 2 次：隧道数", ["A05"], "tunnel_open 的个数。", ["（整数）"])
row("R13", s, "明文两个源交替各 2 次：代理连接数", ["A06"], "代理端口上 accept 的个数。", ["（整数）"])
row("R14", s, "HTTPS 6 个并发（源站支持 h2）：隧道数", ["A07"], "tunnel_open 的个数。", ["（整数）"])
row("R15", s, "HTTPS 6 个并发（源站只说 HTTP/1.1）：隧道数", ["A08"], "tunnel_open 的个数。", ["（整数）"])
row("R16", s, "明文 6 个并发：代理连接数", ["A09"], "代理端口上 accept 的个数。", ["（整数）"])
row("R17", s, "目标是 localhost 的明文请求", ["A10"],
    "带 k 的请求出现在代理端口上是“经代理”；出现在源站端口的直连上是“直连”；都没有且驱动这一步失败是“报错”。", ["经代理", "直连", "报错"])
row("R18", s, "目标是 localhost 的 HTTPS 请求", ["A11"], "同 R17；经代理指请求出现在隧道里。", ["经代理", "直连", "报错"])
row("R19", s, "明文 POST 的正文怎么分帧", ["A12"], "带 k 的 http_request 有 Transfer-Encoding: chunked 是 chunked，否则看 Content-Length。", ["Content-Length", "chunked"])
row("R20", s, "2 MiB 的明文 POST 先不先发 Expect: 100-continue", ["A14"], "带 k 的 http_request 有没有 Expect 头。", ["发", "不发"])
row("R21", s, "ws:// 经代理的方式", ["A15"],
    "带 k=A15.w1 的请求：出现在到 80 端口的隧道里（origin_request）是第一种；出现在代理端口上的绝对形式请求里是第二种。",
    ["CONNECT 到 80 端口，隧道里明文升级", "绝对形式的 GET 加 Upgrade", "直连", "没到"])
row("R22", s, "wss:// 经代理的方式", ["A16"], "带 k=A16.w1 的请求出现在到 443 端口的隧道里，且隧道首包是 TLS。",
    ["CONNECT 到 443 端口，隧道里 TLS", "直连", "没到"])
row("R23", s, "代理连接上客户端发的第一个字节", ["A01", "A02", "S01"],
    "三个用例里第一条代理连接的 first_bytes 的第一个字节，可打印的写成字符，否则写两位十六进制，用“ / ”连接（顺序：明文、HTTPS、SOCKS5）。",
    ["（原样）"])

row("R24", s, "POST 的正文是否完整到达源站", ["A12", "A13", "A14"],
    "三个用例里带 k 的 origin_request 的正文长度和 SHA-256 与 run.py 生成的正文文件相同。", ["完整", "不完整（用例号）"])

# ---------- 认证 ----------
s = "认证"
FIRST = ["先带", "等 407 再带", "始终不带"]
row("R30", s, "明文：第一个请求带不带凭据", ["B01"],
    "代理端口上按时间第一个 http_request 的 auth 判定不是 none 就是“先带”；是 none 而后面有带凭据的请求是“等 407 再带”。", FIRST)
row("R31", s, "CONNECT：第一个 CONNECT 带不带凭据", ["B02"], "同 R30，看 form=connect 的请求。", FIRST)
RETRY = ["原连接", "新连接", "不适用", "没有重试"]
row("R32", s, "明文：407 之后的重试走哪条连接", ["B01"],
    "第一个收到 407 的请求和第一个带凭据的请求是否在同一条代理连接上。没有收到过 407 是“不适用”。", RETRY)
row("R33", s, "CONNECT：407 之后的重试走哪条连接", ["B02"], "同 R32。", RETRY)
row("R34", s, "明文：407 带 Connection: close", ["B03"], "驱动这一步 ok 且 status 为 200 是“成功”。没有收到过 407 是“不适用”。", ["成功", "失败", "不适用"])
row("R35", s, "CONNECT：407 带 Connection: close", ["B04"], "同 R34。", ["成功", "失败", "不适用"])
row("R36", s, "明文连续 3 次：代理收到的请求数 / 其中没带凭据的", ["B05"],
    "代理端口上 http_request 的总数，斜杠，其中 auth 判定为 none 的个数。", ["（n/m）"])
row("R37", s, "访问第二个源时 CONNECT 带不带凭据", ["B06"], "目标是 b.kaoju.test 的 CONNECT 里按时间第一个的 auth 判定。", ["先带", "等 407 再带"])
row("R38", s, "HTTPS 同一个源连续 3 次（要认证）：隧道数", ["B07"], "tunnel_open 的个数。", ["（整数）"])
row("R39", s, "代理凭据有没有被带到源站", ["B02", "B07", "B08", "B09", "B10", "B12"],
    "这些用例里隧道内或直连的 origin_request 有没有带 Proxy-Authorization 的。绝对形式的请求由仪器转给源站，不算。有的话列出用例号。", ["没有", "有（用例号）"])
row("R40", s, "三种重定向是否都走通", ["B08", "B09", "B10"], "三个用例里跳转后的请求（k 以 b 结尾）都到达源站且驱动拿到 200。", ["都成功", "失败（用例号）"])
row("R41", s, "明文，同一个进程两个用户交替", ["B11"],
    "每一步带 k 的、auth 判定为 ok 的 http_request，解出的用户名是否等于这一步该用的用户。驱动报 unsupported 是“不支持”。",
    ["各用各的凭据", "用错了凭据", "不支持"])
row("R42", s, "HTTPS，同一个进程两个用户交替", ["B12"],
    "每一步带 k 的 origin_request 所在的隧道，建立它的 CONNECT 解出的用户名是否等于这一步该用的用户。",
    ["各开各的隧道", "用了别人的隧道", "不支持"])
row("R43", s, "带正文的明文 POST 遇到认证：完整的正文发了几遍", ["B13"], "带 k 的 http_request 里正文长度等于 65536 的个数。", ["（整数）"])
row("R44", s, "HTTPS 6 个并发（要认证）：收到几个 407", ["B14"], "状态码是 407 的 http_response 的个数。", ["（整数）"])
row("R45", s, "没配凭据，明文：调用方看到什么", ["C01"], SURF_HOW.format(c=407), surf(407))
row("R46", s, "没配凭据，HTTPS：调用方看到什么", ["C02"], SURF_HOW.format(c=407), surf(407))
row("R47", s, "密码错，明文：带着凭据试了几次", ["C03"], "auth 判定不是 none 的 http_request 的个数。", ["（整数）"])
row("R48", s, "密码错，HTTPS：带着凭据试了几次", ["C04"], "同 R47。", ["（整数）"])
row("R49", s, "密码错，HTTPS，代理一直回 407：调用方看到什么", ["C04"], SURF_HOW.format(c=407), surf(407))
row("R50", s, "密码错，HTTPS，代理回 403：调用方看到什么", ["C05"], SURF_HOW.format(c=403), surf(403))
row("R51", s, "密码错，明文，代理回 403：调用方看到什么", ["C08"], SURF_HOW.format(c=403), surf(403))
row("R52", s, "代理没要求认证，明文请求带不带凭据", ["C06"], "代理端口上有没有 auth 判定不是 none 的 http_request。", ["带", "不带"])
row("R53", s, "代理没要求认证，CONNECT 带不带凭据", ["C07"], "同 R52。", ["带", "不带"])

# ---------- 用户名和密码的字节（HTTP 代理，Basic） ----------
s = "用户名和密码的字节（HTTP 代理）"
BYTES_HOW = ("取代理端口上最后一个带 Proxy-Authorization 的 http_request，把 Basic 后面的 base64 解开，"
             "与“用例里的用户名、冒号、密码”的 UTF-8 字节逐字节比较。没有任何带凭据的请求：驱动这一步失败是“客户端报错”，否则是“没发凭据”。"
             "变了的格子，实际收到的字节记在脚注。")
BYTES_VALUES = ["原样", "变了", "没发凭据", "客户端报错"]
D_TITLES = ["常见的参数写法（连字符）", "下划线、点、波浪号、等号、分号、逗号", "要转义的字符：@ % + / 和空格",
            "UTF-8 用户名，质询不带 charset", "UTF-8 用户名，质询带 charset=\"UTF-8\"", "用户名 255 字节",
            "用户名 256 字节", "用户名 1024 字节", "密码里有冒号、@、空格、%2F、加号", "空密码",
            "用户名里有冒号（“原样”指原样拼接，服务端只能按第一个冒号拆）"]
for i, t in enumerate(D_TITLES, 1):
    row(f"R{59 + i}", s, t, [f"D{i:02d}"], BYTES_HOW, BYTES_VALUES)

# ---------- 报错可见性 ----------
s = "代理报错时调用方能看到什么"
row("R80", s, "CONNECT 回 502：默认用法", ["E01"], VIS_HOW.format(f="default_text", code=502) + VIS, ["（列表）", "都看不到"])
row("R81", s, "CONNECT 回 502：加上需要主动打开的手段", ["E01"],
    VIS_HOW.format(f="default_text 和 extra_text", code=502) + VIS + "。驱动没有用任何额外手段（extra_text 为空）写“没有这样的手段”。",
    ["（列表）", "都看不到", "没有这样的手段"])
row("R82", s, "CONNECT 回 403：默认用法", ["E02"], VIS_HOW.format(f="default_text", code=403) + VIS, ["（列表）", "都看不到"])
row("R83", s, "CONNECT 回 503 带 Retry-After: 1：发了几次 CONNECT", ["E03"], "form=connect 的 http_request 的个数。", ["（整数）"])
row("R84", s, "CONNECT 成功时 200 里附加的头：默认用法", ["E04"], "default_text 里有没有 KaojuHeaderMarker 或 KaojuStatusMarker。", ["看得到", "看不到"])
row("R85", s, "CONNECT 成功时 200 里附加的头：加上需要主动打开的手段", ["E04"],
    "default_text 和 extra_text 里有没有那两个记号。extra_text 为空写“没有这样的手段”。", ["看得到", "看不到", "没有这样的手段"])
row("R86", s, "明文请求被代理回 403：默认用法", ["E05"], VIS_HOW.format(f="default_text", code=403) + VIS, ["（列表）", "都看不到"])
row("R87", s, "明文请求成功时代理附加的响应头：默认用法", ["E06"], "default_text 里有没有 KaojuHeaderMarker 或 KaojuStatusMarker。", ["看得到", "看不到"])
row("R88", s, "CONNECT 失败但代理没关连接：下一个 CONNECT 走哪条连接", ["E07"],
    "目标是 a.kaoju.test 的 CONNECT 与目标是 fail.kaoju.test 的 CONNECT 是否在同一条代理连接上。", ["原连接", "新连接", "没有第二个 CONNECT"])
row("R89", s, "CONNECT 失败之后，对另一个源的请求", ["E07"], "驱动的 s2 这一步 ok 且 status 为 200。", ["成功", "失败"])

# ---------- 断连与重发 ----------
s = "连接被关以后"
row("R90", s, "明文：空闲连接被代理关掉后再请求", ["F01"],
    "s2 成功且它的请求与 s1 的请求不在同一条代理连接上是第一种。", ["换新连接，成功", "失败"])
row("R91", s, "HTTPS：空闲隧道被代理关掉后再请求", ["F02"],
    "s2 成功且它的 origin_request 与 s1 的不在同一条隧道里是第一种。", ["换新隧道，成功", "失败"])
REPLAY_HOW = ("仪器的丢弃动作没有发生（action 事件里没有）写“未触发”。否则写：被丢弃的那一步的请求到达{where}的次数（含被丢弃的那次），"
              "逗号，驱动这一步是否 ok 且 status 为 200。")
REPLAY_VALUES = ["（n 次，成功）", "（n 次，失败）", "未触发"]
for rid, title, c, where in [
    ("R92", "明文，复用的连接，GET，连接被关（FIN）", "F03", "代理（带 k 的 http_request）"),
    ("R93", "明文，复用的连接，POST，连接被关（FIN）", "F04", "代理（带 k 的 http_request）"),
    ("R94", "HTTPS，复用的隧道，GET，隧道被切断（FIN）", "F05", "源站（带 k 的 origin_request）"),
    ("R95", "HTTPS，复用的隧道，POST，隧道被切断（FIN）", "F06", "源站（带 k 的 origin_request）"),
    ("R96", "明文，新连接上的第一个 GET，连接被关", "F07", "代理（带 k 的 http_request）"),
    ("R97", "HTTPS，新隧道里的第一个 GET，隧道被切断", "F08", "源站（带 k 的 origin_request）"),
    ("R98", "明文，复用的连接，GET，连接被复位（RST）", "F09", "代理（带 k 的 http_request）"),
    ("R99", "HTTPS，复用的隧道，GET，隧道被复位（RST）", "F10", "源站（带 k 的 origin_request）"),
]:
    row(rid, s, title + "：请求到达几次，结果", [c], REPLAY_HOW.format(where=where), REPLAY_VALUES)
row("R100", s, "CONNECT 发出后代理不回应就关连接：发了几次 CONNECT，结果", ["F11"],
    "form=connect 的 http_request 的个数，逗号，驱动这一步是否 ok 且 status 为 200。", ["（n 次，成功）", "（n 次，失败）"])
row("R101", s, "HTTPS（源站支持 h2），复用的隧道，GET，隧道被切断：请求到达几次，结果", ["F12"],
    REPLAY_HOW.format(where="源站（带 k 的 origin_request）"), REPLAY_VALUES)

# ---------- SOCKS5 ----------
s = "SOCKS5 入口"
ATYP = ["域名", "IPv4", "IPv6"]
row("R110", s, "没配凭据时提供的认证方法", ["S01"], "第一条 SOCKS5 连接的 socks5_greeting 里的方法，两位十六进制，用逗号连接。", ["（原样）"])
row("R111", s, "配了凭据时提供的认证方法", ["S05"], "同 R110。", ["（原样）", "不支持"])
row("R112", s, "socks5h：请求里的地址类型", ["S01"], "第一个 socks5_request 的地址类型。", ATYP)
row("R113", s, "socks5（客户端自己解析），目标是 localhost：请求里的地址类型", ["S03"],
    "同 R112。代理端口上没有连接而源站端口上有直连是“直连”；都没有是“没连代理”。", ATYP + ["直连", "没连代理"])
row("R114", s, "socks5（客户端自己解析），域名本机解析不了", ["S04"],
    "代理端口上没有任何连接且驱动这一步失败是第一种；socks5_request 的地址类型是域名是第二种。", ["没连代理就报错", "把域名交给了代理", "其他"])
row("R115", s, "SOCKS5 建好以后的首包（HTTPS）", ["S01"], "第一条隧道的 tunnel_first_bytes 的归类。", ["TLS ClientHello", "明文 HTTP", "其他"])
row("R116", s, "SOCKS5 建好以后的首包（明文）", ["S02"], "同 R115。", ["TLS ClientHello", "明文 HTTP", "其他"])
row("R117", s, "用户名密码认证，凭据正确", ["S05"], "驱动这一步 ok 且 status 为 200，且 socks5_auth 的状态是 0。", ["成功", "失败", "不支持"])
row("R118", s, "配了凭据而代理选了无认证", ["S06"], "驱动这一步 ok 且 status 为 200。", ["成功", "失败", "不支持"])
KW = "default_text 转小写后含有 auth、method、credential、password、认证、方法 之一是“提到认证或方法”"
row("R119", s, "代理回 0xFF（没有可接受的方法）时的报错", ["S07"], KW + "，否则是“只说失败”。", ["提到认证或方法", "只说失败"])
row("R120", s, "用户名密码不对时的报错", ["S08"], KW + "，否则是“只说失败”。", ["提到认证或方法", "只说失败", "不支持"])
row("R121", s, "应答码 2、4、5 的报错能否区分", ["S09", "S10", "S11"],
    "取三个用例里失败那一步的 default_text，去掉用例号（S09、S10、S11）和 3 位以上的数字串以后两两不同是“能区分”。", ["能区分", "不能区分"])
row("R122", s, "HTTPS 同一个源连续 3 次：SOCKS5 连接数", ["S12"], "代理端口上 accept 的个数。", ["（整数）"])
row("R123", s, "HTTPS 6 个并发（源站只说 HTTP/1.1）：SOCKS5 连接数", ["S13"], "代理端口上 accept 的个数。", ["（整数）"])
row("R124", s, "同一个进程两个用户交替", ["S14"],
    "每一步带 k 的 origin_request 所在的隧道，它那条连接的 socks5_auth 的用户名是否等于这一步该用的用户。", ["各开各的连接", "用了别人的连接", "不支持"])
S_BYTES_HOW = ("取最后一个 socks5_auth，用户名和密码的字节分别与用例里的 UTF-8 字节比较，两样都相同是“原样”。"
               "没有 socks5_auth：驱动这一步失败是“客户端报错”，否则是“没发凭据”。驱动报 unsupported 是“不支持”。")
S_TITLES = ["常见的参数写法（连字符）", "要转义的字符：@ % + / 和空格", "UTF-8 用户名", "用户名 255 字节",
            "用户名 256 字节（超出 RFC 1929 的上限）", "密码里有冒号、@、空格、%2F、加号", "空密码", "用户名里有冒号"]
for i, t in enumerate(S_TITLES):
    row(f"R{125 + i}", s, "SOCKS5 用户名密码：" + t, [f"S{15 + i}"], S_BYTES_HOW, BYTES_VALUES + ["不支持"])

ids = [r["id"] for r in rows]
assert len(ids) == len(set(ids))
cases = {c["id"] for c in json.load(open(sys.argv[2]))["cases"]}
used = {c for r in rows for c in r["cases"]}
assert used <= cases, used - cases
doc = {"version": "1.0",
       "说明": "矩阵的行表。每一行写明看哪些用例、怎样从事件和驱动结果里取值、可能的取值。取数之前写定；matrix.py 按 id 一行一个函数实现这里的规则。"
               "所有行通用：驱动报 unsupported 的写“不支持”，用例的 only 不含该列的写“不适用”，没通过抓包核对的写“未通过核对”。",
       "rows": rows}
json.dump(doc, open(sys.argv[1], "w"), ensure_ascii=False, indent=1)
print(len(rows), "rows; cases not referenced by any row:", sorted(cases - used))
