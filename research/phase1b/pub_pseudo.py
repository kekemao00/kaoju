#!/usr/bin/env python3
"""公开库用的假名：带密钥、确定、单向。只用标准库。

规则（`PUBLIC.md`“假名”一节）：

- **标识**（候选键里的节点编号、nonce、证据哈希、叶子证书哈希等）：HMAC-SHA256(密钥, 类别 ‖ 0 ‖ 原值) 的十六进制，
  截到与原值一样长。同一类别里相等的原值得到相等的假名，不同类别之间互不相干。
- **IPv4**：公网地址换进 240.0.0.0/4（保留地址段，不会与真实主机相撞）。同一个真实 /24 里的地址落进同一个假 /24，
  最后一个字节在这个 /24 里按密钥打乱。假 /24 的编号 = 把数据里出现过的全部真实 /24 按 HMAC 排序后的名次，
  所以编号只泄露“一共有多少个 /24”。保留地址段里的真实地址（内网、回环等）不指向任何人，原样保留；
  只有本来就落在 240.0.0.0/4 里的（列表里的垃圾条目）挪到 0.0.0.0/8，免得与假名混在一起。
- **judge 自己的地址**：不进上面的映射（进了的话，与它同一个 /24 的代理一旦被认出，judge 的 /24 就跟着露了），
  固定换成 240.0.0.101 起的几个地址。回环地址原样保留。
- **IPv6**：换成 2001:db8::/32（文档用地址段）里的地址，后 96 位取 HMAC；不保留任何结构。

密钥不进仓库，也不进公开库。没有密钥，假名对不回原值；但候选来自公开列表，拿列表的提交历史和公开库里的上榜时刻、端口去对，
大部分候选是认得出来的（`PUBLIC.md`“挡不住什么”）。
"""
import hashlib
import hmac
import ipaddress
import sys

# lists.go 的 reserved，与 m_freshness.RESERVED_V4、m_labels.RESERVED_V4 相同
RESERVED_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
               "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
               "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]
PSEUDO_V4 = "240.0.0.0/4"          # 假名地址段；分析脚本在公开库上把它当公网地址（pubdb.py）
PSEUDO_V6 = "2001:db8::/32"
JUDGE_FIRST = 101                  # judge 的地址：240.0.0.101、240.0.0.102……三位数，互相不是对方的子串

_RESERVED = [ipaddress.ip_network(s) for s in RESERVED_V4]
_PSEUDO4 = ipaddress.ip_network(PSEUDO_V4)
_LOOP = ipaddress.ip_network("127.0.0.0/8")


class Pseudo:
    def __init__(self, key):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("密钥至少 32 字节")
        self.key = key
        self.slot = {}       # 真实 /24（"a.b.c"）→ 假 /24 的编号（1 起）
        self.judge = {}      # judge 的地址 → 假名
        self.keep24 = {}     # 真实 /24 → 公开库的 prefix24 列里写什么（out/ 里已经点了名的保持原样）
        self._perm = {}
        self._frozen = False

    # ---- 标识

    def mac(self, kind, value):
        return hmac.new(self.key, kind.encode() + b"\0" + value.encode("utf-8", "surrogatepass"), hashlib.sha256).digest()

    def ident(self, kind, value, length=None):
        """与原值一样长的十六进制假名（原值比 64 个字符长时给 64 个）。None 和空串原样返回。"""
        if value is None or value == "":
            return value
        n = min(64, length or len(value))
        return self.mac(kind, value).hex()[:n]

    # ---- IPv4

    def prepare(self, ipv4s, judge_ips, named24=()):
        """第一遍：登记数据里出现过的全部 IPv4（字符串）和 judge 的地址。之后 ip() 才可用。
        named24 是 out/ 里已经点了名的真实 /24（"a.b.c.0/24"），公开库的 prefix24 列里保持原样。"""
        pub24 = set()
        for s in ipv4s:
            a = _v4(s)
            if a is None or _reserved(a):
                continue
            pub24.add(_p24(a))
        jd = []
        for s in judge_ips:
            a = _parse(s)
            if a is None or (a.version == 4 and a in _LOOP) or (a.version == 6 and a.is_loopback):
                continue
            jd.append(str(a))
        for i, s in enumerate(sorted(set(jd), key=lambda x: self.mac("judge-ip", x))):
            if JUDGE_FIRST + i > 254:
                raise ValueError("judge 的地址太多")
            self.judge[s] = "240.0.0.%d" % (JUDGE_FIRST + i)
        # judge 所在的 /24 仍然参加排序（里面可能有代理），但 judge 自己的地址不经过它
        for i, p in enumerate(sorted(pub24, key=lambda x: self.mac("p24", x)), 1):
            if i >= 1 << 20:
                raise ValueError("公网 /24 超过 2^20 个，240.0.0.0/4 放不下")
            self.slot[p] = i
        self.keep24 = {}
        for name in named24:
            p = name[:-len(".0/24")] if name.endswith(".0/24") else None
            if p is None or p not in self.slot:
                raise ValueError("点了名的 /24 不在数据里：%r" % name)
            self.keep24[p] = name
        self._frozen = True

    def _octet(self, p24, last):
        perm = self._perm.get(p24)
        if perm is None:
            order = sorted(range(256), key=lambda o: self.mac("oct", "%s.%d" % (p24, o)))
            perm = [0] * 256
            for new, old in enumerate(order):
                perm[old] = new
            if len(self._perm) > 4096:
                self._perm.clear()
            self._perm[p24] = perm
        return perm[last]

    def ip(self, s):
        """地址字符串 → 假名。不是地址的原样返回 None（调用方决定怎么办）。"""
        if s is None:
            return None
        if not self._frozen:
            raise RuntimeError("先调用 prepare()")
        a = _parse(s)
        if a is None:
            return None
        key = str(a)
        if key in self.judge:
            return self.judge[key]
        if a.version == 6:
            if a.is_loopback or a.is_unspecified or a.is_link_local:
                return key
            if a.ipv4_mapped is not None:
                return "::ffff:" + self.ip(str(a.ipv4_mapped))
            tail = int.from_bytes(self.mac("ip6", key)[:12], "big")
            return str(ipaddress.IPv6Address((0x20010db8 << 96) | tail))
        if _reserved(a):
            if a in _PSEUDO4:      # 真实数据里落在假名地址段里的垃圾条目：挪到 0.0.0.0/8，仍然是保留地址
                d = self.mac("ip4-reserved", key)
                return "0.%d.%d.%d" % (d[0], d[1], d[2])
            return key
        p = _p24(a)
        i = self.slot.get(p)
        if i is None:
            raise KeyError("地址没有登记（prepare 时没见过它的 /24）")
        return "%d.%d.%d.%d" % (240 + (i >> 16), (i >> 8) & 255, i & 255, self._octet(p, int(a) & 255))

    def prefix24(self, s):
        """prefix24 列（"a.b.c.0/24"）→ 公开库里的写法：点了名的保持原样，其余换成假 /24。"""
        if s is None:
            return None
        if not s.endswith(".0/24"):
            raise ValueError("不是 /24 的写法")
        p = s[:-len(".0/24")]
        if p in self.keep24:
            return self.keep24[p]
        fake = self.ip(p + ".0")
        return fake.rsplit(".", 1)[0] + ".0/24"

    def cand(self, s, kind=None):
        """att.cand 一类的键：代理是 ip:port，节点是 12 位十六进制，对照组是 control:…（原样）。"""
        if s is None:
            return None
        if s.startswith("control:"):
            return s
        if kind == "node" or (kind is None and ":" not in s and "." not in s):
            return self.ident("node", s)
        host, sep, port = s.rpartition(":")
        if not sep:
            raise ValueError("候选键不是 ip:port")
        fake = self.ip(host.strip("[]"))
        if fake is None:
            raise ValueError("候选键里的主机不是地址")
        return ("[%s]:%s" % (fake, port)) if ":" in fake else "%s:%s" % (fake, port)


def _parse(s):
    try:
        return ipaddress.ip_address(s.strip())
    except (ValueError, AttributeError):
        return None


def _v4(s):
    a = _parse(s)
    return a if a is not None and a.version == 4 else None


def _reserved(a):
    return any(a in n for n in _RESERVED)


def _p24(a):
    return str(a).rsplit(".", 1)[0]


def is_ip(s):
    return _parse(s) is not None


# ---------------------------------------------------------------- 自检

def selftest():
    key = bytes(range(32))
    ps = Pseudo(key)
    real = ["198.51.100.7", "8.8.8.8", "8.8.8.9", "8.8.4.4", "1.2.3.4", "1.2.3.200", "10.0.0.5", "240.1.2.3", "9.9.9.9"]
    ps.prepare(real, ["9.9.9.9", "127.0.0.1", "10.0.0.5"], named24=["1.2.3.0/24"])
    fails = []

    def expect(what, got, want):
        if got != want:
            fails.append("%s：得到 %r，期望 %r" % (what, got, want))

    a, b, c = ps.ip("8.8.8.8"), ps.ip("8.8.8.9"), ps.ip("8.8.4.4")
    expect("同一个 /24 落在同一个假 /24", a.rsplit(".", 1)[0], b.rsplit(".", 1)[0])
    expect("同一个 /24 里不同地址假名不同", a != b, True)
    expect("不同 /24 落在不同的假 /24", a.rsplit(".", 1)[0] != c.rsplit(".", 1)[0], True)
    for x in (a, b, c):
        expect("假名在 240.0.0.0/4 里：" + x, ipaddress.ip_address(x) in _PSEUDO4, True)
        expect("假名不在 judge 的 /24 里：" + x, x.startswith("240.0.0."), False)
    expect("确定：再算一遍相同", ps.ip("8.8.8.8"), a)
    expect("回环原样", ps.ip("127.0.0.1"), "127.0.0.1")
    expect("文档地址原样", ps.ip("198.51.100.7"), "198.51.100.7")
    expect("judge 的公网地址是固定假名", ps.ip("9.9.9.9") in ("240.0.0.101", "240.0.0.102"), True)
    expect("judge 的内网地址也换掉", ps.ip("10.0.0.5") in ("240.0.0.101", "240.0.0.102"), True)
    expect("judge 的两个地址假名不同", ps.ip("9.9.9.9") != ps.ip("10.0.0.5"), True)
    expect("真实数据里的 240/4 挪到 0/8", ps.ip("240.1.2.3").startswith("0."), True)
    expect("点了名的 /24 保持原样", ps.prefix24("1.2.3.0/24"), "1.2.3.0/24")
    expect("没点名的 /24 换成假的", ps.prefix24("8.8.8.0/24"), a.rsplit(".", 1)[0] + ".0/24")
    expect("点了名的 /24 里的地址照样换假名", ipaddress.ip_address(ps.ip("1.2.3.4")) in _PSEUDO4, True)
    octs = {ps.ip("1.2.3.%d" % i).rsplit(".", 1)[1] for i in (4, 200)}
    expect("最后一个字节是置换（不相撞）", len(octs), 2)
    full = {ps._octet("1.2.3", i) for i in range(256)}
    expect("最后一个字节的置换是满射", len(full), 256)
    expect("代理候选键", ps.cand("8.8.8.8:3128"), a + ":3128")
    expect("对照组原样", ps.cand("control:public"), "control:public")
    n = ps.cand("0123456789ab", "node")
    expect("节点编号：12 位十六进制", (len(n), n != "0123456789ab", all(ch in "0123456789abcdef" for ch in n)), (12, True, True))
    v6 = ps.ip("2606:4700::1111")
    expect("IPv6 换进文档地址段", ipaddress.ip_address(v6) in ipaddress.ip_network(PSEUDO_V6), True)
    expect("标识：类别不同假名不同", ps.ident("nonce", "abcd1234") != ps.ident("ev", "abcd1234"), True)
    expect("标识：长度相同", len(ps.ident("ev", "a" * 64)), 64)
    expect("标识：空值原样", (ps.ident("ev", None), ps.ident("ev", "")), (None, ""))
    other = Pseudo(bytes(range(1, 33)))
    other.prepare(real, ["9.9.9.9"], named24=[])
    expect("换一把密钥假名不同", other.ip("8.8.8.8") != a or other.ident("ev", "x" * 64) != ps.ident("ev", "x" * 64), True)
    try:
        ps.ip("5.6.7.8")
        fails.append("没登记的地址应该报错")
    except KeyError:
        pass
    try:
        Pseudo(b"short")
        fails.append("短密钥应该报错")
    except ValueError:
        pass
    for f in fails:
        print("不符：" + f, file=sys.stderr)
    print("pub_pseudo 自检：%s" % ("通过" if not fails else "%d 项不符" % len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(selftest())
