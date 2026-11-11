#!/usr/bin/env python3
"""核对 docs/design/config.example.yaml 符合 docs/design/config.schema.json，并且 Schema 确实会拒绝几种写错的配置。

需要 jsonschema 和 PyYAML（设计阶段的核对工具；网关本身的校验在第 4 阶段用 Go 实现）。
用法：python3 research/design/check_config.py      # 退出码 0 通过，1 不通过，2 缺依赖
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DESIGN = os.path.normpath(os.path.join(HERE, "..", "..", "docs", "design"))


def mutations(good):
    """（说明，改坏的配置）。每一个都必须被 Schema 拒绝。"""
    out = []

    def mut(desc, fn):
        c = copy.deepcopy(good)
        fn(c)
        out.append((desc, c))

    mut("不认识的顶层键", lambda c: c.update({"nope": 1}))
    mut("账号没有口令来源", lambda c: c["accounts"][0].pop("password_env"))
    mut("口令明文写在文件里", lambda c: c["accounts"][0].update({"password": "x"}))
    mut("账号并发上限低于 6", lambda c: c["accounts"][0].update({"max_connections": 5}))
    mut("会话标识里有连字符", lambda c: c["listen"][1]["session"].update({"session": "a-b"}))
    mut("不认识的换绑策略", lambda c: c["defaults"].update({"onfail": "silent"}))
    mut("探测速率超过 1B 用过的上限", lambda c: c["probe"].update({"rate": 100}))
    mut("同一个 /24 的并发超过 4", lambda c: c["probe"].update({"per_prefix24": 16}))
    mut("聚合器抽样超过测过的 5000", lambda c: c["sources"]["aggregators"].update({"sample": 50000}))
    mut("来源不是 https", lambda c: c["sources"]["lists"][0].update({"url": "http://example.org/x"}))
    mut("judge 没有公钥钉扎", lambda c: c["observers"]["judge"].pop("pin_sha256"))
    mut("不认识的选路策略", lambda c: c["routing"].update({"strategy": "fastest"}))
    mut("可信上游的地址明文写在文件里", lambda c: c["trusted"][0].update({"url": "socks5://u:p@h:1"}))
    return out


def main():
    try:
        import jsonschema
        import yaml
    except ImportError as e:
        print("check_config: 缺依赖：%s" % e, file=sys.stderr)
        return 2
    with open(os.path.join(DESIGN, "config.schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    with open(os.path.join(DESIGN, "config.example.yaml"), encoding="utf-8") as fh:
        good = yaml.safe_load(fh)
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    v = cls(schema)
    problems = ["例子不符合 Schema：%s（位置 %s）" % (e.message, "/".join(str(x) for x in e.absolute_path)) for e in v.iter_errors(good)]
    muts = mutations(good)
    for desc, bad in muts:
        if v.is_valid(bad):
            problems.append("Schema 没有拒绝：%s" % desc)
    for p in problems:
        print("check_config: %s" % p, file=sys.stderr)
    print("check_config: 例子 1 份，改坏的配置 %d 种，问题 %d 个" % (len(muts), len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
