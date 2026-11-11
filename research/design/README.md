# research/design

设计文档（`docs/design/`）的核对工具。设计文档本身不在这里。

| 文件 | 作用 |
| --- | --- |
| `check_design.py` | 核对设计文档里引用的第 2 阶段矩阵格子和规范条款号、1B 的数据（按键到 `research/phase1b/out/*.json` 里取值比对，相除的自己再除一遍）、INV / AC / DD 编号（不重复、有定义、每条不变量至少有一条验收标准）、相对链接、表格列数。只用标准库 |
| `check_config.py` | 核对 `docs/design/config.example.yaml` 符合 `config.schema.json`，并且 Schema 拒绝 13 种写错的配置。需要 jsonschema 和 PyYAML |

```sh
python3 research/design/check_design.py --selftest
python3 research/design/check_design.py
python3 research/design/check_config.py
```

CI 见 `.github/workflows/design.yml`。
