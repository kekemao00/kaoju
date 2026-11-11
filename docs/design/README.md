# kaoju 设计文档

状态：草案，第 3 阶段（`docs/brief.md`“交付顺序”第 2、3 项）。网关还没有代码；本目录写的是“要做成什么样、凭什么这样做、怎样证明做到了”。

## 怎么读

| 顺序 | 文件 | 内容 |
| --- | --- | --- |
| 1 | [01-threat-model.md](01-threat-model.md) | 威胁模型、信任分层、每层的默认策略、不防什么 |
| 2 | [02-gateway.md](02-gateway.md) | 架构、入口、控制通道（用户名参数）、报错通道、对客户端的兼容承诺 |
| 3 | [03-sticky.md](03-sticky.md) | 粘性契约：状态机、不变量、换绑的两种策略 |
| 4 | [04-failures.md](04-failures.md) | 重试语义、失败分类法 |
| 5 | [05-routing.md](05-routing.md) | 选路、探测调度、出口观察、来源治理 |
| 6 | [06-config.md](06-config.md) | 配置文件、管理 API、指标；Schema 在 [config.schema.json](config.schema.json)，例子在 [config.example.yaml](config.example.yaml) |
| 7 | [07-acceptance.md](07-acceptance.md) | 验收标准：每条不变量和每个承诺对应的可证伪门槛，哪些门槛现在就能定、哪些要先做预实验 |
| 8 | [08-open.md](08-open.md) | 砍掉的功能、与题目默认决定的偏离、被否决的方案、还不确定的事 |

## 写法上的约定

- **编号。** 设计决定是 DD-n，不变量是 INV-n，验收标准是 AC-n。每条不变量至少有一条验收标准去证伪它。
- **证据。** 三种引用都由脚本核对（`research/design/check_design.py`）：
  - 第 2 阶段矩阵的格子写成 `R行[列]=值`，规范条款写条款号（如 9110-9.2.2-5），出处见 `docs/research/phase2-report.md`；
  - 1B 的数据写成“1B[模块 » 键 » …]=值”，放在反引号里，指 `research/phase1b/out/<模块>.json` 里的那个值；两个值相除写成“1B÷[甲 ÷ 乙]=百分数”，
    脚本自己再除一遍。出处见 `docs/research/phase1b-report.md`；
  - 竞品的做法引 `docs/research/phase1-report.md`。
- **设计参数不是测量值。** 超时、上限、间隔这些数是设计时选的，文中写明“设计参数”和选它的理由；
  凡是理由不是数据的，都标“**未验证**”，并在验收标准里说明怎样验证或者预实验之后怎样改。
- **不写做不到的话。** 网关看不见的东西（TLS 隧道里的状态码、客户端有没有校验证书）不作承诺，写在“不防什么”和 [08-open.md](08-open.md) 里。

## 核对

```sh
python3 research/design/check_design.py --selftest
python3 research/design/check_design.py          # 引用、编号、链接、表格的列数
python3 research/design/check_config.py          # 配置例子符合 Schema（需要 jsonschema 和 PyYAML）
```
