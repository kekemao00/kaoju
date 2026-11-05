# kaoju：给 Claude 会话的常驻说明

每个新会话先读 [`docs/HANDOFF.md`](docs/HANDOFF.md)，那里是当前状态、待办和已知的坑。
本文件只放不随进度变化的规矩。

## 项目是什么

面向不可信上游的代理池网关。规矩是“无征不信，孤证不立”：
上游代理说的每句话都由独立见证方核对，项目对外的每条声明都附第三方可以复现的证据。
用户要的是“更深入的版本，而不是更大的版本”：宁可砍功能，也不留下无法验证的声明。

## 协作方式

- 用中文回复和写文档；代码注释、提交信息也用中文。
- 用户把技术决定交给 Claude（“你来决定，我来协助你”）。能自己定的就定，把决定和理由记进
  `docs/decisions/README.md`；只有不可逆、并且两边都说得通的事才停下来问。
- 不直接往 `main` 提交。开分支、推送、开 PR，由用户合并。
- 每个结论标注证据（规范条款、源码路径、数据文件、测试名）；没有验证过的写“未验证”，不要写成已验证。
- 数字不手抄：报告里的数字由脚本生成（`research/census/report_tables.py`），改数据就重新生成。

## 不能做的事

- **仓库是公开的。** 实测服务器的域名、IP、登录凭据不写进仓库、文件、日志、提交信息或 PR。
  用户在对话里给出这些信息时，只在当次使用，不复述。
- 用户的邮箱只用来识别用户，不写进提交、配置或发给第三方服务。
- 探测只面向公开列表里的地址，并受 `research/fieldtest/PROTOCOL.md` 的限速约束。
  不做未授权访问，不帮人绕过访问控制。
- 除自检夹具（`internal/evil`）外，任何地方都不许用 `InsecureSkipVerify` 跳过证书校验。
- 不使用 sing-box 的名称给项目或产物命名（决策 D6）。
- 法律和许可证方面只陈述事实，注明“这不是法律意见”。

## 改动 fieldtest 之前

`research/fieldtest` 是测量仪器，测量口径事先写在 `PROTOCOL.md` 里。

- 改口径（判定类别、限速、调度间隔、指标定义）要同时改 `PROTOCOL.md`，并在其中记下版本和改动原因。
  72 小时实测开始之后不改口径；非改不可时，两段数据分开报告。
- 只用 Go 标准库，不引入第三方依赖。
- 提交前在 `research/fieldtest` 下跑：

  ```sh
  gofmt -l . && go vet ./...
  FIELDTEST_SINGBOX=/path/to/sing-box go test -race -count=1 ./...
  SINGBOX=/path/to/sing-box ./test/e2e.sh        # 约 5 分钟
  ```

  sing-box 用官方 1.14.4，SHA-256 在 `deploy/install.sh` 和 `.github/workflows/fieldtest.yml` 里。
- 改了会进部署包的文件就要升版本号重新打包：版本号只写在 `research/fieldtest/VERSION`，
  改它再运行 `./deploy/build-bundle.sh`（构建脚本和 CI 都从这个文件读），并告诉用户换包。
- 每个发给用户的包都要在构建它的提交上打标签 `fieldtest-vX.Y.Z`，并把包和两个二进制的 SHA-256 记进 `docs/HANDOFF.md`。
