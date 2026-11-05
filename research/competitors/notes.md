# 竞品拆解证据清单

核对日期 2026-11-05。每条结论对应一个提交号和文件路径，可以直接在对应仓库里打开核对。
“检索未命中”表示用所列关键字在非测试代码里没有找到，不等于证明不存在。

## Resin（Resinat/Resin，5473c7e，2026-10-21，MIT）

| 结论 | 位置 |
| --- | --- |
| HTTP 正向、SOCKS5、反向代理同端口，按首字节分流 | `DESIGN.md`“入站接入点” |
| 身份格式 `Platform.Account:TOKEN`，HTTP 与 SOCKS5 共用 | `DESIGN.md`“业务身份如何稳定映射到网络身份”；`internal/proxy/forward.go` `authenticateV1` |
| 租约绑定出口 IP；固定过期、不续期；默认 168 小时 | `DESIGN.md`“租约的过期清理机制”、`RESIN_DEFAULT_PLATFORM_STICKY_TTL` |
| 节点失效：先换同 IP 节点，否则新建租约（新 IP） | `internal/routing/router.go` `decideStickyLease`、`tryLeaseSameIPRotation`、`createOrAbortStickyLease` |
| 没有“失效即报错”的平台开关 | `internal/platform/platform.go` `Platform` 结构体 |
| 正向代理响应里只有 `X-Resin-Error`，没有告知换绑的头 | 检索 `X-Resin`：`internal/proxy/errors.go`、`reverse.go` |
| P2C；评分 =（LeaseCount+1）× Latency | `DESIGN.md`“综合评分公式”；`internal/routing/random.go` |
| 延迟按 eTLD+1 记 TD-EWMA，普通站点 LRU 默认 12 条 | `DESIGN.md`“延迟统计”、`RESIN_MAX_LATENCY_TABLE_ENTRIES` |
| 连续 3 次失败熔断；新节点默认处于熔断状态 | `DESIGN.md`“熔断与恢复机制”、`MaxConsecutiveFailures` |
| 出口探测用 `https://cloudflare.com/cdn-cgi/trace`；默认最长 1 天复测 | `internal/probe/manager.go` 74 行；`MaxEgressTestInterval` |
| 被动健康只看网络层，“即便 HTTP 返回 500”也视为健康 | `DESIGN.md`“被动延迟探测 · 信号源” |
| 单次请求内不重试：拨号失败直接返回 502 | `internal/proxy/forward.go` `handleHTTP`；`internal/proxy/tunnel.go` `prepareConnectTunnel`；检索 `retry` 未命中 |
| 未找到按节点限制并发的代码 | 检索 `semaphore`、`MaxConnsPerHost`、`inflight`、`rate.Limiter` 未命中 |
| 探测与转发未关闭证书校验 | 检索 `InsecureSkipVerify` 未命中（非测试代码） |
| 默认监听 `0.0.0.0`；两个令牌必须定义但允许为空 | `DESIGN.md`“环境变量设置项” |
| 进程内嵌入 sing-box：每个节点一个 `adapter.Outbound` | `internal/outbound/builder.go`（174 行） |
| 依赖 `github.com/sagernet/sing-box v1.12.21` | `go.mod` |
| 96 个测试文件；无模糊测试；工作流只有发布和关闭 issue，不运行测试 | `find . -name '*_test.go'`；检索 `func Fuzz` 未命中；`.github/workflows/` |

## proxyhub（jiusanzhou/proxyhub，59a596f，2026-04-26，MIT）

| 结论 | 位置 |
| --- | --- |
| 会话绑定代理对象（地址），仅内存，空闲 TTL 默认 10 分钟，失败 3 次换绑 | `internal/session/session.go` |
| 换绑通过 `X-Proxyhub-Rotated` 响应头告知 | `internal/server/server.go` 252 行 |
| 普通 HTTP 请求最多重试 5 次，不区分方法，复用已读过的请求体 | `internal/server/server.go` `handleHTTPProxy`（`maxRetries = 5`，注释“仅重试不重读 body”） |
| 评分 = 成功率×0.6 + 延迟分×0.4 | `internal/pool/proxy.go` 113 行 |
| 默认健康探测只做 TCP 拨号，L7 探测默认关闭 | `internal/config/config.go` `CheckL7: false`；`internal/pool/checker.go` |
| 代理端口与 API 端口无鉴权，监听全部网卡 | `cmd/proxyhub/commands/serve.go` 127、141 行；`server.go` 检索 `token`、`407` 未命中 |
| 来源只有 proxifly 和文本订阅 | README；`internal/source/` |

## mihomo（MetaCubeX/mihomo，Meta 分支 3f27ef3，2026-10-21，GPL-3.0）

仓库默认分支 `main` 是无关内容，真实代码在 `Meta` 和 `Alpha` 分支。

| 结论 | 位置 |
| --- | --- |
| 负载均衡组三种策略：round-robin、consistent-hashing、sticky-sessions | `adapter/outboundgroup/loadbalance.go` |
| `hash-key: in-user` 用入站认证用户名作哈希键 | 同上 76–106 行；`docs/config.yaml` 1799–1808 行 |
| sticky-sessions：LRU 1000 条，10 分钟过期，均为硬编码；绑定节点下标 | 同上 `strategyStickySessions` |
| 入站用户是静态名单，用户名不能携带任意会话 ID | `component/auth/auth.go` `inMemoryAuthenticator` |
| 健康判断只用 URL 测试结果 | `AliveForTestUrl` |

## glider（nadoo/glider，487da73，2026-10-09，GPL-3.0）

| 结论 | 位置 |
| --- | --- |
| 策略 rr、ha、lha、dh；dh = FNV(目标地址) mod 可用数 | `rule/group.go` `scheduleDH` |
| 默认健康检查 `http://www.msftconnecttest.com/connecttest.txt#expect=200`，间隔 30 秒 | `config/glider.conf.example` |
| 没有测试文件 | `find . -name '*_test.go'` |

## jhao104/proxy_pool（9cc0cad，2026-06-15，MIT）

| 结论 | 位置 |
| --- | --- |
| 接口发代理：`/get`、`/pop`、`/all`、`/count`、`/delete`；依赖 Redis | README |
| HTTPS 校验 `verify=False`；只判断状态码 200 | `helper/validator.py` `httpsTimeOutValidator` |
| 校验目标 `http://httpbin.org` 与 `https://www.qq.com` | `setting.py` |
| 接口监听 `0.0.0.0:5010`，无鉴权 | `setting.py` |

## 关闭证书校验的其他项目

| 项目 | 结论 | 位置 |
| --- | --- | --- |
| rota（alpkeskin/rota，f8a09cc，Apache-2.0） | 健康检查在 `StrictTLS`（默认 false）未开启时接受任何证书；共享传输层 `InsecureSkipVerify: true`、最低 TLS 1.0 | `core/internal/proxy/healthcheck.go` 98–118 行；`core/internal/proxy/transport.go` 80–90 行 |
| mubeng（mubeng/mubeng，963b14d，Apache-2.0） | CONNECT 走 `goproxy.MitmConnect`；上游传输层 `InsecureSkipVerify: true`、最低 TLS 1.0 | `internal/server/handler.go` 151 行；`pkg/mubeng/transport.go` 44–48 行 |
| ProxyCat（honmashironeko/ProxyCat，7afc593，GPL-2.0） | 校验时 `verify=False`、`ssl.CERT_NONE` | `modules/proxyserver.py` 183、1750 行；`modules/modules.py` 1390 行 |

## 引擎与许可证

| 项目 | 许可证 | 位置 |
| --- | --- | --- |
| sing-box（SagerNet/sing-box，9f1cd1e） | GPL-3.0-or-later，另加“衍生作品未经同意不得使用其名称或暗示关联” | `LICENSE` |
| sing-box 路由规则支持 `auth_user` | | `option/rule.go` 144 行；`docs/configuration/route/rule.md` |
| sing-box 收到 SIGHUP 时关闭并重建整个实例 | | `cmd/sing-box/cmd_run.go` 190–220 行 |
| Xray-core（XTLS/Xray-core，a52db8f） | MPL-2.0 | `LICENSE`；`core/functions.go` `Dial` |
| v2ray-core（v2fly/v2ray-core，ec5ce8b） | MIT | `LICENSE` |

## 未能核对

- madhatter349/rotating-proxypool：搜索结果里出现过，克隆时提示需要凭据，仓库已不可公开访问。
