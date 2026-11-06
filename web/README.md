# Strix Worker Node

分布式扫描执行节点。主控通过固定 Bearer Token 走 HTTP 下发任务、查询容量、投递指令、拉取结果。本节点**不做**任务目录、漏洞库、UI、邮件、复测。

## 角色

```text
Master                         Worker (this package)
  调度 / 目录 / UI               GET  /v1/node     容量 + 在跑任务
  漏洞库 / 邮件 / 复测           POST /v1/jobs     接单（满载 503）
                                POST /v1/jobs/{id}/steer
                                GET  /v1/jobs/{id}/result
                                DELETE /v1/jobs/{id}
```

鉴权：

```http
Authorization: Bearer <STRIX_API_KEY>
```

## 启动

```bash
# 仓库根目录
./scripts/start-web.sh
# 或
make web

export STRIX_API_KEY=dev-local
export STRIX_LLM=...
export LLM_API_KEY=...
```

首次运行若没有 `web/.env`，脚本会从 `.env.example` 复制。扫描依赖 `STRIX_LLM` + `LLM_API_KEY`。

## 一键部署并注册到主控

在主控「执行服务器 → 新增服务器」复制安装命令，到全新服务器以 root 执行。脚本 `web/deploy/install.sh` 会：安装 uv 与 Python 依赖（含 x86-64-v2 兼容的 `numpy<2.4`）、准备沙箱镜像、写 systemd 服务、配置 HTTPS（有 1Panel OpenResty 则走反向代理，否则节点自签 TLS）、开放防火墙，最后把节点地址、API Key 和证书 POST 到主控 `/agent/register`。节点只做引导，模型 / 并发等配置之后由主控下发。

可选环境变量：`STRIX_PROXY`（访问 GitHub / ghcr.io / PyPI 的代理）、`STRIX_NODE_URL`（主控访问本节点的地址，默认按到主控的路由自动推断）、`STRIX_PUBLIC_PORT`（默认 8787）、`STRIX_NODE_NAME`。需预先安装 docker、curl、openssl。

## API

| Method | Path | 说明 |
|--------|------|------|
| GET | `/health` | 存活 + 槽位 |
| GET | `/v1/node` | 节点 ID、容量、`free_slots`、在跑任务（主控调度依据） |
| GET / PUT | `/v1/config` | 主控下发/读取运行配置（见下）；GET 中密钥只显示 `***` |
| POST | `/v1/jobs` | 下发任务；满载 → `503 NODE_FULL` |
| GET | `/v1/jobs` | 本机运行态列表（非产品目录） |
| GET | `/v1/jobs/{id}` | 状态 |
| POST | `/v1/jobs/{id}/cancel` | 取消 |
| POST | `/v1/jobs/{id}/steer` | 运行中投递指令 `{"message":"..."}` |
| GET | `/v1/jobs/{id}/result` | findings + report（读磁盘） |
| GET | `/v1/jobs/{id}/events` | Agent 事件 |
| GET | `/v1/jobs/{id}/artifacts` | 产物列表 |
| GET | `/v1/jobs/{id}/artifacts/{path}` | 下载产物 |
| GET | `/v1/jobs/{id}/logs` | 执行日志 |
| DELETE | `/v1/jobs/{id}` | 清盘（须已结束） |

创建示例：

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/jobs \
  -H "Authorization: Bearer $STRIX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id":"job_001","type":"pentest","target":"https://example.com","scan_mode":"quick"}'
```

可选 `id`：主控指定关联键；省略则节点生成 `job_…`。

## 本地存储

- **无 SQLite 任务/漏洞库**
- `data/jobs/<id>/job.json`：运行态
- `data/jobs/<id>/strix_runs/`：扫描产物
- 主控拉完结果后应 `DELETE`，或自行做 TTL

## 运行配置由主控下发

节点本地 `.env` 只需引导项（`STRIX_API_KEY` / `STRIX_API_HOST` / `STRIX_API_PORT` / `STRIX_NODE_ID`）。模型、代理、并发、Git 凭据等一律由主控 `PUT /v1/config` 推送，节点落盘到 `data/node-config.json`（0600），重启自动恢复，新任务立即生效（已在跑的任务不受影响）。

```bash
curl -sS -X PUT http://NODE:8787/v1/config -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{"env":{"STRIX_LLM":"openai/xxx","LLM_API_KEY":"sk-...","OPENAI_API_BASE":"https://..."},
       "settings":{"max_concurrent":4,"task_cpu_percent":30,"task_memory_gb":2}}'
```

- 合并语义：`env` 中值为 `null` 表示删除该项；未出现的键保持不变。
- `env` 仅允许 `STRIX_* / LLM_* / OPENAI_* / ANTHROPIC_* / AZURE_* / GEMINI_* / VERTEX_* / AWS_* / PERPLEXITY_*` 与 `HTTP(S)_PROXY / NO_PROXY / ALL_PROXY`；`STRIX_API_*`、`STRIX_BIN`、`STRIX_NODE_ID` 不可改。
- `settings` 可含：`max_concurrent`、`task_cpu_percent`、`task_memory_gb`、`default_scan_mode`、`default_max_budget`、`sandbox_reap_interval`、`allow_private_targets`、`pentest_allowed_targets`、`git_username` + `git_token`。

## HTTPS（反向代理，与 1Panel 一致）

节点只监听回环明文端口，TLS 由 1Panel 的 OpenResty 终结：

```bash
bash deploy/1panel-proxy.sh [公网端口=8787] [上游端口=18787] [站点名=strix-node]
```

脚本会在 `/opt/1panel/www/conf.d/<站点>.conf` 写入反代站点、在 `sites/<站点>/ssl/` 生成自签证书（可在 1Panel 面板里替换为正式证书）、把节点改为 `127.0.0.1:<上游端口>`、`nginx -t` 后 reload。主控用 `fullchain.pem` 作为信任证书。

## 满载策略

节点不排队。`free_slots == 0` 时 `POST /v1/jobs` 返回：

```json
{"error":{"code":"NODE_FULL","message":"no free slots (...)"}}
```

主控根据 `GET /v1/node` 决定换节点、等待或取消低优先级任务。

## 明确不做

- UI / session Cookie
- 邮件 / 飞书
- 复测 / finding 审核
- 资产聚合 / 批量导入 / Gitea Issue
- Viewer 反代（主控用 `steer` + 自有 UI）
