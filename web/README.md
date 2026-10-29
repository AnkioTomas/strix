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

## API

| Method | Path | 说明 |
|--------|------|------|
| GET | `/health` | 存活 + 槽位 |
| GET | `/v1/node` | 节点 ID、容量、`free_slots`、在跑任务（主控调度依据） |
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
