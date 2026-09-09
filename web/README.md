# Local Strix Security API

编排层，不是第二个 Agent。HTTP 管任务；`strix -n` 管子弹。

## 能力

1. 列出 / 创建任务（pentest + audit）
2. 按系统负载排队（内存不足 / load 过高时不放行，任务留在 `queued`）
3. 取消 / 重试 / 复测
4. 事件查询 + SSE
5. 用户消息（运行中只入库；结束后自动开 follow-up 任务）
6. 报告 / artifacts 下载
7. **按任务**查看漏洞 `GET /api/v1/tasks/{id}/results`（不跨任务）

## 鉴权

固定 Token，无用户登录系统：

```http
Authorization: Bearer <STRIX_API_KEY>
```

```bash
export STRIX_API_KEY="replace-me"
```

仅本地调试可临时：`STRIX_API_AUTH_DISABLED=1`。

## 启动

```bash
cd web
pip install -r requirements.txt   # 或: uv pip install -r requirements.txt

export STRIX_API_KEY="replace-me"
# 可选调度阈值：
# export STRIX_MAX_CONCURRENT=1          # 硬上限，默认 1
# export STRIX_MIN_FREE_MEMORY_GB=2      # 可用内存低于此值则只排队不启动
# export STRIX_MAX_LOAD_PER_CPU=1.5      # 1分钟 load >= cpu*该值 则只排队不启动

PYTHONPATH=. python -m app
# → http://127.0.0.1:8787
```

浏览器根路径是简易控制台；OpenAPI 在 `/docs`。`GET /health` 返回 `admission`（当前是否放行、load/内存快照）。

## 主要 API

| Method | Path | 说明 |
|--------|------|------|
| POST | `/api/v1/tasks` | 创建任务（202，进入队列） |
| GET | `/api/v1/tasks` | 列表 |
| GET | `/api/v1/tasks/{id}` | 详情 |
| POST | `/api/v1/tasks/{id}/cancel` | SIGTERM→SIGKILL |
| POST | `/api/v1/tasks/{id}/retry` | 同配置重跑 |
| POST | `/api/v1/tasks/{id}/retest` | 带复测指令重跑 |
| GET | `/api/v1/tasks/{id}/results` | 该任务 Finding |
| GET | `/api/v1/tasks/{id}/report` | Markdown 报告 |
| GET | `/api/v1/tasks/{id}/events` | Agent 事件 |
| GET | `/api/v1/tasks/{id}/events/stream` | SSE |
| POST | `/api/v1/tasks/{id}/messages` | 用户消息 / follow-up |
| GET | `/api/v1/tasks/{id}/artifacts` | 产物列表 |
| GET | `/health` | 健康 + 准入状态 |

## 排队策略

```text
创建任务 → status=queued
         ↓
Worker 每秒检查：
  - 运行中数量 < STRIX_MAX_CONCURRENT
  - 可用内存 ≥ STRIX_MIN_FREE_MEMORY_GB
  - load1 < cpu_count * STRIX_MAX_LOAD_PER_CPU
         ↓
通过才 claim → starting → running
否则继续排队，避免把机器打满
```

## 设计约束

- 不在 HTTP handler 里跑 Strix
- 每任务独立 workspace：`web/data/tasks/<task_id>/`
- 漏洞只按 `task_id` 暴露，不做全局汇聚
- 固定 Bearer Token，不做账号体系
