# Local Strix Security API

编排层，不是第二个 Agent。HTTP 管任务；**独立扫描子进程**跑 `run_strix_scan(interactive=True)` + viewer（API 重启不杀扫描）。

## 能力

1. 列出 / 创建任务（pentest + audit）
2. 按系统负载排队（内存不足 / load 过高时不放行，任务留在 `queued`）
3. 取消 / 重试 / 复测
4. 事件查询 + SSE
5. 运行中实时与 Agent 交互（viewer steer / `POST .../messages`）
6. 报告 / artifacts 下载（同源）
7. **按任务**查看漏洞 `GET /api/v1/tasks/{id}/results`（不跨任务）
8. **同源反代**官方 Live Viewer：`/api/v1/tasks/{id}/viewer/`

## 鉴权

固定 Token，无用户登录系统：

```http
Authorization: Bearer <STRIX_API_KEY>
```

浏览器控制台还会调用 `POST /api/v1/session`，把同一 Token 写成 `HttpOnly` Cookie（`strix_web_session`），以便 **iframe / 图片** 无需带 Authorization。API 同时接受 Bearer 或该 Cookie。

```bash
export STRIX_API_KEY="replace-me"
```

仅本地调试可临时：`STRIX_API_AUTH_DISABLED=1`。

私网 / localhost 目标**默认允许**（`STRIX_ALLOW_PRIVATE_TARGETS=1`）。若要对公网部署收紧，设 `STRIX_ALLOW_PRIVATE_TARGETS=0`。

## 启动

```bash
cd web
pip install -r requirements.txt   # 或: uv pip install -r requirements.txt

cp .env.example .env              # 首次：写入 Token / LLM 等
# 编辑 web/.env —— 扫描依赖 STRIX_LLM + LLM_API_KEY（会灌进进程环境）

PYTHONPATH=. python -m app
# → http://127.0.0.1:8787
```

`web/.env` 在启动时通过 `python-dotenv` 载入 **`os.environ`**（shell 已 export 的变量优先生效）。只靠 pydantic `env_file` 不够：`STRIX_LLM` 等是 Strix 内核读环境变量，不在 web `Settings` 里。

超时相关（写进 `.env` 即可）：

| 变量 | 默认 | 含义 |
|------|------|------|
| `STRIX_TIMEOUT` | 1800 | Web 单任务墙钟上限（同义：`STRIX_MAX_TASK_TIME`） |
| `LLM_TIMEOUT` | 300 | 单次 LLM 请求 |
| `STRIX_DOCKER_TIMEOUT` | 300 | Docker API / pull |
| `STRIX_GIT_TIMEOUT` | 300 | git clone / checkout |

浏览器根路径是控制台（`web/static/`：`index.html` + `css/` + `js/`）；静态资源在 `/static/*`。漏洞与报告页用 [Penna Markdown](https://penna.ankio.net/guide/getting-started) 只读渲染器（CDN `penna-markdown@0.2.5`）。OpenAPI 在 `/docs`。`GET /health` 返回 `admission`（当前是否放行、load/内存快照）。

## 主要 API

| Method | Path | 说明 |
|--------|------|------|
| POST | `/api/v1/session` | 写入会话 Cookie（需 Bearer） |
| DELETE | `/api/v1/session` | 清除会话 Cookie |
| POST | `/api/v1/tasks` | 创建任务（202，进入队列） |
| GET | `/api/v1/tasks` | 列表 |
| GET | `/api/v1/tasks/{id}` | 详情（含 `viewer_proxy_url`） |
| POST | `/api/v1/tasks/{id}/cancel` | SIGTERM→SIGKILL |
| POST | `/api/v1/tasks/{id}/retry` | 同配置重跑 |
| POST | `/api/v1/tasks/{id}/retest` | 带复测指令重跑 |
| GET | `/api/v1/tasks/{id}/results` | 该任务 Finding |
| GET | `/api/v1/tasks/{id}/report` | Markdown 报告 |
| GET | `/api/v1/tasks/{id}/events` | Agent 事件 |
| GET | `/api/v1/tasks/{id}/events/stream` | SSE |
| POST | `/api/v1/tasks/{id}/messages` | 用户消息 / follow-up |
| GET | `/api/v1/tasks/{id}/artifacts` | 产物列表 |
| GET | `/api/v1/tasks/{id}/artifacts/{path}` | 下载工件（含报告截图） |
| * | `/api/v1/tasks/{id}/viewer/...` | 同源反代 Live Viewer |
| GET | `/health` | 健康 + 准入状态 |

## Viewer 代理

```text
浏览器 iframe → /api/v1/tasks/{id}/viewer/
  → 校验 session/Bearer
  → 仅允许上游 127.0.0.1/localhost
  → 服务端注入 strix_viewer_session_{port}=viewer_token
  → 对 index.html 注入 fetch 改写（把 /api/* 指回 proxy 前缀）
```

任务 JSON 字段：

- `viewer_url`：直连调试（含 token，勿外传）
- `viewer_proxy_url`：控制台内嵌用的同源路径（不暴露 token）

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

- 扫描在 **detached 子进程**（`python -m app.services.scan_worker`，`start_new_session=True`）；API 重启后通过 PID + `.web_scan_state.json` 重连，Viewer 反代仍指向原 loopback 端口
- 不在 HTTP handler 里同步跑扫描；Worker 只负责排队/认领/收尸
- 每任务独立 workspace：`web/data/tasks/<task_id>/`
- 漏洞只按 `task_id` 暴露，不做全局汇聚
- 固定 Bearer Token，不做账号体系
- 不把 `viewer_token` 下发给浏览器

## 交互（实话）

`strix -n` **不会**开可 steer 的 HTTP。能双向对话的是同一进程里的 viewer：

```text
API Worker
  → run_strix_scan(interactive=True) + AgentCoordinator
  → viewer.serve(..., steer_handler=...)
  → POST /api/agents/steer   （经本服务反代）
```

| 时机 | `POST /api/v1/tasks/{id}/messages` |
|------|-------------------------------------|
| 运行中 | 经 coordinator 实时投递（与 viewer steer 同源） |
| 已结束 | 创建 follow-up 任务，消息并进 instruction |
