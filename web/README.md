# Local Strix Security API

编排层，不是第二个 Agent。HTTP 管任务；**独立扫描子进程**跑 `run_strix_scan(interactive=True)` + viewer（API 重启不杀扫描）。

## 能力

1. 列出 / 创建任务（pentest + audit；创建时可上传附件挂到 `/workspace` 并告知模型）
2. 按系统负载排队（内存不足 / load 过高时不放行，任务留在 `queued`）
3. 取消 / 重试 / 续跑 / 复测 / **删除已结束任务**
4. **导入**旧版 CLI `strix_runs/`（`POST /api/v1/tasks/import`）
5. 事件查询 + SSE
6. 运行中通过 Live Viewer 与 Agent 交互（同源反代）
7. 报告 / artifacts 下载（同源）
8. **按任务**查看漏洞列表与详情 `GET /api/v1/tasks/{id}/results`（不跨任务）
9. **同源反代**官方 Live Viewer：`/api/v1/tasks/{id}/viewer/`

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

推荐用仓库根目录的启动工具（自动处理 `.env`、依赖、`PYTHONPATH`）：

```bash
# 仓库根目录
./scripts/start-web.sh
# 或
make web

# 可选
./scripts/start-web.sh --reload          # 开发热重载
./scripts/start-web.sh --host 0.0.0.0 --port 8787
```

首次运行若没有 `web/.env`，脚本会从 `.env.example` 复制一份。**扫描真正依赖** `STRIX_LLM` + `LLM_API_KEY`（会灌进进程环境）；缺了它们 API 能起来，任务会挂。

等价手写启动：

```bash
cd web
cp -n .env.example .env   # 首次
# 编辑 web/.env

pip install -r requirements.txt   # 或: uv pip install -r requirements.txt
PYTHONPATH=. python -m app
# → http://127.0.0.1:8787
```

`web/.env` 在启动时通过 `python-dotenv` 载入 **`os.environ`**（shell 已 export 的变量优先生效）。只靠 pydantic `env_file` 不够：`STRIX_LLM` 等是 Strix 内核读环境变量，不在 web `Settings` 里。

常用环境变量（写进 `.env` 即可）：

| 变量 | 默认 | 含义 |
|------|------|------|
| `STRIX_API_KEY` | （空） | Bearer Token；空且未关鉴权则拒绝 |
| `STRIX_API_HOST` / `STRIX_API_PORT` | `127.0.0.1` / `8787` | 监听地址 |
| `STRIX_LLM` | — | LiteLLM 模型 id（扫描必需） |
| `LLM_API_KEY` | — | LLM 密钥（扫描必需） |
| `OPENAI_API_BASE` / `LLM_API_BASE` | — | 本地/兼容 OpenAI 的 base URL |
| `LLM_TIMEOUT` | 300 | 所有 AI/LLM 请求超时（秒） |
| `STRIX_REPORT_LANGUAGE` | `zh` | 报告叙事/交付包语言（`zh`/`en`/`ja`/`Français`/…；空=不强制） |
| `STRIX_MAX_CONCURRENT` | 1 | 同时跑的扫描数 |
| `STRIX_MIN_FREE_MEMORY_GB` | 2.0 | 可用内存低于此值则继续排队 |
| `STRIX_MAX_LOAD_PER_CPU` | 1.5 | load1 / cpu_count 上限 |
| `STRIX_ALLOW_PRIVATE_TARGETS` | 1 | 是否允许扫私网/localhost |

浏览器根路径是控制台（`web/static/`：`index.html` + `css/` + `js/`）；静态资源在 `/static/*`。漏洞与报告页用 [Penna Markdown](https://penna.ankio.net/guide/getting-started) 只读渲染器（CDN `penna-markdown@0.2.5`）。OpenAPI 在 `/docs`。`GET /health` 返回 `admission`（当前是否放行、load/内存快照）。

## 主要 API

| Method | Path | 说明 |
|--------|------|------|
| POST | `/api/v1/session` | 写入会话 Cookie（需 Bearer） |
| DELETE | `/api/v1/session` | 清除会话 Cookie |
| POST | `/api/v1/tasks` | 创建任务（202，进入队列；也支持 multipart 附件） |
| POST | `/api/v1/tasks/import` | 导入旧版 CLI `strix_runs/`（可 `dry_run`） |
| GET | `/api/v1/tasks` | 列表 |
| GET | `/api/v1/tasks/{id}` | 详情（含 `viewer_proxy_url`） |
| PATCH | `/api/v1/tasks/{id}` | 重命名 / 更新备注 |
| POST | `/api/v1/tasks/{id}/hold` | 挂起（queued → held，不进执行队列） |
| POST | `/api/v1/tasks/{id}/release` | 放行（held → queued） |
| DELETE | `/api/v1/tasks/{id}` | 删除已结束或挂起任务（DB + workspace） |
| POST | `/api/v1/tasks/{id}/cancel` | SIGTERM→SIGKILL |
| POST | `/api/v1/tasks` + `parent_task_id`/`action` | UI 重试：可改配置后建子任务（复制父附件） |
| POST | `/api/v1/tasks/{id}/retry` | 同配置立刻重跑（新 run，API 兼容） |
| POST | `/api/v1/tasks/{id}/resume` | 原地续跑同一任务（同 `run_name`，需 `agents.json`） |
| POST | `/api/v1/tasks/{id}/refresh-report` | 要求 Agent 按交付规范重写报告（resume 或 live 投递） |
| POST | `/api/v1/tasks/{id}/retest` | 复测子任务（强制标记修复状态 + 佐证） |
| GET | `/api/v1/tasks/{id}/results` | 该任务 Finding |
| GET | `/api/v1/tasks/{id}/report` | Markdown 报告 |
| GET | `/api/v1/tasks/{id}/events` | Agent 事件 |
| GET | `/api/v1/tasks/{id}/events/stream` | SSE |
| GET | `/api/v1/tasks/{id}/messages` | 消息历史 |
| POST | `/api/v1/tasks/{id}/messages` | 用户消息 / follow-up |
| GET | `/api/v1/tasks/{id}/artifacts` | 产物列表 |
| GET | `/api/v1/tasks/{id}/artifacts/{path}` | 下载工件（含报告截图） |
| * | `/api/v1/tasks/{id}/viewer/...` | 同源反代 Live Viewer |
| GET | `/health` | 健康 + 准入状态 |

创建任务示例：

```bash
# Black-box pentest
curl -sS -X POST http://127.0.0.1:8787/api/v1/tasks \
  -H "Authorization: Bearer $STRIX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"pentest","target":"http://127.0.0.1:3000","scan_mode":"quick"}'

# White-box audit（本地目录）
curl -sS -X POST http://127.0.0.1:8787/api/v1/tasks \
  -H "Authorization: Bearer $STRIX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"audit","source":{"type":"local","path":"/path/to/app"},"scan_mode":"quick"}'
```

## Viewer 代理

```text
浏览器 iframe → /api/v1/tasks/{id}/viewer/
  → 校验 session/Bearer
  → 仅允许上游 127.0.0.1/localhost
  → 服务端注入 strix_viewer_session_{port}=viewer_token
  → 对 index.html 注入 bootstrap：
       · fetch 改写（/api/* → proxy 前缀）
       · 隐藏 OSS Viewer 营销壳（侧栏 Strix/Local 顶栏、Past runs /
         Feedback / PR Reviews / Integrations / Members、Local viewer 底栏、
         「Run in the cloud」按钮、「Run this pentest with more depth」升级卡）
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
