"""Periodic progress check-in for running scans.

Every ``STRIX_CHECKIN_INTERVAL`` seconds a running task gets a steer message
asking the agent to report status and to break out of loops, and a progress
card is pushed to the Feishu webhook (with stall / loop warnings).
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.services.feishu import _task_label, post_card
from app.services.results import (
    read_events,
    read_run_overview,
    read_vulnerabilities,
    workspace_run_dir,
)
from app.services.scan_state import read_state, write_state


if TYPE_CHECKING:
    from app.config import Settings
    from app.services.task_manager import TaskManager

logger = logging.getLogger(__name__)

_EVENT_WINDOW = 40
_LOOP_REPEATS = 8
_SIGNATURE_CHARS = 160
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def detect_loop(
    events: list[dict[str, Any]],
    *,
    window: int = _EVENT_WINDOW,
    repeats: int = _LOOP_REPEATS,
) -> str | None:
    """Return a sample of the repeated action when the recent tail looks stuck."""
    tail = events[-window:]
    if len(tail) < repeats:
        return None
    counts: Counter[tuple[str, str]] = Counter()
    for item in tail:
        message = str(item.get("message") or "").strip()
        if not message:
            continue
        counts[(str(item.get("type") or ""), message[:_SIGNATURE_CHARS])] += 1
    if not counts:
        return None
    (kind, message), seen = counts.most_common(1)[0]
    if seen >= repeats:
        return f"{kind}: {message}（近 {len(tail)} 条中重复 {seen} 次）"
    return None


def _format_elapsed(seconds: float) -> str:
    minutes = int(seconds // 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}小时{minutes}分" if hours else f"{minutes}分"


def _parse_time(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).timestamp()
    except ValueError:
        return None


def collect_progress(task: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    """Snapshot of a running task: elapsed, tokens, findings, event tail."""
    now = now if now is not None else time.time()
    started = _parse_time(task.get("started_at") or task.get("created_at"))
    run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
    usage: dict[str, Any] = {}
    severities: Counter[str] = Counter()
    events: list[dict[str, Any]] = []
    if run_dir is not None:
        usage = (read_run_overview(run_dir).get("llm_usage")) or {}
        for item in read_vulnerabilities(run_dir):
            if isinstance(item, dict):
                severities[str(item.get("severity") or "unknown").lower()] += 1
        events = read_events(run_dir, limit=0)
    last_event_at = max((_parse_time(e.get("timestamp")) or 0.0 for e in events), default=0.0)
    return {
        "elapsed": max(0.0, now - started) if started else 0.0,
        "total_tokens": int(usage.get("total_tokens") or 0),
        "cost": usage.get("cost"),
        "requests": int(usage.get("requests") or 0),
        "findings": sum(severities.values()),
        "severities": dict(severities),
        "event_count": len(events),
        "idle_seconds": (now - last_event_at) if last_event_at else None,
        "loop": detect_loop(events),
    }


def assess(progress: dict[str, Any], previous: dict[str, Any]) -> tuple[bool, str | None]:
    """``(stalled, loop_sample)`` compared with the previous check-in."""
    stalled = bool(previous) and (
        progress["event_count"] == previous.get("events")
        and progress["total_tokens"] == previous.get("tokens")
    )
    return stalled, progress["loop"]


def build_prompt(progress: dict[str, Any], *, stalled: bool, loop: str | None) -> str:
    lines = [
        f"[系统巡检] 本次扫描已运行 {_format_elapsed(progress['elapsed'])}，"
        f"已发现 {progress['findings']} 个漏洞。请用几句话汇报：",
        "1. 当前在测什么、已完成哪些、还剩哪些；",
        "2. 是否遇到阻塞（超时、无响应、被拦截、重复失败）。",
        "要求：不要卡在同一操作上反复循环；同一方法连续失败 3 次就换思路或放弃该分支，"
        "已无新的有效测试点就收尾并生成报告。",
    ]
    if loop:
        lines.append(f"警告：检测到疑似循环，最近反复出现：{loop}。请立刻停止该重复动作并换方向。")
    elif stalled:
        lines.append("警告：距上次巡检没有任何新进展。请检查是否卡死，必要时终止卡住的操作并继续。")
    return "\n".join(lines)


def build_progress_card(
    task: dict[str, Any],
    progress: dict[str, Any],
    *,
    stalled: bool,
    loop: str | None,
    delivered: bool,
    console_url: str | None,
) -> dict[str, Any]:
    template = "red" if stalled else "orange" if loop else "blue"
    sev = progress["severities"]
    sev_text = " / ".join(f"{k} {sev[k]}" for k in _SEVERITIES if sev.get(k)) or "暂无"
    cost = progress.get("cost")
    tokens = f"{progress['total_tokens']:,}" + (f"（约 ${cost:.2f}）" if isinstance(cost, int | float) else "")
    fields = [
        {"is_short": True, "text": {"tag": "lark_md", "content": f"**任务**\n{_task_label(task)}"}},
        {"is_short": True, "text": {"tag": "lark_md", "content": f"**已运行**\n{_format_elapsed(progress['elapsed'])}"}},
        {"is_short": True, "text": {"tag": "lark_md", "content": f"**Token**\n{tokens}"}},
        {"is_short": True, "text": {"tag": "lark_md", "content": f"**漏洞**\n{progress['findings']}（{sev_text}）"}},
        {
            "is_short": False,
            "text": {
                "tag": "lark_md",
                "content": "**巡检**\n" + ("已向 AI 询问进展" if delivered else "AI 暂未能接收消息"),
            },
        },
    ]
    if stalled:
        fields.append(
            {"is_short": False, "text": {"tag": "lark_md", "content": "**⚠ 疑似卡死**\n距上次巡检无新事件、无 Token 消耗"}}
        )
    if loop:
        fields.append(
            {"is_short": False, "text": {"tag": "lark_md", "content": f"**⚠ 疑似循环**\n{loop}"}}
        )
    elements: list[dict[str, Any]] = [{"tag": "div", "fields": fields}]
    if console_url:
        elements.append(
            {
                "tag": "action",
                "actions": [
                    {
                        "tag": "button",
                        "text": {"tag": "plain_text", "content": "打开控制台"},
                        "type": "primary",
                        "url": console_url,
                    }
                ],
            }
        )
    return {
        "header": {"title": {"tag": "plain_text", "content": "Strix · 进度巡检"}, "template": template},
        "elements": elements,
    }


def run_checkin(manager: TaskManager, task: dict[str, Any], *, console_url: str | None) -> bool:
    """Check in on one running task. Returns True when the check-in was sent."""
    settings: Settings = manager.settings
    workspace = Path(task["workspace"])
    state = read_state(workspace)
    previous = state.get("checkin") if isinstance(state.get("checkin"), dict) else {}
    progress = collect_progress(task)
    stalled, loop = assess(progress, previous)

    delivered = False
    try:
        manager.resume_with_message(
            task["id"], build_prompt(progress, stalled=stalled, loop=loop)
        )
        delivered = True
    except Exception as exc:
        logger.warning("checkin message not delivered task=%s: %s", task["id"], exc)

    webhook = settings.feishu_webhook.strip()
    if webhook:
        card = build_progress_card(
            task,
            progress,
            stalled=stalled,
            loop=loop,
            delivered=delivered,
            console_url=console_url,
        )
        post_card(webhook, card, proxy=settings.feishu_proxy.strip() or None)

    write_state(
        workspace,
        checkin={
            "at": time.time(),
            "events": progress["event_count"],
            "tokens": progress["total_tokens"],
        },
    )
    return True


def checkin_due(task: dict[str, Any], interval: float, *, now: float | None = None) -> bool:
    now = now if now is not None else time.time()
    state = read_state(Path(task["workspace"]))
    checkin = state.get("checkin")
    if isinstance(checkin, dict) and checkin.get("at"):
        return now - float(checkin["at"]) >= interval
    started = _parse_time(task.get("started_at") or task.get("created_at"))
    return started is not None and now - started >= interval
