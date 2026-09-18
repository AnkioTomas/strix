"""Feishu group-bot notifications for web task lifecycle (no Strix core hooks)."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from app.config import Settings


logger = logging.getLogger(__name__)

_EVENT_TITLES = {
    "started": "扫描开始",
    "finished": "扫描完成",
    "failed": "扫描失败",
    "cancelled": "扫描已取消",
    "needs_user": "需要用户回复",
}

_STATUS_TO_EVENT = {
    "completed": "finished",
    "failed": "failed",
    "cancelled": "cancelled",
}

_TERMINAL_EVENTS = frozenset({"finished", "failed", "cancelled"})


class _TaskUpdater(Protocol):
    def update_task(self, task_id: str, **fields: Any) -> dict[str, Any] | None: ...


def status_to_event(status: str) -> str | None:
    return _STATUS_TO_EVENT.get(status)


def load_notify_state(task: dict[str, Any]) -> dict[str, Any]:
    raw = task.get("feishu_notify")
    if not raw:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    try:
        data = json.loads(str(raw))
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def dump_notify_state(state: dict[str, Any]) -> str:
    return json.dumps(state, ensure_ascii=False, separators=(",", ":"))


def should_send(event: str, task: dict[str, Any], *, fingerprint: str | None = None) -> bool:
    """True when this event has not been recorded for the current run/wait."""
    state = load_notify_state(task)
    key = event.strip().lower()
    if key == "started":
        return state.get("started_run") != (task.get("run_name") or "")
    if key in _TERMINAL_EVENTS:
        return state.get("terminal") != key
    if key == "needs_user":
        return bool(fingerprint) and state.get("needs_user") != fingerprint
    return True


def next_notify_state(
    event: str,
    task: dict[str, Any],
    *,
    fingerprint: str | None = None,
) -> dict[str, Any]:
    state = load_notify_state(task)
    key = event.strip().lower()
    if key == "started":
        state["started_run"] = task.get("run_name") or ""
        state.pop("terminal", None)
        state.pop("needs_user", None)
    elif key in _TERMINAL_EVENTS:
        state["terminal"] = key
        state.pop("needs_user", None)
    elif key == "needs_user" and fingerprint:
        state["needs_user"] = fingerprint
    return state


def clear_needs_user_state(task: dict[str, Any]) -> dict[str, Any] | None:
    """Drop needs_user fingerprint when agents are no longer waiting."""
    state = load_notify_state(task)
    if "needs_user" not in state:
        return None
    state = dict(state)
    state.pop("needs_user", None)
    return state


def _task_label(task: dict[str, Any]) -> str:
    name = str(task.get("name") or "").strip()
    if name:
        return name
    return str(task.get("target") or task.get("source_url") or task.get("id") or "—")


def format_message(
    event: str,
    task: dict[str, Any],
    *,
    detail: str | None = None,
) -> str:
    title = _EVENT_TITLES.get(event, event)
    lines = [
        f"[Strix] {title}",
        f"任务: {_task_label(task)}",
        f"ID: {task.get('id') or '—'}",
    ]
    target = task.get("target") or task.get("source_url")
    if target and str(target) != _task_label(task):
        lines.append(f"目标: {target}")
    if task.get("run_name"):
        lines.append(f"Run: {task['run_name']}")
    if task.get("scan_mode"):
        lines.append(f"模式: {task['scan_mode']}")
    if event == "failed" and task.get("error"):
        lines.append(f"错误: {task['error']}")
    if detail:
        lines.append(detail)
    return "\n".join(lines)


def post_text(webhook: str, text: str, *, timeout: float = 3.0) -> bool:
    """POST Feishu bot text message. Never raises."""
    url = webhook.strip()
    if not url:
        return False
    body = json.dumps(
        {"msg_type": "text", "content": {"text": text}},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(raw) if raw.strip() else {}
        if isinstance(payload, dict) and payload.get("code") not in (None, 0):
            logger.warning("feishu webhook rejected: %s", payload)
            return False
        return True
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        logger.warning("feishu webhook failed: %s", exc)
        return False


def notify(
    settings: Settings,
    event: str,
    task: dict[str, Any],
    *,
    detail: str | None = None,
) -> bool:
    """Send one lifecycle event if webhook + event filter allow it (no dedupe)."""
    webhook = settings.feishu_webhook.strip()
    if not webhook:
        return False
    key = event.strip().lower()
    if key not in settings.feishu_event_set():
        return False
    text = format_message(key, task, detail=detail)
    return post_text(webhook, text)


def notify_task(
    settings: Settings,
    db: _TaskUpdater,
    event: str,
    task: dict[str, Any],
    *,
    detail: str | None = None,
    fingerprint: str | None = None,
) -> bool:
    """Send once per durable key; persist ``feishu_notify`` only after success."""
    key = event.strip().lower()
    webhook = settings.feishu_webhook.strip()
    if not webhook or key not in settings.feishu_event_set():
        return False
    if not should_send(key, task, fingerprint=fingerprint):
        return False
    if not notify(settings, key, task, detail=detail):
        return False
    task_id = str(task.get("id") or "")
    if not task_id:
        return True
    state = next_notify_state(key, task, fingerprint=fingerprint)
    updated = db.update_task(task_id, feishu_notify=dump_notify_state(state))
    if updated is not None:
        task.update(updated)
    return True


def notify_status(
    settings: Settings,
    db: _TaskUpdater,
    task: dict[str, Any],
    status: str,
    *,
    detail: str | None = None,
) -> bool:
    event = status_to_event(status)
    if not event:
        return False
    return notify_task(settings, db, event, task, detail=detail)


def agents_waiting_on_user(agents_path: Path) -> list[str]:
    """Return agent ids whose wait_kind is ``user`` (from agents.json snapshot)."""
    if not agents_path.is_file():
        return []
    try:
        data = json.loads(agents_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    wait_kinds = data.get("wait_kinds")
    if not isinstance(wait_kinds, dict):
        return []
    return sorted(str(aid) for aid, kind in wait_kinds.items() if kind == "user")


def needs_user_fingerprint(agents_path: Path) -> str | None:
    waiting = agents_waiting_on_user(agents_path)
    if not waiting:
        return None
    return ",".join(waiting)
