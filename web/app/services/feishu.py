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

# Feishu card header templates (bot webhook interactive cards).
_EVENT_TEMPLATES = {
    "started": "blue",
    "finished": "green",
    "failed": "red",
    "cancelled": "orange",
    "needs_user": "purple",
}

_STATUS_TO_EVENT = {
    "completed": "finished",
    "failed": "failed",
    "cancelled": "cancelled",
}

_TERMINAL_EVENTS = frozenset({"finished", "failed", "cancelled"})

_SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "未知",
}

_FINDINGS_CARD_LIMIT = 20


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


def _md_escape(value: object) -> str:
    """Keep lark_md fields readable; strip control chars that break cards."""
    text = str(value if value is not None else "—").replace("\r", " ").strip()
    return text or "—"


def _field(label: str, value: object, *, is_short: bool = True) -> dict[str, Any]:
    return {
        "is_short": is_short,
        "text": {
            "tag": "lark_md",
            "content": f"**{label}**\n{_md_escape(value)}",
        },
    }


def _severity_label(severity: object) -> str:
    key = str(severity or "info").strip().lower()
    return _SEVERITY_LABEL.get(key, key or "信息")


def format_findings_lines(
    findings: list[dict[str, Any]] | None,
    *,
    limit: int = _FINDINGS_CARD_LIMIT,
) -> str:
    """One line per finding: ``严重 · 漏洞名``. Empty list → ``无``."""
    if not findings:
        return "无"
    lines: list[str] = []
    for item in findings[:limit]:
        sev = _severity_label(item.get("severity"))
        name = _md_escape(item.get("title") or item.get("id") or "—")
        lines.append(f"• {sev} · {name}")
    remaining = len(findings) - limit
    if remaining > 0:
        lines.append(f"… 另有 {remaining} 项")
    return "\n".join(lines)


def load_task_findings(task: dict[str, Any]) -> list[dict[str, Any]]:
    """Read normalized findings from the task run dir (empty if missing)."""
    workspace = task.get("workspace")
    if not workspace:
        return []
    from app.services.results import (
        discover_run_name,
        load_normalized_findings,
        workspace_run_dir,
    )

    run_name = task.get("run_name") or discover_run_name(Path(workspace))
    run_dir = workspace_run_dir(Path(workspace), run_name)
    if run_dir is None:
        return []
    return load_normalized_findings(run_dir, task_id=str(task.get("id") or ""))


def build_card(
    event: str,
    task: dict[str, Any],
    *,
    detail: str | None = None,
    console_url: str | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a Feishu interactive card payload (``msg_type=interactive`` body)."""
    key = event.strip().lower()
    title = _EVENT_TITLES.get(key, key)
    template = _EVENT_TEMPLATES.get(key, "blue")
    label = _task_label(task)
    target = task.get("target") or task.get("source_url")

    fields: list[dict[str, Any]] = [
        _field("任务", label),
        _field("任务 ID", task.get("id") or "—"),
    ]
    if target and str(target) != label:
        fields.append(_field("目标", target, is_short=False))
    if task.get("run_name"):
        fields.append(_field("Run", task["run_name"]))
    if task.get("scan_mode"):
        fields.append(_field("模式", task["scan_mode"]))
    if task.get("type"):
        fields.append(_field("类型", task["type"]))
    if key == "failed" and task.get("error"):
        fields.append(_field("错误", task["error"], is_short=False))
    if key == "finished":
        items = findings if findings is not None else []
        count = len(items)
        fields.append(
            _field(f"漏洞 ({count})", format_findings_lines(items), is_short=False)
        )
    if detail:
        fields.append(_field("说明", detail, is_short=False))

    elements: list[dict[str, Any]] = [
        {"tag": "div", "fields": fields},
        {"tag": "hr"},
        {
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": "Strix Local Security API",
                }
            ],
        },
    ]
    if console_url:
        elements.insert(
            -1,
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
            },
        )

    return {
        "header": {
            "title": {"tag": "plain_text", "content": f"Strix · {title}"},
            "template": template,
        },
        "elements": elements,
    }


def format_message(
    event: str,
    task: dict[str, Any],
    *,
    detail: str | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> str:
    """Plain-text fallback (tests / logs). Prefer ``build_card`` for delivery."""
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
    if event == "finished":
        items = findings if findings is not None else []
        lines.append(f"漏洞 ({len(items)}):")
        lines.append(format_findings_lines(items))
    if detail:
        lines.append(detail)
    return "\n".join(lines)


def _console_url(settings: Settings) -> str | None:
    host = (settings.host or "").strip()
    if not host or host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    port = int(settings.port or 8787)
    return f"http://{host}:{port}/"


def post_json(
    webhook: str,
    payload: dict[str, Any],
    *,
    timeout: float = 3.0,
    proxy: str | None = None,
) -> bool:
    """POST JSON to Feishu bot webhook. Never raises.

    ``proxy`` is an optional ``http://`` / ``https://`` proxy used only for
    this outbound call (does not inherit process ``HTTP_PROXY``).
    """
    url = webhook.strip()
    if not url:
        return False
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    proxy_url = (proxy or "").strip()
    if proxy_url:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
    else:
        # Explicit empty handler: ignore ambient HTTP(S)_PROXY for Feishu.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw) if raw.strip() else {}
        if isinstance(data, dict) and data.get("code") not in (None, 0):
            logger.warning("feishu webhook rejected: %s", data)
            return False
        return True
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        logger.warning("feishu webhook failed: %s", exc)
        return False


def post_card(
    webhook: str,
    card: dict[str, Any],
    *,
    timeout: float = 3.0,
    proxy: str | None = None,
) -> bool:
    return post_json(
        webhook,
        {"msg_type": "interactive", "card": card},
        timeout=timeout,
        proxy=proxy,
    )


def post_text(
    webhook: str,
    text: str,
    *,
    timeout: float = 3.0,
    proxy: str | None = None,
) -> bool:
    """Legacy plain text helper (kept for ad-hoc curls / tests)."""
    return post_json(
        webhook,
        {"msg_type": "text", "content": {"text": text}},
        timeout=timeout,
        proxy=proxy,
    )


def notify(
    settings: Settings,
    event: str,
    task: dict[str, Any],
    *,
    detail: str | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> bool:
    """Send one lifecycle card if webhook + event filter allow it (no dedupe)."""
    webhook = settings.feishu_webhook.strip()
    if not webhook:
        return False
    key = event.strip().lower()
    if key not in settings.feishu_event_set():
        return False
    resolved = findings
    if key == "finished" and resolved is None:
        resolved = load_task_findings(task)
    card = build_card(
        key,
        task,
        detail=detail,
        console_url=_console_url(settings),
        findings=resolved,
    )
    return post_card(webhook, card, proxy=settings.feishu_proxy.strip() or None)


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
