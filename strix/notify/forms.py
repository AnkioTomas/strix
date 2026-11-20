"""Agent-authored HTML forms that a human fills in and submits back to the agent.

The agent supplies only the form *fields*; the platform wraps them in a fixed
page and ``<form>`` so the page can only ever post to its own submit endpoint.
Forms live under ``<run_dir>/forms/<form_id>.json`` and are served by the
worker node (``GET/POST /forms/<run_name>/<form_id>``).
"""

from __future__ import annotations

import contextlib
import html
import json
import os
import re
import secrets
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


PUBLIC_URL_ENV = "STRIX_PUBLIC_URL"
FORMS_DIR_NAME = "forms"

FORM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
RUN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

MAX_FIELDS = 50
MAX_VALUE_CHARS = 4000
MAX_HTML_CHARS = 60_000

# The page may load nothing and run nothing: inline styles and data: images only.
CSP = (
    "default-src 'none'; img-src data:; style-src 'unsafe-inline'; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)

_lock = threading.Lock()

_DROP_BLOCKS = re.compile(
    r"<\s*(script|style|iframe|object|embed|form)\b[^>]*>.*?<\s*/\s*\1\s*>", re.I | re.S
)
_DROP_TAGS = re.compile(
    r"</?\s*(script|iframe|object|embed|link|meta|base|form|frame|frameset|svg|math)\b[^>]*>",
    re.I,
)
_ON_ATTR = re.compile(r"""\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", re.I)
_JS_URL = re.compile(r"""(?i)\b(href|src)\s*=\s*["']?\s*(javascript|vbscript):""")
_URL_ATTR = re.compile(r"""\s+(formaction|action)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", re.I)


def public_base_url() -> str:
    return (os.environ.get(PUBLIC_URL_ENV) or "").strip().rstrip("/")


def form_url(run_name: str, form_id: str) -> str:
    base = public_base_url()
    return f"{base}/forms/{run_name}/{form_id}" if base else ""


def forms_dir(run_dir: Path) -> Path:
    return Path(run_dir) / FORMS_DIR_NAME


def sanitize_fields_html(raw: str) -> str:
    """Reduce agent-supplied HTML to inert markup (CSP is the real boundary)."""
    cleaned = raw[:MAX_HTML_CHARS]
    cleaned = _DROP_BLOCKS.sub("", cleaned)
    cleaned = _DROP_TAGS.sub("", cleaned)
    cleaned = _ON_ATTR.sub("", cleaned)
    cleaned = _URL_ATTR.sub("", cleaned)
    return _JS_URL.sub(r"\1=", cleaned).strip()


FORM_KINDS = ("credentials", "captcha", "interactive", "decision")
_MAX_OPTIONS = 12


def build_fields(
    kind: str, fields: list[str], options: list[str], images: list[str]
) -> tuple[str, list[str]]:
    """Return ``(fields_html, remaining_images)`` for a preset form kind."""
    esc = html.escape
    if kind == "credentials":
        rows = []
        for raw in fields[:MAX_FIELDS] or ["username", "password"]:
            name = re.sub(r"[^A-Za-z0-9_.-]", "_", raw)[:60] or "field"
            secret = re.search(r"pass|pwd|secret|token|key|密码|密钥", raw, re.I)
            kind_attr = "password" if secret else "text"
            rows.append(
                f'<label>{esc(raw)}<input type="{kind_attr}" name="{esc(name)}" '
                'autocomplete="off"></label>'
            )
        return "".join(rows), images
    if kind == "captcha":
        label = esc(fields[0]) if fields else "验证码"
        return (
            f'<label>{label}<input name="code" autocomplete="off" autofocus required></label>',
            images,
        )
    if kind == "interactive":
        shots = "".join(
            f"<p>点击图片上的目标位置（按题目要求依次点击；提交时记录最后一次点击坐标）</p>"
            f'<input type="image" name="click{i or ""}" alt="click" '
            f'src="{esc(src, quote=True)}" style="max-width:none;cursor:crosshair">'
            for i, src in enumerate(images)
            if src.startswith("data:image/")
        )
        note = '<label>补充说明（可选）<input name="note" autocomplete="off"></label>'
        return shots + note, []
    if kind == "decision":
        opts = "".join(
            f'<label class="opt"><input type="radio" name="choice" value="{esc(o, quote=True)}" '
            f"required> {esc(o)}</label>"
            for o in options[:_MAX_OPTIONS]
        )
        note = '<label>补充说明（可选）<textarea name="note" rows="3"></textarea></label>'
        return opts + note, images
    raise ValueError(f"unknown form_kind {kind!r}; expected one of {', '.join(FORM_KINDS)}")


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _path(run_dir: Path, form_id: str) -> Path:
    return forms_dir(run_dir) / f"{form_id}.json"


def _write(path: Path, record: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    try:
        tmp.replace(path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def create_form(
    run_dir: Path,
    *,
    agent_id: str,
    title: str,
    fields_html: str,
    images: list[str] | None = None,
    intro: str = "",
) -> dict[str, Any]:
    form_id = secrets.token_urlsafe(18)
    record: dict[str, Any] = {
        "id": form_id,
        "agent_id": agent_id,
        "title": (title or "需要你的确认").strip()[:200],
        "intro": intro.strip()[:2000],
        "fields_html": sanitize_fields_html(fields_html),
        "images": list(images or []),
        "status": "pending",
        "created_at": _now(),
        "submitted_at": None,
        "values": None,
    }
    with _lock:
        forms_dir(run_dir).mkdir(parents=True, exist_ok=True)
        _write(_path(run_dir, form_id), record)
    return record


def load_form(run_dir: Path, form_id: str) -> dict[str, Any] | None:
    if not FORM_ID_RE.match(form_id):
        return None
    try:
        data = json.loads(_path(run_dir, form_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def submit_form(run_dir: Path, form_id: str, values: dict[str, str]) -> dict[str, Any] | None:
    """Record a submission once. Returns the form, or ``None`` if unknown/already done."""
    with _lock:
        record = load_form(run_dir, form_id)
        if record is None or record.get("status") != "pending":
            return None
        record["status"] = "submitted"
        record["submitted_at"] = _now()
        record["values"] = values
        _write(_path(run_dir, form_id), record)
        return record


def clean_values(raw: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in list(raw.items())[:MAX_FIELDS]:
        values[str(key)[:100]] = str(value)[:MAX_VALUE_CHARS]
    return values


def format_submission_message(record: dict[str, Any]) -> str:
    body = json.dumps(record.get("values") or {}, ensure_ascii=False, indent=2)
    return (
        f"[user form response] form_id={record.get('id')} title={record.get('title')!r}\n"
        "The user submitted the form you sent with notify_user. Continue the task using "
        "these values:\n"
        f"{body}"
    )


def render_page(record: dict[str, Any]) -> str:
    title = html.escape(str(record.get("title") or ""))
    intro = html.escape(str(record.get("intro") or "")).replace("\n", "<br>")
    images = "".join(
        f'<img src="{html.escape(src, quote=True)}" alt="">'
        for src in record.get("images") or []
        if isinstance(src, str) and src.startswith("data:image/")
    )
    if record.get("status") != "pending":
        body = '<p class="done">该表单已提交，Agent 已收到。</p>'
    else:
        body = (
            '<form method="post">'
            f"{images}"
            f'<div class="fields">{record.get("fields_html") or ""}</div>'
            '<button type="submit">提交</button></form>'
        )
    intro_html = f"<p>{intro}</p>" if intro else ""
    return (
        '<!doctype html><html lang="zh"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{title}</title><style>"
        "body{font:16px/1.6 system-ui,sans-serif;max-width:560px;margin:24px auto;"
        "padding:0 16px;color:#222}"
        "h1{font-size:20px}img{max-width:100%;display:block;margin:12px 0;border:1px solid #ddd}"
        "input,select,textarea{width:100%;box-sizing:border-box;padding:8px;margin:4px 0 12px;"
        "font:inherit}"
        "input[type=radio],input[type=checkbox]{width:auto}"
        "button{padding:10px 24px;font:inherit;background:#2563eb;color:#fff;border:0;"
        "border-radius:6px}"
        ".done{padding:16px;background:#ecfdf5;border-radius:6px}"
        f"</style></head><body><h1>{title}</h1>{intro_html}{body}</body></html>"
    )
