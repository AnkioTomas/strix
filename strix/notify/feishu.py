"""Feishu (Lark) custom-bot delivery for agent → user notifications."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

WEBHOOK_ENV = "STRIX_FEISHU_WEBHOOK"
SECRET_ENV = "STRIX_FEISHU_SECRET"  # noqa: S105 - env var name, not a secret

_MAX_TEXT = 3000
_TEMPLATES = {"info": "blue", "warning": "orange", "error": "red", "success": "green"}


def webhook_url() -> str:
    return (os.environ.get(WEBHOOK_ENV) or "").strip()


def configured() -> bool:
    return bool(webhook_url())


def _sign(secret: str, timestamp: str) -> str:
    key = f"{timestamp}\n{secret}".encode()
    return base64.b64encode(hmac.new(key, digestmod=hashlib.sha256).digest()).decode()


def _clip(text: str) -> str:
    text = text.strip()
    if len(text) <= _MAX_TEXT:
        return text
    return text[: _MAX_TEXT - 20].rstrip() + "\n…(已截断)"


def build_payload(
    message: str,
    *,
    title: str = "",
    level: str = "info",
    link_url: str = "",
    link_label: str = "打开表单",
) -> dict[str, object]:
    elements: list[dict[str, object]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": _clip(message)}}
    ]
    if link_url:
        elements.append(
            {
                "tag": "action",
                "actions": [
                    {
                        "tag": "button",
                        "text": {"tag": "plain_text", "content": link_label},
                        "type": "primary",
                        "url": link_url,
                    }
                ],
            }
        )
        elements.append({"tag": "div", "text": {"tag": "plain_text", "content": link_url}})
    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": (title or "Strix 通知")[:100]},
                "template": _TEMPLATES.get(level, "blue"),
            },
            "elements": elements,
        },
    }


def send(
    message: str,
    *,
    title: str = "",
    level: str = "info",
    link_url: str = "",
    link_label: str = "打开表单",
) -> tuple[bool, str]:
    """Blocking send. Returns ``(ok, detail)``; never raises."""
    url = webhook_url()
    if not url:
        return False, f"{WEBHOOK_ENV} is not configured"
    if urlparse(url).scheme not in {"http", "https"}:
        return False, f"{WEBHOOK_ENV} must be an http(s) URL"

    payload = build_payload(
        message, title=title, level=level, link_url=link_url, link_label=link_label
    )
    secret = (os.environ.get(SECRET_ENV) or "").strip()
    if secret:
        timestamp = str(int(time.time()))
        payload["timestamp"] = timestamp
        payload["sign"] = _sign(secret, timestamp)

    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            body = response.read(65536).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("feishu send failed: %s", exc)
        return False, f"request failed: {exc}"

    try:
        data = json.loads(body)
    except ValueError:
        return False, f"unexpected response: {body[:200]}"
    code = data.get("code", data.get("StatusCode", 0)) if isinstance(data, dict) else 0
    if code not in (0, "0", None):
        msg = data.get("msg") or data.get("StatusMessage") or body[:200]
        return False, f"feishu rejected the message (code={code}): {msg}"
    return True, "sent"
