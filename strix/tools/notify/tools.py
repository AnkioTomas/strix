"""``notify_user`` / ``wait_for_user`` — reach the human out of band and wait for them."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.notify import feishu, forms
from strix.tools.ocr.tool import _normalize_sandbox_path, _read_sandbox_bytes
from strix.tools.respond.tool import park_for_user


logger = logging.getLogger(__name__)

_MAX_IMAGES = 4
_MAX_IMAGE_BYTES = 2 * 1024 * 1024
_LEVELS = {"info", "warning", "error", "success"}


def _result(**payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def _ctx(ctx: RunContextWrapper) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


def _image_mime(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in {b"GIF87a", b"GIF89a"}:
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


async def _load_images(ctx: RunContextWrapper, paths: list[str]) -> list[str]:
    uris: list[str] = []
    for raw in paths[:_MAX_IMAGES]:
        data = await _read_sandbox_bytes(ctx, _normalize_sandbox_path(raw))
        if len(data) > _MAX_IMAGE_BYTES:
            raise ValueError(f"{raw}: image exceeds {_MAX_IMAGE_BYTES // (1024 * 1024)} MiB")
        mime = _image_mime(data)
        if mime is None:
            raise ValueError(f"{raw}: not a PNG/JPEG/GIF/WebP image")
        uris.append(f"data:{mime};base64,{base64.b64encode(data).decode()}")
    return uris


def _run_dir() -> Path | None:
    from strix.core.paths import run_dir_for  # noqa: PLC0415
    from strix.report.state import get_global_report_state  # noqa: PLC0415

    state = get_global_report_state()
    run_name = getattr(state, "run_name", None)
    if not run_name:
        return None
    return run_dir_for(str(run_name))


@function_tool(timeout=60)
async def notify_user(  # noqa: PLR0911
    ctx: RunContextWrapper,
    message: str,
    title: str = "",
    level: str = "info",
    form_html: str = "",
    form_title: str = "",
    image_paths: list[str] | None = None,
    form_kind: str = "",
    form_fields: list[str] | None = None,
    form_options: list[str] | None = None,
) -> str:
    """Send the human operator a Feishu notification, optionally with a form to fill in.

    Use this for things the operator must see or decide while you keep
    working or wait: progress reports, a blocker (target unreachable,
    login wall, OCR cannot read a captcha), a dynamic verification code
    only they can read, or a decision you cannot make yourself. This call
    only DELIVERS the message — it does not wait. When you need an answer,
    call it, then call ``wait_for_user`` as your next step.

    Keep ``message`` short and self-contained: what happened, what you
    tried, and exactly what you need. No secrets or full credentials.

    To ask for input, pass ``form_html``: the FIELDS only of an HTML form
    (``<label>``, ``<input>``, ``<select>``, ``<textarea>``, radio
    buttons, plain text and CSS-free markup). Do NOT include ``<form>``,
    ``<script>``, event handlers, external links or a submit button — the
    platform wraps your fields in a page with a Submit button, the operator
    opens it from the Feishu card, and their answers return to you as a
    ``[user form response]`` message. Give every input a ``name``.
    Example fields for a captcha::

        <label>Captcha text<input name="captcha" autocomplete="off"></label>

    To show the operator a screenshot (e.g. a captcha image), pass sandbox
    paths in ``image_paths``; they are embedded at the top of the form.

    Preset forms (preferred — pass ``form_kind`` instead of ``form_html``):

    - ``credentials``: the user has not given you a login/token you need.
      ``form_fields`` = labels to collect, e.g. ``["Username", "Password"]``
      (labels containing pass/token/key render as password inputs).
      Answer: ``{"Username": ..., "Password": ...}`` keyed by sanitized label.
    - ``captcha``: a code only the user can read (SMS, email, TOTP, an image
      OCR cannot read). Add the screenshot via ``image_paths``. Answer: ``code``.
    - ``interactive``: slider / click-the-characters / puzzle captchas. The
      screenshot (``image_paths``) is shown at natural size and the user
      clicks it; the answer carries pixel coordinates ``click.x`` /
      ``click.y`` (top-left origin of that screenshot) plus optional ``note``.
    - ``decision``: you need the user to choose. ``form_options`` = the
      choices, e.g. ``["Continue with Tor", "Skip this target"]``. Answer:
      ``choice`` and optional ``note``.

    For anything else, use ``form_html`` (fields only, see above).

    Args:
        message: Body of the notification.
        title: Card title (short).
        level: info, warning, error or success.
        form_html: Optional form fields HTML (see above). Needs the node's
            public URL (STRIX_PUBLIC_URL) to be configured.
        form_title: Optional title shown on the form page.
        form_kind: credentials, captcha, interactive or decision (see above).
        form_fields: Labels for ``credentials`` (or the captcha label).
        form_options: Choices for ``decision``.
        image_paths: Optional sandbox image paths to embed in the form.
    """
    if not feishu.configured():
        return _result(
            success=False,
            error=(
                "No notification channel is configured (STRIX_FEISHU_WEBHOOK). "
                "Continue without the operator, or record the blocker in coverage/notes."
            ),
        )
    level = level if level in _LEVELS else "info"
    link = ""
    form_id = ""

    if form_html.strip() or form_kind:
        inner = _ctx(ctx)
        agent_id = str(inner.get("agent_id") or "")
        run_dir = _run_dir()
        run_name = run_dir.name if run_dir is not None else ""
        if run_dir is None or not forms.RUN_NAME_RE.match(run_name):
            return _result(success=False, error="No active run directory for the form")
        if not forms.public_base_url():
            return _result(
                success=False,
                error=(
                    "Forms need STRIX_PUBLIC_URL (the node's public base URL). "
                    "Send a text-only notification and ask for a reply instead."
                ),
            )
        try:
            images = await _load_images(ctx, image_paths or [])
        except (ValueError, RuntimeError, OSError, TypeError) as exc:
            return _result(success=False, error=f"Cannot attach image: {exc}")
        fields_html = form_html
        if form_kind:
            try:
                fields_html, images = forms.build_fields(
                    form_kind, form_fields or [], form_options or [], images
                )
            except ValueError as exc:
                return _result(success=False, error=str(exc))
            if form_kind == "interactive" and '<input type="image"' not in fields_html:
                return _result(success=False, error="interactive forms need image_paths")
        record = await asyncio.to_thread(
            forms.create_form,
            run_dir,
            agent_id=agent_id,
            title=form_title or title or "需要你的确认",
            fields_html=fields_html,
            images=images,
            intro=message,
        )
        form_id = str(record["id"])
        link = forms.form_url(run_name, form_id)

    ok, detail = await asyncio.to_thread(
        feishu.send, message, title=title, level=level, link_url=link
    )
    if not ok:
        return _result(success=False, error=detail)
    payload: dict[str, Any] = {"success": True, "delivered": True}
    if form_id:
        payload["form_id"] = form_id
        payload["note"] = (
            "Form sent. Call wait_for_user now and do nothing else until the "
            "[user form response] message arrives."
        )
    return _result(**payload)


@function_tool
async def wait_for_user(ctx: RunContextWrapper, reason: str = "") -> str:
    """Pause until the human operator replies, however long that takes.

    Call it right after ``notify_user`` when you need the operator's
    answer (a form submission, a decision, a verification code) and cannot
    make progress without it. You resume exactly where you stopped, with
    the operator's message — or the submitted form values — as the result.
    There is no timeout: do not poll, retry or work around the question
    while waiting.

    Not for waiting on other agents (use ``wait_for_agents``) and not a
    substitute for ``notify_user`` — the operator only knows you are
    waiting if you told them.

    Args:
        reason: One line saying what you are waiting for.
    """
    return await park_for_user(ctx, reason)
