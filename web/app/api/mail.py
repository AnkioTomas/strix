"""SMTP self-test endpoint."""

from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from app.security.auth import require_api_key
from app.services.mailer import (
    MailError,
    mail_enabled,
    sample_report_html,
    send_test_mail,
    smtp_target,
)

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class TestMailRequest(BaseModel):
    to: str | None = None


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def _default_to(settings) -> list[str]:
    for cand in (*settings.mail_cc_list()[:1], settings.smtp_from.strip(), settings.smtp_user.strip()):
        if cand and _EMAIL.match(cand):
            return [cand]
    return []


@router.get("/mail")
async def mail_status(request: Request):
    settings = request.app.state.manager.settings
    return {
        "enabled": mail_enabled(settings),
        "smtp": smtp_target(settings) if mail_enabled(settings) else None,
        "cc": settings.mail_cc_list(),
        "default_to": (_default_to(settings) or [""])[0],
    }


@router.get("/mail/preview", response_class=HTMLResponse)
async def mail_preview(request: Request):
    """Render the HTML report mail with sample data (open in a browser to review)."""
    settings = request.app.state.manager.settings
    try:
        return HTMLResponse(sample_report_html(settings))
    except MailError as exc:
        return _error(500, "MAIL_TEMPLATE_ERROR", str(exc))


@router.post("/mail/test")
async def send_mail_test(payload: TestMailRequest, request: Request):
    """Send a test mail so SMTP host / proxy / TLS / login can be verified."""
    settings = request.app.state.manager.settings
    if not mail_enabled(settings):
        return _error(400, "MAIL_DISABLED", "未配置 STRIX_SMTP_HOST，邮件功能未启用")
    to = [a for a in re.split(r"[,;，；\s]+", payload.to or "") if a] or _default_to(settings)
    if not to:
        return _error(400, "INVALID_REQUEST", "请填写收件邮箱")
    bad = [a for a in to if not _EMAIL.match(a)]
    if bad:
        return _error(400, "INVALID_REQUEST", f"邮箱格式不正确：{', '.join(bad)}")
    try:
        await asyncio.to_thread(send_test_mail, settings, to=to)
    except MailError as exc:
        return _error(502, "MAIL_SEND_FAILED", str(exc))
    return {"ok": True, "to": to, "smtp": smtp_target(settings)}
