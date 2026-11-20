"""Public operator forms: the Feishu link opens a form, the submission steers the agent.

Deliberately unauthenticated (the operator clicks a link from a chat card).
Access is bounded by an unguessable one-time form id and a strict CSP.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.services.artifacts import workspace_run_dir
from app.services.job_manager import JobError, JobManager
from strix.notify import forms


router = APIRouter(prefix="/forms")

_MAX_BODY_BYTES = 256 * 1024


def _headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": forms.CSP,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def _locate(manager: JobManager, run_name: str, form_id: str) -> tuple[str, Path] | None:
    if not forms.RUN_NAME_RE.match(run_name) or not forms.FORM_ID_RE.match(form_id):
        return None
    for job in manager.store.list_jobs():
        if job.get("run_name") != run_name:
            continue
        run_dir = workspace_run_dir(Path(job["workspace"]), run_name)
        if run_dir is not None:
            return str(job["id"]), run_dir
    return None


def _page(text: str, status: int = 200) -> HTMLResponse:
    body = f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><p>{text}</p>"
    return HTMLResponse(body, status_code=status, headers=_headers())


@router.get("/{run_name}/{form_id}")
async def show_form(request: Request, run_name: str, form_id: str) -> HTMLResponse:
    found = _locate(request.app.state.manager, run_name, form_id)
    record = forms.load_form(found[1], form_id) if found else None
    if record is None:
        return _page("表单不存在或已失效。", 404)
    if record.get("status") != "pending":
        return _page("该表单已提交，无需重复填写。")
    return HTMLResponse(forms.render_page(record), headers=_headers())


@router.post("/{run_name}/{form_id}")
async def submit(request: Request, run_name: str, form_id: str) -> HTMLResponse:
    manager: JobManager = request.app.state.manager
    found = _locate(manager, run_name, form_id)
    if found is None:
        return _page("表单不存在或已失效。", 404)
    job_id, run_dir = found
    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
        return _page("提交内容过大。", 413)
    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    values = forms.clean_values({key: vals[-1] for key, vals in parsed.items() if vals})
    record = await asyncio.to_thread(forms.submit_form, run_dir, form_id, values)
    if record is None:
        return _page("该表单已提交或已失效。", 409)
    try:
        await asyncio.to_thread(
            manager.steer_job,
            job_id,
            forms.format_submission_message(record),
            agent_id=record.get("agent_id") or None,
        )
    except JobError as exc:
        return _page(f"已记录，但无法送达 Agent：{exc.message}", 502)
    return _page("已提交，Agent 会继续执行。可以关闭此页面。")
