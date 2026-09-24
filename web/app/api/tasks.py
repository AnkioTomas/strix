"""Task REST endpoints."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import ValidationError

from app.schemas import (
    ArtifactsResponse,
    CreateTaskRequest,
    EventsResponse,
    Finding,
    FindingsResponse,
    GitSource,
    ImportRunsRequest,
    ImportRunsResponse,
    LocalSource,
    MessageCreate,
    MessagesResponse,
    ReportResponse,
    RequestFindingTestResponse,
    ResumeTaskRequest,
    RetestTaskRequest,
    RetryTaskRequest,
    TaskListResponse,
    TaskLogsResponse,
    TaskSummary,
    UpdateFindingRequest,
    UpdateTaskRequest,
    normalize_earliest_start,
    summarize_finding,
)
from app.api.viewer_proxy import attach_viewer_proxy_url
from app.security.auth import require_api_key
from app.services.findings import empty_finding_counts
from app.services.results import list_artifacts, resolve_artifact, resolve_task_log, workspace_run_dir
from app.services.task_manager import TaskError, TaskManager, report_download_stem


router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


def get_manager(request: Request) -> TaskManager:
    return request.app.state.manager


_LIST_STATUSES = {
    "held",
    "queued",
    "starting",
    "running",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
}
_LIST_TYPES = {"pentest", "audit"}
_LIST_ACTIONS = {"retest", "retry", "resume", "import"}
_LIST_MODES = {"quick", "standard", "deep"}
_LIST_SORTS = {"created_at", "updated_at", "started_at", "finished_at"}
_LIST_ORDERS = {"asc", "desc"}


def _csv_allowlist(name: str, raw: str | None, allowed: set[str]) -> str | None:
    values = [part.strip() for part in (raw or "").split(",") if part.strip()]
    if not values:
        return None
    unknown = [value for value in values if value not in allowed]
    if unknown:
        raise TaskError("INVALID_REQUEST", f"invalid {name}: {', '.join(unknown)}")
    return ",".join(values)


def _parse_list_time(name: str, raw: str | None) -> str | None:
    if raw is None or not str(raw).strip():
        return None
    try:
        return normalize_earliest_start(str(raw))
    except ValueError as exc:
        raise TaskError("INVALID_REQUEST", f"invalid {name}: {exc}") from exc


def _error(exc: TaskError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


def _summary(task: dict[str, Any], *, include_findings: bool = True) -> TaskSummary:
    data = attach_viewer_proxy_url(task)
    from app.services.proxy_config import redact_proxy_url

    data["proxy_display"] = redact_proxy_url(data.get("proxy_url"))
    if include_findings:
        data["finding_counts"] = data.get("finding_counts") or empty_finding_counts()
    else:
        data.pop("finding_counts", None)
    data.setdefault("has_report", False)
    return TaskSummary.model_validate(data)


def _summarize(
    task: dict[str, Any],
    manager: TaskManager,
    *,
    include_findings: bool = True,
) -> TaskSummary:
    manager.attach_task_overlays([task], include_findings=include_findings)
    return _summary(task, include_findings=include_findings)


def _form_value(form: Any, key: str) -> str | None:
    value = form.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


async def _parse_create_payload(
    request: Request,
) -> tuple[CreateTaskRequest, list[tuple[str, bytes]]]:
    content_type = (request.headers.get("content-type") or "").lower()
    if "multipart/form-data" in content_type:
        form = await request.form()
        task_type = _form_value(form, "type")
        if not task_type:
            raise TaskError("INVALID_REQUEST", "type is required")
        payload: dict[str, Any] = {
            "type": task_type,
            "scan_mode": _form_value(form, "scan_mode") or "deep",
            "instruction": _form_value(form, "instruction"),
            "name": _form_value(form, "name"),
            "notes": _form_value(form, "notes"),
            "held": str(form.get("held") or "").lower() in {"1", "true", "yes", "on"},
            "earliest_start": _form_value(form, "earliest_start"),
            "use_proxy": str(form.get("use_proxy") or "").lower()
            in {"1", "true", "yes", "on"},
            "proxy_url": _form_value(form, "proxy_url"),
            "use_headers": str(form.get("use_headers") or "").lower()
            in {"1", "true", "yes", "on"},
            "request_headers": _form_value(form, "request_headers"),
        }
        parent_task_id = _form_value(form, "parent_task_id")
        if parent_task_id:
            payload["parent_task_id"] = parent_task_id
            payload["action"] = _form_value(form, "action") or "retry"
        max_budget = _form_value(form, "max_budget")
        if max_budget:
            payload["max_budget"] = float(max_budget)
        if task_type == "pentest":
            payload["target"] = _form_value(form, "target")
        else:
            source_type = _form_value(form, "source_type") or "git"
            if source_type == "local":
                payload["source"] = LocalSource(
                    type="local",
                    path=_form_value(form, "source_path") or "",
                )
            else:
                payload["source"] = GitSource(
                    type="git",
                    url=_form_value(form, "source_url") or "",
                    branch=_form_value(form, "source_branch"),
                    commit=_form_value(form, "source_commit"),
                )
        try:
            req = CreateTaskRequest.model_validate(payload)
        except ValidationError as exc:
            raise TaskError("INVALID_REQUEST", str(exc.errors())) from exc

        uploads: list[tuple[str, bytes]] = []
        for item in form.getlist("attachments"):
            if not hasattr(item, "read"):
                continue
            upload = item  # UploadFile-like
            content = await upload.read()
            name = getattr(upload, "filename", None) or "attachment.bin"
            uploads.append((str(name), content))
        return req, uploads

    body = await request.json()
    try:
        req = CreateTaskRequest.model_validate(body)
    except ValidationError as exc:
        raise TaskError("INVALID_REQUEST", str(exc.errors())) from exc
    return req, []


@router.post("/tasks", status_code=202, response_model=TaskSummary)
async def create_task(
    request: Request,
    manager: TaskManager = Depends(get_manager),
):
    try:
        payload, uploads = await _parse_create_payload(request)
        copy_from = None
        if payload.parent_task_id:
            parent = await asyncio.to_thread(manager.get_task, payload.parent_task_id)
            copy_from = parent["workspace"]
        task = await asyncio.to_thread(
            manager.create_task,
            payload,
            parent_task_id=payload.parent_task_id,
            action=payload.action,
            attachments=uploads or None,
            copy_attachments_from=copy_from,
        )
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.post("/tasks/import", response_model=ImportRunsResponse)
async def import_tasks(
    payload: ImportRunsRequest,
    manager: TaskManager = Depends(get_manager),
):
    try:
        result = await asyncio.to_thread(
            manager.import_runs,
            payload.path,
            dry_run=payload.dry_run,
            skip_existing=payload.skip_existing,
        )
    except TaskError as exc:
        return _error(exc)
    return ImportRunsResponse.model_validate(result)


@router.get("/tasks", response_model=TaskListResponse)
async def list_tasks(
    status: str | None = Query(default=None, description="Comma-separated statuses"),
    type: str | None = Query(default=None, alias="type"),
    action: str | None = Query(default=None, description="Comma-separated actions"),
    parent_task_id: str | None = None,
    scan_mode: str | None = Query(default=None, description="Comma-separated scan modes"),
    q: str | None = Query(default=None, description="Search id / name / target / source_url"),
    created_after: str | None = Query(default=None, description="ISO-8601 inclusive"),
    created_before: str | None = Query(default=None, description="ISO-8601 inclusive"),
    sort: str = Query(default="created_at"),
    order: str = Query(default="desc"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    include_findings_summary: bool = Query(default=True),
    manager: TaskManager = Depends(get_manager),
):
    try:
        status = _csv_allowlist("status", status, _LIST_STATUSES)
        task_type = _csv_allowlist("type", type, _LIST_TYPES)
        action = _csv_allowlist("action", action, _LIST_ACTIONS)
        scan_mode = _csv_allowlist("scan_mode", scan_mode, _LIST_MODES)
        created_after = _parse_list_time("created_after", created_after)
        created_before = _parse_list_time("created_before", created_before)
        if sort not in _LIST_SORTS:
            raise TaskError("INVALID_REQUEST", f"invalid sort: {sort}")
        if order not in _LIST_ORDERS:
            raise TaskError("INVALID_REQUEST", f"invalid order: {order}")
        query = (q or "").strip() or None
        if query and len(query) > 200:
            raise TaskError("INVALID_REQUEST", "q must be at most 200 characters")
        parent = (parent_task_id or "").strip() or None
    except TaskError as exc:
        return _error(exc)

    filters = {
        "status": status,
        "task_type": task_type,
        "action": action,
        "parent_task_id": parent,
        "scan_mode": scan_mode,
        "q": query,
        "created_after": created_after,
        "created_before": created_before,
    }

    def _load() -> tuple[list[dict[str, Any]], int]:
        rows = manager.list_tasks(
            **filters,
            sort=sort,
            order=order,
            limit=limit,
            offset=offset,
        )
        total = manager.count_tasks(**filters)
        return manager.attach_task_overlays(rows, include_findings=include_findings_summary), total

    try:
        tasks, total = await asyncio.to_thread(_load)
    except ValueError as exc:
        return _error(TaskError("INVALID_REQUEST", str(exc)))
    return TaskListResponse(
        tasks=[_summary(t, include_findings=include_findings_summary) for t in tasks],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/tasks/{task_id}", response_model=TaskSummary)
async def get_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.patch("/tasks/{task_id}", response_model=TaskSummary)
async def update_task(
    task_id: str,
    payload: UpdateTaskRequest,
    manager: TaskManager = Depends(get_manager),
):
    fields = payload.model_dump(exclude_unset=True)
    try:
        task = await asyncio.to_thread(manager.update_task_meta, task_id, fields)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.post("/tasks/{task_id}/hold", response_model=TaskSummary)
async def hold_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.hold_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.post("/tasks/{task_id}/release", status_code=202, response_model=TaskSummary)
async def release_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.release_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.post("/tasks/{task_id}/complete", response_model=TaskSummary)
async def complete_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.complete_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.post("/tasks/{task_id}/cancel", response_model=TaskSummary)
async def cancel_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.cancel_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.delete("/tasks/{task_id}", status_code=204)
async def delete_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        await asyncio.to_thread(manager.delete_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return Response(status_code=204)


@router.post("/tasks/{task_id}/retry", status_code=202, response_model=TaskSummary)
async def retry_task(
    task_id: str,
    payload: RetryTaskRequest | None = None,
    manager: TaskManager = Depends(get_manager),
):
    earliest_start = payload.earliest_start if payload else None
    try:
        task = await asyncio.to_thread(
            manager.retry_task,
            task_id,
            earliest_start=earliest_start,
        )
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.post("/tasks/{task_id}/retest", status_code=202, response_model=TaskSummary)
async def retest_task(
    task_id: str,
    payload: RetestTaskRequest | None = None,
    instruction: str | None = Query(default=None),
    manager: TaskManager = Depends(get_manager),
):
    note = (payload.instruction if payload else None) or instruction
    finding_ids = payload.finding_ids if payload else None
    try:
        task = await asyncio.to_thread(
            manager.retest_task,
            task_id,
            note,
            finding_ids=finding_ids,
        )
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.patch("/tasks/{task_id}/findings/{finding_id}", response_model=Finding)
async def update_finding(
    task_id: str,
    finding_id: str,
    payload: UpdateFindingRequest,
    manager: TaskManager = Depends(get_manager),
):
    try:
        finding = await asyncio.to_thread(
            manager.update_finding_review,
            task_id,
            finding_id,
            review_status=payload.review_status,
            request_test=payload.request_test,
        )
    except TaskError as exc:
        return _error(exc)
    return Finding.model_validate(finding)


@router.post(
    "/tasks/{task_id}/findings/{finding_id}/test",
    status_code=202,
    response_model=RequestFindingTestResponse,
)
async def request_finding_test(
    task_id: str,
    finding_id: str,
    manager: TaskManager = Depends(get_manager),
):
    try:
        result = await asyncio.to_thread(manager.request_finding_test, task_id, finding_id)
    except TaskError as exc:
        return _error(exc)
    return RequestFindingTestResponse(
        finding=Finding.model_validate(result["finding"]),
        task=_summarize(result["task"], manager),
    )


@router.post("/tasks/{task_id}/refresh-report", status_code=202, response_model=TaskSummary)
async def refresh_report(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.refresh_report, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.post("/tasks/{task_id}/resume", status_code=202, response_model=TaskSummary)
async def resume_task(
    task_id: str,
    payload: ResumeTaskRequest | None = None,
    manager: TaskManager = Depends(get_manager),
):
    instruction = payload.instruction if payload else None
    try:
        task = await asyncio.to_thread(manager.resume_task, task_id, instruction)
    except TaskError as exc:
        return _error(exc)
    return _summarize(task, manager)


@router.get("/tasks/{task_id}/results", response_model=FindingsResponse)
async def task_results(
    task_id: str,
    summary: bool = Query(
        default=False,
        description="Omit PoC/evidence bodies — use for list UIs; fetch one finding for detail",
    ),
    manager: TaskManager = Depends(get_manager),
):
    try:
        findings = await asyncio.to_thread(manager.get_results, task_id)
    except TaskError as exc:
        return _error(exc)
    if summary:
        findings = [summarize_finding(item) for item in findings]
    return FindingsResponse(task_id=task_id, findings=findings)


@router.get("/tasks/{task_id}/findings/{finding_id}", response_model=Finding)
async def get_finding(
    task_id: str,
    finding_id: str,
    manager: TaskManager = Depends(get_manager),
):
    try:
        finding = await asyncio.to_thread(manager.get_finding, task_id, finding_id)
    except TaskError as exc:
        return _error(exc)
    return finding


@router.get(
    "/tasks/{task_id}/report",
    response_model=ReportResponse,
    responses={
        200: {
            "description": (
                "JSON ``{task_id, format, content}`` by default. "
                "``download=true`` returns a zip attachment "
                "(markdown + images), not JSON."
            ),
        },
        404: {"description": "Report package not found"},
        409: {"description": "Report not ready"},
    },
)
async def task_report(
    task_id: str,
    download: bool = False,
    manager: TaskManager = Depends(get_manager),
):
    if download:
        try:
            task = await asyncio.to_thread(manager.get_task, task_id)
            package = await asyncio.to_thread(manager.get_report_package, task_id)
        except TaskError as exc:
            return _error(exc)
        return FileResponse(
            package,
            media_type="application/zip",
            filename=f"{report_download_stem(task)}.zip",
        )
    try:
        content = await asyncio.to_thread(manager.get_report, task_id)
    except TaskError as exc:
        return _error(exc)
    return ReportResponse(task_id=task_id, format="markdown", content=content)


@router.get("/tasks/{task_id}/events", response_model=EventsResponse)
async def task_events(
    task_id: str,
    limit: int = Query(default=500, ge=1, le=5000),
    manager: TaskManager = Depends(get_manager),
):
    try:
        events = await asyncio.to_thread(manager.get_events, task_id, limit=limit)
    except TaskError as exc:
        return _error(exc)
    return EventsResponse(task_id=task_id, events=events)


@router.get("/tasks/{task_id}/events/stream")
async def task_events_stream(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)

    async def event_generator():
        last_count = 0
        while True:
            task = await asyncio.to_thread(manager.get_task, task_id)
            events = await asyncio.to_thread(manager.get_events, task_id, limit=2000)
            if len(events) > last_count:
                for item in events[last_count:]:
                    payload = json.dumps(item, ensure_ascii=False, default=str)
                    yield f"event: progress\ndata: {payload}\n\n"
                last_count = len(events)
            status_payload = json.dumps(
                {"status": task["status"], "run_name": task.get("run_name")},
                ensure_ascii=False,
            )
            yield f"event: status\ndata: {status_payload}\n\n"
            if task["status"] in {"completed", "failed", "cancelled"}:
                yield "event: done\ndata: {}\n\n"
                break
            await asyncio.sleep(1.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/tasks/{task_id}/messages", response_model=MessagesResponse)
async def list_messages(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)
    rows = await asyncio.to_thread(manager.db.list_messages, task_id)
    messages = [
        {
            "id": row["id"],
            "task_id": row["task_id"],
            "role": row["role"],
            "content": row["content"],
            "created_at": row["created_at"],
            "delivered": bool(row["delivered"]),
        }
        for row in rows
    ]
    return MessagesResponse(task_id=task_id, messages=messages)


@router.post("/tasks/{task_id}/messages", response_model=MessagesResponse)
async def post_message(
    task_id: str,
    payload: MessageCreate,
    manager: TaskManager = Depends(get_manager),
):
    try:
        await asyncio.to_thread(
            lambda: manager.resume_with_message(
                task_id, payload.content, agent_id=payload.agent_id
            )
        )
        rows = await asyncio.to_thread(manager.db.list_messages, task_id)
    except TaskError as exc:
        return _error(exc)
    messages = [
        {
            "id": row["id"],
            "task_id": row["task_id"],
            "role": row["role"],
            "content": row["content"],
            "created_at": row["created_at"],
            "delivered": bool(row["delivered"]),
        }
        for row in rows
    ]
    return MessagesResponse(task_id=task_id, messages=messages)


@router.get("/tasks/{task_id}/artifacts", response_model=ArtifactsResponse)
async def task_artifacts(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)
    run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
    artifacts = list_artifacts(run_dir) if run_dir else []
    return ArtifactsResponse(task_id=task_id, artifacts=artifacts)


@router.get("/tasks/{task_id}/logs", response_model=TaskLogsResponse)
async def task_logs(
    task_id: str,
    download: bool = False,
    manager: TaskManager = Depends(get_manager),
):
    if download:
        try:
            package = await asyncio.to_thread(manager.get_logs_package, task_id)
        except TaskError as exc:
            return _error(exc)
        return FileResponse(
            package,
            media_type="application/zip",
            filename=f"{task_id}-logs.zip",
        )
    try:
        logs = await asyncio.to_thread(manager.list_logs, task_id)
    except TaskError as exc:
        return _error(exc)
    return TaskLogsResponse(task_id=task_id, logs=logs)


@router.get("/tasks/{task_id}/logs/{log_path:path}")
async def download_task_log(
    task_id: str,
    log_path: str,
    manager: TaskManager = Depends(get_manager),
):
    try:
        task = await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)
    path = resolve_task_log(Path(task["workspace"]), log_path)
    if path is None:
        return _error(TaskError("LOGS_NOT_FOUND", "Log file not found", 404))
    return FileResponse(path, filename=path.name)


@router.get("/tasks/{task_id}/artifacts/{artifact_path:path}")
async def download_artifact(
    task_id: str,
    artifact_path: str,
    manager: TaskManager = Depends(get_manager),
):
    try:
        task = await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)
    run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
    if not run_dir:
        return _error(TaskError("RESULT_NOT_READY", "Artifacts not ready", 409))
    path = resolve_artifact(run_dir, artifact_path)
    if path is None:
        return _error(TaskError("TASK_NOT_FOUND", "Artifact not found", 404))
    return FileResponse(path, filename=path.name)
