"""Task REST endpoints."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from app.schemas import (
    ArtifactsResponse,
    CreateTaskRequest,
    EventsResponse,
    FindingsResponse,
    MessageCreate,
    MessagesResponse,
    ReportResponse,
    TaskListResponse,
    TaskSummary,
)
from app.api.viewer_proxy import attach_viewer_proxy_url
from app.security.auth import require_api_key
from app.services.results import list_artifacts, resolve_artifact, workspace_run_dir
from app.services.task_manager import TaskError, TaskManager


router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


def get_manager(request: Request) -> TaskManager:
    return request.app.state.manager


def _error(exc: TaskError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


def _summary(task: dict[str, Any]) -> TaskSummary:
    return TaskSummary.model_validate(attach_viewer_proxy_url(task))


@router.post("/tasks", status_code=202, response_model=TaskSummary)
async def create_task(
    payload: CreateTaskRequest,
    manager: TaskManager = Depends(get_manager),
):
    try:
        task = await asyncio.to_thread(manager.create_task, payload)
    except TaskError as exc:
        return _error(exc)
    return _summary(task)


@router.get("/tasks", response_model=TaskListResponse)
async def list_tasks(
    status: str | None = None,
    type: str | None = Query(default=None, alias="type"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    manager: TaskManager = Depends(get_manager),
):
    tasks = await asyncio.to_thread(
        manager.list_tasks, status=status, task_type=type, limit=limit, offset=offset
    )
    return TaskListResponse(tasks=[_summary(t) for t in tasks], total=len(tasks))


@router.get("/tasks/{task_id}", response_model=TaskSummary)
async def get_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summary(task)


@router.post("/tasks/{task_id}/cancel", response_model=TaskSummary)
async def cancel_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.cancel_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summary(task)


@router.post("/tasks/{task_id}/retry", status_code=202, response_model=TaskSummary)
async def retry_task(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        task = await asyncio.to_thread(manager.retry_task, task_id)
    except TaskError as exc:
        return _error(exc)
    return _summary(task)


@router.post("/tasks/{task_id}/retest", status_code=202, response_model=TaskSummary)
async def retest_task(
    task_id: str,
    instruction: str | None = Query(default=None),
    manager: TaskManager = Depends(get_manager),
):
    try:
        task = await asyncio.to_thread(manager.retest_task, task_id, instruction)
    except TaskError as exc:
        return _error(exc)
    return _summary(task)


@router.get("/tasks/{task_id}/results", response_model=FindingsResponse)
async def task_results(task_id: str, manager: TaskManager = Depends(get_manager)):
    try:
        findings = await asyncio.to_thread(manager.get_results, task_id)
    except TaskError as exc:
        return _error(exc)
    return FindingsResponse(task_id=task_id, findings=findings)


@router.get("/tasks/{task_id}/report", response_model=ReportResponse)
async def task_report(
    task_id: str,
    download: bool = False,
    manager: TaskManager = Depends(get_manager),
):
    try:
        content = await asyncio.to_thread(manager.get_report, task_id)
    except TaskError as exc:
        return _error(exc)
    if download:
        return StreamingResponse(
            iter([content.encode("utf-8")]),
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{task_id}-report.md"'
            },
        )
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
