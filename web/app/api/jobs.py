"""Job control API for the worker node."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import ValidationError

from app.schemas import (
    ArtifactsResponse,
    CreateJobRequest,
    EventsResponse,
    JobListResponse,
    JobLogsResponse,
    JobResultResponse,
    JobSummary,
    SteerRequest,
)
from app.security.auth import require_api_key
from app.services.attachments import MAX_ATTACHMENTS, MAX_ATTACHMENT_BYTES
from app.services.job_manager import JobError, JobManager


router = APIRouter(prefix="/v1", dependencies=[Depends(require_api_key)])


def get_manager(request: Request) -> JobManager:
    return request.app.state.manager


def _error(exc: JobError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


def _summary(manager: JobManager, job: dict[str, Any]) -> JobSummary:
    return JobSummary.model_validate(manager.summarize(job))


async def _parse_create_payload(
    request: Request,
) -> tuple[CreateJobRequest, list[tuple[str, bytes]]]:
    content_type = (request.headers.get("content-type") or "").lower()
    if "multipart/form-data" in content_type:
        form = await request.form()
        raw = form.get("payload") or form.get("json")
        if raw is None:
            raise JobError("INVALID_REQUEST", "multipart requires payload= JSON field")
        try:
            data = json.loads(str(raw))
        except json.JSONDecodeError as exc:
            raise JobError("INVALID_REQUEST", f"invalid payload JSON: {exc}") from exc
        try:
            req = CreateJobRequest.model_validate(data)
        except ValidationError as exc:
            raise JobError("INVALID_REQUEST", str(exc.errors())) from exc
        uploads: list[tuple[str, bytes]] = []
        files = form.getlist("files") or form.getlist("file")
        if len(files) > MAX_ATTACHMENTS:
            raise JobError("INVALID_ATTACHMENT", f"Too many attachments (max {MAX_ATTACHMENTS})")
        for item in files:
            if not isinstance(item, UploadFile):
                continue
            content = await item.read()
            if len(content) > MAX_ATTACHMENT_BYTES:
                raise JobError(
                    "INVALID_ATTACHMENT",
                    f"{item.filename}: exceeds {MAX_ATTACHMENT_BYTES} bytes",
                )
            uploads.append((item.filename or "file", content))
        return req, uploads

    data = await request.json()
    try:
        return CreateJobRequest.model_validate(data), []
    except ValidationError as exc:
        raise JobError("INVALID_REQUEST", str(exc.errors())) from exc


@router.post("/jobs", status_code=202, response_model=JobSummary)
async def create_job(request: Request, manager: JobManager = Depends(get_manager)):
    try:
        req, uploads = await _parse_create_payload(request)
        job = await asyncio.to_thread(manager.create_job, req, attachments=uploads or None)
        return _summary(manager, job)
    except JobError as exc:
        return _error(exc)


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(manager: JobManager = Depends(get_manager)):
    jobs = [_summary(manager, job) for job in manager.list_jobs()]
    return JobListResponse(jobs=jobs, total=len(jobs))


@router.get("/jobs/{job_id}", response_model=JobSummary)
async def get_job(job_id: str, manager: JobManager = Depends(get_manager)):
    try:
        return _summary(manager, manager.get_job(job_id))
    except JobError as exc:
        return _error(exc)


@router.post("/jobs/{job_id}/cancel", response_model=JobSummary)
async def cancel_job(job_id: str, manager: JobManager = Depends(get_manager)):
    try:
        job = await asyncio.to_thread(manager.cancel_job, job_id)
        return _summary(manager, job)
    except JobError as exc:
        return _error(exc)


@router.post("/jobs/{job_id}/steer")
async def steer_job(
    job_id: str,
    body: SteerRequest,
    manager: JobManager = Depends(get_manager),
):
    try:
        return await asyncio.to_thread(
            manager.steer_job, job_id, body.message, agent_id=body.agent_id
        )
    except JobError as exc:
        return _error(exc)


@router.get("/jobs/{job_id}/result", response_model=JobResultResponse)
async def job_result(job_id: str, manager: JobManager = Depends(get_manager)):
    try:
        payload = manager.get_result(job_id)
        payload["job"] = _summary(manager, payload["job"])
        return JobResultResponse.model_validate(payload)
    except JobError as exc:
        return _error(exc)


@router.get("/jobs/{job_id}/events", response_model=EventsResponse)
async def job_events(
    job_id: str,
    limit: int = 500,
    manager: JobManager = Depends(get_manager),
):
    try:
        return EventsResponse(events=manager.get_events(job_id, limit=limit))
    except JobError as exc:
        return _error(exc)


@router.get("/jobs/{job_id}/artifacts", response_model=ArtifactsResponse)
async def job_artifacts(job_id: str, manager: JobManager = Depends(get_manager)):
    try:
        return ArtifactsResponse(artifacts=manager.get_artifacts(job_id))
    except JobError as exc:
        return _error(exc)


@router.get("/jobs/{job_id}/artifacts/{artifact_path:path}")
async def download_artifact(
    job_id: str,
    artifact_path: str,
    manager: JobManager = Depends(get_manager),
):
    try:
        path = manager.get_artifact_file(job_id, artifact_path)
        return FileResponse(path, filename=path.name)
    except JobError as exc:
        return _error(exc)


@router.get("/jobs/{job_id}/logs", response_model=JobLogsResponse)
async def job_logs(job_id: str, manager: JobManager = Depends(get_manager)):
    try:
        return JobLogsResponse(logs=manager.get_logs(job_id))
    except JobError as exc:
        return _error(exc)


@router.get("/jobs/{job_id}/logs/{log_path:path}")
async def download_log(
    job_id: str,
    log_path: str,
    manager: JobManager = Depends(get_manager),
):
    try:
        path = manager.get_log_file(job_id, log_path)
        return FileResponse(path, filename=path.name)
    except JobError as exc:
        return _error(exc)


@router.delete("/jobs/{job_id}", status_code=204)
async def delete_job(job_id: str, manager: JobManager = Depends(get_manager)):
    try:
        await asyncio.to_thread(manager.delete_job, job_id)
        return Response(status_code=204)
    except JobError as exc:
        return _error(exc)
