"""Health endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.schemas import HealthResponse
from app.services.strix_runner import strix_available


router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    manager = request.app.state.manager
    worker = request.app.state.worker
    db_ok = True
    try:
        manager.db.count_by_status("queued")
    except Exception:
        db_ok = False
    admission = worker.admission_status() if hasattr(worker, "admission_status") else None
    return HealthResponse(
        status="ok" if db_ok and worker.healthy else "degraded",
        strix=strix_available(manager.settings),
        worker=worker.healthy,
        database=db_ok,
        running_tasks=manager.db.count_by_status("running")
        + manager.db.count_by_status("starting"),
        queued_tasks=manager.db.count_by_status("queued"),
        admission=admission,
    )
