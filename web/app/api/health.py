"""Health endpoint."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request

from app.schemas import HealthResponse
from app.services.strix_runner import strix_available


router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    manager = request.app.state.manager
    worker = request.app.state.worker
    admission = worker.admission_status() if hasattr(worker, "admission_status") else manager.admission()
    return HealthResponse(
        status="ok" if worker.healthy else "degraded",
        node_id=manager.settings.resolved_node_id,
        strix=await asyncio.to_thread(strix_available, manager.settings),
        worker=worker.healthy,
        running_jobs=int(admission.get("running", 0)),
        free_slots=int(admission.get("free_slots", 0)),
        admission=admission,
    )
