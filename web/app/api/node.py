"""Node capacity / identity endpoint for the master scheduler."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.schemas import JobSummary, NodeCapacity, NodeInfo
from app.security.auth import require_api_key
from app.services.job_manager import JobManager


router = APIRouter(prefix="/v1", dependencies=[Depends(require_api_key)])

NODE_VERSION = "0.2.0"


def get_manager(request: Request) -> JobManager:
    return request.app.state.manager


@router.get("/node", response_model=NodeInfo)
async def node_info(request: Request, manager: JobManager = Depends(get_manager)) -> NodeInfo:
    worker = request.app.state.worker
    admission = worker.admission_status() if hasattr(worker, "admission_status") else manager.admission()
    free = int(admission.get("free_slots", 0))
    running = int(admission.get("running", 0))
    if not worker.healthy:
        status = "degraded"
    elif free <= 0:
        status = "full"
    else:
        status = "ready"

    jobs = [
        JobSummary.model_validate(manager.summarize(job))
        for job in manager.list_jobs()
        if job.get("status") in {"starting", "running", "cancelling"}
    ]
    return NodeInfo(
        node_id=manager.settings.resolved_node_id,
        version=NODE_VERSION,
        status=status,
        capacity=NodeCapacity(
            max_concurrent=int(admission.get("max_concurrent", manager.settings.max_concurrent)),
            running=running,
            free_slots=free,
            reason=str(admission.get("reason") or ""),
            task_cpu_percent=float(
                admission.get("task_cpu_percent", manager.settings.task_cpu_percent)
            ),
            task_memory_gb=float(
                admission.get("task_memory_gb", manager.settings.task_memory_gb)
            ),
        ),
        system=dict(admission.get("system") or {}),
        jobs=jobs,
    )
