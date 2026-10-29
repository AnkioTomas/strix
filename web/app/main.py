"""Strix worker-node API entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.api.health import router as health_router
from app.api.jobs import router as jobs_router
from app.api.node import router as node_router
from app.config import get_settings
from app.job_store import JobStore
from app.services.job_manager import JobManager
from app.workers.pool import WorkerPool


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("strix-node")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store = JobStore(settings.jobs_dir)
    manager = JobManager(store, settings)
    worker = WorkerPool(manager)
    app.state.settings = settings
    app.state.store = store
    app.state.manager = manager
    app.state.worker = worker
    reattached = manager.reattach_running_scans()
    await worker.start()
    logger.info(
        "Strix worker node listening node_id=%s data_dir=%s max_concurrent=%s reattached=%s",
        settings.resolved_node_id,
        settings.data_dir,
        settings.max_concurrent,
        reattached,
    )
    yield
    await worker.stop()
    logger.info(
        "API shutting down; %s detached scan(s) left running",
        manager.active_process_count(),
    )


app = FastAPI(
    title="Strix Worker Node",
    version="0.2.0",
    description="Distributed scan worker controlled by a master over HTTP.",
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(node_router)
app.include_router(jobs_router)


@app.exception_handler(ValidationError)
async def validation_error_handler(_request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "INVALID_REQUEST",
                "message": str(exc.errors()),
            }
        },
    )


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
