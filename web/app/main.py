"""Local Strix Security API entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError

from app.api.health import router as health_router
from app.api.tasks import router as tasks_router
from app.config import get_settings
from app.db import Database
from app.services.task_manager import TaskManager
from app.workers.pool import WorkerPool


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("strix-api")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db = Database(settings.database_path)
    manager = TaskManager(db, settings)
    worker = WorkerPool(manager)
    app.state.settings = settings
    app.state.db = db
    app.state.manager = manager
    app.state.worker = worker
    await worker.start()
    logger.info(
        "Strix API listening data_dir=%s max_concurrent=%s",
        settings.data_dir,
        settings.max_concurrent,
    )
    yield
    await worker.stop()


app = FastAPI(
    title="Local Strix Security API",
    version="0.1.0",
    description="Task orchestration layer over local Strix CLI scans.",
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(tasks_router)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.exception_handler(ValidationError)
async def validation_error_handler(_request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "INVALID_TASK_TYPE",
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
