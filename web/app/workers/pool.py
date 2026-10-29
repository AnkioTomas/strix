"""Background loop: finalize finished scans + reap orphan sandboxes."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

from app.services.sandbox_reaper import reap_stopped_job_sandboxes
from app.services.system_load import effective_concurrency, sample_system


if TYPE_CHECKING:
    from app.services.job_manager import JobManager

logger = logging.getLogger(__name__)


class WorkerPool:
    def __init__(self, manager: JobManager) -> None:
        self.manager = manager
        self.settings = manager.settings
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._running = False
        self._last_sandbox_reap = 0.0
        self._last_admission: dict[str, Any] = {
            "allowed_slots": self.settings.max_concurrent,
            "free_slots": self.settings.max_concurrent,
            "running": 0,
            "reason": "ok:init",
            "system": {},
        }

    @property
    def healthy(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def admission_status(self) -> dict[str, Any]:
        return dict(self._last_admission)

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="strix-node-worker")

    async def stop(self) -> None:
        self._stop.set()
        self._running = False
        if self._task is not None:
            await self._task
            self._task = None

    async def _loop(self) -> None:
        logger.info(
            "worker pool started max_concurrent=%s task_est=%s%%CPU+%sGiB",
            self.settings.max_concurrent,
            self.settings.task_cpu_percent,
            self.settings.task_memory_gb,
        )
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:
                logger.exception("worker tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=1.0)
            except TimeoutError:
                continue
        logger.info("worker pool stopped")

    async def _tick(self) -> None:
        for job_id, process in list(self.manager._processes.items()):
            code = process.poll()
            if code is None:
                name = process.refresh_run_name()
                if name:
                    self.manager.store.update(job_id, run_name=name)
                continue
            job = self.manager.store.get(job_id)
            cancelled = bool(job and job["status"] == "cancelling")
            await asyncio.to_thread(self.manager.finish_process, job_id, cancelled=cancelled)

        await self._maybe_reap_sandboxes()

        snap = sample_system()
        allowed, reason = effective_concurrency(
            max_concurrent=self.settings.max_concurrent,
            task_cpu_percent=self.settings.task_cpu_percent,
            task_memory_gb=self.settings.task_memory_gb,
            snapshot=snap,
        )
        running = self.manager.active_process_count()
        self._last_admission = {
            "allowed_slots": allowed,
            "running": running,
            "free_slots": max(0, allowed - running),
            "reason": reason,
            "task_cpu_percent": self.settings.task_cpu_percent,
            "task_memory_gb": self.settings.task_memory_gb,
            "max_concurrent": self.settings.max_concurrent,
            "system": snap.as_dict(),
        }

    async def _maybe_reap_sandboxes(self) -> None:
        interval = int(self.settings.sandbox_reap_interval)
        if interval <= 0:
            return
        now = time.monotonic()
        if now - self._last_sandbox_reap < interval:
            return
        self._last_sandbox_reap = now
        jobs = await asyncio.to_thread(self.manager.store.list_jobs)
        await asyncio.to_thread(reap_stopped_job_sandboxes, jobs)
