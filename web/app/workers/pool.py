"""Background worker pool with concurrency + host admission control."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from app.db import utc_now
from app.services.system_load import effective_concurrency, sample_system
from app.services.task_manager import TaskError


if TYPE_CHECKING:
    from app.services.task_manager import TaskManager

logger = logging.getLogger(__name__)


class WorkerPool:
    def __init__(self, manager: TaskManager) -> None:
        self.manager = manager
        self.settings = manager.settings
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._running = False
        self._last_admission: dict[str, Any] = {
            "allowed_slots": self.settings.max_concurrent,
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
        self._task = asyncio.create_task(self._loop(), name="strix-api-worker")

    async def stop(self) -> None:
        self._stop.set()
        self._running = False
        if self._task is not None:
            await self._task
            self._task = None

    async def _loop(self) -> None:
        logger.info(
            "worker pool started max_concurrent=%s min_free_mem=%sGiB max_load_per_cpu=%s",
            self.settings.max_concurrent,
            self.settings.min_free_memory_gb,
            self.settings.max_load_per_cpu,
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
        for task_id, process in list(self.manager._processes.items()):
            code = process.poll()
            if code is None:
                name = process.refresh_run_name()
                if name:
                    self.manager.db.update_task(task_id, run_name=name)
                continue
            task = self.manager.db.get_task(task_id)
            cancelled = bool(task and task["status"] == "cancelling")
            await asyncio.to_thread(self.manager.finish_process, task_id, cancelled=cancelled)

        snap = sample_system()
        allowed, reason = effective_concurrency(
            max_concurrent=self.settings.max_concurrent,
            min_free_memory_gb=self.settings.min_free_memory_gb,
            max_load_per_cpu=self.settings.max_load_per_cpu,
            snapshot=snap,
        )
        self._last_admission = {
            "allowed_slots": allowed,
            "reason": reason,
            "system": snap.as_dict(),
        }

        running = self.manager.active_process_count()
        slots = allowed - running
        if slots <= 0:
            if allowed == 0 and self.manager.db.count_by_status("queued") > 0:
                logger.info("admission paused; queued tasks waiting (%s)", reason)
            return

        for _ in range(slots):
            claimed = await asyncio.to_thread(self.manager.db.claim_next_queued)
            if not claimed:
                break
            await self._launch(claimed)

    async def _launch(self, task: dict) -> None:
        task_id = task["id"]
        try:
            target = await asyncio.to_thread(self.manager.prepare_target, task)
            task = self.manager.get_task(task_id)
            process = await asyncio.to_thread(self.manager.start_process, task, target)
            logger.info("task %s running pid=%s", task_id, process.pid)
        except TaskError as exc:
            logger.error("task %s failed to start: %s", task_id, exc.message)
            self.manager.db.update_task(
                task_id,
                status="failed",
                error=exc.message,
                finished_at=utc_now(),
            )
        except Exception as exc:
            logger.exception("task %s crashed during start", task_id)
            self.manager.db.update_task(
                task_id,
                status="failed",
                error=str(exc),
                finished_at=utc_now(),
            )
