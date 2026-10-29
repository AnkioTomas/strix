"""Filesystem job state — no SQLite catalog."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ACTIVE_STATUSES = frozenset({"starting", "running", "cancelling"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})
JOB_FILENAME = "job.json"


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class JobStore:
    """One ``job.json`` per workspace under ``jobs_dir/<id>/``."""

    def __init__(self, jobs_dir: Path) -> None:
        self.jobs_dir = Path(jobs_dir)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    def job_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / JOB_FILENAME

    def exists(self, job_id: str) -> bool:
        return self.job_path(job_id).is_file()

    def get(self, job_id: str) -> dict[str, Any] | None:
        path = self.job_path(job_id)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def list_jobs(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not self.jobs_dir.is_dir():
            return rows
        for child in sorted(self.jobs_dir.iterdir()):
            if not child.is_dir():
                continue
            job = self.get(child.name)
            if job is not None:
                rows.append(job)
        return rows

    def count_active(self) -> int:
        return sum(1 for job in self.list_jobs() if job.get("status") in ACTIVE_STATUSES)

    def list_by_status(self, *statuses: str) -> list[dict[str, Any]]:
        wanted = set(statuses)
        return [job for job in self.list_jobs() if job.get("status") in wanted]

    def insert(self, job: dict[str, Any]) -> dict[str, Any]:
        job_id = str(job["id"])
        with self._lock:
            if self.exists(job_id):
                raise ValueError(f"job already exists: {job_id}")
            workspace = self.job_dir(job_id)
            workspace.mkdir(parents=True, exist_ok=False)
            job = dict(job)
            job["workspace"] = str(workspace)
            self._write(job_id, job)
            return job

    def update(self, job_id: str, **fields: Any) -> dict[str, Any] | None:
        with self._lock:
            current = self.get(job_id)
            if current is None:
                return None
            current.update(fields)
            current["updated_at"] = utc_now()
            self._write(job_id, current)
            return current

    def delete(self, job_id: str) -> bool:
        with self._lock:
            workspace = self.job_dir(job_id)
            if not workspace.exists():
                return False
            import shutil

            shutil.rmtree(workspace, ignore_errors=True)
            return True

    def _write(self, job_id: str, job: dict[str, Any]) -> None:
        path = self.job_path(job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".job.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(job, handle, ensure_ascii=False, default=str)
                handle.write("\n")
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
