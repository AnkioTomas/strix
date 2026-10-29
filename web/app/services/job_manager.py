"""Worker-node job lifecycle: accept, run, steer, finish, delete."""

from __future__ import annotations

import contextlib
import logging
import shutil
import threading
import uuid
from pathlib import Path
from typing import Any

from app.config import Settings
from app.job_store import ACTIVE_STATUSES, JobStore, utc_now
from app.schemas import CreateJobRequest, GitSource, LocalSource
from app.security.source import SourceValidationError, validate_source
from app.security.target import TargetValidationError, check_tcp_reachable, validate_pentest_target
from app.services.artifacts import (
    count_disk_findings,
    discover_run_name,
    load_normalized_findings,
    list_artifacts,
    list_job_logs,
    read_events,
    read_report_markdown,
    read_run_overview,
    read_run_record,
    read_vulnerabilities,
    report_exists,
    resolve_artifact,
    resolve_job_log,
    workspace_run_dir,
)
from app.services.attachments import save_uploads
from app.services.findings import empty_finding_counts
from app.services.git_clone import GitError, clone_repository
from app.services.strix_runner import (
    DetachedScanHandle,
    close_process_logs,
    start_strix,
)
from app.services.system_load import effective_concurrency, sample_system


logger = logging.getLogger(__name__)


class JobError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class JobManager:
    def __init__(self, store: JobStore, settings: Settings) -> None:
        self.store = store
        self.settings = settings
        self._processes: dict[str, DetachedScanHandle] = {}
        self._admit_lock = threading.Lock()

    # --- capacity ---

    def admission(self) -> dict[str, Any]:
        snap = sample_system()
        allowed, reason = effective_concurrency(
            max_concurrent=self.settings.max_concurrent,
            task_cpu_percent=self.settings.task_cpu_percent,
            task_memory_gb=self.settings.task_memory_gb,
            snapshot=snap,
        )
        running = self.active_process_count()
        free = max(0, allowed - running)
        return {
            "allowed_slots": allowed,
            "running": running,
            "free_slots": free,
            "reason": reason,
            "task_cpu_percent": self.settings.task_cpu_percent,
            "task_memory_gb": self.settings.task_memory_gb,
            "max_concurrent": self.settings.max_concurrent,
            "system": snap.as_dict(),
        }

    def active_process_count(self) -> int:
        return self.store.count_active()

    # --- create / get ---

    def create_job(
        self,
        req: CreateJobRequest,
        *,
        attachments: list[tuple[str, bytes]] | None = None,
    ) -> dict[str, Any]:
        """Accept a job only when a free slot exists. Otherwise raise NODE_FULL."""
        job_id = (req.id or "").strip() or f"job_{uuid.uuid4().hex[:16]}"
        target, source_fields = self._validate_request(req)

        now = utc_now()
        row = {
            "id": job_id,
            "type": req.type,
            "status": "starting",
            "name": (req.name or "").strip() or None,
            "target": target,
            **source_fields,
            "instruction": req.instruction,
            "scan_mode": req.scan_mode,
            "max_budget": req.max_budget,
            "proxy_url": req.proxy_url,
            "request_headers": req.request_headers,
            "workspace": "",  # filled by store.insert
            "run_name": None,
            "viewer_url": None,
            "viewer_token": None,
            "pid": None,
            "exit_code": None,
            "error": None,
            "created_at": now,
            "started_at": now,
            "finished_at": None,
            "updated_at": now,
        }

        with self._admit_lock:
            admission = self.admission()
            if admission["free_slots"] <= 0:
                raise JobError(
                    "NODE_FULL",
                    f"no free slots ({admission['reason']})",
                    status_code=503,
                )
            if self.store.exists(job_id):
                raise JobError("JOB_EXISTS", f"job already exists: {job_id}", status_code=409)
            try:
                job = self.store.insert(row)
            except OSError as exc:
                raise JobError("JOB_CREATE_FAILED", str(exc), status_code=500) from exc

        workspace = Path(job["workspace"])
        try:
            (workspace / "source").mkdir(exist_ok=True)
            (workspace / "logs").mkdir(exist_ok=True)
            (workspace / "attachments").mkdir(exist_ok=True)
            if attachments:
                save_uploads(workspace, attachments)
        except ValueError as exc:
            self.store.delete(job_id)
            raise JobError("INVALID_ATTACHMENT", str(exc)) from exc
        except OSError as exc:
            self.store.delete(job_id)
            raise JobError("JOB_CREATE_FAILED", str(exc), status_code=500) from exc

        try:
            prepared = self.prepare_target(job)
            process = self.start_process(job, prepared)
        except JobError as exc:
            self.store.update(
                job_id,
                status="failed",
                error=exc.message,
                finished_at=utc_now(),
                pid=None,
            )
            raise
        except Exception as exc:
            logger.exception("job %s failed to start", job_id)
            self.store.update(
                job_id,
                status="failed",
                error=str(exc),
                finished_at=utc_now(),
                pid=None,
            )
            raise JobError("STRIX_START_FAILED", str(exc), status_code=500) from exc

        logger.info("job %s running pid=%s", job_id, process.pid)
        return self.get_job(job_id)

    def _validate_request(
        self, req: CreateJobRequest
    ) -> tuple[str, dict[str, Any]]:
        source_fields: dict[str, Any] = {
            "source_type": None,
            "source_url": None,
            "source_branch": None,
            "source_commit": None,
            "source_path": None,
        }
        try:
            if req.type == "pentest":
                assert req.target is not None
                target = validate_pentest_target(req.target, self.settings)
                check_tcp_reachable(target, proxy_url=req.proxy_url)
                return target, source_fields

            assert req.source is not None
            source = validate_source(req.source, self.settings)
            if isinstance(source, GitSource):
                source_fields.update(
                    {
                        "source_type": "git",
                        "source_url": source.url,
                        "source_branch": source.branch,
                        "source_commit": source.commit,
                    }
                )
                return source.url, source_fields
            assert isinstance(source, LocalSource)
            source_fields.update(
                {
                    "source_type": "local",
                    "source_path": source.path,
                }
            )
            return source.path, source_fields
        except (TargetValidationError, SourceValidationError) as exc:
            raise JobError(exc.code, exc.message) from exc

    def get_job(self, job_id: str) -> dict[str, Any]:
        job = self.store.get(job_id)
        if job is None:
            raise JobError("JOB_NOT_FOUND", f"job not found: {job_id}", status_code=404)
        return job

    def list_jobs(self) -> list[dict[str, Any]]:
        return self.store.list_jobs()

    def summarize(self, job: dict[str, Any]) -> dict[str, Any]:
        """Attach disk-derived finding counts / report flag for API responses."""
        out = dict(job)
        run_dir = workspace_run_dir(Path(job["workspace"]), job.get("run_name"))
        if run_dir is None:
            run_name = discover_run_name(Path(job["workspace"]))
            if run_name:
                out["run_name"] = run_name
                run_dir = workspace_run_dir(Path(job["workspace"]), run_name)
        if run_dir is None:
            out["finding_counts"] = empty_finding_counts()
            out["has_report"] = False
            out["llm_usage"] = None
            out["duration_seconds"] = None
            return out
        out["finding_counts"] = count_disk_findings(run_dir)
        out["has_report"] = report_exists(run_dir)
        overview = read_run_overview(run_dir)
        out["llm_usage"] = overview.get("llm_usage")
        out["duration_seconds"] = overview.get("duration_seconds")
        return out

    # --- control ---

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        job = self.get_job(job_id)
        if job["status"] in {"completed", "failed", "cancelled"}:
            return job
        self.store.update(job_id, status="cancelling")
        process = self._processes.get(job_id)
        if process is not None and process.poll() is None:
            process.terminate(self.settings.cancel_grace_seconds)
        return self.finish_process(job_id, cancelled=True)

    def steer_job(self, job_id: str, message: str, *, agent_id: str | None = None) -> dict[str, Any]:
        job = self.get_job(job_id)
        if job["status"] not in {"starting", "running"}:
            raise JobError("JOB_NOT_RUNNING", "job is not running", status_code=409)
        process = self._processes.get(job_id)
        if process is None:
            process = DetachedScanHandle.attach(Path(job["workspace"]), job_id)
            self._processes[job_id] = process
        ok = process.send_message(message, agent_id=agent_id)
        if not ok:
            raise JobError("STEER_FAILED", "failed to deliver message to scan", status_code=502)
        return {"ok": True, "job_id": job_id}

    def delete_job(self, job_id: str) -> None:
        job = self.get_job(job_id)
        if job["status"] in ACTIVE_STATUSES:
            raise JobError(
                "JOB_ACTIVE",
                "cancel the job before deleting",
                status_code=409,
            )
        process = self._processes.pop(job_id, None)
        if process is not None and process.poll() is None:
            process.terminate(self.settings.cancel_grace_seconds)
            close_process_logs(process)
        self._stop_job_sandbox(job)
        self.store.delete(job_id)

    # --- results ---

    def get_result(self, job_id: str) -> dict[str, Any]:
        job = self.summarize(self.get_job(job_id))
        run_dir = workspace_run_dir(Path(job["workspace"]), job.get("run_name"))
        findings: list[dict[str, Any]] = []
        report: str | None = None
        overview: dict[str, Any] | None = None
        if run_dir is not None:
            findings = load_normalized_findings(run_dir, job_id=job_id)
            report = read_report_markdown(run_dir)
            overview = read_run_overview(run_dir)
        return {
            "job": job,
            "findings": findings,
            "finding_counts": job.get("finding_counts") or empty_finding_counts(),
            "report_markdown": report,
            "overview": overview,
        }

    def get_events(self, job_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
        job = self.get_job(job_id)
        run_dir = workspace_run_dir(Path(job["workspace"]), job.get("run_name"))
        if run_dir is None:
            return []
        return read_events(run_dir, limit=limit)

    def get_artifacts(self, job_id: str) -> list[dict[str, Any]]:
        job = self.get_job(job_id)
        run_dir = workspace_run_dir(Path(job["workspace"]), job.get("run_name"))
        if run_dir is None:
            return []
        return list_artifacts(run_dir)

    def get_artifact_file(self, job_id: str, path: str) -> Path:
        job = self.get_job(job_id)
        run_dir = workspace_run_dir(Path(job["workspace"]), job.get("run_name"))
        if run_dir is None:
            raise JobError("ARTIFACT_NOT_FOUND", "no run artifacts", status_code=404)
        resolved = resolve_artifact(run_dir, path)
        if resolved is None:
            raise JobError("ARTIFACT_NOT_FOUND", path, status_code=404)
        return resolved

    def get_logs(self, job_id: str) -> list[dict[str, Any]]:
        job = self.get_job(job_id)
        return list_job_logs(Path(job["workspace"]))

    def get_log_file(self, job_id: str, path: str) -> Path:
        job = self.get_job(job_id)
        resolved = resolve_job_log(Path(job["workspace"]), path)
        if resolved is None:
            raise JobError("LOG_NOT_FOUND", path, status_code=404)
        return resolved

    # --- process lifecycle ---

    def prepare_target(self, job: dict[str, Any]) -> str:
        workspace = Path(job["workspace"])
        if job["type"] == "pentest":
            return str(job["target"])
        if job["source_type"] == "local":
            return str(job["source_path"])
        source_dir = workspace / "source" / "repo"
        if source_dir.exists():
            return str(source_dir)
        try:
            clone_repository(
                str(job["source_url"]),
                source_dir,
                branch=job.get("source_branch"),
                commit=job.get("source_commit"),
                settings=self.settings,
            )
        except GitError as exc:
            raise JobError("STRIX_START_FAILED", str(exc)) from exc
        return str(source_dir)

    def start_process(self, job: dict[str, Any], target: str) -> DetachedScanHandle:
        job_id = job["id"]

        def on_ready(session: DetachedScanHandle) -> None:
            self.store.update(
                job_id,
                run_name=session.run_name,
                viewer_url=session.viewer_url,
                viewer_token=session.viewer_token,
                pid=session.pid,
            )

        try:
            process = start_strix(
                job,
                settings=self.settings,
                target=target,
                on_ready=on_ready,
            )
        except (OSError, RuntimeError) as exc:
            raise JobError("STRIX_START_FAILED", str(exc)) from exc

        process.wait_ready(timeout=180)
        self._processes[job_id] = process
        if process._error and process.poll() is not None:
            raise JobError("STRIX_START_FAILED", process._error)

        self.store.update(
            job_id,
            status="running",
            pid=process.pid,
            run_name=process.run_name,
            viewer_url=process.viewer_url,
            viewer_token=process.viewer_token,
        )
        return process

    def reattach_running_scans(self) -> int:
        from app.services.scan_state import pid_alive, read_state

        attached = 0
        for job in self.store.list_by_status("starting", "running", "cancelling"):
            job_id = job["id"]
            if job_id in self._processes:
                continue
            workspace = Path(job["workspace"])
            state = read_state(workspace)
            pid = state.get("pid") or job.get("pid")
            if state.get("exit_code") is not None:
                self._processes[job_id] = DetachedScanHandle.attach(workspace, job_id)
                continue
            if not pid_alive(pid):
                if self._finalize_orphaned_job(job):
                    continue
                self.store.update(
                    job_id,
                    status="failed",
                    error="SCAN_WORKER_GONE",
                    finished_at=utc_now(),
                    pid=None,
                    viewer_url=None,
                    viewer_token=None,
                )
                continue
            handle = DetachedScanHandle.attach(workspace, job_id)
            self._processes[job_id] = handle
            self.store.update(
                job_id,
                status="running" if job["status"] != "cancelling" else "cancelling",
                pid=handle.pid,
                run_name=handle.run_name or job.get("run_name"),
                viewer_url=handle.viewer_url or job.get("viewer_url"),
                viewer_token=handle.viewer_token or job.get("viewer_token"),
            )
            attached += 1
            logger.info("reattached scan worker job=%s pid=%s", job_id, handle.pid)
        return attached

    def _finalize_orphaned_job(self, job: dict[str, Any]) -> bool:
        workspace = Path(job["workspace"])
        run_name = job.get("run_name") or discover_run_name(workspace)
        run_dir = workspace_run_dir(workspace, run_name)
        if not run_dir:
            return False
        status = str(read_run_record(run_dir).get("status") or "")
        if status not in {"completed", "failed", "interrupted", "stopped"}:
            return False
        if status == "completed":
            web_status = "completed"
            exit_code = 2 if read_vulnerabilities(run_dir) else 0
            error = None
        elif status == "stopped":
            web_status = "cancelled"
            exit_code = 130
            error = None
        else:
            web_status = "failed"
            exit_code = 1
            error = f"run ended with status={status}"
        self.store.update(
            job["id"],
            status=web_status,
            exit_code=exit_code,
            run_name=run_name,
            finished_at=utc_now(),
            pid=None,
            viewer_url=None,
            viewer_token=None,
            error=error,
        )
        self._stop_job_sandbox(job)
        return True

    def finish_process(self, job_id: str, *, cancelled: bool = False) -> dict[str, Any]:
        process = self._processes.pop(job_id, None)
        job = self.get_job(job_id)
        if job["status"] in {"completed", "failed", "cancelled"} and not cancelled:
            if process is not None:
                close_process_logs(process)
            return job

        exit_code = None
        run_name = job.get("run_name")
        detail_error: str | None = None
        if process is not None:
            exit_code = process.poll()
            if exit_code is None:
                exit_code = process.terminate(self.settings.cancel_grace_seconds)
            run_name = process.refresh_run_name() or run_name
            detail_error = getattr(process, "_error", None) or None
            close_process_logs(process)

        if cancelled or job["status"] == "cancelling":
            status = "cancelled"
        elif exit_code in (0, 2):
            status = "completed"
        else:
            status = "failed"

        if status in ("completed", "cancelled"):
            error_msg = None
        elif detail_error:
            error_msg = detail_error
        else:
            error_msg = f"strix exited with code {exit_code}"

        updated = self.store.update(
            job_id,
            status=status,
            exit_code=exit_code,
            run_name=run_name,
            finished_at=utc_now(),
            pid=None,
            error=error_msg,
            viewer_url=None,
            viewer_token=None,
        )
        assert updated is not None
        self._stop_job_sandbox(updated)
        return updated

    def _stop_job_sandbox(self, job: dict[str, Any]) -> None:
        from strix.runtime.session_manager import stop_sandbox_from_run_dir

        run_dir = workspace_run_dir(Path(job["workspace"]), job.get("run_name"))
        if run_dir is None:
            return
        with contextlib.suppress(Exception):
            stop_sandbox_from_run_dir(run_dir)
