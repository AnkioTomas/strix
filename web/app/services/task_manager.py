"""Task lifecycle: create, queue, cancel, retry, retest, ingest results."""

from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

from app.config import Settings
from app.db import Database, utc_now
from app.schemas import CreateTaskRequest, GitSource, LocalSource
from app.security.source import SourceValidationError, validate_source
from app.security.target import TargetValidationError, validate_pentest_target
from app.services.git_clone import GitError, clone_repository
from app.services.results import (
    load_normalized_findings,
    read_events,
    read_report_markdown,
    workspace_run_dir,
)
from app.services.strix_runner import LiveStrixSession, close_process_logs, start_strix


logger = logging.getLogger(__name__)

ACTIVE = {"queued", "starting", "running", "cancelling"}
TERMINAL = {"completed", "failed", "cancelled"}
CANCELLABLE = {"queued", "starting", "running"}


class TaskError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class TaskManager:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self._processes: dict[str, LiveStrixSession] = {}

    # --- create / list ---

    def create_task(self, req: CreateTaskRequest, *, parent_task_id: str | None = None,
                    action: str | None = None) -> dict[str, Any]:
        task_id = f"task_{uuid.uuid4().hex[:16]}"
        workspace = self.settings.tasks_dir / task_id
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "source").mkdir(exist_ok=True)
        (workspace / "logs").mkdir(exist_ok=True)
        (workspace / "results").mkdir(exist_ok=True)

        target: str | None = None
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
            else:
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
                    target = source.url
                else:
                    assert isinstance(source, LocalSource)
                    source_fields.update(
                        {
                            "source_type": "local",
                            "source_path": source.path,
                        }
                    )
                    target = source.path
        except (TargetValidationError, SourceValidationError) as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise TaskError(exc.code, exc.message) from exc

        now = utc_now()
        row = {
            "id": task_id,
            "type": req.type,
            "status": "queued",
            "target": target,
            **source_fields,
            "instruction": req.instruction,
            "scan_mode": req.scan_mode,
            "max_budget": req.max_budget,
            "workspace": str(workspace),
            "run_name": None,
            "viewer_url": None,
            "viewer_token": None,
            "pid": None,
            "exit_code": None,
            "parent_task_id": parent_task_id,
            "action": action,
            "error": None,
            "created_at": now,
            "started_at": None,
            "finished_at": None,
            "updated_at": now,
        }
        return self.db.insert_task(row)

    def list_tasks(
        self,
        *,
        status: str | None = None,
        task_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self.db.list_tasks(
            status=status, task_type=task_type, limit=limit, offset=offset
        )

    def get_task(self, task_id: str) -> dict[str, Any]:
        task = self.db.get_task(task_id)
        if not task:
            raise TaskError("TASK_NOT_FOUND", "Task not found", status_code=404)
        return task

    # --- cancel / retry / retest ---

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        task = self.get_task(task_id)
        if task["status"] not in CANCELLABLE:
            raise TaskError("TASK_NOT_CANCELLABLE", f"Task status is {task['status']}")

        if task["status"] == "queued":
            return self.db.update_task(
                task_id,
                status="cancelled",
                finished_at=utc_now(),
            ) or task

        self.db.update_task(task_id, status="cancelling")
        process = self._processes.get(task_id)
        if process is not None:
            code = process.terminate(self.settings.cancel_grace_seconds)
            close_process_logs(process)
            self._processes.pop(task_id, None)
            return (
                self.db.update_task(
                    task_id,
                    status="cancelled",
                    exit_code=code,
                    finished_at=utc_now(),
                    pid=None,
                )
                or task
            )

        return (
            self.db.update_task(
                task_id,
                status="cancelled",
                finished_at=utc_now(),
            )
            or task
        )

    def retry_task(self, task_id: str) -> dict[str, Any]:
        parent = self.get_task(task_id)
        if parent["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be retried")
        req = self._request_from_task(parent)
        return self.create_task(req, parent_task_id=task_id, action="retry")

    def retest_task(self, task_id: str, instruction: str | None = None) -> dict[str, Any]:
        parent = self.get_task(task_id)
        if parent["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be retested")
        base = self._request_from_task(parent)
        note = (
            instruction
            or "Retest previously reported findings and verify whether fixes hold."
        )
        if base.instruction:
            base.instruction = f"{base.instruction}\n\n[Retest]\n{note}"
        else:
            base.instruction = note
        return self.create_task(base, parent_task_id=task_id, action="retest")

    def resume_with_message(
        self, task_id: str, content: str, *, agent_id: str | None = None
    ) -> dict[str, Any]:
        """Deliver a live message into a running scan, or queue a follow-up.

        Running tasks use the in-process coordinator (same channel as the
        Strix viewer ``POST /api/agents/steer``). Finished tasks spawn a
        follow-up scan with the note folded into the instruction.
        """
        parent = self.get_task(task_id)
        if parent["status"] in {"starting", "running"}:
            session = self._processes.get(task_id)
            delivered = False
            if session is not None:
                delivered = session.send_message(content, agent_id=agent_id)
            self.db.add_message(task_id, "user", content, delivered=delivered)
            if not delivered:
                raise TaskError(
                    "RESULT_NOT_READY",
                    "Agent not ready to receive messages yet; retry shortly",
                    status_code=409,
                )
            return self.get_task(task_id)

        self.db.add_message(task_id, "user", content, delivered=False)
        if parent["status"] == "queued":
            return parent
        if parent["status"] == "cancelling":
            raise TaskError("TASK_NOT_CANCELLABLE", "Task is cancelling")
        if parent["status"] not in TERMINAL:
            raise TaskError(
                "TASK_NOT_CANCELLABLE",
                f"Cannot message task in status {parent['status']}",
            )
        req = self._request_from_task(parent)
        follow = f"[User follow-up]\n{content}"
        req.instruction = f"{req.instruction}\n\n{follow}" if req.instruction else follow
        return self.create_task(req, parent_task_id=task_id, action="follow_up")

    # --- worker hooks ---

    def prepare_target(self, task: dict[str, Any]) -> str:
        workspace = Path(task["workspace"])
        if task["type"] == "pentest":
            return str(task["target"])

        if task["source_type"] == "local":
            return str(task["source_path"])

        # git
        source_dir = workspace / "source" / "repo"
        if source_dir.exists():
            return str(source_dir)
        try:
            clone_repository(
                str(task["source_url"]),
                source_dir,
                branch=task.get("source_branch"),
                commit=task.get("source_commit"),
            )
        except GitError as exc:
            raise TaskError("STRIX_START_FAILED", str(exc)) from exc
        return str(source_dir)

    def start_process(self, task: dict[str, Any], target: str) -> LiveStrixSession:
        task_id = task["id"]

        def on_ready(session: LiveStrixSession) -> None:
            self.db.update_task(
                task_id,
                run_name=session.run_name,
                viewer_url=session.viewer_url,
                viewer_token=session.viewer_token,
                pid=session.pid,
            )

        try:
            process = start_strix(
                task,
                settings=self.settings,
                target=target,
                on_ready=on_ready,
            )
        except (OSError, RuntimeError) as exc:
            raise TaskError("STRIX_START_FAILED", str(exc)) from exc
        # Wait until prepare_run + viewer bind finish so clients see viewer_url.
        process.wait_ready(timeout=180)
        self._processes[task_id] = process
        if process._error and process.poll() is not None:
            raise TaskError("STRIX_START_FAILED", process._error)
        self.db.update_task(
            task_id,
            status="running",
            pid=process.pid,
            run_name=process.run_name,
            viewer_url=process.viewer_url,
            viewer_token=process.viewer_token,
        )
        return process

    def finish_process(self, task_id: str, *, cancelled: bool = False) -> dict[str, Any]:
        process = self._processes.pop(task_id, None)
        task = self.get_task(task_id)
        exit_code = None
        run_name = task.get("run_name")
        if process is not None:
            exit_code = process.poll()
            if exit_code is None:
                exit_code = process.terminate(self.settings.cancel_grace_seconds)
            run_name = process.refresh_run_name() or run_name
            close_process_logs(process)

        # Strix headless: 0 = clean, 2 = vulnerabilities found. Both are OK runs.
        if cancelled or task["status"] == "cancelling":
            status = "cancelled"
        elif exit_code in (0, 2):
            status = "completed"
        else:
            status = "failed"

        updated = self.db.update_task(
            task_id,
            status=status,
            exit_code=exit_code,
            run_name=run_name,
            finished_at=utc_now(),
            pid=None,
            error=None if status == "completed" else f"strix exited with code {exit_code}",
        )
        assert updated is not None
        self.ingest_results(updated)
        return updated

    def ingest_results(self, task: dict[str, Any]) -> None:
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if run_dir is None:
            discovered = None
            from app.services.results import discover_run_name

            name = discover_run_name(Path(task["workspace"]))
            if name:
                self.db.update_task(task["id"], run_name=name)
                run_dir = workspace_run_dir(Path(task["workspace"]), name)
                discovered = name
            if run_dir is None:
                return
            if discovered:
                task = self.get_task(task["id"])

        findings = load_normalized_findings(run_dir, task_id=task["id"])
        self.db.replace_findings(task["id"], findings)

    def get_results(self, task_id: str) -> list[dict[str, Any]]:
        task = self.get_task(task_id)
        cached = self.db.list_findings(task_id=task_id, limit=1000)
        if cached:
            return cached
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            if task["status"] in ACTIVE:
                raise TaskError("RESULT_NOT_READY", "Results not ready", status_code=409)
            return []
        findings = load_normalized_findings(run_dir, task_id=task_id)
        self.db.replace_findings(task_id, findings)
        return self.db.list_findings(task_id=task_id, limit=1000)

    def get_report(self, task_id: str) -> str:
        task = self.get_task(task_id)
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        content = read_report_markdown(run_dir)
        if not content and task["status"] in ACTIVE:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        return content

    def get_events(self, task_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
        task = self.get_task(task_id)
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            # Try discover while running
            from app.services.results import discover_run_name

            name = discover_run_name(Path(task["workspace"]))
            if name:
                self.db.update_task(task_id, run_name=name)
                run_dir = workspace_run_dir(Path(task["workspace"]), name)
        if not run_dir:
            return []
        return read_events(run_dir, limit=limit)

    def active_process_count(self) -> int:
        return sum(1 for p in self._processes.values() if p.poll() is None)

    def _request_from_task(self, task: dict[str, Any]) -> CreateTaskRequest:
        if task["type"] == "pentest":
            return CreateTaskRequest(
                type="pentest",
                target=task["target"],
                instruction=task.get("instruction"),
                scan_mode=task.get("scan_mode") or "standard",
                max_budget=task.get("max_budget"),
            )
        if task.get("source_type") == "local":
            source: GitSource | LocalSource = LocalSource(type="local", path=task["source_path"])
        else:
            source = GitSource(
                type="git",
                url=task["source_url"],
                branch=task.get("source_branch"),
                commit=task.get("source_commit"),
            )
        return CreateTaskRequest(
            type="audit",
            source=source,
            instruction=task.get("instruction"),
            scan_mode=task.get("scan_mode") or "standard",
            max_budget=task.get("max_budget"),
        )
