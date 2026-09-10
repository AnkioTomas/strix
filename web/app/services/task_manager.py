"""Task lifecycle: create, queue, cancel, retry, retest, delete, import, ingest."""

from __future__ import annotations

import json
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

from app.config import Settings
from app.db import Database, utc_now
from app.schemas import CreateTaskRequest, GitSource, LocalSource
from app.security.source import SourceValidationError, validate_source
from app.security.target import (
    TargetValidationError,
    check_tcp_reachable,
    validate_pentest_target,
)
from app.services.attachments import copy_attachments, save_uploads
from app.services.agent_prompts import REFRESH_REPORT_INSTRUCTION, RETEST_INSTRUCTION
from app.services.git_clone import GitError, clone_repository
from app.services.results import (
    load_normalized_findings,
    read_events,
    read_report_markdown,
    read_run_record,
    workspace_run_dir,
)
from app.services.run_import import (
    discover_run_dirs,
    fields_from_run_record,
    preview_run,
)
from app.services.strix_runner import (
    DetachedScanHandle,
    close_process_logs,
    start_strix,
    steer_via_viewer_http,
)


logger = logging.getLogger(__name__)

ACTIVE = {"queued", "starting", "running", "cancelling"}
TERMINAL = {"completed", "failed", "cancelled"}
CANCELLABLE = {"queued", "starting", "running"}
DELETABLE = TERMINAL | {"held"}
HOLDABLE = {"queued"}
RELEASABLE = {"held"}
_NOTES_MAX_LEN = 4000


def _merge_connectivity_note(existing: str | None, detail: str) -> str:
    """Append a TCP preflight failure line; de-dupe exact repeats; cap length."""
    line = f"[连通性] {detail.strip()}"
    base = (existing or "").strip()
    if not base:
        merged = line
    elif line in base:
        merged = base
    else:
        merged = f"{base}\n{line}"
    return merged[:_NOTES_MAX_LEN]


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
        self._processes: dict[str, DetachedScanHandle] = {}

    # --- create / list ---

    def create_task(
        self,
        req: CreateTaskRequest,
        *,
        parent_task_id: str | None = None,
        action: str | None = None,
        attachments: list[tuple[str, bytes]] | None = None,
        copy_attachments_from: Path | str | None = None,
    ) -> dict[str, Any]:
        task_id = f"task_{uuid.uuid4().hex[:16]}"
        workspace = self.settings.tasks_dir / task_id
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "source").mkdir(exist_ok=True)
        (workspace / "logs").mkdir(exist_ok=True)
        (workspace / "results").mkdir(exist_ok=True)
        (workspace / "attachments").mkdir(exist_ok=True)

        target: str | None = None
        source_fields: dict[str, Any] = {
            "source_type": None,
            "source_url": None,
            "source_branch": None,
            "source_commit": None,
            "source_path": None,
        }

        hold_for_unreachable = False
        unreachable_note: str | None = None
        try:
            if req.type == "pentest":
                assert req.target is not None
                target = validate_pentest_target(req.target, self.settings)
                try:
                    check_tcp_reachable(target)
                except TargetValidationError as exc:
                    if exc.code != "TARGET_UNREACHABLE":
                        raise
                    # Keep the task: park it and record why, instead of 400.
                    hold_for_unreachable = True
                    unreachable_note = exc.message
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
            if attachments:
                save_uploads(workspace, attachments)
            if copy_attachments_from is not None:
                copy_attachments(Path(copy_attachments_from), workspace)
        except (TargetValidationError, SourceValidationError) as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise TaskError(exc.code, exc.message) from exc
        except ValueError as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise TaskError("INVALID_ATTACHMENT", str(exc)) from exc

        now = utc_now()
        name = (req.name or "").strip() or None
        notes = (req.notes or "").strip() or None
        if unreachable_note:
            notes = _merge_connectivity_note(notes, unreachable_note)
        row = {
            "id": task_id,
            "type": req.type,
            "status": "held" if (req.held or hold_for_unreachable) else "queued",
            "name": name,
            "notes": notes,
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

    def delete_task(self, task_id: str) -> None:
        """Permanently remove a finished or held task (DB + workspace on disk)."""
        task = self.get_task(task_id)
        if task["status"] not in DELETABLE:
            raise TaskError(
                "TASK_NOT_DELETABLE",
                f"Only finished or held tasks can be deleted (status={task['status']})",
                status_code=409,
            )
        self._processes.pop(task_id, None)
        workspace = Path(task["workspace"])
        tasks_root = self.settings.tasks_dir.resolve()
        try:
            workspace.resolve().relative_to(tasks_root)
        except ValueError as exc:
            raise TaskError(
                "INVALID_WORKSPACE",
                "Task workspace is outside the managed tasks directory",
                status_code=500,
            ) from exc
        if not self.db.delete_task(task_id):
            raise TaskError("TASK_NOT_FOUND", "Task not found", status_code=404)
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)

    def update_task_meta(
        self,
        task_id: str,
        *,
        name: str | None = None,
        notes: str | None = None,
        has_name: bool = False,
        has_notes: bool = False,
    ) -> dict[str, Any]:
        """Update display name and/or notes. Pass has_* when the field was provided."""
        self.get_task(task_id)
        fields: dict[str, Any] = {}
        if has_name:
            fields["name"] = (name or "").strip() or None
        if has_notes:
            fields["notes"] = (notes or "").strip() or None
        if not fields:
            raise TaskError("INVALID_REQUEST", "No fields to update")
        updated = self.db.update_task(task_id, **fields)
        assert updated is not None
        return updated

    def hold_task(self, task_id: str) -> dict[str, Any]:
        """Park a queued task so the worker pool will not claim it."""
        task = self.get_task(task_id)
        if task["status"] not in HOLDABLE:
            raise TaskError(
                "TASK_NOT_HOLDABLE",
                f"Only queued tasks can be held (status={task['status']})",
                status_code=409,
            )
        updated = self.db.update_task(task_id, status="held")
        assert updated is not None
        return updated

    def release_task(self, task_id: str) -> dict[str, Any]:
        """Move a held task into the execution queue."""
        task = self.get_task(task_id)
        if task["status"] not in RELEASABLE:
            raise TaskError(
                "TASK_NOT_RELEASABLE",
                f"Only held tasks can be released (status={task['status']})",
                status_code=409,
            )
        if task.get("type") == "pentest" and task.get("target"):
            try:
                check_tcp_reachable(str(task["target"]))
            except TargetValidationError as exc:
                if exc.code == "TARGET_UNREACHABLE":
                    notes = _merge_connectivity_note(task.get("notes"), exc.message)
                    self.db.update_task(task_id, notes=notes)
                raise TaskError(exc.code, exc.message) from exc
        updated = self.db.update_task(task_id, status="queued")
        assert updated is not None
        return updated

    def import_runs(
        self,
        path: str | Path,
        *,
        dry_run: bool = False,
        skip_existing: bool = True,
    ) -> dict[str, Any]:
        """Import CLI ``strix_runs`` into new web tasks (copy, never mount in-place)."""
        root = Path(path).expanduser()
        try:
            run_dirs = discover_run_dirs(root)
        except FileNotFoundError as exc:
            raise TaskError("IMPORT_PATH_NOT_FOUND", str(exc), status_code=404) from exc
        except NotADirectoryError as exc:
            raise TaskError("IMPORT_PATH_INVALID", str(exc)) from exc

        if not run_dirs:
            raise TaskError(
                "IMPORT_NO_RUNS",
                f"No strix runs with run.json found under {root}",
                status_code=404,
            )

        imported: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for run_dir in run_dirs:
            preview = preview_run(run_dir)
            existing = self.db.find_task_by_run_name(str(preview["run_name"]))
            if skip_existing and existing:
                skipped.append(
                    {
                        **preview,
                        "reason": "run_name already imported",
                        "existing_task_id": existing["id"],
                    }
                )
                continue
            # Do not re-import a run that already lives inside our tasks_dir.
            try:
                run_dir.resolve().relative_to(self.settings.tasks_dir.resolve())
                skipped.append(
                    {
                        **preview,
                        "reason": "run already under managed tasks directory",
                    }
                )
                continue
            except ValueError:
                pass

            if dry_run:
                imported.append({**preview, "task_id": None})
                continue

            task = self._import_one_run(run_dir)
            imported.append(
                {
                    **preview,
                    "task_id": task["id"],
                    "status": task["status"],
                }
            )

        return {
            "path": str(root.expanduser().resolve()),
            "dry_run": dry_run,
            "imported": imported,
            "skipped": skipped,
            "imported_count": len(imported),
            "skipped_count": len(skipped),
        }

    def _import_one_run(self, run_dir: Path) -> dict[str, Any]:
        record = read_run_record(run_dir)
        fields = fields_from_run_record(record, run_dir=run_dir)
        run_name = str(fields["run_name"])
        task_id = f"task_{uuid.uuid4().hex[:16]}"
        workspace = self.settings.tasks_dir / task_id
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "source").mkdir(exist_ok=True)
        (workspace / "logs").mkdir(exist_ok=True)
        (workspace / "results").mkdir(exist_ok=True)
        (workspace / "attachments").mkdir(exist_ok=True)
        dest_run = workspace / "strix_runs" / run_name
        try:
            shutil.copytree(run_dir, dest_run)
        except OSError as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise TaskError("IMPORT_COPY_FAILED", str(exc), status_code=500) from exc

        now = utc_now()
        row = {
            "id": task_id,
            "type": fields["type"],
            "status": fields["status"],
            "target": fields["target"],
            "source_type": fields["source_type"],
            "source_url": fields["source_url"],
            "source_branch": fields["source_branch"],
            "source_commit": fields["source_commit"],
            "source_path": fields["source_path"],
            "instruction": fields["instruction"],
            "scan_mode": fields["scan_mode"],
            "max_budget": None,
            "workspace": str(workspace),
            "run_name": run_name,
            "viewer_url": None,
            "viewer_token": None,
            "pid": None,
            "exit_code": None,
            "parent_task_id": None,
            "action": "import",
            "error": fields["error"],
            "created_at": fields["started_at"] or now,
            "started_at": fields["started_at"] or now,
            "finished_at": fields["finished_at"] or now,
            "updated_at": now,
        }
        task = self.db.insert_task(row)
        self.ingest_results(task)
        return self.get_task(task_id)

    def retry_task(self, task_id: str) -> dict[str, Any]:
        parent = self.get_task(task_id)
        if parent["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be retried")
        req = self._request_from_task(parent)
        return self.create_task(
            req,
            parent_task_id=task_id,
            action="retry",
            copy_attachments_from=parent["workspace"],
        )

    def retest_task(self, task_id: str, instruction: str | None = None) -> dict[str, Any]:
        parent = self.get_task(task_id)
        if parent["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be retested")
        base = self._request_from_task(parent)
        extra = (instruction or "").strip()
        note = (
            f"{RETEST_INSTRUCTION}\n\n[附加说明]\n{extra}"
            if extra
            else RETEST_INSTRUCTION
        )
        if base.instruction:
            base.instruction = f"{base.instruction}\n\n{note}"
        else:
            base.instruction = note
        return self.create_task(
            base,
            parent_task_id=task_id,
            action="retest",
            copy_attachments_from=parent["workspace"],
        )

    def refresh_report(self, task_id: str) -> dict[str, Any]:
        """Ask Strix to rewrite the delivery report in-place (resume or live steer)."""
        task = self.get_task(task_id)
        if task["status"] in {"starting", "running"}:
            return self.resume_with_message(task_id, REFRESH_REPORT_INSTRUCTION)
        if task["status"] in TERMINAL:
            return self.resume_task(task_id, REFRESH_REPORT_INSTRUCTION)
        raise TaskError(
            "REFRESH_UNAVAILABLE",
            f"Cannot refresh report for task in status {task['status']}",
        )

    def resume_task(self, task_id: str, instruction: str | None = None) -> dict[str, Any]:
        """Continue a finished scan in-place via Strix ``--resume`` (same task id)."""
        from strix.core.paths import RUNS_DIR_NAME, RUNTIME_STATE_DIR_NAME

        task = self.get_task(task_id)
        if task["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be resumed")
        if task.get("type") == "pentest" and task.get("target"):
            try:
                check_tcp_reachable(str(task["target"]))
            except TargetValidationError as exc:
                if exc.code == "TARGET_UNREACHABLE":
                    notes = _merge_connectivity_note(task.get("notes"), exc.message)
                    self.db.update_task(task_id, notes=notes)
                raise TaskError(exc.code, exc.message) from exc
        run_name = task.get("run_name")
        if not run_name:
            raise TaskError(
                "RESUME_UNAVAILABLE",
                "Task has no run_name; nothing to resume",
            )
        workspace = Path(task["workspace"])
        agents_path = (
            workspace / RUNS_DIR_NAME / run_name / RUNTIME_STATE_DIR_NAME / "agents.json"
        )
        if not agents_path.is_file():
            raise TaskError(
                "RESUME_UNAVAILABLE",
                f"Missing agent snapshot for run {run_name}; cannot resume",
            )
        workspace_s = str(workspace)
        for other in self.db.list_tasks(limit=500, offset=0):
            if (
                other["id"] != task_id
                and other["status"] in ACTIVE
                and other.get("workspace") == workspace_s
            ):
                raise TaskError(
                    "TASK_ALREADY_RUNNING",
                    f"Workspace already in use by {other['id']}",
                )

        self._processes.pop(task_id, None)
        note = (instruction or "").strip()
        note_path = workspace / ".web_resume_instruction"
        if note:
            note_path.write_text(note, encoding="utf-8")
        elif note_path.exists():
            note_path.unlink()

        # Clear stale terminal status before the worker boots. Otherwise the API
        # pool can reap the new process while run.json still says "completed".
        run_json = workspace / RUNS_DIR_NAME / run_name / "run.json"
        if run_json.is_file():
            try:
                record = json.loads(run_json.read_text(encoding="utf-8"))
                if isinstance(record, dict):
                    record["status"] = "running"
                    record["end_time"] = None
                    run_json.write_text(
                        json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8",
                    )
            except (OSError, json.JSONDecodeError, TypeError):
                logger.warning(
                    "could not reset run.json status for resume task=%s run=%s",
                    task_id,
                    run_name,
                    exc_info=True,
                )

        updated = self.db.update_task(
            task_id,
            status="queued",
            action="resume",
            exit_code=None,
            error=None,
            finished_at=None,
            started_at=None,
            pid=None,
            viewer_url=None,
            viewer_token=None,
        )
        assert updated is not None
        return updated

    def resume_with_message(
        self, task_id: str, content: str, *, agent_id: str | None = None
    ) -> dict[str, Any]:
        """Deliver a live message into a running scan, or resume a finished one.

        Running tasks use the in-process coordinator (same channel as the
        Strix viewer ``POST /api/agents/steer``). Finished tasks resume the
        same ``run_name`` with ``content`` as ``resume_instruction``.
        """
        parent = self.get_task(task_id)
        if parent["status"] in {"starting", "running"}:
            session = self._processes.get(task_id)
            delivered = False
            if session is not None:
                delivered = session.send_message(content, agent_id=agent_id)
            elif parent.get("viewer_url") and parent.get("viewer_token"):
                # API restarted: no in-memory handle yet — steer via viewer HTTP.
                delivered = steer_via_viewer_http(
                    viewer_url=parent.get("viewer_url"),
                    viewer_token=parent.get("viewer_token"),
                    message=content,
                    agent_id=agent_id,
                    run_dir=Path(parent["workspace"]),
                    run_name=parent.get("run_name"),
                )
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
        return self.resume_task(task_id, instruction=content)

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

    def start_process(self, task: dict[str, Any], target: str) -> DetachedScanHandle:
        task_id = task["id"]

        def on_ready(session: DetachedScanHandle) -> None:
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

    def reattach_running_scans(self) -> int:
        """Reconnect to scan workers that survived an API restart."""
        from app.services.scan_state import pid_alive, read_state

        attached = 0
        for status in ("starting", "running", "cancelling"):
            for task in self.db.list_tasks(status=status, limit=500, offset=0):
                task_id = task["id"]
                if task_id in self._processes:
                    continue
                workspace = Path(task["workspace"])
                state = read_state(workspace)
                pid = state.get("pid") or task.get("pid")
                if state.get("exit_code") is not None:
                    handle = DetachedScanHandle.attach(workspace, task_id)
                    self._processes[task_id] = handle
                    # Let the worker pool finish_process on next tick.
                    logger.info(
                        "scan worker already exited task=%s code=%s; will finalize",
                        task_id,
                        state.get("exit_code"),
                    )
                    continue
                if not pid_alive(pid):
                    # Worker gone — prefer run.json status over blanket failure.
                    finalized = self._finalize_orphaned_task(task)
                    if finalized:
                        continue
                    logger.warning(
                        "orphaned task %s (pid=%s dead); marking failed", task_id, pid
                    )
                    self.db.update_task(
                        task_id,
                        status="failed",
                        error="SCAN_WORKER_GONE",
                        finished_at=utc_now(),
                        pid=None,
                        viewer_url=None,
                        viewer_token=None,
                    )
                    continue
                handle = DetachedScanHandle.attach(workspace, task_id)
                self._processes[task_id] = handle
                self.db.update_task(
                    task_id,
                    status="running" if task["status"] != "cancelling" else "cancelling",
                    pid=handle.pid,
                    run_name=handle.run_name or task.get("run_name"),
                    viewer_url=handle.viewer_url or task.get("viewer_url"),
                    viewer_token=handle.viewer_token or task.get("viewer_token"),
                )
                attached += 1
                logger.info(
                    "reattached scan worker task=%s pid=%s viewer=%s",
                    task_id,
                    handle.pid,
                    bool(handle.viewer_url),
                )
        return attached

    def _finalize_orphaned_task(self, task: dict[str, Any]) -> bool:
        """If a dead worker left a terminal run.json, close the task correctly."""
        from app.services.results import (
            discover_run_name,
            read_run_record,
            read_vulnerabilities,
            workspace_run_dir,
        )

        workspace = Path(task["workspace"])
        run_name = task.get("run_name") or discover_run_name(workspace)
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
        updated = self.db.update_task(
            task["id"],
            status=web_status,
            exit_code=exit_code,
            run_name=run_name,
            finished_at=utc_now(),
            pid=None,
            viewer_url=None,
            viewer_token=None,
            error=error,
        )
        if updated:
            self.ingest_results(updated)
        logger.info(
            "finalized orphaned task %s from run.json status=%s → %s",
            task["id"],
            status,
            web_status,
        )
        return True

    def finish_process(self, task_id: str, *, cancelled: bool = False) -> dict[str, Any]:
        process = self._processes.pop(task_id, None)
        task = self.get_task(task_id)
        exit_code = None
        run_name = task.get("run_name")
        detail_error: str | None = None
        if process is not None:
            exit_code = process.poll()
            if exit_code is None:
                exit_code = process.terminate(self.settings.cancel_grace_seconds)
            run_name = process.refresh_run_name() or run_name
            detail_error = getattr(process, "_error", None) or None
            close_process_logs(process)

        # Strix headless: 0 = clean, 2 = vulnerabilities found. Both are OK runs.
        if cancelled or task["status"] == "cancelling":
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

        updated = self.db.update_task(
            task_id,
            status=status,
            exit_code=exit_code,
            run_name=run_name,
            finished_at=utc_now(),
            pid=None,
            error=error_msg,
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
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if run_dir is None:
            from app.services.results import discover_run_name

            name = discover_run_name(Path(task["workspace"]))
            if name:
                self.db.update_task(task_id, run_name=name)
                run_dir = workspace_run_dir(Path(task["workspace"]), name)
        if run_dir is not None:
            # Always re-read disk: early polls must not freeze a partial cache.
            findings = load_normalized_findings(run_dir, task_id=task_id)
            self.db.replace_findings(task_id, findings)
            return findings
        cached = self.db.list_findings(task_id=task_id, limit=1000)
        if cached:
            return cached
        if task["status"] in ACTIVE:
            raise TaskError("RESULT_NOT_READY", "Results not ready", status_code=409)
        return []

    def get_report(self, task_id: str) -> str:
        task = self.get_task(task_id)
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        from app.services.results import rebuild_delivery_report

        rebuilt = rebuild_delivery_report(run_dir)
        content = rebuilt if rebuilt is not None else read_report_markdown(run_dir)
        if not content and task["status"] in ACTIVE:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        return content or ""

    def get_report_package(self, task_id: str) -> Path:
        """Path to penetration_test_report.zip (markdown + images)."""
        from app.services.results import resolve_report_package

        task = self.get_task(task_id)
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        package = resolve_report_package(run_dir)
        if package is None:
            if task["status"] in ACTIVE:
                raise TaskError("RESULT_NOT_READY", "Report package not ready", status_code=409)
            raise TaskError("RESULT_NOT_READY", "Report package not found", status_code=404)
        return package

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
                name=task.get("name"),
                notes=task.get("notes"),
                scan_mode=task.get("scan_mode") or "deep",
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
            name=task.get("name"),
            notes=task.get("notes"),
            scan_mode=task.get("scan_mode") or "deep",
            max_budget=task.get("max_budget"),
        )
