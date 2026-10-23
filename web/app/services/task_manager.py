"""Task lifecycle: create, queue, cancel, retry, retest, delete, import, ingest."""

from __future__ import annotations

import json
import logging
import re
import shutil
import threading
import uuid
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.config import Settings
from app.db import Database, utc_now
from app.schemas import CreateTaskRequest, GitSource, LocalSource
from app.services.assets import parse_tags
from app.security.source import SourceValidationError, validate_source
from app.security.target import (
    TargetValidationError,
    check_tcp_reachable,
    validate_pentest_target,
)
from app.services.attachments import copy_attachments, save_uploads
from app.services.agent_prompts import (
    REFRESH_REPORT_INSTRUCTION,
    translate_report_instruction,
    RETEST_INSTRUCTION,
    focused_retest_instruction,
)
from app.services.feishu import notify_status, notify_task
from app.services.findings import (
    apply_finding_flags,
    empty_finding_counts,
    invalid_finding_ids,
    sort_findings,
)
from app.services.git_clone import GitError, clone_repository
from app.services.results import (
    count_disk_findings,
    discover_run_name,
    load_normalized_findings,
    read_events,
    read_report_markdown,
    read_run_record,
    report_exists,
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
_LIVE_COUNT_STATUSES = {"starting", "running", "cancelling"}
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


def _strip_connectivity_notes(existing: str | None) -> str | None:
    if not existing:
        return None
    cleaned = "\n".join(
        line for line in existing.splitlines() if not line.startswith("[连通性]")
    ).strip()
    return cleaned or None


_HELD_ONLY_FIELDS = frozenset(
    {
        "instruction",
        "scan_mode",
        "max_budget",
        "earliest_start",
        "target",
        "source",
        "proxy_url",
        "use_proxy",
        "request_headers",
        "use_headers",
    }
)


_DOWNLOAD_UNSAFE = re.compile(r'[/\\:*?"<>|\x00-\x1f]+')


def task_display_title(task: dict[str, Any]) -> str:
    """``应用名称（host:port）`` for pentest tasks; falls back to name / target."""
    from app.services.findings import _parse_address

    name = str(task.get("name") or "").strip()
    parsed = (
        _parse_address(str(task.get("target") or "")) if task.get("type") == "pentest" else None
    )
    address = parsed[0] if parsed else ""
    if name and address and address not in name:
        return f"{name}（{address}）"
    return name or address or str(task.get("target") or task.get("source_url") or "").strip()


def report_download_stem(task: dict[str, Any]) -> str:
    """Client-facing report basename: ``名称（host:port）``, 「复测-」 prefix for retests."""
    base = (task_display_title(task) or str(task.get("id") or "report")).strip()
    base = _DOWNLOAD_UNSAFE.sub("_", base)
    base = re.sub(r"\s+", " ", base).strip(" ._") or "report"
    base = base[:120]
    if str(task.get("action") or "") == "retest" and not base.startswith("复测"):
        base = f"复测-{base}"
    return f"{base}-报告"


class TaskError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _reset_run_json_for_resume(workspace: Path, run_name: str) -> None:
    """Clear a stale terminal status so the pool does not reap the resumed run."""
    run_json = workspace / "strix_runs" / run_name / "run.json"
    if not run_json.is_file():
        return
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
            "could not reset run.json status for resume run=%s", run_name, exc_info=True
        )


class TaskManager:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self._processes: dict[str, DetachedScanHandle] = {}
        # Skip DELETE+INSERT of findings when vulnerabilities.json is unchanged.
        self._findings_disk_mtime: dict[str, float] = {}

    # --- create / list ---

    def create_task(
        self,
        req: CreateTaskRequest,
        *,
        parent_task_id: str | None = None,
        action: str | None = None,
        attachments: list[tuple[str, bytes]] | None = None,
        copy_attachments_from: Path | str | None = None,
        reuse_environment_from: dict[str, Any] | None = None,
        resume_note: str | None = None,
    ) -> dict[str, Any]:
        """Create a task.

        ``reuse_environment_from`` (a finished parent task) clones its workspace
        and keeps its ``run_name``, so the new task resumes the parent's run
        (agents, scripts, source checkout) without touching the parent.
        """
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
                    check_tcp_reachable(target, proxy_url=req.proxy_url)
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
            if reuse_environment_from is not None:
                self._clone_environment(reuse_environment_from, workspace, resume_note)
        except (TargetValidationError, SourceValidationError) as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise TaskError(exc.code, exc.message) from exc
        except ValueError as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise TaskError("INVALID_ATTACHMENT", str(exc)) from exc
        except OSError as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise TaskError("ENVIRONMENT_CLONE_FAILED", str(exc), status_code=500) from exc

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
            "tags": ",".join(req.tags or []) or None,
            "mail_to": ",".join(req.mail_to or []) or None,
            "mail_status": "pending" if req.mail_to and self._mail_enabled() else None,
            "target": target,
            **source_fields,
            "instruction": req.instruction,
            "scan_mode": req.scan_mode,
            "max_budget": req.max_budget,
            "proxy_url": req.proxy_url,
            "request_headers": req.request_headers,
            "workspace": str(workspace),
            "run_name": reuse_environment_from["run_name"] if reuse_environment_from else None,
            "viewer_url": None,
            "viewer_token": None,
            "pid": None,
            "exit_code": None,
            "parent_task_id": parent_task_id,
            "action": action,
            "error": None,
            "earliest_start": req.earliest_start or None,
            "created_at": now,
            "started_at": None,
            "finished_at": None,
            "updated_at": now,
        }
        return self.db.insert_task(row)

    @staticmethod
    def _clone_environment(
        parent: dict[str, Any], workspace: Path, resume_note: str | None
    ) -> None:
        """Copy the parent's workspace into a new task and arm it to resume."""
        shutil.copytree(
            Path(parent["workspace"]),
            workspace,
            symlinks=True,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("logs", "results", ".web_resume_instruction"),
        )
        for name in ("logs", "results"):
            (workspace / name).mkdir(exist_ok=True)
        _reset_run_json_for_resume(workspace, str(parent["run_name"]))
        note_path = workspace / ".web_resume_instruction"
        note_path.unlink(missing_ok=True)
        if resume_note and resume_note.strip():
            note_path.write_text(resume_note.strip(), encoding="utf-8")

    def list_tasks(
        self,
        *,
        status: str | None = None,
        task_type: str | None = None,
        action: str | None = None,
        parent_task_id: str | None = None,
        scan_mode: str | None = None,
        q: str | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        sort: str = "created_at",
        order: str = "desc",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self.db.list_tasks(
            status=status,
            task_type=task_type,
            action=action,
            parent_task_id=parent_task_id,
            scan_mode=scan_mode,
            q=q,
            created_after=created_after,
            created_before=created_before,
            sort=sort,
            order=order,
            limit=limit,
            offset=offset,
        )

    def count_tasks(
        self,
        *,
        status: str | None = None,
        task_type: str | None = None,
        action: str | None = None,
        parent_task_id: str | None = None,
        scan_mode: str | None = None,
        q: str | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
    ) -> int:
        return self.db.count_tasks(
            status=status,
            task_type=task_type,
            action=action,
            parent_task_id=parent_task_id,
            scan_mode=scan_mode,
            q=q,
            created_after=created_after,
            created_before=created_before,
        )

    def attach_task_overlays(
        self,
        tasks: list[dict[str, Any]],
        *,
        include_findings: bool = True,
    ) -> list[dict[str, Any]]:
        """Attach ``finding_counts`` / ``has_report`` without calling ``/results``.

        Completed tasks use one SQL aggregate. Live scans (and not-yet-ingested
        runs) count ``vulnerabilities.json`` so the list stays current.
        """
        if not tasks:
            return tasks
        ids = [str(task["id"]) for task in tasks]
        sql_counts = self.db.count_active_findings(ids) if include_findings else {}
        need_flags: list[str] = []
        if include_findings:
            for task in tasks:
                tid = str(task["id"])
                live = str(task.get("status") or "") in _LIVE_COUNT_STATUSES
                if live or (tid not in sql_counts and task.get("run_name")):
                    need_flags.append(tid)
        invalid_by_task = (
            self.db.invalid_finding_ids_for_tasks(need_flags) if need_flags else {}
        )

        for task in tasks:
            workspace = Path(task["workspace"])
            run_dir = workspace_run_dir(workspace, task.get("run_name"))
            if run_dir is None:
                run_dir = workspace_run_dir(workspace, discover_run_name(workspace))
            task["has_report"] = bool(run_dir and report_exists(run_dir))
            if not include_findings:
                task.pop("finding_counts", None)
                continue
            tid = str(task["id"])
            live = str(task.get("status") or "") in _LIVE_COUNT_STATUSES
            if run_dir is not None and (live or tid not in sql_counts):
                task["finding_counts"] = count_disk_findings(
                    run_dir, invalid_ids=invalid_by_task.get(tid, set())
                )
            else:
                task["finding_counts"] = sql_counts.get(tid) or empty_finding_counts()
        return tasks

    def get_task(self, task_id: str) -> dict[str, Any]:
        task = self.db.get_task(task_id)
        if not task:
            raise TaskError("TASK_NOT_FOUND", "Task not found", status_code=404)
        return task

    # --- cancel / retry / retest ---

    def complete_task(self, task_id: str) -> dict[str, Any]:
        """Operator close. Stop a live scan if there is one, then mark completed.

        ``finish_process`` must not overwrite this: a manual complete is the
        status, even when the worker exits with a non-zero code afterwards.
        """
        task = self.get_task(task_id)
        if task["status"] == "completed":
            raise TaskError(
                "TASK_ALREADY_COMPLETED",
                "Task is already completed",
                status_code=409,
            )

        updated = (
            self.db.update_task(
                task_id,
                status="completed",
                finished_at=utc_now(),
                pid=None,
                error=None,
                viewer_url=None,
                viewer_token=None,
            )
            or task
        )
        process = self._processes.pop(task_id, None)
        if process is not None:
            code = process.terminate(self.settings.cancel_grace_seconds)
            close_process_logs(process)
            updated = self.db.update_task(task_id, exit_code=code) or updated

        self.ingest_results(updated)
        self._stop_task_sandbox(updated)
        self._feishu_status(updated, "completed")
        return self.get_task(task_id)

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        task = self.get_task(task_id)
        if task["status"] not in CANCELLABLE:
            raise TaskError("TASK_NOT_CANCELLABLE", f"Task status is {task['status']}")

        if task["status"] == "queued":
            updated = self.db.update_task(
                task_id,
                status="cancelled",
                finished_at=utc_now(),
            ) or task
            self._feishu_status(updated, "cancelled")
            return updated

        self.db.update_task(task_id, status="cancelling")
        process = self._processes.get(task_id)
        if process is not None:
            code = process.terminate(self.settings.cancel_grace_seconds)
            close_process_logs(process)
            self._processes.pop(task_id, None)
            updated = (
                self.db.update_task(
                    task_id,
                    status="cancelled",
                    exit_code=code,
                    finished_at=utc_now(),
                    pid=None,
                )
                or task
            )
            self._feishu_status(updated, "cancelled")
            return updated

        updated = (
            self.db.update_task(
                task_id,
                status="cancelled",
                finished_at=utc_now(),
            )
            or task
        )
        self._feishu_status(updated, "cancelled")
        return updated

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

    def _mail_enabled(self) -> bool:
        from app.services.mailer import mail_enabled

        return mail_enabled(self.settings)

    def update_task_meta(self, task_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        """Patch display fields always; scan settings only while ``held``."""
        task = self.get_task(task_id)
        if not fields:
            raise TaskError("INVALID_REQUEST", "No fields to update")
        if _HELD_ONLY_FIELDS & fields.keys() and task["status"] != "held":
            raise TaskError(
                "TASK_NOT_EDITABLE",
                f"Scan settings can only be changed while held (status={task['status']})",
                status_code=409,
            )

        patch: dict[str, Any] = {}
        if "name" in fields:
            patch["name"] = (fields.get("name") or "").strip() or None
        if "notes" in fields:
            patch["notes"] = (fields.get("notes") or "").strip() or None
        if "tags" in fields:
            patch["tags"] = ",".join(fields.get("tags") or []) or None
        if "mail_to" in fields:
            recipients = fields.get("mail_to") or []
            patch["mail_to"] = ",".join(recipients) or None
            if task.get("mail_status") in (None, "", "pending", "failed"):
                patch["mail_status"] = "pending" if recipients and self._mail_enabled() else None
                patch["mail_error"] = None
        if "instruction" in fields:
            text = fields.get("instruction")
            patch["instruction"] = (text or "").strip() or None
        if "scan_mode" in fields and fields["scan_mode"] is not None:
            patch["scan_mode"] = fields["scan_mode"]
        if "max_budget" in fields:
            patch["max_budget"] = fields["max_budget"]
        if "earliest_start" in fields:
            patch["earliest_start"] = fields["earliest_start"]
        if "use_proxy" in fields or "proxy_url" in fields:
            if fields.get("use_proxy") is False:
                patch["proxy_url"] = None
            elif "proxy_url" in fields:
                patch["proxy_url"] = fields["proxy_url"]
        if "use_headers" in fields or "request_headers" in fields:
            if fields.get("use_headers") is False:
                patch["request_headers"] = None
            elif "request_headers" in fields:
                patch["request_headers"] = fields["request_headers"]

        if "target" in fields:
            if task["type"] != "pentest":
                raise TaskError("INVALID_REQUEST", "target is only valid for pentest tasks")
            raw = (fields.get("target") or "").strip()
            if not raw:
                raise TaskError("INVALID_REQUEST", "pentest tasks require target")
            try:
                patch["target"] = validate_pentest_target(raw, self.settings)
            except TargetValidationError as exc:
                raise TaskError(exc.code, exc.message) from exc

        if "source" in fields:
            if task["type"] != "audit":
                raise TaskError("INVALID_REQUEST", "source is only valid for audit tasks")
            raw_source = fields["source"]
            if raw_source is None:
                raise TaskError("INVALID_REQUEST", "audit tasks require source")
            try:
                source = raw_source
                if not isinstance(source, (GitSource, LocalSource)):
                    source = (
                        GitSource.model_validate(source)
                        if str(source.get("type") or "git") == "git"
                        else LocalSource.model_validate(source)
                    )
                source = validate_source(source, self.settings)
            except (SourceValidationError, ValidationError) as exc:
                if isinstance(exc, SourceValidationError):
                    raise TaskError(exc.code, exc.message) from exc
                raise TaskError("INVALID_REQUEST", str(exc)) from exc
            if isinstance(source, GitSource):
                patch.update(
                    {
                        "source_type": "git",
                        "source_url": source.url,
                        "source_branch": source.branch,
                        "source_commit": source.commit,
                        "source_path": None,
                        "target": source.url,
                    }
                )
            else:
                patch.update(
                    {
                        "source_type": "local",
                        "source_path": source.path,
                        "source_url": None,
                        "source_branch": None,
                        "source_commit": None,
                        "target": source.path,
                    }
                )

        notes = patch["notes"] if "notes" in patch else task.get("notes")
        target = patch.get("target", task.get("target"))
        proxy_url = patch["proxy_url"] if "proxy_url" in patch else task.get("proxy_url")
        if task["type"] == "pentest" and target and (
            "target" in patch or "proxy_url" in patch
        ):
            try:
                check_tcp_reachable(str(target), proxy_url=proxy_url)
            except TargetValidationError as exc:
                if exc.code != "TARGET_UNREACHABLE":
                    raise TaskError(exc.code, exc.message) from exc
                notes = _merge_connectivity_note(notes, exc.message)
            else:
                notes = _strip_connectivity_notes(notes)
            patch["notes"] = notes

        if not patch:
            raise TaskError("INVALID_REQUEST", "No fields to update")
        updated = self.db.update_task(task_id, **patch)
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
                check_tcp_reachable(
                    str(task["target"]),
                    proxy_url=task.get("proxy_url"),
                )
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
            "proxy_url": None,
            "request_headers": None,
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

    def retry_task(
        self,
        task_id: str,
        *,
        earliest_start: str | None = None,
    ) -> dict[str, Any]:
        parent = self.get_task(task_id)
        if parent["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be retried")
        req = self._request_from_task(parent)
        # Do not inherit parent schedule; only apply when the caller sets one.
        if earliest_start is not None:
            req = CreateTaskRequest.model_validate(
                {**req.model_dump(), "earliest_start": earliest_start}
            )
        return self.create_task(
            req,
            parent_task_id=task_id,
            action="retry",
            copy_attachments_from=parent["workspace"],
        )

    def retest_task(
        self,
        task_id: str,
        instruction: str | None = None,
        *,
        finding_ids: list[str] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Retest in a new task that reuses the parent's environment.

        The parent's workspace (agents, scripts, source, run dir) is cloned, so
        the parent keeps its own findings and report untouched.
        """
        task = self.get_task(task_id)
        if task["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be retested")

        findings = self.get_results(task_id)
        flags = self.db.list_finding_flags(task_id)
        skipped_invalid = invalid_finding_ids(flags)

        scope_ids: list[str] | None = None
        selected_ids = [str(x) for x in (finding_ids or []) if str(x).strip()]
        if not selected_ids:
            selected_ids = [
                str(flag["finding_id"])
                for flag in flags.values()
                if flag.get("request_test") and str(flag.get("review_status") or "") != "invalid"
            ]

        active = [
            item
            for item in findings
            if str(item.get("id") or "") not in skipped_invalid
        ]
        if selected_ids:
            wanted = set(selected_ids)
            targets = [item for item in active if str(item.get("id") or "") in wanted]
            if not targets:
                raise TaskError(
                    "NO_FINDINGS_TO_RETEST",
                    "No eligible findings to retest (missing or marked invalid)",
                )
            note = focused_retest_instruction(targets)
            scope_ids = [str(item.get("id")) for item in targets]
            self.db.clear_finding_request_test(
                task_id, [str(item.get("id")) for item in targets]
            )
        else:
            if findings and not active:
                raise TaskError(
                    "NO_FINDINGS_TO_RETEST",
                    "All findings are marked invalid; nothing to retest",
                )
            note = RETEST_INSTRUCTION
            if skipped_invalid:
                skipped_titles = [
                    str(item.get("title") or item.get("id"))
                    for item in findings
                    if str(item.get("id")) in skipped_invalid
                ]
                note = (
                    f"{note}\n\n[跳过 — 无效漏洞]\n"
                    + "\n".join(f"- {title}" for title in skipped_titles)
                )

        extra = (instruction or "").strip()
        if extra:
            note = f"{note}\n\n[附加说明]\n{extra}"
        return self._spawn_retest_task(task, note, scope_ids=scope_ids, overrides=overrides)

    def _spawn_retest_task(
        self,
        parent: dict[str, Any],
        note: str,
        *,
        scope_ids: list[str] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from strix.core.paths import RUNS_DIR_NAME, RUNTIME_STATE_DIR_NAME

        run_name = parent.get("run_name")
        if not run_name:
            raise TaskError("RESUME_UNAVAILABLE", "Task has no run_name; nothing to retest")
        agents_path = (
            Path(parent["workspace"]) / RUNS_DIR_NAME / run_name / RUNTIME_STATE_DIR_NAME / "agents.json"
        )
        if not agents_path.is_file():
            raise TaskError(
                "RESUME_UNAVAILABLE",
                f"Missing agent snapshot for run {run_name}; cannot retest",
            )
        request = self._request_from_task(parent)
        changes = overrides or {}
        if changes:
            try:
                request = CreateTaskRequest(**{**request.model_dump(), **changes})
            except ValidationError as exc:
                raise TaskError("INVALID_REQUEST", str(exc.errors()[0].get("msg"))) from exc
        if not (changes.get("name") or "").strip():
            base = str(request.name or parent.get("target") or "").strip()
            if base and not base.startswith("复测"):
                request.name = f"复测-{base}"[:200]
        child = self.create_task(
            request,
            parent_task_id=parent["id"],
            action="retest",
            reuse_environment_from=parent,
            resume_note=note,
        )
        from app.services.results import write_retest_scope

        write_retest_scope(Path(child["workspace"]), scope_ids)
        for flag in self.db.list_finding_flags(parent["id"]).values():
            self.db.upsert_finding_flag(
                child["id"],
                str(flag["finding_id"]),
                review_status=str(flag.get("review_status") or "active"),
                request_test=False,
            )
        return child

    def update_finding_review(
        self,
        task_id: str,
        finding_id: str,
        *,
        review_status: str | None = None,
        request_test: bool | None = None,
    ) -> dict[str, Any]:
        """Mark a finding invalid / restore it / queue it for focused retest."""
        self.get_task(task_id)
        findings = self.get_results(task_id)
        match = next((item for item in findings if str(item.get("id")) == finding_id), None)
        if match is None:
            raise TaskError("FINDING_NOT_FOUND", f"Finding {finding_id} not found", status_code=404)
        if review_status == "invalid":
            request_test = False
        try:
            flag = self.db.upsert_finding_flag(
                task_id,
                finding_id,
                review_status=review_status,
                request_test=request_test,
            )
        except ValueError as exc:
            raise TaskError("INVALID_FINDING_FLAG", str(exc), status_code=400) from exc
        if flag["review_status"] == "invalid" and flag["request_test"]:
            flag = self.db.upsert_finding_flag(
                task_id, finding_id, review_status="invalid", request_test=False
            )
        self._rebuild_report_for_task(task_id)
        match["review_status"] = flag["review_status"]
        match["request_test"] = flag["request_test"]
        return match

    def request_finding_test(self, task_id: str, finding_id: str) -> dict[str, Any]:
        """Queue + start a focused retest for one finding (terminal tasks only)."""
        finding = self.update_finding_review(
            task_id, finding_id, review_status="active", request_test=True
        )
        if finding.get("review_status") == "invalid":
            raise TaskError("FINDING_INVALID", "Cannot retest an invalid finding", status_code=400)
        child = self.retest_task(task_id, finding_ids=[finding_id])
        return {"finding": finding, "task": child}

    def _rebuild_report_for_task(self, task_id: str) -> None:
        task = self.get_task(task_id)
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            return
        from app.services.results import rebuild_delivery_report

        flags = self.db.list_finding_flags(task_id)
        rebuild_delivery_report(
            run_dir,
            exclude_ids=invalid_finding_ids(flags),
            retest=task.get("action") == "retest",
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

    def translate_report(self, task_id: str) -> dict[str, Any]:
        """Hand the existing markdown report to the agent for English translation."""
        task = self.get_task(task_id)
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir or not (run_dir / "penetration_test_report.md").is_file():
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        instruction = translate_report_instruction(task.get("run_name"))
        if task["status"] in {"starting", "running"}:
            return self.resume_with_message(task_id, instruction)
        if task["status"] in TERMINAL:
            return self.resume_task(task_id, instruction)
        raise TaskError(
            "TRANSLATE_UNAVAILABLE",
            f"Cannot translate report for task in status {task['status']}",
        )

    def _translated_report(self, task: dict[str, Any]) -> tuple[Path, Path]:
        from app.services.results import translated_report_path

        workspace = Path(task["workspace"])
        run_dir = workspace_run_dir(workspace, task.get("run_name"))
        found = translated_report_path(run_dir, workspace) if run_dir else None
        if run_dir is None or found is None:
            raise TaskError(
                "TRANSLATION_NOT_READY",
                "English report not available; ask the agent to translate it first",
                status_code=409,
            )
        return run_dir, found

    def resume_task(
        self,
        task_id: str,
        instruction: str | None = None,
        *,
        action: str = "resume",
    ) -> dict[str, Any]:
        """Continue a finished scan in-place via Strix ``--resume`` (same task id)."""
        from strix.core.paths import RUNS_DIR_NAME, RUNTIME_STATE_DIR_NAME

        task = self.get_task(task_id)
        if task["status"] not in TERMINAL:
            raise TaskError("TASK_ALREADY_RUNNING", "Only finished tasks can be resumed")
        if task.get("type") == "pentest" and task.get("target"):
            try:
                check_tcp_reachable(
                    str(task["target"]),
                    proxy_url=task.get("proxy_url"),
                )
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
        _reset_run_json_for_resume(workspace, run_name)

        resume_action = action if action in {"resume", "retest"} else "resume"
        updated = self.db.update_task(
            task_id,
            status="queued",
            action=resume_action,
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
                settings=self.settings,
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
        current = self.get_task(task_id)
        if current["status"] == "completed":
            self._processes.pop(task_id, None)
            if process.poll() is None:
                code = process.terminate(self.settings.cancel_grace_seconds)
                self.db.update_task(task_id, exit_code=code)
            close_process_logs(process)
            self._stop_task_sandbox(current)
            return process
        self.db.update_task(
            task_id,
            status="running",
            pid=process.pid,
            run_name=process.run_name,
            viewer_url=process.viewer_url,
            viewer_token=process.viewer_token,
        )
        running = self.get_task(task_id)
        notify_task(self.settings, self.db, "started", running)
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
                    failed = self.db.update_task(
                        task_id,
                        status="failed",
                        error="SCAN_WORKER_GONE",
                        finished_at=utc_now(),
                        pid=None,
                        viewer_url=None,
                        viewer_token=None,
                    )
                    if failed:
                        self._feishu_status(failed, "failed")
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
            self._stop_task_sandbox(updated)
            self._feishu_status(updated, web_status)
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
        if task["status"] == "completed":
            if process is not None:
                if process.poll() is None:
                    process.terminate(self.settings.cancel_grace_seconds)
                close_process_logs(process)
            return task
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
            viewer_url=None,
            viewer_token=None,
        )
        assert updated is not None
        self.ingest_results(updated)
        self._stop_task_sandbox(updated)
        self._feishu_status(updated, status)
        return updated

    def _feishu_status(self, task: dict[str, Any], status: str) -> None:
        notify_status(self.settings, self.db, task, status)
        # Batch tasks mail their report once the scan completes (off-thread: SMTP is slow).
        if status == "completed" and task.get("mail_status") == "pending":
            threading.Thread(
                target=self._send_report_mail_safe,
                args=(str(task["id"]),),
                name=f"report-mail-{task['id']}",
                daemon=True,
            ).start()

    def _send_report_mail_safe(self, task_id: str) -> None:
        try:
            self.send_report_mail(task_id)
        except TaskError:
            logger.exception("report mail failed for %s", task_id)

    def batch_create(
        self,
        rows: list[Any],
        *,
        scan_mode: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Create one pentest task per spreadsheet row; failures are reported per row."""
        from app.services.mailer import mail_enabled

        results: list[dict[str, Any]] = []
        for row in rows:
            entry: dict[str, Any] = {"row": row.row, "name": row.name, "target": row.target}
            if not row.target:
                entry["error"] = "URL 为空（该行没有可识别的 URL，请检查表头是否含 URL/地址/域名 列）"
                results.append(entry)
                continue
            notes = "\n".join(
                part
                for part in (
                    f"BU: {row.bu}" if row.bu else "",
                    f"负责人: {row.owner}" if row.owner else "",
                )
                if part
            )
            try:
                req = CreateTaskRequest(
                    type="pentest",
                    target=row.target,
                    name=row.name or None,
                    notes=notes or None,
                    tags=[row.bu] if row.bu else None,
                    scan_mode=scan_mode or self.settings.default_scan_mode,
                    **(options or {}),
                )
                task = self.create_task(req)
            except (TaskError, ValidationError) as exc:
                entry["error"] = exc.message if isinstance(exc, TaskError) else str(exc)
                results.append(entry)
                continue
            fields: dict[str, Any] = {"mail_to": ",".join(row.emails) or None}
            if mail_enabled(self.settings):
                fields["mail_status"] = "pending"
            self.db.update_task(task["id"], **fields)
            entry["task_id"] = task["id"]
            entry["mail_to"] = fields["mail_to"]
            if row.owner and not row.emails:
                entry["warning"] = "负责人不是有效邮箱，报告只会发给抄送邮箱"
            results.append(entry)
        return results

    def send_report_mail(self, task_id: str) -> dict[str, Any]:
        """Mail the Chinese report zip to the owner, CC'ing STRIX_MAIL_CC."""
        from app.services.mailer import MailError, render_template, send_report_mail

        task = self.get_task(task_id)
        if task["status"] != "completed":
            raise TaskError(
                "RESULT_NOT_READY", "Task is not completed yet", status_code=409
            )
        recipients = [a for a in str(task.get("mail_to") or "").split(",") if a]
        try:
            package = self.get_report_package(task_id)
            self.attach_task_overlays([task])
            counts = task.get("finding_counts") or {}
            name = task_display_title(task) or task_id
            owner = ""
            for line in str(task.get("notes") or "").splitlines():
                if line.startswith("负责人: "):
                    owner = line[len("负责人: ") :]
            from app.services.assets import _finding_detail
            from app.services.findings import invalid_finding_ids
            from app.services.mailer import build_report_html

            skipped = invalid_finding_ids(self.db.list_finding_flags(task_id))
            details = [
                _finding_detail(item)
                for item in self.get_results(task_id)
                if str(item.get("id") or "") not in skipped
            ]
            values = {
                "name": name,
                "target": task.get("target") or "-",
                "total": counts.get("total", 0),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0),
                "bu": next(
                    (
                        line[len("BU: ") :]
                        for line in str(task.get("notes") or "").splitlines()
                        if line.startswith("BU: ")
                    ),
                    "",
                ),
                "owner": owner,
                "task_id": task_id,
            }
            subject = render_template(self.settings.mail_subject, values)
            html = build_report_html(
                self.settings,
                subject=subject,
                title=name,
                target=str(task.get("target") or "-"),
                counts=counts,
                findings=details,
                bu=str(values["bu"]),
                owner=owner,
                task_id=task_id,
                retest=task.get("action") == "retest",
            )
            send_report_mail(
                self.settings,
                to=recipients,
                subject=subject,
                html=html,
                attachment=package,
                attachment_name=f"{report_download_stem(task)}.zip",
                high_priority=bool(counts.get("critical") or counts.get("high")),
            )
        except (MailError, TaskError) as exc:
            message = exc.message if isinstance(exc, TaskError) else str(exc)
            self.db.update_task(task_id, mail_status="failed", mail_error=message)
            raise TaskError("MAIL_FAILED", message, status_code=502) from exc
        updated = self.db.update_task(task_id, mail_status="sent", mail_error=None)
        assert updated is not None
        return updated

    def _gitea_sync_issues(
        self, task: dict[str, Any], findings: list[dict[str, Any]]
    ) -> None:
        """Open Gitea issues for audit findings (web-only; never raises)."""
        from app.services.findings import invalid_finding_ids
        from app.services.gitea_issues import sync_findings_as_issues

        skip = invalid_finding_ids(self.db.list_finding_flags(str(task["id"])))
        sync_findings_as_issues(self.settings, task, findings, skip_ids=skip)

    def _stop_task_sandbox(self, task: dict[str, Any]) -> None:
        """Stop Docker sandboxes for every run under this task workspace."""
        from strix.runtime.session_manager import stop_sandbox_from_run_dir

        workspace = Path(task["workspace"])
        runs_root = workspace / "strix_runs"
        run_dirs: list[Path] = []
        if runs_root.is_dir():
            run_dirs.extend(
                p for p in runs_root.iterdir() if p.is_dir() and (p / "run.json").is_file()
            )
        named = workspace_run_dir(workspace, task.get("run_name"))
        if named is not None and named not in run_dirs:
            run_dirs.append(named)
        if not run_dirs:
            from app.services.results import discover_run_name

            discovered = workspace_run_dir(workspace, discover_run_name(workspace))
            if discovered is not None:
                run_dirs.append(discovered)
        for run_dir in run_dirs:
            stop_sandbox_from_run_dir(run_dir)

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
        from app.services.results import vulnerabilities_mtime

        self._findings_disk_mtime[task["id"]] = vulnerabilities_mtime(run_dir)
        if str(task.get("status") or "") == "completed":
            self._gitea_sync_issues(task, findings)

    def get_results(self, task_id: str) -> list[dict[str, Any]]:
        task = self.get_task(task_id)
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if run_dir is None:
            from app.services.results import discover_run_name

            name = discover_run_name(Path(task["workspace"]))
            if name:
                self.db.update_task(task_id, run_name=name)
                run_dir = workspace_run_dir(Path(task["workspace"]), name)
        flags = self.db.list_finding_flags(task_id)
        if run_dir is not None:
            from app.services.results import vulnerabilities_mtime

            mtime = vulnerabilities_mtime(run_dir)
            # Re-read only when disk inputs changed — polling used to DELETE+INSERT
            # every finding (and its raw JSON) on every request.
            if self._findings_disk_mtime.get(task_id) == mtime:
                cached = self.db.list_findings(task_id=task_id, limit=1000)
                if cached or mtime == 0.0:
                    return sort_findings(apply_finding_flags(cached, flags))
            findings = load_normalized_findings(run_dir, task_id=task_id)
            self.db.replace_findings(task_id, findings)
            self._findings_disk_mtime[task_id] = mtime
            return sort_findings(apply_finding_flags(findings, flags))
        cached = self.db.list_findings(task_id=task_id, limit=1000)
        if cached:
            return sort_findings(apply_finding_flags(cached, flags))
        if task["status"] in ACTIVE:
            raise TaskError("RESULT_NOT_READY", "Results not ready", status_code=409)
        return []

    def get_finding(self, task_id: str, finding_id: str) -> dict[str, Any]:
        """Full finding body for the detail pane (list uses summary)."""
        findings = self.get_results(task_id)
        match = next(
            (item for item in findings if str(item.get("id")) == str(finding_id)),
            None,
        )
        if match is None:
            raise TaskError("FINDING_NOT_FOUND", f"Finding {finding_id} not found", status_code=404)
        return match

    def get_report(self, task_id: str, lang: str | None = None) -> str:
        task = self.get_task(task_id)
        if str(lang or "").lower().startswith("en"):
            return self._translated_report(task)[1].read_text(encoding="utf-8")
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        from app.services.results import rebuild_delivery_report

        exclude = invalid_finding_ids(self.db.list_finding_flags(task_id))
        # UI only needs markdown; skip zip rebuild on every tab open.
        rebuilt = rebuild_delivery_report(
            run_dir,
            exclude_ids=exclude,
            build_zip=False,
            retest=task.get("action") == "retest",
            lang=lang,
        )
        content = rebuilt if rebuilt is not None else read_report_markdown(run_dir, lang)
        if not content and task["status"] in ACTIVE:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        return content or ""

    def get_report_package(self, task_id: str, lang: str | None = None) -> Path:
        """Path to penetration_test_report.zip (markdown + images)."""
        from app.services.results import (
            build_translated_report_zip,
            rebuild_delivery_report,
            resolve_report_package,
        )

        task = self.get_task(task_id)
        if str(lang or "").lower().startswith("en"):
            run_dir, en_path = self._translated_report(task)
            package = build_translated_report_zip(
                run_dir, en_path, f"{report_download_stem(task)}.en.md"
            )
            if package is None:
                raise TaskError("TRANSLATION_NOT_READY", "English report package failed", status_code=409)
            return package
        run_dir = workspace_run_dir(Path(task["workspace"]), task.get("run_name"))
        if not run_dir:
            raise TaskError("RESULT_NOT_READY", "Report not ready", status_code=409)
        # Match the on-screen report (invalid findings filtered) before packaging.
        exclude = invalid_finding_ids(self.db.list_finding_flags(task_id))
        rebuild_delivery_report(
            run_dir,
            exclude_ids=exclude,
            build_zip=False,
            retest=task.get("action") == "retest",
        )
        package = resolve_report_package(
            run_dir, md_arcname=f"{report_download_stem(task)}.md"
        )
        if package is None:
            if task["status"] in ACTIVE:
                raise TaskError("RESULT_NOT_READY", "Report package not ready", status_code=409)
            raise TaskError("RESULT_NOT_READY", "Report package not found", status_code=404)
        return package

    def list_logs(self, task_id: str) -> list[dict[str, Any]]:
        from app.services.results import list_task_logs

        task = self.get_task(task_id)
        return list_task_logs(Path(task["workspace"]))

    def get_logs_package(self, task_id: str) -> Path:
        """Zip of scan_worker stdout/stderr (+ workspace/logs/* if any)."""
        from app.services.results import build_task_logs_zip

        task = self.get_task(task_id)
        package = build_task_logs_zip(Path(task["workspace"]))
        if package is None:
            raise TaskError(
                "LOGS_NOT_FOUND",
                "No execution logs found for this task yet",
                status_code=404,
            )
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
        proxy_url = task.get("proxy_url")
        use_proxy = bool(proxy_url)
        request_headers = task.get("request_headers")
        use_headers = bool(request_headers)
        if task["type"] == "pentest":
            return CreateTaskRequest(
                type="pentest",
                target=task["target"],
                instruction=task.get("instruction"),
                name=task.get("name"),
                notes=task.get("notes"),
                tags=parse_tags(task.get("tags")),
                mail_to=parse_tags(task.get("mail_to")) or None,
                scan_mode=task.get("scan_mode") or "deep",
                max_budget=task.get("max_budget"),
                proxy_url=proxy_url,
                use_proxy=use_proxy,
                request_headers=request_headers,
                use_headers=use_headers,
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
            tags=parse_tags(task.get("tags")),
            mail_to=parse_tags(task.get("mail_to")) or None,
            scan_mode=task.get("scan_mode") or "deep",
            max_budget=task.get("max_budget"),
            proxy_url=proxy_url,
            use_proxy=use_proxy,
            request_headers=request_headers,
            use_headers=use_headers,
        )
