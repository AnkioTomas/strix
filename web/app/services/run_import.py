"""Import legacy CLI ``strix_runs`` directories into the web task store."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.results import read_run_record


def discover_run_dirs(root: Path) -> list[Path]:
    """Find run directories under ``root``.

    Accepts:
    - a project cwd that contains ``strix_runs/``
    - a ``strix_runs/`` directory itself
    - a single run directory that contains ``run.json``
    """
    root = root.expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root}")

    if (root / "run.json").is_file():
        return [root]

    runs_dir = root / "strix_runs" if (root / "strix_runs").is_dir() else root
    if not runs_dir.is_dir():
        return []

    found: list[Path] = []
    for child in sorted(runs_dir.iterdir()):
        if child.is_dir() and (child / "run.json").is_file():
            found.append(child)
    return found


def map_run_status(raw: str | None) -> tuple[str, str | None]:
    """Map CLI ``run.json`` status → web ``TaskStatus`` + optional error note."""
    status = (raw or "").strip().lower()
    if status == "completed":
        return "completed", None
    if status in {"failed", "interrupted"}:
        return "failed", f"imported from CLI status={status or 'unknown'}"
    if status == "stopped":
        return "cancelled", None
    # Never import as ACTIVE — incomplete/running CLI runs become failed.
    return "failed", f"imported incomplete CLI run (status={status or 'unknown'})"


def fields_from_run_record(record: dict[str, Any], *, run_dir: Path) -> dict[str, Any]:
    """Derive web task columns from a CLI ``run.json`` record."""
    run_name = str(record.get("run_name") or record.get("run_id") or run_dir.name)
    status, error = map_run_status(
        str(record.get("status")) if record.get("status") is not None else None
    )
    scan_mode = str(record.get("scan_mode") or "standard")
    if scan_mode not in {"quick", "standard", "deep"}:
        scan_mode = "standard"
    instruction = record.get("instruction") or record.get("user_instruction")
    if instruction is not None:
        instruction = str(instruction) or None

    targets = record.get("targets_info") or []
    if not isinstance(targets, list):
        targets = []

    task_type = "pentest"
    target: str | None = run_name
    source_type: str | None = None
    source_url: str | None = None
    source_path: str | None = None
    source_branch: str | None = None
    source_commit: str | None = None

    for item in targets:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "")
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        original = item.get("original")
        if kind == "local_code":
            task_type = "audit"
            source_type = "local"
            source_path = str(details.get("target_path") or original or "")
            target = source_path or run_name
            break
        if kind == "repository":
            task_type = "audit"
            source_type = "git"
            source_url = str(
                details.get("repo_url")
                or details.get("git_url")
                or details.get("url")
                or original
                or ""
            )
            source_branch = (
                str(details["branch"]) if details.get("branch") is not None else None
            )
            source_commit = (
                str(details["commit"]) if details.get("commit") is not None else None
            )
            target = source_url or run_name
            break
        if kind in {"web_application", "ip_address", "domain", "api_spec"}:
            task_type = "pentest"
            target = str(
                details.get("target_url")
                or details.get("url")
                or original
                or run_name
            )
            break

    return {
        "type": task_type,
        "status": status,
        "target": target,
        "source_type": source_type,
        "source_url": source_url,
        "source_branch": source_branch,
        "source_commit": source_commit,
        "source_path": source_path,
        "instruction": instruction,
        "scan_mode": scan_mode,
        "run_name": run_name,
        "error": error,
        "started_at": _iso_or_none(record.get("start_time")),
        "finished_at": _iso_or_none(record.get("end_time")),
    }


def preview_run(run_dir: Path) -> dict[str, Any]:
    record = read_run_record(run_dir)
    fields = fields_from_run_record(record, run_dir=run_dir)
    return {
        "source_path": str(run_dir),
        "run_name": fields["run_name"],
        "type": fields["type"],
        "status": fields["status"],
        "target": fields["target"],
        "scan_mode": fields["scan_mode"],
        "cli_status": record.get("status"),
    }


def _iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
