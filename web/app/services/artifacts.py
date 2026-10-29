"""Read scan artifacts from a job workspace (disk only)."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Any

from app.services.findings import normalize_findings, tally_finding_counts


_ZIP_LOCKS: dict[str, threading.Lock] = {}
_ZIP_LOCKS_GUARD = threading.Lock()
_WORKER_LOG_FILES = (
    "scan_worker.stdout.log",
    "scan_worker.stderr.log",
)


def _zip_lock_for(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _ZIP_LOCKS_GUARD:
        lock = _ZIP_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _ZIP_LOCKS[key] = lock
        return lock


def _atomic_zip_write(zip_path: Path, writer: Any) -> Path:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with _zip_lock_for(zip_path):
        fd, tmp = tempfile.mkstemp(dir=str(zip_path.parent), prefix=".zip.", suffix=".tmp")
        os.close(fd)
        try:
            with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                writer(zf)
            os.replace(tmp, zip_path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    return zip_path


def workspace_run_dir(workspace: Path, run_name: str | None) -> Path | None:
    if not run_name:
        return None
    path = Path(workspace) / "strix_runs" / run_name
    return path if path.is_dir() else None


def discover_run_name(workspace: Path) -> str | None:
    runs = Path(workspace) / "strix_runs"
    if not runs.is_dir():
        return None
    candidates = [p for p in runs.iterdir() if (p / "run.json").is_file()]
    if not candidates:
        return None
    latest = max(candidates, key=lambda p: (p / "run.json").stat().st_mtime)
    return latest.name


def read_vulnerabilities(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "vulnerabilities.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def load_normalized_findings(run_dir: Path, *, job_id: str) -> list[dict[str, Any]]:
    return normalize_findings(read_vulnerabilities(run_dir), task_id=job_id)


def count_disk_findings(run_dir: Path) -> dict[str, int]:
    return tally_finding_counts(read_vulnerabilities(run_dir))


def report_exists(run_dir: Path) -> bool:
    return any(
        (run_dir / name).is_file()
        for name in ("penetration_test_report.md", "report.md")
    )


def read_report_markdown(run_dir: Path) -> str | None:
    for name in ("penetration_test_report.md", "report.md"):
        path = run_dir / name
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8")
            except OSError:
                return None
    return None


def summarize_llm_usage(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or not raw:
        return None
    cached = 0
    cache_write = 0
    details = raw.get("input_tokens_details")
    if isinstance(details, list):
        for item in details:
            if not isinstance(item, dict):
                continue
            cached += int(item.get("cached_tokens") or 0)
            cache_write += int(item.get("cache_write_tokens") or 0)
    elif isinstance(details, dict):
        cached = int(details.get("cached_tokens") or 0)
        cache_write = int(details.get("cache_write_tokens") or 0)
    return {
        "requests": int(raw.get("requests") or 0),
        "input_tokens": int(raw.get("input_tokens") or 0),
        "output_tokens": int(raw.get("output_tokens") or 0),
        "cached_tokens": cached,
        "cache_write_tokens": cache_write,
        "total_tokens": int(raw.get("total_tokens") or 0),
        "cost": raw.get("cost"),
    }


def read_run_record(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "run.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def read_run_overview(run_dir: Path) -> dict[str, Any]:
    from datetime import datetime

    record = read_run_record(run_dir)
    started = record.get("start_time")
    finished = record.get("end_time")
    duration_seconds: float | None = None
    if isinstance(started, str) and isinstance(finished, str):
        try:
            start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(finished.replace("Z", "+00:00"))
            duration_seconds = max(0.0, (end_dt - start_dt).total_seconds())
        except ValueError:
            duration_seconds = None
    return {
        "scan_started_at": started if isinstance(started, str) else None,
        "scan_finished_at": finished if isinstance(finished, str) else None,
        "duration_seconds": duration_seconds,
        "llm_usage": summarize_llm_usage(
            record.get("llm_usage") if isinstance(record.get("llm_usage"), dict) else None
        ),
    }


def read_events(run_dir: Path, *, limit: int = 500) -> list[dict[str, Any]]:
    events = _events_from_live_view(run_dir)
    if not events:
        events = _events_from_jsonl(run_dir)
    if limit > 0:
        return events[-limit:]
    return events


def list_artifacts(run_dir: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    sandbox = run_dir / "workspace"
    if not sandbox.is_dir():
        return artifacts
    for path in sorted(sandbox.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(sandbox).as_posix()
            size = path.stat().st_size
        except (OSError, ValueError):
            continue
        artifacts.append({"name": rel, "path": f"workspace/{rel}", "size": size})
    # Also surface report / vuln files at run root.
    for name in (
        "penetration_test_report.md",
        "report.md",
        "vulnerabilities.json",
        "run.json",
        "findings.sarif",
    ):
        path = run_dir / name
        if path.is_file():
            try:
                artifacts.append({"name": name, "path": name, "size": path.stat().st_size})
            except OSError:
                continue
    images = run_dir / "images"
    if images.is_dir():
        for path in sorted(images.rglob("*")):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(run_dir).as_posix()
                artifacts.append({"name": rel, "path": rel, "size": path.stat().st_size})
            except (OSError, ValueError):
                continue
    return artifacts


def resolve_artifact(run_dir: Path, name: str) -> Path | None:
    candidate = (run_dir / name).resolve()
    try:
        candidate.relative_to(run_dir.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def list_job_logs(workspace: Path) -> list[dict[str, Any]]:
    root = Path(workspace)
    logs: list[dict[str, Any]] = []
    for name in _WORKER_LOG_FILES:
        path = root / name
        if path.is_file():
            try:
                size = path.stat().st_size
            except OSError:
                continue
            logs.append({"name": name, "path": name, "size": size})
    logs_dir = root / "logs"
    if logs_dir.is_dir():
        for path in sorted(logs_dir.rglob("*")):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root).as_posix()
                size = path.stat().st_size
            except (OSError, ValueError):
                continue
            logs.append({"name": rel, "path": rel, "size": size})
    return logs


def resolve_job_log(workspace: Path, name: str) -> Path | None:
    root = Path(workspace).resolve()
    rel = (name or "").strip().lstrip("/")
    if not rel or ".." in Path(rel).parts:
        return None
    allowed = {item["path"] for item in list_job_logs(root)}
    if rel not in allowed:
        return None
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def build_job_logs_zip(workspace: Path) -> Path | None:
    files = list_job_logs(workspace)
    if not files:
        return None
    root = Path(workspace)
    zip_path = root / "job_logs.zip"

    def _write(zf: zipfile.ZipFile) -> None:
        for item in files:
            path = root / item["path"]
            if path.is_file():
                zf.write(path, arcname=item["path"])

    return _atomic_zip_write(zip_path, _write)


def _events_from_live_view(run_dir: Path) -> list[dict[str, Any]]:
    try:
        from strix.interface.viewer.transcript import build_run_state
    except ImportError:
        return []
    try:
        state = build_run_state(run_dir)
    except Exception:
        return []
    events = state.get("events") if isinstance(state, dict) else None
    return events if isinstance(events, list) else []


def _events_from_jsonl(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "events.jsonl"
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                events.append(item)
    except OSError:
        return []
    return events
