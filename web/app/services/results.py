"""Read Strix run artifacts (results, report, events, files)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from app.services.findings import normalize_findings


def workspace_run_dir(workspace: Path, run_name: str | None) -> Path | None:
    if not run_name:
        return None
    path = workspace / "strix_runs" / run_name
    return path if path.is_dir() else None


def discover_run_name(workspace: Path) -> str | None:
    runs = workspace / "strix_runs"
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


def load_normalized_findings(run_dir: Path, *, task_id: str) -> list[dict[str, Any]]:
    return normalize_findings(read_vulnerabilities(run_dir), task_id=task_id)


def read_report_markdown(run_dir: Path) -> str:
    for name in ("penetration_test_report.md", "report.md"):
        path = run_dir / name
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8")
            except OSError:
                return ""
    return ""


def resolve_report_package(run_dir: Path) -> Path | None:
    """Return the report zip (md + images). Build it if only markdown exists."""
    zip_path = run_dir / "penetration_test_report.zip"
    if zip_path.is_file():
        return zip_path
    md_path = run_dir / "penetration_test_report.md"
    if not md_path.is_file():
        alt = run_dir / "report.md"
        if not alt.is_file():
            return None
        md_path = alt
    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(md_path, arcname="penetration_test_report.md")
            images_dir = run_dir / "images"
            if images_dir.is_dir():
                for image in sorted(images_dir.iterdir()):
                    if image.is_file():
                        zf.write(image, arcname=f"images/{image.name}")
    except OSError:
        return None
    return zip_path if zip_path.is_file() else None


def summarize_llm_usage(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Flatten run.json ``llm_usage`` into overview-friendly totals."""
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


def read_run_overview(run_dir: Path) -> dict[str, Any]:
    """Scan timing + token totals for the task overview panel."""
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


def read_run_record(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "run.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def read_events(run_dir: Path, *, limit: int = 500) -> list[dict[str, Any]]:
    """Prefer Strix live-view projection; fall back to events.jsonl if present."""
    events = _events_from_live_view(run_dir)
    if not events:
        events = _events_from_jsonl(run_dir)
    if limit > 0:
        return events[-limit:]
    return events


def list_artifacts(run_dir: Path) -> list[dict[str, Any]]:
    """List files under the run sandbox ``workspace/`` directory."""
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
    return artifacts


def resolve_artifact(run_dir: Path, name: str) -> Path | None:
    candidate = (run_dir / name).resolve()
    try:
        candidate.relative_to(run_dir.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _events_from_live_view(run_dir: Path) -> list[dict[str, Any]]:
    try:
        from strix.interface.viewer.transcript import build_run_state
    except Exception:
        return []
    try:
        state = build_run_state(run_dir)
    except Exception:
        return []
    raw_events = state.get("events") or []
    normalized: list[dict[str, Any]] = []
    for item in raw_events:
        if not isinstance(item, dict):
            continue
        message = (
            item.get("message")
            or item.get("content")
            or item.get("text")
            or item.get("summary")
            or ""
        )
        normalized.append(
            {
                "timestamp": item.get("timestamp") or item.get("time"),
                "type": item.get("type") or item.get("kind") or "event",
                "message": str(message) if message is not None else "",
                "agent_id": item.get("agent_id"),
                "raw": item,
            }
        )
    return normalized


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
                events.append(
                    {
                        "timestamp": item.get("timestamp"),
                        "type": item.get("type") or "event",
                        "message": str(item.get("message") or item.get("content") or ""),
                        "agent_id": item.get("agent_id"),
                        "raw": item,
                    }
                )
    except OSError:
        return []
    return events
