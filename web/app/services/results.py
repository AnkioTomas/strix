"""Read Strix run artifacts (results, report, events, files)."""

from __future__ import annotations

import contextlib
import json
import shutil
import threading
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.services.findings import normalize_findings

PRIOR_FINDINGS_DIRNAME = "prior_findings"
_RETEST_STRIP_KEYS = ("retest_status", "fix_verification")


if TYPE_CHECKING:
    from collections.abc import Callable

_ZIP_LOCKS: dict[str, threading.Lock] = {}
_ZIP_LOCKS_GUARD = threading.Lock()


def _zip_lock_for(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _ZIP_LOCKS_GUARD:
        lock = _ZIP_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _ZIP_LOCKS[key] = lock
        return lock


def _atomic_zip_write(
    zip_path: Path,
    write_entries: Callable[[zipfile.ZipFile], None],
) -> Path | None:
    """Write a zip via ``*.tmp`` + replace so readers never see truncation."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = zip_path.with_suffix(zip_path.suffix + ".tmp")
    with _zip_lock_for(zip_path):
        try:
            with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                write_entries(zf)
            tmp_path.replace(zip_path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            return None
    return zip_path if zip_path.is_file() else None


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


def prior_findings_dir(workspace: Path) -> Path:
    return Path(workspace) / PRIOR_FINDINGS_DIRNAME


def _raw_retest_report(item: dict[str, Any]) -> dict[str, Any]:
    raw = item.get("raw")
    if isinstance(raw, dict):
        report = dict(raw)
    else:
        report = {
            "id": item.get("id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "description": item.get("description"),
            "target": item.get("asset"),
            "evidence": item.get("evidence"),
            "poc": item.get("poc"),
            "impact": item.get("impact"),
            "remediation_steps": item.get("recommendation"),
            "technical_analysis": item.get("technical_analysis"),
        }
    for key in _RETEST_STRIP_KEYS:
        report.pop(key, None)
    return report


def write_prior_findings(
    workspace: Path,
    *,
    findings: list[dict[str, Any]],
    parent_run_dir: Path | None,
) -> Path | None:
    """Persist the parent findings a retest child must hydrate from."""
    if not findings:
        return None
    dest = prior_findings_dir(workspace)
    dest.mkdir(parents=True, exist_ok=True)
    reports = [_raw_retest_report(item) for item in findings]
    (dest / "vulnerabilities.json").write_text(
        json.dumps(reports, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    if parent_run_dir is None:
        return dest
    ids = {str(report.get("id")) for report in reports if report.get("id")}
    src_md = parent_run_dir / "vulnerabilities"
    if src_md.is_dir():
        out_md = dest / "vulnerabilities"
        out_md.mkdir(exist_ok=True)
        for fid in ids:
            src = src_md / f"{fid}.md"
            if src.is_file():
                shutil.copy2(src, out_md / f"{fid}.md")
    src_images = parent_run_dir / "images"
    if src_images.is_dir():
        shutil.copytree(src_images, dest / "images", dirs_exist_ok=True)
    return dest


def apply_prior_findings(workspace: Path, run_dir: Path) -> bool:
    """Copy staged parent reports into a fresh Strix run dir before hydrate."""
    src = prior_findings_dir(workspace)
    json_path = src / "vulnerabilities.json"
    if not json_path.is_file():
        return False
    run_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(json_path, run_dir / "vulnerabilities.json")
    for name in ("vulnerabilities", "images"):
        src_dir = src / name
        if src_dir.is_dir():
            shutil.copytree(src_dir, run_dir / name, dirs_exist_ok=True)
    return True


def read_report_markdown(run_dir: Path) -> str:
    for name in ("penetration_test_report.md", "report.md"):
        path = run_dir / name
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8")
            except OSError:
                return ""
    return ""


_DELIVERY_EXCLUDE_STAMP = ".web_delivery_exclude"


def _exclude_stamp(exclude_ids: set[str] | None) -> str:
    return ",".join(sorted(exclude_ids or ()))


def vulnerabilities_mtime(run_dir: Path) -> float:
    """Newest mtime of inputs that feed the findings list / delivery report."""
    newest = 0.0
    for name in ("vulnerabilities.json", "run.json"):
        path = run_dir / name
        if path.is_file():
            newest = max(newest, path.stat().st_mtime)
    return newest


def delivery_report_is_fresh(
    run_dir: Path,
    *,
    exclude_ids: set[str] | None = None,
) -> bool:
    """True when on-disk markdown already matches vulns + console excludes."""
    md_path = run_dir / "penetration_test_report.md"
    if not md_path.is_file():
        return False
    stamp_path = run_dir / _DELIVERY_EXCLUDE_STAMP
    try:
        stamped = stamp_path.read_text(encoding="utf-8") if stamp_path.is_file() else None
    except OSError:
        stamped = None
    if stamped != _exclude_stamp(exclude_ids):
        return False
    return md_path.stat().st_mtime >= vulnerabilities_mtime(run_dir)


def rebuild_delivery_report(
    run_dir: Path,
    *,
    exclude_ids: set[str] | None = None,
    build_zip: bool = False,
    force: bool = False,
) -> str | None:
    """Re-assemble the customer markdown from run.json + vulnerabilities.json.

    Skips work when the on-disk report is already fresh for this exclude set.
    UI ``GET /report`` must not rebuild the download zip on every open — pass
    ``build_zip=False`` (default). Download paths can force a zip via
    ``resolve_report_package`` or ``build_zip=True``.
    """
    if not force and delivery_report_is_fresh(run_dir, exclude_ids=exclude_ids):
        return read_report_markdown(run_dir)

    from strix.report.writer import read_run_record
    from strix.report.zh_report import write_zh_delivery_bundle

    record = read_run_record(run_dir)
    vulns = read_vulnerabilities(run_dir)
    if exclude_ids:
        vulns = [
            item
            for item in vulns
            if str(item.get("id") or item.get("report_id") or "") not in exclude_ids
        ]
    if not record and not vulns:
        return None
    scan_results = record.get("scan_results") if isinstance(record, dict) else None
    if not isinstance(scan_results, dict):
        scan_results = None
    try:
        write_zh_delivery_bundle(
            run_dir,
            run_record=record if isinstance(record, dict) else {},
            vulnerability_reports=vulns,
            scan_results=scan_results,
            build_zip=build_zip,
        )
    except Exception:
        return None
    stamp_path = run_dir / _DELIVERY_EXCLUDE_STAMP
    try:
        stamp_path.write_text(_exclude_stamp(exclude_ids), encoding="utf-8")
    except OSError:
        pass
    return read_report_markdown(run_dir)


def _build_report_zip(run_dir: Path, md_path: Path) -> Path | None:
    zip_path = run_dir / "penetration_test_report.zip"

    def _write(zf: zipfile.ZipFile) -> None:
        zf.write(md_path, arcname="penetration_test_report.md")
        images_dir = run_dir / "images"
        if images_dir.is_dir():
            for image in sorted(images_dir.iterdir()):
                if image.is_file():
                    zf.write(image, arcname=f"images/{image.name}")

    return _atomic_zip_write(zip_path, _write)


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
    return _build_report_zip(run_dir, md_path)


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


_WORKER_LOG_FILES = (
    "scan_worker.stdout.log",
    "scan_worker.stderr.log",
)


def list_task_logs(workspace: Path) -> list[dict[str, Any]]:
    """List worker / task log files under the web task workspace (not sandbox)."""
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


def resolve_task_log(workspace: Path, name: str) -> Path | None:
    """Resolve a single log path under the task workspace (no traversal)."""
    root = Path(workspace).resolve()
    rel = (name or "").strip().lstrip("/")
    if not rel or ".." in Path(rel).parts:
        return None
    allowed = {item["path"] for item in list_task_logs(root)}
    if rel not in allowed:
        return None
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def build_task_logs_zip(workspace: Path) -> Path | None:
    """Bundle available task logs into ``task_logs.zip`` under the workspace."""
    files = list_task_logs(workspace)
    if not files:
        return None
    root = Path(workspace)
    zip_path = root / "task_logs.zip"

    def _write(zf: zipfile.ZipFile) -> None:
        for item in files:
            path = root / item["path"]
            if path.is_file():
                zf.write(path, arcname=item["path"])

    return _atomic_zip_write(zip_path, _write)


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
