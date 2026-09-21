"""Sandbox reaper: stop Docker containers for terminal web tasks."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from app.config import get_settings
from app.db import Database
from app.services import sandbox_reaper


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Database:
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    return Database(tmp_path / "data" / "db.sqlite")


def _seed_task(
    db: Database,
    tmp_path: Path,
    *,
    task_id: str,
    status: str,
    runs: list[tuple[str, str | None]],
    run_name: str | None = None,
    workspace: Path | None = None,
) -> Path:
    """``runs`` is ``[(run_dir_name, container_id_or_None), ...]``."""
    ws = workspace or (tmp_path / "tasks" / task_id)
    ws.mkdir(parents=True, exist_ok=True)
    primary = run_name or (runs[0][0] if runs else None)
    for name, container_id in runs:
        run_dir = ws / "strix_runs" / name
        run_dir.mkdir(parents=True, exist_ok=True)
        record: dict = {"run_name": name, "status": "completed"}
        if container_id:
            record["sandbox"] = {"container_id": container_id}
        (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    now = "2026-01-01T00:00:00Z"
    db.insert_task(
        {
            "id": task_id,
            "type": "pentest",
            "status": status,
            "target": "https://example.com",
            "workspace": str(ws),
            "run_name": primary,
            "created_at": now,
            "updated_at": now,
        }
    )
    return ws


def test_reap_stops_sibling_run_not_just_current_run_name(db: Database, tmp_path: Path):
    """Finished task's DB run_name has no sandbox; older sibling still does."""
    ws = _seed_task(
        db,
        tmp_path,
        task_id="t_done",
        status="completed",
        run_name="run_latest",
        runs=[
            ("run_old", "abc123deadbeef"),
            ("run_latest", None),
        ],
    )
    old_dir = ws / "strix_runs" / "run_old"
    stopped: list[Path | None] = []

    def stop(path: Path | None) -> bool:
        stopped.append(path)
        return True

    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_labeled=list,
        stop_run_dir=stop,
        stop_container=lambda _cid: False,
    )
    assert result["stopped"] == 1
    assert result["checked"] == 1
    assert stopped == [old_dir]


def test_reap_skips_active_task_container(db: Database, tmp_path: Path):
    _seed_task(
        db,
        tmp_path,
        task_id="t_run",
        status="running",
        runs=[("run_a", "abc123deadbeef")],
    )
    stop = MagicMock(return_value=True)
    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_labeled=list,
        stop_run_dir=stop,
    )
    assert result["checked"] == 0
    assert result["stopped"] == 0
    stop.assert_not_called()


def test_reap_stops_by_label_when_sandbox_record_missing(db: Database, tmp_path: Path):
    _seed_task(
        db,
        tmp_path,
        task_id="t_done",
        status="completed",
        runs=[("run_orphan", None)],
    )
    stop_dir = MagicMock(return_value=True)
    stop_cid = MagicMock(return_value=True)
    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_labeled=lambda: [("ffffaaaabbbbcccc", "run_orphan")],
        stop_run_dir=stop_dir,
        stop_container=stop_cid,
    )
    assert result["checked"] == 0
    assert result["label_stopped"] == 1
    assert result["stopped"] == 1
    stop_cid.assert_called_once_with("ffffaaaabbbbcccc")
    stop_dir.assert_not_called()


def test_reap_does_not_stop_unrelated_labeled_container(db: Database, tmp_path: Path):
    _seed_task(
        db,
        tmp_path,
        task_id="t_done",
        status="completed",
        runs=[("run_a", None)],
    )
    stop_cid = MagicMock(return_value=True)
    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_labeled=lambda: [("ffffaaaabbbbcccc", "someone_elses_run")],
        stop_run_dir=MagicMock(return_value=True),
        stop_container=stop_cid,
    )
    assert result["stopped"] == 0
    stop_cid.assert_not_called()
