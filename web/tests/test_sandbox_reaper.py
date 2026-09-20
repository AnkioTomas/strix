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
    container_id: str | None,
) -> Path:
    workspace = tmp_path / "tasks" / task_id
    run_name = f"{task_id}_run"
    run_dir = workspace / "strix_runs" / run_name
    run_dir.mkdir(parents=True)
    record: dict = {"run_name": run_name, "status": "completed"}
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
            "workspace": str(workspace),
            "run_name": run_name,
            "created_at": now,
            "updated_at": now,
        }
    )
    return run_dir


def test_reap_stops_running_container_for_completed_task(db: Database, tmp_path: Path):
    run_dir = _seed_task(
        db, tmp_path, task_id="t_done", status="completed", container_id="abc123deadbeef"
    )
    _seed_task(
        db, tmp_path, task_id="t_live", status="running", container_id="live999deadbeef"
    )

    stopped: list[Path | None] = []

    def stop(path: Path | None) -> bool:
        stopped.append(path)
        return True

    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_running=lambda: ["abc123deadbeef00", "live999deadbeef00"],
        stop_run_dir=stop,
    )
    assert result["stopped"] == 1
    assert result["running"] == 1
    assert result["skipped_active"] == 0
    assert stopped == [run_dir]


def test_reap_skips_already_stopped_containers(db: Database, tmp_path: Path):
    _seed_task(
        db, tmp_path, task_id="t_done", status="completed", container_id="abc123deadbeef"
    )
    stop = MagicMock(return_value=True)
    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_running=list,
        stop_run_dir=stop,
    )
    assert result["checked"] == 1
    assert result["running"] == 0
    assert result["stopped"] == 0
    stop.assert_not_called()


def test_reap_does_not_stop_active_task_container(db: Database, tmp_path: Path):
    _seed_task(
        db, tmp_path, task_id="t_run", status="running", container_id="abc123deadbeef"
    )
    stop = MagicMock(return_value=True)
    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_running=lambda: ["abc123deadbeef00"],
        stop_run_dir=stop,
    )
    assert result["checked"] == 0
    assert result["stopped"] == 0
    stop.assert_not_called()


def test_reap_noop_without_sandbox_record(db: Database, tmp_path: Path):
    _seed_task(db, tmp_path, task_id="t_bare", status="failed", container_id=None)
    stop = MagicMock(return_value=True)
    result = sandbox_reaper.reap_stopped_task_sandboxes(
        db,
        list_running=lambda: ["whatever"],
        stop_run_dir=stop,
    )
    assert result["checked"] == 0
    stop.assert_not_called()
