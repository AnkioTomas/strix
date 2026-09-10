"""Tests for CLI run import helpers."""

from __future__ import annotations

import json
from pathlib import Path

from app.services.run_import import (
    discover_run_dirs,
    fields_from_run_record,
    map_run_status,
)


def test_map_run_status():
    assert map_run_status("completed") == ("completed", None)
    assert map_run_status("stopped")[0] == "cancelled"
    assert map_run_status("running")[0] == "failed"
    assert map_run_status("interrupted")[0] == "failed"


def test_discover_and_fields(tmp_path: Path):
    run_dir = tmp_path / "strix_runs" / "demo_run"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": "demo_run",
                "status": "completed",
                "scan_mode": "quick",
                "instruction": "check xss",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-01-01T01:00:00Z",
                "targets_info": [
                    {
                        "type": "web_application",
                        "details": {"target_url": "https://example.com"},
                        "original": "https://example.com",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    found = discover_run_dirs(tmp_path)
    assert found == [run_dir]
    assert discover_run_dirs(tmp_path / "strix_runs") == [run_dir]
    assert discover_run_dirs(run_dir) == [run_dir]

    fields = fields_from_run_record(
        json.loads((run_dir / "run.json").read_text(encoding="utf-8")),
        run_dir=run_dir,
    )
    assert fields["type"] == "pentest"
    assert fields["target"] == "https://example.com"
    assert fields["status"] == "completed"
    assert fields["scan_mode"] == "quick"
    assert fields["instruction"] == "check xss"
