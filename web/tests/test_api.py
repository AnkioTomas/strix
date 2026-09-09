"""Unit tests for the local Strix API (no live Strix runs)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.schemas import CreateTaskRequest
from app.services.findings import normalize_finding


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(data_dir))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.setenv("STRIX_MAX_CONCURRENT", "1")
    get_settings.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_health(client: TestClient):
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["database"] is True
    assert "admission" in body


def test_no_global_findings_route(client: TestClient):
    res = client.get("/api/v1/findings")
    assert res.status_code == 404


def test_create_pentest_blocks_localhost(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "0")
    get_settings.cache_clear()
    with TestClient(app) as client:
        res = client.post(
            "/api/v1/tasks",
            json={"type": "pentest", "target": "http://127.0.0.1/", "scan_mode": "quick"},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_TARGET"
    get_settings.cache_clear()


def test_create_and_list_pentest(client: TestClient):
    res = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "instruction": "Focus on IDOR",
            "scan_mode": "quick",
        },
    )
    assert res.status_code == 202, res.text
    task = res.json()
    assert task["status"] == "queued"
    assert task["id"].startswith("task_")

    listed = client.get("/api/v1/tasks")
    assert listed.status_code == 200
    assert any(t["id"] == task["id"] for t in listed.json()["tasks"])


def test_cancel_queued(client: TestClient):
    res = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    )
    task_id = res.json()["id"]
    # Cancel immediately before worker claims it when possible
    cancelled = client.post(f"/api/v1/tasks/{task_id}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] in {"cancelled", "cancelling"}


def test_normalize_finding():
    raw = {
        "id": "abc",
        "title": "SQLi",
        "severity": "critical",
        "description": "desc",
        "target": "https://example.com",
        "endpoint": "/api?id=1",
        "method": "GET",
        "confidence": "high",
        "poc_description": "poc",
        "remediation_steps": "fix it",
        "cvss": 9.8,
        "cwe": ["CWE-89"],
    }
    finding = normalize_finding(raw, task_id="task_1")
    assert finding["id"] == "abc"
    assert finding["location"]["endpoint"] == "/api?id=1"
    assert finding["cwe"] == "CWE-89"


def test_ingest_results(client: TestClient):
    manager = client.app.state.manager
    task = manager.create_task(
        CreateTaskRequest(type="pentest", target="https://example.com", scan_mode="quick")
    )
    run_name = "demo-run"
    run_dir = Path(task["workspace"]) / "strix_runs" / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps({"run_name": run_name, "status": "completed"}))
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "v1",
                    "title": "XSS",
                    "severity": "high",
                    "description": "x",
                    "target": "https://example.com",
                    "timestamp": "2026-01-01T00:00:00Z",
                }
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "penetration_test_report.md").write_text("# Report\n", encoding="utf-8")
    manager.db.update_task(task["id"], run_name=run_name, status="completed")
    manager.ingest_results(manager.get_task(task["id"]))
    findings = manager.get_results(task["id"])
    assert len(findings) == 1
    assert findings[0]["title"] == "XSS"
    assert "Report" in manager.get_report(task["id"])


def test_retry_creates_child(client: TestClient):
    created = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    ).json()
    manager = client.app.state.manager
    manager.db.update_task(created["id"], status="failed", finished_at="2026-01-01T00:00:00Z")
    # Ensure worker didn't leave it running
    manager._processes.pop(created["id"], None)
    retried = client.post(f"/api/v1/tasks/{created['id']}/retry")
    assert retried.status_code == 202, retried.text
    body = retried.json()
    assert body["parent_task_id"] == created["id"]
    assert body["action"] == "retry"
