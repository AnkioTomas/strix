"""Worker-node API tests (no live Strix runs)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.job_store import utc_now
from app.main import app
from app.schemas import CreateJobRequest


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(data_dir))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.setenv("STRIX_MAX_CONCURRENT", "2")
    monkeypatch.setenv("STRIX_NODE_ID", "test-node")
    get_settings.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def _fake_handle() -> MagicMock:
    handle = MagicMock()
    handle.pid = 4242
    handle.run_name = "run_fake"
    handle.viewer_url = None
    handle.viewer_token = None
    handle._error = None
    handle.poll.return_value = None
    handle.wait_ready.return_value = True
    handle.terminate.return_value = 0
    handle.send_message.return_value = True
    handle.refresh_run_name.return_value = "run_fake"
    return handle


@pytest.fixture()
def mock_start(monkeypatch: pytest.MonkeyPatch):
    def _start(job, *, settings, target, on_ready=None):
        handle = _fake_handle()
        if on_ready is not None:
            on_ready(handle)
        return handle

    monkeypatch.setattr("app.services.job_manager.start_strix", _start)
    monkeypatch.setattr(
        "app.services.job_manager.check_tcp_reachable",
        lambda *args, **kwargs: None,
    )


def test_health(client: TestClient):
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["node_id"] == "test-node"
    assert "free_slots" in body
    assert "admission" in body


def test_node_info(client: TestClient):
    res = client.get("/v1/node")
    assert res.status_code == 200
    body = res.json()
    assert body["node_id"] == "test-node"
    assert body["capacity"]["max_concurrent"] == 2
    assert body["status"] in {"ready", "full", "degraded"}


def test_auth_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "0")
    monkeypatch.setenv("STRIX_API_KEY", "secret-token")
    get_settings.cache_clear()
    with TestClient(app) as client:
        denied = client.get("/v1/node")
        assert denied.status_code == 401
        ok = client.get("/v1/node", headers={"Authorization": "Bearer secret-token"})
        assert ok.status_code == 200
    get_settings.cache_clear()


def test_create_and_get_job(client: TestClient, mock_start):
    res = client.post(
        "/v1/jobs",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "instruction": "Focus on IDOR",
            "scan_mode": "quick",
            "id": "job_demo",
        },
    )
    assert res.status_code == 202, res.text
    job = res.json()
    assert job["id"] == "job_demo"
    assert job["status"] == "running"
    assert job["target"] == "https://example.com"

    got = client.get("/v1/jobs/job_demo")
    assert got.status_code == 200
    assert got.json()["id"] == "job_demo"

    listed = client.get("/v1/jobs")
    assert listed.status_code == 200
    assert listed.json()["total"] >= 1


def test_node_full_returns_503(client: TestClient, mock_start, monkeypatch):
    manager = client.app.state.manager
    monkeypatch.setattr(
        manager,
        "admission",
        lambda: {
            "allowed_slots": 0,
            "running": 0,
            "free_slots": 0,
            "reason": "load:full",
            "task_cpu_percent": 30,
            "task_memory_gb": 2,
            "max_concurrent": 1,
            "system": {},
        },
    )
    res = client.post(
        "/v1/jobs",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    )
    assert res.status_code == 503
    assert res.json()["error"]["code"] == "NODE_FULL"


def test_create_blocks_private_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mock_start
):
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "0")
    get_settings.cache_clear()
    with TestClient(app) as client:
        res = client.post(
            "/v1/jobs",
            json={"type": "pentest", "target": "http://127.0.0.1/", "scan_mode": "quick"},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_TARGET"
    get_settings.cache_clear()


def test_cancel_steer_delete(client: TestClient, mock_start):
    res = client.post(
        "/v1/jobs",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    )
    assert res.status_code == 202, res.text
    job_id = res.json()["id"]

    steer = client.post(f"/v1/jobs/{job_id}/steer", json={"message": "status?"})
    assert steer.status_code == 200
    assert steer.json()["ok"] is True

    cancel = client.post(f"/v1/jobs/{job_id}/cancel")
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelled"

    deleted = client.delete(f"/v1/jobs/{job_id}")
    assert deleted.status_code == 204
    assert client.get(f"/v1/jobs/{job_id}").status_code == 404


def test_result_reads_disk(client: TestClient, mock_start):
    res = client.post(
        "/v1/jobs",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    )
    job_id = res.json()["id"]
    manager = client.app.state.manager
    job = manager.get_job(job_id)
    workspace = Path(job["workspace"])
    run_dir = workspace / "strix_runs" / "run_fake"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status":"completed"}', encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(
        '[{"id":"v1","title":"XSS","severity":"high"}]',
        encoding="utf-8",
    )
    (run_dir / "penetration_test_report.md").write_text("# Report\n", encoding="utf-8")
    manager.store.update(job_id, run_name="run_fake", status="completed", finished_at=utc_now())

    result = client.get(f"/v1/jobs/{job_id}/result")
    assert result.status_code == 200
    body = result.json()
    assert body["finding_counts"]["high"] == 1
    assert body["findings"][0]["id"] == "v1"
    assert body["report_markdown"] == "# Report\n"


def test_create_job_request_shape():
    req = CreateJobRequest.model_validate(
        {"type": "pentest", "target": "https://example.com", "scan_mode": "quick"}
    )
    assert req.type == "pentest"
    with pytest.raises(Exception):
        CreateJobRequest.model_validate({"type": "pentest", "scan_mode": "quick"})
