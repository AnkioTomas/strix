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


def test_create_task_with_attachments(client: TestClient):
    from app.config import get_settings
    from app.services.attachments import resolve_task_workspace_files

    res = client.post(
        "/api/v1/tasks",
        data={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "instruction": "Use the wordlist",
        },
        files=[
            ("attachments", ("notes.txt", b"admin:admin\n", "text/plain")),
            ("attachments", ("paths.txt", b"/api/v1\n/admin\n", "text/plain")),
        ],
    )
    assert res.status_code == 202, res.text
    task = res.json()
    settings = get_settings()
    workspace = settings.tasks_dir / task["id"]
    attached = resolve_task_workspace_files(workspace)
    assert len(attached) == 2
    names = {Path(item["workspace_path"]).name for item in attached}
    assert names == {"notes.txt", "paths.txt"}
    for item in attached:
        assert Path(item["source_path"]).is_file()


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


def test_run_overview_tokens(tmp_path: Path):
    from app.services.results import read_run_overview

    run_dir = tmp_path / "strix_runs" / "demo"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": "demo",
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2026-01-01T01:30:00+00:00",
                "llm_usage": {
                    "requests": 3,
                    "input_tokens": 1000,
                    "output_tokens": 200,
                    "total_tokens": 1200,
                    "input_tokens_details": [
                        {"cached_tokens": 400, "cache_write_tokens": 50}
                    ],
                    "cost": 0.12,
                },
            }
        ),
        encoding="utf-8",
    )
    overview = read_run_overview(run_dir)
    assert overview["duration_seconds"] == 5400.0
    assert overview["llm_usage"]["input_tokens"] == 1000
    assert overview["llm_usage"]["cached_tokens"] == 400
    assert overview["llm_usage"]["cache_write_tokens"] == 50
    assert overview["llm_usage"]["total_tokens"] == 1200


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
        "poc_description": "poc steps",
        "poc_script_code": "curl 'https://example.com/?id=1'",
        "technical_analysis": "union based",
        "screenshot_rels": ["images/abc-1.png"],
        "remediation_steps": "fix it",
        "cvss": 9.8,
        "cwe": ["CWE-89"],
    }
    finding = normalize_finding(raw, task_id="task_1")
    assert finding["id"] == "abc"
    assert finding["location"]["endpoint"] == "/api?id=1"
    assert finding["cwe"] == "CWE-89"
    assert "poc steps" in finding["poc"]
    assert "curl" in finding["poc"]
    assert finding["technical_analysis"] == "union based"
    assert finding["screenshots"] == ["images/abc-1.png"]


def test_get_results_refreshes_stale_cache(client: TestClient):
    manager = client.app.state.manager
    task = manager.create_task(
        CreateTaskRequest(type="pentest", target="https://example.com", scan_mode="quick")
    )
    run_name = "vuln-refresh"
    run_dir = Path(task["workspace"]) / "strix_runs" / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps({"run_name": run_name, "status": "running"}))
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "v1",
                    "title": "First",
                    "severity": "low",
                    "description": "one",
                    "target": "https://example.com",
                }
            ]
        ),
        encoding="utf-8",
    )
    manager.db.update_task(task["id"], run_name=run_name, status="running")
    first = client.get(f"/api/v1/tasks/{task['id']}/results").json()["findings"]
    assert [f["id"] for f in first] == ["v1"]

    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "v1",
                    "title": "First",
                    "severity": "low",
                    "description": "one",
                    "target": "https://example.com",
                },
                {
                    "id": "v2",
                    "title": "Second",
                    "severity": "critical",
                    "description": "two",
                    "target": "https://example.com",
                    "poc_description": "click",
                    "poc_script_code": "id",
                    "screenshot_rels": ["images/v2-1.png"],
                },
            ]
        ),
        encoding="utf-8",
    )
    second = client.get(f"/api/v1/tasks/{task['id']}/results").json()["findings"]
    assert [f["id"] for f in second] == ["v2", "v1"]  # severity order
    assert "click" in (second[0].get("poc") or "")
    assert "id" in (second[0].get("poc") or "")
    assert second[0].get("screenshots") == ["images/v2-1.png"]


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
    package = manager.get_report_package(task["id"])
    assert package.name == "penetration_test_report.zip"
    assert package.is_file()

    (run_dir / "workspace").mkdir()
    (run_dir / "workspace" / "note.txt").write_text("hi", encoding="utf-8")
    arts = client.get(f"/api/v1/tasks/{task['id']}/artifacts").json()["artifacts"]
    assert any(a["path"] == "workspace/note.txt" for a in arts)

    zipped = client.get(f"/api/v1/tasks/{task['id']}/report?download=1")
    assert zipped.status_code == 200
    assert "zip" in zipped.headers.get("content-type", "")
    assert zipped.content[:2] == b"PK"


def test_start_strix_job_preserves_resume_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import subprocess as sp

    from app.services import strix_runner

    class _FakePopen:
        pid = 4242

        def __init__(self, *args, **kwargs):
            pass

        def poll(self):
            return None

    monkeypatch.setattr(sp, "Popen", _FakePopen)

    workspace = tmp_path / "task"
    workspace.mkdir()
    (tmp_path / "data").mkdir()
    task = {
        "id": "task_resume_job",
        "type": "pentest",
        "instruction": "orig",
        "scan_mode": "quick",
        "max_budget": None,
        "workspace": str(workspace),
        "action": "resume",
        "run_name": "keep_this_run",
        "target": "https://example.com",
    }
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    get_settings.cache_clear()
    settings = get_settings()
    handle = strix_runner.start_strix(task, settings=settings, target="https://example.com")
    assert handle.pid == 4242
    job = json.loads((workspace / ".web_scan_job.json").read_text(encoding="utf-8"))
    assert job["task"]["action"] == "resume"
    assert job["task"]["run_name"] == "keep_this_run"
    assert job["task"]["id"] == "task_resume_job"
    get_settings.cache_clear()


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


def test_create_as_retry_copies_attachments(client: TestClient):
    created = client.post(
        "/api/v1/tasks",
        files={
            "type": (None, "pentest"),
            "target": (None, "https://example.com"),
            "scan_mode": (None, "quick"),
            "name": (None, "parent"),
            "attachments": ("note.txt", b"hello", "text/plain"),
        },
    ).json()
    manager = client.app.state.manager
    parent = manager.get_task(created["id"])
    assert (Path(parent["workspace"]) / "attachments" / "note.txt").is_file()

    child = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com/v2",
            "scan_mode": "deep",
            "name": "parent (retry)",
            "instruction": "focus on auth",
            "parent_task_id": created["id"],
            "action": "retry",
        },
    )
    assert child.status_code == 202, child.text
    body = child.json()
    assert body["parent_task_id"] == created["id"]
    assert body["action"] == "retry"
    assert body["target"] == "https://example.com/v2"
    assert body["name"] == "parent (retry)"
    child_task = manager.get_task(body["id"])
    assert (Path(child_task["workspace"]) / "attachments" / "note.txt").read_bytes() == b"hello"


def test_resume_requires_agent_snapshot(client: TestClient):
    created = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    ).json()
    manager = client.app.state.manager
    task = manager.get_task(created["id"])
    workspace = Path(task["workspace"])
    run_name = "example_resume_1"
    state_dir = workspace / "strix_runs" / run_name / ".state"
    state_dir.mkdir(parents=True)
    (workspace / "strix_runs" / run_name / "run.json").write_text(
        '{"run_name":"example_resume_1","targets_info":[{"type":"web","details":{}}]}',
        encoding="utf-8",
    )
    manager.db.update_task(
        created["id"],
        status="failed",
        finished_at="2026-01-01T00:00:00Z",
        run_name=run_name,
    )
    manager._processes.pop(created["id"], None)

    missing = client.post(f"/api/v1/tasks/{created['id']}/resume")
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "RESUME_UNAVAILABLE"

    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    ok = client.post(
        f"/api/v1/tasks/{created['id']}/resume",
        json={"instruction": "继续找 SQLi"},
    )
    assert ok.status_code == 202, ok.text
    body = ok.json()
    assert body["id"] == created["id"]
    assert body["action"] == "resume"
    assert body["status"] == "queued"
    assert body["run_name"] == run_name
    assert body["finished_at"] is None
    note = workspace / ".web_resume_instruction"
    assert note.is_file()
    assert note.read_text(encoding="utf-8") == "继续找 SQLi"


def test_task_name_notes_hold_release(client: TestClient):
    created = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "name": "客户A",
            "notes": "周末再跑",
            "held": True,
        },
    )
    assert created.status_code == 202, created.text
    task = created.json()
    assert task["status"] == "held"
    assert task["name"] == "客户A"
    assert task["notes"] == "周末再跑"

    renamed = client.patch(
        f"/api/v1/tasks/{task['id']}",
        json={"name": "客户A-复测", "notes": "改备注"},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "客户A-复测"
    assert renamed.json()["notes"] == "改备注"

    released = client.post(f"/api/v1/tasks/{task['id']}/release")
    assert released.status_code == 202
    assert released.json()["status"] == "queued"

    held = client.post(f"/api/v1/tasks/{task['id']}/hold")
    assert held.status_code == 200
    assert held.json()["status"] == "held"

    deleted = client.delete(f"/api/v1/tasks/{task['id']}")
    assert deleted.status_code == 204

    created = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    ).json()
    manager = client.app.state.manager
    workspace = Path(manager.get_task(created["id"])["workspace"])
    assert workspace.is_dir()

    blocked = client.delete(f"/api/v1/tasks/{created['id']}")
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "TASK_NOT_DELETABLE"

    manager.db.update_task(
        created["id"],
        status="failed",
        finished_at="2026-01-01T00:00:00Z",
    )
    manager._processes.pop(created["id"], None)
    deleted = client.delete(f"/api/v1/tasks/{created['id']}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/tasks/{created['id']}").status_code == 404
    assert not workspace.exists()


def test_import_cli_runs(client: TestClient, tmp_path: Path):
    legacy = tmp_path / "legacy_project"
    run_dir = legacy / "strix_runs" / "legacy_web_1"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": "legacy_web_1",
                "status": "completed",
                "scan_mode": "standard",
                "instruction": "from CLI",
                "start_time": "2026-01-02T00:00:00Z",
                "end_time": "2026-01-02T02:00:00Z",
                "targets_info": [
                    {
                        "type": "web_application",
                        "details": {"target_url": "https://legacy.example"},
                        "original": "https://legacy.example",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "legacy-v1",
                    "title": "XSS",
                    "severity": "medium",
                    "description": "reflected",
                    "target": "https://legacy.example",
                }
            ]
        ),
        encoding="utf-8",
    )

    preview = client.post(
        "/api/v1/tasks/import",
        json={"path": str(legacy), "dry_run": True},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["imported_count"] == 1
    assert body["imported"][0]["run_name"] == "legacy_web_1"
    assert body["imported"][0]["task_id"] is None

    imported = client.post(
        "/api/v1/tasks/import",
        json={"path": str(legacy), "dry_run": False},
    )
    assert imported.status_code == 200, imported.text
    result = imported.json()
    assert result["imported_count"] == 1
    task_id = result["imported"][0]["task_id"]
    assert task_id

    detail = client.get(f"/api/v1/tasks/{task_id}").json()
    assert detail["action"] == "import"
    assert detail["status"] == "completed"
    assert detail["target"] == "https://legacy.example"
    assert detail["run_name"] == "legacy_web_1"

    findings = client.get(f"/api/v1/tasks/{task_id}/results").json()
    assert any(f["id"] == "legacy-v1" for f in findings["findings"])

    again = client.post(
        "/api/v1/tasks/import",
        json={"path": str(legacy), "dry_run": False},
    ).json()
    assert again["imported_count"] == 0
    assert again["skipped_count"] == 1
