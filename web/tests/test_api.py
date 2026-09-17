"""Unit tests for the local Strix API (no live Strix runs)."""

from __future__ import annotations

import json
import urllib.parse
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


def test_create_task_with_agent_proxy_and_headers(client: TestClient):
    bad = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "use_proxy": True,
            "proxy_url": "ftp://bad",
        },
    )
    assert bad.status_code == 400

    missing = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "use_proxy": True,
        },
    )
    assert missing.status_code == 400

    unused = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "use_proxy": False,
            "proxy_url": "http://127.0.0.1:7890",
            "use_headers": False,
            "request_headers": "Authorization: Bearer x",
        },
    )
    assert unused.status_code == 202, unused.text
    assert unused.json().get("proxy_url") in (None, "")
    assert unused.json().get("request_headers") in (None, "")

    bad_headers = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "use_headers": True,
            "request_headers": "not-a-header",
        },
    )
    assert bad_headers.status_code == 400

    ok = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "instruction": "Focus on auth",
            "use_proxy": True,
            "proxy_url": "http://alice:s3cret@127.0.0.1:7890",
            "use_headers": True,
            "request_headers": "Authorization: Bearer tok\nCookie: s=1",
        },
    )
    assert ok.status_code == 202, ok.text
    body = ok.json()
    assert body["proxy_url"] == "http://alice:s3cret@127.0.0.1:7890"
    assert body["proxy_display"] == "http://***@127.0.0.1:7890"
    assert body["request_headers"] == "Authorization: Bearer tok\nCookie: s=1"
    # User instruction stays clean; mandates are composed at scan start.
    assert body["instruction"] == "Focus on auth"
    assert "[出站代理" not in (body["instruction"] or "")

    detail = client.get(f"/api/v1/tasks/{body['id']}").json()
    assert detail["proxy_url"] == body["proxy_url"]
    assert detail["request_headers"] == body["request_headers"]
    assert detail["proxy_display"] == body["proxy_display"]


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

    # Unchanged disk must not thrash SQLite replace_findings on every poll.
    before = manager.db.list_findings(task_id=task["id"], limit=1000)
    third = client.get(f"/api/v1/tasks/{task['id']}/results").json()["findings"]
    assert [f["id"] for f in third] == [f["id"] for f in before]
    assert manager._findings_disk_mtime.get(task["id"]) is not None

    summary = client.get(f"/api/v1/tasks/{task['id']}/results?summary=1").json()["findings"]
    assert [f["id"] for f in summary] == ["v2", "v1"]
    assert summary[0].get("poc") in (None, "")
    assert summary[0].get("description") in (None, "")
    detail = client.get(f"/api/v1/tasks/{task['id']}/findings/v2").json()
    assert "click" in (detail.get("poc") or "")
    assert detail.get("screenshots") == ["images/v2-1.png"]


def test_get_report_skips_rebuild_when_fresh(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    manager = client.app.state.manager
    task = manager.create_task(
        CreateTaskRequest(type="pentest", target="https://example.com", scan_mode="quick")
    )
    run_name = "report-cache"
    run_dir = Path(task["workspace"]) / "strix_runs" / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": run_name,
                "status": "completed",
                "scan_results": {
                    "executive_summary": "摘要",
                    "methodology": "方法",
                    "technical_analysis": "分析",
                    "recommendations": "建议",
                },
            }
        ),
        encoding="utf-8",
    )
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
    manager.db.update_task(
        task["id"],
        run_name=run_name,
        status="completed",
        finished_at="2026-01-01T00:00:00Z",
    )

    calls = {"n": 0}
    from strix.report import zh_report

    real = zh_report.write_zh_delivery_bundle

    def counted(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(zh_report, "write_zh_delivery_bundle", counted)

    first = client.get(f"/api/v1/tasks/{task['id']}/report")
    assert first.status_code == 200, first.text
    assert "XSS" in first.json()["content"]
    assert calls["n"] == 1

    second = client.get(f"/api/v1/tasks/{task['id']}/report")
    assert second.status_code == 200
    assert calls["n"] == 1, "fresh report must not rebuild markdown/zip"

    # Marking invalid must force a rebuild so excluded findings disappear.
    client.patch(
        f"/api/v1/tasks/{task['id']}/findings/v1",
        json={"review_status": "invalid"},
    )
    # update_finding_review already rebuilds; reset counter and fetch again.
    calls["n"] = 0
    third = client.get(f"/api/v1/tasks/{task['id']}/report")
    assert third.status_code == 200
    assert "XSS" not in third.json()["content"]
    assert calls["n"] == 0  # stamp already updated by invalidate rebuild


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
    assert "XSS" in manager.get_report(task["id"])
    assert "漏洞清单" in manager.get_report(task["id"]) or "Findings" in manager.get_report(
        task["id"]
    )
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
    disposition = urllib.parse.unquote(zipped.headers.get("content-disposition", ""))
    assert "报告.zip" in disposition
    assert "example.com" in disposition

    manager.db.update_task(task["id"], name="客户A门户", action="retest")
    renamed = client.get(f"/api/v1/tasks/{task['id']}/report?download=1")
    assert renamed.status_code == 200
    renamed_disp = urllib.parse.unquote(renamed.headers.get("content-disposition", ""))
    assert "复测-客户A门户-报告.zip" in renamed_disp

    empty_logs = client.get(f"/api/v1/tasks/{task['id']}/logs")
    assert empty_logs.status_code == 200
    assert empty_logs.json()["logs"] == []
    missing_bundle = client.get(f"/api/v1/tasks/{task['id']}/logs?download=1")
    assert missing_bundle.status_code == 404

    workspace = Path(task["workspace"])
    (workspace / "scan_worker.stdout.log").write_text("hello stdout\n", encoding="utf-8")
    (workspace / "scan_worker.stderr.log").write_text("warn stderr\n", encoding="utf-8")
    (workspace / "logs").mkdir(exist_ok=True)
    (workspace / "logs" / "extra.log").write_text("extra\n", encoding="utf-8")
    listed = client.get(f"/api/v1/tasks/{task['id']}/logs").json()["logs"]
    names = {item["name"] for item in listed}
    assert "scan_worker.stdout.log" in names
    assert "scan_worker.stderr.log" in names
    assert "logs/extra.log" in names
    one = client.get(f"/api/v1/tasks/{task['id']}/logs/scan_worker.stdout.log")
    assert one.status_code == 200
    assert one.content == b"hello stdout\n"
    traversal = client.get(f"/api/v1/tasks/{task['id']}/logs/../scan_worker.stdout.log")
    assert traversal.status_code == 404
    logs_zip = client.get(f"/api/v1/tasks/{task['id']}/logs?download=1")
    assert logs_zip.status_code == 200
    assert logs_zip.content[:2] == b"PK"


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
        '{"run_name":"example_resume_1","status":"completed","targets_info":[{"type":"web","details":{}}]}',
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
    run_record = json.loads(
        (workspace / "strix_runs" / run_name / "run.json").read_text(encoding="utf-8")
    )
    assert run_record["status"] == "running"
    assert run_record.get("end_time") is None


def test_refresh_report_writes_resume_instruction(client: TestClient):
    from app.services.agent_prompts import REFRESH_REPORT_INSTRUCTION

    created = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    ).json()
    manager = client.app.state.manager
    task = manager.get_task(created["id"])
    workspace = Path(task["workspace"])
    run_name = "example_refresh_1"
    state_dir = workspace / "strix_runs" / run_name / ".state"
    state_dir.mkdir(parents=True)
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    (workspace / "strix_runs" / run_name / "run.json").write_text(
        '{"run_name":"example_refresh_1","status":"completed","targets_info":[{"type":"web","details":{}}]}',
        encoding="utf-8",
    )
    manager.db.update_task(
        created["id"],
        status="completed",
        finished_at="2026-01-01T00:00:00Z",
        run_name=run_name,
    )
    manager._processes.pop(created["id"], None)

    refreshed = client.post(f"/api/v1/tasks/{created['id']}/refresh-report")
    assert refreshed.status_code == 202, refreshed.text
    body = refreshed.json()
    assert body["action"] == "resume"
    assert body["status"] == "queued"
    note = workspace / ".web_resume_instruction"
    assert note.is_file()
    assert "更新报告" in note.read_text(encoding="utf-8")
    assert "finish_scan" in note.read_text(encoding="utf-8")
    assert "screenshots" in note.read_text(encoding="utf-8")
    assert REFRESH_REPORT_INSTRUCTION.strip() in note.read_text(encoding="utf-8")


def test_retest_queues_behind_existing_waiting_tasks(client: TestClient):
    """Retest must not cut the line via the original created_at timestamp."""
    manager = client.app.state.manager

    waiting = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com/wait", "scan_mode": "quick"},
    ).json()
    assert waiting["status"] == "queued"

    old = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com/old", "scan_mode": "quick"},
    ).json()
    task = manager.get_task(old["id"])
    workspace = Path(task["workspace"])
    run_name = "old_retest_queue"
    state_dir = workspace / "strix_runs" / run_name / ".state"
    state_dir.mkdir(parents=True)
    (workspace / "strix_runs" / run_name / "run.json").write_text(
        json.dumps({"run_name": run_name, "status": "completed", "targets_info": []}),
        encoding="utf-8",
    )
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    # Simulate an older finished task (created earlier than ``waiting``).
    manager.db.update_task(
        old["id"],
        status="completed",
        finished_at="2026-01-01T00:00:00Z",
        run_name=run_name,
        created_at="2020-01-01T00:00:00Z",
        updated_at="2020-01-01T00:00:00Z",
    )
    manager._processes.pop(old["id"], None)

    retest = client.post(f"/api/v1/tasks/{old['id']}/retest")
    assert retest.status_code == 202, retest.text
    assert retest.json()["status"] == "queued"
    assert retest.json()["action"] == "retest"

    first = manager.db.claim_next_queued()
    assert first is not None
    assert first["id"] == waiting["id"], "waiting task must stay ahead of retest"

    second = manager.db.claim_next_queued()
    assert second is not None
    assert second["id"] == old["id"]


def test_retest_embeds_mandatory_instruction(client: TestClient):
    from app.services.agent_prompts import RETEST_INSTRUCTION

    created = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
            "instruction": "原始指令",
        },
    ).json()
    manager = client.app.state.manager
    task = manager.get_task(created["id"])
    workspace = Path(task["workspace"])
    run_name = "retest_resume_1"
    state_dir = workspace / "strix_runs" / run_name / ".state"
    state_dir.mkdir(parents=True)
    (workspace / "strix_runs" / run_name / "run.json").write_text(
        json.dumps(
            {
                "run_name": run_name,
                "status": "completed",
                "targets_info": [{"type": "web", "details": {}}],
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    manager.db.update_task(
        created["id"],
        status="completed",
        finished_at="2026-01-01T00:00:00Z",
        run_name=run_name,
    )
    manager._processes.pop(created["id"], None)

    retried = client.post(f"/api/v1/tasks/{created['id']}/retest")
    assert retried.status_code == 202, retried.text
    body = retried.json()
    assert body["id"] == created["id"]
    assert body["action"] == "retest"
    assert body["status"] == "queued"
    assert body["run_name"] == run_name
    note = workspace / ".web_resume_instruction"
    assert note.is_file()
    note_text = note.read_text(encoding="utf-8")
    assert RETEST_INSTRUCTION.strip() in note_text
    assert "retest_status" in note_text
    assert "screenshots" in note_text
    # Original scan instruction stays on the task; resume nudge is separate.
    assert "原始指令" not in note_text

    manager.db.update_task(
        created["id"],
        status="completed",
        finished_at="2026-01-01T00:00:00Z",
    )
    manager._processes.pop(created["id"], None)
    with_creds = client.post(
        f"/api/v1/tasks/{created['id']}/retest",
        json={"instruction": "新密码是 Secret123!\nCookie: session=abc"},
    )
    assert with_creds.status_code == 202, with_creds.text
    assert with_creds.json()["id"] == created["id"]
    note2 = (workspace / ".web_resume_instruction").read_text(encoding="utf-8")
    assert "新密码是 Secret123!" in note2
    assert "[附加说明]" in note2
    assert RETEST_INSTRUCTION.strip() in note2


def _seed_completed_task_with_vulns(client: TestClient) -> tuple[dict, Path]:
    created = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com",
            "scan_mode": "quick",
        },
    ).json()
    manager = client.app.state.manager
    task = manager.get_task(created["id"])
    run_name = "finding-flags"
    run_dir = Path(task["workspace"]) / "strix_runs" / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": run_name,
                "status": "completed",
                "scan_results": {
                    "executive_summary": "摘要",
                    "methodology": "方法",
                    "technical_analysis": "分析",
                    "recommendations": "建议",
                },
            }
        ),
        encoding="utf-8",
    )
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "v-keep",
                    "title": "Keep Me",
                    "severity": "high",
                    "description": "real",
                    "target": "https://example.com",
                    "poc_description": "open /vuln",
                    "evidence": "HTTP 200 with reflected payload",
                    "retest_status": "not_fixed",
                },
                {
                    "id": "v-drop",
                    "title": "Drop Me",
                    "severity": "medium",
                    "description": "noise",
                    "target": "https://example.com",
                },
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities").mkdir(exist_ok=True)
    (run_dir / "vulnerabilities" / "v-keep.md").write_text("# Keep Me\n", encoding="utf-8")
    (run_dir / "vulnerabilities" / "v-drop.md").write_text("# Drop Me\n", encoding="utf-8")
    manager.db.update_task(
        created["id"],
        status="completed",
        run_name=run_name,
        finished_at="2026-01-01T00:00:00Z",
    )
    manager._processes.pop(created["id"], None)
    return manager.get_task(created["id"]), run_dir


def test_mark_finding_invalid_hides_from_report_and_retest(client: TestClient):
    created, _run_dir = _seed_completed_task_with_vulns(client)
    task_id = created["id"]

    findings = client.get(f"/api/v1/tasks/{task_id}/results").json()["findings"]
    assert {f["id"] for f in findings} == {"v-keep", "v-drop"}
    assert all(f["review_status"] == "active" for f in findings)

    patched = client.patch(
        f"/api/v1/tasks/{task_id}/findings/v-drop",
        json={"review_status": "invalid"},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["review_status"] == "invalid"
    assert patched.json()["request_test"] is False

    findings2 = client.get(f"/api/v1/tasks/{task_id}/results").json()["findings"]
    by_id = {f["id"]: f for f in findings2}
    assert by_id["v-drop"]["review_status"] == "invalid"
    assert by_id["v-keep"]["review_status"] == "active"

    report = client.get(f"/api/v1/tasks/{task_id}/report").json()["content"]
    assert "Keep Me" in report
    assert "Drop Me" not in report

    retest = client.post(f"/api/v1/tasks/{task_id}/retest")
    assert retest.status_code == 202, retest.text
    body = retest.json()
    assert body["id"] == task_id
    assert body["action"] == "retest"
    note = (
        Path(created["workspace"]) / ".web_resume_instruction"
    ).read_text(encoding="utf-8")
    assert "Drop Me" in note
    assert "跳过" in note or "无效" in note
    assert "Keep Me" not in note or "retest_status" in note
    # Same run — no prior_findings child seed.
    assert not (Path(created["workspace"]) / "prior_findings").exists()


def test_request_finding_test_creates_focused_retest(client: TestClient):
    created, _run_dir = _seed_completed_task_with_vulns(client)
    task_id = created["id"]

    res = client.post(f"/api/v1/tasks/{task_id}/findings/v-keep/test")
    assert res.status_code == 202, res.text
    body = res.json()
    assert body["finding"]["id"] == "v-keep"
    assert body["task"]["id"] == task_id
    assert body["task"]["action"] == "retest"
    note = (
        Path(created["workspace"]) / ".web_resume_instruction"
    ).read_text(encoding="utf-8")
    assert "指定漏洞复测" in note
    assert "Keep Me" in note
    assert "v-keep" in note
    assert "Drop Me" not in note
    assert "open /vuln" not in note


def test_retest_respects_request_test_queue(client: TestClient):
    created, _run_dir = _seed_completed_task_with_vulns(client)
    task_id = created["id"]

    queued = client.patch(
        f"/api/v1/tasks/{task_id}/findings/v-keep",
        json={"request_test": True},
    )
    assert queued.status_code == 200, queued.text
    assert queued.json()["request_test"] is True

    retest = client.post(f"/api/v1/tasks/{task_id}/retest")
    assert retest.status_code == 202, retest.text
    assert retest.json()["id"] == task_id
    note = (
        Path(created["workspace"]) / ".web_resume_instruction"
    ).read_text(encoding="utf-8")
    assert "指定漏洞复测" in note
    assert "Keep Me" in note
    assert "Drop Me" not in note

    flags = client.app.state.manager.db.list_finding_flags(task_id)
    assert flags["v-keep"]["request_test"] is False


def test_resolve_retest_reports_prefers_disk_over_db_shaped_findings(tmp_path: Path):
    """Imported / pre-DB runs only have vulnerabilities.json — that must win."""
    from app.services.results import resolve_retest_reports, write_prior_findings

    run_dir = tmp_path / "parent_run"
    run_dir.mkdir()
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "v-disk",
                    "title": "From Disk",
                    "severity": "high",
                    "description": "full body",
                    "timestamp": "2026-03-01 00:00:00 UTC",
                    "poc_description": "steps",
                }
            ]
        ),
        encoding="utf-8",
    )
    # DB-shaped finding: no raw, thin fields — must not override disk.
    findings = [
        {
            "id": "v-disk",
            "title": "From Disk",
            "severity": "high",
            "description": "thin",
            "created_at": "2026-01-01T00:00:00Z",
        }
    ]
    reports = resolve_retest_reports(
        parent_run_dir=run_dir,
        findings=findings,
        include_ids=None,
        skipped_invalid=set(),
    )
    assert len(reports) == 1
    assert reports[0]["description"] == "full body"
    assert reports[0]["timestamp"] == "2026-03-01 00:00:00 UTC"
    assert reports[0].get("poc_description") == "steps"

    child = tmp_path / "child"
    child.mkdir()
    write_prior_findings(
        child, findings=findings, parent_run_dir=run_dir, reports=reports
    )
    seeded = json.loads(
        (child / "prior_findings" / "vulnerabilities.json").read_text(encoding="utf-8")
    )
    assert seeded[0]["description"] == "full body"


def test_apply_prior_findings_seeds_run_dir(tmp_path: Path):
    from app.services.results import apply_prior_findings, write_prior_findings

    parent_run = tmp_path / "parent_run"
    (parent_run / "vulnerabilities").mkdir(parents=True)
    (parent_run / "images").mkdir()
    (parent_run / "vulnerabilities" / "v1.md").write_text("# v1\n", encoding="utf-8")
    (parent_run / "images" / "shot.png").write_bytes(b"png")
    findings = [
        {
            "id": "v1",
            "title": "XSS",
            "severity": "high",
            "description": "reflected",
            "created_at": "2026-01-01T00:00:00Z",
            "raw": {
                "id": "v1",
                "title": "XSS",
                "severity": "high",
                "description": "reflected",
                "retest_status": "partial",
                "fix_verification": "old",
            },
        }
    ]
    workspace = tmp_path / "child"
    workspace.mkdir()
    write_prior_findings(workspace, findings=findings, parent_run_dir=parent_run)
    run_dir = workspace / "strix_runs" / "fresh"
    assert apply_prior_findings(workspace, run_dir) is True
    seeded = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert seeded[0]["id"] == "v1"
    assert seeded[0]["timestamp"] == "2026-01-01T00:00:00Z"
    assert "retest_status" not in seeded[0]
    assert "fix_verification" not in seeded[0]
    assert (run_dir / "vulnerabilities" / "v1.md").is_file()
    assert (run_dir / "images" / "shot.png").is_file()

    # DB-shaped finding (no raw) must still produce a writable report.
    from app.services.results import _raw_retest_report

    db_shaped = _raw_retest_report(
        {
            "id": "v2",
            "title": "CSRF",
            "severity": "medium",
            "description": "no token",
            "created_at": "2026-02-01T00:00:00Z",
        }
    )
    assert db_shaped["timestamp"] == "2026-02-01T00:00:00Z"
    from strix.report.writer import write_vulnerabilities

    write_vulnerabilities(run_dir, [db_shaped], set())


def test_reap_skips_until_worker_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from app.services.scan_state import write_state
    from app.services.strix_runner import DetachedScanHandle

    workspace = tmp_path / "task"
    run_dir = workspace / "strix_runs" / "run_a"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        '{"status":"completed","run_name":"run_a"}',
        encoding="utf-8",
    )
    write_state(workspace, pid=12345, ready=False, run_name="run_a", exit_code=None)
    handle = DetachedScanHandle(workspace, "task_x")
    monkeypatch.setattr("app.services.scan_state.pid_alive", lambda _pid: True)
    assert handle._reap_finished_interactive() is None

    write_state(workspace, ready=True)
    assert handle._reap_finished_interactive() == 0
    assert handle._state().get("exit_code") == 0


def test_web_scan_exit_requires_report_and_root():
    from types import SimpleNamespace

    from app.services.strix_runner import _web_scan_should_exit

    report = SimpleNamespace(run_record={"status": "completed"})
    coordinator = SimpleNamespace(
        parent_of={"root": None},
        statuses={"root": "completed"},
    )
    assert _web_scan_should_exit(report, coordinator) is True

    report.run_record["status"] = "running"
    assert _web_scan_should_exit(report, coordinator) is False

    report.run_record["status"] = "completed"
    coordinator.statuses["root"] = "running"
    assert _web_scan_should_exit(report, coordinator) is False


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
