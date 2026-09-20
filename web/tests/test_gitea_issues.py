"""Gitea issue sync for completed audit (git) tasks — web-side only."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from app.config import Settings, get_settings
from app.schemas import CreateTaskRequest, GitSource
from app.services import gitea_issues
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(data_dir))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.setenv("STRIX_MAX_CONCURRENT", "1")
    monkeypatch.setenv("STRIX_GIT_USERNAME", "bot")
    monkeypatch.setenv("STRIX_GIT_TOKEN", "s3cret")
    monkeypatch.setenv("STRIX_GITEA_ISSUES", "1")
    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_parse_repo_url():
    parsed = gitea_issues.parse_repo_url("https://gitea.example.com/org/repo.git")
    assert parsed == {
        "base": "https://gitea.example.com",
        "owner": "org",
        "repo": "repo",
    }
    nested = gitea_issues.parse_repo_url("https://git.example/a/b/c.git")
    assert nested == {"base": "https://git.example", "owner": "a/b", "repo": "c"}
    assert gitea_issues.parse_repo_url("not-a-url") is None


def test_should_sync_gates():
    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_GIT_USERNAME="bot",
        STRIX_GIT_TOKEN="tok",
        STRIX_GITEA_ISSUES=True,
    )
    task = {
        "type": "audit",
        "source_type": "git",
        "source_url": "https://gitea.example.com/org/repo.git",
    }
    assert gitea_issues.should_sync(settings, task) is True
    assert gitea_issues.should_sync(settings, {**task, "type": "pentest"}) is False
    assert gitea_issues.should_sync(settings, {**task, "source_type": "local"}) is False
    off = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_GIT_USERNAME="bot",
        STRIX_GIT_TOKEN="tok",
        STRIX_GITEA_ISSUES=False,
    )
    assert gitea_issues.should_sync(off, task) is False


def test_format_issue_contains_marker_and_severity():
    finding = {
        "id": "vuln-0001",
        "title": "SQL Injection",
        "severity": "high",
        "description": "注入点在 /login",
        "asset": "https://app.example",
        "location": {"file": "app.py", "line": 42},
        "poc": "curl ...",
        "recommendation": "参数化查询",
    }
    title = gitea_issues.format_issue_title(finding)
    assert title.startswith("[Strix:vuln-0001] [高危] ")
    assert "SQL Injection" in title
    body = gitea_issues.format_issue_body(finding, task={"id": "t1", "name": "审计"})
    assert "<!-- strix-finding:vuln-0001 -->" in body
    assert "app.py:42" in body
    assert "参数化查询" in body


def test_sync_creates_and_dedupes(tmp_path: Path):
    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_GIT_USERNAME="bot",
        STRIX_GIT_TOKEN="tok",
        STRIX_GITEA_ISSUES=True,
    )
    workspace = tmp_path / "ws"
    workspace.mkdir()
    task = {
        "id": "task1",
        "type": "audit",
        "source_type": "git",
        "source_url": "https://gitea.example.com/org/repo.git",
        "workspace": str(workspace),
        "name": "客户仓",
    }
    findings = [
        {
            "id": "v1",
            "title": "XSS",
            "severity": "medium",
            "description": "reflect",
        }
    ]
    calls: list[tuple[str, str]] = []

    def fake_api(method, url, *, auth, payload=None, query=None):  # noqa: ARG001
        calls.append((method, url))
        if method == "GET":
            return []
        assert method == "POST"
        assert payload is not None
        assert "[Strix:v1]" in payload["title"]
        assert "<!-- strix-finding:v1 -->" in payload["body"]
        return {
            "number": 7,
            "html_url": "https://gitea.example.com/org/repo/issues/7",
            "title": payload["title"],
        }

    with patch.object(gitea_issues, "api_request", side_effect=fake_api):
        first = gitea_issues.sync_findings_as_issues(settings, task, findings)
        second = gitea_issues.sync_findings_as_issues(settings, task, findings)

    assert first["enabled"] is True
    assert first["created"] == 1
    assert first["errors"] == 0
    assert first["issues"]["v1"]["number"] == 7
    assert second["created"] == 0
    assert second["skipped"] >= 1
    # Second pass must not POST again.
    assert sum(1 for method, _ in calls if method == "POST") == 1
    state = json.loads((workspace / "gitea_issues.json").read_text(encoding="utf-8"))
    assert state["issues"]["v1"]["number"] == 7


def test_sync_reuses_remote_existing(tmp_path: Path):
    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_GIT_USERNAME="bot",
        STRIX_GIT_TOKEN="tok",
        STRIX_GITEA_ISSUES=True,
    )
    workspace = tmp_path / "ws"
    workspace.mkdir()
    task = {
        "id": "task1",
        "type": "audit",
        "source_type": "git",
        "source_url": "https://gitea.example.com/org/repo.git",
        "workspace": str(workspace),
    }
    findings = [{"id": "v9", "title": "RCE", "severity": "critical"}]

    def fake_api(method, url, *, auth, payload=None, query=None):  # noqa: ARG001
        if method == "GET":
            return [
                {
                    "number": 3,
                    "html_url": "https://gitea.example.com/org/repo/issues/3",
                    "title": "[Strix:v9] [严重] RCE",
                    "body": "<!-- strix-finding:v9 -->\n",
                }
            ]
        raise AssertionError("must not create when remote exists")

    with patch.object(gitea_issues, "api_request", side_effect=fake_api):
        result = gitea_issues.sync_findings_as_issues(settings, task, findings)

    assert result["created"] == 0
    assert result["issues"]["v9"]["number"] == 3


def test_ingest_completed_audit_triggers_gitea_sync(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        "app.security.source.socket.getaddrinfo",
        lambda *_a, **_k: [(0, 0, 0, "", ("1.2.3.4", 443))],
    )
    manager = client.app.state.manager
    task = manager.create_task(
        CreateTaskRequest(
            type="audit",
            source=GitSource(url="https://gitea.example.com/org/repo.git"),
            scan_mode="quick",
            name="Gitea审计",
        )
    )

    run_name = "audit-run"
    run_dir = Path(task["workspace"]) / "strix_runs" / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"run_name": run_name, "status": "completed"}),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "vuln-1",
                    "title": "Path Traversal",
                    "severity": "high",
                    "description": "read /etc/passwd",
                    "target": "repo",
                    "timestamp": "2026-01-01T00:00:00Z",
                }
            ]
        ),
        encoding="utf-8",
    )
    manager.db.update_task(task["id"], run_name=run_name, status="completed")

    with patch.object(gitea_issues, "sync_findings_as_issues", return_value={"created": 1}) as sync:
        manager.ingest_results(manager.get_task(task["id"]))
        sync.assert_called_once()
        args = sync.call_args
        assert args.args[1]["id"] == task["id"]
        assert args.args[2][0]["id"] == "vuln-1"
