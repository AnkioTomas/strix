"""Gitea issue sync for audit findings."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx
import pytest
from app.config import Settings
from app.db import Database
from app.services import gitea_issues
from app.services.gitea_issues import (
    GiteaError,
    close_invalid_issue,
    close_issue_as_invalid,
    create_issue,
    repo_from_source_url,
    sync_open_issues,
)


if TYPE_CHECKING:
    from pathlib import Path


class _Resp:
    def __init__(
        self,
        status_code: int,
        payload: dict[str, Any] | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or str(payload or "")

    def json(self) -> dict[str, Any]:
        return self._payload


def _settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    hosts: str = "gitea.example.com",
    username: str = "bot",
    token: str = "s3cret",  # noqa: S107
) -> Settings:
    monkeypatch.setenv("STRIX_GIT_HOSTS", hosts)
    monkeypatch.setenv("STRIX_GIT_USERNAME", username)
    monkeypatch.setenv("STRIX_GIT_TOKEN", token)
    return Settings()


def _task(**overrides: object) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "task_audit",
        "type": "audit",
        "source_type": "git",
        "source_url": "https://gitea.example.com/org/repo.git",
    }
    row.update(overrides)
    return row


def _db_with_task(tmp_path: Path, task: dict[str, Any] | None = None) -> Database:
    db = Database(tmp_path / "db.sqlite")
    row = task or _task()
    db.insert_task(
        {
            "id": row["id"],
            "type": row["type"],
            "status": "completed",
            "target": row.get("source_url"),
            "source_type": row.get("source_type"),
            "source_url": row.get("source_url"),
            "workspace": str(tmp_path / "ws"),
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    return db


def test_parse_repo_from_https_url(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    repo = repo_from_source_url("https://gitea.example.com/org/repo.git", settings)
    assert repo is not None
    assert repo.api_base == "https://gitea.example.com/api/v1"
    assert repo.owner == "org"
    assert repo.repo == "repo"


def test_parse_repo_rejects_host_outside_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    assert repo_from_source_url("https://github.com/org/repo.git", settings) is None


def test_create_issue_posts_title_and_returns_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(monkeypatch)
    repo = repo_from_source_url("https://gitea.example.com/org/repo.git", settings)
    assert repo is not None
    seen: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _Resp:
        seen["url"] = url
        seen["json"] = kwargs.get("json")
        seen["headers"] = kwargs.get("headers")
        return _Resp(201, {"number": 12, "html_url": "https://gitea.example.com/org/repo/issues/12"})

    monkeypatch.setattr(httpx, "post", fake_post)
    number, html_url = create_issue(repo, "s3cret", title="[HIGH] XSS", body="body")
    assert number == 12
    assert html_url.endswith("/issues/12")
    assert seen["url"].endswith("/repos/org/repo/issues")
    assert seen["json"] == {"title": "[HIGH] XSS", "body": "body"}
    assert seen["headers"]["Authorization"] == "token s3cret"


def test_close_issue_comments_then_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    repo = repo_from_source_url("https://gitea.example.com/org/repo.git", settings)
    assert repo is not None
    calls: list[tuple[str, str]] = []

    def fake_post(url: str, **_kwargs: Any) -> _Resp:
        calls.append(("POST", url))
        return _Resp(201, {})

    def fake_patch(url: str, **kwargs: Any) -> _Resp:
        calls.append(("PATCH", url))
        assert kwargs.get("json") == {"state": "closed"}
        return _Resp(200, {})

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "patch", fake_patch)
    close_issue_as_invalid(repo, "s3cret", 12)
    assert calls[0][0] == "POST"
    assert calls[0][1].endswith("/issues/12/comments")
    assert calls[1] == ("PATCH", f"{repo.api_base}/repos/org/repo/issues/12")


def test_create_issue_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    repo = repo_from_source_url("https://gitea.example.com/org/repo.git", settings)
    assert repo is not None
    monkeypatch.setattr(httpx, "post", lambda *_a, **_k: _Resp(403, text="forbidden"))
    with pytest.raises(GiteaError, match="403"):
        create_issue(repo, "s3cret", title="x", body="y")


def test_sync_opens_issue_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    db = _db_with_task(tmp_path)
    created: list[str] = []

    def fake_create(*_args: Any, **kwargs: Any) -> tuple[int, str]:
        created.append(str(kwargs.get("title")))
        return 7, "https://gitea.example.com/org/repo/issues/7"

    monkeypatch.setattr(gitea_issues, "create_issue", fake_create)
    findings = [{"id": "v1", "title": "XSS", "severity": "high", "description": "x"}]
    sync_open_issues(db, settings, _task(), findings)
    sync_open_issues(db, settings, _task(), findings)
    assert created == ["[HIGH] XSS"]
    flag = db.list_finding_flags("task_audit")["v1"]
    assert flag["issue_number"] == 7
    assert flag["issue_url"].endswith("/issues/7")


def test_sync_skips_pentest_and_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(monkeypatch)
    db = _db_with_task(tmp_path)

    def fail_create(*_args: Any, **_kwargs: Any) -> tuple[int, str]:
        raise AssertionError("must not create issue")

    monkeypatch.setattr(gitea_issues, "create_issue", fail_create)
    sync_open_issues(
        db,
        settings,
        _task(type="pentest", source_type=None, source_url=None),
        [{"id": "v1", "title": "XSS", "severity": "high"}],
    )
    db.upsert_finding_flag("task_audit", "v2", review_status="invalid")
    sync_open_issues(db, settings, _task(), [{"id": "v2", "title": "drop", "severity": "low"}])


def test_close_invalid_uses_stored_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(monkeypatch)
    db = _db_with_task(tmp_path)
    db.set_finding_issue(
        "task_audit",
        "v1",
        issue_number=9,
        issue_url="https://gitea.example.com/org/repo/issues/9",
    )
    seen: list[int] = []

    def fake_close(_repo: Any, _token: str, number: int) -> None:
        seen.append(number)

    monkeypatch.setattr(gitea_issues, "close_issue_as_invalid", fake_close)
    close_invalid_issue(db, settings, _task(), "v1")
    close_invalid_issue(db, settings, _task(), "missing")
    assert seen == [9]
