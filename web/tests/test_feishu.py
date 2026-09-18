"""Feishu webhook notifier (web-side, no Strix core hooks)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.services import feishu
from app.workers.pool import WorkerPool


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(data_dir))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.setenv("STRIX_MAX_CONCURRENT", "1")
    monkeypatch.delenv("STRIX_FEISHU_WEBHOOK", raising=False)
    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_notify_noop_without_webhook():
    settings = Settings(STRIX_API_AUTH_DISABLED=True, STRIX_FEISHU_WEBHOOK="")
    with patch.object(feishu, "post_text") as post:
        assert feishu.notify(settings, "started", {"id": "t1", "name": "x"}) is False
        post.assert_not_called()


def test_notify_respects_event_filter():
    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_FEISHU_WEBHOOK="https://example.com/hook",
        STRIX_FEISHU_EVENTS="finished,failed",
    )
    db = MagicMock()
    with patch.object(feishu, "post_text", return_value=True) as post:
        assert feishu.notify_task(settings, db, "started", {"id": "t1"}) is False
        post.assert_not_called()
        assert (
            feishu.notify_task(settings, db, "failed", {"id": "t1", "error": "boom"})
            is True
        )
        post.assert_called_once()
        text = post.call_args.args[1]
        assert "扫描失败" in text
        assert "boom" in text
        db.update_task.assert_called_once()


def test_post_text_sends_feishu_body():
    captured: dict[str, object] = {}

    class _Resp:
        def read(self) -> bytes:
            return b'{"code":0}'

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(req: object, timeout: float = 0) -> _Resp:
        captured["url"] = getattr(req, "full_url", None) or getattr(req, "get_full_url")()
        captured["body"] = req.data  # type: ignore[attr-defined]
        captured["timeout"] = timeout
        return _Resp()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        assert feishu.post_text("https://open.feishu.cn/hook", "hello") is True
    payload = json.loads(captured["body"])  # type: ignore[arg-type]
    assert payload == {"msg_type": "text", "content": {"text": "hello"}}


def test_needs_user_fingerprint(tmp_path: Path):
    path = tmp_path / "agents.json"
    path.write_text(
        json.dumps({"wait_kinds": {"root": "user", "child": "agents", "a2": "user"}}),
        encoding="utf-8",
    )
    assert feishu.needs_user_fingerprint(path) == "a2,root"
    path.write_text(json.dumps({"wait_kinds": {"root": "agents"}}), encoding="utf-8")
    assert feishu.needs_user_fingerprint(path) is None


def test_notify_task_dedupes_across_restart(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("STRIX_FEISHU_WEBHOOK", "https://example.com/hook")
    get_settings.cache_clear()
    manager = client.app.state.manager
    manager.settings = get_settings()

    created = client.post(
        "/api/v1/tasks",
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    ).json()
    task_id = created["id"]
    manager.db.update_task(task_id, status="running", run_name="run_a")

    posts: list[str] = []

    def capture(_url: str, text: str, **_kwargs: object) -> bool:
        posts.append(text)
        return True

    with patch.object(feishu, "post_text", side_effect=capture):
        task = manager.get_task(task_id)
        assert feishu.notify_task(manager.settings, manager.db, "started", task) is True
        # Simulate web restart: reload row from DB, memory gone.
        task2 = manager.get_task(task_id)
        assert task2.get("feishu_notify")
        assert feishu.notify_task(manager.settings, manager.db, "started", task2) is False

        manager.db.update_task(task_id, status="failed", error="boom")
        failed = manager.get_task(task_id)
        assert feishu.notify_status(manager.settings, manager.db, failed, "failed") is True
        failed2 = manager.get_task(task_id)
        assert feishu.notify_status(manager.settings, manager.db, failed2, "failed") is False

    assert len(posts) == 2
    assert "扫描开始" in posts[0]
    assert "扫描失败" in posts[1]


def test_pool_needs_user_survives_restart(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("STRIX_FEISHU_WEBHOOK", "https://example.com/hook")
    get_settings.cache_clear()
    manager = client.app.state.manager
    manager.settings = get_settings()

    created = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": "https://example.com/wait",
            "scan_mode": "quick",
            "name": "wait-me",
        },
    ).json()
    task_id = created["id"]
    workspace = Path(manager.get_task(task_id)["workspace"])
    run_name = "feishu_wait_run"
    state_dir = workspace / "strix_runs" / run_name / ".state"
    state_dir.mkdir(parents=True)
    agents = state_dir / "agents.json"
    agents.write_text(json.dumps({"wait_kinds": {"root": "user"}}), encoding="utf-8")
    manager.db.update_task(task_id, status="running", run_name=run_name)

    posts: list[str] = []

    def capture(_url: str, text: str, **_kwargs: object) -> bool:
        posts.append(text)
        return True

    with patch.object(feishu, "post_text", side_effect=capture):
        pool = WorkerPool(manager)
        pool.manager._processes[task_id] = MagicMock()
        pool._poll_needs_user()
        assert len(posts) == 1

        # New pool instance = web restart; DB still has fingerprint.
        pool2 = WorkerPool(manager)
        pool2.manager._processes[task_id] = MagicMock()
        pool2._poll_needs_user()
        assert len(posts) == 1

        agents.write_text(json.dumps({"wait_kinds": {}}), encoding="utf-8")
        pool2._poll_needs_user()
        agents.write_text(json.dumps({"wait_kinds": {"root": "user"}}), encoding="utf-8")
        pool2._poll_needs_user()
        assert len(posts) == 2
