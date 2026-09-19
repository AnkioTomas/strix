"""Feishu webhook notifier (web-side, no Strix core hooks)."""

from __future__ import annotations

import json
import urllib.request
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
    with patch.object(feishu, "post_card") as post:
        assert feishu.notify(settings, "started", {"id": "t1", "name": "x"}) is False
        post.assert_not_called()


def test_notify_respects_event_filter():
    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_FEISHU_WEBHOOK="https://example.com/hook",
        STRIX_FEISHU_EVENTS="finished,failed",
    )
    db = MagicMock()
    with patch.object(feishu, "post_card", return_value=True) as post:
        assert feishu.notify_task(settings, db, "started", {"id": "t1"}) is False
        post.assert_not_called()
        assert (
            feishu.notify_task(settings, db, "failed", {"id": "t1", "error": "boom"})
            is True
        )
        post.assert_called_once()
        card = post.call_args.args[1]
        assert card["header"]["template"] == "red"
        assert "扫描失败" in card["header"]["title"]["content"]
        body = json.dumps(card, ensure_ascii=False)
        assert "boom" in body
        db.update_task.assert_called_once()


def test_build_card_structure():
    card = feishu.build_card(
        "started",
        {
            "id": "task_demo",
            "name": "DVWA 深扫",
            "target": "https://dvwa.example.com",
            "run_name": "demo_run",
            "scan_mode": "deep",
            "type": "pentest",
        },
        console_url="http://127.0.0.1:8787/",
    )
    assert card["header"]["template"] == "blue"
    assert card["header"]["title"]["content"] == "Strix · 扫描开始"
    dumped = json.dumps(card, ensure_ascii=False)
    assert "DVWA 深扫" in dumped
    assert "打开控制台" in dumped
    assert "http://127.0.0.1:8787/" in dumped


def test_build_card_finished_includes_findings():
    card = feishu.build_card(
        "finished",
        {"id": "t1", "name": "ok"},
        findings=[
            {"title": "SQL Injection", "severity": "critical"},
            {"title": "XSS Reflect", "severity": "medium"},
        ],
    )
    body = json.dumps(card, ensure_ascii=False)
    assert "漏洞 (2)" in body
    assert "严重 · SQL Injection" in body
    assert "中危 · XSS Reflect" in body


def test_build_card_finished_empty_findings():
    card = feishu.build_card("finished", {"id": "t1", "name": "clean"}, findings=[])
    body = json.dumps(card, ensure_ascii=False)
    assert "漏洞 (0)" in body
    assert "无" in body


def test_format_findings_lines_truncates():
    items = [{"title": f"v{i}", "severity": "low"} for i in range(25)]
    text = feishu.format_findings_lines(items, limit=3)
    assert text.count("•") == 3
    assert "另有 22 项" in text


def test_notify_finished_loads_findings_from_workspace(tmp_path: Path):
    run_dir = tmp_path / "strix_runs" / "run_a"
    run_dir.mkdir(parents=True)
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {"id": "v1", "title": "RCE", "severity": "high"},
                {"id": "v2", "title": "Info Leak", "severity": "low"},
            ]
        ),
        encoding="utf-8",
    )
    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_FEISHU_WEBHOOK="https://example.com/hook",
        STRIX_FEISHU_EVENTS="finished",
    )
    task = {
        "id": "task_x",
        "name": "demo",
        "workspace": str(tmp_path),
        "run_name": "run_a",
    }
    with patch.object(feishu, "post_card", return_value=True) as post:
        assert feishu.notify(settings, "finished", task) is True
        card = post.call_args.args[1]
        body = json.dumps(card, ensure_ascii=False)
        assert "漏洞 (2)" in body
        assert "高危 · RCE" in body
        assert "低危 · Info Leak" in body


def test_post_card_uses_configured_proxy():
    seen: dict[str, object] = {}

    class _FakeOpener:
        def open(self, req: object, timeout: float = 0) -> object:
            seen["timeout"] = timeout
            seen["url"] = getattr(req, "full_url", None) or req.get_full_url()  # type: ignore[attr-defined]

            class _Resp:
                def read(self) -> bytes:
                    return b'{"code":0}'

                def __enter__(self) -> _Resp:
                    return self

                def __exit__(self, *args: object) -> None:
                    return None

            return _Resp()

    def fake_build_opener(*handlers: object) -> _FakeOpener:
        seen["handlers"] = handlers
        return _FakeOpener()

    card = feishu.build_card("finished", {"id": "t1", "name": "ok"})
    with patch("urllib.request.build_opener", side_effect=fake_build_opener):
        assert (
            feishu.post_card(
                "https://open.feishu.cn/hook",
                card,
                proxy="http://127.0.0.1:7890",
            )
            is True
        )
    handlers = seen["handlers"]
    assert handlers
    proxy_handler = handlers[0]
    assert isinstance(proxy_handler, urllib.request.ProxyHandler)
    assert proxy_handler.proxies.get("https") == "http://127.0.0.1:7890"


def test_notify_passes_feishu_proxy():
    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_FEISHU_WEBHOOK="https://example.com/hook",
        STRIX_FEISHU_PROXY="http://127.0.0.1:7890",
    )
    with patch.object(feishu, "post_card", return_value=True) as post:
        assert feishu.notify(settings, "started", {"id": "t1", "name": "x"}) is True
        assert post.call_args.kwargs.get("proxy") == "http://127.0.0.1:7890"


def test_needs_user_fingerprint(tmp_path: Path):
    path = tmp_path / "agents.json"
    path.write_text(
        json.dumps({"wait_kinds": {"root": "user", "child": "agents", "a2": "user"}}),
        encoding="utf-8",
    )
    assert feishu.needs_user_fingerprint(path) == "a2,root"
    path.write_text(json.dumps({"wait_kinds": {"root": "agents"}}), encoding="utf-8")
    assert feishu.needs_user_fingerprint(path) is None


def test_question_from_session_items_uses_respond_message():
    items = [
        {"role": "assistant", "content": "thinking out loud"},
        {
            "type": "function_call",
            "name": "respond_to_user",
            "arguments": json.dumps({"message": "请提供管理员账号密码"}),
        },
    ]
    assert feishu.question_from_session_items(items) == "请提供管理员账号密码"


def test_question_from_session_items_falls_back_to_assistant_when_empty():
    items = [
        {"role": "assistant", "content": "我需要目标的登录凭据才能继续。"},
        {
            "type": "function_call",
            "name": "respond_to_user",
            "arguments": "{}",
        },
    ]
    assert (
        feishu.question_from_session_items(items) == "我需要目标的登录凭据才能继续。"
    )


def test_build_card_needs_user_includes_question():
    card = feishu.build_card(
        "needs_user",
        {"id": "t1", "name": "wait"},
        detail="等待 Agent: root",
        questions=[
            {
                "agent_id": "root",
                "question": "请确认是否允许对 /admin 做暴力破解？",
            }
        ],
    )
    body = json.dumps(card, ensure_ascii=False)
    assert "AI 问题" in body
    assert "请确认是否允许对 /admin 做暴力破解？" in body
    assert "等待 Agent: root" in body


def test_notify_needs_user_loads_question_from_agents_db(tmp_path: Path):
    import sqlite3

    run_dir = tmp_path / "strix_runs" / "run_wait"
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    (state_dir / "agents.json").write_text(
        json.dumps({"wait_kinds": {"root": "user"}, "statuses": {"root": "waiting"}}),
        encoding="utf-8",
    )
    conn = sqlite3.connect(state_dir / "agents.db")
    try:
        conn.execute(
            "create table agent_messages (id integer primary key, session_id text, "
            "message_data text, created_at text)"
        )
        conn.execute(
            "insert into agent_messages (id, session_id, message_data, created_at) "
            "values (1, ?, ?, ?)",
            (
                "root",
                json.dumps(
                    {
                        "type": "function_call",
                        "name": "respond_to_user",
                        "arguments": json.dumps(
                            {"message": "目标需要登录，请提供测试账号。"}
                        ),
                    }
                ),
                "2026-01-01T00:00:01+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    settings = Settings(
        STRIX_API_AUTH_DISABLED=True,
        STRIX_FEISHU_WEBHOOK="https://example.com/hook",
        STRIX_FEISHU_EVENTS="needs_user",
    )
    task = {
        "id": "task_wait",
        "name": "wait-me",
        "workspace": str(tmp_path),
        "run_name": "run_wait",
    }
    with patch.object(feishu, "post_card", return_value=True) as post:
        assert (
            feishu.notify(
                settings,
                "needs_user",
                task,
                detail="等待 Agent: root",
                fingerprint="root",
            )
            is True
        )
        body = json.dumps(post.call_args.args[1], ensure_ascii=False)
        assert "目标需要登录，请提供测试账号。" in body


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

    cards: list[dict] = []

    def capture(_url: str, card: dict, **_kwargs: object) -> bool:
        cards.append(card)
        return True

    with patch.object(feishu, "post_card", side_effect=capture):
        task = manager.get_task(task_id)
        assert feishu.notify_task(manager.settings, manager.db, "started", task) is True
        task2 = manager.get_task(task_id)
        assert task2.get("feishu_notify")
        assert feishu.notify_task(manager.settings, manager.db, "started", task2) is False

        manager.db.update_task(task_id, status="failed", error="boom")
        failed = manager.get_task(task_id)
        assert feishu.notify_status(manager.settings, manager.db, failed, "failed") is True
        failed2 = manager.get_task(task_id)
        assert feishu.notify_status(manager.settings, manager.db, failed2, "failed") is False

    assert len(cards) == 2
    assert cards[0]["header"]["template"] == "blue"
    assert cards[1]["header"]["template"] == "red"


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

    cards: list[dict] = []

    def capture(_url: str, card: dict, **_kwargs: object) -> bool:
        cards.append(card)
        return True

    with patch.object(feishu, "post_card", side_effect=capture):
        pool = WorkerPool(manager)
        pool.manager._processes[task_id] = MagicMock()
        pool._poll_needs_user()
        assert len(cards) == 1
        assert cards[0]["header"]["template"] == "purple"

        pool2 = WorkerPool(manager)
        pool2.manager._processes[task_id] = MagicMock()
        pool2._poll_needs_user()
        assert len(cards) == 1

        agents.write_text(json.dumps({"wait_kinds": {}}), encoding="utf-8")
        pool2._poll_needs_user()
        agents.write_text(json.dumps({"wait_kinds": {"root": "user"}}), encoding="utf-8")
        pool2._poll_needs_user()
        assert len(cards) == 2
