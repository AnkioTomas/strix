"""Tests for session cookie auth and viewer proxy helpers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.viewer_proxy import (
    _inject_fetch_rewrite,
    attach_viewer_proxy_url,
    parse_local_viewer,
    viewer_proxy_path,
)
from app.config import get_settings
from app.main import app
from app.schemas import CreateTaskRequest
from app.services.task_manager import TaskError


@pytest.fixture()
def auth_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "0")
    monkeypatch.setenv("STRIX_API_KEY", "test-secret")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "1")
    get_settings.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_session_cookie_auth(auth_client: TestClient):
    bare = auth_client.get("/api/v1/tasks")
    assert bare.status_code == 401

    bad = auth_client.post(
        "/api/v1/session",
        headers={"Authorization": "Bearer wrong"},
    )
    assert bad.status_code == 401

    ok = auth_client.post(
        "/api/v1/session",
        headers={"Authorization": "Bearer test-secret"},
    )
    assert ok.status_code == 204
    assert "strix_web_session=" in ok.headers.get("set-cookie", "")

    listed = auth_client.get("/api/v1/tasks")
    assert listed.status_code == 200

    cleared = auth_client.delete("/api/v1/session")
    assert cleared.status_code == 204
    # TestClient may keep cookies unless cleared; force empty cookie jar
    auth_client.cookies.clear()
    again = auth_client.get("/api/v1/tasks")
    assert again.status_code == 401


def test_parse_local_viewer_rejects_remote():
    with pytest.raises(TaskError) as exc:
        parse_local_viewer("http://evil.example:9/?token=x")
    assert exc.value.code == "VIEWER_UNSAFE"

    base, port = parse_local_viewer("http://127.0.0.1:63862/?token=abc")
    assert base == "http://127.0.0.1:63862"
    assert port == 63862


def test_inject_fetch_rewrite_contains_bootstrap():
    html = b"<html><head><title>x</title></head><body></body></html>"
    out = _inject_fetch_rewrite(html, "/api/v1/tasks/task_1/viewer")
    text = out.decode()
    assert "strix-viewer-proxy-bootstrap" in text
    assert "/api/v1/tasks/task_1/viewer" in text
    assert "window.fetch" in text
    assert "strix-viewer-proxy-chrome" in text
    assert "strix-proxy-hide" in text
    assert "Past runs" in text
    assert "Run in the cloud" in text
    assert "Run this pentest with more depth" in text
    assert "overflow: hidden" in text
    assert "zoom: 1" in text
    # Idempotent
    again = _inject_fetch_rewrite(out, "/api/v1/tasks/task_1/viewer")
    assert again.count(b"strix-viewer-proxy-bootstrap") == 1


def test_viewer_proxy_not_ready(auth_client: TestClient):
    created = auth_client.post(
        "/api/v1/tasks",
        headers={"Authorization": "Bearer test-secret"},
        json={"type": "pentest", "target": "https://example.com", "scan_mode": "quick"},
    )
    assert created.status_code == 202
    task_id = created.json()["id"]
    assert created.json().get("viewer_proxy_url") is None

    proxied = auth_client.get(
        f"/api/v1/tasks/{task_id}/viewer/",
        headers={"Authorization": "Bearer test-secret"},
    )
    assert proxied.status_code == 409
    assert proxied.json()["error"]["code"] == "VIEWER_NOT_READY"


def test_attach_viewer_proxy_url():
    bare = attach_viewer_proxy_url({"id": "task_a", "viewer_url": None, "viewer_token": None})
    assert bare["viewer_proxy_url"] is None

    ready = attach_viewer_proxy_url(
        {
            "id": "task_b",
            "viewer_url": "http://127.0.0.1:1/?token=x",
            "viewer_token": "x",
        }
    )
    assert ready["viewer_proxy_url"] == viewer_proxy_path("task_b")


def test_artifact_image_path_no_traversal(auth_client: TestClient, tmp_path: Path):
    manager = auth_client.app.state.manager
    task = manager.create_task(
        CreateTaskRequest(type="pentest", target="https://example.com", scan_mode="quick")
    )
    run_name = "art-run"
    run_dir = Path(task["workspace"]) / "strix_runs" / run_name
    images = run_dir / "images"
    images.mkdir(parents=True)
    (images / "shot.png").write_bytes(b"\x89PNG\r\n")
    (run_dir / "run.json").write_text("{}", encoding="utf-8")
    manager.db.update_task(task["id"], run_name=run_name, status="completed")

    headers = {"Authorization": "Bearer test-secret"}
    ok = auth_client.get(f"/api/v1/tasks/{task['id']}/artifacts/images/shot.png", headers=headers)
    assert ok.status_code == 200

    bad = auth_client.get(
        f"/api/v1/tasks/{task['id']}/artifacts/../../../../etc/passwd",
        headers=headers,
    )
    assert bad.status_code in {400, 404}
