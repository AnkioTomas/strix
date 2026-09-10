"""Tests for pentest target TCP reachability preflight."""

from __future__ import annotations

import socket
import threading
from typing import TYPE_CHECKING

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.security.target import (
    TargetValidationError,
    check_tcp_reachable,
    parse_tcp_endpoint,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    data_dir = tmp_path / "data"
    monkeypatch.setenv("STRIX_API_DATA_DIR", str(data_dir))
    monkeypatch.setenv("STRIX_API_AUTH_DISABLED", "1")
    monkeypatch.setenv("STRIX_ALLOW_PRIVATE_TARGETS", "1")
    monkeypatch.setenv("STRIX_MAX_CONCURRENT", "1")
    get_settings.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


@pytest.fixture()
def listening_port() -> Iterator[int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = int(server.getsockname()[1])
    stop = threading.Event()

    def _serve() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            conn.close()

    thread = threading.Thread(target=_serve, name="tcp-preflight-test", daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        server.close()
        thread.join(timeout=1)


def test_parse_tcp_endpoint() -> None:
    assert parse_tcp_endpoint("https://example.com/path") == ("example.com", 443)
    assert parse_tcp_endpoint("http://192.168.1.1:8081/x") == ("192.168.1.1", 8081)
    assert parse_tcp_endpoint("192.168.1.1:8081") == ("192.168.1.1", 8081)
    assert parse_tcp_endpoint("example.com") is None
    assert parse_tcp_endpoint("/tmp/repo") is None


def test_check_tcp_reachable_ok(listening_port: int) -> None:
    check_tcp_reachable(f"http://127.0.0.1:{listening_port}/")


def test_check_tcp_reachable_fails_closed_port() -> None:
    # Bind then close to pick a free port that is not listening.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    with pytest.raises(TargetValidationError) as exc:
        check_tcp_reachable(f"http://127.0.0.1:{port}/", timeout=0.5)
    assert exc.value.code == "TARGET_UNREACHABLE"


def test_create_task_holds_unreachable_target(client: TestClient) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    resp = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": f"http://127.0.0.1:{port}/",
            "scan_mode": "quick",
            "notes": "用户备注",
        },
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "held"
    assert "用户备注" in (body.get("notes") or "")
    assert "[连通性]" in (body.get("notes") or "")
    assert "TARGET_UNREACHABLE" not in resp.text


def test_release_unreachable_stays_held(client: TestClient) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    created = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": f"http://127.0.0.1:{port}/",
            "scan_mode": "quick",
        },
    )
    assert created.status_code == 202, created.text
    task_id = created.json()["id"]
    released = client.post(f"/api/v1/tasks/{task_id}/release")
    assert released.status_code == 400, released.text
    assert released.json()["error"]["code"] == "TARGET_UNREACHABLE"
    got = client.get(f"/api/v1/tasks/{task_id}")
    assert got.status_code == 200
    assert got.json()["status"] == "held"
    assert "[连通性]" in (got.json().get("notes") or "")


def test_create_task_accepts_reachable_target(
    client: TestClient, listening_port: int
) -> None:
    resp = client.post(
        "/api/v1/tasks",
        json={
            "type": "pentest",
            "target": f"http://127.0.0.1:{listening_port}/",
            "scan_mode": "quick",
            "held": True,
        },
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "held"
