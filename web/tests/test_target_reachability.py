"""Tests for pentest target TCP reachability preflight."""

from __future__ import annotations

import socket
import threading
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

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
def mock_start(monkeypatch: pytest.MonkeyPatch):
    handle = MagicMock()
    handle.pid = 1
    handle.run_name = "run_fake"
    handle.viewer_url = None
    handle.viewer_token = None
    handle._error = None
    handle.poll.return_value = None
    handle.wait_ready.return_value = True
    handle.refresh_run_name.return_value = "run_fake"

    def _start(job, *, settings, target, on_ready=None):
        if on_ready is not None:
            on_ready(handle)
        return handle

    monkeypatch.setattr("app.services.job_manager.start_strix", _start)


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


def test_check_tcp_reachable_uses_http_proxy(listening_port: int) -> None:
    seen: list[str] = []
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)
    proxy_port = int(proxy.getsockname()[1])
    stop = threading.Event()

    def _serve() -> None:
        proxy.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = proxy.accept()
            except TimeoutError:
                continue
            try:
                buf = b""
                conn.settimeout(1)
                while b"\r\n\r\n" not in buf and len(buf) < 4096:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                first = buf.split(b"\r\n", 1)[0].decode("ascii", "replace")
                seen.append(first)
                dest = first.split(" ", 2)[1] if first.startswith("CONNECT ") else ""
                host, _, port_s = dest.rpartition(":")
                try:
                    with socket.create_connection((host, int(port_s)), timeout=0.5):
                        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except (OSError, ValueError):
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            finally:
                conn.close()

    thread = threading.Thread(target=_serve, name="http-connect-proxy-test", daemon=True)
    thread.start()
    try:
        check_tcp_reachable(
            f"http://127.0.0.1:{listening_port}/",
            proxy_url=f"http://127.0.0.1:{proxy_port}",
        )
        assert seen == [f"CONNECT 127.0.0.1:{listening_port} HTTP/1.1"]
        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind(("127.0.0.1", 0))
        closed_port = int(closed.getsockname()[1])
        closed.close()
        with pytest.raises(TargetValidationError) as exc:
            check_tcp_reachable(
                f"http://127.0.0.1:{closed_port}/",
                proxy_url=f"http://127.0.0.1:{proxy_port}",
                timeout=0.8,
            )
        assert exc.value.code == "TARGET_UNREACHABLE"
        assert "via proxy 127.0.0.1" in exc.value.message
    finally:
        stop.set()
        proxy.close()
        thread.join(timeout=1)


def test_check_tcp_reachable_dead_proxy() -> None:
    with pytest.raises(TargetValidationError) as exc:
        check_tcp_reachable(
            "http://example.com/",
            proxy_url="http://127.0.0.1:1",
            timeout=0.4,
        )
    assert exc.value.code == "TARGET_UNREACHABLE"
    assert "via proxy 127.0.0.1:1" in exc.value.message


def test_check_tcp_reachable_fails_closed_port() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    with pytest.raises(TargetValidationError) as exc:
        check_tcp_reachable(f"http://127.0.0.1:{port}/", timeout=0.5)
    assert exc.value.code == "TARGET_UNREACHABLE"


def test_create_job_rejects_unreachable_target(client: TestClient) -> None:
    """Worker node fails fast — no local hold queue for dead targets."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    resp = client.post(
        "/v1/jobs",
        json={
            "type": "pentest",
            "target": f"http://127.0.0.1:{port}/",
            "scan_mode": "quick",
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "TARGET_UNREACHABLE"


def test_create_job_preflight_follows_outbound_proxy(
    client: TestClient, listening_port: int, mock_start
) -> None:
    seen: list[str] = []
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)
    proxy_port = int(proxy.getsockname()[1])
    stop = threading.Event()

    def _serve() -> None:
        proxy.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = proxy.accept()
            except TimeoutError:
                continue
            try:
                buf = b""
                conn.settimeout(1)
                while b"\r\n\r\n" not in buf and len(buf) < 4096:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                first = buf.split(b"\r\n", 1)[0].decode("ascii", "replace")
                seen.append(first)
                dest = first.split(" ", 2)[1] if first.startswith("CONNECT ") else ""
                host, _, port_s = dest.rpartition(":")
                try:
                    with socket.create_connection((host, int(port_s)), timeout=0.5):
                        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except (OSError, ValueError):
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            finally:
                conn.close()

    thread = threading.Thread(target=_serve, name="create-proxy-preflight", daemon=True)
    thread.start()
    try:
        resp = client.post(
            "/v1/jobs",
            json={
                "type": "pentest",
                "target": f"http://127.0.0.1:{listening_port}/",
                "scan_mode": "quick",
                "use_proxy": True,
                "proxy_url": f"http://127.0.0.1:{proxy_port}",
            },
        )
        assert resp.status_code == 202, resp.text
        assert resp.json()["status"] == "running"
        assert seen and seen[0].startswith("CONNECT 127.0.0.1:")
    finally:
        stop.set()
        proxy.close()
        thread.join(timeout=1)


def test_create_job_accepts_reachable_target(
    client: TestClient, listening_port: int, mock_start
) -> None:
    resp = client.post(
        "/v1/jobs",
        json={
            "type": "pentest",
            "target": f"http://127.0.0.1:{listening_port}/",
            "scan_mode": "quick",
        },
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "running"
