"""stop_sandbox_from_run_dir stops retained containers without an in-memory session."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from strix.runtime.session_manager import stop_sandbox_from_run_dir, write_sandbox_record


def test_stop_sandbox_from_run_dir_stops_running_container(tmp_path: Any) -> None:
    run_dir = tmp_path / "run"
    write_sandbox_record(run_dir, {"container_id": "abc123deadbeef", "backend": "docker"})

    container = MagicMock()
    container.status = "running"
    client = MagicMock()
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        assert stop_sandbox_from_run_dir(run_dir) is True

    container.stop.assert_called_once_with(timeout=10)
    client.close.assert_called_once()


def test_stop_sandbox_from_run_dir_noop_when_already_stopped(tmp_path: Any) -> None:
    run_dir = tmp_path / "run"
    write_sandbox_record(run_dir, {"container_id": "abc123deadbeef"})

    container = MagicMock()
    container.status = "exited"
    client = MagicMock()
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        assert stop_sandbox_from_run_dir(run_dir) is True

    container.stop.assert_not_called()


def test_stop_sandbox_from_run_dir_noop_without_record(tmp_path: Any) -> None:
    assert stop_sandbox_from_run_dir(tmp_path / "missing") is False
    assert stop_sandbox_from_run_dir(None) is False
