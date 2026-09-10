"""Container reuse, run workspace mount, and stop-not-delete cleanup."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agents.sandbox.manifest import Manifest
from docker import errors as docker_errors

from strix.core.paths import run_dir_for, workspace_dir
from strix.runtime import session_manager
from strix.runtime.docker_client import (
    ContainerImageMismatchError,
    StrixDockerSandboxClient,
    _apply_run_labels,
    _container_image_matches,
)
from strix.runtime.session_manager import (
    build_bind_mounts,
    build_entrypoint_override_mount,
    build_run_workspace_mount,
    read_sandbox_record,
    write_sandbox_record,
)


def test_workspace_dir_is_under_run_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = run_dir_for("scan-a")
    assert workspace_dir(run_dir) == run_dir / "workspace"


def test_run_workspace_mount_is_writable_root(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    assert build_run_workspace_mount(ws) == {
        "source": str(ws.resolve()),
        "target": "/workspace",
        "read_only": False,
    }


def test_entrypoint_override_mount_points_at_packaged_script() -> None:
    mount = build_entrypoint_override_mount()
    assert mount is not None
    assert mount["target"] == "/usr/local/bin/docker-entrypoint.sh"
    assert mount["read_only"] is True
    assert "certutil" in Path(mount["source"]).read_text(encoding="utf-8")
    assert "timeout 20s certutil -N" in Path(mount["source"]).read_text(encoding="utf-8")


def test_run_workspace_mount_sorts_shallower_than_local_sources(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    repo = tmp_path / "repo"
    ws.mkdir()
    repo.mkdir()
    mounts = [
        build_run_workspace_mount(ws),
        *build_bind_mounts(
            [{"source_path": str(repo), "workspace_subdir": "repo", "protect_metadata": False}]
        ),
    ]
    # docker_client sorts by slash count; /workspace must come before /workspace/repo
    ordered = sorted(mounts, key=lambda s: str(s["target"]).count("/"))
    assert [m["target"] for m in ordered] == ["/workspace", "/workspace/repo"]


def test_sandbox_record_round_trip(tmp_path: Path) -> None:
    run_dir = tmp_path / "strix_runs" / "demo"
    write_sandbox_record(
        run_dir,
        {
            "backend": "docker",
            "container_id": "abc123",
            "image": "strix:latest",
            "workspace": str(run_dir / "workspace"),
        },
    )
    assert read_sandbox_record(run_dir) == {
        "backend": "docker",
        "container_id": "abc123",
        "image": "strix:latest",
        "workspace": str(run_dir / "workspace"),
    }


def test_read_sandbox_record_missing(tmp_path: Path) -> None:
    assert read_sandbox_record(tmp_path / "missing") is None


def test_apply_run_labels_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_RUN_ID", "my-run")
    monkeypatch.setenv("STRIX_RUN_TYPE", "scan")
    kwargs: dict[str, Any] = {}
    _apply_run_labels(kwargs)
    assert kwargs["labels"]["strix-run-id"] == "my-run"
    assert kwargs["labels"]["strix-run-type"] == "scan"


def test_container_image_matches_config_image() -> None:
    container = MagicMock()
    container.attrs = {"Config": {"Image": "strix:latest"}}
    container.image.tags = []
    container.client.images.get.side_effect = docker_errors.ImageNotFound("missing")
    assert _container_image_matches(container, "strix:latest") is True
    assert _container_image_matches(container, "other:tag") is False


@pytest.mark.asyncio
async def test_attach_existing_starts_stopped_container() -> None:
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    docker_client = MagicMock()
    container = MagicMock()
    container.id = "cid-full"
    container.short_id = "cid"
    container.status = "exited"
    container.attrs = {"Config": {"Image": "img:1"}}
    container.image.tags = ["img:1"]
    docker_client.containers.get.return_value = container
    client.docker_client = docker_client
    client._instrumentation = MagicMock()

    wrapped = object()
    with (
        patch.object(client, "_wrap_session", return_value=wrapped) as wrap,
        patch.object(client, "_apply_sandbox_network_session", side_effect=lambda s: s),
    ):
        session = await client.attach_existing(
            "cid-full",
            image="img:1",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )

    assert session is wrapped
    container.start.assert_called_once()
    wrap.assert_called_once()


@pytest.mark.asyncio
async def test_attach_existing_rejects_image_mismatch() -> None:
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    docker_client = MagicMock()
    container = MagicMock()
    container.attrs = {"Config": {"Image": "old:1"}}
    container.image.tags = ["old:1"]
    container.client.images.get.side_effect = docker_errors.ImageNotFound("x")
    docker_client.containers.get.return_value = container
    client.docker_client = docker_client

    with pytest.raises(ContainerImageMismatchError):
        await client.attach_existing(
            "cid",
            image="new:1",
            manifest=Manifest(),
            exposed_ports=(),
        )


@pytest.mark.asyncio
async def test_stop_does_not_remove_container() -> None:
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    docker_client = MagicMock()
    container = MagicMock()
    container.status = "running"
    docker_client.containers.get.return_value = container
    client.docker_client = docker_client

    session = MagicMock()
    session._inner.state.container_id = "abc123deadbeef"

    await client.stop(session)

    container.stop.assert_called_once()
    container.remove.assert_not_called()
    docker_client.containers.get.assert_called_with("abc123deadbeef")


@pytest.mark.asyncio
async def test_cleanup_prefers_stop_over_delete() -> None:
    staging = session_manager.extra_file_staging_dir("scan-stop")
    (staging / "0").mkdir()

    client = MagicMock()
    client.stop = AsyncMock()
    client.delete = AsyncMock()
    client.docker_client = None

    session_manager._SESSION_CACHE["scan-stop"] = {
        "client": client,
        "session": object(),
        "caido_client": None,
        "extra_file_staging_dir": staging,
    }

    await session_manager.cleanup("scan-stop")

    client.stop.assert_awaited_once()
    client.delete.assert_not_awaited()
    assert not staging.exists()
    assert "scan-stop" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_create_or_reuse_attaches_when_sandbox_record_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_id = "reuse-me"
    run_dir = run_dir_for(scan_id)
    write_sandbox_record(
        run_dir,
        {
            "backend": "docker",
            "container_id": "existing-cid",
            "image": "strix:test",
            "workspace": str(workspace_dir(run_dir)),
        },
    )

    fake_session = MagicMock()
    fake_session._inner.state.container_id = "existing-cid"
    fake_session.resolve_exposed_port = AsyncMock(
        return_value=MagicMock(host="127.0.0.1", port=48080, tls=False)
    )

    fake_client = MagicMock()
    backend = AsyncMock(return_value=(fake_client, fake_session))

    monkeypatch.setattr(
        session_manager, "load_settings", lambda: MagicMock(runtime=MagicMock(backend="docker"))
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(session_manager, "backend_supports_bind_mounts", lambda _name: True)
    monkeypatch.setattr(
        session_manager,
        "bootstrap_caido",
        AsyncMock(return_value=MagicMock()),
    )

    session_manager._SESSION_CACHE.pop(scan_id, None)
    try:
        bundle = await session_manager.create_or_reuse(
            scan_id,
            image="strix:test",
            local_sources=[],
        )
    finally:
        session_manager._SESSION_CACHE.pop(scan_id, None)

    assert bundle["session"] is fake_session
    backend.assert_awaited()
    kwargs = backend.await_args.kwargs
    assert kwargs["container_id"] == "existing-cid"
    assert kwargs["bind_mounts"][0]["target"] == "/workspace"
    assert (workspace_dir(run_dir)).is_dir()


@pytest.mark.asyncio
async def test_create_or_reuse_falls_back_when_attach_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_id = "reuse-fail"
    run_dir = run_dir_for(scan_id)
    write_sandbox_record(
        run_dir,
        {
            "backend": "docker",
            "container_id": "gone-cid",
            "image": "strix:test",
            "workspace": str(workspace_dir(run_dir)),
        },
    )

    fake_session = MagicMock()
    fake_session._inner.state.container_id = "new-cid"
    fake_session.resolve_exposed_port = AsyncMock(
        return_value=MagicMock(host="127.0.0.1", port=48080, tls=False)
    )
    fake_client = MagicMock()

    async def backend(**kwargs: Any) -> tuple[Any, Any]:
        if kwargs.get("container_id"):
            raise docker_errors.NotFound("gone")
        return fake_client, fake_session

    monkeypatch.setattr(
        session_manager, "load_settings", lambda: MagicMock(runtime=MagicMock(backend="docker"))
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(session_manager, "backend_supports_bind_mounts", lambda _name: True)
    monkeypatch.setattr(session_manager, "bootstrap_caido", AsyncMock(return_value=MagicMock()))

    session_manager._SESSION_CACHE.pop(scan_id, None)
    try:
        await session_manager.create_or_reuse(scan_id, image="strix:test", local_sources=[])
    finally:
        session_manager._SESSION_CACHE.pop(scan_id, None)

    record = read_sandbox_record(run_dir)
    assert record is not None
    assert record["container_id"] == "new-cid"
