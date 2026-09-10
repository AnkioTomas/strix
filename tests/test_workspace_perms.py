"""Runtime /workspace permission fix for stock remote sandbox images."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from strix.runtime import workspace_perms


class _FakeResult:
    def __init__(self) -> None:
        self.stdout = b"Workspace writable by pentester\n"
        self.stderr = b""
        self.exit_code = 0

    def ok(self) -> bool:
        return True


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def exec(self, *command: str, **kwargs: Any) -> _FakeResult:
        self.calls.append({"command": command, **kwargs})
        return _FakeResult()


def test_stage_workspace_writable_script(tmp_path: Path) -> None:
    dest = workspace_perms.stage_workspace_writable_script(tmp_path)
    assert dest.is_file()
    assert "pentester" in dest.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_ensure_workspace_writable_runs_as_root(tmp_path: Path) -> None:
    session = _FakeSession()
    await workspace_perms.ensure_workspace_writable(session, tmp_path)  # type: ignore[arg-type]
    assert len(session.calls) == 1
    assert session.calls[0]["user"] == "root"
    assert session.calls[0]["command"][0] == "bash"
    assert "ensure_workspace_writable.sh" in session.calls[0]["command"][1]
