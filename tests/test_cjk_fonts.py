"""CJK font ensure stages a host script and runs it as root in the sandbox."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from strix.runtime import cjk_fonts


class _FakeResult:
    def __init__(self, *, ok: bool = True, stdout: str = "CJK fonts OK\n") -> None:
        self._ok = ok
        self.stdout = stdout.encode()
        self.stderr = b""
        self.exit_code = 0 if ok else 1

    def ok(self) -> bool:
        return self._ok


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def exec(self, *command: str, **kwargs: Any) -> _FakeResult:
        self.calls.append({"command": command, **kwargs})
        return _FakeResult()


def test_stage_cjk_font_script_copies_into_workspace(tmp_path: Path) -> None:
    dest = cjk_fonts.stage_cjk_font_script(tmp_path)
    assert dest.is_file()
    assert dest.name == "ensure_cjk_fonts.sh"
    assert dest.stat().st_mode & 0o111
    text = dest.read_text(encoding="utf-8")
    assert "fonts-noto-cjk" in text
    assert "WenQuanYi" in text or "wqy" in text.lower() or "CJK" in text


@pytest.mark.asyncio
async def test_ensure_cjk_fonts_runs_staged_script_as_root(tmp_path: Path) -> None:
    session = _FakeSession()
    await cjk_fonts.ensure_cjk_fonts(session, tmp_path)  # type: ignore[arg-type]
    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["command"] == ("bash", "/workspace/.strix/ensure_cjk_fonts.sh")
    assert call["user"] == "root"
    assert call["timeout"] == cjk_fonts._EXEC_TIMEOUT_S
    assert (tmp_path / ".strix" / "ensure_cjk_fonts.sh").is_file()


@pytest.mark.asyncio
async def test_ensure_cjk_fonts_skips_without_workspace() -> None:
    session = _FakeSession()
    await cjk_fonts.ensure_cjk_fonts(session, None)  # type: ignore[arg-type]
    assert session.calls == []
