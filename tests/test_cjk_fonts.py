"""CJK font ensure uses a RO bind mount; script runs as root in the sandbox."""

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
    assert "/usr/local/share/fonts/strix-cjk" in text
    assert "/workspace/.strix/fonts" in text


def test_bundled_cjk_font_exists() -> None:
    bundled = cjk_fonts.find_bundled_cjk_font()
    assert bundled is not None
    assert bundled.name == "NotoSansSC-Regular.otf"
    assert bundled.stat().st_size > 1_000_000


def test_build_cjk_fonts_mount_is_read_only() -> None:
    mount = cjk_fonts.build_cjk_fonts_mount()
    assert mount is not None
    assert mount["read_only"] is True
    assert mount["target"] == cjk_fonts._CONTAINER_FONTS_DIR
    assert Path(mount["source"]).is_dir()
    assert (Path(mount["source"]) / "NotoSansSC-Regular.otf").is_file()


def test_build_cjk_fonts_mount_none_without_fonts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    empty = tmp_path / "empty-fonts"
    empty.mkdir()
    monkeypatch.setattr(cjk_fonts, "_BUNDLED_FONTS_DIR", empty)
    assert cjk_fonts.build_cjk_fonts_mount() is None


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
    # No per-run font copy into the workspace.
    assert not (tmp_path / ".strix" / "fonts").exists()


@pytest.mark.asyncio
async def test_ensure_cjk_fonts_skips_without_workspace() -> None:
    session = _FakeSession()
    await cjk_fonts.ensure_cjk_fonts(session, None)  # type: ignore[arg-type]
    assert session.calls == []
