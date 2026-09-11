"""CJK fonts for Chromium screenshots inside the sandbox.

Stock images may only ship Latin fonts. This module:

1. Exposes a **read-only bind mount** of the OFL-bundled
   ``strix/runtime/fonts/`` directory (no per-run copy into the workspace).
2. Stages ``ensure_cjk_fonts.sh`` and runs it as root so fontconfig / apt can
   finish the job when needed.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession

logger = logging.getLogger(__name__)

_SCRIPT_NAME = "ensure_cjk_fonts.sh"
_SCRIPT_SRC = Path(__file__).resolve().with_name(_SCRIPT_NAME)
_BUNDLED_FONTS_DIR = Path(__file__).resolve().parent / "fonts"
# Inside the container — fontconfig already scans /usr/local/share/fonts.
_CONTAINER_FONTS_DIR = "/usr/local/share/fonts/strix-cjk"
_CONTAINER_SCRIPT = f"/workspace/.strix/{_SCRIPT_NAME}"
_EXEC_TIMEOUT_S = 600.0

_FONT_SUFFIXES = {".ttf", ".otf", ".ttc", ".otc", ".deb"}


def stage_cjk_font_script(host_workspace: Path) -> Path:
    """Copy the ensure script into the host workspace (bind-mounted at /workspace)."""
    dest = host_workspace / ".strix" / _SCRIPT_NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not _SCRIPT_SRC.is_file():
        raise FileNotFoundError(f"CJK ensure script missing: {_SCRIPT_SRC}")
    shutil.copyfile(_SCRIPT_SRC, dest)
    dest.chmod(0o755)
    return dest


def _is_font_file(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in _FONT_SUFFIXES


def find_bundled_cjk_font() -> Path | None:
    """Return the first font shipped under ``strix/runtime/fonts/``, if any."""
    if not _BUNDLED_FONTS_DIR.is_dir():
        return None
    try:
        fonts = sorted(p for p in _BUNDLED_FONTS_DIR.iterdir() if _is_font_file(p))
    except OSError:
        return None
    return fonts[0] if fonts else None


def build_cjk_fonts_mount() -> dict[str, Any] | None:
    """Read-only bind mount of the packaged CJK fonts directory.

    Same pattern as ``build_entrypoint_override_mount``: one host path, no
    per-container copy into the scan workspace.
    """
    if find_bundled_cjk_font() is None:
        logger.warning("Bundled CJK fonts missing under %s", _BUNDLED_FONTS_DIR)
        return None
    return {
        "source": str(_BUNDLED_FONTS_DIR.resolve()),
        "target": _CONTAINER_FONTS_DIR,
        "read_only": True,
    }


async def ensure_cjk_fonts(
    session: BaseSandboxSession,
    host_workspace: Path | None,
) -> None:
    """Best-effort CJK font ensure on the running sandbox. Never raises."""
    if host_workspace is None:
        logger.debug("Skipping CJK font ensure: no host workspace bind mount")
        return

    try:
        stage_cjk_font_script(host_workspace)
    except OSError:
        logger.exception("Failed to stage CJK font script into %s", host_workspace)
        return

    logger.info("Ensuring CJK fonts inside sandbox (%s)", _CONTAINER_SCRIPT)
    try:
        result = await session.exec(
            "bash",
            _CONTAINER_SCRIPT,
            timeout=_EXEC_TIMEOUT_S,
            user="root",
        )
    except Exception:
        logger.exception("CJK font ensure exec failed")
        return

    stdout = _decode(getattr(result, "stdout", b""))
    stderr = _decode(getattr(result, "stderr", b""))
    ok = bool(result.ok()) if hasattr(result, "ok") else getattr(result, "exit_code", 1) == 0
    if ok:
        logger.info("CJK font ensure finished: %s", stdout.strip() or "(no output)")
    else:
        logger.warning(
            "CJK font ensure exited %s: stdout=%r stderr=%r",
            getattr(result, "exit_code", "?"),
            stdout[:500],
            stderr[:500],
        )


def _decode(blob: Any) -> str:
    if isinstance(blob, bytes):
        return blob.decode("utf-8", errors="replace")
    return str(blob or "")
