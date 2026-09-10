"""Install CJK fonts into a live sandbox without rebuilding the image.

The published sandbox image only ships Latin fonts (``fonts-liberation``), so
Chinese UI in agent-browser screenshots becomes tofu boxes. This module copies
``ensure_cjk_fonts.sh`` into the bind-mounted workspace and runs it as root
inside the already-started container.
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
# Under the container workspace mount so stock images can see the host script.
_CONTAINER_SCRIPT = f"/workspace/.strix/{_SCRIPT_NAME}"
# Noto CJK download + apt can be slow on first run.
_EXEC_TIMEOUT_S = 600.0


def stage_cjk_font_script(host_workspace: Path) -> Path:
    """Copy the ensure script into the host workspace (bind-mounted at /workspace)."""
    dest = host_workspace / ".strix" / _SCRIPT_NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not _SCRIPT_SRC.is_file():
        raise FileNotFoundError(f"CJK ensure script missing: {_SCRIPT_SRC}")
    shutil.copyfile(_SCRIPT_SRC, dest)
    dest.chmod(0o755)
    return dest


async def ensure_cjk_fonts(
    session: BaseSandboxSession,
    host_workspace: Path | None,
) -> None:
    """Best-effort CJK font install on the running sandbox. Never raises."""
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
    except Exception:  # noqa: BLE001
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
