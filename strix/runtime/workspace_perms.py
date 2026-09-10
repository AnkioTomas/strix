"""Make /workspace writable inside a stock remote sandbox (no image rebuild).

When the web API runs as root, ``STRIX_HOST_UID=0`` skips the entrypoint UID
remap. The published image still runs as ``pentester``, so a root-owned bind
mount yields ``Permission denied`` on ``mkdir /workspace/.tool-output``.

This stages a small script into the host workspace mount and runs it as root
right after the container starts — same pattern as CJK font ensure.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession

logger = logging.getLogger(__name__)

_SCRIPT_NAME = "ensure_workspace_writable.sh"
_SCRIPT_SRC = Path(__file__).resolve().with_name(_SCRIPT_NAME)
_CONTAINER_SCRIPT = f"/workspace/.strix/{_SCRIPT_NAME}"
_EXEC_TIMEOUT_S = 60.0


def stage_workspace_writable_script(host_workspace: Path) -> Path:
    dest = host_workspace / ".strix" / _SCRIPT_NAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not _SCRIPT_SRC.is_file():
        raise FileNotFoundError(f"workspace writable script missing: {_SCRIPT_SRC}")
    shutil.copyfile(_SCRIPT_SRC, dest)
    dest.chmod(0o755)
    return dest


async def ensure_workspace_writable(
    session: BaseSandboxSession,
    host_workspace: Path | None,
) -> None:
    """Best-effort chown of /workspace to pentester. Never raises."""
    if host_workspace is None:
        return
    try:
        stage_workspace_writable_script(host_workspace)
    except OSError:
        logger.exception("Failed to stage workspace writable script into %s", host_workspace)
        return

    logger.info("Ensuring /workspace writable inside sandbox")
    try:
        result = await session.exec(
            "bash",
            _CONTAINER_SCRIPT,
            timeout=_EXEC_TIMEOUT_S,
            user="root",
        )
    except Exception:  # noqa: BLE001
        logger.exception("workspace writable ensure exec failed")
        return

    stdout = _decode(getattr(result, "stdout", b""))
    stderr = _decode(getattr(result, "stderr", b""))
    ok = bool(result.ok()) if hasattr(result, "ok") else getattr(result, "exit_code", 1) == 0
    if ok:
        logger.info("workspace writable ensure: %s", stdout.strip() or "(no output)")
    else:
        logger.warning(
            "workspace writable ensure exited %s: stdout=%r stderr=%r",
            getattr(result, "exit_code", "?"),
            stdout[:500],
            stderr[:500],
        )


def _decode(blob: Any) -> str:
    if isinstance(blob, bytes):
        return blob.decode("utf-8", errors="replace")
    return str(blob or "")
