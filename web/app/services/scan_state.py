"""Persisted scan worker state (survives API process restarts)."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


STATE_FILENAME = ".web_scan_state.json"


def state_path(workspace: Path) -> Path:
    return Path(workspace) / STATE_FILENAME


def write_state(workspace: Path, **fields: Any) -> dict[str, Any]:
    path = state_path(workspace)
    current: dict[str, Any] = {}
    if path.is_file():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            current = {}
    for key, value in fields.items():
        current[key] = value
    if current.get("pid") is None:
        current["pid"] = os.getpid()
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".web_scan_state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(current, handle, ensure_ascii=False)
            handle.write("\n")
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return current


def read_state(workspace: Path) -> dict[str, Any]:
    path = state_path(workspace)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def pid_alive(pid: int | None) -> bool:
    if not pid or int(pid) <= 0:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        return True
