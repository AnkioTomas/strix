"""Periodically stop Docker sandboxes left running after terminal web tasks.

Web-side only. Uses each task's ``run.json`` ``sandbox.container_id`` so we
never touch unrelated Strix CLI containers on the same host.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.services.results import discover_run_name, workspace_run_dir


if TYPE_CHECKING:
    from collections.abc import Callable

    from app.db import Database


logger = logging.getLogger(__name__)

_ACTIVE = frozenset({"queued", "starting", "running", "cancelling"})
_TERMINAL = frozenset({"completed", "failed", "cancelled"})
_TASK_SCAN_LIMIT = 5000


def _container_id_for_task(task: dict[str, Any]) -> tuple[str, Path] | None:
    """Return ``(container_id, run_dir)`` when the task has a sandbox record."""
    workspace = Path(str(task.get("workspace") or ""))
    if not workspace.is_dir():
        return None
    run_name = task.get("run_name") or discover_run_name(workspace)
    run_dir = workspace_run_dir(workspace, run_name)
    if run_dir is None:
        return None
    from strix.runtime.session_manager import read_sandbox_record

    record = read_sandbox_record(run_dir)
    if not isinstance(record, dict):
        return None
    cid = record.get("container_id")
    if not isinstance(cid, str) or not cid.strip():
        return None
    return cid.strip(), run_dir


def _running_container_ids(
    list_running: Callable[[], list[str]] | None = None,
) -> set[str] | None:
    """Full ids of currently running containers, or ``None`` if Docker is down."""
    if list_running is not None:
        return set(list_running())
    try:
        import docker
    except ImportError:
        logger.warning("sandbox reaper: docker package unavailable")
        return None
    client = None
    try:
        client = docker.from_env(timeout=30)
        return {str(c.id) for c in client.containers.list(all=False)}
    except Exception as exc:  # noqa: BLE001 — daemon may be down; skip this tick
        logger.warning("sandbox reaper: cannot list containers: %s", exc)
        return None
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()


def _ids_overlap(left: str, right: str) -> bool:
    if left == right:
        return True
    if len(left) >= 12 and len(right) >= 12:
        return left.startswith(right) or right.startswith(left)
    return False


def _id_is_running(container_id: str, running: set[str]) -> bool:
    return any(_ids_overlap(container_id, rid) for rid in running)


def _id_in_set(container_id: str, pool: set[str]) -> bool:
    return any(_ids_overlap(container_id, other) for other in pool)


def reap_stopped_task_sandboxes(
    db: Database,
    *,
    list_running: Callable[[], list[str]] | None = None,
    stop_run_dir: Callable[[Path | None], bool] | None = None,
) -> dict[str, Any]:
    """Stop running sandboxes that belong to terminal (finished) web tasks.

    Never raises. Returns counters for logging / tests.
    """
    from strix.runtime.session_manager import stop_sandbox_from_run_dir

    stop = stop_run_dir or stop_sandbox_from_run_dir
    result: dict[str, Any] = {
        "checked": 0,
        "running": 0,
        "stopped": 0,
        "errors": 0,
        "skipped_active": 0,
    }

    try:
        tasks = db.list_tasks(limit=_TASK_SCAN_LIMIT, offset=0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("sandbox reaper: list_tasks failed: %s", exc)
        result["errors"] = 1
        return result

    active_ids: set[str] = set()
    terminal_targets: list[tuple[str, str, Path]] = []
    for task in tasks:
        status = str(task.get("status") or "")
        mapped = _container_id_for_task(task)
        if mapped is None:
            continue
        cid, run_dir = mapped
        if status in _ACTIVE:
            active_ids.add(cid)
            continue
        if status in _TERMINAL:
            terminal_targets.append((str(task["id"]), cid, run_dir))

    if not terminal_targets:
        return result

    running = _running_container_ids(list_running=list_running)
    if running is None:
        result["errors"] = 1
        return result

    result["checked"] = len(terminal_targets)
    for task_id, cid, run_dir in terminal_targets:
        if _id_in_set(cid, active_ids):
            result["skipped_active"] += 1
            continue
        if not _id_is_running(cid, running):
            continue
        result["running"] += 1
        try:
            if stop(run_dir):
                result["stopped"] += 1
                logger.info(
                    "sandbox reaper: stopped container %s for terminal task %s",
                    cid[:12],
                    task_id,
                )
            else:
                result["errors"] += 1
        except Exception as exc:  # noqa: BLE001
            result["errors"] += 1
            logger.warning(
                "sandbox reaper: stop failed task=%s container=%s: %s",
                task_id,
                cid[:12],
                exc,
            )
    return result
