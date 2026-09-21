"""Periodically stop Docker sandboxes left running after terminal web tasks.

Web-side only. Walks each finished task's ``strix_runs/*/run.json`` (not just
the current ``run_name``) and also matches running containers by the
``strix-run-id`` label, so orphaned sibling runs still get reaped.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.services.results import workspace_run_dir


if TYPE_CHECKING:
    from collections.abc import Callable

    from app.db import Database


logger = logging.getLogger(__name__)

_ACTIVE = frozenset({"queued", "starting", "running", "cancelling"})
_TERMINAL = frozenset({"completed", "failed", "cancelled"})
_TASK_SCAN_LIMIT = 5000
_RUNS_DIRNAME = "strix_runs"
_LABEL_RUN_ID = "strix-run-id"


def _iter_run_dirs(workspace: Path) -> list[Path]:
    root = Path(workspace) / _RUNS_DIRNAME
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / "run.json").is_file())


def _sandbox_container_id(run_dir: Path) -> str | None:
    from strix.runtime.session_manager import read_sandbox_record

    record = read_sandbox_record(run_dir)
    if not isinstance(record, dict):
        return None
    cid = record.get("container_id")
    if not isinstance(cid, str) or not cid.strip():
        return None
    return cid.strip()


def _ids_overlap(left: str, right: str) -> bool:
    if left == right:
        return True
    if len(left) >= 12 and len(right) >= 12:
        return left.startswith(right) or right.startswith(left)
    return False


def _id_in_set(container_id: str, pool: set[str]) -> bool:
    return any(_ids_overlap(container_id, other) for other in pool)


def _collect_task_sandboxes(
    tasks: list[dict[str, Any]],
) -> tuple[set[str], set[str], list[tuple[str, str, Path]]]:
    """Return ``(active_cids, active_run_ids, terminal_targets)``.

    ``terminal_targets`` entries are ``(task_id, container_id, run_dir)`` for
    every run under a terminal task's workspace that still records a container.
    """
    active_cids: set[str] = set()
    active_run_ids: set[str] = set()
    terminal_targets: list[tuple[str, str, Path]] = []
    seen_cids: set[str] = set()

    for task in tasks:
        status = str(task.get("status") or "")
        workspace = Path(str(task.get("workspace") or ""))
        if not workspace.is_dir():
            continue
        run_dirs = _iter_run_dirs(workspace)
        # Always include the DB run_name even if the directory walk missed it.
        named = workspace_run_dir(workspace, task.get("run_name"))
        if named is not None and named not in run_dirs:
            run_dirs.append(named)

        for run_dir in run_dirs:
            run_id = run_dir.name
            cid = _sandbox_container_id(run_dir)
            if status in _ACTIVE:
                active_run_ids.add(run_id)
                if cid:
                    active_cids.add(cid)
                continue
            if status not in _TERMINAL or not cid:
                continue
            if cid in seen_cids:
                continue
            seen_cids.add(cid)
            terminal_targets.append((str(task["id"]), cid, run_dir))

    return active_cids, active_run_ids, terminal_targets


def _list_labeled_running(
    *,
    list_labeled: Callable[[], list[tuple[str, str]]] | None = None,
) -> list[tuple[str, str]] | None:
    """Return ``[(container_id, strix-run-id), ...]`` for running sandboxes."""
    if list_labeled is not None:
        return list(list_labeled())
    try:
        import docker
    except ImportError:
        logger.warning("sandbox reaper: docker package unavailable")
        return None
    client = None
    try:
        client = docker.from_env(timeout=30)
        out: list[tuple[str, str]] = []
        for container in client.containers.list(
            all=False,
            filters={"label": _LABEL_RUN_ID},
        ):
            labels = container.labels or {}
            run_id = labels.get(_LABEL_RUN_ID) if isinstance(labels, dict) else None
            if isinstance(run_id, str) and run_id.strip() and container.id:
                out.append((str(container.id), run_id.strip()))
        return out
    except Exception as exc:  # noqa: BLE001 — daemon may be down; skip label pass
        logger.warning("sandbox reaper: cannot list labeled containers: %s", exc)
        return None
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()


def _stop_container_id(container_id: str) -> bool:
    """Best-effort stop by id (retain container). Never raises."""
    try:
        import docker
    except ImportError:
        return False
    client = None
    try:
        client = docker.from_env(timeout=60)
        container = client.containers.get(container_id)
        container.reload()
        if container.status != "running":
            return True
        try:
            container.stop(timeout=10)
        except Exception:  # noqa: BLE001
            with contextlib.suppress(Exception):
                container.kill()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("sandbox reaper: stop by id failed %s: %s", container_id[:12], exc)
        return False
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()


def reap_stopped_task_sandboxes(
    db: Database,
    *,
    list_labeled: Callable[[], list[tuple[str, str]]] | None = None,
    stop_run_dir: Callable[[Path | None], bool] | None = None,
    stop_container: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """Stop running sandboxes owned by terminal web tasks. Never raises."""
    from strix.runtime.session_manager import stop_sandbox_from_run_dir

    stop_dir = stop_run_dir or stop_sandbox_from_run_dir
    stop_cid = stop_container or _stop_container_id
    result: dict[str, Any] = {
        "checked": 0,
        "stopped": 0,
        "errors": 0,
        "skipped_active": 0,
        "label_stopped": 0,
    }

    try:
        tasks = db.list_tasks(limit=_TASK_SCAN_LIMIT, offset=0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("sandbox reaper: list_tasks failed: %s", exc)
        result["errors"] = 1
        return result

    active_cids, active_run_ids, terminal_targets = _collect_task_sandboxes(tasks)
    terminal_run_ids = {
        run_dir.name
        for task in tasks
        if str(task.get("status") or "") in _TERMINAL
        for run_dir in _iter_run_dirs(Path(str(task.get("workspace") or "")))
    }
    # DB run_name may point at a dir we already walked; keep explicit names too.
    for task in tasks:
        if str(task.get("status") or "") not in _TERMINAL:
            continue
        name = task.get("run_name")
        if isinstance(name, str) and name.strip():
            terminal_run_ids.add(name.strip())

    result["checked"] = len(terminal_targets)
    stopped_cids: set[str] = set()

    for task_id, cid, run_dir in terminal_targets:
        if _id_in_set(cid, active_cids):
            result["skipped_active"] += 1
            continue
        try:
            ok = stop_dir(run_dir)
        except Exception as exc:  # noqa: BLE001
            result["errors"] += 1
            logger.warning(
                "sandbox reaper: stop failed task=%s container=%s: %s",
                task_id,
                cid[:12],
                exc,
            )
            continue
        if ok:
            result["stopped"] += 1
            stopped_cids.add(cid)
            logger.info(
                "sandbox reaper: stopped container %s for terminal task %s (run=%s)",
                cid[:12],
                task_id,
                run_dir.name,
            )
        else:
            result["errors"] += 1

    # Second pass: running containers labeled strix-run-id whose run belongs to
    # a finished task but never got (or lost) sandbox.container_id in run.json.
    labeled = _list_labeled_running(list_labeled=list_labeled)
    if labeled is None:
        result["errors"] += 1
    else:
        for cid, run_id in labeled:
            if run_id in active_run_ids or _id_in_set(cid, active_cids):
                result["skipped_active"] += 1
                continue
            if run_id not in terminal_run_ids:
                continue
            if _id_in_set(cid, stopped_cids):
                continue
            if stop_cid(cid):
                result["label_stopped"] += 1
                result["stopped"] += 1
                stopped_cids.add(cid)
                logger.info(
                    "sandbox reaper: stopped labeled container %s run_id=%s",
                    cid[:12],
                    run_id,
                )
            else:
                result["errors"] += 1

    logger.info(
        "sandbox reaper checked=%s stopped=%s label_stopped=%s skipped_active=%s errors=%s",
        result["checked"],
        result["stopped"],
        result["label_stopped"],
        result["skipped_active"],
        result["errors"],
    )
    return result
