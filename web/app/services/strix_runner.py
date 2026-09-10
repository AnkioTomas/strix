"""Detached Strix scan worker + in-process LiveStrixSession.

Scans run in a separate OS process (``python -m app.services.scan_worker``) so
API restarts do not kill the engagement. The API talks to the live viewer over
loopback HTTP for steering after reattach.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from app.config import Settings


logger = logging.getLogger(__name__)


class LiveStrixSession:
    """One interactive Strix scan running in a background thread."""

    def __init__(self, workspace: Path, task_id: str) -> None:
        self.workspace = workspace
        self.task_id = task_id
        self.run_name: str | None = None
        self.viewer_url: str | None = None
        self.viewer_token: str | None = None
        self.root_agent_id: str | None = None

        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._coordinator: Any | None = None
        self._scan_task: asyncio.Task[Any] | None = None
        self._viewer_httpd: Any | None = None
        self._exit_code: int | None = None
        self._error: str | None = None
        self._started = threading.Event()
        self._ready = threading.Event()  # run_name + viewer known
        self._on_ready: Callable[[LiveStrixSession], None] | None = None

    @property
    def pid(self) -> int | None:
        # In-process: expose the worker thread id for status, not an OS child.
        if self._thread and self._thread.is_alive():
            return self._thread.ident
        return None

    def poll(self) -> int | None:
        if self._thread is None:
            return self._exit_code
        if self._thread.is_alive():
            return None
        return 0 if self._exit_code is None else self._exit_code

    def refresh_run_name(self) -> str | None:
        return self.run_name

    def start(
        self,
        *,
        settings: Settings,
        target: str,
        task: dict[str, Any],
        on_ready: Callable[[LiveStrixSession], None] | None = None,
    ) -> None:
        self._on_ready = on_ready
        self._thread = threading.Thread(
            target=self._thread_main,
            kwargs={"settings": settings, "target": target, "task": task},
            name=f"strix-live-{self.task_id}",
            daemon=True,
        )
        self._thread.start()
        if not self._started.wait(timeout=30):
            raise RuntimeError("Strix live session failed to start")
        if self._error and self.poll() is not None:
            raise RuntimeError(self._error)

    def wait_ready(self, timeout: float = 120.0) -> bool:
        return self._ready.wait(timeout=timeout)

    def send_message(self, message: str, *, agent_id: str | None = None) -> bool:
        coordinator = self._coordinator
        loop = self._loop
        if coordinator is None or loop is None or loop.is_closed():
            return False
        target_id = agent_id or self.root_agent_id or self._discover_root()
        if not target_id:
            return False
        self.root_agent_id = target_id

        async def deliver() -> bool:
            return bool(
                await coordinator.send(
                    target_id,
                    {"from": "user", "content": message, "type": "instruction"},
                )
            )

        future = asyncio.run_coroutine_threadsafe(deliver(), loop)
        try:
            return bool(future.result(timeout=15))
        except Exception:
            logger.exception("live message delivery failed task=%s", self.task_id)
            return False

    def terminate(self, grace_seconds: int = 15) -> int | None:
        if self.poll() is not None:
            return self.poll()
        loop = self._loop
        scan_task = self._scan_task
        if loop is not None and scan_task is not None and not loop.is_closed():
            loop.call_soon_threadsafe(scan_task.cancel)
            # Also ask the coordinator to stop agents.
            if self._coordinator is not None:
                root = self.root_agent_id or self._discover_root()
                if root:

                    async def stop_agents() -> None:
                        with contextlib.suppress(Exception):
                            await self._coordinator.cancel_descendants(root)
                        with contextlib.suppress(Exception):
                            await self._coordinator.request_stop(root)

                    asyncio.run_coroutine_threadsafe(stop_agents(), loop)

        deadline = time.time() + grace_seconds
        while time.time() < deadline:
            code = self.poll()
            if code is not None:
                self._close_viewer()
                return code
            time.sleep(0.2)

        self._close_viewer()
        return self.poll() if self.poll() is not None else 137

    def _thread_main(self, *, settings: Settings, target: str, task: dict[str, Any]) -> None:
        previous_cwd = Path.cwd()
        try:
            os.chdir(self.workspace)
            self._started.set()
            self._exit_code = self._run_scan(settings=settings, target=target, task=task)
        except Exception as exc:
            logger.exception("live strix session crashed task=%s", self.task_id)
            self._error = str(exc)
            self._exit_code = 1
            self._started.set()
            self._ready.set()
        finally:
            self._close_viewer()
            with contextlib.suppress(OSError):
                os.chdir(previous_cwd)

    def _run_scan(self, *, settings: Settings, target: str, task: dict[str, Any]) -> int:
        from strix.config import load_settings
        from strix.core.agents import AgentCoordinator
        from strix.core.paths import run_dir_for
        from strix.core.runner import run_strix_scan
        from strix.interface.scan_setup import build_targets_info, prepare_run
        from strix.interface.utils import read_workspace_files
        from strix.interface.viewer.server import authorized_url, bundle_is_built, serve
        from strix.report.state import ReportState, set_global_report_state
        from strix.runtime import session_manager

        from app.services.attachments import resolve_task_workspace_files

        args = _build_args(target=target, task=task, settings=settings)
        if task.get("action") == "resume" and task.get("run_name"):
            logger.info(
                "resuming Strix run task=%s run_name=%s (CLI --resume equivalent)",
                self.task_id,
                task.get("run_name"),
            )
            _prepare_resume_args(args, run_name=str(task["run_name"]), task=task)
        else:
            if task.get("action") == "resume" and not task.get("run_name"):
                raise RuntimeError("resume requested but task has no run_name")
            build_targets_info(args)
            prepare_run(args)
        # Attachments under task workspace/attachments/ are authoritative for web tasks.
        attached = resolve_task_workspace_files(Path(task["workspace"]))
        if attached:
            args.workspace_files = attached
        self.run_name = args.run_name
        assert self.run_name
        if task.get("action") == "resume" and self.run_name != task.get("run_name"):
            raise RuntimeError(
                f"resume must keep run_name={task.get('run_name')!r}, "
                f"got {self.run_name!r}"
            )
        run_dir = run_dir_for(self.run_name)

        scan_config: dict[str, Any] = {
            "scan_id": self.run_name,
            "targets": args.targets_info,
            "user_instructions": args.instruction or "",
            "run_name": self.run_name,
            "diff_scope": getattr(args, "diff_scope", {"active": False}),
            "scan_mode": args.scan_mode,
            "non_interactive": False,
            "local_sources": getattr(args, "local_sources", None) or [],
            "workspace_files": getattr(args, "workspace_files", None) or [],
            "scope_mode": args.scope_mode,
            "diff_base": args.diff_base,
            "resume_instruction": getattr(args, "user_explicit_instruction", None) or "",
        }

        report_state = ReportState(self.run_name)
        report_state.hydrate_from_run_dir()
        report_state.set_scan_config(scan_config)
        report_state.save_run_data()
        set_global_report_state(report_state)

        image = load_settings().runtime.image
        if not image:
            raise RuntimeError("strix_image is not configured")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        coordinator = AgentCoordinator()
        self._coordinator = coordinator

        if bundle_is_built():
            httpd, base_url, token = serve(
                run_dir,
                open_browser=False,
                steer_handler=self._steer,
            )
            self._viewer_httpd = httpd
            self.viewer_token = token
            self.viewer_url = authorized_url(base_url, token)
            logger.info(
                "viewer ready task=%s url=%s (token redacted in logs)",
                self.task_id,
                base_url,
            )
        else:
            logger.warning("viewer UI bundle missing; live steer HTTP unavailable")

        self._ready.set()
        if self._on_ready is not None:
            with contextlib.suppress(Exception):
                self._on_ready(self)

        extra_files = read_workspace_files(getattr(args, "workspace_files", None))

        async def _main() -> int:
            # Keep a handle to the scan task so terminate() / finish-reap can cancel it.
            # Interactive mode parks forever after finish_scan; web must exit when the
            # engagement is truly finished. Do NOT key off report status alone:
            # save_run_data(mark_complete=True) sets status="completed" BEFORE
            # _save_artifacts() returns, so cancelling on status alone can interrupt
            # the zip / vulnerabilities.json write. Wait until the root agent is also
            # terminal (set only after finish_scan's persistence returns).
            self._scan_task = asyncio.current_task()
            scan = asyncio.create_task(
                run_strix_scan(
                    scan_config=scan_config,
                    scan_id=self.run_name,
                    image=image,
                    local_sources=getattr(args, "local_sources", None) or [],
                    coordinator=coordinator,
                    interactive=True,
                    max_budget_usd=task.get("max_budget") or settings.default_max_budget,
                    extra_files=extra_files,
                ),
                name=f"strix-scan-{self.task_id}",
            )
            # Arm exit detection only after we've observed a live "running" report.
            # Resume hydrates agents.json with a terminal root; without this arming
            # step a stale completed report (or a resume race) would kill the scan
            # before the agent is woken.
            armed = str(report_state.run_record.get("status") or "") == "running"
            try:
                while not scan.done():
                    status_now = str(report_state.run_record.get("status") or "")
                    if status_now == "running":
                        armed = True
                    if armed and _web_scan_should_exit(report_state, coordinator):
                        scan.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await scan
                        return _exit_code_from_report(report_state)
                    try:
                        await asyncio.wait_for(asyncio.shield(scan), timeout=1.0)
                    except TimeoutError:
                        continue
                if scan.cancelled():
                    return _exit_code_from_report(report_state)
                exc = scan.exception()
                if exc is not None:
                    raise exc
                return _exit_code_from_report(report_state)
            except asyncio.CancelledError:
                if not scan.done():
                    scan.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await scan
                if str(report_state.run_record.get("status") or "") == "completed":
                    return _exit_code_from_report(report_state)
                logger.info("scan cancelled task=%s", self.task_id)
                return 130
            finally:
                with contextlib.suppress(Exception):
                    # Do not demote an already-completed report to "stopped".
                    if str(report_state.run_record.get("status") or "") not in {
                        "completed",
                        "failed",
                        "interrupted",
                    }:
                        report_state.cleanup(status="stopped")
                with contextlib.suppress(Exception):
                    await session_manager.cleanup(self.run_name)

        try:
            return int(loop.run_until_complete(_main()))
        finally:
            with contextlib.suppress(Exception):
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            self._loop = None

    def _steer(self, agent_id: str, message: str) -> bool:
        return self.send_message(message, agent_id=agent_id)

    def _discover_root(self) -> str | None:
        coordinator = self._coordinator
        if coordinator is None:
            return None
        for aid, parent in getattr(coordinator, "parent_of", {}).items():
            if parent is None:
                return str(aid)
        statuses = getattr(coordinator, "statuses", {})
        if statuses:
            return str(next(iter(statuses)))
        return None

    def _close_viewer(self) -> None:
        httpd = self._viewer_httpd
        self._viewer_httpd = None
        if httpd is None:
            return
        with contextlib.suppress(Exception):
            httpd.shutdown()
            httpd.server_close()


_ROOT_TERMINAL = frozenset({"completed", "stopped", "failed", "crashed"})
_REPORT_DONE = frozenset({"completed", "failed", "interrupted"})


def _web_scan_should_exit(report_state: Any, coordinator: Any) -> bool:
    """True only when both the report and the root agent have finished.

    ``completed`` alone is not enough: ReportState flips that bit before the
    final artifact write finishes. The root agent's ``completed`` status is set
    by ``finish_scan`` only after persistence returns.
    """
    report_status = str(report_state.run_record.get("status") or "")
    if report_status not in _REPORT_DONE:
        return False
    if coordinator is None:
        return False
    root_id = None
    parent_of = getattr(coordinator, "parent_of", {}) or {}
    for agent_id, parent in parent_of.items():
        if parent is None:
            root_id = str(agent_id)
            break
    if root_id is None:
        statuses = getattr(coordinator, "statuses", {}) or {}
        if statuses:
            root_id = str(next(iter(statuses)))
    if root_id is None:
        return False
    root_status = str((getattr(coordinator, "statuses", {}) or {}).get(root_id) or "")
    return root_status in _ROOT_TERMINAL


def _exit_code_from_report(report_state: Any) -> int:
    """Map ReportState terminal status to headless-like exit codes."""
    status = str(report_state.run_record.get("status") or "")
    if status == "completed":
        vulns = report_state.vulnerability_reports or []
        return 2 if vulns else 0
    if status == "stopped":
        return 130
    return 1


def _build_args(*, target: str, task: dict[str, Any], settings: Settings) -> argparse.Namespace:
    return argparse.Namespace(
        target=[target],
        target_list=None,
        instruction=task.get("instruction"),
        instruction_file=None,
        workspace_file=None,
        workspace_files=[],
        workspace_mount=None,
        non_interactive=False,
        scan_mode=task.get("scan_mode") or settings.default_scan_mode,
        scope_mode="full",
        diff_base=None,
        resume=None,
        max_budget_usd=task.get("max_budget") or settings.default_max_budget,
        needs_setup=False,
        targets_info=[],
        local_sources=[],
        diff_scope={"active": False},
        run_name=None,
        user_instruction=task.get("instruction"),
        user_explicit_instruction=None,
    )


def _prepare_resume_args(
    args: argparse.Namespace, *, run_name: str, task: dict[str, Any]
) -> None:
    """Hydrate ``args`` like ``strix --resume <run_name>`` (cwd = task workspace)."""
    from strix.core.paths import run_dir_for, runtime_state_dir
    from strix.interface.cli_args import _load_resume_state
    from strix.interface.scan_setup import prepare_run

    class _ResumeParser(argparse.ArgumentParser):
        def error(self, message: str) -> None:  # type: ignore[override]
            raise ValueError(message)

    # Optional one-shot nudge written by TaskManager.resume_task — not task.instruction.
    note_path = Path(task["workspace"]) / ".web_resume_instruction"
    resume_note: str | None = None
    if note_path.is_file():
        resume_note = note_path.read_text(encoding="utf-8").strip() or None
        note_path.unlink(missing_ok=True)

    args.resume = run_name
    args.target = None
    args.target_list = None
    # Prior instruction/targets come from run.json; do not treat task.instruction as nudge.
    args.instruction = None
    args.user_instruction = None
    args.user_explicit_instruction = resume_note
    _load_resume_state(args, _ResumeParser())
    agents_path = runtime_state_dir(run_dir_for(run_name)) / "agents.json"
    if not agents_path.is_file():
        raise RuntimeError(
            f"Cannot resume {run_name}: missing {agents_path}. "
            "The run never reached an agent snapshot."
        )
    prepare_run(args)
    if resume_note:
        args.user_explicit_instruction = resume_note


# Back-compat aliases used by older call sites / tests.
StrixProcess = LiveStrixSession


def close_process_logs(_process: Any) -> None:
    return


def strix_available(settings: Settings) -> bool:
    import subprocess

    try:
        result = subprocess.run(
            [settings.strix_bin, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


class DetachedScanHandle:
    """Handle for a scan running in a detached OS process (survives API restart)."""

    def __init__(
        self,
        workspace: Path,
        task_id: str,
        *,
        popen: Any | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.task_id = task_id
        self._popen = popen

    @classmethod
    def attach(cls, workspace: Path, task_id: str) -> DetachedScanHandle:
        return cls(workspace, task_id, popen=None)

    def _state(self) -> dict[str, Any]:
        from app.services.scan_state import read_state

        return read_state(self.workspace)

    @property
    def pid(self) -> int | None:
        st = self._state()
        pid = st.get("pid")
        if pid:
            return int(pid)
        if self._popen is not None:
            return int(self._popen.pid)
        return None

    @property
    def run_name(self) -> str | None:
        value = self._state().get("run_name")
        return str(value) if value else None

    @property
    def viewer_url(self) -> str | None:
        value = self._state().get("viewer_url")
        return str(value) if value else None

    @property
    def viewer_token(self) -> str | None:
        value = self._state().get("viewer_token")
        return str(value) if value else None

    @property
    def root_agent_id(self) -> str | None:
        value = self._state().get("root_agent_id")
        return str(value) if value else None

    @property
    def _error(self) -> str | None:
        value = self._state().get("error")
        return str(value) if value else None

    def refresh_run_name(self) -> str | None:
        return self.run_name

    def poll(self) -> int | None:
        from app.services.scan_state import pid_alive, write_state

        st = self._state()
        if st.get("exit_code") is not None:
            return int(st["exit_code"])
        if self._popen is not None:
            code = self._popen.poll()
            if code is not None:
                # Worker may still be flushing state; prefer file if present.
                st2 = self._state()
                if st2.get("exit_code") is not None:
                    return int(st2["exit_code"])
                return int(code)
        pid = self.pid
        if pid_alive(pid):
            # Interactive scans park after finish_scan; reap when run.json is terminal.
            reaped = self._reap_finished_interactive()
            if reaped is not None:
                return reaped
            return None
        # Process gone but no exit recorded → treat as crash.
        return int(st["exit_code"]) if st.get("exit_code") is not None else 1

    def _reap_finished_interactive(self) -> int | None:
        """If run.json is terminal after a live run, record exit_code and stop the worker.

        Must not fire on resume startup: the prior run leaves ``status=completed``
        on disk until the worker rewrites it to ``running``. Ready is only set
        after that rewrite, so requiring ``ready`` kills the race without
        breaking stuck-park reap after API restart.
        """
        import signal

        from app.services.results import read_run_record, read_vulnerabilities
        from app.services.scan_state import pid_alive, write_state

        st = self._state()
        # Worker has not finished set_scan_config / ready handshake yet.
        if not st.get("ready"):
            return None

        run_name = self.run_name
        if not run_name:
            return None
        run_dir = self.workspace / "strix_runs" / run_name
        record = read_run_record(run_dir)
        status = str(record.get("status") or "")
        if status not in {"completed", "failed", "interrupted", "stopped"}:
            return None
        if status == "completed":
            code = 2 if read_vulnerabilities(run_dir) else 0
        elif status == "stopped":
            code = 130
        else:
            code = 1
        write_state(
            self.workspace,
            exit_code=code,
            run_name=run_name,
            ready=True,
            error=None if status == "completed" else f"run ended with status={status}",
        )
        logger.info(
            "reaping parked interactive worker task=%s run=%s status=%s exit=%s",
            self.task_id,
            run_name,
            status,
            code,
        )
        pid = self.pid
        if pid and pid_alive(pid):
            # Prefer SIGTERM so the worker finally-block can stop the sandbox.
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(pid, signal.SIGTERM)
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.kill(pid, signal.SIGTERM)
            # docker stop inside cleanup can take ~10s; give it room before SIGKILL.
            deadline = time.time() + 25
            while time.time() < deadline and pid_alive(pid):
                time.sleep(0.2)
            if pid_alive(pid):
                logger.warning(
                    "worker pid=%s still alive after SIGTERM; sending SIGKILL",
                    pid,
                )
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.killpg(pid, signal.SIGKILL)
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.kill(pid, signal.SIGKILL)
        return code

    def wait_ready(self, timeout: float = 180.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = self._state()
            if st.get("ready") and (st.get("viewer_url") or st.get("error") or self.poll() is not None):
                return True
            if self.poll() is not None:
                return True
            time.sleep(0.25)
        return bool(self._state().get("ready"))

    def send_message(self, message: str, *, agent_id: str | None = None) -> bool:
        return steer_via_viewer_http(
            viewer_url=self.viewer_url,
            viewer_token=self.viewer_token,
            message=message,
            agent_id=agent_id or self.root_agent_id,
            run_dir=self.workspace,
            run_name=self.run_name,
        )

    def terminate(self, grace_seconds: int = 15) -> int | None:
        import signal

        from app.services.scan_state import pid_alive

        code = self.poll()
        if code is not None:
            return code
        pid = self.pid
        if not pid or not pid_alive(pid):
            return self.poll()
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.kill(pid, signal.SIGTERM)
        deadline = time.time() + grace_seconds
        while time.time() < deadline:
            code = self.poll()
            if code is not None:
                return code
            time.sleep(0.2)
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(pid, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.kill(pid, signal.SIGKILL)
        return self.poll() if self.poll() is not None else 137


def steer_via_viewer_http(
    *,
    viewer_url: str | None,
    viewer_token: str | None,
    message: str,
    agent_id: str | None,
    run_dir: Path | None = None,
    run_name: str | None = None,
) -> bool:
    """POST /api/agents/steer on the live viewer (works after API reattach)."""
    if not viewer_url or not viewer_token:
        return False
    target_agent = agent_id or _root_agent_from_disk(run_dir, run_name)
    if not target_agent:
        return False
    import httpx

    # Keep cookie prefix in sync with strix.interface.viewer.server.SESSION_COOKIE_PREFIX
    cookie_prefix = "strix_viewer_session"
    try:
        from urllib.parse import urlparse

        parsed = urlparse(viewer_url)
        host = (parsed.hostname or "").lower()
        if host not in {"127.0.0.1", "localhost", "::1"}:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        base = f"{parsed.scheme}://{host}:{port}"
    except Exception:
        return False
    cookie = f"{cookie_prefix}_{port}={viewer_token}"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{base}/api/agents/steer",
                headers={"Cookie": cookie, "Content-Type": "application/json"},
                json={"agent_id": target_agent, "message": message},
            )
    except httpx.HTTPError:
        logger.exception("viewer steer HTTP failed")
        return False
    if resp.status_code != 200:
        return False
    try:
        payload = resp.json()
    except ValueError:
        return False
    return bool(payload.get("ok"))


def _root_agent_from_disk(run_dir: Path | None, run_name: str | None) -> str | None:
    if run_dir is None or not run_name:
        return None
    agents_path = run_dir / "strix_runs" / run_name / ".state" / "agents.json"
    if not agents_path.is_file():
        return None
    try:
        data = json.loads(agents_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    parent_of = data.get("parent_of") or {}
    if isinstance(parent_of, dict):
        for aid, parent in parent_of.items():
            if parent is None:
                return str(aid)
    statuses = data.get("statuses") or {}
    if isinstance(statuses, dict) and statuses:
        return str(next(iter(statuses)))
    return None


def start_strix(
    task: dict[str, Any],
    *,
    settings: Settings,
    target: str,
    on_ready: Callable[[Any], None] | None = None,
) -> DetachedScanHandle:
    """Spawn a detached scan worker process that outlives the API."""
    import json
    import subprocess
    import sys

    from app.services.scan_state import write_state

    workspace = Path(task["workspace"])
    job_path = workspace / ".web_scan_job.json"
    # Pass the full DB row — resume needs ``action`` + ``run_name`` or the worker
    # silently starts a brand-new scan (new run_name, empty agents.db).
    job_task = {key: task.get(key) for key in task}
    job_task["workspace"] = str(workspace)
    job = {
        "workspace": str(workspace),
        "target": target,
        "task": job_task,
    }
    job_path.write_text(json.dumps(job, ensure_ascii=False, default=str), encoding="utf-8")
    write_state(
        workspace,
        pid=None,
        task_id=task["id"],
        ready=False,
        exit_code=None,
        error=None,
        viewer_url=None,
        viewer_token=None,
        run_name=task.get("run_name"),
        root_agent_id=None,
    )

    web_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(web_root), env["PYTHONPATH"]] if env.get("PYTHONPATH") else [str(web_root)]
    )
    popen = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "app.services.scan_worker", "--job", str(job_path)],
        cwd=str(web_root),
        env=env,
        start_new_session=True,
        stdout=open(workspace / "scan_worker.stdout.log", "ab", buffering=0),  # noqa: SIM115
        stderr=open(workspace / "scan_worker.stderr.log", "ab", buffering=0),  # noqa: SIM115
    )
    handle = DetachedScanHandle(workspace, task["id"], popen=popen)
    # Seed pid immediately so DB reattach works even before worker writes state.
    write_state(workspace, pid=popen.pid, task_id=task["id"], ready=False)

    if on_ready is not None:
        # Best-effort: invoke after ready so DB gets viewer fields.
        def _watch() -> None:
            if handle.wait_ready(timeout=180):
                with contextlib.suppress(Exception):
                    on_ready(handle)

        threading.Thread(target=_watch, name=f"strix-ready-{task['id']}", daemon=True).start()
    return handle
