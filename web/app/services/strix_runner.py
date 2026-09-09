"""In-process Strix runner with live viewer steer (real user↔agent chat).

Headless ``strix -n`` does **not** open a steerable HTTP server. Live chat only
exists when the scan process owns an ``AgentCoordinator`` and wires
``viewer.serve(..., steer_handler=...)``. That is what this module does.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
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
        from strix.interface.viewer.server import authorized_url, bundle_is_built, serve
        from strix.report.state import ReportState, set_global_report_state
        from strix.runtime import session_manager

        args = _build_args(target=target, task=task, settings=settings)
        build_targets_info(args)
        prepare_run(args)
        self.run_name = args.run_name
        assert self.run_name
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
            "resume_instruction": "",
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

        async def _main() -> int:
            self._scan_task = asyncio.current_task()
            try:
                await run_strix_scan(
                    scan_config=scan_config,
                    scan_id=self.run_name,
                    image=image,
                    local_sources=getattr(args, "local_sources", None) or [],
                    coordinator=coordinator,
                    interactive=True,
                    max_budget_usd=task.get("max_budget") or settings.default_max_budget,
                )
            except asyncio.CancelledError:
                logger.info("scan cancelled task=%s", self.task_id)
                return 130
            finally:
                with contextlib.suppress(Exception):
                    report_state.cleanup(status="stopped")
                with contextlib.suppress(Exception):
                    await session_manager.cleanup(self.run_name)
            # Match headless semantics loosely: vulns present → 2, else 0.
            vulns = report_state.vulnerability_reports or []
            return 2 if vulns else 0

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


# Back-compat aliases used by older call sites / tests.
StrixProcess = LiveStrixSession


def close_process_logs(_process: LiveStrixSession) -> None:
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


def start_strix(
    task: dict[str, Any],
    *,
    settings: Settings,
    target: str,
    on_ready: Callable[[LiveStrixSession], None] | None = None,
) -> LiveStrixSession:
    session = LiveStrixSession(Path(task["workspace"]), task["id"])
    session.start(settings=settings, target=target, task=task, on_ready=on_ready)
    return session
