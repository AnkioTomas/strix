"""Launch and supervise a Strix CLI subprocess for one task."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from app.config import Settings
from app.services.results import discover_run_name


logger = logging.getLogger(__name__)


class StrixProcess:
    def __init__(self, popen: subprocess.Popen[str], workspace: Path, log_path: Path) -> None:
        self.popen = popen
        self.workspace = workspace
        self.log_path = log_path
        self.run_name: str | None = None

    @property
    def pid(self) -> int | None:
        return self.popen.pid

    def poll(self) -> int | None:
        return self.popen.poll()

    def refresh_run_name(self) -> str | None:
        if not self.run_name:
            self.run_name = discover_run_name(self.workspace)
        return self.run_name

    def terminate(self, grace_seconds: int = 15) -> int | None:
        if self.popen.poll() is not None:
            return self.popen.returncode
        pgid = None
        try:
            pgid = os.getpgid(self.popen.pid)
        except ProcessLookupError:
            return self.popen.poll()

        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return self.popen.poll()

        deadline = time.time() + grace_seconds
        while time.time() < deadline:
            code = self.popen.poll()
            if code is not None:
                return code
            time.sleep(0.2)

        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return self.popen.wait(timeout=5)


def build_strix_command(
    task: dict[str, Any],
    *,
    settings: Settings,
    target: str,
    resume: str | None = None,
) -> list[str]:
    cmd = [settings.strix_bin, "-n"]
    if resume:
        cmd.extend(["--resume", resume])
    else:
        cmd.extend(["-t", target])
        scan_mode = task.get("scan_mode") or settings.default_scan_mode
        cmd.extend(["--scan-mode", scan_mode])
        instruction = (task.get("instruction") or "").strip()
        if instruction:
            cmd.extend(["--instruction", instruction])
        budget = task.get("max_budget")
        if budget is None:
            budget = settings.default_max_budget
        if budget is not None:
            cmd.extend(["--max-budget", str(budget)])
    return cmd


def start_strix(
    task: dict[str, Any],
    *,
    settings: Settings,
    target: str,
    resume: str | None = None,
) -> StrixProcess:
    workspace = Path(task["workspace"])
    logs = workspace / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log_path = logs / "strix.log"

    cmd = build_strix_command(task, settings=settings, target=target, resume=resume)
    logger.info("starting strix task=%s cmd=%s cwd=%s", task["id"], cmd, workspace)

    log_file = log_path.open("a", encoding="utf-8")
    try:
        popen = subprocess.Popen(
            cmd,
            cwd=str(workspace),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            env=os.environ.copy(),
        )
    except Exception:
        log_file.close()
        raise

    # Keep the file handle open for the subprocess lifetime; close on process end.
    process = StrixProcess(popen, workspace, log_path)
    process._log_file = log_file  # type: ignore[attr-defined]
    return process


def close_process_logs(process: StrixProcess) -> None:
    handle = getattr(process, "_log_file", None)
    if handle is not None:
        try:
            handle.close()
        except OSError:
            pass
        process._log_file = None  # type: ignore[attr-defined]


def strix_available(settings: Settings) -> bool:
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
