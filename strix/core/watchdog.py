"""Per-scan watchdog: hourly progress requests and stall / out-of-credit alerts.

Runs in its own daemon thread so it keeps working when the scan's event loop
is busy. It only acts when a Feishu channel is configured, because every
output of it is a message to the human operator.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from strix.core.agents import TERMINAL_STATUSES, AgentCoordinator
from strix.notify import feishu


logger = logging.getLogger(__name__)

PROGRESS_ENV = "STRIX_WATCHDOG_PROGRESS_SECONDS"
STALL_ENV = "STRIX_WATCHDOG_STALL_SECONDS"
DEFAULT_PROGRESS_SECONDS = 3600
DEFAULT_STALL_SECONDS = 7200
CHECK_INTERVAL_SECONDS = 30

_LOG_TAIL_LINES = 400
_LOG_REPORT_LINES = 40
_LOG_REPORT_CHARS = 2500

_PROBLEM_LINE = re.compile(
    r"\b(ERROR|CRITICAL|WARNING|Traceback|Exception)\b|[A-Za-z]+Error\b"
    r"|status[_ ]?code[=: ]*[45]\d\d",
    re.IGNORECASE,
)
_OUT_OF_CREDIT = re.compile(
    r"insufficient[_ ]?(quota|funds|balance|credit)|exceeded your current quota|quota[_ ]exceeded"
    r"|out of credits?|credits? (exhausted|depleted)|billing[_ ]?(hard[_ ]?limit|not active|issue)"
    r"|payment[_ ]required|\b402\b|account[_ ]?(balance|suspended|deactivated|overdue)"
    r"|arrears|overdue|余额不足|余额|欠费|额度(不足|已用尽|用尽)|配额(不足|已用尽)|账户.{0,6}(停用|冻结)",
    re.IGNORECASE,
)


def _env_seconds(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def classify_log(lines: list[str]) -> tuple[str, str]:
    """Return ``("out_of_credit" | "stalled", evidence_text)`` for recent log lines."""
    problems = [line for line in lines if _PROBLEM_LINE.search(line)]
    pool = problems or lines
    for line in reversed(pool):
        if _OUT_OF_CREDIT.search(line):
            return "out_of_credit", line.strip()[:_LOG_REPORT_CHARS]
    tail = "\n".join(pool[-_LOG_REPORT_LINES:])
    return "stalled", tail[-_LOG_REPORT_CHARS:]


def read_log_tail(path: Path, max_lines: int = _LOG_TAIL_LINES) -> list[str]:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return [line.rstrip("\n") for line in deque(handle, maxlen=max_lines)]
    except OSError:
        return []


def total_tokens(report_state: Any) -> int:
    try:
        usage = report_state.get_total_llm_usage()
    except Exception:
        logger.debug("watchdog: cannot read llm usage", exc_info=True)
        return 0
    if not isinstance(usage, dict):
        return 0
    total = int(usage.get("total_tokens") or 0)
    if total:
        return total
    return int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0)


class ScanWatchdog:
    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        coordinator: AgentCoordinator,
        report_state: Any,
        run_dir: Path,
        scan_id: str,
        progress_seconds: int | None = None,
        stall_seconds: int | None = None,
        check_interval: float = CHECK_INTERVAL_SECONDS,
    ) -> None:
        self._loop = loop
        self._coordinator = coordinator
        self._report_state = report_state
        self._log_path = Path(run_dir) / "strix.log"
        self._scan_id = scan_id
        self._progress = (
            _env_seconds(PROGRESS_ENV, DEFAULT_PROGRESS_SECONDS)
            if progress_seconds is None
            else progress_seconds
        )
        self._stall = (
            _env_seconds(STALL_ENV, DEFAULT_STALL_SECONDS)
            if stall_seconds is None
            else stall_seconds
        )
        self._check_interval = check_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return feishu.configured() and (self._progress > 0 or self._stall > 0)

    def start(self) -> bool:
        if not self.enabled:
            logger.info("watchdog disabled (no Feishu channel or both intervals are 0)")
            return False
        self._thread = threading.Thread(
            target=self._run, name=f"strix-watchdog-{self._scan_id}", daemon=True
        )
        self._thread.start()
        logger.info(
            "watchdog started (progress every %ss, stall after %ss)", self._progress, self._stall
        )
        return True

    def stop(self) -> None:
        self._stop.set()

    # --- loop ---

    def _run(self) -> None:
        now = time.monotonic()
        last_progress = now
        last_tokens = total_tokens(self._report_state)
        last_change = now
        while not self._stop.wait(self._check_interval):
            try:
                now = time.monotonic()
                if self._finished():
                    return
                tokens = total_tokens(self._report_state)
                if tokens != last_tokens or self._only_waiting_on_user():
                    last_tokens, last_change = tokens, now
                if self._progress > 0 and now - last_progress >= self._progress:
                    last_progress = now
                    self._request_progress()
                if self._stall > 0 and now - last_change >= self._stall:
                    last_change = now
                    self._alert_stall(self._stall)
            except Exception:
                logger.exception("watchdog iteration failed")

    def _root_id(self) -> str | None:
        for agent_id, parent in dict(self._coordinator.parent_of).items():
            if parent is None:
                return str(agent_id)
        return None

    def _finished(self) -> bool:
        root = self._root_id()
        return root is not None and self._coordinator.statuses.get(root) in TERMINAL_STATUSES

    def _only_waiting_on_user(self) -> bool:
        statuses = dict(self._coordinator.statuses)
        wait_kinds = dict(self._coordinator.wait_kinds)
        live = [aid for aid, status in statuses.items() if status not in TERMINAL_STATUSES]
        if not live:
            return False
        return all(wait_kinds.get(aid) == "user" for aid in live)

    # --- actions ---

    def _request_progress(self) -> None:
        root = self._root_id()
        if root is None or self._only_waiting_on_user():
            return
        message = {
            "from": "system",
            "type": "instruction",
            "priority": "normal",
            "content": (
                "[watchdog] Hourly progress check. Call notify_user now with a short report "
                "for the operator: what is done, what you and your sub-agents are working on, "
                "findings so far, and anything blocking you. Then continue your work — do NOT "
                "call wait_for_user unless you need an answer."
            ),
        }
        future = asyncio.run_coroutine_threadsafe(self._coordinator.send(root, message), self._loop)
        try:
            delivered = future.result(timeout=15)
        except Exception:
            logger.exception("watchdog: progress request failed")
            return
        logger.info("watchdog: progress request delivered=%s", delivered)

    def _alert_stall(self, stall_seconds: int) -> None:
        kind, evidence = classify_log(read_log_tail(self._log_path))
        hours = stall_seconds / 3600
        if kind == "out_of_credit":
            title = "Strix：疑似余额/额度不足"
            body = (
                f"扫描 {self._scan_id} 的 token 用量已 {hours:g} 小时没有变化，"
                f"最新错误日志命中余额/额度关键词，疑似模型账户没钱了：\n{evidence}"
            )
        else:
            title = "Strix：任务可能卡住"
            body = (
                f"扫描 {self._scan_id} 的 token 用量已 {hours:g} 小时没有变化，"
                "没有匹配到余额不足的特征，可能卡住了。最近的日志原文：\n"
                f"{evidence or '(日志为空)'}"
            )
        ok, detail = feishu.send(body, title=title, level="error")
        logger.info("watchdog: stall alert kind=%s sent=%s (%s)", kind, ok, detail)
