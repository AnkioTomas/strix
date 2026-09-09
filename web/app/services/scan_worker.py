"""Detached Strix scan worker — runs outside the API process.

Usage (invoked by the API)::

    python -m app.services.scan_worker --job /path/to/job.json

The worker owns the interactive scan + viewer. API restarts do not kill it
because it is started with ``start_new_session=True``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("strix-api.scan-worker")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detached Strix scan worker")
    parser.add_argument("--job", required=True, help="Path to job JSON written by the API")
    args = parser.parse_args(argv)

    job_path = Path(args.job)
    job = json.loads(job_path.read_text(encoding="utf-8"))
    workspace = Path(job["workspace"])
    task = job["task"]
    target = job["target"]
    task_id = task["id"]

    # Ensure web package imports work when spawned with -m.
    web_root = Path(__file__).resolve().parents[2]
    if str(web_root) not in sys.path:
        sys.path.insert(0, str(web_root))

    from app.config import get_settings, load_web_dotenv
    from app.services.scan_state import write_state
    from app.services.strix_runner import LiveStrixSession

    load_web_dotenv()
    get_settings.cache_clear()
    settings = get_settings()

    write_state(
        workspace,
        pid=os.getpid(),
        task_id=task_id,
        ready=False,
        exit_code=None,
        error=None,
        viewer_url=None,
        viewer_token=None,
        run_name=None,
        root_agent_id=None,
    )

    session = LiveStrixSession(workspace, task_id)

    def on_ready(live: LiveStrixSession) -> None:
        write_state(
            workspace,
            pid=os.getpid(),
            task_id=task_id,
            ready=True,
            run_name=live.run_name,
            viewer_url=live.viewer_url,
            viewer_token=live.viewer_token,
            root_agent_id=live.root_agent_id,
        )

    try:
        session.start(settings=settings, target=target, task=task, on_ready=on_ready)
    except Exception as exc:
        logger.exception("scan worker failed to start task=%s", task_id)
        write_state(workspace, ready=True, exit_code=1, error=str(exc), pid=os.getpid())
        return 1

    session.wait_ready(timeout=180)
    write_state(
        workspace,
        ready=True,
        run_name=session.run_name,
        viewer_url=session.viewer_url,
        viewer_token=session.viewer_token,
        root_agent_id=session.root_agent_id,
        pid=os.getpid(),
    )

    while session.poll() is None:
        # Keep root agent id fresh for post-restart message delivery.
        root = session.root_agent_id or session._discover_root()
        if root and root != session.root_agent_id:
            session.root_agent_id = root
        write_state(
            workspace,
            ready=True,
            run_name=session.run_name,
            viewer_url=session.viewer_url,
            viewer_token=session.viewer_token,
            root_agent_id=session.root_agent_id,
            pid=os.getpid(),
            exit_code=None,
        )
        time.sleep(2)

    code = session.poll()
    write_state(
        workspace,
        ready=True,
        run_name=session.run_name,
        viewer_url=session.viewer_url,
        viewer_token=session.viewer_token,
        root_agent_id=session.root_agent_id,
        pid=os.getpid(),
        exit_code=code,
        error=session._error,
    )
    logger.info("scan worker finished task=%s exit=%s", task_id, code)
    return int(code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
