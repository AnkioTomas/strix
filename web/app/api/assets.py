"""Read-only asset view of pentest results, pulled by the asset management system."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from app.schemas import normalize_earliest_start
from app.security.auth import require_api_key
from app.services.assets import build_asset_records, parse_tags, root_task_ids
from app.services.task_manager import TaskManager

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])

_STATUSES = {"completed", "failed", "cancelled", "running", "queued", "held"}
_PAGE = 500


def _bad_request(message: str) -> JSONResponse:
    return JSONResponse(
        status_code=400, content={"error": {"code": "INVALID_REQUEST", "message": message}}
    )


def _load(manager: TaskManager, status: str, since: str | None) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = manager.list_tasks(
            status=status,
            task_type="pentest",
            sort="updated_at",
            order="asc",
            limit=_PAGE,
            offset=offset,
        )
        tasks.extend(page)
        if len(page) < _PAGE:
            break
        offset += _PAGE
    if since:
        # Keep whole retest chains so a retest child never loses its parent's findings.
        roots = root_task_ids(tasks)
        fresh = {roots[str(t["id"])] for t in tasks if str(t.get("updated_at") or "") >= since}
        tasks = [t for t in tasks if roots[str(t["id"])] in fresh]
    return tasks


@router.get("/assets/pentests")
async def list_asset_pentests(
    request: Request,
    status: str = Query(default="completed", description="Comma-separated task statuses"),
    since: str | None = Query(default=None, description="ISO-8601; only tasks updated at/after"),
    tag: str | None = Query(default=None, description="Comma-separated; record must have all"),
    q: str | None = Query(default=None, description="Substring match on host:port"),
    collapse: bool = Query(default=True, description="Merge retest chains into one record per asset"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    manager: TaskManager = request.app.state.manager
    statuses = parse_tags(status)
    if not statuses or any(s not in _STATUSES for s in statuses):
        return _bad_request(f"invalid status: {status}")
    try:
        since_utc = normalize_earliest_start(since)
    except ValueError as exc:
        return _bad_request(str(exc).replace("earliest_start", "since"))
    wanted_tags = parse_tags(tag)
    needle = (q or "").strip().lower()

    def _build() -> list[dict[str, Any]]:
        tasks = _load(manager, ",".join(statuses), since_utc)
        return build_asset_records(manager.db, tasks, collapse=collapse)

    records = await asyncio.to_thread(_build)
    if wanted_tags:
        records = [r for r in records if set(wanted_tags) <= set(r["tags"])]
    if needle:
        records = [r for r in records if needle in r["asset"].lower()]
    return {
        "items": records[offset : offset + limit],
        "total": len(records),
        "limit": limit,
        "offset": offset,
    }
