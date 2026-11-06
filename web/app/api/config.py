"""Master-pushed runtime configuration (model, proxies, capacity, Git creds)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app import runtime_config
from app.runtime_config import ConfigPatch
from app.security.auth import require_api_key


router = APIRouter(prefix="/v1", dependencies=[Depends(require_api_key)])


@router.get("/config")
async def get_config(request: Request):
    return runtime_config.view(request.app.state.settings)


@router.put("/config")
async def put_config(patch: ConfigPatch, request: Request):
    return runtime_config.update(request.app.state.settings, patch)
