"""API authentication."""

from __future__ import annotations

from fastapi import Header, HTTPException, status

from app.config import get_settings


def require_api_key(
    authorization: str | None = Header(default=None),
) -> None:
    cfg = get_settings()
    if cfg.auth_disabled:
        return
    expected = cfg.api_key.strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": {
                    "code": "AUTH_NOT_CONFIGURED",
                    "message": "Set STRIX_API_KEY or STRIX_API_AUTH_DISABLED=1",
                }
            },
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Missing Bearer token",
                }
            },
        )
    token = authorization.removeprefix("Bearer ").strip()
    if token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Invalid API key",
                }
            },
        )
