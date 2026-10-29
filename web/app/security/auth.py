"""API authentication: fixed Bearer token only."""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from app.config import get_settings


def unauthorized(message: str = "Missing or invalid credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "UNAUTHORIZED", "message": message}},
    )


def expected_api_key() -> str | None:
    """Return configured API key, or None when auth is disabled."""
    cfg = get_settings()
    if cfg.auth_disabled:
        return None
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
    return expected


def token_matches(candidate: str | None, expected: str) -> bool:
    if not candidate:
        return False
    return secrets.compare_digest(candidate.strip(), expected)


def require_api_key(
    authorization: str | None = Header(default=None),
) -> None:
    expected = expected_api_key()
    if expected is None:
        return

    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        if token_matches(token, expected):
            return

    raise unauthorized()
