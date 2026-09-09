"""API authentication: Bearer token or session cookie."""

from __future__ import annotations

import secrets

from fastapi import Cookie, Header, HTTPException, status

from app.config import get_settings


SESSION_COOKIE_NAME = "strix_web_session"


def _unauthorized(message: str = "Missing or invalid credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "UNAUTHORIZED", "message": message}},
    )


def _expected_key() -> str | None:
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
    strix_web_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> None:
    expected = _expected_key()
    if expected is None:
        return

    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        if token_matches(token, expected):
            return

    if token_matches(strix_web_session, expected):
        return

    raise _unauthorized()
