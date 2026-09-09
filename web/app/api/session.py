"""Browser session cookie so iframe / <img> can authenticate without Bearer."""

from __future__ import annotations

from fastapi import APIRouter, Header, Response, status

from app.config import get_settings
from app.security.auth import SESSION_COOKIE_NAME, expected_api_key, token_matches, unauthorized


router = APIRouter(prefix="/api/v1")


@router.post("/session", status_code=status.HTTP_204_NO_CONTENT)
async def create_session(
    response: Response,
    authorization: str | None = Header(default=None),
) -> Response:
    expected = expected_api_key()
    if expected is None:
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return response

    if not authorization or not authorization.startswith("Bearer "):
        raise unauthorized("Missing Bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    if not token_matches(token, expected):
        raise unauthorized("Invalid API key")

    secure = get_settings().host not in {"127.0.0.1", "localhost", "::1"}
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        secure=secure,
        max_age=60 * 60 * 24 * 30,
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(response: Response) -> Response:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
