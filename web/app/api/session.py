"""Browser session cookie so iframe / <img> can authenticate without Bearer."""

from __future__ import annotations

from fastapi import APIRouter, Header, Request, Response, status

from app.security.auth import SESSION_COOKIE_NAME, expected_api_key, token_matches, unauthorized


router = APIRouter(prefix="/api/v1")


def _cookie_secure(request: Request) -> bool:
    """Whether Set-Cookie should include Secure.

    Must follow the *browser* scheme (or reverse-proxy proto), not the bind
    address. ``STRIX_API_HOST=0.0.0.0`` is common for LAN daemons over plain
    HTTP; forcing Secure there makes the cookie invisible to the Viewer iframe
    (which cannot send Authorization Bearer), yielding UNAUTHORIZED JSON.
    """
    forwarded = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if forwarded:
        return forwarded == "https"
    return request.url.scheme == "https"


@router.post("/session", status_code=status.HTTP_204_NO_CONTENT)
async def create_session(
    request: Request,
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

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        secure=_cookie_secure(request),
        max_age=60 * 60 * 24 * 30,
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(response: Response) -> Response:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
