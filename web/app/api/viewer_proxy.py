"""Same-origin reverse proxy for the per-task Strix live Viewer."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from app.security.auth import require_api_key
from app.services.task_manager import TaskError, TaskManager


logger = logging.getLogger("strix-api.viewer-proxy")

VIEWER_COOKIE_PREFIX = "strix_viewer_session"
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
    "set-cookie",
}

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


def get_manager(request: Request) -> TaskManager:
    return request.app.state.manager


def viewer_proxy_path(task_id: str) -> str:
    return f"/api/v1/tasks/{task_id}/viewer/"


def parse_local_viewer(viewer_url: str) -> tuple[str, int]:
    """Return (base_url_without_trailing_slash, port). Reject non-loopback hosts."""
    parsed = urlparse(viewer_url)
    host = (parsed.hostname or "").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise TaskError("VIEWER_UNSAFE", "Viewer upstream is not loopback", 502)
    if parsed.scheme not in {"http", "https"}:
        raise TaskError("VIEWER_UNSAFE", "Viewer upstream scheme not allowed", 502)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    base = f"{parsed.scheme}://{host}:{port}"
    return base, port


def _inject_fetch_rewrite(html: bytes, proxy_prefix: str) -> bytes:
    """Rewrite absolute /api/* fetches so the Viewer SPA stays under the proxy prefix."""
    try:
        text = html.decode("utf-8")
    except UnicodeDecodeError:
        return html
    if "strix-viewer-proxy-bootstrap" in text:
        return html
    # Keep prefix without trailing slash; SPA calls start with "/api/..."
    prefix = proxy_prefix.rstrip("/")
    bootstrap = f"""<script id="strix-viewer-proxy-bootstrap">
(function () {{
  var PREFIX = {prefix!r};
  var origFetch = window.fetch.bind(window);
  function rewrite(url) {{
    if (typeof url !== "string") return url;
    if (url.startsWith("/api/") && !url.startsWith(PREFIX + "/")) {{
      return PREFIX + url;
    }}
    return url;
  }}
  window.fetch = function (input, init) {{
    if (typeof input === "string") {{
      input = rewrite(input);
    }} else if (input && typeof Request !== "undefined" && input instanceof Request) {{
      try {{
        var u = new URL(input.url, location.origin);
        if (u.origin === location.origin) {{
          var next = rewrite(u.pathname + u.search);
          if (next !== u.pathname + u.search) {{
            input = new Request(next, input);
          }}
        }}
      }} catch (e) {{}}
    }}
    return origFetch(input, init);
  }};
}})();
</script>"""
    lower = text.lower()
    idx = lower.find("</head>")
    if idx == -1:
        return (bootstrap + text).encode("utf-8")
    return (text[:idx] + bootstrap + text[idx:]).encode("utf-8")


def _error(exc: TaskError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


async def _proxy(
    task_id: str,
    path: str,
    request: Request,
    manager: TaskManager,
) -> Response:
    try:
        task = await asyncio.to_thread(manager.get_task, task_id)
    except TaskError as exc:
        return _error(exc)

    viewer_url = task.get("viewer_url")
    viewer_token = task.get("viewer_token")
    if not viewer_url or not viewer_token:
        return _error(TaskError("VIEWER_NOT_READY", "Viewer not available for this task", 409))

    try:
        base, port = parse_local_viewer(viewer_url)
    except TaskError as exc:
        return _error(exc)

    rel = path.lstrip("/")
    upstream_path = f"/{rel}" if rel else "/"
    query = request.url.query
    upstream = f"{base}{upstream_path}"
    if query:
        upstream = f"{upstream}?{query}"

    cookie_name = f"{VIEWER_COOKIE_PREFIX}_{port}"
    headers: dict[str, str] = {
        "Cookie": f"{cookie_name}={viewer_token}",
        "Accept": request.headers.get("accept", "*/*"),
    }
    content_type = request.headers.get("content-type")
    if content_type:
        headers["Content-Type"] = content_type

    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
            upstream_resp = await client.request(
                request.method,
                upstream,
                content=body if body else None,
                headers=headers,
            )
    except httpx.HTTPError as exc:
        logger.warning("viewer proxy upstream error task=%s err=%s", task_id, exc)
        return _error(TaskError("VIEWER_UNAVAILABLE", f"Viewer upstream error: {exc}", 502))

    out_headers: dict[str, str] = {}
    for key, value in upstream_resp.headers.multi_items():
        if key.lower() in HOP_BY_HOP:
            continue
        out_headers[key] = value

    content = upstream_resp.content
    ctype = (upstream_resp.headers.get("content-type") or "").lower()
    is_html = "text/html" in ctype or (
        not rel and upstream_resp.status_code == 200 and content[:64].lstrip().startswith(b"<!")
    )
    if is_html and upstream_resp.status_code == 200:
        content = _inject_fetch_rewrite(content, viewer_proxy_path(task_id).rstrip("/"))
        out_headers.pop("content-length", None)

    return Response(
        content=content,
        status_code=upstream_resp.status_code,
        headers=out_headers,
    )


@router.api_route("/tasks/{task_id}/viewer", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
@router.api_route(
    "/tasks/{task_id}/viewer/{path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy_viewer(
    task_id: str,
    request: Request,
    path: str = "",
    manager: TaskManager = Depends(get_manager),
) -> Response:
    return await _proxy(task_id, path, request, manager)


def attach_viewer_proxy_url(task: dict[str, Any]) -> dict[str, Any]:
    data = dict(task)
    if task.get("viewer_url") and task.get("viewer_token"):
        data["viewer_proxy_url"] = viewer_proxy_path(task["id"])
    else:
        data["viewer_proxy_url"] = None
    return data
