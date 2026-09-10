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


# Sidebar / topbar chrome that belongs to the standalone OSS viewer, not the
# embedded task console. Matched by visible label text (SPA class names churn).
_PROXY_HIDE_NAV_LABELS = (
    "Past runs",
    "Feedback & support",
    "PR Security Reviews",
    "Integrations",
    "Members",
)


def _viewer_proxy_bootstrap(proxy_prefix: str) -> str:
    """Fetch rewrite + hide Cloud/marketing chrome when Viewer is iframed."""
    prefix = proxy_prefix.rstrip("/")
    hide_labels = list(_PROXY_HIDE_NAV_LABELS)
    return f"""<style id="strix-viewer-proxy-chrome">
.strix-proxy-hide {{ display: none !important; }}
/* Fit iframe at 100% zoom: scroll inside main column, not the document/iframe chrome. */
html {{
  height: 100% !important;
  overflow: hidden !important;
  zoom: 1 !important;
}}
html, body {{
  height: 100% !important;
  max-height: 100% !important;
  margin: 0 !important;
  overflow: hidden !important;
}}
#root {{
  height: 100% !important;
  overflow: hidden !important;
}}
#root > div {{
  height: 100% !important;
  min-height: 0 !important;
  max-height: 100% !important;
  overflow: hidden !important;
}}
#root > div > div:last-child {{
  min-height: 0 !important;
  height: 100% !important;
  overflow: auto !important;
  -webkit-overflow-scrolling: touch;
}}
</style>
<script id="strix-viewer-proxy-bootstrap">
(function () {{
  var PREFIX = {prefix!r};
  var HIDE_LABELS = {hide_labels!r};
  var hideSet = Object.create(null);
  for (var i = 0; i < HIDE_LABELS.length; i++) hideSet[HIDE_LABELS[i]] = 1;

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

  function hide(el) {{
    if (el && !el.classList.contains("strix-proxy-hide")) {{
      el.classList.add("strix-proxy-hide");
    }}
  }}

  function buttonMatchesHideLabel(el) {{
    var spans = el.querySelectorAll("span");
    for (var i = 0; i < spans.length; i++) {{
      var t = (spans[i].textContent || "").trim();
      if (hideSet[t]) return true;
    }}
    return false;
  }}

  function scrubChrome() {{
    var aside = document.querySelector("aside");
    if (aside) {{
      var header = aside.querySelector(":scope > header");
      if (header) hide(header);
      var section = aside.querySelector(":scope > section");
      if (section) hide(section);
      var nav = aside.querySelector("nav");
      if (nav) {{
        var nodes = nav.querySelectorAll("button, hr");
        for (var i = 0; i < nodes.length; i++) {{
          var el = nodes[i];
          if (el.tagName === "HR") {{
            hide(el);
          }} else if (buttonMatchesHideLabel(el)) {{
            hide(el);
          }}
        }}
      }}
    }}
    var links = document.querySelectorAll("a");
    for (var j = 0; j < links.length; j++) {{
      var a = links[j];
      var text = (a.textContent || "").replace(/\\s+/g, " ").trim();
      if (text.indexOf("Run in the cloud") !== -1) hide(a);
    }}
    var paras = document.querySelectorAll("p");
    for (var k = 0; k < paras.length; k++) {{
      var p = paras[k];
      var pt = (p.textContent || "").replace(/\\s+/g, " ").trim();
      if (pt === "Run this pentest with more depth" && p.parentElement) {{
        hide(p.parentElement);
      }}
    }}
  }}

  var scheduled = false;
  function scheduleScrub() {{
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(function () {{
      scheduled = false;
      scrubChrome();
    }});
  }}

  if (typeof MutationObserver !== "undefined") {{
    new MutationObserver(scheduleScrub).observe(document.documentElement, {{
      childList: true,
      subtree: true,
    }});
  }}
  if (document.readyState === "loading") {{
    document.addEventListener("DOMContentLoaded", scrubChrome);
  }} else {{
    scrubChrome();
  }}
}})();
</script>"""


def _inject_fetch_rewrite(html: bytes, proxy_prefix: str) -> bytes:
    """Inject fetch rewrite + chrome-hide bootstrap into Viewer HTML."""
    try:
        text = html.decode("utf-8")
    except UnicodeDecodeError:
        return html
    if "strix-viewer-proxy-bootstrap" in text:
        return html
    bootstrap = _viewer_proxy_bootstrap(proxy_prefix)
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

    # Overview extras from run.json (timing + tokens). Best-effort only.
    try:
        from pathlib import Path

        from app.services.results import (
            discover_run_name,
            read_run_overview,
            workspace_run_dir,
        )

        workspace = Path(task["workspace"]) if task.get("workspace") else None
        run_name = task.get("run_name")
        run_dir = workspace_run_dir(workspace, run_name) if workspace else None
        if run_dir is None and workspace is not None:
            discovered = discover_run_name(workspace)
            if discovered:
                run_dir = workspace_run_dir(workspace, discovered)
        if run_dir is not None:
            data.update(read_run_overview(run_dir))
    except Exception:
        logger.debug("attach overview stats failed task=%s", task.get("id"), exc_info=True)
    return data
