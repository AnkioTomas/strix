"""Export Caido's captured traffic to disk so it can be analysed after the scan.

Opt-in via ``STRIX_EXPORT_TRAFFIC``. Writes, under ``<run_dir>/traffic/``:

- ``requests.jsonl``: one JSON object per exchange with the raw request and
  response bytes base64-encoded (lossless).
- ``traffic.har``: a HAR 1.2 file (open in Chrome DevTools, Burp, Fiddler...).
"""

from __future__ import annotations

import base64
import json
import logging
import os
from datetime import UTC
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from strix.tools.proxy import caido_api


if TYPE_CHECKING:
    from pathlib import Path

    from caido_sdk_client import Client


logger = logging.getLogger(__name__)

EXPORT_ENV = "STRIX_EXPORT_TRAFFIC"
MAX_ENTRIES_ENV = "STRIX_EXPORT_TRAFFIC_MAX"
DEFAULT_MAX_ENTRIES = 20000
MAX_BODY_BYTES = 5 * 1024 * 1024
PAGE_SIZE = 100
TRAFFIC_DIR = "traffic"


def enabled() -> bool:
    return (os.environ.get(EXPORT_ENV) or "").strip().lower() in {"1", "true", "yes", "on"}


def _max_entries() -> int:
    try:
        return max(1, int(os.environ.get(MAX_ENTRIES_ENV) or DEFAULT_MAX_ENTRIES))
    except ValueError:
        return DEFAULT_MAX_ENTRIES


def _split(raw: bytes) -> tuple[list[str], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    return head.decode("iso-8859-1", errors="replace").split("\r\n"), body


def _headers(lines: list[str]) -> list[dict[str, str]]:
    out = []
    for line in lines:
        if ":" in line:
            name, value = line.split(":", 1)
            out.append({"name": name.strip(), "value": value.strip()})
    return out


def _content(body: bytes, headers: list[dict[str, str]]) -> dict[str, Any]:
    mime = next((h["value"] for h in headers if h["name"].lower() == "content-type"), "")
    body = body[:MAX_BODY_BYTES]
    try:
        return {"size": len(body), "mimeType": mime, "text": body.decode("utf-8")}
    except UnicodeDecodeError:
        return {
            "size": len(body),
            "mimeType": mime,
            "text": base64.b64encode(body).decode(),
            "encoding": "base64",
        }


def _iso(value: Any) -> str:
    if hasattr(value, "astimezone"):
        return str(value.astimezone(UTC).isoformat()).replace("+00:00", "Z")
    return str(value)


def _har_entry(meta: dict[str, Any], req_raw: bytes, resp_raw: bytes | None) -> dict[str, Any]:
    req_lines, req_body = _split(req_raw)
    req_headers = _headers(req_lines[1:])
    scheme = "https" if meta["is_tls"] else "http"
    url = f"{scheme}://{meta['host']}:{meta['port']}{meta['path']}"
    if meta["query"]:
        url += f"?{meta['query']}"
    request: dict[str, Any] = {
        "method": meta["method"],
        "url": url,
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": req_headers,
        "queryString": [{"name": k, "value": v} for k, v in parse_qsl(meta["query"] or "")],
        "headersSize": -1,
        "bodySize": len(req_body),
    }
    if req_body:
        mime = next((h["value"] for h in req_headers if h["name"].lower() == "content-type"), "")
        request["postData"] = {"mimeType": mime, "text": req_body.decode("utf-8", "replace")}
    response: dict[str, Any] = {
        "status": 0,
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": [],
        "content": {"size": 0, "mimeType": ""},
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": 0,
    }
    if resp_raw:
        resp_lines, resp_body = _split(resp_raw)
        status = resp_lines[0].split(" ", 2)
        resp_headers = _headers(resp_lines[1:])
        response.update(
            status=int(status[1]) if len(status) > 1 and status[1].isdigit() else 0,
            statusText=status[2] if len(status) > 2 else "",
            headers=resp_headers,
            content=_content(resp_body, resp_headers),
            bodySize=len(resp_body),
        )
    return {
        "startedDateTime": meta["created_at"],
        "time": meta.get("roundtrip_ms") or 0,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"send": 0, "wait": meta.get("roundtrip_ms") or 0, "receive": 0},
        "_caido_id": meta["id"],
    }


async def export_traffic(client: Client, run_dir: Path) -> dict[str, Any]:
    """Write requests.jsonl and traffic.har; returns ``{"entries": n, "dir": ...}``."""
    out_dir = run_dir / TRAFFIC_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    limit = _max_entries()
    entries: list[dict[str, Any]] = []
    cursor: str | None = None
    with (out_dir / "requests.jsonl").open("w", encoding="utf-8") as jsonl:
        while len(entries) < limit:
            page = await caido_api.list_requests_with_client(
                client,
                first=min(PAGE_SIZE, limit - len(entries)),
                after=cursor,
                sort_by="timestamp",
                sort_order="asc",
            )
            for edge in page.edges:
                req = edge.node.request
                resp = edge.node.response
                meta = {
                    "id": req.id,
                    "host": req.host,
                    "port": req.port,
                    "method": req.method,
                    "path": req.path,
                    "query": req.query,
                    "is_tls": req.is_tls,
                    "created_at": _iso(req.created_at),
                    "status_code": resp.status_code if resp is not None else None,
                    "roundtrip_ms": resp.roundtrip_time if resp is not None else None,
                }
                try:
                    full = await caido_api.get_request_with_client(client, req.id)
                except Exception:  # noqa: BLE001
                    logger.warning("traffic export: cannot fetch %s", req.id, exc_info=True)
                    continue
                if full is None:
                    continue
                req_raw = full.request.raw or b""
                resp_raw = full.response.raw if full.response is not None else None
                jsonl.write(
                    json.dumps(
                        {
                            **meta,
                            "request_raw_b64": base64.b64encode(req_raw[:MAX_BODY_BYTES]).decode(),
                            "response_raw_b64": base64.b64encode(
                                (resp_raw or b"")[:MAX_BODY_BYTES]
                            ).decode(),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                entries.append(_har_entry(meta, req_raw, resp_raw))
            if not page.page_info.has_next_page:
                break
            cursor = page.page_info.end_cursor
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "strix-caido-export", "version": "1"},
            "entries": entries,
        }
    }
    (out_dir / "traffic.har").write_text(json.dumps(har, ensure_ascii=False), encoding="utf-8")
    return {"entries": len(entries), "dir": str(out_dir)}
