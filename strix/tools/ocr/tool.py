"""``ocr_image`` — local OCR over a sandbox screenshot (host-side, no Docker change)."""

from __future__ import annotations

import io
import json
import logging
import tempfile
import threading
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_MAX_IMAGE_BYTES = 10 * 1024 * 1024
_ENGINE_LOCK = threading.Lock()
_ENGINE: Any | None = None
_ENGINE_ERROR: str | None = None


def _load_engine() -> Any:
    """Lazy-load RapidOCR once. Raises RuntimeError with install hint if missing."""
    global _ENGINE, _ENGINE_ERROR  # noqa: PLW0603
    if _ENGINE is not None:
        return _ENGINE
    if _ENGINE_ERROR is not None:
        raise RuntimeError(_ENGINE_ERROR)
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            return _ENGINE
        if _ENGINE_ERROR is not None:
            raise RuntimeError(_ENGINE_ERROR)
        try:
            from rapidocr_onnxruntime import RapidOCR  # noqa: PLC0415
        except ImportError as exc:
            _ENGINE_ERROR = (
                "rapidocr_onnxruntime is missing from this Strix install. "
                "Reinstall with: pip install -e .   (or: uv sync)"
            )
            raise RuntimeError(_ENGINE_ERROR) from exc
        try:
            _ENGINE = RapidOCR()
        except Exception as exc:
            _ENGINE_ERROR = f"Failed to initialize RapidOCR: {exc}"
            raise RuntimeError(_ENGINE_ERROR) from exc
        return _ENGINE


def _normalize_sandbox_path(path: str) -> Path:
    raw = (path or "").strip()
    if not raw:
        raise ValueError("path is required")
    # Agents usually pass absolute sandbox paths from agent-browser.
    if raw.startswith("/workspace/"):
        return Path(raw)
    if raw.startswith("workspace/"):
        return Path("/workspace") / raw[len("workspace/") :]
    if raw.startswith("/"):
        raise ValueError("OCR path must be under /workspace (sandbox screenshot path)")
    return Path("/workspace") / raw


async def _read_sandbox_bytes(ctx: RunContextWrapper, path: Path) -> bytes:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    session = inner.get("sandbox_session")
    if session is None:
        raise RuntimeError("No sandbox session in tool context — cannot read image")
    handle = await session.read(path)
    data = handle.read() if hasattr(handle, "read") else handle
    if isinstance(data, memoryview):
        data = data.tobytes()
    if isinstance(data, bytearray):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise TypeError(f"Unexpected sandbox read type: {type(data).__name__}")
    return data


def _run_ocr(image_bytes: bytes) -> list[dict[str, Any]]:
    from PIL import Image  # noqa: PLC0415 — optional via strix-agent[ocr]

    if len(image_bytes) > _MAX_IMAGE_BYTES:
        raise ValueError(f"Image exceeds {_MAX_IMAGE_BYTES // (1024 * 1024)} MiB limit")
    # Validate it is an image before handing bytes to the engine.
    Image.open(io.BytesIO(image_bytes)).verify()
    engine = _load_engine()
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp.write(image_bytes)
            tmp_path = Path(tmp.name)
        result, _elapsed = engine(str(tmp_path))
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    lines: list[dict[str, Any]] = []
    if not result:
        return lines
    for item in result:
        if not isinstance(item, list | tuple) or len(item) < 2:
            continue
        text = str(item[1]).strip()
        if not text:
            continue
        score = float(item[2]) if len(item) > 2 and item[2] is not None else None
        entry: dict[str, Any] = {"text": text}
        if score is not None:
            entry["confidence"] = round(score, 4)
        lines.append(entry)
    return lines


@function_tool(timeout=60)
async def ocr_image(ctx: RunContextWrapper, path: str) -> str:
    """Extract text from a sandbox image with local OCR (no vision model).

    Use when you need readable strings from a screenshot — URLs, error
    messages, form labels, status codes — especially if ``view_image`` is
    unavailable or you only need text, not pixels in context.

    Typical flow: ``agent-browser screenshot`` → pass the printed path here.

    Args:
        path: Absolute sandbox path under ``/workspace`` (e.g.
            ``/workspace/.agent-browser-screenshots/page.png``).
    """
    try:
        sandbox_path = _normalize_sandbox_path(path)
        image_bytes = await _read_sandbox_bytes(ctx, sandbox_path)
        lines = _run_ocr(image_bytes)
    except Exception as exc:  # noqa: BLE001 — return to the agent as JSON
        logger.debug("ocr_image failed for %s", path, exc_info=True)
        return json.dumps(
            {"success": False, "path": path, "error": str(exc)},
            ensure_ascii=False,
        )

    text = "\n".join(item["text"] for item in lines)
    return json.dumps(
        {
            "success": True,
            "path": str(sandbox_path),
            "line_count": len(lines),
            "text": text,
            "lines": lines,
        },
        ensure_ascii=False,
    )
