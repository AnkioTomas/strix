"""Tests for the host-side ocr_image tool."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from agents.tool_context import ToolContext
from PIL import Image

from strix.tools.ocr import tool as ocr_tool


@pytest.fixture(autouse=True)
def _reset_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ocr_tool, "_ENGINE", None)
    monkeypatch.setattr(ocr_tool, "_ENGINE_ERROR", None)


def _png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), color=(255, 0, 0)).save(buf, format="PNG")
    return buf.getvalue()


def _ctx_with_session(payload: bytes) -> ToolContext[dict[str, Any]]:
    handle = MagicMock()
    handle.read.return_value = payload
    session = MagicMock()
    session.read = AsyncMock(return_value=handle)
    return ToolContext(
        context={"sandbox_session": session},
        tool_name="ocr_image",
        tool_call_id="call-ocr-1",
        tool_arguments="{}",
    )


@pytest.mark.asyncio
async def test_ocr_image_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = __import__

    def _blocked(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "rapidocr_onnxruntime":
            raise ImportError("nope")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked)
    raw = await ocr_tool.ocr_image.on_invoke_tool(
        _ctx_with_session(_png_bytes()),
        json.dumps({"path": "/workspace/.agent-browser-screenshots/a.png"}),
    )
    result = json.loads(raw)
    assert result["success"] is False
    assert "OCR import failed" in result["error"]


@pytest.mark.asyncio
async def test_ocr_image_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeEngine:
        def __call__(self, _img: Any) -> tuple[list[Any], float]:
            return (
                [
                    [[[0, 0], [1, 0], [1, 1], [0, 1]], "Hello", 0.99],
                    [[[0, 0], [1, 0], [1, 1], [0, 1]], "世界", 0.88],
                ],
                0.01,
            )

    monkeypatch.setattr(ocr_tool, "_ENGINE", _FakeEngine())
    raw = await ocr_tool.ocr_image.on_invoke_tool(
        _ctx_with_session(_png_bytes()),
        json.dumps({"path": "/workspace/.agent-browser-screenshots/a.png"}),
    )
    result = json.loads(raw)
    assert result["success"] is True
    assert result["text"] == "Hello\n世界"
    assert result["line_count"] == 2
    assert result["lines"][0]["confidence"] == 0.99


def test_normalize_rejects_outside_workspace() -> None:
    with pytest.raises(ValueError, match="/workspace"):
        ocr_tool._normalize_sandbox_path("/etc/hosts")
    assert ocr_tool._normalize_sandbox_path("shots/a.png") == Path("/workspace/shots/a.png")
