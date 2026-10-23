"""Build a pre-filled retest task draft from a delivered report zip."""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import Any

from app.services.agent_prompts import retest_from_report_instruction

MAX_ZIP_BYTES = 25 * 1024 * 1024
MAX_MD_BYTES = 5 * 1024 * 1024

_URL = re.compile(r"https?://[^\s<>\"')）,，]+")
_ADDRESS_LINE = re.compile(r"(?:地址|Address|目标|Target)[:：*\s]*\**\s*(https?://[^\s<>\"')）,，]+)", re.I)
_FINDING = re.compile(r"^##\s+\d+\.\s+(.+)$", re.M)


class DraftError(ValueError):
    pass


def _pick_markdown(zf: zipfile.ZipFile) -> zipfile.ZipInfo:
    candidates = [
        info
        for info in zf.infolist()
        if not info.is_dir()
        and info.filename.lower().endswith(".md")
        and not info.filename.startswith("__MACOSX/")
    ]
    if not candidates:
        raise DraftError("zip 里没有找到 Markdown 报告")
    candidates.sort(key=lambda i: (i.filename.count("/"), "retest" in i.filename.lower(), i.filename))
    return candidates[0]


def build_retest_draft(data: bytes, filename: str | None = None) -> dict[str, Any]:
    if len(data) > MAX_ZIP_BYTES:
        raise DraftError(f"报告 zip 超过 {MAX_ZIP_BYTES // (1024 * 1024)} MiB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise DraftError("不是有效的 zip 文件") from exc
    with zf:
        info = _pick_markdown(zf)
        if info.file_size > MAX_MD_BYTES:
            raise DraftError("报告 Markdown 过大")
        markdown = zf.read(info).decode("utf-8", errors="replace")

    stem = Path(filename or "").stem.strip() or Path(info.filename).stem
    stem = re.sub(r"^复测[-_ ]?", "", stem)
    match = _ADDRESS_LINE.search(markdown) or _URL.search(markdown)
    target = (match.group(1) if match and match.lastindex else match.group(0)) if match else ""
    titles = [
        re.sub(r"\s*[（(][^）)]*[）)]\s*$", "", re.sub(r"^\[[^\]]*\]\s*", "", t)).strip()
        for t in _FINDING.findall(markdown)
    ]
    zip_name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(filename or "report.zip").name).strip("._") or "report.zip"
    return {
        "name": f"复测-{stem}"[:200],
        "target": target.rstrip(".,;"),
        "report_file": info.filename,
        "findings": titles,
        "instruction": retest_from_report_instruction(markdown, zip_name),
    }
