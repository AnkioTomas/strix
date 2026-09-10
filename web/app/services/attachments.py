"""Task attachment helpers — host files mounted into the scan sandbox."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from strix.interface.utils import resolve_workspace_files


ATTACHMENTS_DIRNAME = "attachments"
MAX_ATTACHMENTS = 20
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024  # 25 MiB per file


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def attachments_dir(workspace: Path) -> Path:
    return Path(workspace) / ATTACHMENTS_DIRNAME


def safe_filename(name: str) -> str:
    base = Path(name or "file").name
    cleaned = _SAFE_NAME.sub("_", base).strip("._") or "file"
    return cleaned[:180]


def unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    index = 1
    while True:
        alt = directory / f"{stem}_{index}{suffix}"
        if not alt.exists():
            return alt
        index += 1


def save_uploads(
    workspace: Path,
    uploads: list[tuple[str, bytes]],
    *,
    max_files: int = MAX_ATTACHMENTS,
    max_bytes: int = MAX_ATTACHMENT_BYTES,
) -> list[Path]:
    """Persist uploaded ``(filename, content)`` pairs under ``attachments/``."""
    if len(uploads) > max_files:
        raise ValueError(f"Too many attachments (max {max_files})")
    dest_dir = attachments_dir(workspace)
    dest_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    for name, content in uploads:
        if len(content) > max_bytes:
            raise ValueError(
                f"Attachment '{name}' exceeds {max_bytes // (1024 * 1024)} MiB limit"
            )
        path = unique_path(dest_dir, safe_filename(name))
        path.write_bytes(content)
        saved.append(path)
    return saved


def copy_attachments(src_workspace: Path, dest_workspace: Path) -> list[Path]:
    """Copy attachment files from a parent task workspace (retry / retest)."""
    src = attachments_dir(src_workspace)
    if not src.is_dir():
        return []
    dest = attachments_dir(dest_workspace)
    dest.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for item in sorted(src.iterdir()):
        if not item.is_file():
            continue
        target = unique_path(dest, item.name)
        shutil.copy2(item, target)
        copied.append(target)
    return copied


def list_attachment_paths(workspace: Path) -> list[Path]:
    directory = attachments_dir(workspace)
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.iterdir() if path.is_file())


def resolve_task_workspace_files(workspace: Path) -> list[dict[str, str]]:
    """Build Strix ``workspace_files`` entries for files under ``attachments/``."""
    paths = list_attachment_paths(workspace)
    if not paths:
        return []
    return resolve_workspace_files([str(path) for path in paths])


def attachment_summary(workspace: Path) -> list[dict[str, Any]]:
    return [
        {
            "name": path.name,
            "size": path.stat().st_size,
            "workspace_path": f"/workspace/{path.name}",
        }
        for path in list_attachment_paths(workspace)
    ]
