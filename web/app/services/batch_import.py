"""Parse the batch-scan spreadsheet (应用名称 / 端口 / BU / 负责人 / URL)."""

from __future__ import annotations

import io
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_ALIASES = {
    "name": ("应用名称", "应用名", "应用", "系统名称", "名称", "name"),
    "port": ("端口", "port"),
    "bu": ("bu", "事业部", "业务单元"),
    "owner": ("负责人", "责任人", "owner", "邮箱", "负责人邮箱"),
    "url": ("url", "地址", "链接", "访问地址", "域名"),
}
_POSITIONAL = ("name", "port", "bu", "owner", "url")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SheetError(ValueError):
    pass


@dataclass
class BatchRow:
    row: int
    name: str
    target: str
    bu: str
    owner: str
    emails: list[str]


def _cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def build_target(url: str, port: str) -> str:
    """URL/host plus the port column; a port already in the URL wins."""
    url = url.strip()
    port = port.strip()
    if not url or not port.isdigit():
        return url
    parts = urlsplit(url if "://" in url else f"//{url}")
    if parts.port is not None or not parts.hostname:
        return url
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    netloc = f"{host}:{port}"
    scheme = f"{parts.scheme}://" if parts.scheme else ""
    rest = parts.path + (f"?{parts.query}" if parts.query else "")
    return f"{scheme}{netloc}{rest}"


def owner_emails(owner: str, mail_domain: str = "") -> list[str]:
    emails: list[str] = []
    for part in re.split(r"[,;，；\s]+", owner):
        part = part.strip()
        if not part:
            continue
        if "@" not in part and mail_domain:
            part = f"{part}@{mail_domain.lstrip('@')}"
        if _EMAIL.match(part):
            emails.append(part)
    return emails


def parse_sheet(data: bytes, *, mail_domain: str = "") -> list[BatchRow]:
    from openpyxl import load_workbook

    try:
        sheet = load_workbook(io.BytesIO(data), read_only=True, data_only=True).active
    except Exception as exc:
        raise SheetError("无法读取 Excel 文件（需要 .xlsx）") from exc
    rows = [[_cell(v) for v in row] for row in sheet.iter_rows(values_only=True)]
    rows = [(i, r) for i, r in enumerate(rows, start=1) if any(r)]
    if not rows:
        raise SheetError("表格为空")

    header = {}
    first = [c.lower() for c in rows[0][1]]
    for key, aliases in _ALIASES.items():
        for idx, title in enumerate(first):
            if title in aliases:
                header[key] = idx
                break
    if "url" in header:
        body = rows[1:]
    else:
        # No recognisable header: fall back to column order A..E.
        header = {key: idx for idx, key in enumerate(_POSITIONAL)}
        body = rows

    def pick(row: list[str], key: str) -> str:
        idx = header.get(key)
        return row[idx] if idx is not None and idx < len(row) else ""

    result: list[BatchRow] = []
    for number, row in body:
        url = pick(row, "url")
        owner = pick(row, "owner")
        result.append(
            BatchRow(
                row=number,
                name=pick(row, "name"),
                target=build_target(url, pick(row, "port")),
                bu=pick(row, "bu"),
                owner=owner,
                emails=owner_emails(owner, mail_domain),
            )
        )
    if not result:
        raise SheetError("表格没有数据行")
    return result
