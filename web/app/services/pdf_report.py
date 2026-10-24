"""Render the delivery markdown (+ screenshots) to PDF with no system dependencies."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from markdown_it import MarkdownIt
from markdown_it.token import Token
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import (
    HRFlowable,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    XPreformatted,
)
from reportlab.platypus.flowables import Flowable

FONT = "STSong-Light"
_PAGE_W, _PAGE_H = A4
_MARGIN = 18 * mm
_CONTENT_W = _PAGE_W - 2 * _MARGIN
_HEADING_SIZE = {1: 20, 2: 16, 3: 13, 4: 11.5, 5: 10.5, 6: 10}
_HTML_BR = re.compile(r"<br\s*/?>", re.IGNORECASE)


def _register_font() -> None:
    if FONT not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(UnicodeCIDFont(FONT))
        pdfmetrics.registerFontFamily(
            FONT, normal=FONT, bold=FONT, italic=FONT, boldItalic=FONT
        )


def _styles() -> dict[str, ParagraphStyle]:
    body = ParagraphStyle("body", fontName=FONT, fontSize=10, leading=15, alignment=TA_LEFT, spaceAfter=4)
    styles = {
        "body": body,
        "cell": ParagraphStyle("cell", parent=body, fontSize=8.5, leading=12, spaceAfter=0),
        "code": ParagraphStyle(
            "code",
            parent=body,
            fontSize=8,
            leading=11,
            backColor=colors.HexColor("#f4f5f7"),
            borderPadding=4,
            spaceBefore=3,
            spaceAfter=8,
        ),
    }
    for level, size in _HEADING_SIZE.items():
        styles[f"h{level}"] = ParagraphStyle(
            f"h{level}",
            parent=body,
            fontSize=size,
            leading=size * 1.35,
            spaceBefore=12 if level > 1 else 0,
            spaceAfter=6,
            textColor=colors.HexColor("#1a2b4c"),
            keepWithNext=1,
        )
    return styles


def _inline_markup(children: list[Token]) -> str:
    out: list[str] = []
    for tok in children:
        kind = tok.type
        if kind == "text":
            out.append(escape(tok.content))
        elif kind in {"softbreak"}:
            out.append(" ")
        elif kind == "hardbreak":
            out.append("<br/>")
        elif kind == "strong_open":
            out.append("<b>")
        elif kind == "strong_close":
            out.append("</b>")
        elif kind == "em_open":
            out.append("<i>")
        elif kind == "em_close":
            out.append("</i>")
        elif kind == "code_inline":
            out.append(f'<font color="#b3261e">{escape(tok.content)}</font>')
        elif kind == "link_open":
            href = escape(str(tok.attrGet("href") or ""), {'"': "&quot;"})
            out.append(f'<a href="{href}" color="#1a5fb4">')
        elif kind == "link_close":
            out.append("</a>")
        elif kind == "html_inline" and _HTML_BR.fullmatch(tok.content.strip()):
            out.append("<br/>")
    return "".join(out)


def _images(children: list[Token], run_dir: Path) -> list[Flowable]:
    flowables: list[Flowable] = []
    for tok in children:
        if tok.type != "image":
            continue
        src = str(tok.attrGet("src") or "")
        path = (run_dir / src).resolve()
        if not src or src.startswith(("http://", "https://")):
            continue
        if run_dir.resolve() not in path.parents or not path.is_file():
            continue
        try:
            img = Image(str(path))
        except Exception:
            continue
        scale = min(1.0, _CONTENT_W / img.imageWidth, (_PAGE_H * 0.6) / img.imageHeight)
        img.drawWidth, img.drawHeight = img.imageWidth * scale, img.imageHeight * scale
        img.hAlign = "LEFT"
        flowables.extend([Spacer(1, 2), img, Spacer(1, 6)])
    return flowables


def _wrap_code(text: str, size: float, width: float) -> str:
    """Hard-wrap by rendered width; XPreformatted keeps spaces but never wraps."""
    out: list[str] = []
    for line in text.rstrip("\n").expandtabs(4).split("\n"):
        current = ""
        for ch in line:
            if pdfmetrics.stringWidth(current + ch, FONT, size) > width:
                out.append(current)
                current = ""
            current += ch
        out.append(current)
    return "\n".join(out)


def _table(rows: list[list[str]], head_rows: int, styles: dict[str, ParagraphStyle]) -> Table:
    cols = max(len(r) for r in rows)
    data = [
        [Paragraph(cell or "&nbsp;", styles["cell"]) for cell in row + [""] * (cols - len(row))]
        for row in rows
    ]
    table = Table(data, colWidths=[_CONTENT_W / cols] * cols, repeatRows=head_rows)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8ccd4")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if head_rows:
        style.append(("BACKGROUND", (0, 0), (-1, head_rows - 1), colors.HexColor("#eef1f6")))
    table.setStyle(TableStyle(style))
    return table


def markdown_to_flowables(md: str, run_dir: Path) -> list[Flowable]:
    styles = _styles()
    tokens = MarkdownIt("commonmark", {"html": True}).enable("table").parse(md)
    flow: list[Flowable] = []
    lists: list[list[Any]] = []  # [ordered, counter]
    quote = 0
    bullet_pending: str | None = None
    rows: list[list[str]] = []
    head_rows = 0
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        kind = tok.type
        if kind in {"bullet_list_open", "ordered_list_open"}:
            lists.append([kind == "ordered_list_open", int(tok.attrGet("start") or 1) - 1])
        elif kind in {"bullet_list_close", "ordered_list_close"}:
            lists.pop()
        elif kind == "list_item_open" and lists:
            lists[-1][1] += 1
            bullet_pending = f"{lists[-1][1]}." if lists[-1][0] else "•"
        elif kind == "blockquote_open":
            quote += 1
        elif kind == "blockquote_close":
            quote -= 1
        elif kind == "hr":
            flow.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#c8ccd4")))
        elif kind == "heading_open":
            inline = tokens[i + 1]
            level = int(tok.tag[1])
            flow.append(Paragraph(_inline_markup(inline.children or []), styles[f"h{level}"]))
            i += 2
        elif kind == "paragraph_open":
            inline = tokens[i + 1]
            children = inline.children or []
            markup = _inline_markup(children)
            indent = 12 * len(lists) + 10 * quote
            style = ParagraphStyle("p", parent=styles["body"], leftIndent=indent)
            if markup.strip():
                if bullet_pending:
                    style = ParagraphStyle(
                        "li", parent=style, leftIndent=indent + 6, bulletIndent=indent - 6
                    )
                    flow.append(Paragraph(markup, style, bulletText=bullet_pending))
                    bullet_pending = None
                else:
                    flow.append(Paragraph(markup, style))
            flow.extend(_images(children, run_dir))
            i += 2
        elif kind in {"fence", "code_block"}:
            flow.append(
                XPreformatted(
                    escape(_wrap_code(tok.content, 8, _CONTENT_W - 12 * len(lists) - 8)),
                    styles["code"],
                )
            )
        elif kind == "table_open":
            rows, head_rows = [], 0
        elif kind == "thead_open":
            head_rows = 1
        elif kind == "tr_open":
            rows.append([])
        elif kind in {"th_open", "td_open"}:
            rows[-1].append(_inline_markup(tokens[i + 1].children or []))
            i += 2
        elif kind == "table_close" and rows:
            flow.append(_table(rows, head_rows, styles))
            flow.append(Spacer(1, 8))
        i += 1
    return flow


def _footer(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    canvas.setFont(FONT, 8)
    canvas.setFillColor(colors.HexColor("#8a8f99"))
    canvas.drawCentredString(_PAGE_W / 2, 10 * mm, str(doc.page))
    canvas.restoreState()


def render_pdf(md: str, run_dir: Path, out_path: Path, *, title: str = "") -> Path:
    """Write ``out_path``; relative image links resolve against ``run_dir``."""
    _register_font()
    tmp = out_path.with_suffix(".pdf.tmp")
    doc = SimpleDocTemplate(
        str(tmp),
        pagesize=A4,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        topMargin=_MARGIN,
        bottomMargin=18 * mm,
        title=title,
    )
    flow = markdown_to_flowables(md, run_dir) or [Paragraph(" ", _styles()["body"])]
    doc.build(flow, onFirstPage=_footer, onLaterPages=_footer)
    tmp.replace(out_path)
    return out_path

