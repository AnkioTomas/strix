"""Customer-facing penetration test report + zip delivery.

Structural labels follow ``STRIX_REPORT_LANGUAGE`` (Chinese or English chrome).
Finding narrative text is whatever the agents wrote.
"""

from __future__ import annotations

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from strix.report.locale import chrome_locale, report_labels, severity_label
from strix.report.writer import atomic_write_text, parse_fenced_code, safe_fence


logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}
_RETEST_STATUS_LABEL_KEYS = {
    "fixed": "retest_fixed",
    "not_fixed": "retest_not_fixed",
    "partial": "retest_partial",
    "regressed": "retest_regressed",
}
_RETEST_TAG_KEYS = {
    "fixed": "retest_tag_fixed",
    "not_fixed": "retest_tag_not_fixed",
    "partial": "retest_tag_partial",
    "regressed": "retest_tag_regressed",
}
_ATX_HEADING_RE = re.compile(r"^(#{1,6})(\s+.*)$", re.MULTILINE)


def demote_markdown_headings(text: str, *, min_level: int = 3) -> str:
    """Raise ATX heading levels so nested prose cannot outrank section chrome.

    Agent-written fields often contain ``# 根因`` style headings. Without this,
    they become top-level TOC entries beside「测试概述」.
    """
    if not text or min_level < 1:
        return text

    def _raise(match: re.Match[str]) -> str:
        level = len(match.group(1))
        if level >= min_level:
            return match.group(0)
        return "#" * min_level + match.group(2)

    return _ATX_HEADING_RE.sub(_raise, text)

# Absolute sandbox paths and markdown image refs that point at screenshots.
_SCREENSHOT_PATH_RE = re.compile(
    r"(?:^|[\s`\"'(=])("
    r"/workspace/(?:\.agent-browser-screenshots|[^\s`\"')]+)"
    r"\.(?:png|jpe?g|gif|webp)"
    r")",
    re.IGNORECASE | re.MULTILINE,
)
_MD_IMAGE_RE = re.compile(
    r"!\[[^\]]*]\(([^)]+\.(?:png|jpe?g|gif|webp))\)",
    re.IGNORECASE,
)


def severity_zh(severity: str | None) -> str:
    """Backward-compatible severity label (follows ``STRIX_REPORT_LANGUAGE``)."""
    return severity_label(severity)


def extract_screenshot_paths(*texts: str | None) -> list[str]:
    """Return unique sandbox/host screenshot paths mentioned in report text."""
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in _SCREENSHOT_PATH_RE.finditer(text):
            path = match.group(1).strip()
            if path not in seen:
                seen.add(path)
                found.append(path)
        for match in _MD_IMAGE_RE.finditer(text):
            path = match.group(1).strip()
            if path.startswith(("http://", "https://", "data:")):
                continue
            if path not in seen:
                seen.add(path)
                found.append(path)
    return found


def _safe_image_name(report_id: str, index: int, source: Path) -> str:
    suffix = source.suffix.lower() or ".png"
    if suffix not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        suffix = ".png"
    return f"{report_id}-{index}{suffix}"


def _host_candidates(sandbox_path: str, run_dir: Path) -> list[Path]:
    """Map a container path to possible host locations under the run dir."""
    raw = Path(sandbox_path)
    candidates: list[Path] = []
    if raw.is_absolute() and raw.exists():
        candidates.append(raw)
    if sandbox_path.startswith("/workspace/"):
        rel = sandbox_path[len("/workspace/") :]
        candidates.append(run_dir / "workspace" / rel)
        candidates.append(run_dir / rel)
    candidates.append(run_dir / sandbox_path)
    return candidates


def materialize_screenshots(
    run_dir: Path,
    vulnerability_reports: list[dict[str, Any]],
    *,
    file_bytes: dict[str, bytes] | None = None,
) -> dict[str, list[str]]:
    """Copy screenshots into ``run_dir/images/`` and return relative paths per report."""
    images_dir = run_dir / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    pulled = file_bytes or {}
    mapping: dict[str, list[str]] = {}

    for report in vulnerability_reports:
        report_id = str(report.get("id") or "vuln")
        declared = report.get("screenshots")
        declared_paths = (
            [str(p) for p in declared if p] if isinstance(declared, list) else []
        )
        paths = extract_screenshot_paths(
            report.get("evidence"),
            report.get("poc_description"),
            report.get("poc_script_code"),
            *declared_paths,
        )
        ordered: list[str] = []
        for path in [*declared_paths, *paths]:
            if path not in ordered:
                ordered.append(path)

        rels: list[str] = []
        for index, sandbox_path in enumerate(ordered, start=1):
            source_name = _safe_image_name(report_id, index, Path(sandbox_path))
            dest = images_dir / source_name
            written = False
            for host_path in _host_candidates(sandbox_path, run_dir):
                if host_path.is_file():
                    dest.write_bytes(host_path.read_bytes())
                    written = True
                    break
            if not written and sandbox_path in pulled:
                dest.write_bytes(pulled[sandbox_path])
                written = True
            if written:
                rels.append(f"images/{source_name}")
            else:
                logger.warning("screenshot missing for %s: %s", report_id, sandbox_path)
        if rels:
            mapping[report_id] = rels
            report["screenshot_rels"] = rels
    return mapping


def _md_table(rows: list[tuple[str, object]], *, field: str, value: str) -> str:
    lines = [f"| {field} | {value} |", "| --- | --- |"]
    for key, cell_value in rows:
        cell = str(cell_value or "—").replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {key} | {cell} |")
    return "\n".join(lines)


def _vuln_meta_table(report: dict[str, Any]) -> str:
    labels = report_labels()
    return _md_table(
        [
            (labels["cvss"], report.get("cvss")),
            (labels["cwe"], report.get("cwe")),
            (labels["target"], report.get("target")),
            (labels["endpoint"], report.get("endpoint")),
            (labels["method"], report.get("method")),
        ],
        field=labels["field"],
        value=labels["value"],
    )


def _system_name(run_record: dict[str, Any]) -> str:
    labels = report_labels()
    targets = run_record.get("targets_info") or []
    for target in targets:
        if isinstance(target, dict) and target.get("original"):
            return str(target["original"])
    return str(run_record.get("run_name") or labels["default_system"])


def _narrative_sections(
    *,
    overview: str | None,
    scan_results: dict[str, Any] | None,
) -> list[str]:
    """Front-matter overview only — long finish_scan extras go to the appendix."""
    labels = report_labels()
    if isinstance(scan_results, dict):
        text = demote_markdown_headings(
            str(scan_results.get("executive_summary") or "").strip(),
            min_level=3,
        )
        if text:
            return [f"# {labels['overview_heading']}", "", text, ""]

    if overview and overview.strip():
        body = demote_markdown_headings(overview.strip(), min_level=3)
        return [f"# {labels['overview_heading']}", "", body, ""]
    return []


def _render_report_appendix(scan_results: dict[str, Any] | None) -> list[str]:
    """Park methodology / technical analysis / recommendations under「附录」."""
    if not isinstance(scan_results, dict):
        return []
    labels = report_labels()
    bits: list[str] = []
    for heading_key, field in (
        ("methodology_heading", "methodology"),
        ("technical_analysis_heading", "technical_analysis"),
        ("recommendations_heading", "recommendations"),
    ):
        text = demote_markdown_headings(
            str(scan_results.get(field) or "").strip(),
            min_level=3,
        )
        if not text:
            continue
        bits.extend([f"## {labels[heading_key]}", "", text, ""])
    if not bits:
        return []
    return [f"# {labels['appendix']}", "", *bits]


def _retest_status_label(status: object | None) -> str:
    labels = report_labels()
    key = _RETEST_STATUS_LABEL_KEYS.get(str(status or "").strip().lower())
    return labels[key] if key else labels["retest_unknown"]


def _retest_tag(status: object | None) -> str | None:
    """Short tag for vulnerability headings, or None when not retested."""
    key = _RETEST_TAG_KEYS.get(str(status or "").strip().lower())
    if not key:
        return None
    return report_labels()[key]


def _retest_evidence_cell(report: dict[str, Any]) -> str:
    labels = report_labels()
    bits: list[str] = []
    rels = report.get("screenshot_rels") or []
    if isinstance(rels, list):
        for i, rel in enumerate(rels, start=1):
            alt = labels["screenshot_n"].format(n=i)
            bits.append(f"![{alt}]({rel})")
    shots = report.get("screenshots") or []
    if isinstance(shots, list) and not bits:
        for shot in shots:
            if shot:
                bits.append(f"`{shot}`")
    verification = str(report.get("fix_verification") or "").strip()
    if verification:
        bits.append(verification.replace("|", "\\|").replace("\n", "<br>"))
    evidence = str(report.get("evidence") or "").strip()
    cited = extract_screenshot_paths(evidence, verification)
    if cited and not rels:
        for path in cited[:3]:
            bits.append(f"`{path}`")
    if not bits:
        return labels["retest_no_evidence"]
    # Deduplicate while preserving order.
    ordered: list[str] = []
    seen: set[str] = set()
    for bit in bits:
        if bit not in seen:
            seen.add(bit)
            ordered.append(bit)
    return "<br>".join(ordered)


def _has_retest_data(vulnerability_reports: list[dict[str, Any]]) -> bool:
    """Only show「复测情况」when agents explicitly set retest_status."""
    return any(str(r.get("retest_status") or "").strip() for r in vulnerability_reports)


def _render_retest_section(vulnerability_reports: list[dict[str, Any]]) -> list[str]:
    """Build the customer-facing retest summary table."""
    if not _has_retest_data(vulnerability_reports):
        return []
    labels = report_labels()
    rows = [
        (
            labels["retest_col_title"],
            labels["retest_col_status"],
            labels["retest_col_evidence"],
        )
    ]
    for report in vulnerability_reports:
        title = str(report.get("title") or labels["untitled"]).replace("|", "\\|")
        status = _retest_status_label(report.get("retest_status"))
        evidence = _retest_evidence_cell(report)
        rows.append((title, status, evidence))

    lines = [
        f"| {rows[0][0]} | {rows[0][1]} | {rows[0][2]} |",
        "| --- | --- | --- |",
    ]
    for title, status, evidence in rows[1:]:
        lines.append(f"| {title} | {status} | {evidence} |")
    return [f"# {labels['retest_heading']}", "", *lines, ""]


def render_zh_vulnerability_section(report: dict[str, Any], index: int) -> str:
    """Render one finding block for the consolidated delivery report."""
    labels = report_labels()
    sev = severity_label(report.get("severity"), labels)
    title = report.get("title") or labels["untitled"]
    retest = _retest_tag(report.get("retest_status"))
    heading = (
        f"## {index}. [ {sev} ] [ {retest} ] {title}"
        if retest
        else f"## {index}. [ {sev} ] {title}"
    )
    description = demote_markdown_headings(
        str(report.get("description") or labels["no_description"]),
        min_level=4,
    )
    lines: list[str] = [
        heading,
        "",
        _vuln_meta_table(report),
        "",
        f"### {labels['description']}",
        "",
        description,
        "",
        f"### {labels['reproduction']}",
        "",
    ]
    if report.get("poc_description"):
        lines.append(demote_markdown_headings(str(report["poc_description"]), min_level=4))
        lines.append("")
    if report.get("poc_script_code"):
        lines.append(f"**{labels['poc']}**")
        lines.append("")
        language, code = parse_fenced_code(str(report["poc_script_code"]))
        fence_lang = language or ""
        fence = safe_fence(code)
        lines.append(f"{fence}{fence_lang}")
        lines.append(code)
        lines.append(fence)
        lines.append("")

    rels = report.get("screenshot_rels") or []
    if isinstance(rels, list) and rels:
        lines.append(f"**{labels['screenshots']}**")
        lines.append("")
        for i, rel in enumerate(rels, start=1):
            alt = labels["screenshot_n"].format(n=i)
            lines.append(f"![{alt}]({rel})")
            lines.append("")
    elif report.get("evidence"):
        lines.append(f"**{labels['evidence_excerpt']}**")
        lines.append("")
        lines.append(demote_markdown_headings(str(report["evidence"]), min_level=4))
        lines.append("")

    lines.extend(
        [
            f"### {labels['impact']}",
            "",
            demote_markdown_headings(
                str(report.get("impact") or labels["impact_missing"]),
                min_level=4,
            ),
            "",
            f"### {labels['remediation']}",
            "",
            demote_markdown_headings(
                str(report.get("remediation_steps") or labels["remediation_missing"]),
                min_level=4,
            ),
            "",
        ]
    )

    appendix_bits: list[str] = []
    if report.get("technical_analysis"):
        appendix_bits.append(
            demote_markdown_headings(str(report["technical_analysis"]), min_level=4)
        )
        appendix_bits.append("")
    if report.get("assumptions"):
        appendix_bits.append(f"**{labels['assumptions']}** {report['assumptions']}")
        appendix_bits.append("")
    if report.get("counterevidence"):
        appendix_bits.append(f"**{labels['counterevidence']}** {report['counterevidence']}")
        appendix_bits.append("")
    if report.get("confidence"):
        appendix_bits.append(f"**{labels['confidence']}** {report['confidence']}")
        appendix_bits.append("")
    if report.get("confidence_rationale"):
        appendix_bits.append(
            f"**{labels['confidence_rationale']}** {report['confidence_rationale']}"
        )
        appendix_bits.append("")
    if report.get("severity_change_conditions"):
        appendix_bits.append(
            f"**{labels['severity_change']}** {report['severity_change_conditions']}"
        )
        appendix_bits.append("")
    if report.get("fix_verification"):
        appendix_bits.append(f"**{labels['fix_verification']}** {report['fix_verification']}")
        appendix_bits.append("")
    if report.get("retest_status"):
        status_text = _retest_status_label(report.get("retest_status"))
        if chrome_locale() == "zh":
            appendix_bits.append(f"**{labels['retest_col_status']}：** {status_text}")
        else:
            appendix_bits.append(f"**{labels['retest_col_status']}:** {status_text}")
        appendix_bits.append("")
    dep = report.get("dependency_metadata")
    if isinstance(dep, dict) and dep:
        for key, label_key in (
            ("package_name", "package_name"),
            ("package_ecosystem", "package_ecosystem"),
            ("installed_version", "installed_version"),
            ("fixed_version", "fixed_version"),
        ):
            if dep.get(key):
                if chrome_locale() == "zh":
                    appendix_bits.append(f"**{labels[label_key]}：** {dep[key]}")
                else:
                    appendix_bits.append(f"**{labels[label_key]}:** {dep[key]}")
        appendix_bits.append("")
    locations = report.get("code_locations")
    if isinstance(locations, list):
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            file_path = loc.get("file") or "unknown"
            appendix_bits.append(f"**{labels['code_location']}** `{file_path}`")
            snippet = loc.get("snippet")
            if snippet:
                fence = safe_fence(str(snippet))
                appendix_bits.extend([f"{fence}", str(snippet), fence, ""])
            else:
                appendix_bits.append("")
    if appendix_bits:
        lines.extend([f"### {labels['appendix']}", "", *appendix_bits])
    return "\n".join(lines).rstrip()


def render_zh_penetration_report(
    *,
    run_record: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
    overview: str | None = None,
    scan_results: dict[str, Any] | None = None,
) -> str:
    """Build the consolidated penetration test report markdown.

    Top matter is agent narrative only. Findings are structurally assembled;
    each finding is an ``h2``.
    """
    labels = report_labels()
    system = _system_name(run_record)
    sorted_reports = sorted(
        vulnerability_reports,
        key=lambda r: (
            _SEVERITY_ORDER.get(str(r.get("severity", "info")).lower(), 5),
            str(r.get("timestamp") or ""),
        ),
    )

    title = (
        f"# {system}{labels['report_title_suffix']}"
        if chrome_locale() == "zh"
        else f"# {system} — {labels['report_title_suffix']}"
    )

    lines: list[str] = [title, ""]
    narrative = _narrative_sections(overview=overview, scan_results=scan_results)
    if narrative:
        lines.extend(narrative)
    elif sorted_reports:
        top = ", ".join(
            f"{severity_label(r.get('severity'), labels)}·{r.get('title')}"
            for r in sorted_reports[:5]
        )
        lines.extend(
            [
                f"# {labels['overview_heading']}",
                "",
                labels["overview_with_findings"].format(
                    count=len(sorted_reports),
                    top=top,
                ),
                "",
            ]
        )
    else:
        lines.extend(
            [
                f"# {labels['overview_heading']}",
                "",
                labels["overview_clean"],
                "",
            ]
        )

    lines.extend(_render_retest_section(sorted_reports))

    lines.extend([f"# {labels['findings_heading']}", ""])
    if not sorted_reports:
        lines.append(labels["no_findings"])
        lines.append("")
    else:
        for index, report in enumerate(sorted_reports, start=1):
            lines.append(render_zh_vulnerability_section(report, index))
            lines.append("")
            lines.append("---")
            lines.append("")

    lines.extend(_render_report_appendix(scan_results))

    return "\n".join(lines).rstrip() + "\n"


def write_zh_delivery_bundle(
    run_dir: Path,
    *,
    run_record: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
    overview: str | None = None,
    scan_results: dict[str, Any] | None = None,
    file_bytes: dict[str, bytes] | None = None,
) -> Path:
    """Write delivery markdown, materialise images, and zip them.

    Returns the path of ``penetration_test_report.zip``.
    """
    materialize_screenshots(run_dir, vulnerability_reports, file_bytes=file_bytes)
    md = render_zh_penetration_report(
        run_record=run_record,
        vulnerability_reports=vulnerability_reports,
        overview=overview,
        scan_results=scan_results,
    )
    md_path = run_dir / "penetration_test_report.md"
    atomic_write_text(md_path, md)

    zip_path = run_dir / "penetration_test_report.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(md_path, arcname="penetration_test_report.md")
        images_dir = run_dir / "images"
        if images_dir.is_dir():
            for image in sorted(images_dir.iterdir()):
                if image.is_file():
                    zf.write(image, arcname=f"images/{image.name}")
    logger.info("Wrote delivery bundle: %s", zip_path)
    return zip_path
