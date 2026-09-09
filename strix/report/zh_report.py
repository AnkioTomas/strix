"""Chinese customer-facing penetration test report + zip delivery."""

from __future__ import annotations

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from strix.report.writer import atomic_write_text, parse_fenced_code, safe_fence


logger = logging.getLogger(__name__)

_SEVERITY_ZH: dict[str, str] = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "none": "信息",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}

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
    return _SEVERITY_ZH.get(str(severity or "info").lower(), str(severity or "信息"))


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
    # When /workspace is bind-mounted from run_dir/workspace.
    if sandbox_path.startswith("/workspace/"):
        rel = sandbox_path[len("/workspace/") :]
        candidates.append(run_dir / "workspace" / rel)
        candidates.append(run_dir / rel)
    # Already a relative deliverable path.
    candidates.append(run_dir / sandbox_path)
    return candidates


def materialize_screenshots(
    run_dir: Path,
    vulnerability_reports: list[dict[str, Any]],
    *,
    file_bytes: dict[str, bytes] | None = None,
) -> dict[str, list[str]]:
    """Copy screenshots into ``run_dir/images/`` and return relative paths per report.

    ``file_bytes`` maps sandbox absolute paths to content already pulled from
    the live sandbox session. Host-side copies under ``run_dir/workspace`` are
    preferred when present.
    """
    images_dir = run_dir / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    pulled = file_bytes or {}
    mapping: dict[str, list[str]] = {}

    for report in vulnerability_reports:
        report_id = str(report.get("id") or "vuln")
        declared = report.get("screenshots")
        declared_paths = (
            [str(p) for p in declared if p]
            if isinstance(declared, list)
            else []
        )
        paths = extract_screenshot_paths(
            report.get("evidence"),
            report.get("poc_description"),
            report.get("poc_script_code"),
            *declared_paths,
        )
        # Explicit screenshots list first, then anything cited in prose.
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
                rel = f"images/{source_name}"
                rels.append(rel)
            else:
                logger.warning(
                    "screenshot missing for %s: %s",
                    report_id,
                    sandbox_path,
                )
        if rels:
            mapping[report_id] = rels
            report["screenshot_rels"] = rels
    return mapping


def _md_table(rows: list[tuple[str, str]]) -> str:
    lines = ["| 项目 | 内容 |", "| --- | --- |"]
    for key, value in rows:
        cell = str(value or "—").replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {key} | {cell} |")
    return "\n".join(lines)


def _vuln_meta_table(report: dict[str, Any]) -> str:
    return _md_table(
        [
            ("CVSS", report.get("cvss")),
            ("CWE", report.get("cwe")),
            ("目标", report.get("target")),
            ("端点", report.get("endpoint")),
            ("方法", report.get("method")),
        ]
    )


def _engagement_type(run_record: dict[str, Any]) -> str:
    targets = run_record.get("targets_info") or []
    has_code = any(
        isinstance(t, dict) and t.get("type") in {"local_code", "repository", "git_repo"}
        for t in targets
    )
    has_url = any(
        isinstance(t, dict) and t.get("type") in {"web", "url", "domain", "ip", "api_spec"}
        for t in targets
    )
    if has_code and has_url:
        return "灰盒（源码 + 线上目标）"
    if has_code:
        return "白盒"
    return "黑盒"


def _scope_text(run_record: dict[str, Any]) -> str:
    targets = run_record.get("targets_info") or []
    parts: list[str] = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        original = target.get("original") or target.get("details", {})
        if isinstance(original, dict):
            original = original.get("url") or original.get("path") or original.get("repo_url")
        if original:
            parts.append(str(original))
    return "<br>".join(parts) if parts else "—"


def _system_name(run_record: dict[str, Any]) -> str:
    targets = run_record.get("targets_info") or []
    for target in targets:
        if isinstance(target, dict) and target.get("original"):
            return str(target["original"])
    return str(run_record.get("run_name") or "目标系统")


def render_zh_vulnerability_section(report: dict[str, Any], index: int) -> str:
    """Render one finding block for the consolidated Chinese report."""
    sev = severity_zh(report.get("severity"))
    title = report.get("title") or "未命名漏洞"
    lines: list[str] = [
        f"## {index}. [ {sev} ] {title}",
        "",
        _vuln_meta_table(report),
        "",
        "### 描述",
        "",
        str(report.get("description") or report.get("technical_analysis") or "无描述。"),
        "",
        "### 复现步骤",
        "",
    ]
    if report.get("poc_description"):
        lines.append(str(report["poc_description"]))
        lines.append("")
    if report.get("poc_script_code"):
        lines.append("**POC：**")
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
        lines.append("**漏洞截图：**")
        lines.append("")
        for i, rel in enumerate(rels, start=1):
            lines.append(f"![漏洞截图 {i}]({rel})")
            lines.append("")
    elif report.get("evidence"):
        # Keep textual evidence when no image could be materialised.
        lines.append("**证据摘录：**")
        lines.append("")
        lines.append(str(report["evidence"]))
        lines.append("")

    lines.extend(
        [
            "### 影响",
            "",
            str(report.get("impact") or "未说明。"),
            "",
            "### 修复建议",
            "",
            str(report.get("remediation_steps") or "未提供。"),
            "",
        ]
    )

    appendix_bits: list[str] = []
    if report.get("technical_analysis"):
        appendix_bits.append(str(report["technical_analysis"]))
    if report.get("assumptions"):
        appendix_bits.append(f"**前提假设：** {report['assumptions']}")
    if appendix_bits:
        lines.extend(["### 附录", "", *appendix_bits, ""])
    return "\n".join(lines)


def render_zh_penetration_report(
    *,
    run_record: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
    overview: str | None = None,
) -> str:
    """Build the Chinese consolidated penetration test report markdown."""
    system = _system_name(run_record)
    sorted_reports = sorted(
        vulnerability_reports,
        key=lambda r: (
            _SEVERITY_ORDER.get(str(r.get("severity", "info")).lower(), 5),
            str(r.get("timestamp") or ""),
        ),
    )

    if overview and overview.strip():
        overview_body = overview.strip()
    elif sorted_reports:
        top = ", ".join(
            f"{severity_zh(r.get('severity'))}·{r.get('title')}" for r in sorted_reports[:5]
        )
        overview_body = (
            f"本次测试共确认 **{len(sorted_reports)}** 个漏洞。"
            f"危害较大的问题包括：{top}。"
        )
    else:
        overview_body = "本次测试未确认可复现的高价值漏洞；建议持续关注权限边界与输入校验硬化。"

    meta = _md_table(
        [
            ("系统名称", system),
            ("技术架构", run_record.get("tech_stack") or "见测试范围与目标技术识别结果"),
            ("测试标准", "OWASP WSTG / PTES"),
            ("评估类型", _engagement_type(run_record)),
            ("测试范围", _scope_text(run_record)),
        ]
    )

    lines: list[str] = [
        f"# {system}安全渗透测试报告",
        "",
        meta,
        "",
        "# 测试概述",
        "",
        overview_body,
        "",
        "# 漏洞清单",
        "",
    ]
    if not sorted_reports:
        lines.append("本次测试未发现可复现漏洞。")
        lines.append("")
    else:
        for index, report in enumerate(sorted_reports, start=1):
            lines.append(render_zh_vulnerability_section(report, index))
            lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_zh_delivery_bundle(
    run_dir: Path,
    *,
    run_record: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
    overview: str | None = None,
    file_bytes: dict[str, bytes] | None = None,
) -> Path:
    """Write Chinese markdown, materialise images, and zip them for delivery.

    Returns the path of ``penetration_test_report.zip``.
    """
    materialize_screenshots(run_dir, vulnerability_reports, file_bytes=file_bytes)
    md = render_zh_penetration_report(
        run_record=run_record,
        vulnerability_reports=vulnerability_reports,
        overview=overview,
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
    logger.info("Wrote Chinese delivery bundle: %s", zip_path)
    return zip_path
