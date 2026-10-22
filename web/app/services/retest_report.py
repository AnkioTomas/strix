"""Customer markdown for a retest task: results first, no re-written findings."""

from __future__ import annotations

from typing import Any

from app.services.findings import apply_address

RETEST_REPORT_MARKER = "<!-- retest-report -->"

_SEVERITY_ORDER = {key: i for i, key in enumerate(("critical", "high", "medium", "low", "info"))}

_TEXT = {
    "zh": {
        "status": {"fixed": "已修复", "not_fixed": "未修复", "partial": "部分修复", "regressed": "回归恶化"},
        "untested": "未复测",
        "severity": {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"},
        "title": "复测报告",
        "overview": "复测概述",
        "summary": "复测情况",
        "details": "复测详情",
        "col_finding": "漏洞",
        "col_status": "状态",
        "col_address": "地址",
        "untitled": "未命名漏洞",
        "address": "**地址：**",
        "steps": "复测步骤",
        "no_steps": "未提供复测步骤。",
        "evidence": "复测证据",
        "screenshot": "复测截图",
        "remediation": "修复建议",
        "none": "本次没有复测的漏洞。",
        "paren": ("（", "）"),
        "sep": "，",
    },
    "en": {
        "status": {"fixed": "Fixed", "not_fixed": "Not fixed", "partial": "Partially fixed", "regressed": "Regressed"},
        "untested": "Not retested",
        "severity": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "title": "Retest Report",
        "overview": "Retest Overview",
        "summary": "Retest Results",
        "details": "Retest Details",
        "col_finding": "Finding",
        "col_status": "Status",
        "col_address": "Address",
        "untitled": "Untitled finding",
        "address": "**Address:**",
        "steps": "Retest Steps",
        "no_steps": "No retest steps provided.",
        "evidence": "Retest Evidence",
        "screenshot": "Retest screenshot",
        "remediation": "Remediation",
        "none": "No findings were retested.",
        "paren": (" (", ")"),
        "sep": ", ",
    },
}


def _status(report: dict[str, Any]) -> str:
    return str(report.get("retest_status") or "").strip().lower()


def _status_label(report: dict[str, Any], t: dict[str, Any]) -> str:
    return t["status"].get(_status(report), t["untested"])


def _address(report: dict[str, Any]) -> str:
    finding = apply_address(
        {
            "asset": report.get("target"),
            "location": {"url": report.get("endpoint")} if report.get("endpoint") else {},
        }
    )
    return str((finding.get("location") or {}).get("address") or report.get("target") or "")


def _cell(value: object) -> str:
    return str(value or "—").replace("|", "\\|").replace("\n", "<br>")


def _text(report: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(report.get(key) or "").strip()
        if value:
            return value
    return ""


def _screenshots(report: dict[str, Any]) -> list[str]:
    rels = report.get("screenshot_rels") or report.get("screenshots") or []
    if not isinstance(rels, list):
        return []
    return [str(r) for r in rels if str(r).strip().startswith("images/")]


def _overview(
    reports: list[dict[str, Any]], executive_summary: str, t: dict[str, Any], lang: str
) -> str:
    if executive_summary.strip():
        return executive_summary.strip()
    if not reports:
        return t["none"]
    counts: dict[str, int] = {}
    for report in reports:
        label = _status_label(report, t)
        counts[label] = counts.get(label, 0) + 1
    if lang == "zh":
        detail = t["sep"].join(f"{label} {n} 项" for label, n in counts.items())
        return f"本次对 {len(reports)} 项漏洞进行了复测：{detail}。"
    detail = t["sep"].join(f"{label}: {n}" for label, n in counts.items())
    return f"{len(reports)} finding(s) were retested — {detail}."


def _finding_block(index: int, report: dict[str, Any], t: dict[str, Any]) -> list[str]:
    title = str(report.get("title") or t["untitled"])
    left, right = t["paren"]
    status = f"{left}{_status_label(report, t)}{right}"
    if _status(report) == "fixed":
        return [f"## {index}. {title}{status}", ""]

    severity = t["severity"].get(str(report.get("severity") or "").lower(), t["severity"]["info"])
    lines = [f"## {index}. [ {severity} ] {title}{status}", ""]
    address = _address(report)
    if address:
        lines += [f"{t['address']} {address}", ""]
    steps = _text(report, "fix_verification", "poc_description")
    lines += [f"### {t['steps']}", "", steps or t["no_steps"], ""]
    evidence = _text(report, "evidence")
    shots = _screenshots(report)
    if evidence or shots:
        lines += [f"### {t['evidence']}", ""]
        if evidence:
            lines += [evidence, ""]
        lines += [f"![{t['screenshot']} {n}]({shot})" for n, shot in enumerate(shots, start=1)]
        if shots:
            lines.append("")
    remediation = _text(report, "remediation_steps")
    if remediation:
        lines += [f"### {t['remediation']}", "", remediation, ""]
    return lines


def render_retest_report(
    *,
    run_record: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
    scan_results: dict[str, Any] | None = None,
    lang: str = "zh",
    scope_ids: set[str] | None = None,
) -> str:
    """``scope_ids`` limits a focused retest; otherwise every finding is listed.

    Findings the agent did not mark show as "not retested" instead of vanishing.
    """
    t = _TEXT[lang if lang in _TEXT else "zh"]
    lang = "en" if t is _TEXT["en"] else "zh"
    reports = [
        r
        for r in vulnerability_reports
        if scope_ids is None or str(r.get("id") or r.get("report_id") or "") in scope_ids
    ]
    reports.sort(
        key=lambda r: (
            _SEVERITY_ORDER.get(str(r.get("severity") or "").lower(), 5),
            str(r.get("timestamp") or ""),
        )
    )
    system = ""
    for target in run_record.get("targets_info") or []:
        if isinstance(target, dict) and target.get("original"):
            system = str(target["original"])
            break
    system = system or str(run_record.get("run_name") or "")
    summary = str((scan_results or {}).get("executive_summary") or "")

    suffix = f" {t['title']}" if lang == "en" else t["title"]
    lines = [
        RETEST_REPORT_MARKER,
        f"# {system}{suffix}" if system else f"# {t['title']}",
        "",
        f"# {t['overview']}",
        "",
        _overview(reports, summary, t, lang),
        "",
    ]
    if reports:
        lines += [
            f"# {t['summary']}",
            "",
            f"| {t['col_finding']} | {t['col_status']} | {t['col_address']} |",
            "| --- | --- | --- |",
        ]
        lines += [
            f"| {_cell(r.get('title'))} | {_status_label(r, t)} | {_cell(_address(r))} |"
            for r in reports
        ]
        lines += ["", f"# {t['details']}", ""]
        for index, report in enumerate(reports, start=1):
            lines += _finding_block(index, report, t)
    return "\n".join(lines).rstrip() + "\n"
