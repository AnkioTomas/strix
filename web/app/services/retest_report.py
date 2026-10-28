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
        "col_severity": "等级",
        "col_finding": "漏洞",
        "col_status": "复测情况",
        "col_address": "地址",
        "brackets": ("【", "】"),
        "title_join": "",
        "untitled": "未命名漏洞",
        "address": "**地址：**",
        "steps": "复测步骤",
        "no_steps": "未提供复测步骤。",
        "evidence": "复测证据",
        "screenshot": "复测截图",
        "remediation": "修复建议",
        "none": "本次没有复测的漏洞。",
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
        "col_severity": "Severity",
        "col_finding": "Finding",
        "col_status": "Retest Result",
        "col_address": "Address",
        "brackets": ("[", "]"),
        "title_join": " ",
        "untitled": "Untitled finding",
        "address": "**Address:**",
        "steps": "Retest Steps",
        "no_steps": "No retest steps provided.",
        "evidence": "Retest Evidence",
        "screenshot": "Retest screenshot",
        "remediation": "Remediation",
        "none": "No findings were retested.",
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


_OPEN_STATUSES = ("not_fixed", "partial", "regressed")


def _overview(
    reports: list[dict[str, Any]], executive_summary: str, t: dict[str, Any], lang: str
) -> str:
    if not reports:
        return t["none"]
    fixed = sum(1 for r in reports if _status(r) == "fixed")
    untested = sum(1 for r in reports if _status(r) not in t["status"])
    open_by_severity: dict[str, int] = {}
    for report in reports:
        if _status(report) in _OPEN_STATUSES:
            key = str(report.get("severity") or "").lower()
            if key not in _SEVERITY_ORDER:
                key = "info"
            open_by_severity[key] = open_by_severity.get(key, 0) + 1
    open_total = sum(open_by_severity.values())
    severity_bits = [
        (key, open_by_severity[key])
        for key in _SEVERITY_ORDER
        if open_by_severity.get(key)
    ]
    if lang == "zh":
        bits = [f"已修复 {fixed} 项"]
        if open_total:
            detail = "、".join(f"{t['severity'][key]} {n} 项" for key, n in severity_bits)
            bits.append(f"仍有 {open_total} 项未完全修复（{detail}）")  # noqa: RUF001
        if untested:
            bits.append(f"另有 {untested} 项未复测")
        lead = f"本次对 {len(reports)} 项漏洞进行了复测：{'，'.join(bits)}。"  # noqa: RUF001
    else:
        bits = [f"{fixed} fixed"]
        if open_total:
            detail = ", ".join(f"{t['severity'][key]}: {n}" for key, n in severity_bits)
            bits.append(f"{open_total} not fully remediated ({detail})")
        if untested:
            bits.append(f"{untested} not retested")
        lead = f"Retested {len(reports)} finding(s): {', '.join(bits)}."
    if executive_summary.strip():
        return f"{lead}\n\n{executive_summary.strip()}"
    return lead


def _finding_block(report: dict[str, Any], t: dict[str, Any]) -> list[str]:
    title = str(report.get("title") or t["untitled"])
    severity = t["severity"].get(str(report.get("severity") or "").lower(), t["severity"]["info"])
    open_b, close_b = t["brackets"]
    heading = (
        f"### {open_b}{severity}{close_b}{open_b}{_status_label(report, t)}{close_b}"
        f"{t['title_join']}{title}"
    )
    if _status(report) == "fixed":
        return [heading, ""]

    lines = [heading, ""]
    address = _address(report)
    if address:
        lines += [f"{t['address']} {address}", ""]
    steps = _text(report, "fix_verification", "poc_description")
    lines += [f"**{t['steps']}**", "", steps or t["no_steps"], ""]
    evidence = _text(report, "evidence")
    shots = _screenshots(report)
    if evidence or shots:
        lines += [f"**{t['evidence']}**", ""]
        if evidence:
            lines += [evidence, ""]
        lines += [f"![{t['screenshot']} {n}]({shot})" for n, shot in enumerate(shots, start=1)]
        if shots:
            lines.append("")
    remediation = _text(report, "remediation_steps")
    if remediation:
        lines += [f"**{t['remediation']}**", "", remediation, ""]
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
        f"## {t['overview']}",
        "",
        _overview(reports, summary, t, lang),
        "",
    ]
    if reports:
        lines += [
            f"## {t['summary']}",
            "",
            f"| {t['col_severity']} | {t['col_finding']} | {t['col_status']} | {t['col_address']} |",
            "| --- | --- | --- | --- |",
        ]
        lines += [
            f"| {t['severity'].get(str(r.get('severity') or '').lower(), t['severity']['info'])}"
            f" | {_cell(r.get('title'))} | {_status_label(r, t)} | {_cell(_address(r))} |"
            for r in reports
        ]
        lines += ["", f"## {t['details']}", ""]
        for report in reports:
            lines += _finding_block(report, t)
    return "\n".join(lines).rstrip() + "\n"
