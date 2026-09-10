"""Normalize Strix vulnerability records into the unified Finding schema."""

from __future__ import annotations

from typing import Any


_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def normalize_finding(raw: dict[str, Any], *, task_id: str) -> dict[str, Any]:
    location: dict[str, Any] = {}
    code_locations = raw.get("code_locations") or []
    if isinstance(code_locations, list) and code_locations:
        first = code_locations[0]
        if isinstance(first, dict):
            location = {
                "file": first.get("file") or first.get("path"),
                "line": first.get("line") or first.get("start_line"),
            }
    endpoint = raw.get("endpoint")
    if endpoint:
        location.setdefault("url", endpoint)
        location.setdefault("endpoint", endpoint)
    if raw.get("method"):
        location["method"] = raw.get("method")

    cwe = raw.get("cwe")
    if isinstance(cwe, list):
        cwe = ", ".join(str(item) for item in cwe)

    return {
        "id": str(raw.get("id") or raw.get("report_id") or "unknown"),
        "task_id": task_id,
        "title": str(raw.get("title") or "Untitled"),
        "severity": (str(raw.get("severity") or "info")).lower(),
        "confidence": raw.get("confidence"),
        "description": raw.get("description"),
        "asset": raw.get("target"),
        "location": location or None,
        "evidence": _as_text(raw.get("evidence")),
        "poc": _combine_poc(raw),
        "technical_analysis": _as_text(raw.get("technical_analysis")),
        "screenshots": _screenshot_paths(raw),
        "impact": raw.get("impact"),
        "recommendation": raw.get("remediation_steps") or raw.get("recommendation"),
        "cwe": cwe,
        "cvss": raw.get("cvss"),
        "created_at": raw.get("timestamp"),
        "raw": raw,
    }


def normalize_findings(raw_items: list[Any], *, task_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in raw_items:
        if isinstance(item, dict):
            findings.append(normalize_finding(item, task_id=task_id))
    findings.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "").lower(), 9),
            str(item.get("created_at") or ""),
            str(item.get("id") or ""),
        )
    )
    return findings


def _combine_poc(raw: dict[str, Any]) -> str | None:
    """Keep both narrative steps and the reproducible script."""
    desc = _as_text(raw.get("poc_description"))
    script = _as_text(raw.get("poc_script_code"))
    legacy = _as_text(raw.get("poc"))
    parts: list[str] = []
    if desc:
        parts.append(desc.strip())
    if script and script.strip() not in {p.strip() for p in parts}:
        parts.append(script.strip())
    if not parts and legacy:
        parts.append(legacy.strip())
    return "\n\n".join(parts) if parts else None


def _screenshot_paths(raw: dict[str, Any]) -> list[str]:
    rels = raw.get("screenshot_rels")
    if isinstance(rels, list) and rels:
        return [str(item).strip() for item in rels if str(item).strip()]
    screenshots = raw.get("screenshots")
    if not isinstance(screenshots, list):
        return []
    # Sandbox absolute paths are useless to the UI; keep basename under images/.
    out: list[str] = []
    for item in screenshots:
        text = str(item).strip()
        if not text:
            continue
        name = text.rsplit("/", 1)[-1]
        out.append(f"images/{name}" if name else text)
    return out


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)
