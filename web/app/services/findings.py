"""Normalize Strix vulnerability records into the unified Finding schema."""

from __future__ import annotations

from typing import Any


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
        "poc": raw.get("poc_description") or raw.get("poc_script_code") or raw.get("poc"),
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
    return findings


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)
