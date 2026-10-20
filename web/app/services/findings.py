"""Normalize Strix vulnerability records into the unified Finding schema."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit


_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}

FINDING_COUNT_KEYS = ("critical", "high", "medium", "low", "info")


def empty_finding_counts() -> dict[str, int]:
    return dict.fromkeys(FINDING_COUNT_KEYS, 0) | {"total": 0}


def bucket_severity(severity: object) -> str:
    key = str(severity or "info").strip().lower()
    return key if key in FINDING_COUNT_KEYS else "info"


def tally_finding_counts(
    items: list[dict[str, Any]],
    *,
    invalid_ids: set[str] | None = None,
) -> dict[str, int]:
    """Count active findings by severity. Unknown buckets fold into info."""
    skip = invalid_ids or set()
    counts = empty_finding_counts()
    for item in items:
        fid = str(item.get("id") or item.get("report_id") or "")
        if fid and fid in skip:
            continue
        sev = bucket_severity(item.get("severity"))
        counts[sev] += 1
        counts["total"] += 1
    return counts


_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
_FILE_SUFFIXES = frozenset(
    {"json", "lock", "py", "js", "ts", "go", "xml", "yml", "yaml", "txt", "md", "toml", "mod", "sum"}
)
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def _looks_like_host(host: str, *, has_port: bool) -> bool:
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return True
    if "." not in host:
        return has_port and bool(re.fullmatch(r"[a-z0-9-]+", host))
    return has_port or host.rsplit(".", 1)[1] not in _FILE_SUFFIXES


def _parse_address(value: str) -> tuple[str, bool] | None:
    """Return (``host[:port]``, explicit_port) for a URL / host / host:port string."""
    value = value.strip()
    if not value or any(ch.isspace() for ch in value):
        return None
    has_scheme = bool(_SCHEME_RE.match(value))
    try:
        parts = urlsplit(value if has_scheme else f"//{value}")
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if not host or (not has_scheme and not _looks_like_host(host, has_port=port is not None)):
        return None
    explicit = port is not None
    if port is None and has_scheme:
        port = _DEFAULT_PORTS.get(parts.scheme.lower())
    if ":" in host:
        host = f"[{host}]"
    return (f"{host}:{port}" if port else host), explicit


def derive_address(*values: object) -> str | None:
    """``host:port`` from the first usable value, preferring one with an explicit port."""
    found = [r for v in values if isinstance(v, str) and (r := _parse_address(v))]
    for address, explicit in found:
        if explicit:
            return address
    return found[0][0] if found else None


def apply_address(finding: dict[str, Any]) -> dict[str, Any]:
    """Show network findings as host:port instead of a path.

    Idempotent, so rows cached before this existed are migrated on read.
    """
    loc = finding.get("location")
    loc = dict(loc) if isinstance(loc, dict) else {}
    if not loc.get("file"):
        address = loc.get("address") or derive_address(
            finding.get("asset"), loc.get("url"), loc.get("endpoint")
        )
        if address:
            loc["address"] = address
            for key in ("url", "endpoint", "method"):
                loc.pop(key, None)
    finding["location"] = loc or None
    return finding


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

    cwe = raw.get("cwe")
    if isinstance(cwe, list):
        cwe = ", ".join(str(item) for item in cwe)

    return apply_address({
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
        "vulnerability_type": raw.get("vulnerability_type"),
        "cvss": raw.get("cvss"),
        "created_at": raw.get("timestamp"),
        "raw": raw,
    })


def normalize_findings(raw_items: list[Any], *, task_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in raw_items:
        if isinstance(item, dict):
            findings.append(normalize_finding(item, task_id=task_id))
    return sort_findings(findings)


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Severity first (critical→info), then time, then id — stable for the UI list."""
    findings.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "").lower(), 9),
            str(item.get("created_at") or ""),
            str(item.get("id") or ""),
        )
    )
    return findings


def apply_finding_flags(
    findings: list[dict[str, Any]],
    flags: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach console review flags without mutating Strix source reports."""
    for item in findings:
        flag = flags.get(str(item.get("id") or ""), {})
        item["review_status"] = str(flag.get("review_status") or "active")
        item["request_test"] = bool(flag.get("request_test"))
    return findings


def invalid_finding_ids(flags: dict[str, dict[str, Any]]) -> set[str]:
    return {
        fid
        for fid, flag in flags.items()
        if str(flag.get("review_status") or "") == "invalid"
    }


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
