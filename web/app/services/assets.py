"""Asset-centric view of pentest results, for the asset management system."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from app.db import Database
from app.services.findings import (
    _parse_address,
    bucket_severity,
    derive_address,
    empty_finding_counts,
)
from app.services.results import discover_run_name, read_run_overview, workspace_run_dir

_TAG_SPLIT = re.compile(r"[,，;；\n]+")
_MAX_TAGS = 20
_MAX_TAG_LEN = 50
# open = 尚未复测；其余为复测结论
_FIX_STATUSES = ("fixed", "not_fixed", "partial", "regressed")
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_TAG = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def parse_tags(value: object) -> list[str]:
    """Split a CSV string or list into unique, trimmed tags (order kept)."""
    if value is None:
        return []
    parts = _TAG_SPLIT.split(value) if isinstance(value, str) else [str(v) for v in value]
    tags: list[str] = []
    for part in parts:
        tag = part.strip()
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def validate_tags(value: object) -> list[str]:
    tags = parse_tags(value)
    if len(tags) > _MAX_TAGS:
        raise ValueError(f"at most {_MAX_TAGS} tags")
    if any(len(tag) > _MAX_TAG_LEN for tag in tags):
        raise ValueError(f"each tag must be at most {_MAX_TAG_LEN} characters")
    return tags


def split_address(address: str) -> tuple[str, int | None, str]:
    """``host[:port]`` -> (host, port, ``ip`` | ``domain``)."""
    host, port = address, None
    if address.startswith("["):
        host, _, rest = address[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    elif address.count(":") == 1:
        host, _, raw_port = address.partition(":")
        port = int(raw_port) if raw_port.isdigit() else None
    try:
        ipaddress.ip_address(host)
        kind = "ip"
    except ValueError:
        kind = "domain"
    return host, port, kind


def _task_addresses(task: dict[str, Any]) -> list[str]:
    if task.get("type") != "pentest":
        return []
    parsed = _parse_address(str(task.get("target") or ""))
    return [parsed[0]] if parsed else []


def _finding_address(finding: dict[str, Any]) -> str | None:
    loc = finding.get("location") or {}
    return loc.get("address") or derive_address(finding.get("asset"))


def root_task_ids(tasks: list[dict[str, Any]]) -> dict[str, str]:
    """task id -> origin task id. Only ``retest`` children (new-style) chain to a parent."""
    by_id = {str(t["id"]): t for t in tasks}
    roots: dict[str, str] = {}
    for tid in by_id:
        cur, seen = tid, {tid}
        while True:
            task = by_id[cur]
            parent = str(task.get("parent_task_id") or "")
            if task.get("action") != "retest" or parent not in by_id or parent in seen:
                break
            cur = parent
            seen.add(cur)
        roots[tid] = cur
    return roots


def build_asset_records(
    db: Database, tasks: list[dict[str, Any]], *, collapse: bool = True
) -> list[dict[str, Any]]:
    """One record per (asset, task); ``collapse`` merges retest chains into one per asset.

    A new-style retest is a child task that clones the parent's run, so its
    ``run.json`` (start time, token usage) is already cumulative: the latest
    task's numbers are used as is, never summed.
    """
    records = _build_task_records(db, tasks)
    return collapse_retests(records, tasks) if collapse else records


def _build_task_records(db: Database, tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not tasks:
        return []
    ids = [str(t["id"]) for t in tasks]
    invalid = db.invalid_finding_ids_for_tasks(ids)
    records: list[dict[str, Any]] = []
    for task in tasks:
        tid = str(task["id"])
        per_asset: dict[str, dict[str, int]] = {a: empty_finding_counts() for a in _task_addresses(task)}
        details: dict[str, list[dict[str, Any]]] = {}
        for finding in db.list_findings(task_id=tid, limit=5000):
            if str(finding.get("id")) in invalid.get(tid, set()):
                continue
            address = _finding_address(finding)
            if not address:
                continue
            counts = per_asset.setdefault(address, empty_finding_counts())
            counts[bucket_severity(finding.get("severity"))] += 1
            counts["total"] += 1
            details.setdefault(address, []).append(_finding_detail(finding))
        if not per_asset:
            continue

        workspace = Path(task["workspace"])
        run_dir = workspace_run_dir(workspace, task.get("run_name")) or workspace_run_dir(
            workspace, discover_run_name(workspace)
        )
        overview = read_run_overview(run_dir) if run_dir else {}
        usage = overview.get("llm_usage") or {}
        pentest = {
            "started_at": overview.get("scan_started_at") or task.get("started_at"),
            "finished_at": overview.get("scan_finished_at") or task.get("finished_at"),
            "duration_seconds": overview.get("duration_seconds"),
        }
        tokens = {
            "input": usage.get("input_tokens", 0),
            "output": usage.get("output_tokens", 0),
            "cached": usage.get("cached_tokens", 0),
            "total": usage.get("total_tokens", 0),
            "cost": usage.get("cost"),
        }
        for address, counts in per_asset.items():
            host, port, kind = split_address(address)
            records.append(
                {
                    "asset": address,
                    "asset_type": kind,
                    "host": host,
                    "port": port,
                    "task_id": tid,
                    "task_name": task.get("name"),
                    "status": task.get("status"),
                    "tags": _tags_for(task, counts),
                    "pentest": pentest,
                    "tokens": tokens,
                    "finding_counts": counts,
                    "findings": details.get(address, []),
                    "updated_at": task.get("updated_at"),
                    "parent_task_id": task.get("parent_task_id"),
                    "action": task.get("action"),
                }
            )
    return records


def collapse_retests(
    records: list[dict[str, Any]], tasks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge records of one asset across a retest chain; latest task wins, fix status accumulates."""
    roots = root_task_ids(tasks)
    order = {str(t["id"]): i for i, t in enumerate(sorted(tasks, key=lambda t: str(t.get("created_at"))))}
    task_by_id = {str(t["id"]): t for t in tasks}
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for rec in records:
        groups.setdefault((roots[rec["task_id"]], rec["asset"]), []).append(rec)

    merged: list[dict[str, Any]] = []
    for (root, _asset), group in groups.items():
        group.sort(key=lambda r: order[r["task_id"]])
        latest = dict(group[-1])
        findings: dict[str, dict[str, Any]] = {}
        for rec in group:
            for item in rec["findings"]:
                old = findings.get(str(item["id"]))
                new = dict(item)
                if old and new["fix_status"] == "open":
                    new["fix_status"] = old["fix_status"]
                findings[str(item["id"])] = new
        items = list(findings.values())
        counts = empty_finding_counts()
        for item in items:
            counts[item["severity"]] += 1
            counts["total"] += 1
        tags = _tags_for(task_by_id[latest["task_id"]], counts)
        for rec in group[:-1]:
            tags += [t for t in parse_tags(task_by_id[rec["task_id"]].get("tags")) if t not in tags]
        latest.update(
            findings=items,
            finding_counts=counts,
            tags=tags,
            origin_task_id=root,
            task_ids=[r["task_id"] for r in group],
            updated_at=max(str(r["updated_at"] or "") for r in group),
        )
        merged.append(latest)
    return merged


def _finding_detail(finding: dict[str, Any]) -> dict[str, Any]:
    raw = finding.get("raw") or {}
    retest = str(raw.get("retest_status") or "").strip().lower()
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": bucket_severity(finding.get("severity")),
        "vulnerability_type": finding.get("vulnerability_type"),
        "fix_status": retest if retest in _FIX_STATUSES else "open",
    }


def _tags_for(task: dict[str, Any], counts: dict[str, int]) -> list[str]:
    tags = ["渗透测试"]
    if task.get("scan_mode"):
        tags.append(str(task["scan_mode"]))
    if task.get("action") == "retest":
        tags.append("复测")
    top = next((s for s in _SEVERITY_ORDER if counts.get(s)), None)
    tags.append(_SEVERITY_TAG[top] if top else "无漏洞")
    for tag in parse_tags(task.get("tags")):
        if tag not in tags:
            tags.append(tag)
    return tags

