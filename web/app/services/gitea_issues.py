"""Create Gitea issues from audit findings (web-side only; no Strix core hooks).

Enabled when ``STRIX_GITEA_ISSUES=1`` and ``STRIX_GIT_USERNAME`` /
``STRIX_GIT_TOKEN`` are set. Only audit tasks with ``source_type=git`` sync.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse


if TYPE_CHECKING:
    from app.config import Settings

logger = logging.getLogger(__name__)

STATE_FILENAME = "gitea_issues.json"
FINDING_MARKER_RE = re.compile(r"<!--\s*strix-finding:(\S+?)\s*-->")
_SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "未知",
}
_TITLE_MAX = 200
_HTTP_TIMEOUT = 30.0


def should_sync(settings: Settings, task: dict[str, Any]) -> bool:
    if not settings.gitea_issues_enabled:
        return False
    if settings.git_auth() is None:
        return False
    if str(task.get("type") or "") != "audit":
        return False
    if str(task.get("source_type") or "") != "git":
        return False
    return bool(str(task.get("source_url") or "").strip())


def parse_repo_url(url: str) -> dict[str, str] | None:
    """Split ``https://host/owner/repo.git`` into API base / owner / repo."""
    raw = (url or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    repo = parts[-1]
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not repo:
        return None
    owner = "/".join(parts[:-1])
    if not owner:
        return None
    base = f"{parsed.scheme}://{parsed.netloc}"
    return {"base": base, "owner": owner, "repo": repo}


def finding_marker(finding_id: str) -> str:
    return f"<!-- strix-finding:{finding_id} -->"


def format_issue_title(finding: dict[str, Any]) -> str:
    fid = str(finding.get("id") or "unknown")
    severity = str(finding.get("severity") or "info").lower()
    sev = _SEVERITY_LABEL.get(severity, severity)
    title = str(finding.get("title") or "Untitled").strip() or "Untitled"
    prefix = f"[Strix:{fid}] [{sev}] "
    room = max(20, _TITLE_MAX - len(prefix))
    if len(title) > room:
        title = title[: room - 1] + "…"
    return prefix + title


def format_issue_body(finding: dict[str, Any], *, task: dict[str, Any]) -> str:
    fid = str(finding.get("id") or "unknown")
    severity = str(finding.get("severity") or "info").lower()
    sev = _SEVERITY_LABEL.get(severity, severity)
    loc = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    where = "—"
    if loc.get("file"):
        where = f"{loc.get('file')}"
        if loc.get("line") is not None:
            where = f"{where}:{loc.get('line')}"
    elif loc.get("url") or loc.get("endpoint"):
        where = str(loc.get("url") or loc.get("endpoint"))
    elif finding.get("asset"):
        where = str(finding.get("asset"))

    sections = [
        finding_marker(fid),
        "",
        f"**严重级别:** {sev} (`{severity}`)",
        f"**Finding ID:** `{fid}`",
        f"**任务:** `{task.get('id') or '—'}`"
        + (f" / {task.get('name')}" if task.get("name") else ""),
        f"**资产:** {finding.get('asset') or '—'}",
        f"**位置:** {where}",
    ]
    if finding.get("cwe"):
        sections.append(f"**CWE:** {finding.get('cwe')}")
    if finding.get("confidence"):
        sections.append(f"**置信度:** {finding.get('confidence')}")

    for heading, key in (
        ("描述", "description"),
        ("技术分析", "technical_analysis"),
        ("证据", "evidence"),
        ("PoC", "poc"),
        ("影响", "impact"),
        ("修复建议", "recommendation"),
    ):
        text = _as_text(finding.get(key))
        if text:
            sections.extend(["", f"## {heading}", "", text])

    sections.extend(
        [
            "",
            "---",
            "_由 Strix 代码审计自动创建。请勿删除文首 `strix-finding` 标记(用于去重)。_",
        ]
    )
    return "\n".join(sections).rstrip() + "\n"


def load_state(workspace: Path) -> dict[str, Any]:
    path = Path(workspace) / STATE_FILENAME
    if not path.is_file():
        return {"issues": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"issues": {}}
    if not isinstance(data, dict):
        return {"issues": {}}
    issues = data.get("issues")
    if not isinstance(issues, dict):
        issues = {}
    return {"issues": {str(k): v for k, v in issues.items() if isinstance(v, dict)}}


def save_state(workspace: Path, state: dict[str, Any]) -> None:
    path = Path(workspace) / STATE_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"issues": state.get("issues") or {}}
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def sync_findings_as_issues(
    settings: Settings,
    task: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    skip_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Create missing Gitea issues for findings. Never raises."""
    result: dict[str, Any] = {
        "enabled": False,
        "created": 0,
        "skipped": 0,
        "errors": 0,
        "issues": {},
    }
    if not should_sync(settings, task):
        return result
    result["enabled"] = True

    repo = parse_repo_url(str(task.get("source_url") or ""))
    if repo is None:
        logger.warning("gitea issues: cannot parse source_url for task %s", task.get("id"))
        result["errors"] = 1
        return result

    auth = settings.git_auth()
    assert auth is not None
    workspace = Path(str(task.get("workspace") or ""))
    if not workspace.is_dir():
        logger.warning("gitea issues: missing workspace for task %s", task.get("id"))
        result["errors"] = 1
        return result

    state = load_state(workspace)
    known = state["issues"]
    created = skipped = errors = 0
    for finding in findings:
        fid = str(finding.get("id") or "").strip()
        outcome, meta = _sync_one_finding(
            finding,
            task=task,
            repo=repo,
            auth=auth,
            known=known,
            skip_ids=skip_ids or set(),
        )
        if outcome == "created" and meta is not None and fid:
            created += 1
            known[fid] = meta
        elif outcome == "skipped":
            skipped += 1
            if meta is not None and fid:
                known[fid] = meta
        else:
            errors += 1

    state["issues"] = known
    try:
        save_state(workspace, state)
    except OSError as exc:
        logger.warning("gitea issues: cannot save state: %s", exc)
        errors += 1

    result["created"] = created
    result["skipped"] = skipped
    result["errors"] = errors
    result["issues"] = {
        fid: {"number": meta.get("number"), "url": meta.get("url")} for fid, meta in known.items()
    }
    if created or errors:
        logger.info(
            "gitea issues task=%s repo=%s/%s created=%s skipped=%s errors=%s",
            task.get("id"),
            repo["owner"],
            repo["repo"],
            created,
            skipped,
            errors,
        )
    return result


def _sync_one_finding(
    finding: dict[str, Any],
    *,
    task: dict[str, Any],
    repo: dict[str, str],
    auth: tuple[str, str],
    known: dict[str, Any],
    skip_ids: set[str],
) -> tuple[str, dict[str, Any] | None]:
    """Return ``(created|skipped|error, issue_meta_or_none)``."""
    fid = str(finding.get("id") or "").strip()
    if not fid or fid in skip_ids or fid in known:
        return "skipped", None
    try:
        existing = find_existing_issue(repo, fid, auth=auth)
        if existing is not None:
            return "skipped", existing
        created = create_issue(
            repo,
            title=format_issue_title(finding),
            body=format_issue_body(finding, task=task),
            auth=auth,
        )
    except RuntimeError as exc:
        logger.warning(
            "gitea issues: failed finding=%s task=%s: %s",
            fid,
            task.get("id"),
            exc,
        )
        return "error", None
    else:
        return "created", created


def find_existing_issue(
    repo: dict[str, str],
    finding_id: str,
    *,
    auth: tuple[str, str],
) -> dict[str, Any] | None:
    """Return ``{number, url, title}`` if an issue already carries this finding id."""
    marker = finding_marker(finding_id)
    q = f"Strix:{finding_id}"
    data = api_request(
        "GET",
        f"{repo['base']}/api/v1/repos/{urllib.parse.quote(repo['owner'], safe='')}/"
        f"{urllib.parse.quote(repo['repo'], safe='')}/issues",
        auth=auth,
        query={"state": "all", "type": "issues", "q": q, "limit": 50},
    )
    if not isinstance(data, list):
        return None
    for item in data:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "")
        body = str(item.get("body") or "")
        if f"[Strix:{finding_id}]" in title or marker in body:
            return _issue_meta(item)
        match = FINDING_MARKER_RE.search(body)
        if match and match.group(1) == finding_id:
            return _issue_meta(item)
    return None


def create_issue(
    repo: dict[str, str],
    *,
    title: str,
    body: str,
    auth: tuple[str, str],
) -> dict[str, Any]:
    data = api_request(
        "POST",
        f"{repo['base']}/api/v1/repos/{urllib.parse.quote(repo['owner'], safe='')}/"
        f"{urllib.parse.quote(repo['repo'], safe='')}/issues",
        auth=auth,
        payload={"title": title, "body": body},
    )
    if not isinstance(data, dict) or not data.get("number"):
        raise RuntimeError(f"unexpected create-issue response: {data!r}")
    return _issue_meta(data)


def api_request(
    method: str,
    url: str,
    *,
    auth: tuple[str, str],
    payload: dict[str, Any] | None = None,
    query: dict[str, str] | None = None,
) -> Any:
    if not url.startswith(("http://", "https://")):
        raise RuntimeError(f"refusing non-http URL: {url!r}")
    target = url
    if query:
        target = f"{url}?{urllib.parse.urlencode(query)}"
    headers = {
        "Accept": "application/json",
        "Authorization": _basic_auth_header(auth[0], auth[1]),
        "User-Agent": "strix-web-gitea-issues",
    }
    body: bytes | None = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = urllib.request.Request(target, data=body, headers=headers, method=method)
    # Match git clone: internal Gitea often uses a private CA / self-signed cert.
    ctx = ssl._create_unverified_context()  # noqa: S323
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT, context=ctx) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"HTTP {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"request failed: {exc.reason}") from exc
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid JSON from Gitea") from exc


def _basic_auth_header(username: str, token: str) -> str:
    token_bytes = f"{username}:{token}".encode()
    return "Basic " + base64.b64encode(token_bytes).decode("ascii")


def _issue_meta(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": int(item.get("number") or 0),
        "url": str(item.get("html_url") or item.get("url") or ""),
        "title": str(item.get("title") or ""),
    }


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value).strip()
