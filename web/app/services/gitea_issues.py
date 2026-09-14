"""Open and close Gitea issues for audit findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx


if TYPE_CHECKING:
    from app.config import Settings
    from app.db import Database

logger = logging.getLogger(__name__)

_CLOSE_COMMENT = "已在 Strix 控制台标记为无效。自动关闭。"
_TIMEOUT = 15.0


class GiteaError(RuntimeError):
    pass


@dataclass(frozen=True)
class GiteaRepo:
    api_base: str
    owner: str
    repo: str


def repo_from_source_url(url: str, settings: Settings) -> GiteaRepo | None:
    if settings.git_auth() is None:
        return None
    parsed = urlparse((url or "").strip())
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name:
        return None
    return GiteaRepo(api_base=f"https://{parsed.netloc}/api/v1", owner=owner, repo=name)


def create_issue(
    repo: GiteaRepo,
    token: str,
    *,
    title: str,
    body: str,
) -> tuple[int, str]:
    payload = httpx.post(
        f"{repo.api_base}/repos/{repo.owner}/{repo.repo}/issues",
        headers=_headers(token),
        json={"title": title, "body": body},
        timeout=_TIMEOUT,
    )
    if payload.status_code >= 400:
        raise GiteaError(_http_error("create issue", payload))
    data = payload.json()
    number = data.get("number")
    html_url = data.get("html_url") or ""
    if not isinstance(number, int):
        raise GiteaError("Gitea create issue response missing number")
    return number, str(html_url)


def close_issue_as_invalid(repo: GiteaRepo, token: str, number: int) -> None:
    comment = httpx.post(
        f"{repo.api_base}/repos/{repo.owner}/{repo.repo}/issues/{number}/comments",
        headers=_headers(token),
        json={"body": _CLOSE_COMMENT},
        timeout=_TIMEOUT,
    )
    if comment.status_code >= 400:
        raise GiteaError(_http_error("comment issue", comment))
    closed = httpx.patch(
        f"{repo.api_base}/repos/{repo.owner}/{repo.repo}/issues/{number}",
        headers=_headers(token),
        json={"state": "closed"},
        timeout=_TIMEOUT,
    )
    if closed.status_code >= 400:
        raise GiteaError(_http_error("close issue", closed))


def sync_open_issues(
    db: Database,
    settings: Settings,
    task: dict[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    ctx = _repo_auth(task, settings)
    if ctx is None:
        return
    repo, token = ctx
    flags = db.list_finding_flags(task["id"])
    for finding in findings:
        finding_id = str(finding.get("id") or "")
        if not finding_id:
            continue
        flag = flags.get(finding_id) or {}
        if flag.get("issue_number") is not None:
            continue
        if str(flag.get("review_status") or "") == "invalid":
            continue
        try:
            number, html_url = create_issue(
                repo,
                token,
                title=_issue_title(finding),
                body=_issue_body(finding, task),
            )
        except (GiteaError, httpx.HTTPError):
            logger.exception(
                "gitea create issue failed task=%s finding=%s",
                task.get("id"),
                finding_id,
            )
            continue
        db.set_finding_issue(
            task["id"], finding_id, issue_number=number, issue_url=html_url
        )


def close_invalid_issue(
    db: Database,
    settings: Settings,
    task: dict[str, Any],
    finding_id: str,
) -> None:
    ctx = _repo_auth(task, settings)
    if ctx is None:
        return
    flag = db.list_finding_flags(task["id"]).get(finding_id) or {}
    number = flag.get("issue_number")
    if number is None:
        return
    repo, token = ctx
    try:
        close_issue_as_invalid(repo, token, int(number))
    except (GiteaError, httpx.HTTPError):
        logger.exception(
            "gitea close issue failed task=%s finding=%s issue=%s",
            task.get("id"),
            finding_id,
            number,
        )


def _repo_auth(task: dict[str, Any], settings: Settings) -> tuple[GiteaRepo, str] | None:
    if task.get("type") != "audit" or task.get("source_type") != "git":
        return None
    auth = settings.git_auth()
    if auth is None:
        return None
    repo = repo_from_source_url(str(task.get("source_url") or ""), settings)
    if repo is None:
        return None
    return repo, auth[1]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"token {token}", "Accept": "application/json"}


def _http_error(action: str, response: httpx.Response) -> str:
    detail = (response.text or "").strip().replace("\n", " ")
    if len(detail) > 200:
        detail = detail[:200] + "…"
    return f"Gitea {action} failed HTTP {response.status_code}: {detail or 'no body'}"


def _issue_title(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity") or "info").upper()
    title = str(finding.get("title") or "Untitled").strip() or "Untitled"
    text = f"[{severity}] {title}"
    return text[:255]


def _issue_body(finding: dict[str, Any], task: dict[str, Any]) -> str:
    location = finding.get("location") or {}
    where = "—"
    if isinstance(location, dict):
        path = location.get("file")
        line = location.get("line")
        if path:
            where = f"{path}:{line}" if line is not None else str(path)
        else:
            where = str(location.get("url") or location.get("endpoint") or "—")
    parts = [
        f"- Task: `{task.get('id')}`",
        f"- Finding: `{finding.get('id')}`",
        f"- Severity: `{finding.get('severity') or 'unknown'}`",
        f"- Location: `{where}`",
    ]
    if finding.get("cwe"):
        parts.append(f"- CWE: `{finding['cwe']}`")
    parts.append("")
    description = str(finding.get("description") or "").strip()
    if description:
        parts.extend(["## 描述", "", description[:4000], ""])
    recommendation = str(finding.get("recommendation") or "").strip()
    if recommendation:
        parts.extend(["## 修复建议", "", recommendation[:4000], ""])
    return "\n".join(parts).strip() + "\n"
