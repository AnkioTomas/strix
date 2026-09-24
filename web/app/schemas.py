"""Pydantic request/response schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


ScanMode = Literal["quick", "standard", "deep"]
TaskType = Literal["pentest", "audit"]
TaskStatus = Literal[
    "held",
    "queued",
    "starting",
    "running",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
]


def normalize_earliest_start(value: str | None) -> str | None:
    """Normalize optional ISO datetime to UTC ``…Z``; empty → None."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("earliest_start must be an ISO-8601 datetime") from exc
    if dt.tzinfo is None:
        raise ValueError("earliest_start must include a timezone (Z or offset)")
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class GitSource(BaseModel):
    type: Literal["git"] = "git"
    url: str
    branch: str | None = None
    commit: str | None = None


class LocalSource(BaseModel):
    type: Literal["local"] = "local"
    path: str


Source = GitSource | LocalSource


class LLMUsageSummary(BaseModel):
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cache_write_tokens: int = 0
    total_tokens: int = 0
    cost: float | None = None


class CreateTaskRequest(BaseModel):
    type: TaskType
    target: str | None = None
    source: Source | None = None
    instruction: str | None = None
    name: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=4000)
    held: bool = False
    earliest_start: str | None = None
    scan_mode: ScanMode = "deep"
    max_budget: float | None = Field(default=None, gt=0)
    parent_task_id: str | None = None
    action: str | None = None
    # Optional agent mandates (injected into instruction at scan start).
    proxy_url: str | None = Field(default=None, max_length=500)
    use_proxy: bool = False
    request_headers: str | None = Field(default=None, max_length=8000)
    use_headers: bool = False

    @field_validator("earliest_start", mode="before")
    @classmethod
    def _normalize_earliest_start(cls, value: object) -> str | None:
        if value is None:
            return None
        return normalize_earliest_start(str(value))

    @model_validator(mode="after")
    def validate_shape(self) -> CreateTaskRequest:
        if self.type == "pentest":
            if not self.target:
                raise ValueError("pentest tasks require target")
        elif self.source is None:
            raise ValueError("audit tasks require source")
        if self.use_proxy:
            from app.services.proxy_config import ProxyValidationError, normalize_proxy_url

            try:
                normalized = normalize_proxy_url(self.proxy_url)
            except ProxyValidationError as exc:
                raise ValueError(exc.message) from exc
            if not normalized:
                raise ValueError("use_proxy requires proxy_url")
            self.proxy_url = normalized
        else:
            self.proxy_url = None
        if self.use_headers:
            from app.services.proxy_config import (
                HeadersValidationError,
                normalize_request_headers,
            )

            try:
                normalized_headers = normalize_request_headers(self.request_headers)
            except HeadersValidationError as exc:
                raise ValueError(exc.message) from exc
            if not normalized_headers:
                raise ValueError("use_headers requires request_headers")
            self.request_headers = normalized_headers
        else:
            self.request_headers = None
        return self


class UpdateTaskRequest(BaseModel):
    """Patch a task. Name/notes work in any status; scan settings only while held."""

    name: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=4000)
    instruction: str | None = None
    scan_mode: ScanMode | None = None
    max_budget: float | None = Field(default=None, gt=0)
    earliest_start: str | None = None
    target: str | None = None
    source: Source | None = None
    proxy_url: str | None = Field(default=None, max_length=500)
    use_proxy: bool | None = None
    request_headers: str | None = Field(default=None, max_length=8000)
    use_headers: bool | None = None

    @field_validator("earliest_start", mode="before")
    @classmethod
    def _normalize_earliest_start(cls, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        return normalize_earliest_start(str(value))

    @model_validator(mode="after")
    def validate_optional_http(self) -> UpdateTaskRequest:
        if self.use_proxy is True:
            from app.services.proxy_config import ProxyValidationError, normalize_proxy_url

            try:
                normalized = normalize_proxy_url(self.proxy_url)
            except ProxyValidationError as exc:
                raise ValueError(exc.message) from exc
            if not normalized:
                raise ValueError("use_proxy requires proxy_url")
            self.proxy_url = normalized
        elif self.use_proxy is False:
            self.proxy_url = None
        elif self.proxy_url is not None:
            from app.services.proxy_config import ProxyValidationError, normalize_proxy_url

            try:
                self.proxy_url = normalize_proxy_url(self.proxy_url)
            except ProxyValidationError as exc:
                raise ValueError(exc.message) from exc
        if self.use_headers is True:
            from app.services.proxy_config import (
                HeadersValidationError,
                normalize_request_headers,
            )

            try:
                normalized_headers = normalize_request_headers(self.request_headers)
            except HeadersValidationError as exc:
                raise ValueError(exc.message) from exc
            if not normalized_headers:
                raise ValueError("use_headers requires request_headers")
            self.request_headers = normalized_headers
        elif self.use_headers is False:
            self.request_headers = None
        elif self.request_headers is not None:
            from app.services.proxy_config import (
                HeadersValidationError,
                normalize_request_headers,
            )

            try:
                self.request_headers = normalize_request_headers(self.request_headers)
            except HeadersValidationError as exc:
                raise ValueError(exc.message) from exc
        return self


class ResumeTaskRequest(BaseModel):
    """Optional nudge delivered as Strix ``resume_instruction``."""

    instruction: str | None = None


class RetryTaskRequest(BaseModel):
    """Optional schedule for a retry child task."""

    earliest_start: str | None = None

    @field_validator("earliest_start", mode="before")
    @classmethod
    def _normalize_earliest_start(cls, value: object) -> str | None:
        if value is None:
            return None
        return normalize_earliest_start(str(value))


class ImportRunsRequest(BaseModel):
    """Import legacy CLI runs from a host path into new web tasks."""

    path: str = Field(min_length=1)
    dry_run: bool = False
    skip_existing: bool = True


class ImportRunItem(BaseModel):
    source_path: str
    run_name: str
    type: str | None = None
    status: str | None = None
    target: str | None = None
    scan_mode: str | None = None
    cli_status: str | None = None
    task_id: str | None = None
    reason: str | None = None
    existing_task_id: str | None = None


class ImportRunsResponse(BaseModel):
    path: str
    dry_run: bool
    imported: list[ImportRunItem]
    skipped: list[ImportRunItem]
    imported_count: int
    skipped_count: int


class FindingCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class TaskSummary(BaseModel):
    id: str
    type: TaskType
    status: TaskStatus
    name: str | None = None
    notes: str | None = None
    target: str | None = None
    source_type: str | None = None
    source_url: str | None = None
    source_branch: str | None = None
    instruction: str | None = None
    scan_mode: str | None = None
    run_name: str | None = None
    viewer_url: str | None = None
    viewer_proxy_url: str | None = None
    parent_task_id: str | None = None
    action: str | None = None
    pid: int | None = None
    exit_code: int | None = None
    error: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str | None = None
    scan_started_at: str | None = None
    scan_finished_at: str | None = None
    duration_seconds: float | None = None
    llm_usage: LLMUsageSummary | None = None
    proxy_url: str | None = None
    proxy_display: str | None = None
    request_headers: str | None = None
    earliest_start: str | None = None
    finding_counts: FindingCounts | None = None
    has_report: bool = False


class TaskListResponse(BaseModel):
    tasks: list[TaskSummary]
    total: int
    limit: int = 100
    offset: int = 0


class FindingLocation(BaseModel):
    url: str | None = None
    parameter: str | None = None
    method: str | None = None
    file: str | None = None
    line: int | None = None
    endpoint: str | None = None


class Finding(BaseModel):
    id: str
    task_id: str | None = None
    title: str
    severity: str | None = None
    confidence: str | None = None
    description: str | None = None
    asset: str | None = None
    location: FindingLocation | dict[str, Any] | None = None
    evidence: str | None = None
    poc: str | None = None
    technical_analysis: str | None = None
    screenshots: list[str] | None = None
    impact: str | None = None
    recommendation: str | None = None
    cwe: str | None = None
    cvss: float | None = None
    created_at: str | None = None
    review_status: Literal["active", "invalid"] = "active"
    request_test: bool = False


# List views only need triage columns — full PoC bodies kill the browser.
FINDING_SUMMARY_KEYS = frozenset(
    {
        "id",
        "task_id",
        "title",
        "severity",
        "confidence",
        "asset",
        "location",
        "cwe",
        "cvss",
        "created_at",
        "review_status",
        "request_test",
    }
)


def summarize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Drop narrative/PoC fields for list endpoints."""
    out = {key: finding.get(key) for key in FINDING_SUMMARY_KEYS}
    out["id"] = str(finding.get("id") or "unknown")
    out["title"] = str(finding.get("title") or "Untitled")
    return out


class FindingsResponse(BaseModel):
    task_id: str | None = None
    findings: list[Finding]


class UpdateFindingRequest(BaseModel):
    """Console-side triage for one finding (survives Strix re-ingest)."""

    review_status: Literal["active", "invalid"] | None = None
    request_test: bool | None = None

    @model_validator(mode="after")
    def require_change(self) -> UpdateFindingRequest:
        if self.review_status is None and self.request_test is None:
            raise ValueError("provide review_status and/or request_test")
        return self


class RetestTaskRequest(BaseModel):
    instruction: str | None = None
    finding_ids: list[str] | None = None


class RequestFindingTestResponse(BaseModel):
    finding: Finding
    task: TaskSummary


class ReportResponse(BaseModel):
    task_id: str
    format: str
    content: str


class EventItem(BaseModel):
    timestamp: str | None = None
    type: str | None = None
    message: str | None = None
    agent_id: str | None = None
    raw: dict[str, Any] | None = None


class EventsResponse(BaseModel):
    task_id: str
    events: list[EventItem]


class MessageCreate(BaseModel):
    content: str = Field(min_length=1)
    agent_id: str | None = None


class MessageItem(BaseModel):
    id: int
    task_id: str
    role: str
    content: str
    created_at: str
    delivered: bool = False


class MessagesResponse(BaseModel):
    task_id: str
    messages: list[MessageItem]


class ArtifactItem(BaseModel):
    name: str
    path: str
    size: int


class ArtifactsResponse(BaseModel):
    task_id: str
    artifacts: list[ArtifactItem]


class TaskLogsResponse(BaseModel):
    task_id: str
    logs: list[ArtifactItem]


class HealthResponse(BaseModel):
    status: str
    strix: bool
    worker: bool
    database: bool
    running_tasks: int
    queued_tasks: int
    admission: dict[str, Any] | None = None


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
