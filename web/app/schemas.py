"""Pydantic request/response schemas for the worker node."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


ScanMode = Literal["quick", "standard", "deep"]
JobType = Literal["pentest", "audit"]
JobStatus = Literal[
    "starting",
    "running",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
]


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


class CreateJobRequest(BaseModel):
    """Master → node job payload. Optional ``id`` lets the master pick the key."""

    id: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9._:-]+$")
    type: JobType
    target: str | None = None
    source: Source | None = None
    instruction: str | None = None
    name: str | None = Field(default=None, max_length=200)
    scan_mode: ScanMode = "deep"
    max_budget: float | None = Field(default=None, gt=0)
    proxy_url: str | None = Field(default=None, max_length=500)
    use_proxy: bool = False
    request_headers: str | None = Field(default=None, max_length=8000)
    use_headers: bool = False

    @model_validator(mode="after")
    def validate_shape(self) -> CreateJobRequest:
        if self.type == "pentest":
            if not self.target:
                raise ValueError("pentest jobs require target")
        elif self.source is None:
            raise ValueError("audit jobs require source")
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


class SteerRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20000)
    agent_id: str | None = None


class JobSummary(BaseModel):
    id: str
    type: JobType
    status: JobStatus
    name: str | None = None
    target: str | None = None
    source_type: str | None = None
    source_url: str | None = None
    source_path: str | None = None
    instruction: str | None = None
    scan_mode: str | None = None
    max_budget: float | None = None
    run_name: str | None = None
    pid: int | None = None
    exit_code: int | None = None
    error: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str
    finding_counts: dict[str, int] | None = None
    has_report: bool = False
    llm_usage: LLMUsageSummary | None = None
    duration_seconds: float | None = None


class JobListResponse(BaseModel):
    jobs: list[JobSummary]
    total: int


class Finding(BaseModel):
    id: str
    task_id: str
    title: str
    severity: str | None = None
    confidence: str | None = None
    description: str | None = None
    asset: str | None = None
    location: dict[str, Any] | None = None
    evidence: str | None = None
    poc: str | None = None
    technical_analysis: str | None = None
    screenshots: list[str] | None = None
    impact: str | None = None
    recommendation: str | None = None
    cwe: str | None = None
    vulnerability_type: str | None = None
    cvss: float | None = None
    created_at: str | None = None
    raw: dict[str, Any] | None = None


class JobResultResponse(BaseModel):
    job: JobSummary
    findings: list[Finding]
    finding_counts: dict[str, int]
    report_markdown: str | None = None
    overview: dict[str, Any] | None = None


class EventsResponse(BaseModel):
    events: list[dict[str, Any]]


class ArtifactsResponse(BaseModel):
    artifacts: list[dict[str, Any]]


class JobLogsResponse(BaseModel):
    logs: list[dict[str, Any]]


class NodeCapacity(BaseModel):
    max_concurrent: int
    running: int
    free_slots: int
    reason: str
    task_cpu_percent: float
    task_memory_gb: float


class NodeInfo(BaseModel):
    node_id: str
    version: str
    status: Literal["ready", "degraded", "full"]
    capacity: NodeCapacity
    system: dict[str, Any]
    jobs: list[JobSummary]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    node_id: str
    strix: bool
    worker: bool
    running_jobs: int
    free_slots: int
    admission: dict[str, Any] | None = None
