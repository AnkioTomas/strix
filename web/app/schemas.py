"""Pydantic request/response schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


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
    scan_mode: ScanMode = "deep"
    max_budget: float | None = Field(default=None, gt=0)
    parent_task_id: str | None = None
    action: str | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> CreateTaskRequest:
        if self.type == "pentest":
            if not self.target:
                raise ValueError("pentest tasks require target")
        elif self.source is None:
            raise ValueError("audit tasks require source")
        return self


class UpdateTaskRequest(BaseModel):
    """Rename and/or update notes. Omitted fields are left unchanged."""

    name: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=4000)


class ResumeTaskRequest(BaseModel):
    """Optional nudge delivered as Strix ``resume_instruction``."""

    instruction: str | None = None


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


class TaskListResponse(BaseModel):
    tasks: list[TaskSummary]
    total: int


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


class FindingsResponse(BaseModel):
    task_id: str | None = None
    findings: list[Finding]


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
