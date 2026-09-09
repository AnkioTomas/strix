"""Runtime configuration for the local Strix Security API."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


WEB_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = WEB_ROOT.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", WEB_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_key: str = Field(default="", alias="STRIX_API_KEY")
    auth_disabled: bool = Field(default=False, alias="STRIX_API_AUTH_DISABLED")

    data_dir: Path = Field(default=WEB_ROOT / "data", alias="STRIX_API_DATA_DIR")
    max_concurrent: int = Field(default=1, ge=1, alias="STRIX_MAX_CONCURRENT")
    # Admission control: keep tasks queued when the host is under pressure.
    min_free_memory_gb: float = Field(default=2.0, ge=0.0, alias="STRIX_MIN_FREE_MEMORY_GB")
    max_load_per_cpu: float = Field(default=1.5, ge=0.0, alias="STRIX_MAX_LOAD_PER_CPU")
    max_task_time_seconds: int = Field(default=7200, ge=60, alias="STRIX_MAX_TASK_TIME")
    cancel_grace_seconds: int = Field(default=15, ge=1, alias="STRIX_CANCEL_GRACE")

    strix_bin: str = Field(default="strix", alias="STRIX_BIN")
    default_scan_mode: str = Field(default="standard", alias="STRIX_DEFAULT_SCAN_MODE")
    default_max_budget: float | None = Field(default=None, alias="STRIX_DEFAULT_MAX_BUDGET")

    # Comma-separated host/URL prefixes. Empty = block private targets only.
    pentest_allowed_targets: str = Field(default="", alias="PENTEST_ALLOWED_TARGETS")
    # When true, private/loopback targets are allowed (lab use only).
    allow_private_targets: bool = Field(default=False, alias="STRIX_ALLOW_PRIVATE_TARGETS")

    allowed_source_root: Path | None = Field(default=None, alias="ALLOWED_SOURCE_ROOT")
    host: str = Field(default="127.0.0.1", alias="STRIX_API_HOST")
    port: int = Field(default=8787, alias="STRIX_API_PORT")

    @property
    def database_path(self) -> Path:
        return self.data_dir / "database.sqlite"

    @property
    def tasks_dir(self) -> Path:
        return self.data_dir / "tasks"

    def allowed_target_prefixes(self) -> list[str]:
        raw = self.pentest_allowed_targets.strip()
        if not raw:
            return []
        return [part.strip() for part in raw.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.tasks_dir.mkdir(parents=True, exist_ok=True)
    return settings
