"""Runtime configuration for the local Strix Security API."""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


WEB_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = WEB_ROOT.parent

logger = logging.getLogger(__name__)


def load_web_dotenv() -> Path | None:
    """Load ``web/.env`` (then repo ``.env``) into ``os.environ``.

    Shell exports always win (``override=False``). This must run before Strix
    scans: LLM keys live in the process env, not only in web ``Settings``.
    """
    for path in (WEB_ROOT / ".env", REPO_ROOT / ".env"):
        if path.is_file():
            load_dotenv(path, override=False)
            logger.info("loaded env file %s", path)
            return path
    return None


# Populate os.environ as soon as config is imported (before Settings / scans).
load_web_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(WEB_ROOT / ".env", REPO_ROOT / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_key: str = Field(default="", alias="STRIX_API_KEY")
    auth_disabled: bool = Field(default=False, alias="STRIX_API_AUTH_DISABLED")

    data_dir: Path = Field(default=WEB_ROOT / "data", alias="STRIX_API_DATA_DIR")
    # Hard ceiling; actual parallelism is packed from task CPU%/memory estimates.
    max_concurrent: int = Field(default=8, ge=1, alias="STRIX_MAX_CONCURRENT")
    # Per-task resource estimate for admission packing (top-style CPU%: 100% = 1 core).
    task_cpu_percent: float = Field(default=30.0, gt=0.0, alias="STRIX_TASK_CPU_PERCENT")
    task_memory_gb: float = Field(default=2.0, gt=0.0, alias="STRIX_TASK_MEMORY_GB")
    cancel_grace_seconds: int = Field(default=15, ge=1, alias="STRIX_CANCEL_GRACE")

    strix_bin: str = Field(default="strix", alias="STRIX_BIN")
    default_scan_mode: str = Field(default="deep", alias="STRIX_DEFAULT_SCAN_MODE")
    default_max_budget: float | None = Field(default=None, alias="STRIX_DEFAULT_MAX_BUDGET")

    # Comma-separated host/URL prefixes. Empty = no prefix allowlist.
    pentest_allowed_targets: str = Field(default="", alias="PENTEST_ALLOWED_TARGETS")
    # Local lab API: allow private/loopback by default. Set 0 to harden.
    allow_private_targets: bool = Field(default=True, alias="STRIX_ALLOW_PRIVATE_TARGETS")

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
    load_web_dotenv()
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.tasks_dir.mkdir(parents=True, exist_ok=True)
    return settings
