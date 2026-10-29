"""Runtime configuration for the Strix worker node."""

from __future__ import annotations

import logging
import socket
from functools import lru_cache
from pathlib import Path
from typing import Self

from dotenv import load_dotenv
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


WEB_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = WEB_ROOT.parent

logger = logging.getLogger(__name__)


def load_web_dotenv() -> Path | None:
    """Load ``web/.env`` (then repo ``.env``) into ``os.environ``.

    Shell exports always win (``override=False``). LLM keys live in the process
    env and are read by the Strix core, not only by web ``Settings``.
    """
    for path in (WEB_ROOT / ".env", REPO_ROOT / ".env"):
        if path.is_file():
            load_dotenv(path, override=False)
            logger.info("loaded env file %s", path)
            return path
    return None


load_web_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(WEB_ROOT / ".env", REPO_ROOT / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    api_key: str = Field(default="", alias="STRIX_API_KEY")
    auth_disabled: bool = Field(default=False, alias="STRIX_API_AUTH_DISABLED")

    node_id: str = Field(default="", alias="STRIX_NODE_ID")

    data_dir: Path = Field(default=WEB_ROOT / "data", alias="STRIX_API_DATA_DIR")
    max_concurrent: int = Field(default=8, ge=1, alias="STRIX_MAX_CONCURRENT")
    task_cpu_percent: float = Field(default=30.0, gt=0.0, alias="STRIX_TASK_CPU_PERCENT")
    task_memory_gb: float = Field(default=2.0, gt=0.0, alias="STRIX_TASK_MEMORY_GB")
    cancel_grace_seconds: int = Field(default=15, ge=1, alias="STRIX_CANCEL_GRACE")
    sandbox_reap_interval: int = Field(default=60, ge=0, alias="STRIX_SANDBOX_REAP_INTERVAL")
    strix_bin: str = Field(default="strix", alias="STRIX_BIN")
    default_scan_mode: str = Field(default="deep", alias="STRIX_DEFAULT_SCAN_MODE")
    default_max_budget: float | None = Field(default=None, alias="STRIX_DEFAULT_MAX_BUDGET")

    pentest_allowed_targets: str = Field(default="", alias="PENTEST_ALLOWED_TARGETS")
    allow_private_targets: bool = Field(default=True, alias="STRIX_ALLOW_PRIVATE_TARGETS")

    allowed_source_root: Path | None = Field(default=None, alias="ALLOWED_SOURCE_ROOT")
    git_username: str = Field(default="", alias="STRIX_GIT_USERNAME")
    git_token: str = Field(default="", alias="STRIX_GIT_TOKEN")

    host: str = Field(default="127.0.0.1", alias="STRIX_API_HOST")
    port: int = Field(default=8787, alias="STRIX_API_PORT")

    @model_validator(mode="after")
    def git_auth_pair(self) -> Self:
        user = self.git_username.strip()
        token = self.git_token.strip()
        if bool(user) ^ bool(token):
            raise ValueError("STRIX_GIT_USERNAME and STRIX_GIT_TOKEN must be set together")
        return self

    @property
    def resolved_node_id(self) -> str:
        custom = self.node_id.strip()
        if custom:
            return custom
        return socket.gethostname()

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"

    def git_auth(self) -> tuple[str, str] | None:
        user = self.git_username.strip()
        token = self.git_token.strip()
        if user and token:
            return user, token
        return None

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
    settings.jobs_dir.mkdir(parents=True, exist_ok=True)
    return settings
