"""Master-managed runtime config for the worker node.

The node only needs bootstrap values locally (API key, bind address, data dir).
Model / LLM credentials, proxies, capacity and Git credentials are pushed by the
master via ``PUT /v1/config`` and persisted in ``<data_dir>/node-config.json``.
New scans inherit the values through the process environment.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import Settings


logger = logging.getLogger(__name__)

CONFIG_FILE = "node-config.json"

_ENV_ALLOWED = re.compile(
    r"^(STRIX_|LLM_|OPENAI_|ANTHROPIC_|AZURE_|GEMINI_|VERTEX_|AWS_|PERPLEXITY_|"
    r"HTTP_PROXY$|HTTPS_PROXY$|NO_PROXY$|ALL_PROXY$)",
    re.IGNORECASE,
)
# Bootstrap/identity values stay local so the master cannot lock itself out.
_ENV_RESERVED = re.compile(r"^STRIX_(API_|BIN$|NODE_ID$)", re.IGNORECASE)
_SECRET = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD)", re.IGNORECASE)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")

_lock = threading.Lock()


class SettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_concurrent: int | None = Field(default=None, ge=1, le=256)
    task_cpu_percent: float | None = Field(default=None, gt=0.0, le=100.0)
    task_memory_gb: float | None = Field(default=None, gt=0.0)
    default_scan_mode: str | None = Field(default=None, pattern=r"^(quick|standard|deep)$")
    default_max_budget: float | None = Field(default=None, gt=0.0)
    sandbox_reap_interval: int | None = Field(default=None, ge=0)
    allow_private_targets: bool | None = None
    pentest_allowed_targets: str | None = Field(default=None, max_length=4000)
    git_username: str | None = Field(default=None, max_length=200)
    git_token: str | None = Field(default=None, max_length=500)


class ConfigPatch(BaseModel):
    """Merge patch: an env value of ``null`` removes that key."""

    model_config = ConfigDict(extra="forbid")

    env: dict[str, str | None] = Field(default_factory=dict)
    settings: SettingsPatch = Field(default_factory=SettingsPatch)

    @field_validator("env")
    @classmethod
    def check_env(cls, value: dict[str, str | None]) -> dict[str, str | None]:
        for name, val in value.items():
            if not _ENV_NAME.match(name) or not _ENV_ALLOWED.match(name) or _ENV_RESERVED.match(name):
                raise ValueError(f"env key not allowed: {name}")
            if val is not None and ("\x00" in val or len(val) > 8000):
                raise ValueError(f"invalid value for {name}")
        return value


def _path(settings: Settings) -> Path:
    return settings.data_dir / CONFIG_FILE


def _load(settings: Settings) -> dict[str, Any]:
    path = _path(settings)
    if not path.is_file():
        return {"env": {}, "settings": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("ignoring unreadable %s", path)
        return {"env": {}, "settings": {}}
    return {"env": dict(data.get("env") or {}), "settings": dict(data.get("settings") or {})}


def _save(settings: Settings, data: dict[str, Any]) -> None:
    path = _path(settings)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _apply(settings: Settings, data: dict[str, Any], removed: list[str] | None = None) -> None:
    for name in removed or []:
        os.environ.pop(name, None)
    for name, value in data["env"].items():
        os.environ[name] = value
    for name, value in data["settings"].items():
        setattr(settings, name, value)
        # Detached scan workers rebuild Settings from the environment.
        alias = Settings.model_fields[name].alias
        os.environ[alias] = ("1" if value else "0") if isinstance(value, bool) else str(value)


def apply_saved(settings: Settings) -> None:
    """Re-apply the persisted master config at node startup."""
    with _lock:
        _apply(settings, _load(settings))


def update(settings: Settings, patch: ConfigPatch) -> dict[str, Any]:
    with _lock:
        data = _load(settings)
        removed: list[str] = []
        for name, value in patch.env.items():
            if value is None:
                data["env"].pop(name, None)
                removed.append(name)
            else:
                data["env"][name] = value
        data["settings"].update(patch.settings.model_dump(exclude_unset=True))
        data["settings"] = {k: v for k, v in data["settings"].items() if v is not None}
        _save(settings, data)
        _apply(settings, data, removed)
    return view(settings)


def view(settings: Settings) -> dict[str, Any]:
    """Current managed config with secrets reduced to a set/unset marker."""
    with _lock:
        data = _load(settings)
    env = {
        name: ("***" if _SECRET.search(name) else value) for name, value in data["env"].items()
    }
    values = dict(data["settings"])
    if values.get("git_token"):
        values["git_token"] = "***"
    return {"env": env, "settings": values}
