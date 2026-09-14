"""Gitea env credentials: validation, GIT_ASKPASS injection (no host allowlist)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from app.config import Settings
from app.schemas import GitSource
from app.security.source import SourceValidationError, validate_source
from app.services import git_clone
from app.services.git_askpass import PASSWORD_ENV, USERNAME_ENV, answer
from app.services.git_clone import GitError, clone_repository
from pydantic import ValidationError


def _settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    username: str = "",
    token: str = "",
) -> Settings:
    monkeypatch.setenv("STRIX_GIT_USERNAME", username)
    monkeypatch.setenv("STRIX_GIT_TOKEN", token)
    monkeypatch.delenv("STRIX_GIT_HOSTS", raising=False)
    return Settings()


def test_settings_username_and_token_must_be_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="must be set together"):
        _settings(monkeypatch, username="bot")
    with pytest.raises(ValidationError, match="must be set together"):
        _settings(monkeypatch, token="s3cret")  # noqa: S106


def test_settings_auth_pair_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch, username="bot", token="s3cret")  # noqa: S106
    assert settings.git_auth() == ("bot", "s3cret")


def test_settings_no_auth_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    assert settings.git_auth() is None


def test_reject_url_userinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch, username="bot", token="s3cret")  # noqa: S106
    with pytest.raises(SourceValidationError, match="must not contain credentials"):
        validate_source(
            GitSource(url="https://bot:s3cret@gitea.example.com/org/repo.git"),
            settings,
        )


def test_accept_any_https_host(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch, username="bot", token="s3cret")  # noqa: S106
    monkeypatch.setattr(
        "app.security.source.socket.getaddrinfo",
        lambda *_a, **_k: [(0, 0, 0, "", ("1.2.3.4", 443))],
    )
    out = validate_source(
        GitSource(url="https://gitea.example.com/org/repo.git"),
        settings,
    )
    assert out.url == "https://gitea.example.com/org/repo.git"


def test_clone_injects_askpass_when_auth_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(monkeypatch, username="bot", token="s3cret")  # noqa: S106
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    dest = tmp_path / "repo"
    clone_repository("https://gitea.example.com/org/repo.git", dest, settings=settings)

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:3] == ["git", "clone", "--depth"]
    assert "https://gitea.example.com/org/repo.git" in cmd
    assert "s3cret" not in cmd
    assert "bot" not in cmd

    env = captured["env"]
    assert isinstance(env, dict)
    assert env["GIT_ASKPASS"].endswith("git_askpass.py")
    assert env[USERNAME_ENV] == "bot"
    assert env[PASSWORD_ENV] == "s3cret"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_SSL_NO_VERIFY"] == "1"
    assert env["GIT_CONFIG_KEY_1"] == "http.sslVerify"
    assert env["GIT_CONFIG_VALUE_1"] == "false"


def test_clone_no_inject_without_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(monkeypatch)
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    clone_repository(
        "https://gitea.example.com/org/repo.git", tmp_path / "repo", settings=settings
    )

    env = captured["env"]
    assert isinstance(env, dict)
    assert "GIT_ASKPASS" not in env
    assert USERNAME_ENV not in env
    assert PASSWORD_ENV not in env
    assert env["GIT_SSL_NO_VERIFY"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.sslVerify"
    assert env["GIT_CONFIG_VALUE_0"] == "false"


def test_clone_redacts_token_from_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(monkeypatch, username="bot", token="s3cret")  # noqa: S106

    def fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd, 1, "", "fatal: Authentication failed for bot with s3cret"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(GitError) as exc:
        clone_repository(
            "https://gitea.example.com/org/repo.git",
            tmp_path / "repo",
            settings=settings,
        )
    message = str(exc.value)
    assert "s3cret" not in message
    assert "bot" not in message
    assert "***" in message


def test_askpass_answers_username_or_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(USERNAME_ENV, "bot")
    monkeypatch.setenv(PASSWORD_ENV, "s3cret")
    assert answer("Username for 'https://gitea.example.com':") == "bot"
    assert answer("Password for 'https://gitea.example.com':") == "s3cret"


def test_askpass_program_path_is_the_helper() -> None:
    path = Path(git_clone._askpass_program())
    assert path.name == "git_askpass.py"
    assert path.is_file()
