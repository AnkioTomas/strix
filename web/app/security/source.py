"""Audit source validation (Git HTTPS + local allowlist)."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

from app.config import Settings
from app.schemas import GitSource, LocalSource, Source
from app.security.target import TargetValidationError


class SourceValidationError(TargetValidationError):
    pass


def validate_source(source: Source, settings: Settings) -> Source:
    if isinstance(source, GitSource):
        return _validate_git(source, settings)
    return _validate_local(source, settings)


def _validate_git(source: GitSource, settings: Settings) -> GitSource:
    url = source.url.strip()
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SourceValidationError("INVALID_SOURCE", "MVP only allows HTTPS Git URLs")
    if not parsed.hostname:
        raise SourceValidationError("INVALID_SOURCE", "Git URL missing hostname")
    host = parsed.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"} and not settings.allow_private_targets:
        raise SourceValidationError("INVALID_SOURCE", "localhost Git hosts blocked")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, 443)
        except socket.gaierror as exc:
            raise SourceValidationError("INVALID_SOURCE", f"DNS failed for {host}") from exc
        for info in infos:
            try:
                resolved = ipaddress.ip_address(info[4][0])
            except (ValueError, IndexError):
                continue
            if not settings.allow_private_targets and (
                resolved.is_private or resolved.is_loopback or resolved.is_link_local
            ):
                raise SourceValidationError("INVALID_SOURCE", f"private Git host IP: {resolved}")
    else:
        if not settings.allow_private_targets and (
            ip.is_private or ip.is_loopback or ip.is_link_local
        ):
            raise SourceValidationError("INVALID_SOURCE", f"private Git host IP: {ip}")
    return GitSource(type="git", url=url, branch=source.branch, commit=source.commit)


def _validate_local(source: LocalSource, settings: Settings) -> LocalSource:
    if settings.allowed_source_root is None:
        raise SourceValidationError(
            "INVALID_SOURCE",
            "local sources require ALLOWED_SOURCE_ROOT",
        )
    root = settings.allowed_source_root.resolve()
    path = Path(source.path).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise SourceValidationError(
            "INVALID_SOURCE",
            f"path must be under ALLOWED_SOURCE_ROOT ({root})",
        ) from exc
    if not path.exists() or not path.is_dir():
        raise SourceValidationError("INVALID_SOURCE", f"local path not found: {path}")
    return LocalSource(type="local", path=str(path))
