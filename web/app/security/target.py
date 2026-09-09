"""Pentest target validation (SSRF / private network guards)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app.config import Settings


class TargetValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
}


def validate_pentest_target(target: str, settings: Settings) -> str:
    raw = target.strip()
    if not raw:
        raise TargetValidationError("INVALID_TARGET", "target is empty")

    prefixes = settings.allowed_target_prefixes()
    if prefixes and not any(raw.startswith(prefix) or raw == prefix for prefix in prefixes):
        raise TargetValidationError(
            "INVALID_TARGET",
            "target is not in PENTEST_ALLOWED_TARGETS",
        )

    # Bare domain / IP — treat as host for resolution checks.
    if "://" not in raw:
        host = raw.split("/")[0].split(":")[0]
        _assert_host_safe(host, settings)
        return raw

    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError(
            "INVALID_TARGET",
            f"unsupported URL scheme: {parsed.scheme or '(none)'}",
        )
    if not parsed.hostname:
        raise TargetValidationError("INVALID_TARGET", "URL missing hostname")
    _assert_host_safe(parsed.hostname, settings)
    return raw


def _assert_host_safe(hostname: str, settings: Settings) -> None:
    host = hostname.strip().lower().rstrip(".")
    if host in _BLOCKED_HOSTNAMES or host.endswith(".localhost"):
        if not settings.allow_private_targets:
            raise TargetValidationError("INVALID_TARGET", f"blocked hostname: {hostname}")
        return

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        _assert_ip_safe(ip, settings)
        return

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetValidationError("INVALID_TARGET", f"DNS resolution failed: {hostname}") from exc

    if not infos:
        raise TargetValidationError("INVALID_TARGET", f"DNS resolution failed: {hostname}")

    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        _assert_ip_safe(resolved, settings)


def _assert_ip_safe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, settings: Settings) -> None:
    if settings.allow_private_targets:
        return
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise TargetValidationError("INVALID_TARGET", f"private/restricted IP not allowed: {ip}")
    # AWS/GCP/Azure metadata common address
    if str(ip) == "169.254.169.254":
        raise TargetValidationError("INVALID_TARGET", "cloud metadata IP blocked")
