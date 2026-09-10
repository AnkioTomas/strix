"""Pentest target validation (SSRF / private network guards) + TCP reachability."""

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

# Fast preflight — fail create/retry before queueing a dead host:port.
TCP_CONNECT_TIMEOUT_SECONDS = 2.0


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


def parse_tcp_endpoint(target: str) -> tuple[str, int] | None:
    """Return ``(host, port)`` for a quick TCP probe, or ``None`` if unknown."""
    raw = (target or "").strip()
    if not raw:
        return None

    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.port is not None:
            return parsed.hostname, int(parsed.port)
        return parsed.hostname, 443 if parsed.scheme == "https" else 80

    head = raw.split("/")[0]
    if head.startswith("["):
        # [ipv6]:port
        end = head.find("]")
        if end <= 1:
            return None
        host = head[1:end]
        rest = head[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return None

    if head.count(":") == 1:
        host, port_s = head.split(":", 1)
        if host and port_s.isdigit():
            return host, int(port_s)
    return None


def check_tcp_reachable(
    target: str,
    *,
    timeout: float = TCP_CONNECT_TIMEOUT_SECONDS,
) -> None:
    """Fail fast when the target host:port does not accept TCP connections.

    Skips quietly when the target has no clear TCP endpoint (bare hostname,
    local path, etc.).
    """
    endpoint = parse_tcp_endpoint(target)
    if endpoint is None:
        return
    host, port = endpoint
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except TimeoutError as exc:
        raise TargetValidationError(
            "TARGET_UNREACHABLE",
            f"TCP connect to {host}:{port} timed out after {timeout:g}s",
        ) from exc
    except OSError as exc:
        raise TargetValidationError(
            "TARGET_UNREACHABLE",
            f"TCP connect to {host}:{port} failed: {exc}",
        ) from exc


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
