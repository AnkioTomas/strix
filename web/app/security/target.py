"""Pentest target validation (SSRF / private network guards) + TCP reachability."""

from __future__ import annotations

import base64
import ipaddress
import socket
import ssl
from urllib.parse import ParseResult, unquote, urlparse

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
    proxy_url: str | None = None,
) -> None:
    """Fail fast when the target host:port does not accept TCP connections.

    When ``proxy_url`` is set (the same outbound proxy the agent must use),
    probe through that proxy instead of a direct connect. The API process
    runs on the host — loopback proxies stay loopback, not Docker rewrite.

    Skips quietly when the target has no clear TCP endpoint (bare hostname,
    local path, etc.).
    """
    endpoint = parse_tcp_endpoint(target)
    if endpoint is None:
        return
    host, port = endpoint
    proxy = (proxy_url or "").strip() or None
    try:
        if proxy:
            _connect_via_proxy(proxy, host, port, timeout)
        else:
            with socket.create_connection((host, port), timeout=timeout):
                return
    except TargetValidationError:
        raise
    except TimeoutError as exc:
        raise TargetValidationError(
            "TARGET_UNREACHABLE",
            _unreachable_message(host, port, timeout, proxy, "timed out"),
        ) from exc
    except OSError as exc:
        raise TargetValidationError(
            "TARGET_UNREACHABLE",
            _unreachable_message(host, port, timeout, proxy, str(exc)),
        ) from exc


def _unreachable_message(
    host: str,
    port: int,
    timeout: float,
    proxy_url: str | None,
    detail: str,
) -> str:
    via = ""
    if proxy_url:
        parsed = urlparse(proxy_url)
        phost = parsed.hostname or "?"
        pport = parsed.port or "?"
        via = f" via proxy {phost}:{pport}"
    if detail == "timed out":
        return f"TCP connect to {host}:{port}{via} timed out after {timeout:g}s"
    return f"TCP connect to {host}:{port}{via} failed: {detail}"


def _recvn(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("proxy closed the connection")
        buf += chunk
    return buf


def _tunnel_authority(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _connect_via_proxy(proxy_url: str, host: str, port: int, timeout: float) -> None:
    parsed = urlparse(proxy_url)
    scheme = (parsed.scheme or "").lower()
    if scheme in {"http", "https"}:
        _http_connect_via_proxy(parsed, host, port, timeout)
        return
    if scheme in {"socks5", "socks5h"}:
        _socks5_connect_via_proxy(parsed, host, port, timeout, remote_dns=scheme == "socks5h")
        return
    if scheme in {"socks4", "socks4a"}:
        _socks4_connect_via_proxy(parsed, host, port, timeout, remote_dns=scheme == "socks4a")
        return
    raise OSError(f"unsupported proxy scheme: {scheme or '(none)'}")


def _http_connect_via_proxy(parsed: ParseResult, host: str, port: int, timeout: float) -> None:
    proxy_host = parsed.hostname
    if not proxy_host:
        raise OSError("proxy_url is missing a host")
    scheme = (parsed.scheme or "").lower()
    proxy_port = parsed.port or (443 if scheme == "https" else 80)
    sock: socket.socket | ssl.SSLSocket = socket.create_connection(
        (proxy_host, int(proxy_port)), timeout=timeout
    )
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=proxy_host)
        authority = _tunnel_authority(host, port)
        headers = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
        ]
        if parsed.username is not None:
            password = unquote(parsed.password or "")
            token = base64.b64encode(
                f"{unquote(parsed.username)}:{password}".encode()
            ).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {token}")
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
        status = buf.split(b"\r\n", 1)[0].decode("ascii", "replace")
        parts = status.split(None, 2)
        code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        if code < 200 or code > 299:
            raise OSError(f"proxy CONNECT {authority} returned {status or 'empty response'}")
    finally:
        sock.close()


def _socks5_connect_via_proxy(
    parsed: ParseResult,
    host: str,
    port: int,
    timeout: float,
    *,
    remote_dns: bool,
) -> None:
    proxy_host = parsed.hostname
    if not proxy_host:
        raise OSError("proxy_url is missing a host")
    sock = socket.create_connection((proxy_host, parsed.port or 1080), timeout=timeout)
    try:
        if parsed.username is not None:
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")
        hello = _recvn(sock, 2)
        if hello[0] != 5:
            raise OSError("proxy is not SOCKS5")
        if hello[1] == 2:
            user = unquote(parsed.username or "").encode()
            password = unquote(parsed.password or "").encode()
            if len(user) > 255 or len(password) > 255:
                raise OSError("SOCKS5 credentials too long")
            sock.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
            auth = _recvn(sock, 2)
            if auth[1] != 0:
                raise OSError("SOCKS5 authentication failed")
        elif hello[1] != 0:
            raise OSError(f"SOCKS5 method {hello[1]} rejected")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is None or remote_dns:
            name = host.encode("idna")
            if len(name) > 255:
                raise OSError("SOCKS5 hostname too long")
            req = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big")
        elif ip.version == 4:
            req = b"\x05\x01\x00\x01" + ip.packed + port.to_bytes(2, "big")
        else:
            req = b"\x05\x01\x00\x04" + ip.packed + port.to_bytes(2, "big")
        sock.sendall(req)
        hdr = _recvn(sock, 4)
        if hdr[1] != 0:
            raise OSError(f"SOCKS5 connect failed (rep={hdr[1]})")
        atyp = hdr[3]
        if atyp == 1:
            _recvn(sock, 6)
        elif atyp == 4:
            _recvn(sock, 18)
        elif atyp == 3:
            _recvn(sock, _recvn(sock, 1)[0] + 2)
        else:
            raise OSError(f"SOCKS5 unknown address type {atyp}")
    finally:
        sock.close()


def _socks4_connect_via_proxy(
    parsed: ParseResult,
    host: str,
    port: int,
    timeout: float,
    *,
    remote_dns: bool,
) -> None:
    proxy_host = parsed.hostname
    if not proxy_host:
        raise OSError("proxy_url is missing a host")
    sock = socket.create_connection((proxy_host, parsed.port or 1080), timeout=timeout)
    try:
        userid = unquote(parsed.username or "").encode()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and ip.version == 4 and not remote_dns:
            dest = ip.packed
            extra = b""
        else:
            dest = b"\x00\x00\x00\x01"
            extra = host.encode("idna") + b"\x00"
        sock.sendall(b"\x04\x01" + port.to_bytes(2, "big") + dest + userid + b"\x00" + extra)
        reply = _recvn(sock, 8)
        if reply[1] != 0x5A:
            raise OSError(f"SOCKS4 connect failed (cd={reply[1]})")
    finally:
        sock.close()


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
