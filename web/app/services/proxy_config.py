# ruff: noqa: RUF001
"""Optional HTTP proxy / request-header config the web console hands to the agent."""

from __future__ import annotations

from urllib.parse import quote, urlparse, urlunparse


_ALLOWED_SCHEMES = frozenset({"http", "https", "socks5", "socks5h", "socks4", "socks4a"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_MAX_HEADER_LINES = 40
_MAX_HEADER_BYTES = 8000


class ProxyValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class HeadersValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_proxy_url(raw: str | None) -> str | None:
    """Validate and normalize a proxy URL; empty → None."""
    text = (raw or "").strip()
    if not text:
        return None
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ProxyValidationError(
            "INVALID_PROXY_URL",
            "proxy_url must use http/https/socks5/socks4 (optionally with credentials)",
        )
    if not parsed.hostname:
        raise ProxyValidationError("INVALID_PROXY_URL", "proxy_url is missing a host")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ProxyValidationError(
            "INVALID_PROXY_URL",
            "proxy_url must be scheme://[user:pass@]host:port only",
        )
    return urlunparse((scheme, parsed.netloc, "", "", "", ""))


def rewrite_proxy_for_docker(proxy_url: str) -> str:
    """Point loopback proxies at the Docker host gateway (agent runs in sandbox)."""
    parsed = urlparse(proxy_url)
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        return proxy_url
    userinfo = ""
    if parsed.username is not None:
        user = quote(parsed.username, safe="")
        if parsed.password is not None:
            userinfo = f"{user}:{quote(parsed.password, safe='')}@"
        else:
            userinfo = f"{user}@"
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"{userinfo}host.docker.internal{port}"
    return urlunparse((parsed.scheme, netloc, "", "", "", ""))


def redact_proxy_url(proxy_url: str | None) -> str | None:
    """Hide credentials for UI / logs."""
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    auth = "***@" if parsed.username is not None else ""
    return f"{parsed.scheme}://{auth}{host}{port}"


def normalize_request_headers(raw: str | None) -> str | None:
    """Validate `Name: value` lines; empty → None. Preserves order and values."""
    text = (raw or "").strip()
    if not text:
        return None
    if len(text.encode("utf-8")) > _MAX_HEADER_BYTES:
        raise HeadersValidationError(
            "INVALID_REQUEST_HEADERS",
            f"request_headers exceeds {_MAX_HEADER_BYTES} bytes",
        )
    lines: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            raise HeadersValidationError(
                "INVALID_REQUEST_HEADERS",
                f"line {lineno}: expected 'Header-Name: value'",
            )
        name, value = stripped.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name or any(ch.isspace() for ch in name):
            raise HeadersValidationError(
                "INVALID_REQUEST_HEADERS",
                f"line {lineno}: invalid header name",
            )
        lines.append(f"{name}: {value}")
    if not lines:
        return None
    if len(lines) > _MAX_HEADER_LINES:
        raise HeadersValidationError(
            "INVALID_REQUEST_HEADERS",
            f"request_headers allows at most {_MAX_HEADER_LINES} headers",
        )
    return "\n".join(lines)


def format_proxy_instruction(proxy_url: str) -> str:
    """Mandatory block telling the agent to configure tools with this proxy."""
    docker_url = rewrite_proxy_for_docker(proxy_url)
    if docker_url != proxy_url:
        note = (
            f"\n沙箱内请用 `{docker_url}`（本机 loopback 已改写为 "
            f"host.docker.internal）；用户填写的是 `{proxy_url}`。"
        )
    else:
        note = f"\n代理地址：`{proxy_url}`"
    return f"""\
[出站代理 — 强制]

用户要求：所有出站 HTTP(S) / 浏览器 / curl / python requests / 扫描工具
必须经此代理访问目标，禁止直连绕过。{note}

你必须自己配置工具（例如 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY、curl -x、
playwright/代理设置等）。不要假设基础设施已替你挂好该代理。
"""


def format_headers_instruction(headers_text: str) -> str:
    """Mandatory block telling the agent to attach these headers on requests."""
    return f"""\
[附加请求头 — 强制]

用户要求：对本目标的每一次相关 HTTP(S) 请求（浏览器、curl、代理重放、脚本）
都必须带上下列请求头。缺任一视为未按要求测试：

{headers_text}

配置方式由你决定（浏览器额外头、curl -H、Caido match/replace、脚本默认头等），
但结果必须可在流量/截图中核对。
"""


def compose_agent_http_instruction(
    base: str | None,
    *,
    proxy_url: str | None = None,
    request_headers: str | None = None,
) -> str | None:
    """Merge user instruction with optional proxy/headers mandates."""
    parts: list[str] = []
    if base and base.strip():
        parts.append(base.strip())
    if proxy_url:
        parts.append(format_proxy_instruction(proxy_url).strip())
    if request_headers:
        parts.append(format_headers_instruction(request_headers).strip())
    return "\n\n".join(parts) if parts else None
