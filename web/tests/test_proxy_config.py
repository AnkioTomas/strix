"""Tests for agent proxy / request-header helpers."""

from __future__ import annotations

import pytest
from app.services.proxy_config import (
    HeadersValidationError,
    ProxyValidationError,
    compose_agent_http_instruction,
    normalize_proxy_url,
    normalize_request_headers,
    redact_proxy_url,
    rewrite_proxy_for_docker,
)


def test_normalize_proxy_url_accepts_common_schemes():
    assert normalize_proxy_url("http://127.0.0.1:7890") == "http://127.0.0.1:7890"
    assert (
        normalize_proxy_url("socks5://user:pass@proxy.example:1080")
        == "socks5://user:pass@proxy.example:1080"
    )
    assert normalize_proxy_url("  ") is None
    assert normalize_proxy_url(None) is None


def test_normalize_proxy_url_rejects_junk():
    with pytest.raises(ProxyValidationError):
        normalize_proxy_url("ftp://example.com:21")
    with pytest.raises(ProxyValidationError):
        normalize_proxy_url("http://example.com/path")
    with pytest.raises(ProxyValidationError):
        normalize_proxy_url("not-a-url")


def test_rewrite_loopback_for_docker():
    assert (
        rewrite_proxy_for_docker("http://127.0.0.1:7890")
        == "http://host.docker.internal:7890"
    )
    assert (
        rewrite_proxy_for_docker("socks5://user:s3cret@localhost:1080")
        == "socks5://user:s3cret@host.docker.internal:1080"
    )
    assert (
        rewrite_proxy_for_docker("http://proxy.corp:8080") == "http://proxy.corp:8080"
    )


def test_redact_proxy_url():
    assert redact_proxy_url("http://alice:secret@proxy:8080") == "http://***@proxy:8080"
    assert redact_proxy_url("http://127.0.0.1:7890") == "http://127.0.0.1:7890"


def test_normalize_request_headers():
    assert normalize_request_headers(None) is None
    assert normalize_request_headers("  \n# comment\n  ") is None
    assert (
        normalize_request_headers(
            "Authorization: Bearer x\n# skip\nCookie: a=b\nX-Foo: bar"
        )
        == "Authorization: Bearer x\nCookie: a=b\nX-Foo: bar"
    )
    with pytest.raises(HeadersValidationError):
        normalize_request_headers("no-colon")
    with pytest.raises(HeadersValidationError):
        normalize_request_headers("Bad Name: x")


def test_compose_agent_http_instruction():
    text = compose_agent_http_instruction(
        "Focus on IDOR",
        proxy_url="http://127.0.0.1:7890",
        request_headers="Authorization: Bearer t",
    )
    assert text is not None
    assert "Focus on IDOR" in text
    assert "[出站代理 — 强制]" in text
    assert "host.docker.internal:7890" in text
    assert "[附加请求头 — 强制]" in text
    assert "Authorization: Bearer t" in text
    assert compose_agent_http_instruction(None) is None
