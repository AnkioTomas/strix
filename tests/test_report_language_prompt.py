"""STRIX_REPORT_LANGUAGE drives prompt injection and delivery-report chrome."""

from __future__ import annotations

import pytest

from strix.agents.prompt import render_system_prompt
from strix.config import loader
from strix.config.settings import ReportSettings
from strix.report.locale import (
    chrome_locale,
    report_labels,
    resolve_report_language,
)
from strix.report.zh_report import render_zh_penetration_report


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("zh", "Simplified Chinese (简体中文)"),
        ("zh-CN", "Simplified Chinese (简体中文)"),
        ("chinese", "Simplified Chinese (简体中文)"),
        ("en", "English"),
        ("en-US", "English"),
        ("ja", "Japanese (日本語)"),
        ("Français", "Français"),
        ("日本語", "日本語"),
        ("", None),
        (None, None),
        ("   ", None),
    ],
)
def test_resolve_report_language(raw: str | None, expected: str | None) -> None:
    assert resolve_report_language(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("zh", "zh"),
        ("zh-CN", "zh"),
        ("chinese", "zh"),
        ("en", "en"),
        ("ja", "en"),
        ("Français", "en"),
        ("", "en"),
    ],
)
def test_chrome_locale(raw: str, expected: str) -> None:
    assert chrome_locale(raw) == expected


def test_report_settings_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "en")
    assert ReportSettings().language == "en"


def test_system_prompt_injects_resolved_language(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "zh")
    monkeypatch.setattr(loader, "_cached", None)
    prompt = render_system_prompt(scan_mode="quick", is_root=True)
    assert "<report_language>" in prompt
    assert "Simplified Chinese (简体中文)" in prompt
    assert "update_vulnerability_report" in prompt


def test_system_prompt_embeds_port_scope_and_authorized_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "")
    monkeypatch.setattr(loader, "_cached", None)
    prompt = render_system_prompt(
        scan_mode="quick",
        is_root=True,
        system_prompt_context={
            "scope_source": "system_scan_config",
            "authorization_source": "strix_platform_verified_targets",
            "authorized_targets": [
                {
                    "type": "web_application",
                    "value": "https://app.example.com",
                    "workspace_path": "",
                    "authorized_ports": [443],
                },
            ],
        },
    )
    assert "PORT SCOPE (HARD CONSTRAINT" in prompt
    assert "authorized_ports" in prompt
    assert "ports: 443" in prompt
    assert "full port scan" in prompt
    assert "测试全端口" in prompt


def test_system_prompt_injects_freeform_language(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "Français")
    monkeypatch.setattr(loader, "_cached", None)
    prompt = render_system_prompt(scan_mode="quick", is_root=True)
    assert "<report_language>" in prompt
    assert "Français" in prompt


def test_system_prompt_skips_language_block_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "")
    monkeypatch.setattr(loader, "_cached", None)
    prompt = render_system_prompt(scan_mode="quick", is_root=True)
    assert "<report_language>" not in prompt


def test_delivery_report_chrome_follows_language(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "en")
    monkeypatch.setattr(loader, "_cached", None)
    assert report_labels()["overview_heading"] == "Executive Summary"

    md = render_zh_penetration_report(
        run_record={
            "run_name": "shop",
            "targets_info": [{"type": "web", "original": "https://shop.example.com"}],
        },
        vulnerability_reports=[],
    )
    assert "# https://shop.example.com — Penetration Test Report" in md
    assert "# Executive Summary" in md
    assert "# Findings" in md
    assert "No reproducible findings" in md
    assert "| System |" not in md
    assert "OWASP WSTG / PTES" not in md


def test_delivery_report_chrome_chinese_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_REPORT_LANGUAGE", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    assert report_labels()["overview_heading"] == "测试概述"

    md = render_zh_penetration_report(
        run_record={"run_name": "clean", "targets_info": []},
        vulnerability_reports=[],
    )
    assert "# 测试概述" in md
    assert "未确认可复现" in md or "未发现可复现" in md
