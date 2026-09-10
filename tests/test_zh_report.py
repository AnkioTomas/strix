"""Tests for Chinese penetration-test report delivery bundle."""

from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

import pytest

from strix.config import loader
from strix.report.zh_report import (
    extract_screenshot_paths,
    render_zh_penetration_report,
    write_zh_delivery_bundle,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _chinese_chrome(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REPORT_LANGUAGE", "zh")
    monkeypatch.setattr(loader, "_cached", None)


def test_extract_screenshot_paths_from_evidence_and_markdown() -> None:
    paths = extract_screenshot_paths(
        "screenshot: /workspace/.agent-browser-screenshots/a.png — proves IDOR",
        "![x](images/already-relative.jpg)",
        "https://cdn.example/ignore.png",
    )
    assert paths == [
        "/workspace/.agent-browser-screenshots/a.png",
        "images/already-relative.jpg",
    ]


def test_write_zh_delivery_bundle_embeds_relative_images(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace" / ".agent-browser-screenshots"
    workspace.mkdir(parents=True)
    shot = workspace / "idor.png"
    shot.write_bytes(b"\x89PNG\r\n\x1a\nfake")

    reports = [
        {
            "id": "vuln-0001",
            "title": "IDOR 读取他人订单",
            "severity": "high",
            "timestamp": "2026-09-09 01:00:00 UTC",
            "description": "低权限用户可读取他人订单。",
            "impact": "泄露其他用户 PII。",
            "target": "https://shop.example.com",
            "endpoint": "/api/orders/{id}",
            "method": "GET",
            "cwe": "CWE-639",
            "cvss": 7.5,
            "poc_description": "1. 使用攻击者 cookie 访问受害者订单 URL。",
            "poc_script_code": (
                "```\n"
                "https://shop.example.com/api/orders/42\n"
                "```"
            ),
            "remediation_steps": "按会话主体做对象级授权。",
            "evidence": (
                "screenshot: /workspace/.agent-browser-screenshots/idor.png "
                "— 攻击者会话看到受害者邮箱"
            ),
            "screenshots": ["/workspace/.agent-browser-screenshots/idor.png"],
            "technical_analysis": "授权检查使用了客户端传入的 user_id。",
        }
    ]
    run_record = {
        "run_name": "shop-scan",
        "targets_info": [
            {
                "type": "web",
                "original": "https://shop.example.com",
            }
        ],
    }

    zip_path = write_zh_delivery_bundle(
        tmp_path,
        run_record=run_record,
        vulnerability_reports=reports,
        overview="系统整体风险为高，存在可复现的对象级授权绕过。",
    )

    assert zip_path.exists()
    md = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    assert "# https://shop.example.com安全渗透测试报告" in md
    assert "| 系统名称 |" not in md
    assert "OWASP WSTG / PTES" not in md
    assert "# 测试概述" in md
    assert "对象级授权绕过" in md
    assert "# 漏洞清单" in md
    assert "## 1. [ 高危 ] IDOR 读取他人订单" in md
    assert "### 描述" in md
    assert "### 复现步骤" in md
    assert "### 影响" in md
    assert "### 修复建议" in md
    assert "![漏洞截图 1](images/vuln-0001-1.png)" in md
    assert (tmp_path / "images" / "vuln-0001-1.png").read_bytes() == shot.read_bytes()

    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        assert "penetration_test_report.md" in names
        assert "images/vuln-0001-1.png" in names


def test_render_zh_report_without_findings() -> None:
    md = render_zh_penetration_report(
        run_record={"run_name": "clean", "targets_info": []},
        vulnerability_reports=[],
    )
    assert "未发现可复现漏洞" in md or "未确认可复现" in md
    assert "| 系统名称 |" not in md


def test_render_zh_report_includes_finish_scan_sections() -> None:
    md = render_zh_penetration_report(
        run_record={
            "run_name": "shop",
            "targets_info": [{"type": "web", "original": "https://shop.example.com"}],
        },
        vulnerability_reports=[],
        scan_results={
            "executive_summary": "整体风险中等。",
            "methodology": "按 OWASP WSTG 黑盒测试。",
            "technical_analysis": "主要问题集中在对象级授权。",
            "recommendations": "优先修复 IDOR。",
        },
    )
    assert "# 测试概述" in md
    assert "整体风险中等。" in md
    assert "# 测试方法" in md
    assert "按 OWASP WSTG 黑盒测试。" in md
    assert "# 技术分析" in md
    assert "# 修复建议" in md
    assert "| 技术架构 |" not in md
    assert "见测试范围" not in md
