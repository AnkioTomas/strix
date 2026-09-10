"""Report language helpers — prompt injection + generated-report chrome.

``STRIX_REPORT_LANGUAGE`` drives both:
- the language directive injected into every agent system prompt
- the structural labels (headings/table keys) of the delivery markdown

Narrative *content* comes from the agents; chrome is localized here.
Unsupported chrome locales fall back to English labels.
"""

from __future__ import annotations

from typing import TypedDict

from strix.config import load_settings


# Optional aliases → human label for the agent prompt. Anything else is used as-is.
LANGUAGE_LABELS: dict[str, str] = {
    "zh": "Simplified Chinese (简体中文)",
    "zh-cn": "Simplified Chinese (简体中文)",
    "zh-hans": "Simplified Chinese (简体中文)",
    "chinese": "Simplified Chinese (简体中文)",
    "cn": "Simplified Chinese (简体中文)",
    "en": "English",
    "en-us": "English",
    "en-gb": "English",
    "english": "English",
    "ja": "Japanese (日本語)",
    "ja-jp": "Japanese (日本語)",
    "japanese": "Japanese (日本語)",
    "ko": "Korean (한국어)",
    "ko-kr": "Korean (한국어)",
    "korean": "Korean (한국어)",
}

_ZH_KEYS = frozenset(
    {
        "zh",
        "zh-cn",
        "zh-hans",
        "chinese",
        "cn",
    }
)


class ReportLabels(TypedDict):
    """Structural strings for the customer-facing markdown report."""

    field: str
    value: str
    cvss: str
    cwe: str
    target: str
    endpoint: str
    method: str
    severity_critical: str
    severity_high: str
    severity_medium: str
    severity_low: str
    severity_info: str
    untitled: str
    no_description: str
    description: str
    reproduction: str
    poc: str
    screenshots: str
    screenshot_n: str
    evidence_excerpt: str
    impact: str
    impact_missing: str
    remediation: str
    remediation_missing: str
    appendix: str
    assumptions: str
    counterevidence: str
    confidence: str
    confidence_rationale: str
    severity_change: str
    fix_verification: str
    package_name: str
    package_ecosystem: str
    installed_version: str
    fixed_version: str
    code_location: str
    found_at: str
    engagement_gray: str
    engagement_white: str
    engagement_black: str
    default_system: str
    system_name: str
    tech_stack: str
    tech_stack_fallback: str
    test_standard: str
    test_standard_value: str
    assessment_type: str
    test_scope: str
    report_title_suffix: str
    overview_heading: str
    findings_heading: str
    overview_with_findings: str
    overview_clean: str
    no_findings: str
    update_history: str


_LABELS_ZH: ReportLabels = {
    "field": "项目",
    "value": "内容",
    "cvss": "CVSS",
    "cwe": "CWE",
    "target": "目标",
    "endpoint": "端点",
    "method": "方法",
    "severity_critical": "严重",
    "severity_high": "高危",
    "severity_medium": "中危",
    "severity_low": "低危",
    "severity_info": "信息",
    "untitled": "未命名漏洞",
    "no_description": "无描述。",
    "description": "描述",
    "reproduction": "复现步骤",
    "poc": "POC：",
    "screenshots": "漏洞截图：",
    "screenshot_n": "漏洞截图 {n}",
    "evidence_excerpt": "证据摘录：",
    "impact": "影响",
    "impact_missing": "未说明。",
    "remediation": "修复建议",
    "remediation_missing": "未提供。",
    "appendix": "附录",
    "assumptions": "前提假设：",
    "counterevidence": "反证：",
    "confidence": "置信度：",
    "confidence_rationale": "置信度说明：",
    "severity_change": "严重性可变条件：",
    "fix_verification": "修复验证：",
    "package_name": "包名",
    "package_ecosystem": "生态",
    "installed_version": "已安装版本",
    "fixed_version": "修复版本",
    "code_location": "代码位置：",
    "found_at": "发现时间",
    "engagement_gray": "灰盒（源码 + 线上目标）",
    "engagement_white": "白盒",
    "engagement_black": "黑盒",
    "default_system": "目标系统",
    "system_name": "系统名称",
    "tech_stack": "技术架构",
    "tech_stack_fallback": "见测试范围与目标技术识别结果",
    "test_standard": "测试标准",
    "test_standard_value": "OWASP WSTG / PTES",
    "assessment_type": "评估类型",
    "test_scope": "测试范围",
    "report_title_suffix": "安全渗透测试报告",
    "overview_heading": "测试概述",
    "findings_heading": "漏洞清单",
    "overview_with_findings": (
        "本次测试共确认 **{count}** 个漏洞。危害较大的问题包括：{top}。"
    ),
    "overview_clean": "本次测试未确认可复现的高价值漏洞；建议持续关注权限边界与输入校验硬化。",
    "no_findings": "本次测试未发现可复现漏洞。",
    "update_history": "更新历史",
}

_LABELS_EN: ReportLabels = {
    "field": "Field",
    "value": "Value",
    "cvss": "CVSS",
    "cwe": "CWE",
    "target": "Target",
    "endpoint": "Endpoint",
    "method": "Method",
    "severity_critical": "Critical",
    "severity_high": "High",
    "severity_medium": "Medium",
    "severity_low": "Low",
    "severity_info": "Info",
    "untitled": "Untitled vulnerability",
    "no_description": "No description.",
    "description": "Description",
    "reproduction": "Reproduction Steps",
    "poc": "PoC:",
    "screenshots": "Screenshots:",
    "screenshot_n": "Screenshot {n}",
    "evidence_excerpt": "Evidence excerpt:",
    "impact": "Impact",
    "impact_missing": "Not specified.",
    "remediation": "Remediation",
    "remediation_missing": "Not provided.",
    "appendix": "Appendix",
    "assumptions": "Assumptions:",
    "counterevidence": "Counterevidence:",
    "confidence": "Confidence:",
    "confidence_rationale": "Confidence rationale:",
    "severity_change": "Severity change conditions:",
    "fix_verification": "Fix verification:",
    "package_name": "Package",
    "package_ecosystem": "Ecosystem",
    "installed_version": "Installed version",
    "fixed_version": "Fixed version",
    "code_location": "Code location:",
    "found_at": "Found",
    "engagement_gray": "Gray-box (source + live target)",
    "engagement_white": "White-box",
    "engagement_black": "Black-box",
    "default_system": "Target system",
    "system_name": "System",
    "tech_stack": "Tech stack",
    "tech_stack_fallback": "See scope and technology fingerprinting results",
    "test_standard": "Standard",
    "test_standard_value": "OWASP WSTG / PTES",
    "assessment_type": "Engagement type",
    "test_scope": "Scope",
    "report_title_suffix": "Penetration Test Report",
    "overview_heading": "Executive Summary",
    "findings_heading": "Findings",
    "overview_with_findings": (
        "This assessment confirmed **{count}** finding(s). Notable issues: {top}."
    ),
    "overview_clean": (
        "No high-value reproducible findings were confirmed; continue hardening "
        "authorization boundaries and input validation."
    ),
    "no_findings": "No reproducible findings were confirmed in this assessment.",
    "update_history": "Update History",
}


def normalize_language_key(raw: str | None) -> str:
    return (raw or "").strip().lower().replace("_", "-")


def resolve_report_language(raw: str | None) -> str | None:
    """Human label for the system-prompt language block, or ``None`` to skip."""
    text = (raw or "").strip()
    if not text:
        return None
    key = normalize_language_key(text)
    return LANGUAGE_LABELS.get(key, text)


def chrome_locale(raw: str | None = None) -> str:
    """Return ``zh`` or ``en`` for structural report labels.

    Chinese family → Chinese chrome. Everything else (including empty after
    falling back to settings default) uses English chrome, except when the
    configured default/settings value resolves to Chinese.
    """
    if raw is None:
        raw = load_settings().report.language
    key = normalize_language_key(raw)
    if not key:
        return "en"
    if key in _ZH_KEYS or key.startswith("zh"):
        return "zh"
    return "en"


def report_labels(raw: str | None = None) -> ReportLabels:
    """Label pack for the delivery markdown chrome."""
    return _LABELS_ZH if chrome_locale(raw) == "zh" else _LABELS_EN


def severity_label(severity: str | None, labels: ReportLabels | None = None) -> str:
    pack = labels or report_labels()
    key = str(severity or "info").lower()
    mapping = {
        "critical": pack["severity_critical"],
        "high": pack["severity_high"],
        "medium": pack["severity_medium"],
        "low": pack["severity_low"],
        "info": pack["severity_info"],
        "none": pack["severity_info"],
    }
    return mapping.get(key, str(severity or pack["severity_info"]))
