"""Fixed instructions the web console injects into Strix (resume / retest)."""

from __future__ import annotations

from typing import Any

REFRESH_REPORT_INSTRUCTION = """\
[更新报告 — 强制]

不要扩大测试范围。按当前交付规范重写报告并结束：

1. 禁止编造元数据表（系统名称 / 技术架构 / 测试标准 / 评估类型等）。
   范围、方法、标准写进 finish_scan 的 methodology / technical_analysis /
   recommendations（交付时会进「附录」）；executive_summary 写客户可读概述。
2. finish_scan 四段都必须是客户可读正文：
   executive_summary / methodology / technical_analysis / recommendations。
3. 漏洞正文用 list_reports → get_report → update_vulnerability_report 逐条润色
   （一次一个 id）；交付清单中每条漏洞是二级标题结构。
4. 截图佐证（强制）：对 list_reports 里的每一条，检查 screenshots / evidence 是否
   已有可展示的 PNG/JPEG 沙箱路径。缺失则先复现并截图，再用
   update_vulnerability_report 写入 screenshots（或把路径写进 evidence），
   禁止无截图的空洞描述。
5. 完成后调用 finish_scan 恰好一次。

优先把已有发现组织成合格交付件，而不是继续扫新面。
"""

RETEST_INSTRUCTION = """\
[复测要求 — 强制]

父任务的原始漏洞已载入本次扫描（list_reports / get_report 用原 id），
下文也附了原文。禁止只写口头结论，禁止为同一漏洞另开新报告。

1. 用原 id 逐条复测：验证是否仍可利用。
2. 必须用 update_vulnerability_report 写入 retest_status，取值只能是：
   fixed（已修复）/ not_fixed（未修复）/ partial（部分修复）/ regressed（回归恶化）。
3. 必须提供佐证：screenshots（沙箱内 PNG/JPEG 绝对路径）和/或 evidence /
   fix_verification 中引用截图路径或可复核的 HTTP/响应摘录。无截图或其他硬证据
   不得标记 fixed。
4. fix_verification 写清复测步骤与结果；必要时更新 evidence / screenshots。
5. finish_scan 的 executive_summary 概括整体复测结论。交付报告会单独生成
   「复测情况」章节，依赖你写入的 retest_status 与佐证。

先 list_reports / get_report 核对原文，再逐条更新，最后 finish_scan 一次。
"""

_BODY_FIELDS = (
    ("description", "描述"),
    ("poc", "PoC"),
    ("evidence", "证据"),
    ("technical_analysis", "技术分析"),
    ("impact", "影响"),
    ("recommendation", "修复建议"),
    ("cwe", "CWE"),
)


def format_prior_reports(findings: list[dict[str, Any]]) -> str:
    """Render original finding bodies so a retest agent is not title-blind."""
    if not findings:
        return ""
    blocks = ["[原始漏洞报告]"]
    for item in findings:
        fid = str(item.get("id") or "").strip() or "unknown"
        title = str(item.get("title") or fid)
        lines = [f"## {fid} — {title}"]
        severity = item.get("severity")
        if severity:
            lines.append(f"- severity: {severity}")
        asset = item.get("asset")
        if asset:
            lines.append(f"- target: {asset}")
        location = item.get("location")
        if isinstance(location, dict):
            for key in ("url", "endpoint", "file", "method", "line"):
                value = location.get(key)
                if value not in (None, ""):
                    lines.append(f"- {key}: {value}")
        for key, label in _BODY_FIELDS:
            text = item.get(key)
            if text:
                lines.append(f"\n### {label}\n{text}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def focused_retest_instruction(findings: list[dict[str, Any]]) -> str:
    """Retest only the listed findings (console-selected / request-test)."""
    lines = "\n".join(
        f"- {item.get('id')}: {item.get('title') or item.get('id')}"
        for item in findings
        if str(item.get("id") or item.get("title") or "").strip()
    )
    reports = format_prior_reports(findings)
    extra = f"\n\n{reports}" if reports else ""
    return f"""\
[指定漏洞复测 — 强制]

只复测下列漏洞（用原 id，禁止另开新报告），禁止扩大到其它标题，禁止只写口头结论：

{lines}
{extra}

对每一个列出的 id：
1. 验证是否仍可利用。get_report(id) 可读原文。
2. 用 update_vulnerability_report 写入 retest_status：
   fixed / not_fixed / partial / regressed。
3. 必须提供 screenshots 和/或 evidence / fix_verification 硬证据；无证据不得标 fixed。
4. 未列出的漏洞不要复测、不要改。

完成后 finish_scan 一次；executive_summary 概括本次指定复测结论。
"""
