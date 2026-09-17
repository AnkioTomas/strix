"""Fixed instructions the web console injects into Strix (resume / retest)."""

from __future__ import annotations

from typing import Any

_REPORT_STYLE = "交付正文短写客户事实；无思考过程、无规则复述、字段内不用 #/##。"

REFRESH_REPORT_INSTRUCTION = f"""\
[更新报告 — 强制]
不扩测。按交付规范重写报告后 finish_scan 一次。
禁止编造元数据表；executive_summary 写概述，methodology / technical_analysis /
recommendations 进附录。漏洞用 list_reports → get_report → update 逐条润色（一次一个 id）；
缺截图先补再写入 screenshots。{_REPORT_STYLE}
"""

RETEST_INSTRUCTION = f"""\
[复测 — 强制]
在本 run 上复测已有漏洞（list_reports / get_report 用原 id）。禁止另开新报告、禁止只写口头结论。
对每条：验证是否仍可利用；update_vulnerability_report 写 retest_status
（fixed / not_fixed / partial / regressed）；fixed 必须有 screenshots 或硬证据。
fix_verification 写步骤与结果。最后 finish_scan；executive_summary 概括复测结论。
{_REPORT_STYLE}
"""


def focused_retest_instruction(findings: list[dict[str, Any]]) -> str:
    """Retest only the listed findings (console-selected / request-test)."""
    lines = "\n".join(
        f"- {item.get('id')}: {item.get('title') or item.get('id')}"
        for item in findings
        if str(item.get("id") or item.get("title") or "").strip()
    )
    return f"""\
[指定漏洞复测 — 强制]
只复测下列 id（禁止扩大、禁止另开新报告）：
{lines}
对每个 id：复测 → update retest_status（fixed/not_fixed/partial/regressed）+ screenshots/硬证据；
未列出的不要改。finish_scan 一次。{_REPORT_STYLE}
"""
