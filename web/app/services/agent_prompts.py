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

def translate_report_instruction(run_name: str | None) -> str:
    run_path = f"/workspace/strix_runs/{run_name}" if run_name else "/workspace/strix_runs/<run>"
    return f"""\
[翻译报告 — 强制]
不扩测、不改漏洞结论与事实。把现有交付报告 {run_path}/penetration_test_report.md
完整翻译成英文，写入 /workspace/penetration_test_report.en.md（用终端分段读、分段追加写）。
保留 Markdown 结构、表格、代码块、URL、payload、命令、图片路径（images/...）原样不译；
只翻译说明性文字与标题。写完后用终端确认文件非空，再 finish_scan 一次（不要改动漏洞数据）。
"""


RETEST_INSTRUCTION = f"""\
[复测 — 强制]
在本 run 上复测已有漏洞（list_reports / get_report 用原 id）。禁止另开新报告、禁止只写口头结论。
对每一条（逐条，不得遗漏、不得只挑几条）：验证是否仍可利用；update_vulnerability_report 写 retest_status
（fixed / not_fixed / partial / regressed）；fixed 必须有 screenshots 或硬证据。
全部写完后用 list_reports 逐条核对，凡缺 retest_status 的继续复测补齐，再 finish_scan。
fix_verification 写本次复测的操作步骤与结果（按复测写，不照抄原复现步骤）。
最后 finish_scan；executive_summary 概括复测结论。
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


MAX_REPORT_CHARS = 40000


def retest_from_report_instruction(
    report_md: str, zip_name: str | None = None, *, seeded: bool = False
) -> str:
    """Prompt for a fresh task that retests the findings of a delivered report."""
    body = report_md.strip()
    if len(body) > MAX_REPORT_CHARS:
        body = body[:MAX_REPORT_CHARS] + "\n\n…（报告过长，已截断；完整报告见附件）"
    attached = f"（完整报告与截图在附件 /workspace/{zip_name}）" if zip_name else ""
    if seeded:
        steps = (
            "原报告的漏洞已按原 id 预载入本 run：先 list_reports 取 id，禁止 create_vulnerability_report"
            "（禁止新建报告、禁止把复测结论写进标题）；逐条验证是否仍可利用，"
            "再用 update_vulnerability_report(id) 写 retest_status"
            "（fixed / not_fixed / partial / regressed）。已修复的写 fixed（必须有 screenshots 或硬证据），"
            "仍可利用的写 not_fixed，结论务必与实测一致；"
            "fix_verification 写本次复测的操作步骤与结果。"
        )
    else:
        steps = (
            "对原报告中的每一条漏洞（不得遗漏）：先按报告的地址与复现步骤验证是否仍可利用；"
            "用 create_vulnerability_report 以原标题（不加任何前缀或结论）登记，再用 "
            "update_vulnerability_report 写 retest_status（fixed / not_fixed / partial / regressed）；"
            "fixed 必须有 screenshots 或硬证据；fix_verification 写本次复测的操作步骤与结果。"
        )
    return f"""\
[复测 — 强制]
这是一次全新的复测任务，依据下方原报告{attached}逐条复测；不要扩测新漏洞。
{steps}
全部登记后用 list_reports 逐条核对，缺 retest_status 的补齐，再 finish_scan 一次；
executive_summary 概括复测结论。凭证 / 环境变化见下方[附加说明]（如有）。
{_REPORT_STYLE}

[原报告]
{body}
"""
