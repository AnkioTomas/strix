"""Fixed instructions the web console injects into Strix (resume / retest)."""

from __future__ import annotations

from typing import Any

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
你不负责写报告：复测报告由系统根据你填写的漏洞结论自动生成，不要写报告正文、不要改标题/描述/严重度。
你只填每条漏洞的 retest_status、fix_verification（简短复测步骤与结果）、screenshots。
全部填完用 list_reports 核对，缺 retest_status 的补齐，再 finish_scan 一次，
executive_summary 只用一两句话概括复测结论。凭证 / 环境变化见下方[附加说明]（如有）。

[原报告]
{body}
"""
