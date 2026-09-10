"""Fixed instructions the web console injects into Strix (resume / retest)."""

from __future__ import annotations

REFRESH_REPORT_INSTRUCTION = """\
[更新报告 — 强制]

不要扩大测试范围。按当前交付规范重写报告并结束：

1. 禁止编造元数据表（系统名称 / 技术架构 / 测试标准 / 评估类型等）。
   范围、方法、标准写进 finish_scan 的 methodology 与 executive_summary。
2. finish_scan 四段都必须是客户可读正文：
   executive_summary / methodology / technical_analysis / recommendations。
3. 漏洞正文用 list_reports → get_report → update_vulnerability_report 逐条润色
  （一次一个 id）；交付清单中每条漏洞是二级标题结构。
4. 完成后调用 finish_scan 恰好一次。

优先把已有发现组织成合格交付件，而不是继续扫新面。
"""

RETEST_INSTRUCTION = """\
[复测要求 — 强制]

对父任务已报告的每一个漏洞标题逐条复测，禁止只写口头结论：

1. 验证该标题对应的漏洞是否仍可利用。
2. 必须用 update_vulnerability_report 写入 retest_status，取值只能是：
   fixed（已修复）/ not_fixed（未修复）/ partial（部分修复）/ regressed（回归恶化）。
3. 必须提供佐证：screenshots（沙箱内 PNG/JPEG 绝对路径）和/或 evidence /
   fix_verification 中引用截图路径或可复核的 HTTP/响应摘录。无截图或其他硬证据
   不得标记 fixed。
4. fix_verification 写清复测步骤与结果；必要时更新 evidence / screenshots。
5. finish_scan 的 executive_summary 概括整体复测结论。交付报告会单独生成
   「复测情况」章节，依赖你写入的 retest_status 与佐证。

先 list_reports 拿到全部已有标题，再逐条复测与更新，最后 finish_scan 一次。
"""
