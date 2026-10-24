"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.agents import coordinator_from_context


logger = logging.getLogger(__name__)


def _do_finish(
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    agent_graph: dict[str, Any],
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        from strix.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - report state unavailable",
            }
        report_state.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        vuln_count = len(report_state.vulnerability_reports)
        coverage_summary = _coverage_summary(agent_graph)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        result: dict[str, Any] = {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
        }
        result.update(coverage_summary)
        return result


def _coverage_summary(agent_graph: dict[str, Any]) -> dict[str, Any]:
    """Coverage counts, unresolved surfaces, and gaps the runtime can see.

    The gap list is derived from the agent graph rather than from the ledger,
    so it catches the failure the ledger cannot: a risk class an agent was
    equipped for and never accounted for. Surfacing it here — in the response
    to the call that ends the scan — is the last point at which the root agent
    can still dispatch work or record the class as unresolved instead of
    letting the report imply it was clean.
    """
    from strix.report.coverage import agents_from_graph, skill_coverage_gaps
    from strix.tools.coverage.tools import get_coverage_entries, outcome_counts

    entries = get_coverage_entries()
    if not entries:
        return {
            "coverage_recorded": 0,
            "coverage_warning": (
                "No coverage was recorded for this scan. The report cannot show which "
                "surfaces were reviewed and cleared — only what was found. Use "
                "record_coverage during testing so future scans can report negative space."
            ),
        }

    counts = outcome_counts()
    summary: dict[str, Any] = {
        "coverage_recorded": len(entries),
        "coverage_outcomes": counts,
    }
    unresolved = [e for e in entries if e.get("outcome") == "needs_follow_up"]
    if unresolved:
        summary["coverage_warning"] = (
            f"{len(unresolved)} surface(s) closed as 'needs_follow_up' and remain "
            "unresolved. These should be represented in the report as areas requiring "
            "further review rather than omitted."
        )
        summary["unresolved_surfaces"] = [
            {"surface": e.get("surface", ""), "risk_area": e.get("risk_area", "")}
            for e in unresolved
        ]

    gaps = skill_coverage_gaps(entries, agents_from_graph(agent_graph))
    if gaps:
        summary["coverage_gaps"] = [gap["detail"] for gap in gaps]
        summary["coverage_gap_warning"] = (
            f"{len(gaps)} risk class(es) assigned to agents have no coverage entry and "
            "will be published as unexamined. Record them (or a needs_follow_up row) "
            "before the report goes out."
        )
    return summary


@function_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str = "",
    technical_analysis: str = "",
    recommendations: str = "",
) -> str:
    """Finalize the scan. **Root-agent only** (subagents use ``agent_finish``).

    You do NOT write the report. The customer report is assembled by code
    from the vulnerability reports already filed (titles, evidence, impact,
    remediation, retest results). Your only deliverable here is a short
    ``executive_summary``. This is a terminal action: call it exactly ONCE,
    never as a status probe.

    **Pre-flight checklist (mandatory):**

    1. Call ``view_agent_graph`` first. If ANY agent is ``running`` /
       ``waiting``, wrap it up first (``send_message_to_agent``,
       ``wait_for_agents`` or ``stop_agent``). Finishing with live children
       orphans their work.
    2. Call ``list_reports`` so the summary matches what was actually filed.
       Every vulnerability must already be filed via
       ``create_vulnerability_report`` (or ``create_dependency_report`` for
       known-CVE dependency findings); one report per distinct vulnerability.
       Do not rewrite, translate or polish filed reports here.
    3. Attack-chaining gate: consider chaining confirmed findings into
       end-to-end paths; any validated chain must already be filed.
    4. Coverage reconciliation: call ``list_coverage``; anything still open
       must be a ``needs_follow_up`` row. The response reports unresolved rows.

    **executive_summary rules:** one to three short paragraphs for
    non-technical leadership — risk posture, business impact, notable
    criticals; for a retest, the overall retest outcome. Formal, third
    person, factual, markdown allowed, no ``#``/``##`` headings, no
    internal paths, agent names, tool names or internal IDs. If zero
    vulnerabilities were found, say so plainly.

    Args:
        executive_summary: Short business-level summary (the only required field).
        methodology: Optional; normally leave empty (not part of the report).
        technical_analysis: Optional; normally leave empty.
        recommendations: Optional; normally leave empty.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    parent_id = inner.get("parent_id")
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
        if active_agents and coordinator.reserve_stopped:
            active_agents = []
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
        agent_graph=await coordinator.snapshot() if coordinator is not None else {},
    )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, ensure_ascii=False, default=str)
