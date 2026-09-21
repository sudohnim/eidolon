"""LangGraph pipeline assembly."""

import logging

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from eidolon.analysis.narrative import analysis_node
from eidolon.analysis.threat import mitre_node
from eidolon.core.registry import waves
from eidolon.core.state import ScanState
from eidolon.pipeline.classify import intake_node
from eidolon.pipeline.collect import wave_scan_node
from eidolon.pipeline.correlate import (
    correlation_execute_node,
    correlation_planner_node,
)
from eidolon.report import write_report

logger = logging.getLogger(__name__)


def monitoring_node(state: ScanState) -> ScanState:
    """Diff this scan against the previous scan of the same target (#4).

    Runs immediately before the report so the temporal stamps land in both the
    rendered report and the persisted state — the next scan reads them back.
    """
    from eidolon.core.monitoring import apply_temporal, previous_findings

    identifier = next((c.value for c in state.classifications), "")
    prior = previous_findings(identifier, exclude_run_id=state.run_id)
    diff = apply_temporal(prior, list(state.findings))
    if diff.compared:
        logger.info(
            "monitoring: %d new, %d resolved, %d unchanged",
            len(diff.new_findings),
            len(diff.resolved_findings),
            diff.unchanged_count,
        )
    return state.model_copy(update={"diff": diff})


def report_node(state: ScanState) -> ScanState:
    """Write the final report artifact."""
    path = write_report(state)
    logger.info("report written to %s", path)
    return state.model_copy(update={"report_path": path})


def build_graph() -> CompiledStateGraph:
    """Build the scan pipeline graph from the source registry."""
    builder = StateGraph(ScanState)

    # Entry
    builder.add_node("intake", intake_node)
    builder.set_entry_point("intake")

    # Wave scans (waves derived from REGISTRY)
    for w in waves():
        builder.add_node(f"wave_{w}", lambda s, w=w: wave_scan_node(s, w))

    # Chain waves sequentially
    wave_list = waves()
    for i, w in enumerate(wave_list):
        src = "intake" if i == 0 else f"wave_{wave_list[i - 1]}"
        builder.add_edge(src, f"wave_{w}")

    # Post-wave: MITRE
    builder.add_node("mitre", mitre_node)
    builder.add_edge(f"wave_{wave_list[-1]}", "mitre")

    # Correlation
    builder.add_node("correlation_plan", correlation_planner_node)
    builder.add_node("correlation_execute", correlation_execute_node)
    builder.add_edge("mitre", "correlation_plan")
    builder.add_edge("correlation_plan", "correlation_execute")

    # Analysis
    builder.add_node("analysis", analysis_node)
    builder.add_edge("correlation_execute", "analysis")

    # Report
    builder.add_node("monitoring", monitoring_node)
    builder.add_edge("analysis", "monitoring")
    builder.add_node("report", report_node)
    builder.add_edge("monitoring", "report")
    builder.add_edge("report", END)

    return builder.compile()
