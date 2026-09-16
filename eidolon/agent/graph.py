"""The scan graph (REFACTOR.5): intake → registry waves → analysis → report.

The wave nodes and their chaining derive from ``REGISTRY`` (one node per
distinct wave, in wave order) — no hand-wired source lists. Adding a source
never touches this file.
"""

from langgraph.graph import END, StateGraph

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


def report_node(state: ScanState) -> ScanState:
    """Write the final report artifact."""
    import logging

    logger = logging.getLogger(__name__)
    path = write_report(state)
    logger.info("report written to %s", path)
    return state.model_copy(update={"report_path": path})


def build_graph():  # type: ignore[return-value]
    builder = StateGraph(ScanState)

    builder.add_node("intake", intake_node)
    builder.set_entry_point("intake")
    # One node per registry wave; wave N sources derive their input from
    # wave N-1 findings, and run concurrently within the wave.
    wave_numbers = waves()
    for i, wave in enumerate(wave_numbers):
        builder.add_node(f"wave_{wave}", lambda state, w=wave: wave_scan_node(state, w))
        if i == 0:
            builder.add_edge("intake", f"wave_{wave}")
        else:
            builder.add_edge(f"wave_{wave_numbers[i - 1]}", f"wave_{wave}")

    # MITRE ATT&CK mapping — deterministic, reads all wave findings
    builder.add_node("mitre", mitre_node)
    builder.add_node("correlation_planner", correlation_planner_node)
    builder.add_node("correlation_execute", correlation_execute_node)
    builder.add_node("analysis", analysis_node)
    builder.add_node("report", report_node)

    last_wave = f"wave_{wave_numbers[-1]}" if wave_numbers else "intake"
    builder.add_edge(last_wave, "mitre")
    builder.add_edge("mitre", "correlation_planner")
    builder.add_edge("correlation_planner", "correlation_execute")
    builder.add_edge("correlation_execute", "analysis")
    builder.add_edge("analysis", "report")
    builder.add_edge("report", END)

    return builder.compile()
