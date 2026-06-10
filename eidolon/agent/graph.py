from langgraph.graph import END, StateGraph

from eidolon.agent.nodes import (
    analysis_node,
    correlation_execute_node,
    correlation_planner_node,
    intake_node,
    report_node,
    wave1_scan_node,
    wave2_scan_node,
)
from eidolon.core.models import PipelineState


def build_graph():  # type: ignore[return-value]
    builder = StateGraph(PipelineState)

    builder.add_node("intake", intake_node)
    # Wave 1: breach_check, dehashed, whoxy, paste, stealer, phone_pivot,
    #         surface_map, holehe, blackbird, maigret, ghunt
    #         — all run concurrently (only need classifications)
    builder.add_node("wave1_scan", wave1_scan_node)
    # Wave 2: broker_scan, shodan, public_records, ai_audit
    #         — all run concurrently (need Wave 1 results)
    builder.add_node("wave2_scan", wave2_scan_node)
    builder.add_node("correlation_planner", correlation_planner_node)
    builder.add_node("correlation_execute", correlation_execute_node)
    builder.add_node("analysis", analysis_node)
    builder.add_node("report", report_node)

    builder.set_entry_point("intake")
    builder.add_edge("intake", "wave1_scan")
    builder.add_edge("wave1_scan", "wave2_scan")
    builder.add_edge("wave2_scan", "correlation_planner")
    builder.add_edge("correlation_planner", "correlation_execute")
    builder.add_edge("correlation_execute", "analysis")
    builder.add_edge("analysis", "report")
    builder.add_edge("report", END)

    return builder.compile()
