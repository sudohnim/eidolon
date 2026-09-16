"""Source collection nodes and wave execution."""

import logging
from typing import Callable

from eidolon.core.findings import Finding, merge_findings
from eidolon.core.registry import REGISTRY, SourceSpec
from eidolon.core.state import ScanState, SourceResult
from eidolon.sources.base import collect
from eidolon.sources.shodan import Shodan, ShodanInput

logger = logging.getLogger(__name__)


def _apply_source(state: ScanState, sr: SourceResult) -> dict:
    """Merge a SourceResult into ScanState updates."""
    findings = state.findings or []
    results = dict(state.results or {})
    if sr.status == "ok" and sr.findings:
        findings = merge_findings(findings, sr.findings)
    results[sr.name] = sr
    return {"findings": findings, "results": results}


def shodan_node(state: ScanState) -> ScanState:
    """Shodan is a node override: it aggregates multiple IP collects."""
    from eidolon.core.findings import ExposedHost

    classifications = state.classifications or []
    ips = [c.value for c in classifications if c.type == "ip"]
    if not ips:
        logger.info("shodan: no IPs in classifications")
        return state

    all_findings: list[Finding] = []
    all_results: dict[str, SourceResult] = {}

    for ip in ips:
        sr = collect(Shodan(), ShodanInput(ip=ip))
        if sr.status == "ok":
            logger.info("shodan %s: OK — %s", ip, sr.summary)
        else:
            logger.error("shodan %s: FAILED — %s", ip, sr.detail)
        all_results[f"shodan_{ip}"] = sr
        all_findings.extend(sr.findings)

    # Deduplicate ExposedHost findings by IP (dedup_key is host:<ip>)
    merged = merge_findings(state.findings or [], all_findings)
    merged_ips: dict[str, Finding] = {}
    other: list[Finding] = []
    for f in merged:
        if isinstance(f, ExposedHost):
            merged_ips[f.dedup_key] = f
        else:
            other.append(f)
    final_findings = other + list(merged_ips.values())

    return state.model_copy(
        update={
            "findings": final_findings,
            "results": {**state.results, **all_results},
        }
    )


def _run_concurrent(
    base_state: ScanState,
    extra_nodes: list[Callable[[ScanState], ScanState]],
) -> ScanState:
    """Run extra nodes sequentially (not truly concurrent) and merge."""
    state = base_state
    for node in extra_nodes:
        state = node(state)
    return state


# The shodan override — no other source has a custom node
SOURCE_NODE_OVERRIDES: dict[str, Callable[[ScanState], ScanState]] = {
    "shodan": shodan_node,
}


def _default_source_node(spec: SourceSpec) -> Callable[[ScanState], ScanState]:
    """The generic per-source node: build input from state, collect, apply."""

    def node(state: ScanState) -> ScanState:
        if spec.input_for is None:
            return state
        inp = spec.input_for(state)
        if inp is None:
            return state
        sr = collect(spec.factory(), inp)
        if sr.status == "ok":
            logger.info("%s: OK — %s", spec.name, sr.summary)
        else:
            logger.error("%s: FAILED — %s", spec.name, sr.detail)
        return state.model_copy(update=_apply_source(state, sr))

    node.__name__ = f"{spec.name}_node"
    return node


def _source_node(spec: SourceSpec) -> Callable[[ScanState], ScanState]:
    override = SOURCE_NODE_OVERRIDES.get(spec.name)
    return override if override is not None else _default_source_node(spec)


def wave_scan_node(state: ScanState, wave: int) -> ScanState:
    """Run all sources for a given wave number."""
    specs = [s for s in REGISTRY if s.wave == wave]
    logger.info("wave %d: %d sources", wave, len(specs))
    nodes = [_source_node(s) for s in specs]
    return _run_concurrent(state, nodes)
