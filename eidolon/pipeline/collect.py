"""Source collection nodes and wave execution.

Waves run their members concurrently (REGISTRY's ``wave`` is the concurrency
group). The wave runner enforces a per-tool soft timeout (RESILIENCE.1): a
wedged tool stops blocking the wave after ``PER_TOOL_TIMEOUT_S`` and its slot
gets a visible error result. A node that raises (RESILIENCE.2) writes an error
result into its slots instead of leaving them absent.
"""

import logging
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError, as_completed
from typing import Callable, cast

from eidolon import config
from eidolon.core.findings import merge_findings
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


def _shodan_slots(state: ScanState) -> list[str]:
    """The per-IP result slots the shodan override writes."""
    return [f"shodan_{c.value}" for c in state.classifications if c.type == "ip"]


def shodan_node(state: ScanState) -> ScanState:
    """Shodan is a node override: it aggregates multiple IP collects."""
    from eidolon.core.findings import ExposedHost

    classifications = state.classifications or []
    ips = [c.value for c in classifications if c.type == "ip"]
    if not ips:
        logger.info("shodan: no IPs in classifications")
        return state

    all_findings: list = []
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
    merged_ips: dict[str, object] = {}
    other: list = []
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


shodan_node.slots = _shodan_slots  # type: ignore[attr-defined]


SOURCE_NODE_OVERRIDES: dict[str, Callable[[ScanState], ScanState]] = {
    "shodan": shodan_node,
}


def _default_source_node(spec: SourceSpec) -> Callable[[ScanState], ScanState]:
    """The generic per-source node: build input from state, collect, apply.

    The returned node exposes a ``slots`` callable so the wave runner knows
    which result slot to write a synthetic error into on timeout/exception.
    """

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
    node.slots = lambda _state: [spec.name]  # type: ignore[attr-defined]
    return node


def _source_node(spec: SourceSpec) -> Callable[[ScanState], ScanState]:
    override = SOURCE_NODE_OVERRIDES.get(spec.name)
    return override if override is not None else _default_source_node(spec)


def _node_slots(node: Callable[[ScanState], ScanState], state: ScanState) -> list[str]:
    """The result slots a node may write, from its ``slots`` provider."""
    provider = getattr(node, "slots", None)
    if callable(provider):
        return cast("Callable[[ScanState], list[str]]", provider)(state)
    return []


def _run_concurrent(
    base_state: ScanState,
    node_slots: list[tuple[Callable[[ScanState], ScanState], list[str]]],
    *,
    per_tool_timeout_s: float,
) -> ScanState:
    """Run source nodes concurrently, each with a per-tool soft timeout.

    RESILIENCE.1 — a wedged tool (a hung subprocess / black-holed vendor) must
    not stall the whole wave. ``as_completed(futures, timeout=...)`` bounds how
    long the wave waits, and every slot of a tool that didn't finish receives a
    synthetic error result so the failure renders as failed in coverage and the
    report — never as a silent missing hole. The orphan thread cannot be
    killed, so it keeps running until its own hard cap (RESILIENCE.3 client
    timeouts); the wave just stops waiting for it.

    RESILIENCE.2 — a node that raises (the rare node-level raise; ``collect``
    already never raises) writes an error result into its slots instead of
    leaving them absent.
    """
    results = dict(base_state.results or {})
    findings = list(base_state.findings or [])

    def _guarded(
        node: Callable[[ScanState], ScanState], state: ScanState
    ) -> ScanState | SourceResult:
        try:
            return node(state)
        except Exception as exc:
            logger.exception("wave node raised: %s", exc)
            name = getattr(node, "__name__", "source")
            return SourceResult(
                name=name.removesuffix("_node"),
                status="error",
                findings=[],
                detail=f"{name} node raised: {exc}",
            )

    executor = ThreadPoolExecutor(max_workers=max(1, len(node_slots)))
    futures: dict[Future, list[str]] = {
        executor.submit(_guarded, node, base_state): slots for node, slots in node_slots
    }
    done: set[Future] = set()
    try:
        try:
            for fut in as_completed(futures, timeout=per_tool_timeout_s):
                done.add(fut)
                outcome = fut.result()
                if isinstance(outcome, SourceResult):  # node raised (RESILIENCE.2)
                    results.setdefault(outcome.name, outcome)
                    continue
                results.update(dict(outcome.results or {}))
                if outcome.findings:
                    findings = merge_findings(findings, outcome.findings)
        except TimeoutError:
            # RESILIENCE.1: every slot of a tool the wave stopped waiting for
            # gets a visible error result, so a timeout never reads as a hole.
            for fut, slots in futures.items():
                if fut in done:
                    continue
                for slot in slots:
                    if slot not in results:
                        results[slot] = SourceResult(
                            name=slot,
                            status="error",
                            findings=[],
                            detail=f"{slot} timed out after {per_tool_timeout_s:g}s",
                        )
    finally:
        # The orphan threads finish on their own caps; the wave does not wait.
        executor.shutdown(wait=False)

    findings = sorted(findings, key=lambda f: (f.kind, f.dedup_key))
    return base_state.model_copy(update={"findings": findings, "results": results})


def wave_scan_node(state: ScanState, wave: int) -> ScanState:
    """Run all sources for a given wave number, concurrently."""
    specs = [s for s in REGISTRY if s.wave == wave]
    logger.info("wave %d: %d sources", wave, len(specs))
    node_slots: list[tuple[Callable[[ScanState], ScanState], list[str]]] = []
    for spec in specs:
        node = _source_node(spec)
        slots = _node_slots(node, state) or [spec.name]
        node_slots.append((node, slots))
    timeout_s = float(config.get("PER_TOOL_TIMEOUT_S") or 120)
    return _run_concurrent(state, node_slots, per_tool_timeout_s=timeout_s)
