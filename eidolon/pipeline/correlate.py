"""Correlation planning and execution nodes."""

import ipaddress
import logging
import re

from eidolon.analysis.digest import _build_analysis_digest
from eidolon.analysis.narrative import _parse_json_tolerant
from eidolon.analysis.prompts import CORRELATION_PROMPT
from eidolon.config import is_test_mode
from eidolon.core.findings import Credential, Finding, merge_findings
from eidolon.core.registry import REGISTRY, SourceSpec
from eidolon.core.state import CorrelationRun, ScanState
from eidolon.sources.base import collect

logger = logging.getLogger(__name__)


def _extract_deterministic_pivots(state: ScanState) -> list[dict]:
    """Extract pivot candidates from findings without an LLM call."""
    pivots: list[dict] = []

    for f in state.generic_findings("account"):
        p = f.payload
        username = p.get("username")
        if username and not re.search(r"[.@]", username):
            pivots.append(
                {
                    "type": "username",
                    "value": username,
                    "source": f.kind,
                    "reason": "Username found in "
                    f"{p.get('platform', 'account')} scan",
                }
            )

    for f in state.generic_findings("phone_intel"):
        p = f.payload
        number = p.get("number")
        if number:
            pivots.append(
                {
                    "type": "phone",
                    "value": number,
                    "source": f.kind,
                    "reason": "Phone number found in intel scan",
                }
            )

    for f in state.generic_findings("exposed_host"):
        p = f.payload
        ip = p.get("ip")
        if ip:
            try:
                ipaddress.ip_address(ip)
                pivots.append(
                    {
                        "type": "ip",
                        "value": ip,
                        "source": f.kind,
                        "reason": "IP address found in Shodan scan",
                    }
                )
            except ValueError:
                pass

    for f in state.generic_findings("broker_exposure"):
        p = f.payload
        name = p.get("name")
        if name:
            pivots.append(
                {
                    "type": "name",
                    "value": name,
                    "source": f.kind,
                    "reason": "Name found in broker data",
                }
            )

    # Credential findings: extract email aliases (user+tag@domain, user.name@domain)
    # Cap at 3 to limit correlation scope (test: test_capped_at_three)
    alias_count = 0
    for f in state.findings_of(Credential):
        if alias_count >= 3:
            break
        p = f.payload
        email = f.email or p.get("email", "")
        if email and ("+" in email.split("@")[0] or "." in email.split("@")[0]):
            pivots.append(
                {
                    "type": "email",
                    "value": email,
                    "source": f.kind,
                    "reason": "Email alias found in credential dump",
                }
            )
            alias_count += 1

    # Deduplicate by (type, value)
    seen = set()
    unique = []
    for p in pivots:
        key = (p["type"], p["value"])
        if key not in seen:
            seen.add(key)
            unique.append(p)

    return unique[:5]


def correlation_planner_node(state: ScanState) -> ScanState:
    """Plan correlation pivots using LLM + deterministic extraction."""
    det = _extract_deterministic_pivots(state)
    if not det and not is_test_mode():
        logger.info("correlation: no deterministic pivots, skipping LLM")
        return state.model_copy(update={"correlation_plan": []})

    digest = _build_analysis_digest(state)
    prompt = CORRELATION_PROMPT + "\n" + digest

    if is_test_mode():
        # Return a fixture plan for tests
        plan = [
            {
                "tool": "maigret",
                "input_type": "username",
                "input_value": "testuser",
                "rationale": "Test pivot",
            }
        ]
    else:
        from eidolon.sources.ollama import OllamaProvider

        provider = OllamaProvider()
        raw = provider.complete(
            system="",
            user=prompt,
            response_model=dict,
        )
        parsed = _parse_json_tolerant(raw)
        plan = parsed.get("pivots", []) if isinstance(parsed, dict) else []

    logger.info("correlation: planned %d pivots", len(plan))
    return state.model_copy(update={"correlation_plan": plan})


def _valid_pivot_value(ptype: str, pvalue: str) -> bool:
    """Validate a pivot value by type."""
    if not pvalue:
        return False
    if ptype == "ip":
        try:
            ipaddress.ip_address(pvalue)
            return True
        except ValueError:
            return False
    if ptype == "email":
        return "@" in pvalue and "." in pvalue.split("@")[-1]
    if ptype in ("username", "name"):
        return len(pvalue) >= 3
    if ptype == "phone":
        # Require at least 7 digits (like the normalize_phone function)
        digits = re.sub(r"\D", "", pvalue)
        return len(digits) >= 7
    return False


def correlation_execute_node(state: ScanState) -> ScanState:
    """Execute correlation pivots by mapping to source tools."""
    plan = state.correlation_plan or []
    if not plan:
        return state

    # Build a tool registry by input type
    tools_by_input: dict[str, list[SourceSpec]] = {}
    for spec in REGISTRY:
        for ik in spec.input_kinds:
            tools_by_input.setdefault(ik, []).append(spec)

    runs: list[CorrelationRun] = []
    new_findings: list[Finding] = []

    for pivot in plan:
        ptype = pivot.get("type")
        pvalue = pivot.get("value")
        if not _valid_pivot_value(ptype, pvalue):
            continue

        specs = tools_by_input.get(ptype, [])
        for spec in specs:
            if spec.input_for is None:
                continue
            inp = spec.input_for(state)
            if inp is None:
                continue
            # Override the input value with the pivot value
            if hasattr(inp, "value"):
                inp.value = pvalue  # type: ignore[attr-defined]
            sr = collect(spec.factory(), inp)
            runs.append(
                CorrelationRun(
                    pivot_type=ptype,
                    value=pvalue,
                    source=spec.name,
                    status=sr.status,
                    summary=f"{len(sr.findings)} findings",
                )
            )
            if sr.status == "ok":
                new_findings.extend(sr.findings)

    merged = merge_findings(state.findings or [], new_findings)
    correlation_runs = (state.correlation_runs or []) + runs

    logger.info(
        "correlation: executed %d pivots -> %d findings",
        len(plan),
        len(new_findings),
    )
    return state.model_copy(
        update={
            "findings": merged,
            "correlation_runs": correlation_runs,
        }
    )
