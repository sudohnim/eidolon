"""LLM narrative analysis: identity summary, top risks, findings context."""

import json
import logging
import re
from pathlib import Path

from langchain_ollama import ChatOllama

from eidolon import config
from eidolon.analysis.digest import _build_analysis_digest
from eidolon.analysis.prompts import ANALYSIS_PROMPT
from eidolon.analysis.risk import (
    _filter_top_risks,
    _normalize_what_is_known,
    _state_identity_summary,
    _state_risk_floor,
    _state_what_is_known,
)
from eidolon.config import is_test_mode
from eidolon.core.state import AnalysisResult, ScanState

logger = logging.getLogger(__name__)


def _parse_json_tolerant(text: str) -> dict | list:
    """Parse JSON with tolerance for common LLM errors."""
    text = text.strip()
    # Remove markdown code fences
    if text.startswith("```"):
        text = re.sub(r"^```\w*\n", "", text)
        text = re.sub(r"\n```$", "", text)
    # Find first { or [
    start = min((text.find(c) for c in "{[" if text.find(c) != -1), default=0)
    end = max(text.rfind("}"), text.rfind("]"))
    if start >= 0 and end > start:
        text = text[start : end + 1]
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        # Try to fix common issues
        text = re.sub(r",\s*([}\]])", r"\1", text)  # trailing commas
        text = re.sub(
            r"([{\[,])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1 "\2":', text
        )  # unquoted keys
        try:
            value = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning("JSON parse failed: %s", e)
            return {}
    # A scalar JSON value (0, "x", null, true) is not an analysis document —
    # forcing it into a dict here would crash the caller's .get() chains.
    return value if isinstance(value, (dict, list)) else {}


def _save_raw_response(state: ScanState, raw: str, exc: Exception) -> None:
    """Save raw LLM response for debugging."""
    output_path = config.get("RESULTS_OUTPUT_PATH")
    if not is_test_mode() and output_path:
        out = Path(output_path) / f"{state.run_id}_analysis_raw.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(f"ERROR: {exc}\n\nRAW:\n{raw}")
        logger.debug("Saved raw analysis to %s", out)


def _postprocess_analysis(state: ScanState, analysis: dict) -> dict:
    """Post-process LLM analysis: filter risks, normalize known, merge remediation."""
    from eidolon.analysis.risk import _finalize_remediation

    # Filter top risks
    risks = analysis.get("top_risks", [])
    if not isinstance(risks, list):
        risks = []
    risks = [str(r) for r in risks]
    risks = _filter_top_risks(risks, state)

    # Normalize what_is_known - fall back to deterministic if LLM provides nothing
    known = analysis.get("what_is_known", {})
    if isinstance(known, dict) and known:
        known = _normalize_what_is_known(known)
    else:
        known = _normalize_what_is_known(_state_what_is_known(state))

    # Merge remediation (deterministic wins)
    llm_rem = analysis.get("remediation", {})
    if not isinstance(llm_rem, dict):
        llm_rem = {}
    remediation = _finalize_remediation(state, llm_rem)

    # Identity summary (LLM or deterministic fallback)
    identity = analysis.get("identity_summary")
    if not identity:
        identity = _state_identity_summary(state)

    # Risk score: max of LLM + deterministic floor
    llm_score = analysis.get("overall_risk_score", 0)
    floor = _state_risk_floor(state)
    risk_score = max(int(llm_score), floor)

    # Risk level
    if risk_score >= 70:
        level = "high"
    elif risk_score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "overall_risk_score": risk_score,
        "overall_risk_level": level,
        "identity_summary": identity,
        "top_risks": risks,
        "what_is_known": known,
        "remediation": remediation,
        "findings_context": analysis.get("findings_context", []),
        "breach_severity": analysis.get("breach_severity", "none"),
        "broker_exposure_severity": analysis.get("broker_exposure_severity", "none"),
        "account_exposure_severity": analysis.get("account_exposure_severity", "none"),
    }


def _validate_analysis(analysis: dict) -> None:
    """Validate the analysis dict structure using pydantic."""
    AnalysisResult(**analysis)


def analysis_node(state: ScanState) -> ScanState:
    """Run the LLM analysis and produce the AnalysisResult."""
    if is_test_mode():
        # Fixture response for tests - load real fixture matching report expectations
        from eidolon.utils import load_fixture

        analysis = load_fixture("analysis")
    else:
        digest = _build_analysis_digest(state)
        prompt = ANALYSIS_PROMPT + "\n\nSCAN RESULTS:\n" + digest

        llm = ChatOllama(model="llama3.1:8b", temperature=0)
        raw = llm.invoke(prompt)
        content = raw.content if isinstance(raw.content, str) else str(raw.content)
        parsed = _parse_json_tolerant(content)
        analysis = parsed if isinstance(parsed, dict) else {}

        if not analysis:
            logger.error("LLM returned empty analysis; using deterministic fallback")
            from eidolon.analysis.risk import (
                _build_deterministic_remediation,
            )

            analysis = {
                "overall_risk_score": _state_risk_floor(state),
                "overall_risk_level": "medium",
                "identity_summary": _state_identity_summary(state),
                "top_risks": [],
                "what_is_known": _state_what_is_known(state),
                "remediation": _build_deterministic_remediation(state),
                "findings_context": [],
                "breach_severity": "none",
                "broker_exposure_severity": "none",
                "account_exposure_severity": "none",
            }

    # Post-process and validate
    processed = _postprocess_analysis(state, analysis)
    try:
        _validate_analysis(processed)
    except ValueError as e:
        logger.error("Analysis validation failed: %s", e)
        _save_raw_response(state, str(analysis), e)
        raise

    result = AnalysisResult(**processed)
    logger.info(
        "analysis: risk_score=%d level=%s",
        result.overall_risk_score,
        result.overall_risk_level,
    )
    # Store as dict for LangGraph state compatibility
    return state.model_copy(update={"analysis_result": result.model_dump()})
