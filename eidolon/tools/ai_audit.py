import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class AiAuditInput(BaseModel):
    platforms: list[str]


class AiPlatformPolicy(BaseModel):
    platform_id: str
    display_name: str
    trains_consumer_by_default: bool
    opt_out_available: bool
    consumer_retention_opted_in: str
    consumer_retention_opted_out: str
    api_excluded_from_training: bool
    jurisdiction: str
    risk_level: Literal["high", "medium", "low"]
    opt_out_url: str
    notes: str


class AiAuditOutput(BaseModel):
    platforms_checked: list[str]
    platforms_found: list[AiPlatformPolicy]
    high_risk_count: int
    action_items: list[str]
    overall_risk: Literal["high", "medium", "low"]


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "tests"
    / "fixtures"
    / "ai_audit_response.json"
)
POLICY_DB_PATH = Path(__file__).parent.parent / "data" / "ai_policies.json"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def _build_action_items(policies: list[AiPlatformPolicy]) -> list[str]:
    items = []
    for p in sorted(
        policies, key=lambda x: {"high": 0, "medium": 1, "low": 2}[x.risk_level]
    ):
        if p.risk_level == "high" and not p.opt_out_available:
            items.append(
                f"CRITICAL: {p.display_name} has no training opt-out — "
                "consider deleting account"
            )
        elif p.trains_consumer_by_default and p.opt_out_available:
            items.append(
                f"ACTION: Opt out of {p.display_name} training at {p.opt_out_url}"
            )
        if p.api_excluded_from_training:
            items.append(f"INFO: {p.display_name} API usage is excluded from training")
    return items[:5]


def run(inp: AiAuditInput) -> ToolResult:
    logger.info("ai_audit: checking platforms count=%d", len(inp.platforms))

    if config.is_test_mode():
        return _load_fixture()

    try:
        db = json.loads(POLICY_DB_PATH.read_text())
        platform_data = db["platforms"]

        found: list[AiPlatformPolicy] = []
        for platform_id in inp.platforms:
            entry = platform_data.get(platform_id.lower())
            if entry:
                found.append(AiPlatformPolicy(**entry))

        high_risk_count = sum(1 for p in found if p.risk_level == "high")
        action_items = _build_action_items(found)

        if high_risk_count > 0:
            overall_risk = "high"
        elif any(p.risk_level == "medium" for p in found):
            overall_risk = "medium"
        else:
            overall_risk = "low"

        output = AiAuditOutput(
            platforms_checked=inp.platforms,
            platforms_found=found,
            high_risk_count=high_risk_count,
            action_items=action_items,
            overall_risk=cast(Literal["high", "medium", "low"], overall_risk),
        )
        return ToolResult(
            success=True,
            tool="ai_audit",
            input_type="email",
            input_value=",".join(inp.platforms),
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("ai_audit: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="ai_audit",
            input_type="email",
            input_value=",".join(inp.platforms),
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"ai_audit error: {exc}",
        )
