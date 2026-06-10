from typing import Literal, cast

import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool
from eidolon.utils import load_data


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
    platforms_checked: list[str] = []
    platforms_found: list[AiPlatformPolicy] = []
    high_risk_count: int = 0
    action_items: list[str] = []
    overall_risk: Literal["high", "medium", "low"] = "low"


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


class AiAudit(Tool[AiAuditInput, AiAuditOutput]):
    name = "ai_audit"
    input_schema = AiAuditInput
    output_schema = AiAuditOutput

    def _input_value(self, inp: AiAuditInput) -> str:
        return ",".join(inp.platforms)

    def _run(
        self, inp: AiAuditInput, log: structlog.stdlib.BoundLogger
    ) -> AiAuditOutput:
        db = cast(dict, load_data("ai_policies.json"))
        platform_data = db["platforms"]

        found: list[AiPlatformPolicy] = []
        for platform_id in inp.platforms:
            entry = platform_data.get(platform_id.lower())
            if entry:
                found.append(AiPlatformPolicy(**entry))

        high_risk_count = sum(1 for p in found if p.risk_level == "high")
        if high_risk_count > 0:
            overall_risk = "high"
        elif any(p.risk_level == "medium" for p in found):
            overall_risk = "medium"
        else:
            overall_risk = "low"

        log.info(
            "ok", found=len(found), high_risk=high_risk_count, overall=overall_risk
        )
        return AiAuditOutput(
            platforms_checked=inp.platforms,
            platforms_found=found,
            high_risk_count=high_risk_count,
            action_items=_build_action_items(found),
            overall_risk=cast(Literal["high", "medium", "low"], overall_risk),
        )
