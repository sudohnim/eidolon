from datetime import datetime
from typing import Literal

from pydantic import BaseModel

InputType = Literal["email", "phone", "name", "org"]


class ToolResult(BaseModel):
    success: bool
    tool: str
    input_type: InputType
    input_value: str
    timestamp: datetime
    data: dict
    error: str | None = None


class InputClassification(BaseModel):
    type: Literal["email", "phone", "name", "org"]
    value: str
    raw: str


class PipelineState(BaseModel):
    raw_input: str
    run_id: str = ""
    classifications: list[InputClassification] = []
    location_city: str | None = None
    location_state: str | None = None
    location_zip: str | None = None
    hibp_result: ToolResult | None = None
    dehashed_result: ToolResult | None = None
    whoxy_result: ToolResult | None = None
    paste_result: ToolResult | None = None
    stealer_result: ToolResult | None = None
    broker_result: ToolResult | None = None
    spiderfoot_result: ToolResult | None = None
    holehe_result: ToolResult | None = None
    blackbird_result: ToolResult | None = None
    sherlock_result: ToolResult | None = None
    ghunt_result: ToolResult | None = None
    shodan_result: ToolResult | None = None
    ai_audit_result: ToolResult | None = None
    phone_result: ToolResult | None = None
    public_records_result: ToolResult | None = None
    mitre_result: ToolResult | None = None
    correlation_plan: list[dict] = []
    correlation_results: list[ToolResult] = []
    analysis_result: dict | None = None
    report_path: str | None = None


class WhatIsKnown(BaseModel):
    handles_and_usernames: list[str] = []
    platforms_with_accounts: list[str] = []
    physical_data: list[str] = []
    credentials_exposed: list[str] = []
    google_footprint: list[str] = []
    breach_history: list[str] = []


class Remediation(BaseModel):
    # Credentials & access
    change_passwords: list[str] = []
    enable_2fa: list[str] = []
    account_hygiene: list[str] = []  # revoke OAuth, audit sessions, delete dormant
    # Identity fraud prevention (non-obvious high-value steps)
    credit_freeze: list[str] = []
    identity_fraud_prevention: list[str] = []  # IRS PIN, SSA lock, USPS
    sim_swap_hardening: list[str] = []
    # Account/data reviews
    account_reviews: list[str] = []
    # Legal removal paths — split by jurisdiction
    gdpr_removals: list[str] = []  # EU/UK-HQ services only
    ccpa_removals: list[str] = []  # US companies (CCPA)
    # Data brokers
    broker_optouts: list[str] = []
    # Ongoing monitoring
    monitoring: list[str] = []
    # No action possible
    no_action_available: list[str] = []


class AnalysisResult(BaseModel):
    overall_risk_score: int
    overall_risk_level: Literal["high", "medium", "low"]
    identity_summary: str
    what_is_known: WhatIsKnown
    top_risks: list[str]
    remediation: Remediation
    breach_severity: Literal["high", "medium", "low", "none"] = "none"
    broker_exposure_severity: Literal["high", "medium", "low", "none"] = "none"
    account_exposure_severity: Literal["high", "medium", "low", "none"] = "none"
