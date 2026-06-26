# OSINT Agent — Pydantic Models & Fixture Documentation

## Overview

All tool inputs and outputs are typed with Pydantic v2.
Every tool returns a `ToolResult` envelope.
Fixtures in `tests/fixtures/` must match these schemas exactly.
The analysis_node receives a `PipelineState` and returns an `AnalysisResult`.

---

## Shared Types

> Canonical source: `eidolon/core/models.py`

```python
from pydantic import BaseModel
from typing import Literal
from datetime import datetime

class ToolResult(BaseModel):
    """Envelope wrapper for all tool outputs (3-state)."""
    success: bool          # True for ok/skipped, False for error
    tool: str
    input_type: Literal["email", "phone", "name", "org"]
    input_value: str
    timestamp: datetime
    data: dict
    error: str | None = None
    # "ok"      — ran, result in data (may be empty = nothing found)
    # "skipped" — not configured (no API key); distinct from "found nothing"
    # "error"   — ran and failed (error holds the message)
    status: Literal["ok", "skipped", "error"] = "ok"

class InputClassification(BaseModel):
    """Output of intake_node."""
    type: Literal["email", "phone", "name", "org"]
    value: str
    raw: str
```

`PipelineState` now has ~20 tool result fields; see `eidolon/core/models.py` for
the full list. The fixture schemas below follow the 3-state envelope.

---

## 1. HIBP Tool

### Input Model

```python
# models/hibp.py

from pydantic import BaseModel, EmailStr
from typing import Literal

class HibpInput(BaseModel):
    input_type: Literal["email", "phone"]
    value: str  # email address or E.164 phone number

class BreachRecord(BaseModel):
    name: str                    # breach name e.g. "Adobe"
    title: str                   # human readable title
    domain: str                  # e.g. "adobe.com"
    breach_date: str             # ISO date "2013-10-04"
    added_date: str              # ISO datetime
    modified_date: str           # ISO datetime
    pwn_count: int               # number of accounts breached
    description: str             # HTML description
    logo_path: str               # URL to breach logo
    data_classes: list[str]      # e.g. ["Email addresses", "Passwords"]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    is_malware: bool

class HibpOutput(BaseModel):
    query_value: str
    breach_count: int
    breaches: list[BreachRecord]
    paste_count: int             # pastes found, -1 if not checked
```

### Fixture: `tests/fixtures/hibp_response.json`

```json
{
  "success": true,
  "status": "ok",
  "tool": "hibp",
  "input_type": "email",
  "input_value": "test@example.com",
  "timestamp": "2026-06-06T10:00:00",
  "error": null,
  "data": {
    "query_value": "test@example.com",
    "breach_count": 3,
    "paste_count": 2,
    "breaches": [
      {
        "name": "Adobe",
        "title": "Adobe",
        "domain": "adobe.com",
        "breach_date": "2013-10-04",
        "added_date": "2013-12-04T00:00:00Z",
        "modified_date": "2022-05-15T23:52:49Z",
        "pwn_count": 152445165,
        "description": "In October 2013, 153 million Adobe accounts were breached.",
        "logo_path": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
        "data_classes": [
          "Email addresses",
          "Password hints",
          "Passwords",
          "Usernames"
        ],
        "is_verified": true,
        "is_fabricated": false,
        "is_sensitive": false,
        "is_retired": false,
        "is_spam_list": false,
        "is_malware": false
      },
      {
        "name": "LinkedIn",
        "title": "LinkedIn",
        "domain": "linkedin.com",
        "breach_date": "2012-05-05",
        "added_date": "2016-05-22T21:35:40Z",
        "modified_date": "2023-01-10T12:00:00Z",
        "pwn_count": 164611595,
        "description": "In May 2016, LinkedIn had 164 million email addresses exposed.",
        "logo_path": "https://haveibeenpwned.com/Content/Images/PwnedLogos/LinkedIn.png",
        "data_classes": [
          "Email addresses",
          "Passwords"
        ],
        "is_verified": true,
        "is_fabricated": false,
        "is_sensitive": false,
        "is_retired": false,
        "is_spam_list": false,
        "is_malware": false
      },
      {
        "name": "Dropbox",
        "title": "Dropbox",
        "domain": "dropbox.com",
        "breach_date": "2012-07-01",
        "added_date": "2016-08-31T00:19:19Z",
        "modified_date": "2023-01-10T12:00:00Z",
        "pwn_count": 68648009,
        "description": "In mid-2012, Dropbox suffered a data breach.",
        "logo_path": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Dropbox.png",
        "data_classes": [
          "Email addresses",
          "Passwords"
        ],
        "is_verified": true,
        "is_fabricated": false,
        "is_sensitive": false,
        "is_retired": false,
        "is_spam_list": false,
        "is_malware": false
      }
    ]
  }
}
```

### Fixture: `tests/fixtures/hibp_no_results.json`

```json
{
  "success": true,
  "status": "ok",
  "tool": "hibp",
  "input_type": "email",
  "input_value": "clean@example.com",
  "timestamp": "2026-06-06T10:00:00",
  "error": null,
  "data": {
    "query_value": "clean@example.com",
    "breach_count": 0,
    "paste_count": 0,
    "breaches": []
  }
}
```

---

## 2. SpiderFoot Tool

### Input Model

```python
# models/spiderfoot.py

from pydantic import BaseModel
from typing import Literal

class SpiderfootInput(BaseModel):
    target: str
    target_type: Literal["emailaddr", "phone", "human_name", "company_name"]
    # Restricted module list — do not run all modules
    # Full scan takes 30+ mins and hits rate limits
    modules: list[str] = [
        "sfp_hibp",           # breach check
        "sfp_emailrep",       # email reputation
        "sfp_hunter",         # email pattern discovery
        "sfp_whois",          # domain whois
        "sfp_pgp",            # PGP key search
        "sfp_gravatar",       # avatar/profile lookup
        "sfp_social",         # social media handles
        "sfp_pastebin",       # paste site search
    ]

class SpiderfootElement(BaseModel):
    fp: int                  # false positive flag (0 = not FP)
    confidence: int          # 0-100
    risk: int                # 0 = info, 1 = low, 2 = medium, 3 = high
    source: str              # what triggered this finding
    date_found: str          # ISO datetime
    module: str              # which SpiderFoot module found it
    data: str                # the actual finding
    type: str                # element type e.g. "EMAILADDR", "PHONE_NUMBER"

class SpiderfootOutput(BaseModel):
    scan_id: str
    target: str
    status: Literal["FINISHED", "FAILED", "RUNNING", "ABORTED"]
    element_count: int
    elements: list[SpiderfootElement]
    duration_seconds: int
```

### Fixture: `tests/fixtures/spiderfoot_response.json`

```json
{
  "success": true,
  "status": "ok",
  "tool": "spiderfoot",
  "input_type": "email",
  "input_value": "test@example.com",
  "timestamp": "2026-06-06T10:00:00",
  "error": null,
  "data": {
    "scan_id": "abc123def456",
    "target": "test@example.com",
    "status": "FINISHED",
    "element_count": 5,
    "duration_seconds": 120,
    "elements": [
      {
        "fp": 0,
        "confidence": 100,
        "risk": 0,
        "source": "test@example.com",
        "date_found": "2026-06-06 10:01:00",
        "module": "sfp_gravatar",
        "data": "https://www.gravatar.com/avatar/abc123",
        "type": "INTERNET_NAME"
      },
      {
        "fp": 0,
        "confidence": 80,
        "risk": 1,
        "source": "test@example.com",
        "date_found": "2026-06-06 10:01:15",
        "module": "sfp_pastebin",
        "data": "https://pastebin.com/xYz789 - email found in paste dated 2024-03-15",
        "type": "LEAKSITE_CONTENT"
      },
      {
        "fp": 0,
        "confidence": 90,
        "risk": 0,
        "source": "test@example.com",
        "date_found": "2026-06-06 10:01:30",
        "module": "sfp_social",
        "data": "Twitter/X: @testuser (linked via email)",
        "type": "SOCIAL_MEDIA"
      },
      {
        "fp": 0,
        "confidence": 70,
        "risk": 0,
        "source": "test@example.com",
        "date_found": "2026-06-06 10:02:00",
        "module": "sfp_pgp",
        "data": "PGP key found: 0xABCDEF1234567890",
        "type": "PGP_KEY"
      },
      {
        "fp": 0,
        "confidence": 95,
        "risk": 2,
        "source": "test@example.com",
        "date_found": "2026-06-06 10:02:30",
        "module": "sfp_emailrep",
        "data": "Email reputation: suspicious. Seen in 4 breach databases. Deliverable: true.",
        "type": "RAW_RIR_DATA"
      }
    ]
  }
}
```

---

## 3. Broker Scan Tool

### Input Model

```python
# models/broker_scan.py

from pydantic import BaseModel
from typing import Literal

class BrokerScanInput(BaseModel):
    input_type: Literal["email", "phone", "name", "org"]
    value: str
    first_name: str | None = None   # helps Apify lookup for name/org
    last_name: str | None = None
    state: str | None = None        # US state, helps narrow results

class BrokerProfile(BaseModel):
    broker_name: str             # e.g. "Spokeo"
    broker_domain: str           # e.g. "spokeo.com"
    source: Literal["apify", "google_cse"]
    profile_url: str | None      # direct link to profile if found
    data_found: list[str]        # e.g. ["name", "address", "phone", "relatives"]
    confidence: Literal["high", "medium", "low"]
    optout_url: str              # direct opt-out URL for this broker

class BrokerScanOutput(BaseModel):
    query_value: str
    brokers_found_count: int
    brokers_found: list[BrokerProfile]
    exposure_score: int          # 0-100, calculated from broker count + data depth
    easyoptouts_url: str = "https://easyoptouts.com/dashboard"
    priority_optouts: list[str]  # top 5 broker domains to address first
```

### Fixture: `tests/fixtures/broker_apify_response.json`

```json
{
  "success": true,
  "status": "ok",
  "tool": "broker_scan",
  "input_type": "name",
  "input_value": "John Doe",
  "timestamp": "2026-06-06T10:00:00",
  "error": null,
  "data": {
    "query_value": "John Doe",
    "brokers_found_count": 4,
    "exposure_score": 62,
    "easyoptouts_url": "https://easyoptouts.com/dashboard",
    "priority_optouts": [
      "spokeo.com",
      "whitepages.com",
      "beenverified.com",
      "truthfinder.com"
    ],
    "brokers_found": [
      {
        "broker_name": "Spokeo",
        "broker_domain": "spokeo.com",
        "source": "apify",
        "profile_url": "https://www.spokeo.com/John-Doe/New-York/123456",
        "data_found": ["name", "age", "address", "phone", "relatives", "email"],
        "confidence": "high",
        "optout_url": "https://www.spokeo.com/optout"
      },
      {
        "broker_name": "Whitepages",
        "broker_domain": "whitepages.com",
        "source": "apify",
        "profile_url": "https://www.whitepages.com/name/John-Doe/NY",
        "data_found": ["name", "address", "phone"],
        "confidence": "high",
        "optout_url": "https://www.whitepages.com/suppression_requests/new"
      },
      {
        "broker_name": "BeenVerified",
        "broker_domain": "beenverified.com",
        "source": "google_cse",
        "profile_url": null,
        "data_found": ["name", "address"],
        "confidence": "medium",
        "optout_url": "https://www.beenverified.com/app/optout/search"
      },
      {
        "broker_name": "TruthFinder",
        "broker_domain": "truthfinder.com",
        "source": "google_cse",
        "profile_url": null,
        "data_found": ["name"],
        "confidence": "low",
        "optout_url": "https://www.truthfinder.com/opt-out/"
      }
    ]
  }
}
```

---

## 4. AI Audit Tool

### Input Model

```python
# models/ai_audit.py

from pydantic import BaseModel
from typing import Literal

class AiAuditInput(BaseModel):
    platforms: list[str]    # platforms user says they use
    # e.g. ["claude", "chatgpt", "gemini", "grok", "copilot"]

class AiPlatformPolicy(BaseModel):
    platform_id: str
    display_name: str
    trains_consumer_by_default: bool
    opt_out_available: bool
    consumer_retention_opted_in: str     # e.g. "5 years"
    consumer_retention_opted_out: str    # e.g. "30 days"
    api_excluded_from_training: bool
    jurisdiction: str                    # e.g. "US", "EU", "China"
    risk_level: Literal["high", "medium", "low"]
    opt_out_url: str
    notes: str

class AiAuditOutput(BaseModel):
    platforms_checked: list[str]
    platforms_found: list[AiPlatformPolicy]
    high_risk_count: int
    action_items: list[str]             # ordered by priority
    overall_risk: Literal["high", "medium", "low"]
```

### Policy Database: `data/ai_policies.json`

```json
{
  "last_updated": "2026-06-06",
  "platforms": {
    "claude": {
      "platform_id": "claude",
      "display_name": "Anthropic Claude (Consumer)",
      "trains_consumer_by_default": true,
      "opt_out_available": true,
      "consumer_retention_opted_in": "5 years",
      "consumer_retention_opted_out": "30 days",
      "api_excluded_from_training": true,
      "jurisdiction": "US",
      "risk_level": "medium",
      "opt_out_url": "https://claude.ai/settings/privacy",
      "notes": "Changed policy Aug 2025. Consumer Free/Pro/Max default to training. API/Enterprise excluded. Opt out reduces retention to 30 days."
    },
    "chatgpt": {
      "platform_id": "chatgpt",
      "display_name": "OpenAI ChatGPT (Consumer)",
      "trains_consumer_by_default": true,
      "opt_out_available": true,
      "consumer_retention_opted_in": "indefinite",
      "consumer_retention_opted_out": "30 days",
      "api_excluded_from_training": true,
      "jurisdiction": "US",
      "risk_level": "medium",
      "opt_out_url": "https://chat.openai.com/settings/data-controls",
      "notes": "OpenAI is only provider allowing history without consenting to training. API excluded by default. June 2025 court order required some retention."
    },
    "gemini": {
      "platform_id": "gemini",
      "display_name": "Google Gemini (Consumer)",
      "trains_consumer_by_default": true,
      "opt_out_available": false,
      "consumer_retention_opted_in": "indefinite",
      "consumer_retention_opted_out": "N/A - no opt out",
      "api_excluded_from_training": true,
      "jurisdiction": "US",
      "risk_level": "high",
      "opt_out_url": "https://myaccount.google.com/data-and-privacy",
      "notes": "No formal training opt-out. Disabling Activity Control loses chat history. Mobile app may access call logs and installed apps. Vertex AI (paid) excluded."
    },
    "grok": {
      "platform_id": "grok",
      "display_name": "xAI Grok",
      "trains_consumer_by_default": true,
      "opt_out_available": false,
      "consumer_retention_opted_in": "indefinite",
      "consumer_retention_opted_out": "N/A",
      "api_excluded_from_training": false,
      "jurisdiction": "US",
      "risk_level": "high",
      "opt_out_url": "https://x.com/settings/privacy_and_safety",
      "notes": "Prompts tied to X account. Can delete threads but cannot disable training. Linked to full X social graph."
    },
    "copilot": {
      "platform_id": "copilot",
      "display_name": "Microsoft Copilot (Consumer)",
      "trains_consumer_by_default": true,
      "opt_out_available": true,
      "consumer_retention_opted_in": "180 days",
      "consumer_retention_opted_out": "30 days",
      "api_excluded_from_training": true,
      "jurisdiction": "US",
      "risk_level": "medium",
      "opt_out_url": "https://account.microsoft.com/privacy",
      "notes": "Enterprise plans have Customer Lockbox option. Consumer plans opt-out available but non-obvious."
    },
    "meta_ai": {
      "platform_id": "meta_ai",
      "display_name": "Meta AI",
      "trains_consumer_by_default": true,
      "opt_out_available": false,
      "consumer_retention_opted_in": "indefinite",
      "consumer_retention_opted_out": "N/A",
      "api_excluded_from_training": false,
      "jurisdiction": "US",
      "risk_level": "high",
      "opt_out_url": "https://www.facebook.com/privacy/center",
      "notes": "Governed by Meta general Data Policy. Prompts linked to FB/IG/WhatsApp account and cross-platform ad graph. No dedicated opt-out. EU removed opt-out option."
    },
    "perplexity": {
      "platform_id": "perplexity",
      "display_name": "Perplexity AI",
      "trains_consumer_by_default": false,
      "opt_out_available": true,
      "consumer_retention_opted_in": "indefinite",
      "consumer_retention_opted_out": "0 days",
      "api_excluded_from_training": true,
      "jurisdiction": "US",
      "risk_level": "low",
      "opt_out_url": "https://www.perplexity.ai/settings",
      "notes": "Sonar API: zero data retention, no training. Consumer Personal Search feature may use activity. Best default privacy posture of major providers."
    },
    "deepseek_cloud": {
      "platform_id": "deepseek_cloud",
      "display_name": "DeepSeek (Cloud/App)",
      "trains_consumer_by_default": true,
      "opt_out_available": false,
      "consumer_retention_opted_in": "indefinite",
      "consumer_retention_opted_out": "N/A",
      "api_excluded_from_training": false,
      "jurisdiction": "China",
      "risk_level": "high",
      "opt_out_url": "N/A",
      "notes": "Data stored on Chinese servers under PRC AI regulations. No published data handling disclosures. Hidden code found linking to China Mobile registry. Use local weights only."
    }
  }
}
```

### Fixture: `tests/fixtures/ai_audit_response.json`

```json
{
  "success": true,
  "status": "ok",
  "tool": "ai_audit",
  "input_type": "email",
  "input_value": "test@example.com",
  "timestamp": "2026-06-06T10:00:00",
  "error": null,
  "data": {
    "platforms_checked": ["claude", "chatgpt", "gemini", "grok"],
    "high_risk_count": 2,
    "overall_risk": "high",
    "action_items": [
      "CRITICAL: Disable Grok training — cannot be disabled, consider deleting account",
      "CRITICAL: Gemini has no training opt-out — disable Activity Control and accept history loss, or switch to Vertex AI",
      "ACTION: Opt out of Claude training at claude.ai/settings/privacy",
      "ACTION: Opt out of ChatGPT training at chat.openai.com/settings/data-controls",
      "INFO: Claude API usage is already excluded from training"
    ],
    "platforms_found": [
      {
        "platform_id": "claude",
        "display_name": "Anthropic Claude (Consumer)",
        "trains_consumer_by_default": true,
        "opt_out_available": true,
        "consumer_retention_opted_in": "5 years",
        "consumer_retention_opted_out": "30 days",
        "api_excluded_from_training": true,
        "jurisdiction": "US",
        "risk_level": "medium",
        "opt_out_url": "https://claude.ai/settings/privacy",
        "notes": "Changed policy Aug 2025. Consumer Free/Pro/Max default to training."
      },
      {
        "platform_id": "chatgpt",
        "display_name": "OpenAI ChatGPT (Consumer)",
        "trains_consumer_by_default": true,
        "opt_out_available": true,
        "consumer_retention_opted_in": "indefinite",
        "consumer_retention_opted_out": "30 days",
        "api_excluded_from_training": true,
        "jurisdiction": "US",
        "risk_level": "medium",
        "opt_out_url": "https://chat.openai.com/settings/data-controls",
        "notes": "API excluded by default."
      },
      {
        "platform_id": "gemini",
        "display_name": "Google Gemini (Consumer)",
        "trains_consumer_by_default": true,
        "opt_out_available": false,
        "consumer_retention_opted_in": "indefinite",
        "consumer_retention_opted_out": "N/A - no opt out",
        "api_excluded_from_training": true,
        "jurisdiction": "US",
        "risk_level": "high",
        "opt_out_url": "https://myaccount.google.com/data-and-privacy",
        "notes": "No formal training opt-out available."
      },
      {
        "platform_id": "grok",
        "display_name": "xAI Grok",
        "trains_consumer_by_default": true,
        "opt_out_available": false,
        "consumer_retention_opted_in": "indefinite",
        "consumer_retention_opted_out": "N/A",
        "api_excluded_from_training": false,
        "jurisdiction": "US",
        "risk_level": "high",
        "opt_out_url": "https://x.com/settings/privacy_and_safety",
        "notes": "Cannot disable training. Linked to X social graph."
      }
    ]
  }
}
```

---

## 5. Analysis Node Output

The analysis_node receives the full `PipelineState` as JSON and returns structured analysis. The local Ollama model must respond in JSON only.

### Prompt Template (agent/prompts.py)

```python
ANALYSIS_PROMPT = """
You are a privacy analyst. You will receive OSINT scan results 
as JSON and must return a structured analysis in JSON only.
No preamble. No markdown. Return valid JSON matching this schema exactly.

Input will contain: hibp_result, broker_result, 
spiderfoot_result, ai_audit_result

Return this structure:
{
  "overall_risk_score": <int 0-100>,
  "overall_risk_level": <"high"|"medium"|"low">,
  "summary": <string, 2-3 sentences max>,
  "top_findings": [<string>, ...],  // max 5, most important first
  "immediate_actions": [<string>, ...],  // max 5, ordered by urgency
  "longer_term_actions": [<string>, ...],  // max 5
  "breach_severity": <"high"|"medium"|"low"|"none">,
  "broker_exposure_severity": <"high"|"medium"|"low"|"none">,
  "ai_exposure_severity": <"high"|"medium"|"low"|"none">
}
"""
```

### Fixture: `tests/fixtures/analysis_response.json`

```json
{
  "overall_risk_score": 68,
  "overall_risk_level": "medium",
  "summary": "Target has significant breach exposure across 3 major incidents affecting email and password data. Broker presence is moderate with 4 sites holding personal data. Two AI platforms present unresolvable training risks.",
  "top_findings": [
    "Email found in 3 major breaches including LinkedIn (164M accounts) and Adobe (152M accounts)",
    "Full profile including address and relatives found on Spokeo and Whitepages",
    "Gemini and Grok have no opt-out for training — data permanently embedded",
    "Email found in pastebin paste dated 2024 — recent exposure",
    "PGP key publicly linked to email — identity correlation risk"
  ],
  "immediate_actions": [
    "Opt out of Claude training at claude.ai/settings/privacy",
    "Opt out of ChatGPT training at chat.openai.com/settings/data-controls",
    "Submit opt-out to Spokeo at spokeo.com/optout — highest data depth",
    "Submit opt-out to Whitepages — address and phone exposed",
    "Change password for any accounts using credentials from Adobe or LinkedIn breach"
  ],
  "longer_term_actions": [
    "Consider deleting Grok/X account if not essential — training cannot be disabled",
    "Submit remaining broker opt-outs via EasyOptOuts dashboard",
    "Investigate pastebin paste to understand what data was exposed",
    "Consider email alias strategy to prevent future cross-broker correlation",
    "Review whether PGP key should remain publicly linked to this identity"
  ],
  "breach_severity": "high",
  "broker_exposure_severity": "medium",
  "ai_exposure_severity": "high"
}
```

---

## 6. Error Response Fixture

All tools must return this shape on failure — never raise exceptions.

```json
{
  "success": false,
  "status": "error",
  "tool": "hibp",
  "input_type": "email",
  "input_value": "test@example.com",
  "timestamp": "2026-06-06T10:00:00",
  "error": "HIBP API returned 401 — check HIBP_API_KEY in .env",
  "data": {}
}
```

---

## CLAUDE.md Addition

Add this section to CLAUDE.md:

```markdown
## Pydantic Models
All tool inputs and outputs typed with Pydantic v2.
Models live in models/ directory.
Every tool returns ToolResult envelope from models/shared.py.
LangGraph state typed as PipelineState from models/shared.py.
No untyped dicts passed between nodes — always use model instances.
analysis_node receives PipelineState serialized to JSON string.
analysis_node output parsed and validated against AnalysisResult.

## Fixtures
Fixtures in tests/fixtures/ must match Pydantic model schemas exactly.
Fixtures are the source of truth for expected data shapes.
If a real API returns a field not in the model, log and ignore it.
If a real API is missing a required field, treat as error response.
```
