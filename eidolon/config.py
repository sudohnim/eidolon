import os

from dotenv import load_dotenv

load_dotenv()

# Nothing is hard-required. Every data-source tool self-gates via its `requires`
# list and is reported as "skipped — no token" when its key is absent, so a scan
# runs with whatever the user has configured.
REQUIRED_VARS: list[str] = []

# The API keys that unlock a data source. Used by validate() to warn when none
# are set (a scan would be empty). Each tool also lists its own in `requires`.
SOURCE_KEYS = [
    "HIBP_API_KEY",
    "APIFY_API_TOKEN",
    "SCRAPFLY_API_KEY",
    "DEHASHED_API_KEY",
    "SHODAN_API_KEY",
    "NUMVERIFY_API_KEY",
    "COURTLISTENER_API_TOKEN",
    "OPENCORPORATES_API_KEY",
    "WHOXY_API_KEY",
]

OPTIONAL_VARS_WITH_DEFAULTS = {
    "TEST_MODE": "false",
    "RESULTS_OUTPUT_PATH": "output/",
    "OLLAMA_HOST": "http://localhost:11434",  # local LLM; narrative skipped if down
    "SPIDERFOOT_HOST": "http://localhost:5001",  # footprinting; skipped if down
    "SPIDERFOOT_TIMEOUT": "600",  # seconds to wait for SpiderFoot scan
    "HIBP_API_KEY": "",  # haveibeenpwned.com/API/Key (paid)
    "APIFY_API_TOKEN": "",  # apify.com — broker scanning
    "APIFY_ACTOR_ID": "",  # the Apify actor used for broker lookups
    "SCRAPFLY_API_KEY": "",  # scrapfly.io — people-search scraping backend
    "SHODAN_API_KEY": "",  # shodan.io — exposed-host intel
    "NUMVERIFY_API_KEY": "",  # free tier: 100 req/month at numverify.com
    "COURTLISTENER_API_TOKEN": "",  # free; courtlistener.com -> profile -> API
    "OPENCORPORATES_API_KEY": "",  # free tier at opencorporates.com/api_access
    "DEHASHED_EMAIL": "",  # account email for HTTP Basic auth at dehashed.com
    "DEHASHED_API_KEY": "",  # API key from dehashed.com profile (~$5/month)
    "WHOXY_API_KEY": "",  # whoxy.com — reverse WHOIS by email/name/company
}


def validate():
    """Non-fatal: tools skip cleanly when unconfigured. Warn only if NO data
    source is configured at all (a scan would have nothing to report)."""
    if not any(os.getenv(k) for k in SOURCE_KEYS):
        print(
            "WARNING: no data-source API keys configured — the scan will be "
            "sparse. See .env.example for what each key unlocks."
        )


def get(key: str) -> str:
    val = os.getenv(key, OPTIONAL_VARS_WITH_DEFAULTS.get(key))
    if val is None:
        raise RuntimeError(f"Env var {key} not set and has no default")
    return val


def is_test_mode() -> bool:
    return get("TEST_MODE").lower() == "true"
