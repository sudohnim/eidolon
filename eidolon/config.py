import os
import sys

from dotenv import load_dotenv

load_dotenv()

REQUIRED_VARS = [
    "HIBP_API_KEY",
    "APIFY_API_TOKEN",
    "APIFY_ACTOR_ID",
    "SCRAPFLY_API_KEY",
    "OLLAMA_HOST",
    "SPIDERFOOT_HOST",
]

OPTIONAL_VARS_WITH_DEFAULTS = {
    "TEST_MODE": "false",
    "RESULTS_OUTPUT_PATH": "output/",
    "SHODAN_API_KEY": "",
    "NUMVERIFY_API_KEY": "",  # free tier: 100 req/month at numverify.com
    "COURTLISTENER_API_TOKEN": "",  # free; courtlistener.com -> profile -> API
    "OPENCORPORATES_API_KEY": "",  # free tier at opencorporates.com/api_access
    "DEHASHED_EMAIL": "",  # account email for HTTP Basic auth at dehashed.com
    "DEHASHED_API_KEY": "",  # API key from dehashed.com profile (~$5/month)
    "WHOXY_API_KEY": "",  # whoxy.com — reverse WHOIS by email/name/company
    "SPIDERFOOT_TIMEOUT": "600",  # seconds to wait for SpiderFoot scan (default 600)
}


def validate():
    missing = [v for v in REQUIRED_VARS if not os.getenv(v)]
    if missing:
        for var in missing:
            print(f"ERROR: Missing required environment variable: {var}")
        print("Set all required variables in .env before running. See CLAUDE.md.")
        sys.exit(1)


def get(key: str) -> str:
    val = os.getenv(key, OPTIONAL_VARS_WITH_DEFAULTS.get(key))
    if val is None:
        raise RuntimeError(f"Env var {key} not set and has no default")
    return val


def is_test_mode() -> bool:
    return get("TEST_MODE").lower() == "true"
