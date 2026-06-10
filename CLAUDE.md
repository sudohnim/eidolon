# Eidolon — Privacy OSINT Agent

## Purpose
Local privacy audit tool. Runs OSINT tools against a target identity
(email / phone / name / org), analyzes results using a local Ollama model,
and produces a privacy risk report. No data leaves the machine except to
the explicitly defined external API endpoints listed below.

## Stack
- Python 3.12
- LangChain + LangGraph for pipeline orchestration
- Ollama (llama3.1:8b) — local inference, runs in Docker
- SpiderFoot — broad OSINT, runs in Docker
- uv for package management
- pytest for testing
- Docker + docker-compose for all service management

---

## Running the Tool

### One command
```bash
./bin/run.sh "target@email.com"
./bin/run.sh "John Smith" --state CA
./bin/run.sh "+14155550100"
./bin/run.sh --email target@example.com --name "John Smith" --state NY
```

`bin/run.sh` handles everything: starts SpiderFoot and Ollama if not running,
waits for both to report healthy via Docker healthchecks, pulls the model if
missing, builds the agent image if needed, then fires the scan.

### CLI flags
```
--email EMAIL       Target email address
--phone PHONE       Target phone number (E.164 or 10-digit)
--name NAME         Target full name (2–4 words, title-cased)
--city CITY         Target city (used with --name for broker search)
--state STATE       Target state, e.g. CA (required with --name)
--zip ZIP           Target zip code (5 or 9 digits)
```

`--name` requires at least one of `--city`, `--state`, or `--zip`.

### Environment check
```bash
./bin/check.sh
```

### GHunt one-time login (optional)
```bash
docker compose run --rm agent ghunt login
```

---

## Docker Architecture

Three services defined in `docker-compose.yml`:

| Service | Image | Port | Role |
|---------|-------|------|------|
| spiderfoot | spiderfoot | 5001 | Long-lived OSINT scanner |
| ollama | ollama/ollama | 11434 | Long-lived local LLM |
| agent | osint-agent (built locally) | — | Fire-and-forget scan runner |

- `spiderfoot` and `ollama` use `restart: unless-stopped` — start once, stay up
- `agent` uses `profiles: [run]` — only starts via `docker compose run --rm agent`
- `agent` has `depends_on: service_healthy` for both services
- Ollama uses `init: true` to reap zombie subprocesses spawned during inference
- SpiderFoot healthcheck uses `python3 urllib` (no curl in that image)
- Ollama healthcheck uses `ollama list`
- `bin/run.sh` uses `--no-deps` on `docker compose run` — services already verified healthy in pre-flight, no need for compose to touch them again

### Volumes
- `ollama_models` — persists downloaded models across container restarts
- `ghunt_creds` — persists GHunt auth token (`~/.malfrats/ghunt/creds.m`)
- `./output` — bind-mounted so reports land on the host at `./output/`

---

## Prerequisites

### Required — will fail loudly without these
1. **Docker Desktop** — `docker info` must succeed
2. **`.env` file** — copy `.env.example`, fill all required vars

### Required API keys (`.env`)
```
HIBP_API_KEY=        # haveibeenpwned.com/API/Key — $3.50/month
APIFY_API_TOKEN=     # apify.com → Settings → API Tokens (free tier ok)
APIFY_ACTOR_ID=      # "TruePeopleSearch Contact Finder" actor ID from Apify Store
SCRAPFLY_API_KEY=    # scrapfly.io (used by Holehe internals)
```

### Optional — tools skip gracefully when not set
```
NUMVERIFY_API_KEY=          # numverify.com — real-time carrier/line-type (free: 100/month)
SHODAN_API_KEY=             # shodan.io — infrastructure scan on IPs found by SpiderFoot
COURTLISTENER_API_TOKEN=    # courtlistener.com → profile → API (free)
OPENCORPORATES_API_KEY=     # opencorporates.com/api_access (free tier)
DEHASHED_EMAIL=             # account email for dehashed.com HTTP Basic auth (~$5/month)
DEHASHED_API_KEY=           # API key from dehashed.com profile
WHOXY_API_KEY=              # whoxy.com — reverse WHOIS by email ($3/month)
```

### Automatic (set by docker-compose, not .env)
```
SPIDERFOOT_HOST=http://spiderfoot:5001
OLLAMA_HOST=http://ollama:11434
```

### Removed — do not add back
- ~~Google Custom Search API~~ — closed to new customers as of early 2026
- ~~EasyOptOuts API~~ — no API; tool outputs dashboard link only
- ~~Exodus Privacy~~ — app-level tracker data, not person-specific; same result for all users of an app

---

## Pipeline

```
intake_node

Wave 1 (parallel, input-only — no inter-tool dependencies):
  → breach_check_node     # HIBP — breach metadata
  → dehashed_node         # DeHashed — actual breach record contents (passwords, addresses)
  → whoxy_node            # Whoxy — reverse WHOIS, all domains registered to email
  → phone_pivot_node      # phonenumbers (offline) + optional Numverify (real-time)
  → surface_map_node      # SpiderFoot — broad OSINT across 8 modules
  → holehe_node           # 121 platforms via password-reset probing
  → blackbird_node        # 600+ platforms via email
  → maigret_node          # 3155 platforms via username (derived from email prefix)
  → ghunt_node            # Google account intel (skipped if no creds)

Wave 2 (parallel, needs Wave 1 results):
  → broker_scan_node      # Apify TruePeopleSearch (name inputs only; uses GHunt/SpiderFoot name)
  → shodan_node           # IPs extracted from SpiderFoot elements
  → public_records_node   # CourtListener + OpenCorporates (needs resolved name)
  → ai_audit_node         # platform list from Holehe/Blackbird/SpiderFoot → policy DB lookup

  → correlation_planner_node  # Ollama (llama3.1:8b) plans up to 5 follow-up pivots
  → correlation_execute_node  # executes pivots: username/email/IP/phone/name
  → analysis_node             # Ollama synthesizes all findings into risk profile
  → report_node               # writes .md + .json to output/
```

**Ollama is used twice:** `correlation_planner_node` (plans pivots, `num_ctx=4096`) and
`analysis_node` (full synthesis, `num_ctx=8192 num_predict=4096`). All other nodes are
deterministic Python with no LLM involvement.

---

## Tools

### tools/hibp.py
HIBP API v3. Email inputs only (phone not supported by HIBP v3).
`GET https://haveibeenpwned.com/api/v3/breachedaccount/{account}`
Header: `hibp-api-key`. Returns `HibpOutput` with breach list.
HIBP returns PascalCase JSON — use `alias_generator=to_pascal` + `model_validate()`.
Spam-list-only entries return only `Name` field; all other fields are optional with defaults.

### tools/dehashed.py
`GET https://api.dehashed.com/search?query=email:{email}&size=50`
Auth: HTTP Basic with `DEHASHED_EMAIL` (account email) + `DEHASHED_API_KEY`.
Skips gracefully if either env var is missing.
Returns `DehashedOutput` with raw entries plus aggregated signals: `plaintext_password_count`,
`hashed_password_count`, `unique_usernames`, `unique_addresses`, `unique_phones`, `unique_databases`.
Complements HIBP — HIBP shows "you were in Adobe 2013"; DeHashed shows the actual MD5 hash or
plaintext password, plus any physical address/phone embedded in the breach record.
`_hash_type(h)` detects MD5/SHA-1/SHA-256/SHA-512/bcrypt/pbkdf2 from hash length and prefix.

### tools/whoxy.py
`GET https://api.whoxy.com/?key=KEY&reverse=email&value=EMAIL&page=N`
Auth: `?key=` query param. Paginates up to 5 pages (500 domains max).
Skips gracefully if `WHOXY_API_KEY` not set.
Returns `WhoxyOutput` with domain list plus aggregated signals: `unique_company_names`
(pivot to OpenCorporates), `unique_addresses` (physical data), `active_domain_count`,
`expired_domain_count` (expired domains = impersonation/typosquat risk, flagged in digest).
Registrant contact fields: `full_name`, `email_address`, `company_name`, `mailing_address`,
`city_name`, `state_name`, `zip_code`, `country_name` nested under `registrant_contact`.

### tools/spiderfoot.py
SpiderFoot HTTP API at `SPIDERFOOT_HOST`.
Restricted module list only (8 modules) — full scan takes 30+ mins:
`sfp_hibp, sfp_emailrep, sfp_hunter, sfp_whois, sfp_pgp, sfp_gravatar, sfp_social, sfp_pastebin`
Polls scan status every few seconds until FINISHED.
`POLL_TIMEOUT = 300` (5 minutes hard cap).

### tools/broker_scan.py
Name inputs only — email/phone return empty `BrokerScanOutput` (skip gracefully).
Uses Apify actor client. Access run fields as attributes (`run.id`, `run.status`,
`run.default_dataset_id`) — not `.get()`, it's a Pydantic object not a dict.
Google CSE completely removed — API closed to new customers.

### tools/holehe.py
Uses `holehe` Python library directly (async).
Checks 121 platforms via password-reset flow.
Returns platforms where the email has a registered account.

### tools/blackbird.py
Subprocess call to Blackbird (cloned to `/opt/blackbird` in Docker image at build time).
`PYTHONPATH=src`, parses JSON output from `results/` directory.
600+ platforms checked by email.
Do not add a `vendor/blackbird` directory — Blackbird is baked into the image.

### tools/maigret.py
Uses `maigret.checking.maigret` async function directly (Python library, not subprocess).
Loads `MaigretDatabase` from bundled `data.json` (3155 sites).
Username derived from email prefix (e.g. `minh.v.mai` from `minh.v.mai@gmail.com`).
Result stored in `state.sherlock_result` (legacy field name — do not rename, tests depend on it).
Suppresses maigret's own logging (set to CRITICAL).

### tools/ghunt.py
Subprocess `ghunt` CLI. Requires one-time `ghunt login` to write credentials to
`~/.malfrats/ghunt/creds.m` (persisted in `ghunt_creds` Docker volume).
Skipped gracefully if credentials file is missing.

### tools/phone.py
Two-layer lookup — works with zero API keys:

**Layer 1 (always runs): `phonenumbers` (Google libphonenumber)**
- Validates E.164 format, parses number structure
- Carrier hint from number-range DB (not real-time, but reliable for mobile/landline/VoIP class)
- Geographic description (`geocode`), IANA timezone(s)
- `is_voip: true` flag if VoIP/anonymous number detected — surfaces in report as higher fraud risk
- Fully offline, no API calls required

**Layer 2 (optional supplement): Numverify (`NUMVERIFY_API_KEY` in .env)**
- Real-time carrier name and confirmed line type
- Free tier: 100 req/month
- If key missing or call fails, Layer 1 baseline is used as-is

### tools/public_records.py
Two sources for name inputs. Both skip gracefully if keys not set or on network failure.

**CourtListener** (`courtlistener.com/api/rest/v4/search/`)
- `GET /api/rest/v4/search/?q="Name"&type=r&order_by=score+desc` — `type=r` = RECAP federal dockets
- **Not** `/api/rest/v4/dockets/` — that endpoint fetches a docket by ID, it does not search by name
- Response fields are camelCase: `caseName`, `dateFiled`, `suitNature`, `docketNumber`
- Requires free `COURTLISTENER_API_TOKEN` (courtlistener.com → profile → API)

**OpenCorporates** (`api.opencorporates.com/v0.4/officers/search`)
- Officer/director roles across 140+ jurisdictions
- Requires free `OPENCORPORATES_API_KEY` (opencorporates.com/api_access)
- Response wraps each record: `{"officer": {..., "company": {...}}}`

### tools/ai_audit.py
Dynamic — derives platform list from actual scan results:
`blackbird_result` accounts + `holehe_result` registrations + SpiderFoot SOCIAL_MEDIA elements.
Checks those platforms against `data/ai_policies.json` policy database.
NOT a static list — reflects what was actually found in the scan.

### tools/shodan.py
Requires `SHODAN_API_KEY`. Called per-IP against IPs extracted from SpiderFoot elements.
Skips if no IP_ADDRESS elements found or key not set.

### tools/privacy_url_lookup.py
Static lookup — not an external API call.
`enrich_findings_context(findings)` injects verified deletion URLs and legal frameworks
(GDPR/CCPA) into analysis output. Called at end of `analysis_node` after LLM response.

---

## Analysis Node

Sends a **compact digest** to Ollama, not the full state dump.
`_build_analysis_digest(state)` in `nodes.py` extracts signal only:
breach names/years/data classes, platform lists, counts, exposure scores.
~2-3KB sent vs 50-100KB for full state — critical for local 8B model performance.

Model: `llama3.1:8b`, `temperature=0`, `timeout=300`, `num_ctx=8192`, `num_predict=4096`.

Response handling:
- Strip markdown code fences before `json.loads()` — model often wraps output in ` ```json `
- `_parse_json_tolerant()` repairs trailing commas and extracts first `{...}` block before failing
- Raise explicit error on empty response (blank = timeout was hit)
- `JSONDecodeError` and all other exceptions caught — returns error fallback dict
- Fallback result has `overall_risk_score: 0` and empty sections (pipeline always completes)

**The LLM only produces the narrative**, not the to-do list. The prompt asks for
`identity_summary`, `what_is_known`, `top_risks`, `findings_context`, and severities —
**not** `remediation`. `_postprocess_analysis(state, analysis)` then repairs and completes
the model's output before it reaches the report:
- `_normalize_what_is_known()` — coerces any object-shaped items the model emits
  (`{"PlatformName":..}`, `{"BreachName":..}`) into clean strings, drops junk usernames
  (all-digits/too-short/placeholder), filters `physical_data` to real street addresses
  (rejects raw GEOINFO fragments with no street number), and strips internal probe URLs
  (Holehe/Blackbird `api.*`/`email_available` endpoints are not user-facing profiles).
- `_filter_top_risks()` — drops risks that parrot the prompt's few-shot example breach
  names (ParkMobile/PDL/etc.) unless that breach is actually present in scan state.
- `_finalize_remediation()` — **builds the entire remediation section deterministically
  from scan state** (`_build_deterministic_remediation()`): change-passwords from real
  breach password classes, 2FA/privacy-review from confirmed active accounts, credit
  freeze / IRS-PIN / SIM-swap / broker opt-outs gated on the relevant findings, and
  always-on monitoring. This is why the report is never sparse — the model dropping
  sections no longer matters. Deterministic sections win; the (normalized) LLM output is
  only a fallback for sections the rules don't generate. Unit-tested in
  `tests/test_analysis_postprocess.py` (the TEST_MODE pipeline path returns the fixture
  and bypasses post-processing, so the helpers are covered directly).

## Correlation Planner Node

Also uses Ollama (`num_ctx=4096`, `num_predict=512`).
Sends same digest, asks for up to 5 follow-up pivots as JSON.
`_is_real_value()` validates pivots — rejects placeholder phones (sequential digits, all-same),
private IPs (10.x, 192.168.x, 127.x), and placeholder names (`<name>`, `unknown`, etc.).

---

## Output

Files written to `./output/` (bind-mounted from host):
```
output/YYYY-MM-DD_HH-MM_email_results.json   # full PipelineState dump
output/YYYY-MM-DD_HH-MM_email_report.md      # human-readable privacy report
```

Report sections:
- **What the Internet Knows About You** — identity_summary + what_is_known subsections
- **Top Risks** — up to 5 specific findings
- **What To Do** — do_today / do_this_week / ongoing (checklist format)
- **Raw Tool Results** — one-line summary per tool

---

## Tool Contract

Every tool must:
- Accept a typed Pydantic input model (or plain args for simple tools like `public_records.run(name)`)
- Return `ToolResult` envelope (never raw dicts, never raise)
- Handle errors by returning `ToolResult(success=False, error=..., data={})`
- Log what it queried (input value), **never** log the results (output data)
- In `TEST_MODE=true`, return fixture from `tests/fixtures/` without hitting any API

---

## Testing

```bash
TEST_MODE=true uv run pytest -x -q
```

`TEST_MODE=true` makes all tools return fixtures. Full pipeline must pass in TEST_MODE.
Currently: **115 tests**.

Build order (follow strictly for new tools):
1. Fixture (`tests/fixtures/<tool>_response.json`)
2. Pydantic model (`models/<tool>.py`)
3. Tool wrapper with TEST_MODE (`tools/<tool>.py`)
4. Unit tests — all pass before proceeding
5. Wire into `agent/nodes.py`: node function → wave → digest → report row
6. Integration test (full pipeline in TEST_MODE)
7. Real endpoints only after everything is green

---

## Linting & pre-commit

```bash
./bin/lint.sh          # check black, isort, flake8, mypy
./bin/lint.sh --fix    # auto-fix black + isort, then check
```

A git pre-commit hook (`.githooks/pre-commit`) runs the same checks on the Python
files you're committing and blocks the commit on failure. It is scoped to **staged**
files (so it never blocks on unrelated pre-existing lint debt) and mirrors
`bin/lint.sh`'s scope: black + isort over all staged `.py`, flake8 + mypy over staged
source files excluding `tests/`.

- Enable (already done by `bin/setup.sh`): `git config core.hooksPath .githooks`
- Auto-fix a blocked commit: `./bin/lint.sh --fix`
- Bypass once (not advised): `git commit --no-verify`

The hook is tracked in-repo under `.githooks/`; `core.hooksPath` is local git config,
so each clone enables it via `bin/setup.sh` (or the `git config` line above).

---

## Privacy Constraints

- No API keys in code — `.env` only, gitignored
- No external calls except defined tool endpoints
- Ollama: `http://ollama:11434` (Docker internal) only
- SpiderFoot: `http://spiderfoot:5001` (Docker internal) only
- Results never logged to stdout or log files
- Only `correlation_planner_node` and `analysis_node` send data to Ollama
- No telemetry, no analytics, no external error reporting
- No facial recognition — PimEyes/FaceCheck.ID explicitly excluded

---

## Project Structure

```
osint-agent/
├── CLAUDE.md
├── .env                          # gitignored
├── .env.example
├── .gitignore
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── main.py
├── config.py
├── bin/
│   ├── run.sh                    # pre-flight + scan launcher
│   └── check.sh                  # environment verification
├── data/
│   ├── ai_policies.json
│   └── privacy_urls.json         # verified deletion URLs for enrich_findings_context
├── models/
│   ├── shared.py                 # ToolResult, PipelineState, InputClassification, AnalysisResult
│   ├── hibp.py
│   ├── dehashed.py
│   ├── whoxy.py
│   ├── spiderfoot.py
│   ├── broker_scan.py
│   ├── ai_audit.py
│   ├── holehe.py
│   ├── blackbird.py
│   ├── maigret.py
│   ├── sherlock.py               # legacy alias — used by maigret output
│   ├── ghunt.py
│   ├── phone.py
│   ├── public_records.py
│   └── shodan.py
├── tools/
│   ├── hibp.py
│   ├── dehashed.py
│   ├── whoxy.py
│   ├── spiderfoot.py
│   ├── broker_scan.py
│   ├── ai_audit.py
│   ├── holehe.py
│   ├── blackbird.py
│   ├── maigret.py
│   ├── ghunt.py
│   ├── phone.py
│   ├── public_records.py
│   ├── shodan.py
│   └── privacy_url_lookup.py
├── agent/
│   ├── graph.py
│   ├── nodes.py                  # all node functions + _build_analysis_digest()
│   ├── prompts.py                # ANALYSIS_PROMPT + CORRELATION_PROMPT
│   └── report.py                 # PDF/Markdown report writer
├── tests/
│   ├── fixtures/                 # one JSON per tool (TEST_MODE returns these)
│   ├── test_tools.py
│   ├── test_pipeline.py
│   └── test_routing.py
└── output/                       # gitignored, bind-mounted in Docker
```

---

## Known Issues / Lessons Learned

- **Google CSE removed** — API closed to new customers (early 2026). All broker scanning is Apify only.
- **Exodus removed** — app-level tracker data (same result for every Instagram user). Not person-specific. Replaced by Whoxy/DeHashed for physical data coverage.
- **SpiderFoot healthcheck** — the spiderfoot image has no `curl`. Use `python3 urllib` in the healthcheck test.
- **Ollama zombie processes** — `init: true` required in docker-compose to reap subprocesses spawned during inference.
- **`docker compose run` recreates deps** — use `--no-deps` flag since pre-flight already verified health.
- **Ollama empty response** — `timeout=300` needed; 120s gets truncated on complex prompts with an 8B model.
- **Model wraps JSON in fences** — always strip ` ```json ` before `json.loads()`.
- **Apify Run object** — access fields as attributes (`run.id`), not dict keys (`.get("id")`).
- **HIBP PascalCase** — use `alias_generator=to_pascal` + `model_validate()`; most fields optional (spam entries return Name only).
- **Full state to Ollama** — sending the raw `state.model_dump_json()` (50-100KB) to a local 8B model causes multi-minute hangs and empty responses. Use `_build_analysis_digest()` to send a 2-3KB summary instead.
- **Ollama `num_ctx` default is 2048** — `ANALYSIS_PROMPT` alone is ~2300 tokens, so the default context window truncates both the prompt AND the output (report shows no remediation / What To Do section). Always set `num_ctx=8192` and `num_predict=4096` on the analysis `ChatOllama` call.
- **`docker compose ps --format json`** — returns a JSON array `[{...}]`, not a bare object. Parse with `json.load(sys.stdin)[0].get('Health')`.
- **uv Python selection in Docker** — the Playwright jammy base image ships Python 3.10 (Ubuntu 22.04 default), below the `requires-python = ">=3.11"` floor. Setting `UV_PYTHON_PREFERENCE=only-system` then fails with "No interpreter found". Fix: set `ENV UV_PYTHON=3.12` in the Dockerfile so uv downloads exactly Python 3.12, which has pre-built Pillow wheels on linux/aarch64.
- **CourtListener wrong endpoint** — `/api/rest/v4/dockets/` fetches by docket ID; use `/api/rest/v4/search/?type=r` for name search. Search API returns camelCase fields (`caseName`, `dateFiled`, `suitNature`).
- **CourtListener requires a free API token** — returns 401 without auth. Register at courtlistener.com → profile → API token. Tool skips gracefully if missing.
- **OpenCorporates requires a free API key** — returns 401 without auth. Register at opencorporates.com/api_access. Tool skips gracefully if missing.
- **Correlation planner LLM JSON** — llama3.1:8b sometimes outputs trailing commas or surrounding prose. `_parse_json_tolerant()` in `nodes.py` repairs trailing commas and extracts the first `{...}` block before falling back to the raw error.
- **Hallucinated pivots** — `_is_real_value()` rejects fake phones (sequential digits, all-same digit), private IPs (10.x, 192.168.x), and placeholder names (`unknown`, `<name>`, etc.).
- **Maigret result field** — stored in `state.sherlock_result` for historical reasons. Do not rename — tests and digest both reference this field.
- **8B model drops remediation sections** — asked for a 13-section nested JSON in one shot, llama3.1:8b silently omits most of `remediation` (monitoring, broker opt-outs, SIM-swap all went missing), producing a sparse report. Fix: don't ask the model for remediation at all — `_build_deterministic_remediation()` generates it from scan state. The model only writes narrative.
- **Model returns objects where strings are required** — `what_is_known` / remediation items came back as `{"PlatformName":..}` / `{"action":..,"platforms":[]}` and the report rendered raw dict reprs (and empty `■` bullets for the object shapes `_rem_item` didn't recognise). Fix: `_normalize_what_is_known()` + `_stringify_rem_item()` coerce everything to strings before rendering.
- **Model parrots prompt examples as findings** — verbatim example breach names (ParkMobile, PDL) in the prompt got emitted as if they were real findings for the target. Fix: example brand names in `prompts.py` are now `[bracketed placeholders]`, and `_filter_top_risks()` drops any risk naming a known example breach that isn't actually in scan state.

---

## Future Paid Integrations

These are prioritized by **novelty** — i.e., they surface a new type of data or attack surface not already covered by the free tool stack. Lower items are incremental improvements to existing coverage.

Integrate when the tool has paying clients who justify the cost.

| # | Tool | What it adds | Cost | Link |
|---|------|-------------|------|------|
| 1 | **Optery API** | Data broker removal across 635+ brokers — white-label API designed for resellers. Closes the biggest competitive gap vs. DeleteMe/Kanary. No minimums; contact support@optery.com for pricing. Handles re-population monitoring so removals don't expire silently. | Negotiated per engagement | https://www.optery.com/api/ |
| 2 | **Intelligence X (IntelX)** | Deep web, dark web, and Tor site indexing + full paste/leak archives going back years. Free tier is 2 searches/day (not viable for automated scans). Enterprise access unlocks the breach content API. | ~€7,000/year (enterprise) | https://intelx.io |
| 3 | **DeHashed** ✅ *implemented* | Raw breach record contents — actual plaintext or hashed passwords, not just "you were in this breach." Also surfaces physical addresses and phones embedded in breach dumps — fills the physical data gap when broker scan returns nothing. | ~$5/month | https://dehashed.com |
| 4 | **Twilio Lookup v2** | Real-time SIM swap detection (carrier line-type, ported status, identity match). Surfaces active SIM swap fraud — not detectable by any free tool. | $0.01–$0.04/lookup | https://www.twilio.com/docs/lookup/v2-api |
| 5 | **TrueCaller** | Crowdsourced phone identity — caller name, spam score, carrier. Extends phone pivot beyond what phonenumbers/Numverify return. Note: official API requires partnership; unofficial endpoints exist but are fragile. | Unofficial/free API (fragile) | https://www.truecaller.com/blog/features/truecaller-api |
| 6 | **SecurityTrails** | Full DNS history and WHOIS change log for any domain. Find infrastructure a target owns or has historically operated. Extends SpiderFoot's WHOIS module with years of historical data. | ~$50/month (Freelancer) | https://securitytrails.com/corp/api |
| 7 | **Whoxy** ✅ *implemented* | Reverse WHOIS — given an email, find all domains they've ever registered. Surfaces business activity, company names (pivot to OpenCorporates), physical addresses from WHOIS registrant data, and expired domains (impersonation risk). | $3/month | https://www.whoxy.com |
| 8 | **RentCast** | Property ownership records by address or owner name. Links physical addresses to full ownership history, assessed value, and landlord relationships. US coverage only. | ~$35/month | https://app.rentcast.io/api |
| 9 | **ProxyCurl** | LinkedIn profile data via official LinkedIn API. Returns employment history, skills, connections count without requiring a logged-in account or scraping. Fills the gap Maigret/Blackbird leave on LinkedIn. | $0.01/profile | https://nubela.co/proxycurl |
| 10 | **OpenSanctions** | Sanctions lists, PEPs (politically exposed persons), and criminal watchlists from 100+ government sources. Relevant for high-risk clients or due diligence use cases. | Free (non-commercial) / $300/month (SaaS) | https://www.opensanctions.org |
