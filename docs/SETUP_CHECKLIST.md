# Eidolon — Setup & Configuration

Everything you need to run a scan. Eidolon runs locally — your data and API keys never leave your machine.

---

## 1. Local services (free, no account)

### Ollama — the local LLM that writes the report's narrative
Install from <https://ollama.com>, then:
```bash
ollama pull llama3.1:8b
curl localhost:11434          # -> "Ollama is running"
```

### SpiderFoot — broad footprinting (recommended, but optional)
```bash
docker run -d -p 5001:5001 --name spiderfoot spiderfoot/spiderfoot
# verify: open http://localhost:5001
```
If SpiderFoot is unreachable, Eidolon still runs — that one source is just skipped.

---

## 2. API keys (all optional)

Every key skips gracefully if unset — Eidolon uses a 3-state result envelope
(`ok | skipped | error`), so missing keys simply skip that source without
erroring. Add only what you want.

**High-impact (start here):**

| Key | Cost | Where to get it | What it unlocks |
|---|---|---|---|
| `HIBP_API_KEY` | Paid (low monthly fee) | <https://haveibeenpwned.com/API/Key> | Which breaches your email turns up in |
| `DEHASHED_API_KEY` + `DEHASHED_EMAIL` | Paid (~$5/mo) | dehashed.com | **Actual leaked records — plaintext and hashed passwords (the "Your Actual Leaked Data" dossier).** Highest-impact add-on. |
| `APIFY_API_TOKEN` + `APIFY_ACTOR_ID` | Free tier | apify.com → Settings → Integrations → API tokens | Data-broker / people-search scanning |
| `SCRAPFLY_API_KEY` | Free tier | <https://scrapfly.io> | Scraping backend for people-search sources |

---

## 3. Additional API keys

Each adds a data source. Every one **skips gracefully if unset**, so add only what you want.

| Key | Cost | Where to get it | What it adds |
|---|---|---|---|
| `DEHASHED_API_KEY` (+ `DEHASHED_EMAIL`) | Paid (~$5/mo) | <https://dehashed.com> | **The actual leaked records — plaintext and hashed passwords (the "Your Actual Leaked Data" dossier).** Turns "you were in 18 breaches" into the real credentials. Highest-impact add-on. |
| `NUMVERIFY_API_KEY` | Free (100/mo) | <https://numverify.com> | Phone carrier, line type, and location |
| `SHODAN_API_KEY` | Free tier / paid | <https://shodan.io> | Exposed hosts and open ports tied to your IPs |
| `COURTLISTENER_API_TOKEN` | Free | courtlistener.com → profile → API | Court records (name pivot) |
| `OPENCORPORATES_API_KEY` | Free tier | <https://opencorporates.com/api_access> | Company records (name pivot) |
| `WHOXY_API_KEY` | Paid (pay-as-you-go) | <https://whoxy.com> | Reverse WHOIS — domains registered with your email or name |

---

## 4. Minimal vs. full setup

- **Minimal (cheapest useful scan):** the 4 required keys → breaches, accounts, broker exposure, and a full written report.
- **Worth buying first:** `DEHASHED_API_KEY` (~$5/mo) — it's the difference between *"you were in these breaches"* and *the actual leaked passwords*. Single biggest upgrade.
- **Free add-ons (just sign up):** NumVerify, Shodan, CourtListener, OpenCorporates.

---

## 5. Put it together

```bash
cp .env.example .env     # then fill in your keys
uv sync
```

Minimum `.env`:
```
OLLAMA_HOST=http://localhost:11434
SPIDERFOOT_HOST=http://localhost:5001
HIBP_API_KEY=...
APIFY_API_TOKEN=...
APIFY_ACTOR_ID=...
SCRAPFLY_API_KEY=...
```

---

## 6. Run

```bash
# scan yourself by email
uv run eidolon --email you@example.com

# name + location (drives people-search / data brokers)
uv run eidolon --name "Your Name" --state CA

# run the MCP server (for Claude Desktop / Claude Code)
uv run eidolon-mcp

# tests — no network, uses fixtures
TEST_MODE=true uv run pytest
```

Reports land in `output/` as `.md`, `.pdf`, and `.json`.

---

## 7. Verify before a real run

```bash
curl localhost:11434          # Ollama up
curl localhost:5001           # SpiderFoot up (optional)
uv run eidolon --help         # CLI resolves
```
