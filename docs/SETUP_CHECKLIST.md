# OSINT Agent — Pre-Build Setup Checklist

Complete all steps before opening Claude Code.
Check off each item as you go.

---

## [ ] 1. Ollama

```bash
# Install from ollama.com, then:
ollama pull llama3.1:8b
curl localhost:11434
```

Expected response from curl: `Ollama is running`
No account required. Fully local.

---

## [ ] 2. SpiderFoot (Docker)

```bash
# Requires Docker Desktop installed first
docker run -d -p 5001:5001 --name spiderfoot spiderfoot/spiderfoot
```

Verify: open http://localhost:5001 in browser
SpiderFoot UI should load.
No API key required for local instance.

---

## [ ] 3. Have I Been Pwned API Key

1. Go to https://haveibeenpwned.com/API/Key
2. Purchase subscription ($3.50/month)
3. Copy API key
4. Add to .env: `HIBP_API_KEY=your_key_here`

---

## [ ] 4. Apify Account + API Token

1. Go to https://apify.com and create free account
2. Navigate to Settings → Integrations → API Tokens
3. Create new token, copy it
4. Add to .env: `APIFY_API_TOKEN=your_token_here`
5. Go to Apify Store, search "TruePeopleSearch Contact Finder"
6. Open the actor, copy the Actor ID from the URL
7. Add to .env: `APIFY_ACTOR_ID=actor_id_here`

---

## [ ] 5. Google Custom Search Engine

### Step A — Create the Search Engine
1. Go to https://programmablesearchengine.google.com
2. Click "Add" to create new search engine
3. Name it: "OSINT Broker Scan"
4. Under "Sites to search" — leave blank for now
   (Claude Code will generate data/broker_domains.txt
   and you'll add these domains after project is created)
5. Click Create
6. Go to "Edit search engine" → "Setup"
7. Copy the Search Engine ID (cx value)
8. Add to .env: `GOOGLE_CSE_ID=your_cx_here`

### Step B — Get Google API Key
1. Go to https://console.cloud.google.com
2. Create a new project (or use existing)
3. Go to APIs & Services → Library
4. Search "Custom Search API" and enable it
5. Go to APIs & Services → Credentials
6. Click "Create Credentials" → "API Key"
7. Copy the key
8. Add to .env: `GOOGLE_CSE_API_KEY=your_key_here`

Note: Free tier = 100 queries/day. Sufficient for personal use.

---

## [ ] 6. EasyOptOuts

No setup needed — you have an existing subscription.
The tool outputs your dashboard link: https://easyoptouts.com/dashboard
No env var required.

---

## [ ] 7. UV Package Manager

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv --version  # verify
```

---

## [ ] 8. Create .env File

Create `.env` in project root with all values filled in:

```
HIBP_API_KEY=
APIFY_API_TOKEN=
APIFY_ACTOR_ID=
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_ID=
OLLAMA_HOST=http://localhost:11434
SPIDERFOOT_HOST=http://localhost:5001
TEST_MODE=false
RESULTS_OUTPUT_PATH=output/
```

---

## [ ] 9. Add Broker Domains to Google CSE

After Claude Code generates data/broker_domains.txt:
1. Go back to https://programmablesearchengine.google.com
2. Edit your search engine
3. Under "Sites to search" add each domain from broker_domains.txt
4. Save

---

## Verification Checklist

Before first run, confirm all of these:

```bash
curl localhost:11434          # Ollama is running
curl localhost:5001           # SpiderFoot UI responds
cat .env | grep -v "^$"       # All env vars populated
uv --version                  # UV installed
docker ps | grep spiderfoot   # SpiderFoot container running
```

---

## Start Commands

```bash
# Setup
uv sync

# Run tests (TEST_MODE — no real data)
TEST_MODE=true uv run pytest

# Run against real input
uv run python main.py "your@email.com"

# Multiple inputs
uv run python main.py "your@email.com
Your Name
555-123-4567"
```
