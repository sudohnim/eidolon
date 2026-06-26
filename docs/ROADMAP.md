# Eidolon — Roadmap: now → MCP → stateful

## What this is

Eidolon is a local privacy-OSINT scanner: give it an email/phone/name, it fans
out across ~25 sources, correlates, and produces a risk report. This doc traces
the path from today's stateless CLI to an MCP-driven, stateful app, so a second
engineer can sanity-check the plan and the increments.

**Effort legend:** S = days · M = 1–2 weeks · L = multi-week.

## Constraints any engineer must know first

- **Privacy stance is load-bearing.** It's designed to run on the user's box or
  in a TEE. The report deliberately includes **plaintext passwords** (the
  dossier) — that's intended, not a bug. Logs redact the target (`r***@gmail.com`).
- **Analysis is deterministic-first.** The LLM (local Ollama `llama3.1:8b`) only
  writes *narrative* (`identity_summary`, `top_risks`, `findings_context`). Risk
  score, what-is-known, and the dossier are built from state, so the report
  survives an LLM JSON-parse failure. Don't move sensitive data into the LLM path.
- **Green bar is enforced.** `bin/lint.sh` (black/isort/flake8/mypy) + pytest,
  wired to a pre-commit hook. 177 tests today.

## Repo orientation

- Entry: `eidolon/main.py` — argparse → `build_graph().invoke(state)`.
- Orchestration: `eidolon/agent/graph.py` (LangGraph), nodes in
  `eidolon/agent/nodes.py`.
- Tools: `Tool[TIn,TOut]` base in `eidolon/tools/base.py`; `run_to_result()` is
  the boundary adapter (never raises). ~13 HTTP tools, 3 subprocess
  (maigret/blackbird/ghunt), 2 localhost services (SpiderFoot, Ollama).
- Output: `eidolon/agent/report.py` writes per-run `.json`/`.md`/`.pdf` to
  `RESULTS_OUTPUT_PATH`. The `.json` is a full `state.model_dump()`.
---

## Phase 0 — Baseline (today)

Single-shot CLI. Each scan is an island: run → fan-out → file outputs → exit. No
persistence, no history, no interface besides argparse.

**Architecture:** `CLI → pipeline → tools/LLM → files`.

## Phase 1 — Extract core + thin MCP (stateless) · COMPLETE ✓ · Shipped v0.1.0

**Goal:** drive Eidolon from an MCP client (Claude Desktop/Code) locally. Ships
the distribution story with **no database**.

**Shipped** (in `eidolon/mcp/server.py`, installed via `uvx --from eidolon-osint eidolon-mcp`):
- `scan_target(target)` — fires scan, returns `scan_id` immediately (async)
- `scan_status(scan_id)` — poll until `status == "done"` or `"error"`
- `list_scans()` — enumerate past scans with status
- `get_report(scan_id, fmt)` — markdown or JSON, credentials redacted by default
- `reveal_credentials(scan_id)` — explicit dossier reveal, on-demand only

**Architecture:** FastMCP, stdio transport, `uvx`-launchable from PyPI (`eidolon-osint`).
Published to MCP Registry as `io.github.sudohnim/eidolon` v0.1.0.
All 5 tools are 3-state aware: `ok | skipped | error` — missing keys skip cleanly.

## Phase 2 — Stateful (Postgres) · Effort: L ← the big change

**Goal:** persistence. This is what adds a **time axis** — every later feature
(history, diffing, monitoring) stands on it.

**Work**

- Stand up Postgres (compose service locally; Cloud SQL later).
- Implement the ERD: `target → scan → tool_result(jsonb)`, `finding` as the
  dedup backbone (`UNIQUE(target_id, dedup_key)`), typed detail
  (`breach`/`credential`/`account`/`data_broker`), `mitre_technique`,
  `ai_exposure`, reference tables.
- A **normalizer per finding kind** (tool output → `finding` rows) — this is the
  real work, not the schema.
- Persist in `scan_target`: write `scan` + `tool_result`, **upsert** findings
  (`ON CONFLICT … DO UPDATE` advancing `last_seen_scan`).
- Swap the repository impl file→DB behind the Phase-1 `get_report` (signature
  unchanged).
- App-level **Fernet encryption behind a `KeyProvider`** for sensitive columns
  (`raw_input`, `credential.password/address/phone`, identifiers).
- Backfill importer: existing `output/*.json` → `scan` + `tool_result` rows.

**Tooling:** PostgreSQL, SQLAlchemy 2.x, Alembic, psycopg, `cryptography`.

**Architecture delta:** adds a **data layer below the core**. The pipeline now
persists normalized findings, not just files; `tool_result.data` JSONB preserves
tool flexibility; reads are DB-backed. Files become optional artifacts (or move
behind a `report_artifact` pointer).

**Review focus:** `dedup_key` correctness (same breach across runs = one
finding); the encryption boundary (DB never sees plaintext); migration +
idempotent re-scan; **don't mark a finding "resolved" when a tool merely
errored** — distinguish "gone" from "not checked."

## Phase 3 — Time-travel, monitoring & managed deploy · Effort: M + M

**Goal:** convert state into product value — diffing, "what changed," scheduled
background scans, and a managed tier.

**Work**

- Diff step after each scan → emit `change_event` (appeared/resolved/escalated vs
  prior scan).
- New MCP tools (**additive** — Phase-1 contract untouched): `whats_changed(target)`,
  `list_findings(target)`, history queries.
- `monitor` entity + scheduler: self-host cron/compose-timer; managed = Cloud
  Scheduler → Cloud Run **Job**. Scheduling lives *outside* the app.
- Managed deploy from the **same image**: Cloud Run Jobs, Cloud SQL, SpiderFoot
  sidecar, decoupled LLM (Ollama VM or managed API — viable because the dossier
  is deterministic), GCS for rendered reports via the `Storage` seam, Secret
  Manager/KMS, Confidential Computing for the data posture.

**Tooling:** Cloud Run Jobs, Cloud Scheduler, Cloud SQL, GCS, Secret Manager/KMS
(managed); cron/systemd (self-host); MCP HTTP transport (remote).

**Architecture delta:** pipeline gains a **diff stage**; MCP grows **query
tools**; deployment splits into self-host (compose, fully local) and managed
(serverless jobs, scale-to-zero) from one image. `Storage`/`KeyProvider` get
their cloud implementations.

**Review focus:** diff correctness (the error-vs-resolved trap again); scheduler
idempotency; redaction posture over *remote* MCP; cost floor (Cloud SQL + LLM
host are the only always-on pieces).

---

## Cross-cutting prep (do early, pays every phase)

- **`run_scan()` core** (Phase 1) — one function behind CLI, MCP, and cron.
- **`Storage` + `KeyProvider` interfaces** — introduce with `local` impls in
  Phase 1/2; cloud impls land in Phase 3. Hard to retrofit, cheap to stub now.
- **One Docker image, config-only differences** — no `if SAAS:` branches; DB URL,
  LLM URL, secrets all via `config`.

## Dependency order

Phase 1 is complete and shipped (v0.1.0). **Phase 2 gates Phase 3** —
monitoring and time-travel can't exist before state. MCP's client-facing contract
holds steady across all three: state slots in *underneath* it.

---

## Open decisions (still unsettled)

- **Credential grain:** one `finding` per leaked record (clean diffing, more rows)
  vs. one `finding` per breach with credentials as children.
- **Managed-tier LLM:** hosted API (truly fractional, narrative-only data leaves)
  vs. always-on Ollama VM (model locality, fixed cost floor). Self-host always
  stays fully local.
- **Encryption layer:** app-level Fernet behind `KeyProvider` (recommended for the
  TEE story — DB never sees plaintext) vs. Postgres `pgcrypto`.
- **Tenancy:** single-tenant (local) vs. multi-tenant (the `principal` entity
  stops being optional and becomes the root for monitors/billing).
- **Rendered-report storage:** `bytea` in Postgres vs. a `report_artifact`
  pointer to GCS (client-side encrypted), only relevant in the managed tier.
