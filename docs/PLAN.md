# PLAN.md — eidolon backlog: finding-centric core + operator-grade capability

This file holds only OPEN work. It is the single planning doc (the old `PRD.md`
architecture overhaul is folded in below as Phase REFACTOR).
Each task is self-contained: `file:line` evidence, the exact fix, and an exact Done-when.
The verify gate for every task is:

```bash
./bin/lint.sh && TEST_MODE=true uv run pytest -x -q
```

Called "verify" below. Currently 357 tests; new tasks add tests, so the number only rises.

## 0. Decision principle (read first)

When a technical choice arises, **do not optimize for development cost.** Prefer, in order:
**correctness → simplicity → robustness → scalability → long-term maintainability.**
"It's more work" is not a valid objection to anything in this document.

## Framing

Eidolon is a working POC (v0.1.0, shipped as an MCP) that produces privacy-exposure
reports with good bones: a typed `Tool[In,Out]` contract, a never-raise result envelope,
deterministic-first analysis, a 3-state availability model, an MCP boundary, 177 tests.
**Keep those.** Two problem sets remain:

1. **Structural** (Phase REFACTOR): the pipeline is tool-centric and untyped at the seams.
   `nodes.py` (2248 LOC) + `report.py` (1452 LOC) are god modules; every tool emits typed
   output that `run_to_result` immediately `.model_dump()`s to a raw `dict`, and every
   consumer re-parses that dict **by string key**. Coupling is O(sources × consumers).
2. **Capability** (Phases OPSEC / EVIDENCE / RESILIENCE / SCALE / HARDEN / TASKING): for a
   defense cyber-ops reader (Twenty / twenty.io) this reads as a recon engine, and the gaps
   that decide whether it reads as *operator* code are egress/OPSEC control, an evidence
   chain, partial-failure isolation under adversarial input, and scale beyond one target.

Phase REFACTOR is the substrate; the `Finding` domain it introduces is where provenance,
evidence, and later persistence all attach. Do it first — see the sequencing note at the end.

## How to execute (read first, every agent)

1. One task per turn.
2. Use the exact `file:line` in the task; do not invent unrelated work.
3. `[x]` only after "Done when" is met AND verify is green.
4. `[~]` = code-complete pending a real-endpoint check that TEST_MODE can't cover.
5. `[ ]` = not started.
6. Never `git commit` / `git add`. Working-tree changes only; the human commits.
7. Keep the deterministic-core invariant: the LLM writes narrative only. No task may route
   scan control, remediation, or pivot *values* through the model.
8. Output schemas stay default-constructible (base `run()` returns `output_schema()` when a
   tool is unavailable). Any new field on an output/finding schema needs a default.
9. Testing is **end-to-end first** — exercise the real pipeline in TEST_MODE (fixtures, no
   network). Unit tests only for cheap, load-bearing invariants.

---

## Phase REFACTOR — finding-centric core (foundational; do first)

**In one sentence:** introduce a canonical typed domain (`Finding`); make tools adapters
that emit `Finding`s; make every consumer read `Finding`s. Coupling drops to
O(sources + consumers). This same `Finding` is later the Postgres row and the unit of
monitoring diffs — build it now, in memory, as the domain model.

Target dataflow:

```
inputs ─▶ classify ─▶ [SourceAdapter…]        # each source → list[Finding]
                           ▼
                     ScanState.findings: list[Finding]      # single source of truth
        ┌──────────────────┼───────────────────┬─────────────────┐
        ▼                  ▼                    ▼                 ▼
   analysis(findings)  report_model(findings)  mitre(findings)  persistence(findings)
                           ▼
                    md(model) / pdf(model) / json(model)     # dumb renderers, one source
```

Target module layout (no module owns >1 responsibility; target **no module > ~400 LOC**):

```
eidolon/
  core/ findings.py  state.py  registry.py  runner.py  jobs.py
  sources/            # was tools/ — each is a Tool + to_findings
  pipeline/ classify.py  collect.py  correlate.py
  analysis/ risk.py  narrative.py     # deterministic risk + LLM narrative, separated
  report/ model.py  markdown.py  pdf.py  json.py
  mcp/  config.py  ...
```

### Decision record (settled) — the `Finding` domain (`eidolon/core/findings.py`)

```python
class Severity(str, Enum):
    CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

class RemovalHint(BaseModel):
    mechanism: str; url: str = ""            # deterministic removal path

class Provenance(BaseModel):
    """Unified provenance — folds in the old PRD Provenance + the evidence-chain fields
    the EVIDENCE phase needs. Lives on every Finding; stamped once in collect()."""
    source: str                              # adapter name, e.g. "dehashed"
    retrieved_at: datetime
    status: Literal["ok","skipped","error"]
    detail: str | None = None                # skip reason / error message
    tool_version: str = ""                   # eidolon.__version__ at scan time
    source_host: str = ""                    # vendor host (NOT full URL — no target value leak)
    latency_ms: int = 0
    response_sha256: str = ""                # hash of the source's typed output — replayable
    egress_proxied: bool = False             # was the OPSEC proxy in effect

class Finding(BaseModel):
    """One normalized, deduplicated fact about the target. Base for all kinds."""
    kind: str                                # discriminator; set by each subtype
    dedup_key: str                           # stable identity, e.g. "breach:Adobe"
    title: str
    severity: Severity
    provenance: Provenance
    removable: bool = False
    removal: RemovalHint | None = None

class Breach(Finding):        kind: Literal["breach"]="breach";        breach_date: date|None=None; data_classes: list[str]=[]
class Credential(Finding):    kind: Literal["credential"]="credential"; username:str=""; password: SecretStr|None=None; password_hash:str=""; hash_algo:str=""; source_breach:str=""
class Account(Finding):       kind: Literal["account"]="account";       platform:str=""; url:str=""; active:bool=False
class BrokerExposure(Finding):kind: Literal["broker_exposure"]="broker_exposure"; broker:str=""; opt_out_url:str=""; data_points:list[str]=[]
# …Paste, InfostealerLog, CourtRecord, CorporateRecord, PhoneIntel, ExposedHost,
#   AiTrainingHit, GoogleFootprint — one class per concept a consumer actually renders.
```

Rules:
- `SecretStr` for plaintext passwords → **redacted by default in every renderer**; the
  reveal path is the only caller of `.get_secret_value()`. Redact-by-default becomes a
  **type property**, not renderer discipline.
- `dedup_key` is deterministic + stable across scans → also the future DB unique key and
  the monitoring-diff identity. Same breach in two scans = one key.
- `Provenance` is stamped once, in `collect()` — every downstream consumer trusts it.
  This is the single home for the evidence-chain fields (see Phase EVIDENCE), so there is
  no competing `Provenance` on `ToolResult`.

Tools stay `Tool[TIn,TOut]`; add one method + a collect envelope:

```python
class Tool(ABC, Generic[TIn,TOut]):
    def to_findings(self, out: TOut) -> list[Finding]: return []   # override per tool

@dataclass
class SourceResult:
    name: str; status: Literal["ok","skipped","error"]
    findings: list[Finding]; detail: str | None = None

class ScanState(BaseModel):
    raw_input: str; run_id: str = ""; classifications: list[InputClassification] = []
    results: dict[str, SourceResult] = {}     # by source name
    findings: list[Finding] = []              # single source of truth
    analysis: "Analysis | None" = None
    def findings_of(self, cls): return [f for f in self.findings if isinstance(f, cls)]
    def coverage(self): return [SourceCoverage(r.name, r.status, r.detail) for r in self.results.values()]

@dataclass(frozen=True)
class SourceSpec:
    name:str; factory:Callable[[],Tool]; wave:int; input_kinds:tuple[str,...]
REGISTRY: tuple[SourceSpec,...] = (SourceSpec("hibp",Hibp,1,("email",)), ...)  # graph built from this
```

**Acceptance gates for the whole phase** (hard — REFACTOR isn't "done" until both pass):
- **Decoupling proof:** register a throwaway source returning one `Breach("breach:FakeCorp")`
  at runtime; `run_scan` surfaces it in `state.findings` AND in the rendered report, with
  **zero lines changed** in report/analysis/state. Failing = the refactor didn't decouple.
- **Skipped-honesty:** a source with no key reports `coverage()[src]=="skipped"`, emits no
  findings, renders "not checked" (never "0 found"), and leaves `analysis.risk_score`
  unchanged (skipped ≠ clean).

- [x] **REFACTOR.1 [AGENT] No Finding domain exists.** There is no canonical typed fact;
  consumers read `ToolResult.data` dicts by key. Add `eidolon/core/findings.py` with the
  types above (types only, no behavior change). Verify: unit test — `Finding.dedup_key`
  stable + identical across two scans of the same fixture; `SecretStr` never serializes
  plaintext via `model_dump(mode="json")`.
  Done when: domain types land, nothing wired yet, verify green.

- [x] **REFACTOR.2 [AGENT] Tools don't emit findings.** `eidolon/tools/base.py:93`
  `run_to_result` returns only the dict envelope. Add `to_findings(out)` to `Tool`
  (`base.py`), implement it per tool in `eidolon/tools/*.py`, and add `collect(source,inp)
  -> SourceResult` that runs the tool, maps to findings, and **stamps `Provenance`**
  (source, retrieved_at, status incl. skip reason, tool_version, source_host, latency_ms,
  response_sha256, egress_proxied). Dual-write: populate `ScanState.findings` alongside the
  legacy `*_result` fields so nothing breaks yet. Verify: per-source unit test maps a
  fixture → expected finding count/kinds; every finding has non-empty `provenance.source`.
  Done when: every source emits findings via `collect`; legacy fields still populated.

- [x] **REFACTOR.3 [AGENT] Two renderers drift (md/pdf).** `eidolon/agent/report.py` (1452
  LOC) hand-maintains markdown + PDF in parallel (already drifted: dossier heading desync,
  MITRE section md-only). Add `eidolon/report/model.py` (`ReportModel` built from findings +
  analysis) and `markdown.py`/`pdf.py`/`json.py` that only lay out the model. Keep the old
  renderer until parity proven. Verify: renderer-parity e2e — `section_titles(md) ==
  section_titles(pdf)` from one model; transitional snapshot test asserts new report is
  content-equivalent to the old for a fixture (same breaches/accounts/actions).
  Done when: content defined once (the model); md/pdf provably can't drift.

- [x] **REFACTOR.4 [AGENT] Consumers re-parse raw dicts.** analysis, MITRE, dossier read
  `state.<tool>_result.data.get(...)` by string key (e.g. `report.py` HIBP path). Point them
  at `state.findings_of(...)`; delete raw-dict access. Verify: decoupling-proof e2e (above)
  passes; grep shows no consumer reads `ToolResult.data[` / `.data.get(`.
  Done when: no consumer touches raw dicts; findings are the only read path.

- [x] **REFACTOR.5 [AGENT] 17 flat state fields + hand-wired waves.**
  `eidolon/core/models.py:29` `PipelineState` declares 17 `Optional[ToolResult]` fields for
  26 tools; `eidolon/agent/graph.py` + `nodes.py:1118/1149` hand-wire wave1/wave2. Replace
  with `ScanState` (`results`/`findings`) + build the graph from `REGISTRY`
  (`eidolon/core/registry.py`), concurrency derived from `SourceSpec.wave`. Delete the
  dual-write from REFACTOR.2. Verify: adding a source = one `SourceSpec` + one adapter +
  one `to_findings`, provably (decoupling gate); wave hand-wiring gone.
  Done when: state + graph are registry-driven; 17 fields removed.

- [x] **REFACTOR.6 [AGENT] God modules remain.** After 1–5, `nodes.py` (2248) and
  `report.py` (1452) still hold orchestration+LLM+analysis+two renderers. Split into the
  target layout (`pipeline/`, `analysis/risk.py`+`narrative.py`, `report/`); remove the
  legacy renderer. Verify: no module > ~400 LOC; `nodes.py` and monolithic `report.py`
  gone; full suite + MCP handshake/async flow green.
  Done when: layout matches §Target; both god modules deleted; verify green.

---

## Phase OPSEC — egress control + attribution safety (highest capability signal)

Every tool hits third-party APIs straight from the operator's host IP with no proxy, no
pacing, no record of what each vendor logs. For a cyber-ops audience this absence is
disqualifying. The `collect()` boundary (post-REFACTOR; `run_to_result` pre-REFACTOR) is
the one place to add it once for all vendors.

### Decision record (settled)
- Egress config is **per-tool over a global default**, resolved at the collect boundary —
  not sprinkled into `_run`. A tool reads the resolved `EgressPolicy` from a ContextVar so
  `httpx`/`requests`/subprocess vendors all obey it.
- Policy: `proxy` (SOCKS5/HTTP or None), `min_interval_s`+`jitter_s` (per-vendor pacing),
  `user_agent`, `dns_via_proxy`, `require_proxy`. Defense-in-depth, not obscurity: the
  honest guarantee is "no tool egresses except through the configured policy," at one seam.
- No new crypto, no telemetry. Config from `.env`/`config.py` only.

- [x] **OPSEC.1 [AGENT] No egress policy object.** Nothing describes how a tool reaches the
  network. Add `eidolon/core/egress.py`: frozen `EgressPolicy` (`proxy:str|None`,
  `min_interval_s:float=0`, `jitter_s:float=0`, `user_agent:str`, `dns_via_proxy:bool=False`,
  `require_proxy:bool=False`) + `resolve_policy(tool_name)` overlaying per-tool env
  (`EIDOLON_PROXY`, `EIDOLON_PROXY_<TOOL>`, `EIDOLON_PACING_<TOOL>`) over a global default,
  exposed via a `contextvars.ContextVar`. Verify: `resolve_policy("shodan")` picks
  `EIDOLON_PROXY_SHODAN` over the global; env parsing tested.
  Done when: module + tests land; nothing wired (OPSEC.2/3 wire it).

- [x] **OPSEC.2 [AGENT] Collect boundary sets no egress.** The collect/`run_to_result`
  boundary runs tools with zero network governance. Fix: resolve the policy for the source,
  bind it to the ContextVar for the run, and enforce per-vendor pacing (`min_interval_s` +
  random `jitter_s`) via a process-wide per-vendor last-call map under a lock; record
  `egress_proxied` into `Provenance` (EVIDENCE path). Verify: two back-to-back runs of one
  tool with `min_interval_s=0.2` measure ≥0.2s spacing; `min_interval_s=0` adds no latency
  (TEST_MODE stays fast).
  Done when: pacing enforced at the boundary; TEST_MODE runtime unchanged.

- [x] **OPSEC.3 [AGENT] HTTP tools ignore the proxy.** `hibp/dehashed/whoxy/shodan/numverify/
  courtlistener/opencorporates/spiderfoot` build clients with no `proxy=`. Add
  `eidolon/tools/_http.py` `client(policy)` returning a configured `httpx.Client` (proxy,
  UA, `trust_env=False` so ambient env can't silently redirect egress) and route every HTTP
  tool through it, reading the ContextVar policy. Do NOT change any URL or parsing. Verify:
  each HTTP tool constructs its client with the ContextVar proxy (monkeypatched); tool tests
  pass with policy unset (direct).
  Done when: no HTTP tool builds a bare client; proxy honored end-to-end in test.

- [x] **OPSEC.4 [AGENT] Subprocess tools leak host IP.** `eidolon/tools/ghunt.py` +
  `blackbird.py` shell out, bypassing any Python proxy. Pass proxy env (`HTTPS_PROXY`/
  `ALL_PROXY`) into subprocess `env=`; when `require_proxy` is set and a tool can't comply,
  the boundary returns `status="skipped"` ("egress policy requires proxy; tool cannot
  comply") rather than egressing in the clear. Verify: under `require_proxy` a non-complying
  tool is `skipped`, not `ok`/`error`, and no subprocess spawns.
  Done when: no subprocess egresses in the clear under `require_proxy`; skip path tested.

- [x] **OPSEC.5 [AGENT] No burn/exposure profile in report.** The report never says which
  vendors saw the API key or source IP. Add static `eidolon/data/egress_profile.json` (per
  tool: `logs_api_key`, `logs_source_ip`, `third_party`) + an "Egress exposure" report
  footer listing, per ran tool, what it exposed and whether a proxy was in effect. Data
  only. Verify: report test asserts the footer lists a ran tool with its profile + proxy
  state.
  Done when: report shows a per-run egress-exposure summary from ran tools.

---

## Phase EVIDENCE — populate + surface the evidence chain

The evidence fields live on `Provenance` (defined in REFACTOR's Finding domain). This phase
**stamps and surfaces** them; it no longer defines a competing `Provenance` on `ToolResult`.

- [x] **EVIDENCE.1 [AGENT] collect() doesn't stamp the evidence fields.** REFACTOR.2 adds
  `Provenance` but may leave the evidence fields empty. Fix: in `collect()`, capture
  `latency_ms` around the tool run, set `response_sha256 = sha256(out.model_dump_json())`,
  `tool_version = eidolon.__version__` (else ""), `source_host` from a `vendor: ClassVar`
  on `Tool` (default "" fine), and `egress_proxied` from the resolved policy (OPSEC.2). On
  ok AND error paths. Verify: `latency_ms>=0`, `response_sha256` is 64 hex on ok, identical
  output hashes twice (determinism).
  Done when: every finding's provenance carries stable evidence fields.

- [x] **EVIDENCE.2 [AGENT] Report has no evidence appendix.** `eidolon/report/` (post-
  REFACTOR) renders findings but no per-source evidence. Add an "Evidence" appendix listing,
  per ran source, `tool_version · source_host · latency · sha256 · proxied?` from
  `Provenance`. Appendix only (operator reference), not narrative; omit skipped sources'
  hashes. Verify: report test asserts the appendix shows sha256+source for a ran source and
  omits skipped ones.
  Done when: report includes a replayable evidence appendix bound to real findings.

- [x] **EVIDENCE.3 [AGENT] Provenance not queryable over MCP.** The evidence appendix lives
  only in the file report. Add a `get_evidence(scan_id)` MCP tool returning structured
  provenance rows (source, source_host, sha256, latency, proxied) as JSON so a caller
  verifies a claim without parsing markdown. Verify: TEST_MODE MCP test pulls evidence for a
  completed scan and asserts a known source's sha256/host present.
  Done when: provenance is queryable over MCP, not just readable in the .md.

---

## Phase RESILIENCE — partial-failure isolation + per-tool timeouts

"Enterprise-grade under real-world conflict conditions" = one hung/500-ing vendor can't
sink a scan. The wave runner catches exceptions but has **no timeout**, and a raised tool
leaves *no* result in state (silent hole, not a visible failure). (Pre-REFACTOR anchors
below; post-REFACTOR the equivalent lives in `pipeline/collect.py` + the registry runner —
apply to whichever exists when the task runs.)

- [x] **RESILIENCE.1 [AGENT] Wave runner has no per-tool timeout.**
  `eidolon/agent/nodes.py:1092-1115` `_run_concurrent` iterates `as_completed(futures)` with
  no timeout, so one wedged tool stalls the whole wave (a hung subprocess has no cap). Add
  `per_tool_timeout_s` (config default ~120) and `as_completed(futures, timeout=...)`; on
  `TimeoutError` record a synthetic error result (`status="error"`, "timeout") into that
  tool's slot so it's visible, not missing. Note: ThreadPool can't kill the thread —
  document that the timeout unblocks the wave while the orphan finishes; the hard cap is the
  tool's own client timeout (RESILIENCE.3). Verify: a sleeping fake node — wave returns
  within timeout, slow tool's slot holds an error/timeout result.
  Done when: a slow tool no longer blocks the wave; its slot shows a visible error.

- [x] **RESILIENCE.2 [AGENT] A raised tool leaves no result.** `nodes.py:1112`
  `except Exception` logs and continues but writes nothing, so a crashed tool looks like
  "never ran." Map each node fn → its slot and write an error result on exception (guards
  the rare node-level raise since `run_to_result` already never raises). Verify: a fake node
  that raises leaves an error result in its slot; digest/report render it failed, not absent.
  Done when: every wave tool ends with a result — ok, skipped, or error.

- [x] **RESILIENCE.3 [AGENT] HTTP tools have no explicit timeout.** HTTP tools build clients
  with no `timeout=`, so a black-holed vendor hangs to the OS TCP timeout. Set
  `httpx.Timeout(connect=5, read=<tool-appropriate>)` in the shared `_http.client()`
  (OPSEC.3); each tool passes its read cap. This is the hard cap behind RESILIENCE.1's soft
  wave timeout. Verify: a slow transport in one HTTP tool test raises a timeout inside the
  tool (surfaced as `status="error"`), not an indefinite hang.
  Done when: no HTTP tool can hang past its configured read timeout.

- [x] **RESILIENCE.4 [AGENT] Run health isn't surfaced.** No at-a-glance "what ran/skipped/
  errored/timed out." Add a report footer "Run health" counting sources by status (from
  `coverage()` post-REFACTOR) + total wall time (earliest→latest provenance timestamp).
  Data only. Verify: report test with a mixed set (ok+skipped+error) asserts counts render.
  Done when: report carries a status rollup an operator scans in one glance.

---

## Phase SCALE — batch / queue beyond a single target

The pitch is 100X; the pipeline is single-identity (`raw_input` is one string, graph runs
once). Show bounded concurrent multi-target execution without changing the per-target path.

- [x] **SCALE.1 [AGENT] No batch entrypoint.** `eidolon/main.py` runs one target per
  invocation. Add `eidolon/core/batch.py` `run_batch(targets, max_concurrency) ->
  list[ScanState]` running the compiled graph per target under a bounded pool (pick the
  simpler robust option per §0 and justify in the docstring). Each target: own `run_id`, own
  report, no shared mutable state. Verify: TEST_MODE test runs 3 fixture targets at
  `max_concurrency=2` → 3 independent states, 3 distinct `run_id`s, 3 report paths.
  Done when: N targets scan concurrently under a cap; per-target isolation proven.

- [x] **SCALE.2 [AGENT] No CLI batch surface.** Add `--targets-file PATH` (one per line,
  `#` comments skipped) + `--max-concurrency N` (default 3) to `eidolon/main.py`; dispatch
  to `run_batch`. Single-target flags unchanged. Verify: CLI test with a 2-line file in
  TEST_MODE → 2 reports; single-target CLI tests pass.
  Done when: `--targets-file` drives a bounded batch; single-target path untouched.

- [x] **SCALE.3 [AGENT] Global rate limits ignored across concurrent targets.** Two targets
  can hammer one vendor at once, blowing quotas + raising attribution signal. Make OPSEC.2's
  per-vendor pacing map process-global (keyed by tool name, module-level lock) and note in
  `batch.py` that pacing is shared. Verify: 2 concurrent targets + a paced fake tool — total
  vendor calls spaced by `min_interval_s` across both, not per-target.
  Done when: vendor pacing holds across the whole batch.

---

## Phase HARDEN — adversarial-input resilience (tested contract)

OSINT results are attacker-controllable (poisoned profiles, booby JSON, values designed to
steer a pivot). The instincts exist (`_is_real_value`, `_parse_json_tolerant`, placeholder
filters) — make them a *proven* contract. `hypothesis` is not yet a dependency.

- [x] **HARDEN.1 [AGENT] `_parse_json_tolerant` isn't fuzzed.** `eidolon/agent/nodes.py:35`
  repairs model output and feeds the pipeline. Add `hypothesis` to dev deps
  (`pyproject.toml`) + a property test asserting it **never raises and never hangs** on
  arbitrary text — returns a dict/list or a defined empty/fallback. Verify: hypothesis test
  over random unicode + JSON-ish strings passes; return-type-on-garbage contract asserted.
  Done when: parser proven total (no raise/hang) over fuzzed input.

- [x] **HARDEN.2 [AGENT] `_is_real_value` pivot filter isn't property-tested.**
  `eidolon/agent/nodes.py:1293` rejects fake phones/private IPs/placeholder names, ad-hoc
  cases only. Add hypothesis strategies (phones; IPv4 incl. RFC1918/loopback/link-local;
  names); assert every private/reserved IP and sequential/all-same phone is rejected and no
  accepted pivot is a private IP — the guard that stops hostile scan data from steering a
  follow-up pivot at the operator's own network. Verify: property test passes; add a
  regression case for any gap found.
  Done when: pivot validator proven never to admit a reserved IP or placeholder.

- [x] **HARDEN.3 [AGENT] LLM narrative can inject unvetted strings into the report.** Report
  rendering shouldn't trust field contents blindly. Assert (test) the renderer escapes/
  neutralizes control chars / markdown-breaking sequences in findings' titles + `top_risks`
  so a poisoned string (`"](http://evil)"`, CRLF, null) can't forge report structure; if the
  renderer already escapes, lock it with the test, else add minimal sanitization at the
  render boundary only. Verify: report test feeds a malicious string through and asserts the
  rendered markdown isn't structurally corrupted.
  Done when: hostile finding text can't break out of its report cell; locked by test.

---

## Phase TASKING — MCP as the operator control plane

Operators think in tasking, not CLI flags. `eidolon/mcp/server.py` (163 LOC) is the real
interface (published to the registry) but thinly tested. Exposes `scan_target/scan_status/
list_scans/get_report/reveal_credentials`.

- [x] **TASKING.1 [AGENT] MCP tools lack a schema contract test.** `tests/test_mcp.py`
  (~2.6KB) doesn't pin tool input/output shapes users depend on. Add contract tests
  asserting each MCP tool's declared schema (arg names/types) + that `scan_status`/
  `get_report` return the documented 3-state shape (running/done/error) for a known scan id
  in TEST_MODE. Verify: contract test passes; a shape change breaks it loudly.
  Done when: MCP tool surface is pinned by a contract test.

- [x] **TASKING.2 [AGENT] Batch tasking isn't exposed over MCP.** Once SCALE.1 lands, add a
  `scan_batch(targets, max_concurrency=3)` MCP tool enqueuing via the same async job path
  `scan_target` uses, returning one batch id whose `scan_status` aggregates child states.
  Do NOT block the MCP call on completion. Verify: TEST_MODE MCP test submits 2 targets,
  polls the batch id, sees aggregate progress → done with 2 reports.
  Done when: an operator can submit + poll a batch through MCP alone.

---

## What NOT to do (durable context)

- Do not route scan control, pivot values, or remediation through the LLM. The
  deterministic-core / LLM-narrative-only split is load-bearing (CLAUDE.md "Analysis Node").
- Do not create a second `Provenance` on `ToolResult` — evidence fields live on
  `Finding.Provenance` (REFACTOR). Pre-REFACTOR tasks may stage on `ToolResult` only if they
  migrate onto `Finding` when REFACTOR.2 lands.
- Do not over-model findings — a subtype only for a concept a consumer actually renders;
  everything else stays a base `Finding` with a payload.
- Do not rename `state.sherlock_result` while it exists (holds the maigret result; tests +
  digest depend on the legacy name). It goes away with REFACTOR.5, not before.
- Do not break output-schema / finding default-constructibility — every new field needs a default.
- Do not send the full state to Ollama; the `_build_analysis_digest` 2-3KB path exists
  because the local 8B model hangs on the raw dump.
- Do not add facial recognition (PimEyes/FaceCheck) — excluded by charter, doubly wrong for
  an attribution-safe posture.
- Do not weaken "results never logged" while adding provenance: hash + host go into
  evidence, raw result contents do not go into logs.
- Do not add telemetry/analytics/error-reporting egress. Egress stays limited to the defined
  tool endpoints (now optionally via the OPSEC proxy).
- **Out of scope here** (designed-for, not built): Postgres persistence, monitoring/diff,
  billing/gateway. The `Finding` (= DB row = diff unit) is built so these drop in later.
- No new data sources or new report content in REFACTOR — it is a structural refactor;
  output parity (REFACTOR.3 snapshot) is required.

---

## Sequencing note

**Phase REFACTOR first** — it introduces `Finding`/`Provenance`/`ScanState`/registry that
the capability phases attach to. Strict order inside it: REFACTOR.1 → .2 → (.3, .4) → .5 → .6.

Cross-phase seams:
- EVIDENCE hangs entirely off REFACTOR (Provenance is defined there, stamped in
  REFACTOR.2/EVIDENCE.1). Do REFACTOR.1–2 before EVIDENCE.
- OPSEC.2 (bind policy at collect) + EVIDENCE.1 (stamp evidence) share the collect boundary
  and the `Provenance.egress_proxied` field — do OPSEC.1 and REFACTOR.2 before OPSEC.2 writes
  into provenance.
- OPSEC.3 (`_http.client`) is the shared helper RESILIENCE.3 extends — OPSEC.3 before
  RESILIENCE.3.
- SCALE.1 precedes SCALE.2/.3 and TASKING.2.
- RESILIENCE, HARDEN, SCALE, TASKING are otherwise independent of REFACTOR but land cleaner
  after it (they target `collect`/registry rather than the god modules).
