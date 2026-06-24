"""Common Crawl presence check.

Common Crawl (commoncrawl.org) is a free, openly published crawl of the public
web — billions of pages captured every month. It is NOT a model and it does NOT
"train on" anyone. It is the *raw corpus* that most large-scale LLM training
sets (Google's C4, The Pile's web slice, and many others) are filtered and
deduplicated FROM. So if a person's website or public profile is in Common
Crawl, it means their content sits in the upstream pile that AI training data is
built out of.

HONEST FRAMING (important): a hit here means "your public pages are in the raw
web archive that training sets are derived from." It does NOT mean any specific
model memorized you, was trained on you, or can reproduce your content. We never
claim a model trained on or memorized the person — only that their content is in
the corpus that training data is sourced from.

How it works (no API key required):
  1. GET https://index.commoncrawl.org/collinfo.json — a JSON array of monthly
     index collections; each entry has "id" and "cdx-api". We use the newest.
  2. For each target, GET ``<cdx-api>?url=<target>&output=json&limit=50``.
     Bare domains are queried as ``<domain>/*`` to match every captured page.
     The response is JSON-Lines (one capture object per line), or empty / HTTP
     404 when nothing matched.
  3. Count captures per target and keep one sample url + timestamp as evidence.

Free, public, no authentication. The public CDX endpoint is often overloaded, so
transient 5xx/429/network failures are retried; a target that still can't be
reached is reported as "errored" (could-not-check) — never as "absent" — so the
report never implies the person is out of the pile when the lookup merely failed.

Opt-out paths surfaced in the report:
  - Spawning's "Do Not Train" registry (haveibeentrained.com / spawning.ai)
  - Adding an ``ai.txt`` (and robots rules) to the site to signal opt-out.
"""

from __future__ import annotations

import json
import time
from typing import Literal

import requests
import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"

# Per-target capture cap — we only need presence + a sample, not the full list.
_PER_TARGET_LIMIT = 50
_HTTP_TIMEOUT = 20

# The public CDX index is frequently overloaded and returns transient 5xx/429.
# Retry those a few times before giving up — and when we do give up, report the
# target as "errored" (could-not-check), NOT as "absent". Conflating a server
# error with "not in the archive" would let the report falsely imply the person
# is not in the training-data pile when the lookup simply failed.
_TRANSIENT_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF = 1.0  # seconds, multiplied by attempt number

# Per-target outcome: a real hit, a confirmed absence, or a failed lookup.
QueryStatus = Literal["matched", "absent", "error"]


class CommonCrawlInput(BaseModel):
    targets: list[str] = []  # domains and/or URLs to check


class MatchedProperty(BaseModel):
    target: str = ""
    capture_count: int = 0
    sample_url: str = ""
    sample_timestamp: str = ""  # Common Crawl CDX "timestamp": YYYYMMDDhhmmss


class CommonCrawlOutput(BaseModel):
    present: bool = False
    matched: list[MatchedProperty] = []
    total_captures: int = 0
    index_id: str = ""  # e.g. "CC-MAIN-2026-22"
    checked: int = 0  # targets we actually got an answer for (matched + absent)
    errored_targets: list[str] = []  # targets we could NOT check (server/network)


def _latest_index() -> tuple[str, str] | None:
    """Return (index_id, cdx_api_url) for the newest Common Crawl collection.

    collinfo.json lists collections newest-first, so the first entry is current.
    Returns None on any network/parse error so the caller can skip gracefully.
    """
    resp = requests.get(COLLINFO_URL, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    collections = resp.json()
    if not collections:
        return None
    newest = collections[0]
    index_id = newest.get("id") or ""
    cdx_api = newest.get("cdx-api") or ""
    if not cdx_api:
        return None
    return index_id, cdx_api


def _query_target(
    cdx_api: str, target: str, log: structlog.stdlib.BoundLogger
) -> tuple[QueryStatus, MatchedProperty | None]:
    """Query one target against the CDX index.

    Returns one of:
      ("matched", MatchedProperty)  — captures found
      ("absent",  None)             — checked, genuinely not in the index (404/empty)
      ("error",   None)             — could NOT check (transient 5xx/429/network),
                                       even after retries. Never confuse with "absent".
    Never raises.
    """
    # A bare domain matches all its pages via /*; a path matches its subtree via *.
    if "://" not in target and "/" not in target:
        query = f"{target}/*"
    elif target.endswith("*"):
        query = target
    else:
        query = f"{target}*"

    last_problem = ""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = requests.get(
                cdx_api,
                params={
                    "url": query,
                    "output": "json",
                    "limit": str(_PER_TARGET_LIMIT),
                },
                timeout=_HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            last_problem = str(exc)
            log.warning(
                "commoncrawl: request failed",
                target=target,
                error=str(exc),
                attempt=attempt,
            )
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF * attempt)
            continue

        if resp.status_code == 404:
            log.info("commoncrawl: no captures", target=target)
            return "absent", None
        if resp.status_code in _TRANSIENT_STATUSES:
            last_problem = f"HTTP {resp.status_code}"
            log.warning(
                "commoncrawl: transient status, retrying",
                target=target,
                status=resp.status_code,
                attempt=attempt,
            )
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF * attempt)
            continue
        if resp.status_code != 200:
            log.warning(
                "commoncrawl: unexpected status",
                target=target,
                status=resp.status_code,
            )
            return "error", None

        text = (resp.text or "").strip()
        if not text:
            log.info("commoncrawl: empty response", target=target)
            return "absent", None

        captures: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                captures.append(json.loads(line))
            except json.JSONDecodeError:
                # CDX is JSON-Lines; skip any stray non-JSON line defensively.
                continue

        if not captures:
            log.info("commoncrawl: no captures parsed", target=target)
            return "absent", None

        sample = captures[0]
        return "matched", MatchedProperty(
            target=target,
            capture_count=len(captures),
            sample_url=sample.get("url") or "",
            sample_timestamp=sample.get("timestamp") or "",
        )

    log.warning(
        "commoncrawl: could not check target", target=target, last_problem=last_problem
    )
    return "error", None


class CommonCrawl(Tool[CommonCrawlInput, CommonCrawlOutput]):
    name = "commoncrawl"
    input_type = "name"
    input_schema = CommonCrawlInput
    output_schema = CommonCrawlOutput

    def available(self) -> bool:
        return True  # free public index, no API key required

    def _input_value(self, inp: CommonCrawlInput) -> str:
        return ", ".join(inp.targets)

    def _run(
        self, inp: CommonCrawlInput, log: structlog.stdlib.BoundLogger
    ) -> CommonCrawlOutput:
        targets = [t.strip() for t in inp.targets if t and t.strip()]
        if not targets:
            log.info("commoncrawl: no targets, returning empty")
            return CommonCrawlOutput()

        try:
            latest = _latest_index()
        except requests.RequestException as exc:
            log.warning("commoncrawl: failed to fetch index list", error=str(exc))
            return CommonCrawlOutput()
        if latest is None:
            log.warning("commoncrawl: no usable index collection")
            return CommonCrawlOutput()

        index_id, cdx_api = latest
        log.info("commoncrawl: querying index", index_id=index_id, targets=len(targets))

        matched: list[MatchedProperty] = []
        errored: list[str] = []
        for target in targets:
            status, prop = _query_target(cdx_api, target, log)
            if status == "matched" and prop is not None:
                matched.append(prop)
            elif status == "error":
                errored.append(target)

        total = sum(m.capture_count for m in matched)
        output = CommonCrawlOutput(
            present=bool(matched),
            matched=matched,
            total_captures=total,
            index_id=index_id,
            checked=len(targets) - len(errored),
            errored_targets=errored,
        )
        log.info(
            "commoncrawl: ok",
            present=output.present,
            matched=len(matched),
            checked=output.checked,
            errored=len(errored),
            total_captures=total,
            index_id=index_id,
        )
        return output
