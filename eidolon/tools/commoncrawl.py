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

Free, public, no authentication. Degrades gracefully on 404/empty/network
errors — logs a warning and returns an empty result rather than raising.

Opt-out paths surfaced in the report:
  - Spawning's "Do Not Train" registry (haveibeentrained.com / spawning.ai)
  - Adding an ``ai.txt`` (and robots rules) to the site to signal opt-out.
"""

from __future__ import annotations

import json

import requests
import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"

# Per-target capture cap — we only need presence + a sample, not the full list.
_PER_TARGET_LIMIT = 50
_HTTP_TIMEOUT = 20


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
) -> MatchedProperty | None:
    """Query one target against the CDX index. Returns a MatchedProperty when
    there are captures, else None. Never raises — 404/empty/network → None."""
    # A bare domain (no path, no scheme) matches all of its pages via /*.
    query = target
    if "/" not in target and "://" not in target:
        query = f"{target}/*"

    try:
        resp = requests.get(
            cdx_api,
            params={"url": query, "output": "json", "limit": str(_PER_TARGET_LIMIT)},
            timeout=_HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        log.warning("commoncrawl: request failed", target=target, error=str(exc))
        return None

    # 404 (or any non-200) means no captures for this target — not an error.
    if resp.status_code == 404:
        log.info("commoncrawl: no captures", target=target)
        return None
    if resp.status_code != 200:
        log.warning(
            "commoncrawl: unexpected status",
            target=target,
            status=resp.status_code,
        )
        return None

    text = (resp.text or "").strip()
    if not text:
        log.info("commoncrawl: empty response", target=target)
        return None

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
        return None

    sample = captures[0]
    return MatchedProperty(
        target=target,
        capture_count=len(captures),
        sample_url=sample.get("url") or "",
        sample_timestamp=sample.get("timestamp") or "",
    )


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
        for target in targets:
            prop = _query_target(cdx_api, target, log)
            if prop is not None:
                matched.append(prop)

        total = sum(m.capture_count for m in matched)
        output = CommonCrawlOutput(
            present=bool(matched),
            matched=matched,
            total_captures=total,
            index_id=index_id,
        )
        log.info(
            "commoncrawl: ok",
            present=output.present,
            matched=len(matched),
            total_captures=total,
            index_id=index_id,
        )
        return output
