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

import httpx
import structlog
from pydantic import BaseModel

from eidolon.core.findings import Finding, Severity
from eidolon.sources._http import client
from eidolon.sources.base import Tool

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"

_PER_TARGET_LIMIT = 50
_HTTP_TIMEOUT = 20

_TRANSIENT_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF = 1.0

QueryStatus = Literal["matched", "absent", "error"]


class CommonCrawlInput(BaseModel):
    targets: list[str] = []


class MatchedProperty(BaseModel):
    target: str = ""
    capture_count: int = 0
    sample_url: str = ""
    sample_timestamp: str = ""


class CommonCrawlOutput(BaseModel):
    present: bool = False
    matched: list[MatchedProperty] = []
    total_captures: int = 0
    index_id: str = ""
    checked: int = 0
    errored_targets: list[str] = []


def _latest_index() -> tuple[str, str] | None:
    with client(
        timeout=httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=10.0)
    ) as http:
        resp = http.get(COLLINFO_URL)
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
    if "://" not in target and "/" not in target:
        query = f"{target}/*"
    elif target.endswith("*"):
        query = target
    else:
        query = f"{target}*"

    last_problem = ""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            with client(
                timeout=httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=10.0)
            ) as http:
                resp = http.get(
                    cdx_api,
                    params={
                        "url": query,
                        "output": "json",
                        "limit": str(_PER_TARGET_LIMIT),
                    },
                )
        except httpx.RequestError as exc:
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
    vendor = "index.commoncrawl.org"

    def available(self) -> bool:
        return True

    def _input_value(self, inp: CommonCrawlInput) -> str:
        return ", ".join(inp.targets)

    def to_findings(self, out: CommonCrawlOutput) -> list[Finding]:
        if not out.present:
            return []
        return [
            Finding(
                kind="web_presence",
                dedup_key=f"cc:{m.target}",
                title=m.target,
                severity=Severity.LOW,
                payload={
                    "target": m.target,
                    "capture_count": m.capture_count,
                    "sample_url": m.sample_url,
                    "index_id": out.index_id,
                },
            )
            for m in out.matched
            if m.target
        ]

    def run_summary(self, out: CommonCrawlOutput) -> str:
        if not out.present:
            return ""
        return (
            f"present in the public web archive — "
            f"{len(out.matched)} property(ies), "
            f"{out.total_captures} page capture(s)"
        )

    def _run(
        self, inp: CommonCrawlInput, log: structlog.stdlib.BoundLogger
    ) -> CommonCrawlOutput:
        targets = [t.strip() for t in inp.targets if t and t.strip()]
        if not targets:
            log.info("commoncrawl: no targets, returning empty")
            return CommonCrawlOutput()

        try:
            latest = _latest_index()
        except httpx.RequestError as exc:
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
