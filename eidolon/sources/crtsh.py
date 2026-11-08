"""crt.sh: subdomain discovery from Certificate Transparency logs."""

from __future__ import annotations

import httpx
import structlog
from pydantic import BaseModel

from eidolon.core.findings import Finding, Severity
from eidolon.sources._http import client
from eidolon.sources.base import Tool

MAX_SUBDOMAINS = 500


class CrtshInput(BaseModel):
    domain: str


class CtName(BaseModel):
    name: str
    wildcard: bool = False
    cert_count: int = 0
    first_seen: str = ""
    last_expiry: str = ""
    issuers: list[str] = []


class CrtshOutput(BaseModel):
    domain: str = ""
    cert_count: int = 0
    names: list[CtName] = []


class Crtsh(Tool[CrtshInput, CrtshOutput]):
    name = "crtsh"
    input_schema = CrtshInput
    output_schema = CrtshOutput
    input_type = "domain"
    vendor = "crt.sh"

    def _input_value(self, inp: CrtshInput) -> str:
        return inp.domain

    def to_findings(self, out: CrtshOutput) -> list[Finding]:
        return [
            Finding(
                kind="subdomain",
                dedup_key=f"subdomain:{n.name}",
                title=n.name,
                severity=Severity.INFO,
                payload=n.model_dump(),
            )
            for n in out.names
        ]

    def run_summary(self, out: CrtshOutput) -> str:
        return f"{len(out.names)} names / {out.cert_count} certificates"

    def _run(self, inp: CrtshInput, log: structlog.stdlib.BoundLogger) -> CrtshOutput:
        domain = inp.domain.lower().rstrip(".")
        timeout = httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=10.0)
        with client(timeout=timeout) as http:
            resp = http.get(
                "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}
            )
        resp.raise_for_status()
        certs = resp.json() or []

        names: dict[str, CtName] = {}
        for cert in certs:
            issuer = str(cert.get("issuer_name") or "")
            not_before = str(cert.get("not_before") or "")
            not_after = str(cert.get("not_after") or "")
            for raw in str(cert.get("name_value") or "").splitlines():
                host = raw.strip().lower().rstrip(".")
                if not (host == domain or host.endswith(f".{domain}")):
                    continue
                n = names.setdefault(
                    host, CtName(name=host, wildcard=host.startswith("*."))
                )
                n.cert_count += 1
                if not_before and (not n.first_seen or not_before < n.first_seen):
                    n.first_seen = not_before
                if not_after > n.last_expiry:
                    n.last_expiry = not_after
                if issuer and issuer not in n.issuers:
                    n.issuers.append(issuer)

        log.info("ok", cert_count=len(certs), name_count=len(names))
        return CrtshOutput(
            domain=domain,
            cert_count=len(certs),
            names=sorted(names.values(), key=lambda n: n.name)[:MAX_SUBDOMAINS],
        )
