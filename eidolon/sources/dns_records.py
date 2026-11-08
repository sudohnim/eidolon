"""DNS records per host, plus IP-to-ASN mapping via Team Cymru."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import dns.exception
import dns.resolver
import dns.reversename
import structlog
from pydantic import BaseModel

from eidolon.core.findings import Confidence, Finding, Severity
from eidolon.sources.base import Tool

MAX_HOSTS = 50


class DnsInput(BaseModel):
    domain: str
    hosts: list[str] = []


class IpInfo(BaseModel):
    ip: str
    asn: str = ""
    prefix: str = ""
    country: str = ""
    as_name: str = ""


class DnsHost(BaseModel):
    host: str
    cname: str = ""
    ips: list[IpInfo] = []


class DnsApex(BaseModel):
    mx: list[str] = []
    txt: list[str] = []
    ns: list[str] = []


class DnsOutput(BaseModel):
    domain: str = ""
    apex: DnsApex = DnsApex()
    hosts: list[DnsHost] = []


def attribute_host(domain: str, host: DnsHost) -> Confidence:
    """Is this host the target's own infrastructure? Written by hand (Sunday)."""
    return Confidence.UNVERIFIED


def _resolve(resolver: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        answer = resolver.resolve(name, rtype)
    except (dns.exception.DNSException, OSError):
        return []
    return [r.to_text().strip('"').rstrip(".") for r in answer]


@lru_cache(maxsize=256)
def _as_name(asn: str) -> str:
    rows = _resolve(dns.resolver.Resolver(), f"AS{asn}.asn.cymru.com", "TXT")
    return rows[0].split("|")[-1].strip() if rows else ""


def _ip_info(resolver: dns.resolver.Resolver, ip: str) -> IpInfo:
    rev = dns.reversename.from_address(ip).to_text(omit_final_dot=True)
    if ipaddress.ip_address(ip).version == 4:
        qname = rev.removesuffix(".in-addr.arpa") + ".origin.asn.cymru.com"
    else:
        qname = rev.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"
    rows = _resolve(resolver, qname, "TXT")
    if not rows:
        return IpInfo(ip=ip)
    fields = [f.strip() for f in rows[0].split("|")]
    asn = fields[0].split()[0] if fields and fields[0] else ""
    return IpInfo(
        ip=ip,
        asn=asn,
        prefix=fields[1] if len(fields) > 1 else "",
        country=fields[2] if len(fields) > 2 else "",
        as_name=_as_name(asn) if asn else "",
    )


def _host(resolver: dns.resolver.Resolver, name: str) -> DnsHost:
    cname = next(iter(_resolve(resolver, name, "CNAME")), "")
    ips = _resolve(resolver, name, "A") + _resolve(resolver, name, "AAAA")
    return DnsHost(host=name, cname=cname, ips=[_ip_info(resolver, ip) for ip in ips])


class DnsRecords(Tool[DnsInput, DnsOutput]):
    name = "dns"
    input_schema = DnsInput
    output_schema = DnsOutput
    input_type = "domain"

    def _input_value(self, inp: DnsInput) -> str:
        return inp.domain

    def to_findings(self, out: DnsOutput) -> list[Finding]:
        findings: list[Finding] = [
            Finding(
                kind="dns_apex",
                dedup_key=f"dns_apex:{out.domain}",
                title=f"DNS records for {out.domain}",
                severity=Severity.INFO,
                payload=out.apex.model_dump(),
            )
        ]
        for h in out.hosts:
            findings.append(
                Finding(
                    kind="dns_host",
                    dedup_key=f"dns_host:{h.host}",
                    title=h.host,
                    severity=Severity.INFO,
                    confidence=attribute_host(out.domain, h),
                    payload=h.model_dump(),
                )
            )
        return findings

    def run_summary(self, out: DnsOutput) -> str:
        ips = {i.ip for h in out.hosts for i in h.ips}
        return f"{len(out.hosts)} hosts / {len(ips)} IPs"

    def _run(self, inp: DnsInput, log: structlog.stdlib.BoundLogger) -> DnsOutput:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        domain = inp.domain.lower().rstrip(".")
        names = [domain] + [h for h in inp.hosts if h != domain and "*" not in h]
        apex = DnsApex(
            mx=_resolve(resolver, domain, "MX"),
            txt=_resolve(resolver, domain, "TXT"),
            ns=_resolve(resolver, domain, "NS"),
        )
        with ThreadPoolExecutor(max_workers=10) as pool:
            hosts = list(pool.map(lambda n: _host(resolver, n), names[:MAX_HOSTS]))
        resolved = [h for h in hosts if h.ips or h.cname]
        log.info("ok", queried=len(hosts), resolved=len(resolved))
        return DnsOutput(domain=domain, apex=apex, hosts=resolved)
