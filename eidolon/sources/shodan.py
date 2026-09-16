import logging

import httpx
import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.core.findings import ExposedHost, Finding, Severity
from eidolon.sources._http import client
from eidolon.sources.base import Tool


class ShodanInput(BaseModel):
    ip: str


class ShodanHostResult(BaseModel):
    ip: str
    ports: list[int] = []
    hostnames: list[str] = []
    org: str = ""
    isp: str = ""
    country: str = ""
    vulns: list[str] = []
    tags: list[str] = []
    last_update: str = ""


class ShodanOutput(BaseModel):
    ips_checked: int = 0
    hosts: list[ShodanHostResult] = []
    total_open_ports: int = 0
    total_vulns: int = 0
    high_risk_ips: list[str] = []


logger = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"


def _query_internetdb(ip: str) -> dict | None:
    """Query the free Shodan InternetDB API (no key required).

    Returns parsed JSON dict on success, None if IP not found or error.
    """
    url = INTERNETDB_URL.format(ip=ip)
    try:
        with client(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0)
        ) as http:
            resp = http.get(url)
        if resp.status_code == 404:
            logger.info("shodan: IP %s not found in InternetDB", ip)
            return None
        resp.raise_for_status()
        return resp.json()
    except httpx.RequestError as exc:
        logger.warning("shodan: InternetDB request failed for %s: %s", ip, exc)
        return None


def _query_shodan_api(ip: str, api_key: str) -> dict | None:
    """Query the official Shodan API for richer host data."""
    try:
        import shodan  # type: ignore[import-untyped]

        api = shodan.Shodan(api_key)  # type: ignore[call-arg]
        return api.host(ip)  # type: ignore[return-value,attr-defined]
    except Exception as exc:
        logger.warning("shodan: Shodan API request failed for %s: %s", ip, exc)
        return None


def _build_host_result(ip: str) -> ShodanHostResult | None:
    """Fetch data for a single IP, combining InternetDB and optionally Shodan API."""
    internetdb_data = _query_internetdb(ip)

    api_key = config.get("SHODAN_API_KEY")
    shodan_data: dict | None = None
    if api_key:
        shodan_data = _query_shodan_api(ip, api_key)

    if internetdb_data is None and shodan_data is None:
        return None

    ports: list[int] = []
    hostnames: list[str] = []
    vulns: list[str] = []
    tags: list[str] = []
    org = ""
    isp = ""
    country = ""
    last_update = ""

    if internetdb_data:
        ports = internetdb_data.get("ports", [])
        hostnames = internetdb_data.get("hostnames", [])
        vulns = internetdb_data.get("vulns", [])
        tags = internetdb_data.get("tags", [])

    if shodan_data:
        org = shodan_data.get("org", "")
        isp = shodan_data.get("isp", "")
        country = shodan_data.get("country_name", "")
        last_update = shodan_data.get("last_update", "")
        api_ports = shodan_data.get("ports", [])
        api_hostnames = shodan_data.get("hostnames", [])
        api_vulns = list((shodan_data.get("vulns") or {}).keys())
        api_tags = shodan_data.get("tags", [])
        ports = sorted(set(ports) | set(api_ports))
        hostnames = list(dict.fromkeys(hostnames + api_hostnames))
        vulns = list(dict.fromkeys(vulns + api_vulns))
        tags = list(dict.fromkeys(tags + api_tags))

    return ShodanHostResult(
        ip=ip,
        ports=ports,
        hostnames=hostnames,
        org=org,
        isp=isp,
        country=country,
        vulns=vulns,
        tags=tags,
        last_update=last_update,
    )


class Shodan(Tool[ShodanInput, ShodanOutput]):
    name = "shodan"
    requires = ["SHODAN_API_KEY"]
    input_type = "org"
    input_schema = ShodanInput
    output_schema = ShodanOutput
    vendor = "internetdb.shodan.io"

    def _input_value(self, inp: ShodanInput) -> str:
        return inp.ip

    def to_findings(self, out: ShodanOutput) -> list[Finding]:
        findings: list[Finding] = []
        for h in out.hosts:
            if not h.ip:
                continue
            findings.append(
                ExposedHost(
                    dedup_key=f"host:{h.ip}",
                    title=f"Exposed host {h.ip}",
                    severity=(
                        Severity.HIGH
                        if h.vulns
                        else Severity.MEDIUM if h.ports else Severity.INFO
                    ),
                    ip=h.ip,
                    ports=list(h.ports),
                    hostnames=list(h.hostnames),
                    vulns=list(h.vulns),
                    org=h.org,
                    country=h.country,
                )
            )
        return findings

    def _run(self, inp: ShodanInput, log: structlog.stdlib.BoundLogger) -> ShodanOutput:
        host = _build_host_result(inp.ip)
        hosts = [host] if host is not None else []
        return ShodanOutput(
            ips_checked=1,
            hosts=hosts,
            total_open_ports=sum(len(h.ports) for h in hosts),
            total_vulns=sum(len(h.vulns) for h in hosts),
            high_risk_ips=[h.ip for h in hosts if h.vulns],
        )
