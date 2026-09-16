"""Build the compact LLM input digest from scan findings."""

from collections import defaultdict

from eidolon.analysis.risk import _clean_addresses, _clean_handles
from eidolon.core.findings import (
    Account,
    Breach,
    BrokerExposure,
    Credential,
    ExposedHost,
    GoogleFootprint,
    InfostealerLog,
    PhoneIntel,
)
from eidolon.core.state import ScanState


def _build_analysis_digest(state: ScanState) -> str:
    """Construct a compact text digest of all findings for the LLM."""
    findings = state.findings or []
    if not findings:
        return "No findings."

    buckets: dict[str, list[str]] = defaultdict(list)

    def add(kind: str, line: str) -> None:
        buckets[kind].append(line)

    for f in findings:
        if isinstance(f, Breach):
            p = f.payload
            name = p.get("breach_name", "unknown")
            date = p.get("breach_date", "unknown")
            count = p.get("pwn_count", "?")
            data = ", ".join(p.get("data_classes", []))
            add("breach", f"{name} ({date}) — {count} accounts — {data}")
        elif isinstance(f, Credential):
            p = f.payload
            breach = p.get("source_breach", "unknown")
            user = p.get("username") or p.get("email", "?")
            add("credential", f"{breach} — {user}")
        elif isinstance(f, Account):
            p = f.payload
            platform = p.get("platform", "unknown")
            user = p.get("username", "?")
            status = "active" if p.get("confirmed") else "unconfirmed"
            add("account", f"{platform} — {user} [{status}]")
        elif isinstance(f, BrokerExposure):
            p = f.payload
            broker = p.get("broker", "unknown")
            fields = ", ".join(p.get("exposed_fields", []))
            add("broker", f"{broker} — {fields}")
        elif isinstance(f, InfostealerLog):
            p = f.payload
            family = p.get("family", "unknown")
            host = p.get("host", "?")
            add("infostealer", f"{family} on {host}")
        elif isinstance(f, PhoneIntel):
            p = f.payload
            number = p.get("number", "?")
            carrier = p.get("carrier", "?")
            add("phone", f"{number} — {carrier}")
        elif isinstance(f, GoogleFootprint):
            p = f.payload
            query = p.get("query", "?")
            add("google", f"query: {query}")
        elif isinstance(f, ExposedHost):
            p = f.payload
            ip = p.get("ip", "?")
            ports = ", ".join(str(x) for x in p.get("ports", []))
            add("host", f"{ip} — ports: {ports}")
        elif f.kind == "footprint":
            add("footprint", f.payload.get("name", "?"))
        elif f.kind == "registered_domain":
            add("domain", f.payload.get("domain", "?"))
        elif f.kind == "web_presence":
            add("web", f.payload.get("url", "?"))

    # Build the digest string
    lines = ["SCAN FINDINGS DIGEST", "=" * 20, ""]
    for kind in [
        "breach",
        "credential",
        "account",
        "broker",
        "infostealer",
        "phone",
        "google",
        "host",
        "footprint",
        "domain",
        "web",
    ]:
        if buckets[kind]:
            lines.append(f"{kind.upper()} ({len(buckets[kind])}):")
            for item in buckets[kind][:20]:  # cap per kind
                lines.append(f"  - {item}")
            if len(buckets[kind]) > 20:
                lines.append(f"  ... and {len(buckets[kind]) - 20} more")
            lines.append("")

    # Add cleaned handles/addresses for the LLM's context
    # Handles from Account findings (confirmed usernames)
    account_handles = []
    for f in findings:
        if isinstance(f, Account) and f.active:
            user = f.payload.get("username") or f.payload.get("handle")
            if user:
                account_handles.append(user)
    # Handles from Credential findings (leaked usernames)
    cred_handles = []
    for f in findings:
        if isinstance(f, Credential):
            user = f.username or f.payload.get("username")
            if user:
                cred_handles.append(user)
    all_handles = _clean_handles(account_handles + cred_handles)
    if all_handles:
        lines.append(f"HANDLES ({len(all_handles)}):")
        lines.append("  " + ", ".join(all_handles[:20]))
        lines.append("")

    # Addresses from BrokerExposure findings
    broker_addresses = []
    for f in findings:
        if isinstance(f, BrokerExposure):
            fields = f.payload.get("exposed_fields", [])
            for field in fields:
                if isinstance(field, str):
                    broker_addresses.append(field)
    # Also from Credential findings
    cred_addresses = []
    for f in findings:
        if isinstance(f, Credential):
            addr = f.address or f.payload.get("address")
            if addr:
                cred_addresses.append(addr)
    all_addresses = _clean_addresses(broker_addresses + cred_addresses)
    if all_addresses:
        lines.append(f"ADDRESSES ({len(all_addresses)}):")
        lines.append("  " + "; ".join(all_addresses[:10]))
        lines.append("")

    return "\n".join(lines)
