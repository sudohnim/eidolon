"""Domain recon: domain intake, crt.sh + DNS sources, and the wave-3 Shodan feed."""

import os
import shutil
from pathlib import Path

os.environ["TEST_MODE"] = "true"
os.environ["RESULTS_OUTPUT_PATH"] = "/tmp/osint_test_output_domain/"

import pytest  # noqa: E402

from eidolon.core.logging import get_logger  # noqa: E402
from eidolon.core.state import PipelineState  # noqa: E402
from eidolon.pipeline.classify import _classify_input  # noqa: E402
from eidolon.pipeline.graph import build_graph  # noqa: E402
from eidolon.sources import crtsh  # noqa: E402
from eidolon.sources.base import collect  # noqa: E402
from eidolon.sources.crtsh import Crtsh, CrtshInput  # noqa: E402
from eidolon.sources.dns_records import DnsInput, DnsRecords  # noqa: E402


@pytest.fixture(autouse=True)
def cleanup_output():
    yield
    out = Path("/tmp/osint_test_output_domain")
    if out.exists():
        shutil.rmtree(out)


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("Example.com", "domain", "example.com"),
        ("domain:example.com", "domain", "example.com"),
        ("Acme Corp", "name", "Acme Corp"),
        ("acme", "org", "acme"),
    ],
)
def test_classify_domain(raw, kind, value):
    [c] = _classify_input(raw)
    assert (c.type, c.value) == (kind, value)


def test_crtsh_fixture_maps_to_subdomains():
    sr = collect(Crtsh(), CrtshInput(domain="example.com"))
    keys = {f.dedup_key for f in sr.findings}
    assert keys == {
        "subdomain:*.example.com",
        "subdomain:example.com",
        "subdomain:staging.example.com",
    }
    assert all(f.selector == "example.com" for f in sr.findings)


def test_crtsh_parses_sans(monkeypatch):
    certs = [
        {
            "issuer_name": "CN=R3",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
            "name_value": "example.com\nwww.example.com\nevil.com",
        },
        {
            "issuer_name": "CN=E1",
            "not_before": "2023-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00",
            "name_value": "WWW.example.com.",
        },
    ]

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return certs

    class Http:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, params):
            assert params["q"] == "%.example.com"
            return Resp()

    monkeypatch.setattr(crtsh, "client", lambda **kw: Http())
    out = Crtsh()._run(CrtshInput(domain="example.com"), get_logger("t"))
    www = next(n for n in out.names if n.name == "www.example.com")
    assert [n.name for n in out.names] == ["example.com", "www.example.com"]
    assert www.cert_count == 2
    assert www.first_seen == "2023-01-01T00:00:00"
    assert www.last_expiry == "2025-01-01T00:00:00"
    assert www.issuers == ["CN=R3", "CN=E1"]


def test_dns_fixture_maps_to_findings():
    sr = collect(DnsRecords(), DnsInput(domain="example.com"))
    kinds = sorted(f.kind for f in sr.findings)
    assert kinds == ["dns_apex", "dns_host", "dns_host"]
    staging = next(f for f in sr.findings if f.title == "staging.example.com")
    assert staging.payload["cname"] == "example-staging.herokuapp.com"


def test_domain_pipeline_feeds_dns_and_shodan():
    result = build_graph().invoke(PipelineState(raw_input="domain:example.com"))
    results = result["results"]
    assert results["crtsh"].status == "ok"
    assert results["dns"].status == "ok"
    assert "shodan_93.184.215.14" in results
