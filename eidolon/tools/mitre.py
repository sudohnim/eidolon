"""MITRE ATT&CK mapping — deterministic, local (no network, no key).

Takes a list of finding "signals" (extracted from scan state by the node) and
maps each to one or more MITRE ATT&CK techniques via data/attack_map.json. The
output is the "Threat Model" section of the report: what an attacker can actually
do with what we found, named in the shared ATT&CK vocabulary.

ATT&CK in one line: Tactics are the attacker's GOAL ("why", e.g. Credential
Access / TA0006); Techniques are the HOW ("T1555 — Credentials from Password
Stores"). Each technique carries a plain-English explanation + the official URL.
"""

from typing import Literal, cast

import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool
from eidolon.utils import load_data

Severity = Literal["critical", "high", "medium", "low"]
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class MitreSignal(BaseModel):
    signal: str  # key into attack_map.json (e.g. "infostealer_log")
    evidence: str  # the finding that triggered it
    severity: Severity = "medium"


class MitreInput(BaseModel):
    signals: list[MitreSignal] = []


class MitreTechnique(BaseModel):
    technique_id: str  # "T1555"
    name: str  # "Credentials from Password Stores"
    headline: str = ""  # plain-English title for non-technical readers
    tactic: str  # "Credential Access"
    tactic_id: str  # "TA0006"
    severity: Severity = "medium"
    what_it_is: str = ""  # plain-English: what the technique is
    why_this_finding: str = ""  # plain-English: why our finding enables it
    url: str = ""  # official attack.mitre.org page
    evidence: list[str] = []  # findings that map to this technique


class MitreOutput(BaseModel):
    techniques: list[MitreTechnique] = []
    tactics_covered: list[str] = []
    technique_count: int = 0
    highest_severity: str = "low"


def _more_severe(a: Severity, b: Severity) -> Severity:
    return a if _SEV_RANK[a] <= _SEV_RANK[b] else b


class MitreAttack(Tool[MitreInput, MitreOutput]):
    name = "mitre"
    input_type = "email"
    input_schema = MitreInput
    output_schema = MitreOutput

    def _run(self, inp: MitreInput, log: structlog.stdlib.BoundLogger) -> MitreOutput:
        db = cast(dict, load_data("attack_map.json")).get("signals", {})

        # One technique can be enabled by several findings — dedupe by id and
        # merge their evidence, keeping the most severe triggering signal.
        by_id: dict[str, MitreTechnique] = {}
        for sig in inp.signals:
            for t in db.get(sig.signal, []):
                tech = by_id.get(t["technique_id"])
                if tech is None:
                    tech = MitreTechnique(**t, severity=sig.severity)
                    by_id[t["technique_id"]] = tech
                else:
                    tech.severity = _more_severe(tech.severity, sig.severity)
                if sig.evidence and sig.evidence not in tech.evidence:
                    tech.evidence.append(sig.evidence)

        techniques = sorted(by_id.values(), key=lambda x: _SEV_RANK[x.severity])
        log.info("ok", techniques=len(techniques))
        return MitreOutput(
            techniques=techniques,
            tactics_covered=sorted({t.tactic for t in techniques}),
            technique_count=len(techniques),
            highest_severity=techniques[0].severity if techniques else "low",
        )
