"""Report content, defined once (REFACTOR.3) — re-export façade (REFACTOR.6).

The god module here (694 LOC) split by responsibility:

- ``sections`` — the typed ``ReportModel`` + every section content shape
- ``builders`` — deriving a ``ReportModel`` from one scan state
- ``text`` — display cleaning + static framing strings

This module re-exports the names the old ``model.py`` exposed so renderers,
``report/__init__``, MCP and tests keep working unchanged. The leaked-
credentials dossier is the ONE caller of ``Credential.password
.get_secret_value()`` — the reveal path (``DossierRecord.display`` in
``sections``); every other consumer sees the SecretStr masked by construction.
"""

from __future__ import annotations

from eidolon.report.builders import build_report_model  # noqa: F401
from eidolon.report.sections import (  # noqa: F401
    ActionItem,
    Actions,
    BazzellOptOuts,
    Coverage,
    CoverageRow,
    Dossier,
    DossierGroup,
    DossierRecord,
    KnownGroup,
    OptOutItem,
    RemediationGroup,
    ReportHeader,
    ReportModel,
    ThreatSection,
    ThreatTechnique,
    TrainingPile,
    WebProperty,
)
from eidolon.report.text import (  # noqa: F401
    _KNOWN_GROUPS,
    _MECH_LABELS,
    _REMEDIATION_GROUPS,
    _SOURCE_LABELS,
    _SOURCE_ORDER,
    THREAT_INTRO,
    TRAINING_PILE_INTRO,
    TRAINING_PILE_OPT_OUT_NOTE,
    TRAINING_PILE_OPT_OUT_STEPS,
    _clean_cred_address,
    _clean_cred_hash,
    _clean_cred_username,
    _rem_item,
)
