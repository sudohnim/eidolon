"""Input classification and intake node."""

import logging
import re
import uuid
from typing import Literal

from eidolon.core.state import InputClassification, ScanState

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?1?\d{10}$")


def _classify_input(raw: str) -> list[InputClassification]:
    """Parse the raw input string into structured classifications."""
    out: list[InputClassification] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # Structured format: "type:value"
        if line.startswith(("email:", "phone:", "name:")):
            kind, _, value = line.partition(":")
            type_map: dict[str, Literal["email", "phone", "name", "org"]] = {
                "email": "email",
                "phone": "phone",
                "name": "name",
            }
            out.append(
                InputClassification(
                    type=type_map[kind.strip().lower()], value=value.strip(), raw=line
                )
            )
        elif line.startswith(("city:", "state:", "zip:")):
            # Location fields handled separately
            continue
        else:
            # Fallback: regex-based classification for bare strings
            item = _classify_bare(line)
            if item:
                out.append(item)
    return out


def _classify_bare(raw: str) -> InputClassification | None:
    """Classify a bare string without type prefix."""
    raw = raw.strip()
    if not raw:
        return None
    if EMAIL_RE.match(raw):
        return InputClassification(type="email", value=raw.lower(), raw=raw)
    # Try phone normalization first (handles formats like 555-123-4567)
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 10:
        return InputClassification(type="phone", value=f"+1{digits}", raw=raw)
    if PHONE_RE.match(raw):
        return InputClassification(type="phone", value=raw, raw=raw)
    words = raw.split()
    if 2 <= len(words) <= 4 and all(w[0].isupper() for w in words if w):
        return InputClassification(type="name", value=raw, raw=raw)
    # Treat unrecognized as org
    return InputClassification(type="org", value=raw, raw=raw)


def intake_node(state: ScanState) -> ScanState:
    """Parse raw_input, mint run_id, and seed the classifications."""
    classifications = _classify_input(state.raw_input)
    run_id = state.run_id or uuid.uuid4().hex[:8]
    logger.info("intake: %d classifications, run_id=%s", len(classifications), run_id)
    return state.model_copy(
        update={
            "classifications": classifications,
            "run_id": run_id,
        }
    )
