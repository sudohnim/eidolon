"""DeHashed breach record tool.

DeHashed returns actual breach record contents — plaintext passwords, hashed
passwords, usernames, addresses, and phone numbers — not just metadata like HIBP.

Complements HIBP:
  HIBP  → "you were in Adobe 2013, password class exposed"
  DeHashed → "here is the MD5 hash / plaintext password from that record"

Also surfaces physical data (addresses, phones) found inside breach dumps,
which fills the gap when broker scanning returns nothing.

Auth: API key in `Dehashed-Api-Key` header (v2 API — no longer HTTP Basic).
Requires: DEHASHED_API_KEY in .env (DEHASHED_EMAIL no longer needed for v2).
Skips gracefully if key is missing.
"""

import requests
import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.tools.base import Tool


class DehashedInput(BaseModel):
    email: str


class DehashedEntry(BaseModel):
    database_name: str = ""
    email: str = ""
    username: str = ""
    password: str = ""  # plaintext — present in some older breaches
    hashed_password: str = ""  # MD5 / SHA-1 / bcrypt etc.
    ip_address: str = ""
    phone: str = ""
    name: str = ""
    address: str = ""


class DehashedOutput(BaseModel):
    query: str = ""
    total: int = 0  # total hits reported by API
    entries: list[DehashedEntry] = []  # up to 50 records returned

    # Aggregated signals surfaced to the LLM
    plaintext_password_count: int = 0
    hashed_password_count: int = 0
    unique_usernames: list[str] = []  # pivot targets for Maigret
    unique_addresses: list[str] = []  # fills physical_data gap
    unique_phones: list[str] = []  # supplements phone pivot
    unique_databases: list[str] = []  # breach sources (complements HIBP)


DEHASHED_URL = "https://api.dehashed.com/v2/search"


def _hash_type(h: str) -> str:
    """Best-guess hash algorithm from length/prefix."""
    if not h:
        return ""
    h = h.strip()
    if h.startswith("$2") and len(h) == 60:
        return "bcrypt"
    if h.startswith("$pbkdf2"):
        return "pbkdf2"
    if len(h) == 32:
        return "MD5"
    if len(h) == 40:
        return "SHA-1"
    if len(h) == 64:
        return "SHA-256"
    if len(h) == 128:
        return "SHA-512"
    return "unknown"


class Dehashed(Tool[DehashedInput, DehashedOutput]):
    name = "dehashed"
    input_schema = DehashedInput
    output_schema = DehashedOutput

    def available(self) -> bool:
        return bool(config.get("DEHASHED_API_KEY"))

    def _input_value(self, inp: DehashedInput) -> str:
        return inp.email

    def _run(
        self, inp: DehashedInput, log: structlog.stdlib.BoundLogger
    ) -> DehashedOutput:
        email = inp.email
        dh_key = config.get("DEHASHED_API_KEY")

        # v2 API: POST with JSON body, API key in header.
        resp = requests.post(
            DEHASHED_URL,
            json={"query": f"email:{email}", "size": 50, "de_dupe": True},
            headers={"Dehashed-Api-Key": dh_key, "Content-Type": "application/json"},
            timeout=20,
        )
        if not resp.ok:
            log.error("http error", status=resp.status_code, body=resp.text[:500])
        resp.raise_for_status()
        raw = resp.json()

        entries: list[DehashedEntry] = []
        plaintext_count = 0
        hashed_count = 0
        usernames: list[str] = []
        addresses: list[str] = []
        phones: list[str] = []
        databases: list[str] = []

        def _str(val: object) -> str:
            """v2 API returns some fields as lists instead of strings."""
            if isinstance(val, list):
                return ", ".join(str(v) for v in val if v)
            return str(val) if val else ""

        for hit in raw.get("entries") or []:
            entry = DehashedEntry(
                database_name=_str(hit.get("database_name")),
                email=_str(hit.get("email")),
                username=_str(hit.get("username")),
                password=_str(hit.get("password")),
                hashed_password=_str(hit.get("hashed_password")),
                ip_address=_str(hit.get("ip_address")),
                phone=_str(hit.get("phone")),
                name=_str(hit.get("name")),
                address=_str(hit.get("address")),
            )
            entries.append(entry)

            if entry.password:
                plaintext_count += 1
            if entry.hashed_password:
                hashed_count += 1
            if entry.username and entry.username not in usernames:
                usernames.append(entry.username)
            if entry.address and entry.address not in addresses:
                addresses.append(entry.address)
            if entry.phone and entry.phone not in phones:
                phones.append(entry.phone)
            if entry.database_name and entry.database_name not in databases:
                databases.append(entry.database_name)

        output = DehashedOutput(
            query=email,
            total=raw.get("total") or len(entries),
            entries=entries,
            plaintext_password_count=plaintext_count,
            hashed_password_count=hashed_count,
            unique_usernames=usernames,
            unique_addresses=addresses,
            unique_phones=phones,
            unique_databases=databases,
        )
        log.info(
            "ok",
            total=output.total,
            plaintext=output.plaintext_password_count,
            hashed=output.hashed_password_count,
            addresses=len(output.unique_addresses),
            usernames=len(output.unique_usernames),
        )
        return output
