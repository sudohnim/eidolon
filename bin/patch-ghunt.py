#!/usr/bin/env python3
"""Patch ghunt source to handle missing fields in Google API responses.

Applies two fixes for ghunt 2.3.3/2.3.4 regressions where Google changed
their API response structure:
  1. people.py  — missing 'container' key in cover photo metadata
  2. gmaps.py   — data list shorter than expected (index 24 out of range)
"""

from pathlib import Path

VENV = Path("/app/.venv/lib/python3.12/site-packages/ghunt")

PATCHES = [
    (
        VENV / "parsers/people.py",
        'self.coverPhotos[cover_photo_data["metadata"]["container"]] = person_cover_photo',
        'self.coverPhotos[cover_photo_data.get("metadata", {}).get("container", "unknown")] = person_cover_photo',
        "cover photo container key guard",
    ),
    (
        VENV / "helpers/gmaps.py",
        "if not data[24]:",
        "if not (len(data) > 24 and data[24]):",
        "gmaps data[24] bounds check",
    ),
]


def main():
    applied = 0
    for path, old, new, description in PATCHES:
        if not path.exists():
            print(f"patch-ghunt: {path.name} not found — skipping ({description})")
            continue
        src = path.read_text()
        if old in src:
            path.write_text(src.replace(old, new))
            print(f"patch-ghunt: OK — {description}")
            applied += 1
        else:
            print(f"patch-ghunt: not needed — {description}")
    print(f"patch-ghunt: {applied}/{len(PATCHES)} patches applied")


if __name__ == "__main__":
    main()
