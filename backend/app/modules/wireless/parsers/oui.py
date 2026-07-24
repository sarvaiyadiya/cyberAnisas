"""Parser for IEEE Registration Authority CSV public listings."""

from __future__ import annotations

import csv
import io
import re

_HEX = re.compile(r"[^0-9A-Fa-f]")


def parse_ieee_oui_csv(content: str) -> dict[str, str]:
    """Return MA-L assignment prefixes mapped to organization names."""
    records: dict[str, str] = {}
    reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")))
    for row in reader:
        registry = (row.get("Registry") or "").strip().upper()
        assignment = _normalize_assignment(row.get("Assignment") or "")
        organization = (row.get("Organization Name") or "").strip()
        if registry not in {"MA-L", "OUI"}:
            continue
        if len(assignment) != 6 or not organization:
            continue
        records[assignment] = organization[:500]
    return records


def _normalize_assignment(value: str) -> str:
    return _HEX.sub("", value).upper()
