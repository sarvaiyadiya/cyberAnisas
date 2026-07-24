"""Bounded parser for RIR WHOIS key-value responses."""

from __future__ import annotations

import re

from app.modules.asn.models import WHOISIntelligence

_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")


def parse_whois_response(server: str, text: str) -> WHOISIntelligence:
    """Extract common RIR fields without returning unbounded raw text."""
    values: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("%", "#", ";")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower().replace("-", "")
        cleaned = " ".join(value.split())[:1000]
        if cleaned:
            values.setdefault(normalized_key, []).append(cleaned)

    def first(*keys: str) -> str | None:
        for key in keys:
            candidates = values.get(key, [])
            if candidates:
                return candidates[0]
        return None

    cidrs = _unique(
        values.get("cidr", [])
        + values.get("route", [])
        + values.get("route6", [])
        + values.get("inetnum", [])
        + values.get("inet6num", [])
    )[:100]
    emails = _unique(
        match.group(0).lower()
        for line in text.splitlines()
        if any(token in line.lower() for token in ("abuse", "orgabuse", "e-mail"))
        for match in _EMAIL.finditer(line)
    )[:20]
    network_name = first("netname", "networkname", "ownerid")
    organization = first("orgname", "organization", "owner", "descr")
    country = first("country")
    network_range = first("netrange", "inetnum", "inet6num")
    created = first("regdate", "created")
    updated = first("updated", "lastmodified", "changed")
    evidence = [
        item
        for item in (
            f"Network name: {network_name}" if network_name else None,
            f"Organization: {organization}" if organization else None,
            f"Country: {country}" if country else None,
            f"CIDR records observed: {len(cidrs)}" if cidrs else None,
            f"Abuse contacts observed: {len(emails)}" if emails else None,
        )
        if item
    ]
    return WHOISIntelligence(
        status="available" if evidence else "no_structured_data",
        server=server,
        network_name=network_name,
        organization=organization,
        country=country,
        cidrs=cidrs,
        network_range=network_range,
        created_at=created,
        updated_at=updated,
        abuse_emails=emails,
        confidence=min(0.25 + 0.15 * len(evidence), 0.95) if evidence else 0.0,
        evidence=evidence,
    )


def _unique(values) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
