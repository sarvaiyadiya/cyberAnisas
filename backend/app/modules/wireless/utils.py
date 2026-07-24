"""Validation and normalization utilities for Module 5."""

import re

_MAC_HEX = re.compile(r"^[0-9A-Fa-f]{12}$")


def normalize_mac(value: str) -> str | None:
    """Return an uppercase colon-separated MAC address or ``None``."""
    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if not _MAC_HEX.fullmatch(compact):
        return None
    return ":".join(
        compact[index : index + 2].upper()
        for index in range(0, 12, 2)
    )
