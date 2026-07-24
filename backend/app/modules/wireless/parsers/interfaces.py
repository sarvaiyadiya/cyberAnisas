"""Pure parsers for Windows and Linux wireless interface output."""

from __future__ import annotations

import re

from app.modules.wireless.models import (
    WirelessInterface,
    WirelessInterfaceStatus,
)


def parse_windows_interfaces(output: str) -> tuple[WirelessInterface, ...]:
    """Parse bounded ``netsh wlan show interfaces`` text."""
    blocks = re.split(r"\r?\n\s*\r?\n", output)
    interfaces: list[WirelessInterface] = []
    for block in blocks:
        values = _colon_values(block)
        name = values.get("name")
        if not name:
            continue
        interfaces.append(
            WirelessInterface(
                name=name,
                platform="Windows",
                status=_normalize_status(values.get("state")),
                description=values.get("description"),
            )
        )
    return _unique_interfaces(interfaces)


def parse_linux_nmcli_interfaces(
    output: str,
) -> tuple[WirelessInterface, ...]:
    """Parse escaped ``nmcli -t`` device rows and keep Wi-Fi interfaces."""
    interfaces: list[WirelessInterface] = []
    for raw_line in output.splitlines():
        parts = _split_nmcli_line(raw_line)
        if len(parts) < 3 or parts[1].lower() not in {"wifi", "wireless"}:
            continue
        name = parts[0].strip()
        if not name:
            continue
        interfaces.append(
            WirelessInterface(
                name=name,
                platform="Linux",
                status=_normalize_status(parts[2]),
            )
        )
    return _unique_interfaces(interfaces)


def _colon_values(block: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if normalized_key and normalized_value:
            values[normalized_key] = normalized_value
    return values


def _split_nmcli_line(line: str) -> list[str]:
    values: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            values.append("".join(current))
            current = []
        else:
            current.append(character)
    current.append("\\") if escaped else None
    values.append("".join(current))
    return values


def _normalize_status(value: str | None) -> WirelessInterfaceStatus:
    normalized = (value or "").strip().lower()
    if normalized in {"connected", "activated"}:
        return WirelessInterfaceStatus.CONNECTED
    if normalized in {"disconnected", "disconnected (reason unspecified)"}:
        return WirelessInterfaceStatus.DISCONNECTED
    if normalized in {"unavailable", "disabled", "not present"}:
        return WirelessInterfaceStatus.UNAVAILABLE
    return WirelessInterfaceStatus.UNKNOWN


def _unique_interfaces(
    interfaces: list[WirelessInterface],
) -> tuple[WirelessInterface, ...]:
    unique = {item.name: item for item in interfaces}
    return tuple(unique[name] for name in sorted(unique))
