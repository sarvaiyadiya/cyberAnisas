"""Pure parsers for passive neighbor tables and DHCP lease exports."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address

from app.modules.wireless.models import (
    WirelessClientObservation,
    WirelessClientStatus,
)
from app.modules.wireless.utils import normalize_mac

_WINDOWS_ARP = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9A-Fa-f-]{17})\s+(\S+)\s*$"
)
_ISC_LEASE = re.compile(
    r"lease\s+(\d{1,3}(?:\.\d{1,3}){3})\s*\{(.*?)\}",
    re.IGNORECASE | re.DOTALL,
)


def parse_windows_arp(
    output: str,
    interface: str | None = None,
) -> tuple[WirelessClientObservation, ...]:
    """Parse dynamic/static IPv4 entries from ``arp -a``."""
    observations: list[WirelessClientObservation] = []
    for line in output.splitlines():
        match = _WINDOWS_ARP.match(line)
        if not match:
            continue
        raw_ip, raw_mac, raw_state = match.groups()
        mac = normalize_mac(raw_mac)
        ip = _valid_unicast_ipv4(raw_ip)
        if not mac or not ip or _multicast_mac(mac):
            continue
        observations.append(
            _client(
                mac=mac,
                ip=ip,
                status=(
                    WirelessClientStatus.ACTIVE
                    if raw_state.lower() in {"dynamic", "static"}
                    else WirelessClientStatus.UNKNOWN
                ),
                interface=interface,
                source="arp",
            )
        )
    return _deduplicate(observations)


def parse_linux_neighbors(
    output: str,
    interface: str | None = None,
) -> tuple[WirelessClientObservation, ...]:
    """Parse IPv4 entries from ``ip neigh show``."""
    observations: list[WirelessClientObservation] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        ip = _valid_unicast_ipv4(fields[0])
        if not ip or "lladdr" not in fields:
            continue
        mac_index = fields.index("lladdr") + 1
        if mac_index >= len(fields):
            continue
        mac = normalize_mac(fields[mac_index])
        if not mac or _multicast_mac(mac):
            continue
        observed_interface = interface
        if "dev" in fields and fields.index("dev") + 1 < len(fields):
            observed_interface = fields[fields.index("dev") + 1]
        state = fields[-1].upper()
        observations.append(
            _client(
                mac=mac,
                ip=ip,
                status=_linux_state(state),
                interface=observed_interface,
                source="neighbor",
            )
        )
    return _deduplicate(observations)


def parse_dhcp_leases(
    content: str,
) -> tuple[WirelessClientObservation, ...]:
    """Parse bounded ISC dhcpd or dnsmasq lease text."""
    observations = list(_parse_isc_leases(content))
    observations.extend(_parse_dnsmasq_leases(content))
    return _deduplicate(observations)


def merge_clients(
    *groups: tuple[WirelessClientObservation, ...],
) -> tuple[WirelessClientObservation, ...]:
    """Merge repeated MAC/IP evidence while retaining all source labels."""
    merged: dict[tuple[str, str], WirelessClientObservation] = {}
    for item in (entry for group in groups for entry in group):
        key = (item.mac, item.ip)
        existing = merged.get(key)
        if existing is None:
            merged[key] = item
            continue
        status = (
            WirelessClientStatus.ACTIVE
            if WirelessClientStatus.ACTIVE in {existing.status, item.status}
            else existing.status
        )
        merged[key] = existing.model_copy(
            update={
                "hostname": existing.hostname or item.hostname,
                "status": status,
                "interface": existing.interface or item.interface,
                "sources": tuple(
                    dict.fromkeys(existing.sources + item.sources)
                ),
            }
        )
    return tuple(merged[key] for key in sorted(merged))


def _parse_isc_leases(
    content: str,
) -> tuple[WirelessClientObservation, ...]:
    observations: list[WirelessClientObservation] = []
    for match in _ISC_LEASE.finditer(content):
        raw_ip, body = match.groups()
        mac_match = re.search(
            r"hardware\s+ethernet\s+([0-9A-Fa-f:-]{17})\s*;",
            body,
            re.IGNORECASE,
        )
        if not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        ip = _valid_unicast_ipv4(raw_ip)
        if not mac or not ip:
            continue
        hostname_match = re.search(
            r'client-hostname\s+"([^"\r\n]{1,255})"\s*;',
            body,
            re.IGNORECASE,
        )
        state_match = re.search(
            r"binding\s+state\s+(\w+)\s*;",
            body,
            re.IGNORECASE,
        )
        status = (
            WirelessClientStatus.ACTIVE
            if state_match and state_match.group(1).lower() == "active"
            else WirelessClientStatus.STALE
        )
        observations.append(
            _client(
                mac=mac,
                ip=ip,
                status=status,
                hostname=hostname_match.group(1) if hostname_match else None,
                source="dhcp",
            )
        )
    return tuple(observations)


def _parse_dnsmasq_leases(
    content: str,
) -> tuple[WirelessClientObservation, ...]:
    observations: list[WirelessClientObservation] = []
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        mac = normalize_mac(fields[1])
        ip = _valid_unicast_ipv4(fields[2])
        if not mac or not ip:
            continue
        hostname = None if fields[3] == "*" else fields[3][:255]
        observations.append(
            _client(
                mac=mac,
                ip=ip,
                status=WirelessClientStatus.ACTIVE,
                hostname=hostname,
                source="dhcp",
            )
        )
    return tuple(observations)


def _client(
    *,
    mac: str,
    ip: str,
    status: WirelessClientStatus,
    source: str,
    interface: str | None = None,
    hostname: str | None = None,
) -> WirelessClientObservation:
    return WirelessClientObservation(
        mac=mac,
        ip=ip,
        hostname=hostname,
        status=status,
        last_seen=datetime.now(timezone.utc),
        interface=interface,
        sources=(source,),
        oui=mac[:8],
    )


def _valid_unicast_ipv4(value: str) -> str | None:
    try:
        parsed = ip_address(value)
    except ValueError:
        return None
    if not isinstance(parsed, IPv4Address):
        return None
    if parsed.is_multicast or parsed.is_unspecified or parsed == IPv4Address(
        "255.255.255.255"
    ):
        return None
    return str(parsed)


def _multicast_mac(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x01)


def _linux_state(state: str) -> WirelessClientStatus:
    if state in {"REACHABLE", "PERMANENT", "DELAY", "PROBE"}:
        return WirelessClientStatus.ACTIVE
    if state == "STALE":
        return WirelessClientStatus.STALE
    if state in {"INCOMPLETE", "FAILED"}:
        return WirelessClientStatus.INCOMPLETE
    return WirelessClientStatus.UNKNOWN


def _deduplicate(
    observations: list[WirelessClientObservation],
) -> tuple[WirelessClientObservation, ...]:
    return merge_clients(tuple(observations))
