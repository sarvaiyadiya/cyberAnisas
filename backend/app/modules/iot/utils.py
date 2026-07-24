"""Validation utilities for the IoT fingerprinting module."""

from ipaddress import IPv4Address, ip_address
from typing import Iterable

from app.modules.iot.exceptions import (
    InvalidTargetError,
    PortScanConfigurationError,
)


def validate_ipv4(target: str) -> IPv4Address:
    """Return a canonical IPv4 address without resolving hostnames."""
    try:
        parsed = ip_address(target.strip())
    except (AttributeError, ValueError) as exc:
        raise InvalidTargetError("Target must be a valid IPv4 address") from exc

    if not isinstance(parsed, IPv4Address):
        raise InvalidTargetError("Module 4 Version 1 accepts IPv4 addresses only")
    return parsed


def normalize_ports(ports: Iterable[int]) -> tuple[int, ...]:
    """Validate, deduplicate, and sort a collection of TCP ports."""
    normalized: set[int] = set()
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise PortScanConfigurationError("Every port must be an integer")
        if not 1 <= port <= 65535:
            raise PortScanConfigurationError(
                f"Port {port} is outside the valid range 1-65535"
            )
        normalized.add(port)

    if not normalized:
        raise PortScanConfigurationError("At least one TCP port is required")
    return tuple(sorted(normalized))
