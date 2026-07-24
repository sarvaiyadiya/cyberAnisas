"""Safe, bounded passive banner collection for discovered TCP services."""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from app.core.config import settings
from app.core.logger import get_logger
from app.modules.iot.exceptions import BannerConfigurationError
from app.modules.iot.fingerprints.signatures import match_vendor_signatures
from app.modules.iot.models import BannerDiscoveryResult, BannerObservation
from app.modules.iot.utils import normalize_ports, validate_ipv4

logger = get_logger(__name__)

BannerReceiver = Callable[[str, int, float, int], bytes]
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class BannerCollectorConfig:
    """Operational and memory limits for passive banner collection."""

    timeout_seconds: float = settings.IOT_BANNER_TIMEOUT_SECONDS
    max_bytes: int = settings.IOT_BANNER_MAX_BYTES

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 10:
            raise BannerConfigurationError(
                "Banner timeout must be greater than 0 and at most 10 seconds"
            )
        if not 64 <= self.max_bytes <= 65536:
            raise BannerConfigurationError(
                "Banner size limit must be between 64 and 65536 bytes"
            )


def _receive_banner(
    target: str,
    port: int,
    timeout: float,
    max_bytes: int,
) -> bytes:
    """Connect to an IPv4 TCP service and passively read its initial banner."""
    with socket.create_connection((target, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        return connection.recv(max_bytes + 1)


class BannerFingerprintEngine:
    """
    Collect initial service banners without sending protocol-specific payloads.

    HTTP and RTSP request/response probing deliberately remains in their
    dedicated later phases.
    """

    def __init__(
        self,
        config: BannerCollectorConfig | None = None,
        receiver: BannerReceiver | None = None,
    ) -> None:
        self._config = config or BannerCollectorConfig()
        self._receiver = receiver or _receive_banner

    def collect(
        self,
        target: str,
        open_ports: Iterable[int],
    ) -> BannerDiscoveryResult:
        """Collect sanitized banners from a validated set of open TCP ports."""
        canonical_target = str(validate_ipv4(target))
        requested_ports = tuple(open_ports)
        if not requested_ports:
            return BannerDiscoveryResult(
                target=canonical_target,
                observations=(),
                duration_ms=0,
            )
        ports = normalize_ports(requested_ports)
        started = time.perf_counter()
        observations = tuple(
            self._collect_one(canonical_target, port) for port in ports
        )
        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Banner collection complete target=%s ports=%d responses=%d",
            canonical_target,
            len(ports),
            sum(item.responded for item in observations),
        )
        return BannerDiscoveryResult(
            target=canonical_target,
            observations=observations,
            duration_ms=duration_ms,
        )

    def _collect_one(self, target: str, port: int) -> BannerObservation:
        try:
            payload = self._receiver(
                target,
                port,
                self._config.timeout_seconds,
                self._config.max_bytes,
            )
        except (TimeoutError, socket.timeout):
            return BannerObservation(port=port, error="timeout")
        except OSError as exc:
            logger.debug(
                "Banner connection failed target=%s port=%d type=%s",
                target,
                port,
                type(exc).__name__,
            )
            return BannerObservation(port=port, error=type(exc).__name__)

        truncated = len(payload) > self._config.max_bytes
        bounded_payload = payload[: self._config.max_bytes]
        banner = sanitize_banner(bounded_payload)
        normalized = normalize_banner(banner) if banner else None
        return BannerObservation(
            port=port,
            banner=banner or None,
            normalized_banner=normalized,
            vendor_hints=match_banner_vendor_hints(normalized or ""),
            bytes_received=len(bounded_payload),
            truncated=truncated,
            responded=bool(payload),
        )


def sanitize_banner(payload: bytes) -> str:
    """Decode untrusted bytes and remove terminal/control characters."""
    decoded = payload.decode("utf-8", errors="replace")
    return _CONTROL_CHARACTERS.sub("", decoded).strip()


def normalize_banner(banner: str) -> str:
    """Produce stable lowercase text for deterministic signature matching."""
    return _WHITESPACE.sub(" ", banner).strip().lower()


def match_banner_vendor_hints(normalized_banner: str) -> tuple[str, ...]:
    """Return deduplicated vendor hints supported by explicit banner text."""
    return match_vendor_signatures(normalized_banner)
