"""Bounded, dependency-free TCP connect port discovery."""

from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable

from app.core.config import settings
from app.core.logger import get_logger
from app.modules.iot.exceptions import (
    PortDiscoveryError,
    PortScanConfigurationError,
)
from app.modules.iot.models import (
    PortDiscoveryResult,
    PortObservation,
    PortState,
)
from app.modules.iot.utils import normalize_ports, validate_ipv4

logger = get_logger(__name__)

# Deliberately finite: Version 1 fingerprints one host and does not perform a
# blanket 65,535-port scan. Callers may inject a different explicit port set.
DEFAULT_IOT_TCP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 81, 82, 83, 84, 85, 88, 110, 135, 139, 443,
    445, 515, 554, 631, 8000, 8001, 8080, 8081, 8088, 8443, 8554, 8888,
    9000, 37777, 49152,
)

ConnectFunction = Callable[[str, int, float], tuple[int, float | None]]


@dataclass(frozen=True, slots=True)
class PortScannerConfig:
    """Validated operational limits for a TCP connect scan."""

    timeout_seconds: float = settings.IOT_CONNECT_TIMEOUT_SECONDS
    max_workers: int = settings.IOT_SCAN_WORKERS

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 10:
            raise PortScanConfigurationError(
                "Connect timeout must be greater than 0 and at most 10 seconds"
            )
        if not 1 <= self.max_workers <= 256:
            raise PortScanConfigurationError(
                "Worker count must be between 1 and 256"
            )


def _tcp_connect(target: str, port: int, timeout: float) -> tuple[int, float]:
    """Attempt one IPv4 TCP connection and return errno plus latency."""
    started = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        result = connection.connect_ex((target, port))
    return result, (time.perf_counter() - started) * 1000


class PortDiscoveryEngine:
    """Discover open TCP ports using bounded parallel connect attempts."""

    def __init__(
        self,
        config: PortScannerConfig | None = None,
        connector: ConnectFunction | None = None,
    ) -> None:
        self._config = config or PortScannerConfig()
        self._connector = connector or _tcp_connect

    def scan(
        self,
        target: str,
        ports: Iterable[int] = DEFAULT_IOT_TCP_PORTS,
    ) -> PortDiscoveryResult:
        """Scan an explicit TCP port set on one IPv4 target."""
        canonical_target = str(validate_ipv4(target))
        normalized_ports = normalize_ports(ports)
        started = time.perf_counter()
        observations: list[PortObservation] = []

        worker_count = min(self._config.max_workers, len(normalized_ports))
        logger.info(
            "Starting TCP discovery target=%s ports=%d workers=%d",
            canonical_target,
            len(normalized_ports),
            worker_count,
        )

        try:
            with ThreadPoolExecutor(
                max_workers=worker_count,
                thread_name_prefix="iot-port-scan",
            ) as executor:
                futures = {
                    executor.submit(
                        self._scan_port, canonical_target, port
                    ): port
                    for port in normalized_ports
                }
                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        observations.append(future.result())
                    except Exception as exc:  # connector boundary
                        logger.warning(
                            "TCP probe failed target=%s port=%d: %s",
                            canonical_target,
                            port,
                            exc,
                        )
                        observations.append(
                            PortObservation(
                                port=port,
                                state=PortState.ERROR,
                                error=type(exc).__name__,
                            )
                        )
        except RuntimeError as exc:
            raise PortDiscoveryError("Unable to execute TCP port scan") from exc

        observations.sort(key=lambda item: item.port)
        open_ports = tuple(
            item.port for item in observations if item.state is PortState.OPEN
        )
        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "TCP discovery complete target=%s open_ports=%d duration_ms=%.2f",
            canonical_target,
            len(open_ports),
            duration_ms,
        )
        return PortDiscoveryResult(
            target=canonical_target,
            open_ports=open_ports,
            observations=tuple(observations),
            scanned_port_count=len(normalized_ports),
            duration_ms=duration_ms,
        )

    def _scan_port(self, target: str, port: int) -> PortObservation:
        result, latency_ms = self._connector(
            target,
            port,
            self._config.timeout_seconds,
        )
        state = _state_from_connect_result(result)
        return PortObservation(
            port=port,
            state=state,
            latency_ms=latency_ms,
        )


def _state_from_connect_result(result: int) -> PortState:
    """Normalize platform socket results without exposing raw scanner output."""
    if result == 0:
        return PortState.OPEN
    if result in {errno.ECONNREFUSED, 10061}:
        return PortState.CLOSED
    if result in {
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        10060,
        10065,
        10051,
    }:
        return PortState.FILTERED
    return PortState.ERROR
