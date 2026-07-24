"""Safe RTSP service detection using a single OPTIONS request."""

from __future__ import annotations

import re
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from app.core.config import settings
from app.core.logger import get_logger
from app.modules.iot.exceptions import RTSPConfigurationError
from app.modules.iot.fingerprints.signatures import match_vendor_signatures
from app.modules.iot.models import RTSPDetectionResult, RTSPObservation
from app.modules.iot.utils import validate_ipv4

logger = get_logger(__name__)
DEFAULT_RTSP_PORTS = frozenset({554, 8554})
_STATUS_LINE = re.compile(r"^RTSP/\d+\.\d+\s+(\d{3})(?:\s+.*)?$", re.I)
_HEADER_END = b"\r\n\r\n"
RTSPSender = Callable[[str, int, float, int], tuple[bytes, float]]


@dataclass(frozen=True, slots=True)
class RTSPProbeConfig:
    """RTSP connection and response limits."""

    timeout_seconds: float = settings.IOT_RTSP_TIMEOUT_SECONDS
    max_bytes: int = settings.IOT_RTSP_MAX_BYTES

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 10:
            raise RTSPConfigurationError(
                "RTSP timeout must be greater than 0 and at most 10 seconds"
            )
        if not 256 <= self.max_bytes <= 65536:
            raise RTSPConfigurationError(
                "RTSP response limit must be between 256 and 65536 bytes"
            )


class RTSPDetectionEngine:
    """Detect RTSP without requesting streams or sending credentials."""

    def __init__(
        self,
        config: RTSPProbeConfig | None = None,
        sender: RTSPSender | None = None,
    ) -> None:
        self._config = config or RTSPProbeConfig()
        self._sender = sender or _send_options

    def detect(
        self,
        target: str,
        open_ports: Iterable[int],
    ) -> RTSPDetectionResult:
        """Probe only recognized RTSP ports confirmed open by port discovery."""
        canonical_target = str(validate_ipv4(target))
        ports = sorted(set(open_ports).intersection(DEFAULT_RTSP_PORTS))
        started = time.perf_counter()
        observations = tuple(
            self._detect_one(canonical_target, port) for port in ports
        )
        return RTSPDetectionResult(
            target=canonical_target,
            observations=observations,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _detect_one(self, target: str, port: int) -> RTSPObservation:
        try:
            payload, latency_ms = self._sender(
                target,
                port,
                self._config.timeout_seconds,
                self._config.max_bytes,
            )
            return parse_rtsp_response(
                port=port,
                payload=payload[: self._config.max_bytes],
                latency_ms=latency_ms,
                truncated=len(payload) > self._config.max_bytes,
            )
        except (TimeoutError, socket.timeout):
            return RTSPObservation(port=port, error="timeout")
        except OSError as exc:
            logger.debug(
                "RTSP probe failed target=%s port=%d type=%s",
                target,
                port,
                type(exc).__name__,
            )
            return RTSPObservation(port=port, error=type(exc).__name__)


def _send_options(
    target: str,
    port: int,
    timeout: float,
    max_bytes: int,
) -> tuple[bytes, float]:
    """Send exactly one RTSP OPTIONS request to the service root."""
    request = (
        f"OPTIONS rtsp://{target}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: ANISAS/1.0\r\n"
        "\r\n"
    ).encode("ascii")
    started = time.perf_counter()
    response = bytearray()
    with socket.create_connection((target, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        while len(response) <= max_bytes:
            chunk = connection.recv(min(2048, max_bytes + 1 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if _HEADER_END in response:
                break
    return bytes(response), (time.perf_counter() - started) * 1000


def parse_rtsp_response(
    port: int,
    payload: bytes,
    latency_ms: float,
    truncated: bool = False,
) -> RTSPObservation:
    """Parse RTSP status and selected headers without returning raw data."""
    text = payload.decode("iso-8859-1", errors="replace")
    header_text = text.split("\r\n\r\n", 1)[0]
    lines = header_text.replace("\x00", "").splitlines()
    if not lines:
        return RTSPObservation(
            port=port,
            latency_ms=latency_ms,
            truncated=truncated,
            error="empty_response",
        )

    status_match = _STATUS_LINE.match(lines[0].strip())
    if not status_match:
        return RTSPObservation(
            port=port,
            latency_ms=latency_ms,
            truncated=truncated,
            error="invalid_rtsp_response",
        )

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = _clean(value)

    status_code = int(status_match.group(1))
    authentication = headers.get("www-authenticate")
    authentication_scheme = (
        authentication.split(None, 1)[0].title() if authentication else None
    )
    methods_header = headers.get("public") or headers.get("allow") or ""
    methods = tuple(
        sorted(
            {
                method.strip().upper()
                for method in methods_header.split(",")
                if method.strip()
            }
        )
    )
    server = headers.get("server")
    evidence_text = " ".join(value for value in (server, authentication) if value).lower()
    return RTSPObservation(
        port=port,
        detected=True,
        status_code=status_code,
        server=server,
        public_methods=methods,
        authentication_required=status_code == 401 or bool(authentication),
        authentication_scheme=authentication_scheme,
        vendor_hints=match_vendor_signatures(evidence_text),
        latency_ms=latency_ms,
        truncated=truncated,
        evidence=tuple(
            item
            for item in (
                f"RTSP status observed: {status_code}",
                f"RTSP Server header: {server}" if server else None,
            )
            if item
        ),
        confidence=0.98,
    )


def _clean(value: str) -> str:
    """Remove control characters and bound untrusted header values."""
    return "".join(
        character
        for character in value
        if character in "\t" or ord(character) >= 32
    ).strip()[:1024]
