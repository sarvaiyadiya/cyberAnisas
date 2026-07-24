"""Safe ONVIF device-service endpoint detection."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

import requests

from app.modules.iot.clients.device_http import DeviceHTTPClient, DeviceHTTPResponse
from app.modules.iot.detectors.http import HTTP_PORT_SCHEMES
from app.modules.iot.fingerprints.signatures import match_vendor_signatures
from app.modules.iot.models import (
    ONVIFDetectionResult,
    ONVIFObservation,
    ONVIFStatus,
)
from app.modules.iot.utils import validate_ipv4

ONVIF_DEVICE_PATH = "/onvif/device_service"
ONVIFFetcher = Callable[[str], DeviceHTTPResponse]


class ONVIFDetectionEngine:
    """Check the standard endpoint without credentials or configuration calls."""

    def __init__(self, fetcher: ONVIFFetcher | None = None) -> None:
        client = DeviceHTTPClient() if fetcher is None else None
        self._fetcher = fetcher or client.get  # type: ignore[union-attr]

    def detect(
        self,
        target: str,
        open_ports: Iterable[int],
    ) -> ONVIFDetectionResult:
        """Issue one bounded GET to the standard endpoint per open web port."""
        canonical_target = str(validate_ipv4(target))
        web_ports = sorted(set(open_ports).intersection(HTTP_PORT_SCHEMES))
        started = time.perf_counter()
        observations = tuple(
            self._detect_one(canonical_target, port) for port in web_ports
        )
        return ONVIFDetectionResult(
            target=canonical_target,
            status=_aggregate_status(observations),
            observations=observations,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _detect_one(self, target: str, port: int) -> ONVIFObservation:
        scheme = HTTP_PORT_SCHEMES[port]
        authority = (
            target
            if (scheme, port) in {("http", 80), ("https", 443)}
            else f"{target}:{port}"
        )
        endpoint = f"{scheme}://{authority}{ONVIF_DEVICE_PATH}"
        try:
            response = self._fetcher(endpoint)
        except requests.Timeout:
            return ONVIFObservation(
                endpoint=endpoint,
                port=port,
                status=ONVIFStatus.ERROR,
                error="timeout",
            )
        except (requests.RequestException, OSError) as exc:
            return ONVIFObservation(
                endpoint=endpoint,
                port=port,
                status=ONVIFStatus.ERROR,
                error=type(exc).__name__,
            )

        text = response.body.decode("utf-8", errors="replace")[:16384]
        normalized = text.lower()
        soap_response = any(
            marker in normalized
            for marker in (
                "soap-env:envelope",
                "soap:envelope",
                "http://www.onvif.org/",
                "onvif",
            )
        )
        authentication_required = response.status_code in {401, 403}
        if authentication_required:
            status = ONVIFStatus.AUTHENTICATION_REQUIRED
        elif soap_response and response.status_code < 500:
            status = ONVIFStatus.DETECTED
        elif response.status_code == 405:
            status = ONVIFStatus.DETECTED
        elif response.status_code == 404:
            status = ONVIFStatus.NOT_DETECTED
        else:
            status = ONVIFStatus.UNKNOWN
        evidence_text = " ".join(
            (
                normalized,
                response.headers.get("server", ""),
                response.headers.get("www-authenticate", ""),
            )
        )
        return ONVIFObservation(
            endpoint=endpoint,
            port=port,
            status=status,
            http_status=response.status_code,
            soap_response=soap_response,
            authentication_required=authentication_required,
            vendor_hints=match_vendor_signatures(evidence_text),
            latency_ms=response.latency_ms,
            evidence=tuple(
                item
                for item in (
                    f"ONVIF endpoint HTTP status: {response.status_code}",
                    "ONVIF SOAP signature observed" if soap_response else None,
                )
                if item
            ),
            confidence=(
                0.98
                if status
                in {
                    ONVIFStatus.DETECTED,
                    ONVIFStatus.AUTHENTICATION_REQUIRED,
                }
                else 0.5
            ),
        )


def _aggregate_status(
    observations: tuple[ONVIFObservation, ...],
) -> ONVIFStatus:
    statuses = {item.status for item in observations}
    for priority in (
        ONVIFStatus.DETECTED,
        ONVIFStatus.AUTHENTICATION_REQUIRED,
        ONVIFStatus.ERROR,
        ONVIFStatus.UNKNOWN,
        ONVIFStatus.NOT_DETECTED,
    ):
        if priority in statuses:
            return priority
    return ONVIFStatus.UNKNOWN
