"""Evidence-based TCP service identification for Module 4."""

from __future__ import annotations

import time
from collections.abc import Iterable

from app.modules.iot.fingerprints.signatures import SERVICE_PRODUCT_SIGNATURES
from app.modules.iot.models import (
    BannerDiscoveryResult,
    HTTPFingerprintResult,
    RTSPDetectionResult,
    ServiceDetectionResult,
    ServiceObservation,
)
from app.modules.iot.utils import normalize_ports, validate_ipv4

PORT_SERVICE_HINTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    81: "HTTP",
    82: "HTTP",
    83: "HTTP",
    84: "HTTP",
    85: "HTTP",
    88: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NETBIOS",
    443: "HTTPS",
    445: "SMB",
    515: "LPD",
    554: "RTSP",
    631: "IPP",
    8080: "HTTP",
    8081: "HTTP",
    8088: "HTTP",
    8443: "HTTPS",
    8554: "RTSP",
    8888: "HTTP",
    37777: "DAHUA-DHIP",
}


class ServiceDetectionEngine:
    """Correlate port hints with collected banner and HTTP evidence."""

    def detect(
        self,
        target: str,
        open_ports: Iterable[int],
        banners: BannerDiscoveryResult,
        http: HTTPFingerprintResult,
        rtsp: RTSPDetectionResult | None = None,
    ) -> ServiceDetectionResult:
        """Return one normalized service observation per open port."""
        canonical_target = str(validate_ipv4(target))
        requested_ports = tuple(open_ports)
        if not requested_ports:
            return ServiceDetectionResult(
                target=canonical_target,
                observations=(),
                duration_ms=0,
            )
        ports = normalize_ports(requested_ports)
        started = time.perf_counter()
        observations = tuple(
            self._identify(port, banners, http, rtsp) for port in ports
        )
        return ServiceDetectionResult(
            target=canonical_target,
            observations=observations,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _identify(
        self,
        port: int,
        banners: BannerDiscoveryResult,
        http: HTTPFingerprintResult,
        rtsp: RTSPDetectionResult | None,
    ) -> ServiceObservation:
        service = PORT_SERVICE_HINTS.get(port, "UNKNOWN")
        confidence = 35 if service != "UNKNOWN" else 10
        product: str | None = None
        evidence = [f"TCP port {port} is open"]

        http_items = [
            item
            for item in http.observations
            if item.port == port and item.status_code is not None
        ]
        if http_items:
            service = "HTTPS" if http_items[0].scheme == "https" else "HTTP"
            confidence = 95
            evidence.append(
                f"{service} response status {http_items[0].status_code}"
            )
            product = next(
                (item.server for item in http_items if item.server),
                None,
            )

        banner_item = next(
            (
                item
                for item in banners.observations
                if item.port == port and item.normalized_banner
            ),
            None,
        )
        if banner_item:
            evidence.append("Application banner received")
            for signature, detected_service, detected_product in (
                SERVICE_PRODUCT_SIGNATURES
            ):
                if signature in banner_item.normalized_banner:
                    service = (
                        "HTTPS"
                        if service == "HTTPS" and detected_service == "HTTP"
                        else detected_service
                    )
                    product = product or detected_product
                    confidence = max(confidence, 90)
                    break

        rtsp_item = next(
            (
                item
                for item in (rtsp.observations if rtsp else ())
                if item.port == port and item.detected
            ),
            None,
        )
        if rtsp_item:
            service = "RTSP"
            product = product or rtsp_item.server
            confidence = 95
            evidence.append(
                f"RTSP response status {rtsp_item.status_code}"
            )

        if product:
            evidence.append(f"Product evidence: {product}")
        return ServiceObservation(
            port=port,
            service=service,
            product=product,
            confidence=confidence,
            evidence=tuple(evidence),
        )
