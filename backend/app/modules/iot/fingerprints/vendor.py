"""Rule-based vendor correlation across Module 4 observations."""

from __future__ import annotations

from collections import defaultdict

from app.core.config import settings
from app.modules.iot.exceptions import VendorConfigurationError
from app.modules.iot.fingerprints.signatures import (
    VENDOR_PATH_HINTS,
    VENDOR_PORT_HINTS,
    match_vendor_signatures,
)
from app.modules.iot.models import (
    BannerDiscoveryResult,
    HTTPFingerprintResult,
    PortDiscoveryResult,
    RTSPDetectionResult,
    TLSFingerprintResult,
    VendorAlternative,
    VendorDetectionResult,
)


class VendorFingerprintEngine:
    """Produce a conservative vendor result from corroborated evidence."""

    def __init__(
        self,
        minimum_confidence: int = settings.IOT_VENDOR_MIN_CONFIDENCE,
    ) -> None:
        if not 0 <= minimum_confidence <= 100:
            raise VendorConfigurationError(
                "Vendor minimum confidence must be between 0 and 100"
            )
        self._minimum_confidence = minimum_confidence

    def detect(
        self,
        ports: PortDiscoveryResult,
        banners: BannerDiscoveryResult,
        http: HTTPFingerprintResult,
        tls: TLSFingerprintResult,
        rtsp: RTSPDetectionResult | None = None,
    ) -> VendorDetectionResult:
        """Score vendor candidates without inventing missing evidence."""
        scores: dict[str, int] = defaultdict(int)
        evidence: dict[str, list[str]] = defaultdict(list)

        for port in ports.open_ports:
            hint = VENDOR_PORT_HINTS.get(port)
            if hint:
                vendor, weight = hint
                self._add(
                    scores,
                    evidence,
                    vendor,
                    weight,
                    f"vendor-associated TCP port {port} is open",
                )

        for item in banners.observations:
            if not item.normalized_banner:
                continue
            for vendor in match_vendor_signatures(item.normalized_banner):
                self._add(
                    scores,
                    evidence,
                    vendor,
                    40,
                    f"service banner on port {item.port} matched {vendor}",
                )

        for item in http.observations:
            if item.status_code is None:
                continue
            text = " ".join(
                value
                for value in (
                    item.server,
                    item.x_powered_by,
                    item.title,
                    item.meta_generator,
                    " ".join(item.cookie_names),
                )
                if value
            )
            for vendor in match_vendor_signatures(text):
                self._add(
                    scores,
                    evidence,
                    vendor,
                    35,
                    f"HTTP evidence on port {item.port} matched {vendor}",
                )
            if item.status_code in {401, 403}:
                for path, vendor, weight in VENDOR_PATH_HINTS:
                    if item.path == path:
                        self._add(
                            scores,
                            evidence,
                            vendor,
                            weight,
                            f"HTTP path {path} returned {item.status_code}",
                        )

        for item in tls.observations:
            for vendor in item.vendor_hints:
                self._add(
                    scores,
                    evidence,
                    vendor,
                    30,
                    f"TLS certificate on port {item.port} matched {vendor}",
                )

        for item in rtsp.observations if rtsp else ():
            for vendor in item.vendor_hints:
                self._add(
                    scores,
                    evidence,
                    vendor,
                    40,
                    f"RTSP response on port {item.port} matched {vendor}",
                )

        ranked = sorted(
            scores.items(),
            key=lambda candidate: (-candidate[1], candidate[0]),
        )
        if not ranked or ranked[0][1] < self._minimum_confidence:
            return VendorDetectionResult()

        primary_vendor, primary_score = ranked[0]
        alternatives = tuple(
            VendorAlternative(vendor=vendor, confidence=min(score, 100))
            for vendor, score in ranked[1:4]
            if score >= self._minimum_confidence
        )
        return VendorDetectionResult(
            vendor=primary_vendor,
            confidence=min(primary_score, 100),
            matching_evidence=tuple(evidence[primary_vendor]),
            alternative_vendors=alternatives,
        )

    @staticmethod
    def _add(
        scores: dict[str, int],
        evidence: dict[str, list[str]],
        vendor: str,
        weight: int,
        detail: str,
    ) -> None:
        """Add each distinct evidence statement only once."""
        if detail in evidence[vendor]:
            return
        scores[vendor] += weight
        evidence[vendor].append(detail)
