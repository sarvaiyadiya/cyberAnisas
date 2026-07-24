"""Weighted device classification from correlated Module 4 evidence."""

from __future__ import annotations

from collections import defaultdict

from app.core.config import settings
from app.modules.iot.models import (
    BannerDiscoveryResult,
    ClassificationAlternative,
    DeviceClassificationResult,
    HTTPFingerprintResult,
    ONVIFDetectionResult,
    ONVIFStatus,
    RTSPDetectionResult,
    ServiceDetectionResult,
    VendorDetectionResult,
)

SURVEILLANCE_VENDORS = {
    "Hikvision", "Dahua", "Axis", "Hanwha", "Uniview", "Bosch", "Vivotek",
}


class DeviceClassificationEngine:
    """Classify only when multiple or explicit high-quality signals agree."""

    def __init__(
        self,
        minimum_confidence: int = settings.IOT_DEVICE_MIN_CONFIDENCE,
    ) -> None:
        if not 0 <= minimum_confidence <= 100:
            raise ValueError("Device confidence threshold must be 0-100")
        self._minimum_confidence = minimum_confidence

    def classify(
        self,
        services: ServiceDetectionResult,
        banners: BannerDiscoveryResult,
        http: HTTPFingerprintResult,
        rtsp: RTSPDetectionResult,
        onvif: ONVIFDetectionResult,
        vendor: VendorDetectionResult,
    ) -> DeviceClassificationResult:
        scores: dict[str, int] = defaultdict(int)
        evidence: dict[str, list[str]] = defaultdict(list)

        if any(item.detected for item in rtsp.observations):
            self._add(scores, evidence, "IP Camera", 25, "RTSP responded")
            for device_type in ("NVR", "DVR", "XVR", "Media Server"):
                self._add(scores, evidence, device_type, 15, "RTSP responded")
        if onvif.status in {
            ONVIFStatus.DETECTED,
            ONVIFStatus.AUTHENTICATION_REQUIRED,
        }:
            self._add(scores, evidence, "IP Camera", 35, "ONVIF endpoint detected")
            for device_type in ("NVR", "DVR", "XVR"):
                self._add(
                    scores, evidence, device_type, 20, "ONVIF endpoint detected"
                )

        if vendor.vendor in SURVEILLANCE_VENDORS:
            self._add(
                scores, evidence, "IP Camera", 25,
                f"Surveillance vendor evidence: {vendor.vendor}",
            )
        if vendor.vendor in {"Synology", "QNAP"}:
            self._add(scores, evidence, "NAS", 50, f"NAS vendor: {vendor.vendor}")
        if vendor.vendor in {"MikroTik", "TP-Link", "Netgear", "Ubiquiti"}:
            self._add(
                scores, evidence, "Router", 40, f"Network vendor: {vendor.vendor}"
            )
        if vendor.vendor in {"Canon", "HP", "Epson"}:
            self._add(
                scores, evidence, "Printer", 40, f"Printer vendor: {vendor.vendor}"
            )

        service_names = {item.service for item in services.observations}
        if service_names.intersection({"IPP", "LPD"}):
            self._add(scores, evidence, "Printer", 50, "Printing service detected")
        if "SMB" in service_names:
            self._add(scores, evidence, "NAS", 20, "SMB service detected")
        if "DNS" in service_names:
            self._add(scores, evidence, "Router", 15, "DNS service detected")

        text = _combined_text(banners, http)
        rules = (
            ("xvr", "XVR", 65), ("nvr", "NVR", 65), ("dvr", "DVR", 65),
            ("ip camera", "IP Camera", 50),
            ("network camera", "IP Camera", 50),
            ("wireless access point", "Wireless Access Point", 60),
            ("access point", "Wireless Access Point", 50),
            ("router", "Router", 50), ("printer", "Printer", 50),
            ("door access", "Door Access Controller", 60),
            ("attendance", "Attendance Device", 60),
            ("smart tv", "Smart TV", 60), ("iot hub", "IoT Hub", 60),
        )
        for signature, device_type, weight in rules:
            if signature in text:
                self._add(
                    scores, evidence, device_type, weight,
                    f"Explicit text signature: {signature}",
                )

        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        if not ranked or ranked[0][1] < self._minimum_confidence:
            return DeviceClassificationResult()
        primary, score = ranked[0]
        alternatives = tuple(
            ClassificationAlternative(
                device_type=device_type,
                confidence=min(candidate_score, 100),
            )
            for device_type, candidate_score in ranked[1:4]
            if candidate_score >= 30
        )
        primary_evidence = tuple(evidence[primary])
        return DeviceClassificationResult(
            device_type=primary,
            confidence=min(score, 100),
            alternatives=alternatives,
            evidence=primary_evidence,
            explanation=(
                f"{primary} selected from {len(primary_evidence)} "
                "independent or explicit evidence signal(s)."
            ),
        )

    @staticmethod
    def _add(scores, evidence, device_type, weight, detail) -> None:
        if detail not in evidence[device_type]:
            scores[device_type] += weight
            evidence[device_type].append(detail)


def _combined_text(
    banners: BannerDiscoveryResult,
    http: HTTPFingerprintResult,
) -> str:
    values = [
        item.normalized_banner
        for item in banners.observations
        if item.normalized_banner
    ]
    for item in http.observations:
        values.extend(
            value.lower()
            for value in (item.title, item.server, item.meta_generator)
            if value
        )
    return " ".join(values)
