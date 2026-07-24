"""Conservative model and firmware extraction from observed text."""

from __future__ import annotations

import re

from app.modules.iot.models import (
    BannerDiscoveryResult,
    FirmwareDetectionResult,
    HTTPFingerprintResult,
)

_FIRMWARE_PATTERN = re.compile(
    r"\bfirmware(?:\s+version)?\s*[:=\-]?\s*v?([0-9][a-z0-9._-]{1,31})",
    re.I,
)
_MODEL_PATTERN = re.compile(
    r"\bmodel(?:\s+(?:name|number|no\.?))?\s*[:=\-]\s*"
    r"([a-z0-9][a-z0-9._/-]{1,63})",
    re.I,
)


class FirmwareDetectionEngine:
    """Extract identifiers only when explicitly labelled in evidence."""

    def detect(
        self,
        banners: BannerDiscoveryResult,
        http: HTTPFingerprintResult,
    ) -> FirmwareDetectionResult:
        sources: list[tuple[str, str]] = []
        for item in banners.observations:
            if item.banner:
                sources.append((f"banner on port {item.port}", item.banner))
        for item in http.observations:
            for label, value in (
                ("HTTP title", item.title),
                ("HTTP server", item.server),
                ("meta generator", item.meta_generator),
            ):
                if value:
                    sources.append((f"{label} on port {item.port}", value))

        firmware = "Unknown"
        model = "Unknown"
        evidence: list[str] = []
        for source, text in sources:
            if firmware == "Unknown" and (match := _FIRMWARE_PATTERN.search(text)):
                firmware = match.group(1)
                evidence.append(f"Firmware explicitly labelled in {source}")
            if model == "Unknown" and (match := _MODEL_PATTERN.search(text)):
                model = match.group(1)
                evidence.append(f"Model explicitly labelled in {source}")

        confidence = (50 if firmware != "Unknown" else 0) + (
            50 if model != "Unknown" else 0
        )
        return FirmwareDetectionResult(
            model=model,
            firmware=firmware,
            confidence=confidence,
            evidence=tuple(evidence),
        )
