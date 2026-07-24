"""Tests for concise evidence-grounded summary generation."""

import unittest

from app.modules.iot.models import (
    RiskAssessmentResult,
    RTSPDetectionResult,
    RTSPObservation,
    ServiceDetectionResult,
    ServiceObservation,
    TLSFingerprintResult,
    TLSObservation,
    VendorDetectionResult,
)
from app.modules.iot.summary import SecuritySummaryEngine


class SecuritySummaryEngineTests(unittest.TestCase):
    def test_generates_bounded_factual_summary(self) -> None:
        result = SecuritySummaryEngine().generate(
            target="192.168.1.20",
            services=ServiceDetectionResult(
                target="192.168.1.20",
                observations=(
                    ServiceObservation(
                        port=554,
                        service="RTSP",
                        confidence=95,
                    ),
                ),
                duration_ms=1,
            ),
            vendor=VendorDetectionResult(
                vendor="Hikvision",
                confidence=80,
            ),
            tls=TLSFingerprintResult(
                target="192.168.1.20",
                observations=(
                    TLSObservation(
                        port=443,
                        security_issues=("Certificate validation failed",),
                    ),
                ),
                duration_ms=1,
            ),
            rtsp=RTSPDetectionResult(
                target="192.168.1.20",
                observations=(
                    RTSPObservation(
                        port=554,
                        detected=True,
                        status_code=200,
                    ),
                ),
                duration_ms=1,
            ),
            risk=RiskAssessmentResult(
                score=60,
                level="High",
                assessment_confidence=90,
                recommendations=("Restrict RTSP access.",),
            ),
        )
        self.assertLessEqual(result.word_count, 100)
        self.assertIn("Hikvision", result.text)
        self.assertIn("High (60/100)", result.text)
        self.assertIn("without an authentication challenge", result.text)

    def test_unknown_evidence_does_not_invent_identity(self) -> None:
        result = SecuritySummaryEngine().generate(
            target="10.0.0.15",
            services=ServiceDetectionResult(
                target="10.0.0.15",
                duration_ms=0,
            ),
            vendor=VendorDetectionResult(),
            tls=TLSFingerprintResult(target="10.0.0.15", duration_ms=0),
            rtsp=RTSPDetectionResult(target="10.0.0.15", duration_ms=0),
            risk=RiskAssessmentResult(
                score=0,
                level="Low",
                assessment_confidence=40,
            ),
        )
        self.assertIn("vendor could not be determined", result.text)
        self.assertNotIn("camera", result.text.lower())
        self.assertLessEqual(result.word_count, 100)


if __name__ == "__main__":
    unittest.main()
