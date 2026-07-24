"""Tests for deterministic Module 4 risk assessment."""

import unittest

from app.modules.iot.models import (
    HTTPFingerprintResult,
    HTTPObservation,
    PortDiscoveryResult,
    RTSPDetectionResult,
    RTSPObservation,
    TLSFingerprintResult,
    TLSObservation,
    VendorDetectionResult,
)
from app.modules.iot.risk import RiskAssessmentEngine


class RiskAssessmentEngineTests(unittest.TestCase):
    def test_scores_multiple_observed_high_risk_conditions(self) -> None:
        result = RiskAssessmentEngine().assess(
            ports=PortDiscoveryResult(
                target="203.0.113.20",
                open_ports=(21, 23, 80, 554),
                scanned_port_count=4,
                duration_ms=1,
            ),
            http=HTTPFingerprintResult(
                target="203.0.113.20",
                observations=(
                    HTTPObservation(
                        url="http://203.0.113.20/",
                        port=80,
                        scheme="http",
                        path="/",
                        status_code=200,
                        missing_security_headers=(
                            "content-security-policy",
                            "x-frame-options",
                        ),
                    ),
                ),
                duration_ms=1,
            ),
            tls=TLSFingerprintResult(
                target="203.0.113.20",
                observations=(),
                duration_ms=0,
            ),
            rtsp=RTSPDetectionResult(
                target="203.0.113.20",
                observations=(
                    RTSPObservation(
                        port=554,
                        detected=True,
                        status_code=200,
                        authentication_required=False,
                    ),
                ),
                duration_ms=1,
            ),
            vendor=VendorDetectionResult(
                vendor="Hikvision",
                confidence=80,
            ),
        )
        self.assertEqual(result.level, "Critical")
        self.assertGreaterEqual(result.score, 75)
        self.assertTrue(
            any("Unauthenticated RTSP" in factor.name for factor in result.factors)
        )

    def test_no_observed_risks_returns_low(self) -> None:
        result = RiskAssessmentEngine().assess(
            ports=PortDiscoveryResult(
                target="10.0.0.15",
                open_ports=(22,),
                scanned_port_count=1,
                duration_ms=1,
            ),
            http=HTTPFingerprintResult(
                target="10.0.0.15",
                duration_ms=0,
            ),
            tls=TLSFingerprintResult(
                target="10.0.0.15",
                duration_ms=0,
            ),
            rtsp=RTSPDetectionResult(
                target="10.0.0.15",
                duration_ms=0,
            ),
            vendor=VendorDetectionResult(),
        )
        self.assertEqual(result.score, 0)
        self.assertEqual(result.level, "Low")


if __name__ == "__main__":
    unittest.main()
