"""Tests for deterministic vendor correlation."""

import unittest

from app.modules.iot.fingerprints.vendor import VendorFingerprintEngine
from app.modules.iot.models import (
    BannerDiscoveryResult,
    BannerObservation,
    HTTPFingerprintResult,
    HTTPObservation,
    PortDiscoveryResult,
    TLSFingerprintResult,
)


class VendorFingerprintEngineTests(unittest.TestCase):
    def test_correlates_hikvision_evidence(self) -> None:
        result = VendorFingerprintEngine().detect(
            ports=PortDiscoveryResult(
                target="192.168.1.20",
                open_ports=(80, 8000),
                scanned_port_count=2,
                duration_ms=1,
            ),
            banners=BannerDiscoveryResult(
                target="192.168.1.20",
                observations=(
                    BannerObservation(
                        port=8000,
                        banner="Hikvision-Webs",
                        normalized_banner="hikvision-webs",
                        responded=True,
                    ),
                ),
                duration_ms=1,
            ),
            http=HTTPFingerprintResult(
                target="192.168.1.20",
                observations=(
                    HTTPObservation(
                        url="http://192.168.1.20/",
                        port=80,
                        scheme="http",
                        path="/",
                        status_code=200,
                        title="Hikvision Camera",
                    ),
                ),
                duration_ms=1,
            ),
            tls=TLSFingerprintResult(
                target="192.168.1.20",
                duration_ms=0,
            ),
        )
        self.assertEqual(result.vendor, "Hikvision")
        self.assertGreaterEqual(result.confidence, 80)
        self.assertGreaterEqual(len(result.matching_evidence), 2)

    def test_returns_unknown_for_weak_port_hint(self) -> None:
        result = VendorFingerprintEngine().detect(
            ports=PortDiscoveryResult(
                target="10.0.0.15",
                open_ports=(8000,),
                scanned_port_count=1,
                duration_ms=1,
            ),
            banners=BannerDiscoveryResult(
                target="10.0.0.15",
                duration_ms=0,
            ),
            http=HTTPFingerprintResult(
                target="10.0.0.15",
                duration_ms=0,
            ),
            tls=TLSFingerprintResult(
                target="10.0.0.15",
                duration_ms=0,
            ),
        )
        self.assertEqual(result.vendor, "Unknown")
        self.assertEqual(result.confidence, 0)


if __name__ == "__main__":
    unittest.main()
