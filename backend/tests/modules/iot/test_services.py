"""Tests for evidence-based service detection."""

import unittest

from app.modules.iot.detectors.services import ServiceDetectionEngine
from app.modules.iot.models import (
    BannerDiscoveryResult,
    BannerObservation,
    HTTPFingerprintResult,
    HTTPObservation,
)


class ServiceDetectionEngineTests(unittest.TestCase):
    def test_identifies_http_product_from_response(self) -> None:
        result = ServiceDetectionEngine().detect(
            target="192.168.1.20",
            open_ports=[443],
            banners=BannerDiscoveryResult(
                target="192.168.1.20",
                observations=(),
                duration_ms=0,
            ),
            http=HTTPFingerprintResult(
                target="192.168.1.20",
                observations=(
                    HTTPObservation(
                        url="https://192.168.1.20/",
                        port=443,
                        scheme="https",
                        path="/",
                        status_code=200,
                        server="nginx",
                    ),
                ),
                duration_ms=1,
            ),
        )
        item = result.observations[0]
        self.assertEqual(item.service, "HTTPS")
        self.assertEqual(item.product, "nginx")
        self.assertEqual(item.confidence, 95)

    def test_identifies_ssh_from_banner(self) -> None:
        result = ServiceDetectionEngine().detect(
            target="10.0.0.15",
            open_ports=[22],
            banners=BannerDiscoveryResult(
                target="10.0.0.15",
                observations=(
                    BannerObservation(
                        port=22,
                        banner="SSH-2.0-OpenSSH_9.2",
                        normalized_banner="ssh-2.0-openssh_9.2",
                        responded=True,
                    ),
                ),
                duration_ms=1,
            ),
            http=HTTPFingerprintResult(
                target="10.0.0.15",
                observations=(),
                duration_ms=0,
            ),
        )
        item = result.observations[0]
        self.assertEqual(item.service, "SSH")
        self.assertEqual(item.product, "OpenSSH")
        self.assertGreaterEqual(item.confidence, 90)


if __name__ == "__main__":
    unittest.main()
