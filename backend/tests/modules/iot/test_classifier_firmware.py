"""Tests for device classification and firmware extraction."""

import unittest

from app.modules.iot.fingerprints.classifier import DeviceClassificationEngine
from app.modules.iot.fingerprints.firmware import FirmwareDetectionEngine
from app.modules.iot.models import (
    BannerDiscoveryResult,
    BannerObservation,
    HTTPFingerprintResult,
    ONVIFDetectionResult,
    ONVIFStatus,
    RTSPDetectionResult,
    RTSPObservation,
    ServiceDetectionResult,
    VendorDetectionResult,
)


class ClassificationAndFirmwareTests(unittest.TestCase):
    def test_classifies_camera_from_correlated_protocols(self) -> None:
        result = DeviceClassificationEngine().classify(
            services=ServiceDetectionResult(target="10.0.0.15", duration_ms=0),
            banners=BannerDiscoveryResult(target="10.0.0.15", duration_ms=0),
            http=HTTPFingerprintResult(target="10.0.0.15", duration_ms=0),
            rtsp=RTSPDetectionResult(
                target="10.0.0.15",
                observations=(RTSPObservation(port=554, detected=True),),
                duration_ms=1,
            ),
            onvif=ONVIFDetectionResult(
                target="10.0.0.15",
                status=ONVIFStatus.DETECTED,
                duration_ms=1,
            ),
            vendor=VendorDetectionResult(),
        )
        self.assertEqual(result.device_type, "IP Camera")
        self.assertGreaterEqual(result.confidence, 60)

    def test_single_rtsp_signal_remains_unknown(self) -> None:
        result = DeviceClassificationEngine().classify(
            services=ServiceDetectionResult(target="10.0.0.15", duration_ms=0),
            banners=BannerDiscoveryResult(target="10.0.0.15", duration_ms=0),
            http=HTTPFingerprintResult(target="10.0.0.15", duration_ms=0),
            rtsp=RTSPDetectionResult(
                target="10.0.0.15",
                observations=(RTSPObservation(port=554, detected=True),),
                duration_ms=1,
            ),
            onvif=ONVIFDetectionResult(target="10.0.0.15", duration_ms=0),
            vendor=VendorDetectionResult(),
        )
        self.assertEqual(result.device_type, "Unknown")

    def test_extracts_only_explicit_firmware_and_model(self) -> None:
        result = FirmwareDetectionEngine().detect(
            banners=BannerDiscoveryResult(
                target="10.0.0.15",
                observations=(
                    BannerObservation(
                        port=80,
                        banner="Model: DS-2CD2043 Firmware V5.7.12",
                        responded=True,
                    ),
                ),
                duration_ms=1,
            ),
            http=HTTPFingerprintResult(target="10.0.0.15", duration_ms=0),
        )
        self.assertEqual(result.model, "DS-2CD2043")
        self.assertEqual(result.firmware, "5.7.12")
        self.assertEqual(result.confidence, 100)


if __name__ == "__main__":
    unittest.main()
