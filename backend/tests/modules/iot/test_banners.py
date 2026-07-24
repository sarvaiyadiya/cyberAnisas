"""Tests for bounded and sanitized banner fingerprinting."""

import socket
import unittest

from app.modules.iot.detectors.banners import (
    BannerCollectorConfig,
    BannerFingerprintEngine,
)
from app.modules.iot.exceptions import BannerConfigurationError


class BannerFingerprintEngineTests(unittest.TestCase):
    def test_collects_normalizes_and_matches_vendor(self) -> None:
        def receiver(target: str, port: int, timeout: float, max_bytes: int):
            self.assertEqual(target, "192.168.1.20")
            return b"\x00Hikvision-Webs\r\n Firmware V5.7\x1b"

        result = BannerFingerprintEngine(receiver=receiver).collect(
            "192.168.1.20",
            [8000],
        )
        observation = result.observations[0]

        self.assertTrue(observation.responded)
        self.assertEqual(
            observation.normalized_banner,
            "hikvision-webs firmware v5.7",
        )
        self.assertEqual(observation.vendor_hints, ("Hikvision",))
        self.assertNotIn("\x00", observation.banner)

    def test_bounds_banner_payload(self) -> None:
        def receiver(target: str, port: int, timeout: float, max_bytes: int):
            return b"A" * (max_bytes + 1)

        engine = BannerFingerprintEngine(
            BannerCollectorConfig(max_bytes=64),
            receiver=receiver,
        )
        observation = engine.collect("10.0.0.15", [23]).observations[0]

        self.assertEqual(observation.bytes_received, 64)
        self.assertEqual(len(observation.banner), 64)
        self.assertTrue(observation.truncated)

    def test_timeout_and_os_errors_are_sanitized(self) -> None:
        def timeout_receiver(
            target: str,
            port: int,
            timeout: float,
            max_bytes: int,
        ):
            if port == 22:
                raise socket.timeout()
            raise OSError("private operating system message")

        result = BannerFingerprintEngine(receiver=timeout_receiver).collect(
            "172.16.10.5",
            [22, 23],
        )

        self.assertEqual(result.observations[0].error, "timeout")
        self.assertEqual(result.observations[1].error, "OSError")
        self.assertNotIn("private operating", result.model_dump_json())

    def test_rejects_unsafe_configuration(self) -> None:
        with self.assertRaises(BannerConfigurationError):
            BannerCollectorConfig(max_bytes=1)
        with self.assertRaises(BannerConfigurationError):
            BannerCollectorConfig(timeout_seconds=11)

    def test_empty_open_port_set_is_valid(self) -> None:
        result = BannerFingerprintEngine().collect("127.0.0.1", [])
        self.assertEqual(result.observations, ())


if __name__ == "__main__":
    unittest.main()
