"""Tests for safe RTSP OPTIONS detection."""

import socket
import unittest

from app.modules.iot.detectors.rtsp import (
    RTSPDetectionEngine,
    RTSPProbeConfig,
    parse_rtsp_response,
)
from app.modules.iot.exceptions import RTSPConfigurationError


class RTSPDetectionEngineTests(unittest.TestCase):
    def test_parses_authenticated_hikvision_response(self) -> None:
        payload = (
            b"RTSP/1.0 401 Unauthorized\r\n"
            b"CSeq: 1\r\n"
            b"Server: Hikvision RTSP Server\r\n"
            b"Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
            b'WWW-Authenticate: Digest realm="camera"\r\n\r\n'
        )
        item = parse_rtsp_response(554, payload, latency_ms=8.5)

        self.assertTrue(item.detected)
        self.assertEqual(item.status_code, 401)
        self.assertTrue(item.authentication_required)
        self.assertEqual(item.authentication_scheme, "Digest")
        self.assertEqual(
            item.public_methods,
            ("DESCRIBE", "OPTIONS", "PLAY", "SETUP"),
        )
        self.assertEqual(item.vendor_hints, ("Hikvision",))

    def test_engine_only_probes_rtsp_ports(self) -> None:
        calls: list[int] = []

        def sender(target: str, port: int, timeout: float, max_bytes: int):
            calls.append(port)
            return b"RTSP/1.0 200 OK\r\nPublic: OPTIONS\r\n\r\n", 2.0

        result = RTSPDetectionEngine(sender=sender).detect(
            "192.168.1.20",
            [80, 554, 8554],
        )
        self.assertEqual(calls, [554, 8554])
        self.assertEqual(len(result.observations), 2)

    def test_invalid_response_is_not_detected(self) -> None:
        item = parse_rtsp_response(554, b"HTTP/1.1 200 OK\r\n\r\n", 1.0)
        self.assertFalse(item.detected)
        self.assertEqual(item.error, "invalid_rtsp_response")

    def test_timeout_is_sanitized(self) -> None:
        def sender(target: str, port: int, timeout: float, max_bytes: int):
            raise socket.timeout("private detail")

        item = RTSPDetectionEngine(sender=sender).detect(
            "10.0.0.15",
            [554],
        ).observations[0]
        self.assertEqual(item.error, "timeout")
        self.assertNotIn("private detail", item.model_dump_json())

    def test_rejects_unsafe_configuration(self) -> None:
        with self.assertRaises(RTSPConfigurationError):
            RTSPProbeConfig(max_bytes=100)


if __name__ == "__main__":
    unittest.main()
