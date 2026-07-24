"""Tests for deterministic TCP port discovery behavior."""

import errno
import unittest

from app.modules.iot.exceptions import (
    InvalidTargetError,
    PortScanConfigurationError,
)
from app.modules.iot.detectors.ports import PortDiscoveryEngine, PortScannerConfig
from app.modules.iot.models import PortState


class PortDiscoveryEngineTests(unittest.TestCase):
    def test_scan_classifies_and_sorts_results(self) -> None:
        results = {
            80: (0, 1.25),
            443: (errno.ECONNREFUSED, 0.5),
            554: (errno.ETIMEDOUT, 100.0),
        }

        def connector(target: str, port: int, timeout: float):
            self.assertEqual(target, "192.168.1.20")
            self.assertEqual(timeout, 0.25)
            return results[port]

        engine = PortDiscoveryEngine(
            PortScannerConfig(timeout_seconds=0.25, max_workers=2),
            connector=connector,
        )
        result = engine.scan("192.168.1.20", [554, 80, 443, 80])

        self.assertEqual(result.open_ports, (80,))
        self.assertEqual(result.scanned_port_count, 3)
        self.assertEqual(
            [observation.state for observation in result.observations],
            [PortState.OPEN, PortState.CLOSED, PortState.FILTERED],
        )

    def test_connector_exception_is_sanitized(self) -> None:
        def connector(target: str, port: int, timeout: float):
            raise OSError("sensitive operating system detail")

        result = PortDiscoveryEngine(connector=connector).scan("10.0.0.1", [80])

        self.assertEqual(result.observations[0].state, PortState.ERROR)
        self.assertEqual(result.observations[0].error, "OSError")
        self.assertNotIn("sensitive", result.model_dump_json())

    def test_rejects_ipv6_and_hostnames(self) -> None:
        engine = PortDiscoveryEngine()
        with self.assertRaises(InvalidTargetError):
            engine.scan("example.com", [80])
        with self.assertRaises(InvalidTargetError):
            engine.scan("::1", [80])

    def test_rejects_invalid_configuration_and_ports(self) -> None:
        with self.assertRaises(PortScanConfigurationError):
            PortScannerConfig(timeout_seconds=0)
        with self.assertRaises(PortScanConfigurationError):
            PortDiscoveryEngine().scan("127.0.0.1", [0])


if __name__ == "__main__":
    unittest.main()
