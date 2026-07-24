"""Tests for safe ONVIF endpoint detection."""

import unittest

from app.modules.iot.clients.device_http import DeviceHTTPResponse
from app.modules.iot.detectors.onvif import ONVIFDetectionEngine
from app.modules.iot.models import ONVIFStatus


class ONVIFDetectionEngineTests(unittest.TestCase):
    def test_detects_soap_response_and_vendor(self) -> None:
        fetcher = lambda url: DeviceHTTPResponse(
            url=url,
            status_code=200,
            headers={"server": "Hikvision-Webs"},
            body=b"<SOAP-ENV:Envelope>http://www.onvif.org/</SOAP-ENV:Envelope>",
            truncated=False,
            latency_ms=2,
        )
        result = ONVIFDetectionEngine(fetcher=fetcher).detect(
            "192.168.1.20",
            [80],
        )
        self.assertEqual(result.status, ONVIFStatus.DETECTED)
        self.assertTrue(result.observations[0].soap_response)
        self.assertEqual(result.observations[0].vendor_hints, ("Hikvision",))

    def test_reports_authentication_required(self) -> None:
        fetcher = lambda url: DeviceHTTPResponse(
            url=url,
            status_code=401,
            headers={"www-authenticate": "Digest"},
            body=b"",
            truncated=False,
        )
        result = ONVIFDetectionEngine(fetcher=fetcher).detect(
            "10.0.0.15",
            [8080],
        )
        self.assertEqual(result.status, ONVIFStatus.AUTHENTICATION_REQUIRED)
        self.assertTrue(result.observations[0].authentication_required)

    def test_no_web_ports_returns_unknown_without_request(self) -> None:
        result = ONVIFDetectionEngine(
            fetcher=lambda url: self.fail("must not request")
        ).detect("10.0.0.15", [554])
        self.assertEqual(result.status, ONVIFStatus.UNKNOWN)
        self.assertEqual(result.observations, ())


if __name__ == "__main__":
    unittest.main()
