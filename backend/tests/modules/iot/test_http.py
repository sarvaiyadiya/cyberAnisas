"""Tests for HTTP fingerprint extraction and safety controls."""

import hashlib
import unittest

import requests

from app.modules.iot.clients.device_http import DeviceHTTPResponse
from app.modules.iot.detectors.http import HTTPFingerprintEngine


class HTTPFingerprintEngineTests(unittest.TestCase):
    def test_extracts_page_evidence(self) -> None:
        body = b"""<html><head><title>Hikvision IP Camera</title>
        <meta name="generator" content="Hikvision-Webs"></head>
        <body>Username <input type="password">Login</body></html>"""

        def fetcher(url: str) -> DeviceHTTPResponse:
            return DeviceHTTPResponse(
                url=url, status_code=401,
                headers={
                    "content-type": "text/html", "server": "Hikvision-Webs",
                    "x-powered-by": "PHP/8.2",
                    "x-frame-options": "DENY",
                    "www-authenticate": 'Digest realm="camera"',
                    "set-cookie": "session=secret; HttpOnly",
                },
                body=body, truncated=False,
            )

        item = HTTPFingerprintEngine(fetcher=fetcher).collect(
            "192.168.1.20", [80, 554], paths=["/"]
        ).observations[0]
        self.assertEqual(item.title, "Hikvision IP Camera")
        self.assertEqual(item.meta_generator, "Hikvision-Webs")
        self.assertEqual(item.cookie_names, ("session",))
        self.assertIn("password", item.login_markers)
        self.assertEqual(item.vendor_hints, ("Hikvision",))
        self.assertEqual(item.x_powered_by, "PHP/8.2")
        self.assertIn("PHP", item.technologies)
        self.assertEqual(item.security_headers["x-frame-options"], "DENY")
        self.assertNotIn("set-cookie", item.headers)
        self.assertNotIn("secret", item.model_dump_json())

    def test_hashes_favicon_without_exposing_body(self) -> None:
        icon = b"\x00\x01camera-icon"
        fetcher = lambda url: DeviceHTTPResponse(
            url=url, status_code=200, headers={"content-type": "image/x-icon"},
            body=icon, truncated=False,
        )
        item = HTTPFingerprintEngine(fetcher=fetcher).collect(
            "10.0.0.15", [8080], paths=["/favicon.ico"]
        ).observations[0]
        self.assertEqual(item.favicon_sha256, hashlib.sha256(icon).hexdigest())

    def test_withholds_external_redirect(self) -> None:
        fetcher = lambda url: DeviceHTTPResponse(
            url=url, status_code=302,
            headers={"location": "http://169.254.169.254/latest/meta-data"},
            body=b"", truncated=False,
        )
        item = HTTPFingerprintEngine(fetcher=fetcher).collect(
            "10.0.0.15", [80], paths=["/"]
        ).observations[0]
        self.assertEqual(item.redirect_location, "[external redirect withheld]")

    def test_sanitizes_request_failures(self) -> None:
        def fetcher(url: str) -> DeviceHTTPResponse:
            raise requests.ConnectionError("private network error details")

        item = HTTPFingerprintEngine(fetcher=fetcher).collect(
            "172.16.10.5", [443], paths=["/"]
        ).observations[0]
        self.assertEqual(item.error, "ConnectionError")
        self.assertNotIn("private network", item.model_dump_json())

    def test_ignores_non_http_ports(self) -> None:
        result = HTTPFingerprintEngine(
            fetcher=lambda url: self.fail("fetcher should not be called")
        ).collect("127.0.0.1", [22, 554])
        self.assertEqual(result.observations, ())


if __name__ == "__main__":
    unittest.main()
