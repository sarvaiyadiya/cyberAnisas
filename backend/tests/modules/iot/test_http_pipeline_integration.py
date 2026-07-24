"""Production API integration tests for the Module 4 web pipeline."""

import errno
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.modules.iot.clients.device_http import DeviceHTTPResponse
from app.modules.iot.detectors.banners import BannerFingerprintEngine
from app.modules.iot.detectors.http import HTTPFingerprintEngine
from app.modules.iot.detectors.ports import PortDiscoveryEngine
from app.modules.iot.detectors.rtsp import RTSPDetectionEngine
from app.modules.iot.detectors.onvif import ONVIFDetectionEngine
from app.modules.iot.detectors.tls import (
    TLSFingerprintEngine,
    TLSHandshakeEvidence,
)
from app.modules.iot.service import IoTFingerprintingService, get_iot_service
from app.modules.iot.models import CVEIntelligenceResult


class FakeCVEClient:
    """Keep API integration deterministic and independent of NVD uptime."""

    def lookup(
        self,
        vendor: str,
        model: str,
        firmware: str,
    ) -> CVEIntelligenceResult:
        return CVEIntelligenceResult(
            lookup_attempted=True,
            source_available=True,
            query=vendor,
        )


def certificate_der() -> bytes:
    """Build an in-memory certificate for concrete TLS API integration."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "camera.local")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1234)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def tls_prober(target: str, port: int, timeout: float) -> TLSHandshakeEvidence:
    """Return deterministic handshake evidence to the real TLS detector."""
    return TLSHandshakeEvidence(
        tls_version="TLSv1.3",
        certificate_der=certificate_der(),
        validated=False,
        validation_error="self-signed certificate",
        latency_ms=3.0,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
    )


class HTTPPipelineIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.http_urls: list[str] = []
        self.open_ports = {80}

        def connector(target: str, port: int, timeout: float):
            return (
                (0, 1.0)
                if port in self.open_ports
                else (errno.ECONNREFUSED, 1.0)
            )

        def fetcher(url: str) -> DeviceHTTPResponse:
            self.http_urls.append(url)
            if url.endswith("/onvif/device_service"):
                return DeviceHTTPResponse(
                    url=url,
                    status_code=200,
                    headers={"server": "Hikvision-Webs"},
                    body=(
                        b"<SOAP-ENV:Envelope>"
                        b"http://www.onvif.org/"
                        b"</SOAP-ENV:Envelope>"
                    ),
                    truncated=False,
                    latency_ms=2.0,
                )
            return DeviceHTTPResponse(
                url=url,
                status_code=200,
                headers={
                    "content-type": "text/html",
                    "server": "nginx",
                    "x-powered-by": "PHP/8.2",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                },
                body=b"<html><title>Hikvision Camera Console</title></html>",
                truncated=False,
                latency_ms=2.5,
            )

        service = IoTFingerprintingService(
            port_engine=PortDiscoveryEngine(connector=connector),
            http_engine=HTTPFingerprintEngine(fetcher=fetcher),
            banner_engine=BannerFingerprintEngine(
                receiver=lambda target, port, timeout, max_bytes: (
                    b"nginx/1.26"
                )
            ),
            tls_engine=TLSFingerprintEngine(prober=tls_prober),
            rtsp_engine=RTSPDetectionEngine(
                sender=lambda target, port, timeout, max_bytes: (
                    b"RTSP/1.0 401 Unauthorized\r\n"
                    b"Server: Hikvision RTSP Server\r\n"
                    b'WWW-Authenticate: Digest realm="camera"\r\n\r\n',
                    2.0,
                )
            ),
            onvif_engine=ONVIFDetectionEngine(fetcher=fetcher),
            cve_client=FakeCVEClient(),
        )
        app.dependency_overrides[get_iot_service] = lambda: service
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_api_executes_port_discovery_then_http(self) -> None:
        response = self.client.post(
            "/api/v1/iot/fingerprint",
            json={"ip": "192.168.1.20", "ports": [80, 554]},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertIsNone(payload["error"])
        self.assertIn("tcp-connect", payload["metadata"]["sources_used"])
        self.assertGreaterEqual(payload["metadata"]["confidence_score"], 0.0)
        self.assertGreaterEqual(payload["metadata"]["lookup_duration_ms"], 0)
        self.assertTrue(
            {
                "asn",
                "bgp",
                "ripe",
                "rpki",
                "peeringdb",
                "isp_profile",
            }.isdisjoint(payload["data"])
        )
        self.assertEqual(payload["data"]["port_discovery"]["open_ports"], [80])
        observations = payload["data"]["http"]["observations"]
        self.assertGreater(len(observations), 0)
        self.assertEqual(observations[0]["status_code"], 200)
        self.assertEqual(observations[0]["server"], "nginx")
        self.assertEqual(observations[0]["title"], "Hikvision Camera Console")
        self.assertEqual(observations[0]["x_powered_by"], "PHP/8.2")
        self.assertEqual(
            observations[0]["detection_method"],
            "HTTP Service Enumeration",
        )
        self.assertEqual(observations[0]["source"], "http-fingerprint-engine")
        self.assertGreater(observations[0]["confidence"], 0.0)
        self.assertTrue(observations[0]["evidence"])
        self.assertIn("PHP", observations[0]["technologies"])
        self.assertEqual(
            observations[0]["security_headers"]["x-frame-options"],
            "DENY",
        )
        self.assertIn("headers", observations[0])
        services = payload["data"]["service_detection"]["observations"]
        self.assertEqual(services[0]["service"], "HTTP")
        self.assertEqual(services[0]["product"], "nginx")
        banners = payload["data"]["banner_discovery"]["observations"]
        self.assertEqual(banners[0]["normalized_banner"], "nginx/1.26")
        self.assertEqual(payload["data"]["vendor"]["vendor"], "Hikvision")
        self.assertGreaterEqual(payload["data"]["vendor"]["confidence"], 30)
        self.assertEqual(payload["data"]["onvif"]["status"], "detected")
        self.assertEqual(
            payload["data"]["classification"]["device_type"],
            "IP Camera",
        )
        self.assertEqual(payload["data"]["firmware"]["firmware"], "Unknown")
        self.assertTrue(payload["data"]["cves"]["lookup_attempted"])
        self.assertEqual(
            payload["data"]["capabilities"]["http"]["status"],
            "executed",
        )
        self.assertEqual(
            payload["data"]["capabilities"]["snmp"]["status"],
            "not_implemented",
        )
        self.assertEqual(
            payload["data"]["capabilities"]["default_credentials"]["status"],
            "not_tested",
        )
        self.assertEqual(payload["data"]["report"]["vendor"], "Hikvision")
        self.assertEqual(
            payload["data"]["report"]["manufacturer"],
            "Hikvision",
        )
        self.assertEqual(
            payload["data"]["report"]["default_credentials_status"],
            "not_tested",
        )
        self.assertEqual(
            payload["data"]["report"]["end_of_life_status"],
            "not_assessed",
        )
        self.assertEqual(payload["data"]["report"]["http_server"], "nginx")
        self.assertEqual(
            payload["data"]["report"]["http_title"],
            "Hikvision Camera Console",
        )
        self.assertEqual(payload["data"]["report"]["banner"], "nginx/1.26")
        self.assertIsNone(payload["data"]["report"]["mac_vendor"])
        self.assertEqual(
            payload["data"]["report"]["device_type"],
            "IP Camera",
        )
        self.assertEqual(payload["data"]["cache_status"], "MISS")
        self.assertIn(payload["data"]["risk"]["level"], {"Low", "Medium", "High", "Critical"})
        self.assertGreater(payload["data"]["risk"]["assessment_confidence"], 0)
        self.assertLessEqual(payload["data"]["summary"]["word_count"], 100)
        self.assertIn("Hikvision", payload["data"]["summary"]["text"])
        self.assertTrue(all(":554" not in url for url in self.http_urls))

    def test_open_443_produces_https_observations(self) -> None:
        self.open_ports = {443}
        response = self.client.post(
            "/api/v1/iot/fingerprint",
            json={"ip": "192.168.1.20", "ports": [443]},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()["data"]
        self.assertEqual(payload["port_discovery"]["open_ports"], [443])
        self.assertGreater(len(payload["http"]["observations"]), 0)
        self.assertTrue(
            all(
                item["scheme"] == "https"
                for item in payload["http"]["observations"]
            )
        )
        self.assertEqual(
            payload["service_detection"]["observations"][0]["service"],
            "HTTPS",
        )
        tls_items = payload["tls"]["observations"]
        self.assertEqual(len(tls_items), 1)
        self.assertEqual(tls_items[0]["tls_version"], "TLSv1.3")
        self.assertEqual(
            tls_items[0]["cipher_suite"],
            "TLS_AES_256_GCM_SHA384",
        )
        https_root = next(
            item
            for item in payload["http"]["observations"]
            if item["path"] == "/"
        )
        self.assertIn(
            "strict-transport-security",
            https_root["missing_security_headers"],
        )
        self.assertGreater(payload["risk"]["score"], 0)
        self.assertTrue(
            any(
                "HSTS missing" in factor["name"]
                for factor in payload["risk"]["factors"]
            )
        )
        self.assertIn(
            payload["risk"]["level"],
            payload["summary"]["text"],
        )

    def test_legacy_port_endpoint_remains_compatible(self) -> None:
        response = self.client.post(
            "/api/v1/iot/ports/discover",
            json={"ip": "192.168.1.20", "ports": [80, 554]},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["data"]["open_ports"], [80])
        self.assertIsNone(payload["error"])
        self.assertEqual(payload["metadata"]["sources_used"], ["tcp-connect"])
        self.assertTrue(
            {
                "asn",
                "bgp",
                "ripe",
                "rpki",
                "peeringdb",
                "isp_profile",
            }.isdisjoint(payload["data"])
        )
        port_80 = next(
            item
            for item in payload["data"]["observations"]
            if item["port"] == 80
        )
        self.assertEqual(port_80["service"], "HTTP")
        self.assertEqual(port_80["product"], "nginx")
        self.assertEqual(
            port_80["detection_method"],
            "Banner Analysis and Protocol Identification",
        )
        self.assertEqual(port_80["source"], "service-detection-engine")
        self.assertGreater(port_80["confidence"], 0.0)
        self.assertTrue(port_80["evidence"])
        self.assertIn("summary", payload["data"])
        self.assertIn("statistics", payload["data"])
        self.assertIn("exposure_score", payload["data"])
        self.assertEqual(payload["data"]["host_status"], "up")
        self.assertEqual(
            payload["data"]["capabilities"]["tcp_connect"]["status"],
            "executed",
        )
        self.assertEqual(
            payload["data"]["statistics"]["total_objects_scanned"],
            2,
        )

    def test_repeated_identical_scan_is_served_from_cache(self) -> None:
        request = {"ip": "192.168.1.20", "ports": [80]}

        first = self.client.post("/api/v1/iot/fingerprint", json=request)
        second = self.client.post("/api/v1/iot/fingerprint", json=request)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["data"]["cache_status"], "MISS")
        self.assertEqual(second.json()["data"]["cache_status"], "HIT")
        self.assertEqual(
            first.json()["data"]["report"],
            second.json()["data"]["report"],
        )

    def test_open_554_executes_rtsp_and_vendor_correlation(self) -> None:
        self.open_ports = {554}
        response = self.client.post(
            "/api/v1/iot/fingerprint",
            json={"ip": "192.168.1.20", "ports": [554]},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertEqual(data["http"]["observations"], [])
        self.assertTrue(data["rtsp"]["observations"][0]["detected"])
        self.assertEqual(
            data["service_detection"]["observations"][0]["service"],
            "RTSP",
        )
        self.assertEqual(data["vendor"]["vendor"], "Hikvision")
        self.assertTrue(
            any(
                "RTSP service exposed" in factor["name"]
                for factor in data["risk"]["factors"]
            )
        )
        self.assertIn("RTSP", data["summary"]["text"])


if __name__ == "__main__":
    unittest.main()
