"""Tests for TLS certificate fingerprinting."""

import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.modules.iot.detectors.tls import (
    TLSFingerprintEngine,
    TLSHandshakeEvidence,
    TLSProbeConfig,
)
from app.modules.iot.exceptions import TLSConfigurationError


def _certificate_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hikvision"),
            x509.NameAttribute(NameOID.COMMON_NAME, "camera.local"),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("camera.local"), x509.IPAddress(ip_address("10.0.0.15"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class TLSFingerprintEngineTests(unittest.TestCase):
    def test_parses_certificate_and_vendor_hint(self) -> None:
        certificate = _certificate_der()

        def prober(target: str, port: int, timeout: float):
            return TLSHandshakeEvidence(
                tls_version="TLSv1.3",
                certificate_der=certificate,
                validated=False,
                validation_error="self-signed certificate",
                latency_ms=12.5,
                cipher_suite="TLS_AES_256_GCM_SHA384",
                cipher_bits=256,
            )

        item = TLSFingerprintEngine(prober=prober).collect(
            "10.0.0.15", [443, 554]
        ).observations[0]
        self.assertEqual(item.tls_version, "TLSv1.3")
        self.assertEqual(item.cipher_suite, "TLS_AES_256_GCM_SHA384")
        self.assertEqual(item.cipher_bits, 256)
        self.assertEqual(item.signature_algorithm, "sha256WithRSAEncryption")
        self.assertEqual(item.common_name, "camera.local")
        self.assertIn("10.0.0.15", item.subject_alt_names)
        self.assertTrue(item.self_signed)
        self.assertFalse(item.expired)
        self.assertFalse(item.certificate_validated)
        self.assertEqual(item.vendor_hints, ("Hikvision",))
        self.assertIn("Certificate appears self-signed", item.security_issues)
        self.assertIn("Certificate validation failed", item.security_issues)
        self.assertEqual(item.latency_ms, 12.5)

    def test_sanitizes_probe_error(self) -> None:
        def prober(target: str, port: int, timeout: float):
            raise OSError("private network path")

        item = TLSFingerprintEngine(prober=prober).collect(
            "192.168.1.20", [8443]
        ).observations[0]
        self.assertEqual(item.error, "OSError")
        self.assertNotIn("private network", item.model_dump_json())

    def test_ignores_non_tls_ports(self) -> None:
        result = TLSFingerprintEngine(
            prober=lambda *args: self.fail("should not probe")
        ).collect("127.0.0.1", [80, 554])
        self.assertEqual(result.observations, ())

    def test_rejects_unsafe_timeout(self) -> None:
        with self.assertRaises(TLSConfigurationError):
            TLSProbeConfig(timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
