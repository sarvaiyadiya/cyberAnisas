"""Tests for bounded NVD CVE normalization."""

import unittest

from app.modules.iot.clients.cve_client import CVEIntelligenceClient


class FakeHTTPClient:
    def get(self, url, params=None, extra_headers=None):
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [
                            {"lang": "en", "value": "Example vulnerability."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.test/cve"}],
                    }
                }
            ]
        }


class CVEIntelligenceClientTests(unittest.TestCase):
    def test_normalizes_firmware_quality_result(self) -> None:
        result = CVEIntelligenceClient(
            http_client=FakeHTTPClient(),
            max_results=5,
        ).lookup("Hikvision", "DS-2CD2043", "5.7.12")
        self.assertTrue(result.lookup_attempted)
        self.assertTrue(result.source_available)
        self.assertEqual(result.records[0].cve_id, "CVE-2024-0001")
        self.assertEqual(result.records[0].severity, "CRITICAL")
        self.assertEqual(result.records[0].match_quality, "firmware")

    def test_unknown_vendor_skips_external_lookup(self) -> None:
        result = CVEIntelligenceClient(
            http_client=FakeHTTPClient()
        ).lookup("Unknown", "Unknown", "Unknown")
        self.assertFalse(result.lookup_attempted)
        self.assertEqual(result.records, ())


if __name__ == "__main__":
    unittest.main()
