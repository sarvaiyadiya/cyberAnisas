"""Tests for IEEE OUI parsing and access-point vendor enrichment."""

import subprocess
import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.modules.wireless.analysis.oui import IEEEOUIRegistry
from app.modules.wireless.collectors.access_points import AccessPointCollector
from app.modules.wireless.parsers.oui import parse_ieee_oui_csv
from app.modules.wireless.service import (
    WirelessIntelligenceService,
    get_wireless_service,
)


IEEE_FIXTURE = """Registry,Assignment,Organization Name,Organization Address
MA-L,001A2B,Example Networks Inc.,Example Address
MA-M,AABBCCD,Ignored Medium Assignment,Example Address
"""

WINDOWS_SCAN = """
SSID 1 : SecureLab
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:1a:2b:44:55:66
         Signal             : 82%
         Channel            : 36
"""


class OUIRegistryTests(unittest.TestCase):
    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_parses_only_ieee_ma_l_assignments(self) -> None:
        records = parse_ieee_oui_csv(IEEE_FIXTURE)

        self.assertEqual(records, {"001A2B": "Example Networks Inc."})

    def test_returns_exact_vendor_evidence(self) -> None:
        registry = IEEEOUIRegistry(
            records={"001A2B": "Example Networks Inc."}
        )

        result = registry.lookup("00-1a-2b-44-55-66")

        self.assertEqual(result.vendor, "Example Networks Inc.")
        self.assertEqual(result.confidence, 100)
        self.assertEqual(result.source, "IEEE MA-L")

    def test_locally_administered_mac_does_not_claim_vendor(self) -> None:
        registry = IEEEOUIRegistry(
            records={"AABBCC": "Must Not Be Used"}
        )

        result = registry.lookup("AA:BB:CC:44:55:66")

        self.assertTrue(result.locally_administered)
        self.assertEqual(result.vendor, "Unknown")
        self.assertEqual(result.confidence, 0)

    def test_production_api_contains_vendor_evidence(self) -> None:
        collector = AccessPointCollector(
            runner=lambda command, timeout: subprocess.CompletedProcess(
                command,
                0,
                stdout=WINDOWS_SCAN,
                stderr="",
            ),
            platform_name="Windows",
        )
        service = WirelessIntelligenceService(
            access_point_collector=collector,
            oui_registry=IEEEOUIRegistry(
                records={"001A2B": "Example Networks Inc."}
            ),
        )
        app.dependency_overrides[get_wireless_service] = lambda: service

        response = TestClient(app).post(
            "/api/v1/wireless/access-points",
            json={"rescan": True},
        )

        self.assertEqual(response.status_code, 200)
        access_point = response.json()["data"]["access_points"][0]
        self.assertEqual(access_point["vendor"], "Example Networks Inc.")
        self.assertEqual(access_point["vendor_confidence"], 100)
        self.assertEqual(access_point["vendor_source"], "IEEE MA-L")
        self.assertTrue(access_point["vendor_source_available"])


if __name__ == "__main__":
    unittest.main()
