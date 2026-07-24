"""Unit and production API tests for access-point enumeration."""

import subprocess
import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.modules.wireless.collectors.access_points import AccessPointCollector
from app.modules.wireless.parsers.access_points import (
    parse_linux_access_points,
    parse_windows_access_points,
)
from app.modules.wireless.service import (
    WirelessIntelligenceService,
    get_wireless_service,
)


WINDOWS_SCAN = """
SSID 1 : SecureLab
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 82%
         Radio type         : 802.11ac
         Channel            : 36
         WPS                 : Enabled
         Protected Management Frames : Supported
"""


class AccessPointTests(unittest.TestCase):
    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_parses_windows_access_point(self) -> None:
        access_points = parse_windows_access_points(WINDOWS_SCAN, "Wi-Fi")

        self.assertEqual(len(access_points), 1)
        item = access_points[0]
        self.assertEqual(item.ssid, "SecureLab")
        self.assertEqual(item.bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(item.frequency_mhz, 5180)
        self.assertEqual(item.band, "5GHz")
        self.assertEqual(item.authentication, "WPA2-Personal")
        self.assertTrue(item.wps_enabled)
        self.assertEqual(item.pmf_support, "Supported")
        self.assertFalse(item.hidden_ssid)
        self.assertIsNone(item.rssi_dbm)
        self.assertEqual(item.first_seen, item.last_seen)

    def test_parses_linux_escaped_bssid(self) -> None:
        output = (
            "SecureLab:AA\\:BB\\:CC\\:DD\\:EE\\:FF:"
            "36:5180:72:WPA2\n"
        )
        access_points = parse_linux_access_points(output, "wlan0")

        self.assertEqual(len(access_points), 1)
        self.assertEqual(access_points[0].authentication, "WPA2")
        self.assertEqual(access_points[0].signal_percent, 72)
        self.assertEqual(access_points[0].band, "5GHz")

    def test_collector_uses_safe_windows_argument_list(self) -> None:
        observed = None

        def runner(command, timeout):
            nonlocal observed
            observed = tuple(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=WINDOWS_SCAN,
                stderr="",
            )

        result = AccessPointCollector(
            runner=runner,
            platform_name="Windows",
        ).collect()

        self.assertEqual(
            observed,
            ("netsh", "wlan", "show", "networks", "mode=bssid"),
        )
        self.assertEqual(len(result.access_points), 1)

    def test_unsupported_platform_returns_informative_result(self) -> None:
        result = AccessPointCollector(platform_name="Plan9").collect()

        self.assertFalse(result.command_available)
        self.assertEqual(result.access_points, ())
        self.assertIn("unsupported", result.error.lower())

    def test_production_api_returns_normalized_data(self) -> None:
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
        )
        app.dependency_overrides[get_wireless_service] = lambda: service
        client = TestClient(app)

        response = client.post(
            "/api/v1/wireless/access-points",
            json={"interface": "Wi-Fi", "rescan": True},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertIsNone(payload["error"])
        self.assertEqual(
            payload["data"]["access_points"][0]["bssid"],
            "AA:BB:CC:DD:EE:FF",
        )
        item = payload["data"]["access_points"][0]
        self.assertEqual(item["device_class"], "Access Point")
        required_wireless_fields = {
            "ssid",
            "bssid",
            "manufacturer",
            "security_mode",
            "cipher",
            "country_code",
            "geolocation",
            "evidence",
            "confidence",
            "detection_method",
            "source",
            "risk",
            "channel",
            "frequency_mhz",
            "band",
            "encryption",
            "signal_percent",
            "rssi_dbm",
            "hidden_ssid",
            "wps_enabled",
            "beacon_interval_ms",
            "beacon_observed",
            "probe_response_observed",
            "channel_utilization_percent",
            "noise_dbm",
            "dfs_channel",
            "associated_client_count",
            "mesh_detected",
            "hotspot_detected",
            "captive_portal_detected",
            "rogue_probability",
            "evil_twin_probability",
            "first_seen",
            "last_seen",
        }
        self.assertTrue(required_wireless_fields <= set(item))
        self.assertIsNone(item["country_code"])
        self.assertIsNone(item["geolocation"])
        self.assertEqual(
            item["detection_method"],
            "Operating System Wireless Enumeration",
        )
        self.assertEqual(item["source"], "windows-native-wireless-scan")
        self.assertEqual(item["confidence"], 1.0)
        self.assertTrue(item["evidence"])
        self.assertIn(item["risk"]["severity"], {"Low", "Medium", "High", "Critical", "Unknown"})
        self.assertEqual(payload["data"]["summary"]["total_findings"], 1)
        self.assertEqual(
            payload["data"]["statistics"]["successful_detections"],
            1,
        )
        self.assertIn(
            "windows-native-wireless-scan",
            payload["metadata"]["sources_used"],
        )
        self.assertGreaterEqual(payload["metadata"]["confidence_score"], 0.0)
        self.assertGreaterEqual(payload["metadata"]["lookup_duration_ms"], 0)
        self.assertEqual(payload["metadata"]["endpoint_version"], "v1")
        self.assertEqual(
            payload["metadata"]["detection_engine"],
            "ANISAS Wireless Enumeration",
        )
        self.assertEqual(
            payload["metadata"]["scan_mode"],
            "local-os-enumeration",
        )
        self.assertEqual(payload["metadata"]["execution_status"], "completed")
        self.assertIn("scan_timestamp", payload["metadata"])
        self.assertTrue(
            {"ip", "asn", "bgp", "prefixes", "rpki", "ai_risk"}.isdisjoint(
                payload["data"]
            )
        )
        self.assertNotIn("raw_output", payload["data"])


if __name__ == "__main__":
    unittest.main()
