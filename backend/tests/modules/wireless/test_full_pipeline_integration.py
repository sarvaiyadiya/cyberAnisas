"""End-to-end production API integration for the Module 5 pipeline."""

import subprocess
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.modules.wireless.analysis.behavior import BehaviorAnalysisEngine
from app.modules.wireless.analysis.oui import IEEEOUIRegistry
from app.modules.wireless.collectors.access_points import AccessPointCollector
from app.modules.wireless.collectors.clients import WirelessClientCollector
from app.modules.wireless.service import (
    WirelessIntelligenceService,
    get_wireless_service,
)

ACCESS_POINT_OUTPUT = """
SSID 1 : SecureLab
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:1a:2b:44:55:66
         Signal             : 82%
         Channel            : 36
"""

CLIENT_OUTPUT = """
Interface: 192.168.1.10 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.20          00-1a-2b-11-22-33     dynamic
"""


class PassthroughScaler:
    """Deterministic StandardScaler test boundary."""

    def fit_transform(self, values):
        return values


class DeterministicIsolationForest:
    """Mark the final fixture record as the statistical outlier."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def fit_predict(self, values):
        return [1] * (len(values) - 1) + [-1]

    def score_samples(self, values):
        return [-0.1] * (len(values) - 1) + [-0.9]


class WirelessFullPipelineIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        access_points = AccessPointCollector(
            runner=lambda command, timeout: subprocess.CompletedProcess(
                command,
                0,
                stdout=ACCESS_POINT_OUTPUT,
                stderr="",
            ),
            platform_name="Windows",
        )
        clients = WirelessClientCollector(
            runner=lambda command, timeout: subprocess.CompletedProcess(
                command,
                0,
                stdout=CLIENT_OUTPUT,
                stderr="",
            ),
            platform_name="Windows",
        )
        behavior = BehaviorAnalysisEngine(
            scaler_factory=PassthroughScaler,
            isolation_factory=DeterministicIsolationForest,
        )
        service = WirelessIntelligenceService(
            access_point_collector=access_points,
            client_collector=clients,
            oui_registry=IEEEOUIRegistry(
                records={"001A2B": "Example Networks Inc."}
            ),
            behavior_engine=behavior,
        )
        app.dependency_overrides[get_wireless_service] = lambda: service
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_complete_api_evidence_flow(self) -> None:
        access_point_response = self.client.post(
            "/api/v1/wireless/access-points",
            json={"interface": "Wi-Fi", "rescan": True},
        )
        self.assertEqual(access_point_response.status_code, 200)
        access_point_data = access_point_response.json()["data"]
        access_point = access_point_data["access_points"][0]
        self.assertEqual(access_point["vendor"], "Example Networks Inc.")

        authentication_response = self.client.post(
            "/api/v1/wireless/authentication",
            json={
                "access_points": access_point_data["access_points"],
                "include_mac_auth_lab": True,
            },
        )
        self.assertEqual(authentication_response.status_code, 200)
        authentication_data = authentication_response.json()["data"]
        self.assertEqual(
            authentication_data["assessments"][0]["mode"],
            "WPA2-Personal",
        )

        client_response = self.client.post(
            "/api/v1/wireless/clients",
            json={"interface": "Wi-Fi"},
        )
        self.assertEqual(client_response.status_code, 200)
        client_data = client_response.json()["data"]
        self.assertEqual(client_data["clients"], [])
        self.assertEqual(
            client_data["neighbor_candidates"][0]["vendor"],
            "Example Networks Inc.",
        )

        behavior_response = self.client.post(
            "/api/v1/wireless/behavior",
            json={
                "records": _behavior_records(),
                "contamination": 0.1,
            },
        )
        self.assertEqual(behavior_response.status_code, 200)
        behavior_data = behavior_response.json()["data"]
        self.assertTrue(behavior_data["model_executed"])
        self.assertEqual(behavior_data["anomaly_count"], 1)

        report_response = self.client.post(
            "/api/v1/wireless/report",
            json={
                "access_points": access_point_data["access_points"],
                "clients": client_data["clients"],
                "authentication_assessments": (
                    authentication_data["assessments"]
                ),
                "behavior": behavior_data,
            },
        )
        self.assertEqual(report_response.status_code, 200)
        report = report_response.json()["data"]
        self.assertEqual(report["access_point_count"], 1)
        self.assertEqual(report["client_count"], 0)
        self.assertEqual(report["anomalous_device_count"], 1)
        self.assertGreater(report["risk"]["score"], 0)
        self.assertTrue(
            any(
                finding["finding_id"] == "WIFI-BEHAVIOR-001"
                for finding in report["risk"]["findings"]
            )
        )
        self.assertNotIn("raw_output", report)

    def test_combined_full_scan_returns_all_module_5_stages(self) -> None:
        response = self.client.post(
            "/api/v1/wireless/full-scan",
            json={
                "interface": "Wi-Fi",
                "rescan": True,
                "include_mac_auth_lab": False,
                "behavior_records": _behavior_records(),
                "contamination": 0.1,
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertIsNone(payload["error"])
        data = payload["data"]
        self.assertEqual(len(data["access_points"]["access_points"]), 1)
        self.assertEqual(
            data["authentication"]["assessments"][0]["mode"],
            "WPA2-Personal",
        )
        self.assertEqual(data["clients"]["clients"], [])
        self.assertEqual(
            data["clients"]["neighbor_candidates"][0]["vendor"],
            "Example Networks Inc.",
        )
        self.assertTrue(data["behavior"]["model_executed"])
        self.assertEqual(data["behavior"]["anomaly_count"], 1)
        self.assertEqual(data["report"]["access_point_count"], 1)
        self.assertEqual(data["report"]["anomalous_device_count"], 1)
        self.assertEqual(data["metrics"]["access_points_discovered"], 1)
        self.assertEqual(data["metrics"]["hidden_networks"], 0)
        self.assertIsNone(data["metrics"]["coverage_percentage"])
        self.assertEqual(
            data["metrics"]["scan_completion_percentage"],
            100.0,
        )
        self.assertEqual(
            data["module_health"]["status"],
            "completed_with_limitations",
        )
        self.assertEqual(
            data["module_health"]["submodules"]["bluetooth_scan"]["status"],
            "unsupported",
        )
        self.assertEqual(
            data["module_health"]["submodules"]["rogue_detection"]["status"],
            "limited",
        )
        self.assertEqual(
            data["analysis"]["engine"],
            "deterministic-wireless-evidence-correlation",
        )
        self.assertIsNone(data["analysis"]["rogue_ap_probability"])
        self.assertIsNone(data["analysis"]["unauthorized_device_count"])
        self.assertIsNone(data["analysis"]["iot_exposure_score"])
        self.assertEqual(
            data["stages_completed"],
            [
                "interfaces",
                "access_points",
                "clients",
                "authentication",
                "behavior",
                "report",
            ],
        )
        self.assertEqual(
            payload["metadata"]["detection_engine"],
            "ANISAS Module 5 Orchestrator",
        )
        self.assertEqual(
            payload["metadata"]["scan_mode"],
            "combined-local-session",
        )
        self.assertNotIn("asn", data)
        self.assertNotIn("raw_output", data)

    def test_combined_full_scan_skips_behavior_without_history(self) -> None:
        response = self.client.post(
            "/api/v1/wireless/full-scan",
            json={"interface": "Wi-Fi"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertIsNone(data["behavior"])
        self.assertNotIn("behavior", data["stages_completed"])
        self.assertTrue(
            any(
                "behavior_records" in limitation
                for limitation in data["limitations"]
            )
        )


def _behavior_records() -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "mac": f"00:1A:2B:00:00:{index:02X}",
            "traffic_volume_mb": 10 if index < 5 else 1000,
            "session_duration_minutes": 20,
            "connection_frequency": 3,
            "first_seen": (now - timedelta(hours=24)).isoformat(),
            "last_seen": now.isoformat(),
        }
        for index in range(6)
    ]


if __name__ == "__main__":
    unittest.main()
