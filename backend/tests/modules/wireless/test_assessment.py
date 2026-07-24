"""Tests for wireless risk correlation and production report API."""

import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.modules.wireless.analysis.assessment import WirelessRiskEngine
from app.modules.wireless.models import (
    AccessPointObservation,
    AuthenticationAssessment,
    AuthenticationFinding,
    AuthenticationMode,
)


def open_authentication() -> AuthenticationAssessment:
    finding = AuthenticationFinding(
        title="Open wireless authentication",
        severity="Critical",
        evidence="authentication=Open",
        recommendation="Enable WPA3.",
    )
    return AuthenticationAssessment(
        ssid="Guest",
        bssid="00:1A:2B:44:55:66",
        mode=AuthenticationMode.OPEN,
        enterprise=False,
        ieee8021x=False,
        mac_filtering_observed=None,
        risk_score=80,
        risk_level="Critical",
        findings=(finding,),
        recommendations=("Enable WPA3.",),
    )


class WirelessAssessmentTests(unittest.TestCase):
    def test_open_authentication_creates_explainable_risk(self) -> None:
        result = WirelessRiskEngine().assess(
            access_points=(),
            clients=(),
            authentication=(open_authentication(),),
            behavior=None,
        )

        self.assertGreaterEqual(result.score, 35)
        self.assertTrue(
            any(item.finding_id == "WIFI-AUTH-002" for item in result.findings)
        )

    def test_report_api_correlates_normalized_evidence(self) -> None:
        access_point = AccessPointObservation(
            ssid="Guest",
            bssid="00:1A:2B:44:55:66",
            channel=1,
            frequency_mhz=2412,
            signal_percent=75,
            authentication="Open",
            encryption="None",
            oui="00:1A:2B",
            vendor="Example Networks",
            vendor_confidence=100,
            vendor_source="IEEE MA-L",
        )
        response = TestClient(app).post(
            "/api/v1/wireless/report",
            json={
                "access_points": [access_point.model_dump(mode="json")],
                "authentication_assessments": [
                    open_authentication().model_dump(mode="json")
                ],
                "clients": [],
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertEqual(data["access_point_count"], 1)
        self.assertGreater(data["risk"]["score"], 0)
        self.assertEqual(
            data["security_score"],
            100 - data["risk"]["score"],
        )
        self.assertIn("Overall wireless risk", data["summary"])
        self.assertNotIn("raw_output", data)

    def test_empty_evidence_does_not_invent_findings(self) -> None:
        result = WirelessRiskEngine().assess(
            access_points=(),
            clients=(),
            authentication=(),
            behavior=None,
        )

        self.assertEqual(result.score, 0)
        self.assertEqual(result.findings, ())

    def test_hidden_ssid_and_wps_are_reported(self) -> None:
        access_point = AccessPointObservation(
            ssid="",
            bssid="00:1A:2B:44:55:66",
            authentication="WPA2-Personal",
            encryption="CCMP",
            hidden_ssid=True,
            wps_enabled=True,
            oui="00:1A:2B",
        )

        result = WirelessRiskEngine().assess(
            access_points=(access_point,),
            clients=(),
            authentication=(),
            behavior=None,
        )

        finding_ids = {item.finding_id for item in result.findings}
        self.assertIn("WIFI-CONFIG-001", finding_ids)
        self.assertIn("WIFI-CONFIG-002", finding_ids)


if __name__ == "__main__":
    unittest.main()
