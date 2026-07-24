"""Tests for authentication analysis and safe MAC lab guidance."""

import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.modules.wireless.analysis.authentication import (
    AuthenticationAnalysisEngine,
)
from app.modules.wireless.models import (
    AuthenticationEvidence,
    AuthenticationMode,
)


class AuthenticationAnalysisTests(unittest.TestCase):
    def test_open_network_is_critical(self) -> None:
        result = AuthenticationAnalysisEngine().analyze(
            AuthenticationEvidence(
                ssid="Guest",
                bssid="00:1A:2B:44:55:66",
                authentication="Open",
                encryption="None",
            )
        )

        self.assertEqual(result.mode, AuthenticationMode.OPEN)
        self.assertEqual(result.risk_level, "Critical")

    def test_enterprise_and_8021x_are_detected(self) -> None:
        result = AuthenticationAnalysisEngine().analyze(
            AuthenticationEvidence(
                ssid="Corporate",
                bssid="00:1A:2B:44:55:66",
                authentication="WPA2-Enterprise 802.1X",
                encryption="CCMP",
            )
        )

        self.assertEqual(result.mode, AuthenticationMode.WPA2_ENTERPRISE)
        self.assertTrue(result.enterprise)
        self.assertTrue(result.ieee8021x)

    def test_mac_filtering_is_not_treated_as_authentication(self) -> None:
        result = AuthenticationAnalysisEngine().analyze(
            AuthenticationEvidence(
                bssid="00:1A:2B:44:55:66",
                authentication="WPA2-Personal",
                encryption="CCMP",
                mac_filtering_observed=True,
            )
        )

        self.assertTrue(
            any("MAC filtering" in finding.title for finding in result.findings)
        )

    def test_api_returns_analysis_and_documentation_only_lab(self) -> None:
        response = TestClient(app).post(
            "/api/v1/wireless/authentication",
            json={
                "access_points": [
                    {
                        "ssid": "SecureLab",
                        "bssid": "00:1a:2b:44:55:66",
                        "authentication": "WPA3-Personal",
                        "encryption": "CCMP",
                    }
                ],
                "include_mac_auth_lab": True,
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            payload["data"]["assessments"][0]["mode"],
            "WPA3-Personal",
        )
        guide = payload["data"]["mac_authentication_lab"]
        self.assertFalse(guide["automated_mac_change"])
        self.assertGreater(len(guide["safety_checklist"]), 0)
        self.assertGreater(len(guide["demonstration_steps"]), 0)


if __name__ == "__main__":
    unittest.main()
