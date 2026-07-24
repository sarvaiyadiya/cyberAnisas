"""Deterministic correlation and risk scoring for Module 5 evidence."""

from __future__ import annotations

from collections.abc import Sequence

from app.core.api_models import FindingRisk
from app.modules.wireless.models import (
    AccessPointObservation,
    AuthenticationAssessment,
    AuthenticationMode,
    BehaviorAnalysisResult,
    WirelessClientObservation,
    WirelessRiskAssessment,
    WirelessSecurityFinding,
)


def assess_access_point_observation(
    access_point: AccessPointObservation,
) -> FindingRisk:
    """Assess only security properties directly exposed by the scan."""
    security = (
        f"{access_point.authentication} {access_point.encryption}"
    ).upper()
    if "WEP" in security:
        return FindingRisk(
            severity="Critical",
            exposure_level="High",
            insecure_configurations=("WEP encryption observed",),
            recommendations=("Replace WEP with WPA3 or WPA2-AES.",),
            confidence=0.95,
        )
    if "OPEN" in security or access_point.encryption.upper() == "NONE":
        return FindingRisk(
            severity="High",
            exposure_level="High",
            insecure_configurations=("Open wireless authentication observed",),
            recommendations=(
                "Require WPA3 or WPA2-AES authentication for this network.",
            ),
            confidence=0.95,
        )
    if access_point.wps_enabled is True:
        return FindingRisk(
            severity="Medium",
            exposure_level="Moderate",
            insecure_configurations=("WPS is enabled",),
            recommendations=("Disable WPS when it is not operationally required.",),
            confidence=0.9,
        )
    if "WPA3" in security:
        return FindingRisk(
            severity="Low",
            exposure_level="Limited",
            recommendations=("Keep access-point firmware and WPA3 policy current.",),
            confidence=0.85,
        )
    if "WPA2" in security:
        return FindingRisk(
            severity="Low",
            exposure_level="Limited",
            recommendations=("Prefer WPA3 where all managed clients support it.",),
            confidence=0.85,
        )
    if "WPA" in security:
        return FindingRisk(
            severity="Medium",
            exposure_level="Moderate",
            insecure_configurations=("Legacy WPA security observed",),
            recommendations=("Migrate legacy WPA to WPA3 or WPA2-AES.",),
            confidence=0.9,
        )
    return FindingRisk(
        recommendations=(
            "Collect additional authentication evidence before assigning risk.",
        ),
    )


class WirelessRiskEngine:
    """Create explainable findings without inferring absent controls."""

    def assess(
        self,
        *,
        access_points: Sequence[AccessPointObservation],
        clients: Sequence[WirelessClientObservation],
        authentication: Sequence[AuthenticationAssessment],
        behavior: BehaviorAnalysisResult | None,
    ) -> WirelessRiskAssessment:
        """Return a capped score and unique remediation list."""
        findings: list[WirelessSecurityFinding] = []
        modes = {item.mode for item in authentication}

        if AuthenticationMode.WEP in modes:
            _add(
                findings,
                "WIFI-AUTH-001",
                "Authentication",
                "WEP authentication observed",
                "Critical",
                40,
                "At least one assessed BSSID uses WEP",
                "Replace WEP immediately with WPA3 or WPA2-AES.",
            )
        if AuthenticationMode.OPEN in modes:
            _add(
                findings,
                "WIFI-AUTH-002",
                "Authentication",
                "Open wireless network observed",
                "Critical",
                35,
                "At least one assessed BSSID has no cryptographic authentication",
                "Enable WPA3 or WPA2 and isolate untrusted guest clients.",
            )
        if modes.intersection(
            {
                AuthenticationMode.WPA_PERSONAL,
                AuthenticationMode.WPA_ENTERPRISE,
            }
        ):
            _add(
                findings,
                "WIFI-AUTH-003",
                "Authentication",
                "Legacy WPA authentication observed",
                "High",
                25,
                "At least one assessed BSSID uses legacy WPA",
                "Disable WPA/TKIP and migrate to WPA3 or WPA2-AES.",
            )
        if AuthenticationMode.UNKNOWN in modes:
            _add(
                findings,
                "WIFI-AUTH-004",
                "Authentication",
                "Authentication method is unknown",
                "Medium",
                10,
                "At least one BSSID could not be classified",
                "Verify the access-point authentication configuration.",
            )
        if any(item.mac_filtering_observed is True for item in authentication):
            _add(
                findings,
                "WIFI-AUTH-005",
                "Access Control",
                "MAC filtering is used as an access-control signal",
                "Medium",
                10,
                "MAC filtering was explicitly reported",
                "Use WPA2/WPA3 or 802.1X as the authentication control.",
            )

        hidden_count = sum(item.hidden_ssid for item in access_points)
        if hidden_count:
            _add(
                findings,
                "WIFI-CONFIG-001",
                "Configuration",
                "Hidden SSID observed",
                "Low",
                5,
                f"{hidden_count} access point(s) suppress the SSID name",
                "Do not rely on SSID hiding as a security control.",
            )
        wps_count = sum(item.wps_enabled is True for item in access_points)
        if wps_count:
            _add(
                findings,
                "WIFI-CONFIG-002",
                "Configuration",
                "WPS enabled",
                "High",
                20,
                f"WPS is enabled on {wps_count} access point(s)",
                "Disable WPS and use WPA2/WPA3 authentication.",
            )

        randomized_aps = sum(
            item.locally_administered for item in access_points
        )
        if randomized_aps:
            _add(
                findings,
                "WIFI-ASSET-001",
                "Asset Identity",
                "Locally administered access-point BSSID observed",
                "Medium",
                10,
                f"{randomized_aps} AP BSSID(s) use locally administered addresses",
                "Validate these BSSIDs against the authorized wireless inventory.",
            )

        randomized_clients = sum(
            item.locally_administered for item in clients
        )
        if randomized_clients:
            _add(
                findings,
                "WIFI-ASSET-002",
                "Asset Identity",
                "Client identity cannot be resolved through OUI",
                "Low",
                5,
                f"{randomized_clients} client(s) use locally administered MAC addresses",
                "Correlate randomized clients with authenticated identity records.",
            )

        anomaly_count = behavior.anomaly_count if behavior else 0
        if behavior and behavior.model_executed and anomaly_count:
            _add(
                findings,
                "WIFI-BEHAVIOR-001",
                "Behavior",
                "Statistical device behavior anomalies observed",
                "High",
                min(10 + anomaly_count * 5, 25),
                f"Isolation Forest marked {anomaly_count} device(s) as outliers",
                "Investigate anomalous devices using authorized telemetry and asset context.",
            )

        score = min(sum(item.points for item in findings), 100)
        recommendations = tuple(
            dict.fromkeys(item.recommendation for item in findings)
        )
        return WirelessRiskAssessment(
            score=score,
            level=_risk_level(score),
            assessment_confidence=_confidence(
                access_points=access_points,
                clients=clients,
                authentication=authentication,
                behavior=behavior,
            ),
            findings=tuple(findings),
            recommendations=recommendations,
            rogue_ap_indicators=tuple(
                item.evidence
                for item in findings
                if item.finding_id == "WIFI-ASSET-001"
            ),
        )


def _add(
    findings: list[WirelessSecurityFinding],
    finding_id: str,
    category: str,
    title: str,
    severity: str,
    points: int,
    evidence: str,
    recommendation: str,
) -> None:
    if any(item.finding_id == finding_id for item in findings):
        return
    findings.append(
        WirelessSecurityFinding(
            finding_id=finding_id,
            category=category,
            title=title,
            severity=severity,
            points=points,
            evidence=evidence,
            recommendation=recommendation,
        )
    )


def _risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _confidence(
    *,
    access_points: Sequence[AccessPointObservation],
    clients: Sequence[WirelessClientObservation],
    authentication: Sequence[AuthenticationAssessment],
    behavior: BehaviorAnalysisResult | None,
) -> int:
    confidence = 10
    if access_points:
        confidence += 25
    if authentication:
        confidence += 35
    if clients:
        confidence += 15
    if behavior and behavior.model_executed:
        confidence += 15
    return min(confidence, 100)
