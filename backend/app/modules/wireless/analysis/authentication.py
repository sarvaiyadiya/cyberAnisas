"""Deterministic wireless authentication classification and risk analysis."""

from __future__ import annotations

from app.modules.wireless.models import (
    AuthenticationAssessment,
    AuthenticationEvidence,
    AuthenticationFinding,
    AuthenticationMode,
)


class AuthenticationAnalysisEngine:
    """Classify only from supplied AP security evidence."""

    def analyze(
        self,
        evidence: AuthenticationEvidence,
    ) -> AuthenticationAssessment:
        """Return an evidence-backed assessment for one BSSID."""
        mode = _classify(evidence.authentication, evidence.encryption)
        score, findings = _policy(mode, evidence)
        recommendations = tuple(
            dict.fromkeys(item.recommendation for item in findings)
        )
        return AuthenticationAssessment(
            ssid=evidence.ssid,
            bssid=evidence.bssid,
            mode=mode,
            enterprise=mode
            in {
                AuthenticationMode.WPA_ENTERPRISE,
                AuthenticationMode.WPA2_ENTERPRISE,
                AuthenticationMode.WPA3_ENTERPRISE,
                AuthenticationMode.IEEE8021X,
            },
            ieee8021x=mode
            in {
                AuthenticationMode.WPA_ENTERPRISE,
                AuthenticationMode.WPA2_ENTERPRISE,
                AuthenticationMode.WPA3_ENTERPRISE,
                AuthenticationMode.IEEE8021X,
            },
            pmf_support=evidence.pmf_support,
            mac_filtering_observed=evidence.mac_filtering_observed,
            risk_score=score,
            risk_level=_risk_level(score),
            findings=findings,
            recommendations=recommendations,
        )


def _classify(authentication: str, encryption: str) -> AuthenticationMode:
    text = f"{authentication} {encryption}".upper().replace("_", "-")
    enterprise = any(
        token in text for token in ("ENTERPRISE", "802.1X", "8021X", "EAP")
    )
    if "WEP" in text:
        return AuthenticationMode.WEP
    if "WPA3" in text or "SAE" in text:
        return (
            AuthenticationMode.WPA3_ENTERPRISE
            if enterprise
            else AuthenticationMode.WPA3_PERSONAL
        )
    if "WPA2" in text or "RSN" in text:
        return (
            AuthenticationMode.WPA2_ENTERPRISE
            if enterprise
            else AuthenticationMode.WPA2_PERSONAL
        )
    if "WPA" in text:
        return (
            AuthenticationMode.WPA_ENTERPRISE
            if enterprise
            else AuthenticationMode.WPA_PERSONAL
        )
    if enterprise:
        return AuthenticationMode.IEEE8021X
    if any(token in text for token in ("OPEN", "NONE")):
        return AuthenticationMode.OPEN
    return AuthenticationMode.UNKNOWN


def _policy(
    mode: AuthenticationMode,
    evidence: AuthenticationEvidence,
) -> tuple[int, tuple[AuthenticationFinding, ...]]:
    findings: list[AuthenticationFinding] = []
    score = 0
    observed = (
        f"authentication={evidence.authentication}; "
        f"encryption={evidence.encryption}"
    )
    if mode is AuthenticationMode.OPEN:
        score = 80
        findings.append(
            _finding(
                "Open wireless authentication",
                "Critical",
                observed,
                "Use WPA3 or WPA2 with strong authentication and client isolation.",
            )
        )
    elif mode is AuthenticationMode.WEP:
        score = 95
        findings.append(
            _finding(
                "Obsolete WEP protection",
                "Critical",
                observed,
                "Replace WEP immediately with WPA3 or WPA2-AES.",
            )
        )
    elif mode in {
        AuthenticationMode.WPA_PERSONAL,
        AuthenticationMode.WPA_ENTERPRISE,
    }:
        score = 75
        findings.append(
            _finding(
                "Legacy WPA authentication",
                "High",
                observed,
                "Disable WPA/TKIP and migrate to WPA3 or WPA2-AES.",
            )
        )
    elif mode is AuthenticationMode.WPA2_PERSONAL:
        score = 30
        findings.append(
            _finding(
                "Pre-shared-key authentication",
                "Medium",
                observed,
                "Use a long unique passphrase, disable WPS, and prefer WPA3-SAE.",
            )
        )
    elif mode is AuthenticationMode.WPA2_ENTERPRISE:
        score = 15
        findings.append(
            _finding(
                "Enterprise authentication configuration requires validation",
                "Low",
                observed,
                "Validate server certificates and use strong EAP methods.",
            )
        )
    elif mode is AuthenticationMode.WPA3_PERSONAL:
        score = 10
    elif mode is AuthenticationMode.WPA3_ENTERPRISE:
        score = 5
    elif mode is AuthenticationMode.IEEE8021X:
        score = 20
        findings.append(
            _finding(
                "802.1X configuration requires validation",
                "Low",
                observed,
                "Validate RADIUS trust, certificate validation, and EAP policy.",
            )
        )
    else:
        score = 40
        findings.append(
            _finding(
                "Authentication method could not be determined",
                "Medium",
                observed,
                "Verify the access-point security configuration manually.",
            )
        )

    if evidence.mac_filtering_observed is True:
        score = min(score + 15, 100)
        findings.append(
            _finding(
                "MAC filtering used as an access-control signal",
                "Medium",
                "MAC filtering was explicitly reported in supplied evidence",
                "Do not treat MAC filtering as authentication; use WPA2/WPA3 or 802.1X.",
            )
        )
    return score, tuple(findings)


def _finding(
    title: str,
    severity: str,
    evidence: str,
    recommendation: str,
) -> AuthenticationFinding:
    return AuthenticationFinding(
        title=title,
        severity=severity,
        evidence=evidence,
        recommendation=recommendation,
    )


def _risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"
