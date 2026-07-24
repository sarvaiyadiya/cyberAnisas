"""Deterministic, evidence-backed risk assessment for Module 4."""

from __future__ import annotations

from ipaddress import ip_address

from app.modules.iot.models import (
    CVEIntelligenceResult,
    HTTPFingerprintResult,
    ONVIFDetectionResult,
    ONVIFStatus,
    PortDiscoveryResult,
    PortState,
    RiskAssessmentResult,
    RiskFactor,
    RTSPDetectionResult,
    TLSFingerprintResult,
    VendorDetectionResult,
)


class RiskAssessmentEngine:
    """Calculate risk without CVE or firmware claims that are not available."""

    def assess(
        self,
        ports: PortDiscoveryResult,
        http: HTTPFingerprintResult,
        tls: TLSFingerprintResult,
        rtsp: RTSPDetectionResult,
        vendor: VendorDetectionResult,
        onvif: ONVIFDetectionResult | None = None,
        cves: CVEIntelligenceResult | None = None,
    ) -> RiskAssessmentResult:
        """Return a capped score, level, factors, and unique remediations."""
        factors: list[RiskFactor] = []
        open_ports = set(ports.open_ports)

        if 23 in open_ports:
            self._add(
                factors,
                "Unencrypted Telnet service",
                "High",
                25,
                "TCP port 23 is open",
                "Disable Telnet and use SSH with strong authentication.",
            )
        if 21 in open_ports:
            self._add(
                factors,
                "Unencrypted FTP service",
                "Medium",
                15,
                "TCP port 21 is open",
                "Replace FTP with SFTP or another encrypted transfer protocol.",
            )

        http_ports = {
            item.port
            for item in http.observations
            if item.scheme == "http" and item.status_code is not None
        }
        https_ports = {
            item.port
            for item in http.observations
            if item.scheme == "https" and item.status_code is not None
        }
        if http_ports and not https_ports:
            self._add(
                factors,
                "Management interface lacks HTTPS",
                "Medium",
                15,
                f"HTTP responded on ports {sorted(http_ports)} with no HTTPS response",
                "Enable HTTPS and redirect or disable plaintext HTTP management.",
            )

        root_pages = [
            item
            for item in http.observations
            if item.path == "/" and item.status_code is not None
        ]
        for item in root_pages:
            if "strict-transport-security" in item.missing_security_headers:
                self._add(
                    factors,
                    f"HSTS missing on port {item.port}",
                    "Medium",
                    8,
                    f"HTTPS response on port {item.port} omitted HSTS",
                    "Enable Strict-Transport-Security after validating HTTPS deployment.",
                )
            if "content-security-policy" in item.missing_security_headers:
                self._add(
                    factors,
                    f"CSP missing on port {item.port}",
                    "Low",
                    4,
                    f"HTTP response on port {item.port} omitted Content-Security-Policy",
                    "Deploy a restrictive Content-Security-Policy.",
                )
            if "x-frame-options" in item.missing_security_headers:
                self._add(
                    factors,
                    f"Clickjacking protection missing on port {item.port}",
                    "Low",
                    3,
                    f"HTTP response on port {item.port} omitted X-Frame-Options",
                    "Set X-Frame-Options or an equivalent CSP frame-ancestors policy.",
                )
            if item.login_markers:
                self._add(
                    factors,
                    f"Administrative login exposed on port {item.port}",
                    "Low",
                    5,
                    f"Login indicators were observed on {item.url}",
                    "Restrict administrative interfaces to trusted management networks.",
                )

        for item in tls.observations:
            for issue in item.security_issues:
                points, severity, recommendation = _tls_issue_policy(issue)
                self._add(
                    factors,
                    f"TLS issue on port {item.port}: {issue}",
                    severity,
                    points,
                    issue,
                    recommendation,
                )

        for item in rtsp.observations:
            if not item.detected:
                continue
            if not item.authentication_required:
                self._add(
                    factors,
                    f"Unauthenticated RTSP on port {item.port}",
                    "High",
                    25,
                    f"RTSP returned status {item.status_code} without authentication",
                    "Require RTSP authentication and restrict access by network policy.",
                )
            else:
                self._add(
                    factors,
                    f"RTSP service exposed on port {item.port}",
                    "Low",
                    5,
                    f"RTSP is reachable and requires {item.authentication_scheme or 'authentication'}",
                    "Restrict RTSP access to authorized monitoring systems.",
                )

        if onvif and onvif.status == ONVIFStatus.DETECTED:
            self._add(
                factors,
                "Unauthenticated ONVIF endpoint",
                "Medium",
                12,
                "The ONVIF device-service endpoint returned without authentication",
                "Require ONVIF authentication and restrict it to management networks.",
            )
        elif onvif and onvif.status == ONVIFStatus.AUTHENTICATION_REQUIRED:
            self._add(
                factors,
                "ONVIF endpoint exposed",
                "Low",
                3,
                "The ONVIF endpoint is reachable and requires authentication",
                "Restrict ONVIF access to authorized management systems.",
            )

        if 37777 in open_ports:
            self._add(
                factors,
                "Vendor-specific management service exposed",
                "Medium",
                8,
                "TCP port 37777 is open",
                "Restrict vendor management ports to a dedicated management VLAN.",
            )

        for record in cves.records if cves else ():
            if record.match_quality not in {"model", "firmware"}:
                continue
            if record.severity == "CRITICAL":
                points, severity = 30, "Critical"
            elif record.severity == "HIGH":
                points, severity = 20, "High"
            else:
                continue
            self._add(
                factors,
                f"{record.cve_id} vulnerability candidate",
                severity,
                points,
                (
                    f"{record.cve_id} matched at {record.match_quality} quality "
                    f"with severity {record.severity}"
                ),
                "Validate product applicability and apply the vendor security update.",
            )

        target_address = ip_address(ports.target)
        sensitive_services = open_ports.intersection(
            {21, 23, 80, 81, 443, 554, 8000, 8080, 8443, 8554, 37777}
        )
        if target_address.is_global and sensitive_services:
            self._add(
                factors,
                "Publicly routable device services",
                "High",
                20,
                f"Global IP exposes ports {sorted(sensitive_services)}",
                "Remove direct internet exposure and place the device behind controlled access.",
            )

        score = min(sum(factor.points for factor in factors), 100)
        recommendations = tuple(
            dict.fromkeys(factor.recommendation for factor in factors)
        )
        return RiskAssessmentResult(
            score=score,
            level=_risk_level(score),
            assessment_confidence=_assessment_confidence(
                ports=ports,
                http=http,
                tls=tls,
                rtsp=rtsp,
                vendor=vendor,
            ),
            factors=tuple(factors),
            recommendations=recommendations,
        )

    @staticmethod
    def _add(
        factors: list[RiskFactor],
        name: str,
        severity: str,
        points: int,
        evidence: str,
        recommendation: str,
    ) -> None:
        if any(existing.name == name for existing in factors):
            return
        factors.append(
            RiskFactor(
                name=name,
                severity=severity,
                points=points,
                evidence=evidence,
                recommendation=recommendation,
            )
        )


def _risk_level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def _tls_issue_policy(issue: str) -> tuple[int, str, str]:
    normalized = issue.lower()
    if "obsolete tls" in normalized:
        return 25, "High", "Disable obsolete TLS versions and require TLS 1.2 or later."
    if "weak cipher" in normalized:
        return 20, "High", "Disable weak cipher suites."
    if "weak certificate signature" in normalized:
        return 15, "Medium", "Replace the certificate with a SHA-256 or stronger signature."
    if "expired" in normalized or "not yet valid" in normalized:
        return 20, "High", "Install a currently valid certificate."
    if "self-signed" in normalized:
        return 8, "Medium", "Use a certificate issued by the organization trust chain."
    return 10, "Medium", "Correct the certificate trust or hostname validation failure."


def _assessment_confidence(
    ports: PortDiscoveryResult,
    http: HTTPFingerprintResult,
    tls: TLSFingerprintResult,
    rtsp: RTSPDetectionResult,
    vendor: VendorDetectionResult,
) -> int:
    """Estimate evidence completeness, not device or risk probability."""
    confidence = 40
    if ports.observations and all(
        item.state is not PortState.ERROR for item in ports.observations
    ):
        confidence += 20
    if any(item.status_code is not None for item in http.observations):
        confidence += 15
    if any(item.tls_version for item in tls.observations):
        confidence += 10
    if any(item.detected for item in rtsp.observations):
        confidence += 10
    if vendor.vendor != "Unknown":
        confidence += 5
    return min(confidence, 100)
