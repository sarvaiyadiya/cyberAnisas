"""Final wireless security report generation."""

from __future__ import annotations

from datetime import datetime, timezone

from app.modules.wireless.models import (
    BehaviorAnalysisResult,
    WirelessRiskAssessment,
    WirelessSecurityReport,
)


class WirelessReportEngine:
    """Create a concise report from already-normalized evidence."""

    def generate(
        self,
        *,
        access_point_count: int,
        client_count: int,
        behavior: BehaviorAnalysisResult | None,
        risk: WirelessRiskAssessment,
    ) -> WirelessSecurityReport:
        """Return a report that does not expose raw collector output."""
        anomaly_count = behavior.anomaly_count if behavior else 0
        summary = (
            f"Assessed {access_point_count} access point(s) and "
            f"{client_count} passive client observation(s). "
            f"Identified {len(risk.findings)} security finding(s) and "
            f"{anomaly_count} behavior anomaly/anomalies. "
            f"Overall wireless risk is {risk.level} ({risk.score}/100)."
        )
        return WirelessSecurityReport(
            generated_at=datetime.now(timezone.utc),
            access_point_count=access_point_count,
            client_count=client_count,
            anomalous_device_count=anomaly_count,
            security_score=100 - risk.score,
            risk=risk,
            summary=summary,
        )
