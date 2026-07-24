"""Optional credentialed IP threat and reputation clients."""

from app.core.config import settings
from app.core.http_client import HTTPClient
from app.modules.asn.models import ReputationIntelligence, ThreatIntelligence


class AbuseIPDBClient:
    def __init__(self, api_key: str | None = None, client=None) -> None:
        self._key = api_key if api_key is not None else settings.ABUSEIPDB_API_KEY
        self._client = client or HTTPClient()

    def lookup(self, ip: str) -> ThreatIntelligence:
        if not self._key:
            return ThreatIntelligence()
        payload = self._client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            extra_headers={"Key": self._key},
        )
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        if not data:
            return ThreatIntelligence(status="unavailable")
        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports")
        return ThreatIntelligence(
            status="available",
            malicious=bool(score and score >= 50),
            abuse_confidence_score=score,
            total_reports=reports,
            last_reported_at=data.get("lastReportedAt"),
            usage_type=data.get("usageType"),
            evidence=[
                f"Abuse confidence score: {score}",
                f"Reports in lookback window: {reports}",
            ],
        )


class VirusTotalClient:
    def __init__(self, api_key: str | None = None, client=None) -> None:
        self._key = api_key if api_key is not None else settings.VIRUSTOTAL_API_KEY
        self._client = client or HTTPClient()

    def lookup(self, ip: str) -> ReputationIntelligence:
        if not self._key:
            return ReputationIntelligence()
        payload = self._client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            extra_headers={"x-apikey": self._key},
        )
        attributes = (
            payload.get("data", {}).get("attributes", {})
            if isinstance(payload, dict)
            else {}
        )
        stats = attributes.get("last_analysis_stats", {})
        if not stats:
            return ReputationIntelligence(status="unavailable")
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        score = round(100 * (malicious + 0.5 * suspicious) / total) if total else 0
        classification = "malicious" if malicious else "suspicious" if suspicious else "clean"
        return ReputationIntelligence(
            status="available",
            score=score,
            classification=classification,
            malicious_engines=malicious,
            suspicious_engines=suspicious,
            harmless_engines=harmless,
            undetected_engines=undetected,
            evidence=[
                f"Malicious engine verdicts: {malicious}",
                f"Suspicious engine verdicts: {suspicious}",
            ],
        )
