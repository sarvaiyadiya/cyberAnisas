"""NVD CVE API 2.0 client with conservative match labelling."""

from __future__ import annotations

from app.core.config import settings
from app.core.http_client import HTTPClient
from app.modules.iot.models import CVEIntelligenceResult, CVERecord

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEIntelligenceClient:
    """Look up bounded CVE candidates using observed identity fields."""

    def __init__(
        self,
        http_client: HTTPClient | None = None,
        max_results: int = settings.IOT_CVE_MAX_RESULTS,
    ) -> None:
        if not 1 <= max_results <= 20:
            raise ValueError("CVE result limit must be between 1 and 20")
        headers = (
            {"apiKey": settings.NVD_API_KEY}
            if settings.NVD_API_KEY
            else None
        )
        self._http = http_client or HTTPClient(
            timeout=settings.REQUEST_TIMEOUT,
            default_headers=headers,
        )
        self._max_results = max_results

    def lookup(
        self,
        vendor: str,
        model: str,
        firmware: str,
    ) -> CVEIntelligenceResult:
        """Return candidates without claiming affected status."""
        if vendor == "Unknown":
            return CVEIntelligenceResult(
                lookup_attempted=False,
                source_available=True,
            )

        identity = [vendor]
        match_quality = "vendor-only"
        if model != "Unknown":
            identity.append(model)
            match_quality = "model"
        if firmware != "Unknown":
            identity.append(firmware)
            match_quality = "firmware"
        query = " ".join(identity)
        payload = self._http.get(
            NVD_CVE_API,
            params={
                "keywordSearch": query,
                "resultsPerPage": self._max_results,
            },
        )
        if payload is None:
            return CVEIntelligenceResult(
                lookup_attempted=True,
                source_available=False,
                query=query,
                error="NVD source unavailable",
            )

        records = tuple(
            record
            for item in payload.get("vulnerabilities", [])[: self._max_results]
            if (record := _parse_nvd_record(item, match_quality)) is not None
        )
        return CVEIntelligenceResult(
            lookup_attempted=True,
            source_available=True,
            query=query,
            records=records,
        )


def _parse_nvd_record(
    wrapper: dict,
    match_quality: str,
) -> CVERecord | None:
    cve = wrapper.get("cve")
    if not isinstance(cve, dict) or not cve.get("id"):
        return None
    description = next(
        (
            item.get("value")
            for item in cve.get("descriptions", [])
            if item.get("lang") == "en" and item.get("value")
        ),
        "Description unavailable.",
    )
    score, severity, version = _cvss(cve.get("metrics", {}))
    reference = next(
        (
            item.get("url")
            for item in cve.get("references", [])
            if item.get("url")
        ),
        None,
    )
    return CVERecord(
        cve_id=str(cve["id"]),
        severity=severity,
        cvss_score=score,
        cvss_version=version,
        description=str(description)[:2000],
        reference=reference,
        match_quality=match_quality,
    )


def _cvss(metrics: dict) -> tuple[float | None, str, str | None]:
    for key in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        values = metrics.get(key)
        if not values:
            continue
        metric = values[0]
        data = metric.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        return (
            float(score) if score is not None else None,
            str(severity or "UNKNOWN").upper(),
            str(data.get("version")) if data.get("version") else None,
        )
    return None, "UNKNOWN", None
