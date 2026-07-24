"""Shared, domain-neutral API and scan-result models."""

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class ResponseMetadata(BaseModel):
    """Evidence provenance and timing for an API operation."""

    model_config = ConfigDict(frozen=True)

    sources_used: tuple[str, ...] = ()
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    lookup_duration_ms: int = Field(default=0, ge=0)
    endpoint_version: str = "v1"
    scanner_version: str = "1.0.0"
    detection_engine: str
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    scan_mode: str
    execution_status: str = "completed"


class FindingRisk(BaseModel):
    """Evidence-specific risk without implying an unobserved vulnerability."""

    model_config = ConfigDict(frozen=True)

    severity: str = "Unknown"
    exposure_level: str = "Unknown"
    vulnerable_service: bool = False
    insecure_configurations: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    detection_method: str = "Evidence Correlation"
    source: str = "risk-assessment-engine"


class ScanSummary(BaseModel):
    """Concise deterministic scan outcome."""

    model_config = ConfigDict(frozen=True)

    total_findings: int = Field(default=0, ge=0)
    important_findings: int = Field(default=0, ge=0)
    high_risk_findings: int = Field(default=0, ge=0)
    conclusion: str = "No scan conclusion is available."


class ScanStatistics(BaseModel):
    """Endpoint-local execution counters."""

    model_config = ConfigDict(frozen=True)

    total_objects_scanned: int = Field(default=0, ge=0)
    successful_detections: int = Field(default=0, ge=0)
    failed_detections: int = Field(default=0, ge=0)
    skipped_items: int = Field(default=0, ge=0)
    elapsed_scan_ms: float = Field(default=0, ge=0)
