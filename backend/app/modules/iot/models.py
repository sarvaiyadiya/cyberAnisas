"""Typed domain models shared by IoT fingerprinting engines."""

from enum import Enum
from ipaddress import IPv4Address, ip_address

from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class PortState(str, Enum):
    """Observable TCP port states produced by the discovery engine."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"


class PortObservation(BaseModel):
    """Result of one TCP connection attempt."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    state: PortState
    latency_ms: float | None = Field(default=None, ge=0)
    error: str | None = None


class PortDiscoveryResult(BaseModel):
    """Sanitized aggregate returned by the port discovery engine."""

    model_config = ConfigDict(frozen=True)

    target: str
    open_ports: tuple[int, ...] = ()
    observations: tuple[PortObservation, ...] = ()
    scanned_port_count: int = Field(ge=0)
    duration_ms: float = Field(ge=0)

    @field_validator("target")
    @classmethod
    def target_must_be_ipv4(cls, value: str) -> str:
        """Reject hostnames and IPv6 at the module boundary."""
        parsed = ip_address(value)
        if not isinstance(parsed, IPv4Address):
            raise ValueError("Module 4 Version 1 accepts IPv4 addresses only")
        return str(parsed)


class BannerObservation(BaseModel):
    """Sanitized application-layer banner evidence from one open port."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    banner: str | None = Field(
        default=None,
        description="Sanitized and size-bounded banner text.",
    )
    normalized_banner: str | None = None
    vendor_hints: tuple[str, ...] = ()
    bytes_received: int = Field(default=0, ge=0)
    truncated: bool = False
    responded: bool = False
    error: str | None = None


class BannerDiscoveryResult(BaseModel):
    """Aggregate banner evidence for a single IPv4 target."""

    model_config = ConfigDict(frozen=True)

    target: str
    observations: tuple[BannerObservation, ...] = ()
    duration_ms: float = Field(ge=0)


class ServiceObservation(BaseModel):
    """Normalized service identity for one confirmed open TCP port."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    status: str = "open"
    service: str
    product: str | None = None
    confidence: int = Field(ge=0, le=100)
    evidence: tuple[str, ...] = ()


class ServiceDetectionResult(BaseModel):
    """Aggregate service identities for one IPv4 target."""

    model_config = ConfigDict(frozen=True)

    target: str
    observations: tuple[ServiceObservation, ...] = ()
    duration_ms: float = Field(ge=0)


class HTTPObservation(BaseModel):
    """Sanitized evidence collected from one HTTP endpoint."""

    model_config = ConfigDict(frozen=True)

    url: str
    port: int = Field(ge=1, le=65535)
    scheme: str
    path: str
    status_code: int | None = Field(default=None, ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    title: str | None = None
    server: str | None = None
    x_powered_by: str | None = None
    authentication: str | None = None
    cookie_names: tuple[str, ...] = ()
    meta_generator: str | None = None
    technologies: tuple[str, ...] = ()
    security_headers: dict[str, str] = Field(default_factory=dict)
    missing_security_headers: tuple[str, ...] = ()
    login_markers: tuple[str, ...] = ()
    vendor_hints: tuple[str, ...] = ()
    redirect_location: str | None = None
    favicon_sha256: str | None = None
    content_type: str | None = None
    bytes_received: int = Field(default=0, ge=0)
    latency_ms: float | None = Field(default=None, ge=0)
    tls_validation_failed: bool = False
    truncated: bool = False
    error: str | None = None


class HTTPFingerprintResult(BaseModel):
    """Aggregate HTTP evidence for a single IPv4 target."""

    model_config = ConfigDict(frozen=True)

    target: str
    observations: tuple[HTTPObservation, ...] = ()
    duration_ms: float = Field(ge=0)


class TLSObservation(BaseModel):
    """Certificate and negotiated-protocol evidence from one TLS endpoint."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    tls_version: str | None = None
    cipher_suite: str | None = None
    cipher_bits: int | None = Field(default=None, ge=0)
    signature_algorithm: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    common_name: str | None = None
    subject_alt_names: tuple[str, ...] = ()
    serial_number: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    self_signed: bool | None = None
    expired: bool | None = None
    certificate_validated: bool = False
    validation_error: str | None = None
    vendor_hints: tuple[str, ...] = ()
    security_issues: tuple[str, ...] = ()
    latency_ms: float | None = Field(default=None, ge=0)
    error: str | None = None


class TLSFingerprintResult(BaseModel):
    """Aggregate TLS evidence for one IPv4 target."""

    model_config = ConfigDict(frozen=True)

    target: str
    observations: tuple[TLSObservation, ...] = ()
    duration_ms: float = Field(ge=0)


class VendorAlternative(BaseModel):
    """A non-primary vendor candidate supported by observed evidence."""

    model_config = ConfigDict(frozen=True)

    vendor: str
    confidence: int = Field(ge=0, le=100)


class VendorDetectionResult(BaseModel):
    """Explainable vendor-correlation result."""

    model_config = ConfigDict(frozen=True)

    vendor: str = "Unknown"
    confidence: int = Field(default=0, ge=0, le=100)
    matching_evidence: tuple[str, ...] = ()
    alternative_vendors: tuple[VendorAlternative, ...] = ()


class RTSPObservation(BaseModel):
    """Normalized result of one safe RTSP OPTIONS request."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    detected: bool = False
    status_code: int | None = Field(default=None, ge=100, le=599)
    server: str | None = None
    public_methods: tuple[str, ...] = ()
    authentication_required: bool = False
    authentication_scheme: str | None = None
    vendor_hints: tuple[str, ...] = ()
    latency_ms: float | None = Field(default=None, ge=0)
    truncated: bool = False
    error: str | None = None


class RTSPDetectionResult(BaseModel):
    """Aggregate RTSP evidence for one IPv4 target."""

    model_config = ConfigDict(frozen=True)

    target: str
    observations: tuple[RTSPObservation, ...] = ()
    duration_ms: float = Field(ge=0)


class ONVIFStatus(str, Enum):
    """Normalized ONVIF endpoint detection states."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    AUTHENTICATION_REQUIRED = "authentication_required"
    UNKNOWN = "unknown"
    ERROR = "error"


class ONVIFObservation(BaseModel):
    """Safe observation from the standard ONVIF device-service endpoint."""

    model_config = ConfigDict(frozen=True)

    endpoint: str
    port: int = Field(ge=1, le=65535)
    status: ONVIFStatus
    http_status: int | None = Field(default=None, ge=100, le=599)
    soap_response: bool = False
    authentication_required: bool = False
    vendor_hints: tuple[str, ...] = ()
    latency_ms: float | None = Field(default=None, ge=0)
    error: str | None = None


class ONVIFDetectionResult(BaseModel):
    """Aggregate ONVIF evidence for one IPv4 target."""

    model_config = ConfigDict(frozen=True)

    target: str
    status: ONVIFStatus = ONVIFStatus.UNKNOWN
    observations: tuple[ONVIFObservation, ...] = ()
    duration_ms: float = Field(ge=0)


class ClassificationAlternative(BaseModel):
    """A supported non-primary device classification."""

    model_config = ConfigDict(frozen=True)

    device_type: str
    confidence: int = Field(ge=0, le=100)


class DeviceClassificationResult(BaseModel):
    """Weighted, explainable device classification."""

    model_config = ConfigDict(frozen=True)

    device_type: str = "Unknown"
    confidence: int = Field(default=0, ge=0, le=100)
    alternatives: tuple[ClassificationAlternative, ...] = ()
    evidence: tuple[str, ...] = ()
    explanation: str = "Insufficient evidence for a reliable classification."


class FirmwareDetectionResult(BaseModel):
    """Observed model and firmware identifiers without inference."""

    model_config = ConfigDict(frozen=True)

    model: str = "Unknown"
    firmware: str = "Unknown"
    confidence: int = Field(default=0, ge=0, le=100)
    evidence: tuple[str, ...] = ()


class CVERecord(BaseModel):
    """Normalized vulnerability candidate from an external CVE source."""

    model_config = ConfigDict(frozen=True)

    cve_id: str
    severity: str = "UNKNOWN"
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_version: str | None = None
    description: str
    reference: str | None = None
    match_quality: str


class CVEIntelligenceResult(BaseModel):
    """CVE lookup outcome, including source availability."""

    model_config = ConfigDict(frozen=True)

    source: str = "NVD"
    lookup_attempted: bool = False
    source_available: bool = True
    query: str | None = None
    records: tuple[CVERecord, ...] = ()
    error: str | None = None


class RiskFactor(BaseModel):
    """One evidence-backed contribution to the final risk score."""

    model_config = ConfigDict(frozen=True)

    name: str
    severity: str
    points: int = Field(ge=0, le=100)
    evidence: str
    recommendation: str


class RiskAssessmentResult(BaseModel):
    """Deterministic security risk assessment for one target."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    level: str
    assessment_confidence: int = Field(ge=0, le=100)
    factors: tuple[RiskFactor, ...] = ()
    recommendations: tuple[str, ...] = ()


class SecuritySummaryResult(BaseModel):
    """Concise evidence-grounded summary of the fingerprint result."""

    model_config = ConfigDict(frozen=True)

    text: str
    word_count: int = Field(ge=0, le=100)
    generator: str = "deterministic-evidence-rules"


class DeviceInventoryReport(BaseModel):
    """Flattened, evidence-backed inventory record for one scanned device."""

    model_config = ConfigDict(frozen=True)

    target: str
    device_detected: bool
    device_type: str
    classification_confidence: int = Field(ge=0, le=100)
    vendor: str
    vendor_confidence: int = Field(ge=0, le=100)
    model: str
    firmware: str
    open_ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    http_titles: tuple[str, ...] = ()
    http_server: str | None = None
    http_title: str | None = None
    banner: str | None = None
    mac_vendor: str | None = None
    server_products: tuple[str, ...] = ()
    onvif_status: ONVIFStatus
    rtsp_detected: bool
    cve_candidates: tuple[str, ...] = ()
    known_cves: tuple[CVERecord, ...] = ()
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    summary: str


class HTTPFingerprintScanResult(BaseModel):
    """Integrated Module 4 network fingerprint pipeline result."""

    model_config = ConfigDict(frozen=True)

    target: str
    port_discovery: PortDiscoveryResult
    service_detection: ServiceDetectionResult
    banner_discovery: BannerDiscoveryResult
    http: HTTPFingerprintResult
    tls: TLSFingerprintResult
    rtsp: RTSPDetectionResult
    onvif: ONVIFDetectionResult
    vendor: VendorDetectionResult
    classification: DeviceClassificationResult
    firmware: FirmwareDetectionResult
    cves: CVEIntelligenceResult
    risk: RiskAssessmentResult
    summary: SecuritySummaryResult
    report: DeviceInventoryReport
    cache_status: str = "MISS"
    duration_ms: float = Field(ge=0)


class IoTPortDiscoveryRequest(BaseModel):
    """
    API input for Module 4 port discovery.

    Accepts either a direct ``{"ip": "..."}`` request or an upstream ANISAS
    response envelope containing the target at ``data.ip``. The latter is
    normalized without importing or depending on any upstream module model.
    """

    ip: str = Field(description="Single IPv4 address to scan.")
    ports: list[int] | None = Field(
        default=None,
        description=(
            "Optional explicit TCP ports. When omitted, the curated IoT and "
            "surveillance port set is used."
        ),
        max_length=1024,
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_upstream_envelope(cls, value: Any) -> Any:
        """Extract ``data.ip`` from a successful upstream module response."""
        if not isinstance(value, dict) or value.get("ip") is not None:
            return value
        if value.get("success") is False:
            return value

        upstream_data = value.get("data")
        if not isinstance(upstream_data, dict) or not upstream_data.get("ip"):
            return value

        normalized: dict[str, Any] = {
            "ip": upstream_data["ip"],
        }
        if value.get("ports") is not None:
            normalized["ports"] = value["ports"]
        return normalized

    @field_validator("ip")
    @classmethod
    def ip_must_be_ipv4(cls, value: str) -> str:
        """Validate without performing hostname or DNS resolution."""
        try:
            parsed = ip_address(value.strip())
        except (AttributeError, ValueError) as exc:
            raise ValueError("A valid IPv4 address is required") from exc
        if not isinstance(parsed, IPv4Address):
            raise ValueError("Module 4 Version 1 accepts IPv4 addresses only")
        return str(parsed)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "ip": "192.168.1.20",
                    "ports": [80, 443, 554, 8000],
                },
                {
                    "success": True,
                    "message": "Upstream intelligence lookup completed",
                    "data": {"ip": "192.168.1.20"},
                },
            ]
        }
    )


class IoTPortDiscoveryResponse(BaseModel):
    """Stable API response envelope for Module 4 port discovery."""

    success: bool
    message: str
    data: PortDiscoveryResult


class IoTHTTPFingerprintResponse(BaseModel):
    """Production API envelope for the integrated HTTP pipeline."""

    success: bool
    message: str
    data: HTTPFingerprintScanResult
