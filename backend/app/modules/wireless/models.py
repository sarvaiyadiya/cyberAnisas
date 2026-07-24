"""Typed domain models for Module 5 wireless intelligence."""

from enum import Enum

from datetime import datetime, timezone

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.core.api_models import ResponseMetadata
from app.core.api_models import FindingRisk, ScanStatistics, ScanSummary


class WirelessInterfaceStatus(str, Enum):
    """Normalized operational state of a wireless interface."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class WirelessInterface(BaseModel):
    """Sanitized wireless interface observation."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=255)
    platform: str
    status: WirelessInterfaceStatus
    description: str | None = Field(default=None, max_length=500)


class InterfaceDiscoveryResult(BaseModel):
    """Aggregate interface discovery result for the local host."""

    model_config = ConfigDict(frozen=True)

    platform: str
    interfaces: tuple[WirelessInterface, ...] = ()
    command_available: bool
    duration_ms: float = Field(ge=0)
    error: str | None = None


class AccessPointObservation(BaseModel):
    """Normalized observation for one BSSID."""

    model_config = ConfigDict(frozen=True)

    ssid: str = Field(max_length=255)
    bssid: str
    channel: int | None = Field(default=None, ge=1, le=233)
    frequency_mhz: int | None = Field(default=None, ge=1, le=100_000)
    band: str = "Unknown"
    signal_percent: int | None = Field(default=None, ge=0, le=100)
    rssi_dbm: int | None = Field(default=None, ge=-150, le=0)
    authentication: str = Field(default="Unknown", max_length=100)
    encryption: str = Field(default="Unknown", max_length=100)
    security_mode: str = Field(default="Unknown", max_length=100)
    cipher: str = Field(default="Unknown", max_length=100)
    pmf_support: str = Field(default="Unknown", max_length=50)
    hidden_ssid: bool = False
    wps_enabled: bool | None = None
    beacon_interval_ms: int | None = Field(default=None, ge=1, le=100_000)
    beacon_observed: bool | None = None
    probe_response_observed: bool | None = None
    channel_utilization_percent: float | None = Field(
        default=None,
        ge=0,
        le=100,
    )
    noise_dbm: int | None = Field(default=None, ge=-150, le=0)
    dfs_channel: bool | None = None
    associated_client_count: int | None = Field(default=None, ge=0)
    mesh_detected: bool | None = None
    hotspot_detected: bool | None = None
    captive_portal_detected: bool | None = None
    rogue_probability: float | None = Field(default=None, ge=0, le=1)
    evil_twin_probability: float | None = Field(default=None, ge=0, le=1)
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    interface: str | None = Field(default=None, max_length=255)
    oui: str
    vendor: str = Field(default="Unknown", max_length=500)
    manufacturer: str = Field(default="Unknown", max_length=500)
    country_code: str | None = Field(default=None, max_length=2)
    geolocation: str | None = Field(default=None, max_length=500)
    vendor_confidence: int = Field(default=0, ge=0, le=100)
    vendor_source: str | None = None
    vendor_source_available: bool = False
    device_class: str = "Unknown"
    device_class_confidence: int = Field(default=0, ge=0, le=100)
    locally_administered: bool = False
    duplicate_mac: bool = False
    suspicious_mac: bool = False
    rare_oui: bool = False
    unusual_vendor: bool = False
    evidence: tuple[str, ...] = ()
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    detection_method: str = "Operating System Wireless Enumeration"
    source: str = "local-os-wireless-scan"
    risk: FindingRisk = Field(default_factory=FindingRisk)


class MACVendorResult(BaseModel):
    """Explainable result of one local IEEE OUI lookup."""

    model_config = ConfigDict(frozen=True)

    mac: str
    oui: str
    vendor: str = "Unknown"
    confidence: int = Field(default=0, ge=0, le=100)
    source: str | None = None
    source_available: bool = False
    locally_administered: bool = False


class AccessPointScanResult(BaseModel):
    """Sanitized local access-point scan result."""

    model_config = ConfigDict(frozen=True)

    platform: str
    interface: str | None = None
    access_points: tuple[AccessPointObservation, ...] = ()
    command_available: bool
    duration_ms: float = Field(ge=0)
    limitations: tuple[str, ...] = ()
    error: str | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    statistics: ScanStatistics = Field(default_factory=ScanStatistics)


class AccessPointScanRequest(BaseModel):
    """Optional interface selection for local access-point enumeration."""

    interface: str | None = Field(default=None, min_length=1, max_length=255)
    rescan: bool = True

    @field_validator("interface")
    @classmethod
    def interface_must_be_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or any(character in normalized for character in "\r\n\0"):
            raise ValueError("Interface contains unsupported characters")
        return normalized


class AccessPointScanResponse(BaseModel):
    """Stable API envelope for access-point enumeration."""

    success: bool
    message: str
    data: AccessPointScanResult
    error: str | None = None
    metadata: ResponseMetadata


class WirelessClientStatus(str, Enum):
    """Normalized passive neighbor or lease state."""

    ACTIVE = "active"
    STALE = "stale"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"


class WirelessClientObservation(BaseModel):
    """Normalized passive client observation."""

    model_config = ConfigDict(frozen=True)

    mac: str
    ip: str
    hostname: str | None = Field(default=None, max_length=255)
    status: WirelessClientStatus
    connected_ap: str | None = None
    signal_percent: int | None = Field(default=None, ge=0, le=100)
    rssi_dbm: int | None = Field(default=None, ge=-150, le=0)
    last_seen: datetime | None = None
    device_type: str = "Unknown"
    confirmed_wireless: bool = False
    interface: str | None = Field(default=None, max_length=255)
    sources: tuple[str, ...] = ()
    oui: str
    vendor: str = Field(default="Unknown", max_length=500)
    vendor_confidence: int = Field(default=0, ge=0, le=100)
    vendor_source: str | None = None
    vendor_source_available: bool = False
    locally_administered: bool = False
    randomized_mac: bool = False
    duplicate_mac: bool = False
    suspicious_mac: bool = False


class ClientEnumerationResult(BaseModel):
    """Sanitized aggregate of passive client metadata."""

    model_config = ConfigDict(frozen=True)

    platform: str
    interface: str | None = None
    clients: tuple[WirelessClientObservation, ...] = ()
    neighbor_candidates: tuple[WirelessClientObservation, ...] = ()
    wireless_capture_available: bool = False
    explanation: str = (
        "No wireless association capture is available; passive neighbor "
        "records are returned separately as unconfirmed candidates."
    )
    command_available: bool
    duration_ms: float = Field(ge=0)
    error: str | None = None


class ClientEnumerationRequest(BaseModel):
    """Input for passive neighbor collection and optional lease import."""

    interface: str | None = Field(default=None, min_length=1, max_length=255)
    dhcp_lease_text: str | None = Field(default=None, max_length=1_000_000)

    @field_validator("interface")
    @classmethod
    def client_interface_must_be_safe(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or any(character in normalized for character in "\r\n\0"):
            raise ValueError("Interface contains unsupported characters")
        return normalized


class ClientEnumerationResponse(BaseModel):
    """Stable API envelope for passive wireless client enumeration."""

    success: bool
    message: str
    data: ClientEnumerationResult
    error: str | None = None


class AuthenticationMode(str, Enum):
    """Normalized wireless authentication categories."""

    OPEN = "Open"
    WEP = "WEP"
    WPA_PERSONAL = "WPA-Personal"
    WPA_ENTERPRISE = "WPA-Enterprise"
    WPA2_PERSONAL = "WPA2-Personal"
    WPA2_ENTERPRISE = "WPA2-Enterprise"
    WPA3_PERSONAL = "WPA3-Personal"
    WPA3_ENTERPRISE = "WPA3-Enterprise"
    IEEE8021X = "802.1X"
    UNKNOWN = "Unknown"


class AuthenticationEvidence(BaseModel):
    """Observed AP security metadata supplied to the analysis engine."""

    ssid: str = Field(default="", max_length=255)
    bssid: str
    authentication: str = Field(default="Unknown", max_length=100)
    encryption: str = Field(default="Unknown", max_length=100)
    pmf_support: str = Field(default="Unknown", max_length=50)
    mac_filtering_observed: bool | None = None

    @field_validator("bssid")
    @classmethod
    def bssid_must_be_valid(cls, value: str) -> str:
        from app.modules.wireless.utils import normalize_mac

        normalized = normalize_mac(value)
        if normalized is None:
            raise ValueError("A valid 48-bit BSSID is required")
        return normalized


class AuthenticationFinding(BaseModel):
    """One evidence-backed authentication security finding."""

    model_config = ConfigDict(frozen=True)

    title: str
    severity: str
    evidence: str
    recommendation: str


class AuthenticationAssessment(BaseModel):
    """Normalized assessment for one access point."""

    model_config = ConfigDict(frozen=True)

    ssid: str
    bssid: str
    mode: AuthenticationMode
    enterprise: bool
    ieee8021x: bool
    pmf_support: str = "Unknown"
    mac_filtering_observed: bool | None
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    findings: tuple[AuthenticationFinding, ...] = ()
    recommendations: tuple[str, ...] = ()


class MACAuthenticationLabGuide(BaseModel):
    """Documentation-only authorized lab guidance."""

    model_config = ConfigDict(frozen=True)

    automated_mac_change: bool = False
    purpose: str
    safety_checklist: tuple[str, ...]
    demonstration_steps: tuple[str, ...]
    conclusion: str


class AuthenticationAnalysisRequest(BaseModel):
    """Authentication evidence collected by the AP endpoint or an import."""

    access_points: list[AuthenticationEvidence] = Field(
        min_length=1,
        max_length=1024,
    )
    include_mac_auth_lab: bool = True


class AuthenticationAnalysisResult(BaseModel):
    """Aggregate wireless authentication analysis."""

    model_config = ConfigDict(frozen=True)

    assessments: tuple[AuthenticationAssessment, ...]
    highest_risk: str
    mac_authentication_lab: MACAuthenticationLabGuide | None = None


class AuthenticationAnalysisResponse(BaseModel):
    """Stable API envelope for authentication analysis."""

    success: bool
    message: str
    data: AuthenticationAnalysisResult
    error: str | None = None


class DeviceBehaviorRecord(BaseModel):
    """Previously collected, aggregate device behavior metadata."""

    mac: str
    traffic_volume_mb: float = Field(ge=0)
    session_duration_minutes: float = Field(ge=0)
    connection_frequency: float = Field(ge=0)
    first_seen: datetime
    last_seen: datetime

    @field_validator("mac")
    @classmethod
    def behavior_mac_must_be_valid(cls, value: str) -> str:
        from app.modules.wireless.utils import normalize_mac

        normalized = normalize_mac(value)
        if normalized is None:
            raise ValueError("A valid 48-bit MAC address is required")
        return normalized

    @model_validator(mode="after")
    def timestamps_must_be_ordered(self):
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        return self


class DeviceBehaviorAssessment(BaseModel):
    """Anomaly result for one supplied device record."""

    model_config = ConfigDict(frozen=True)

    mac: str
    anomaly: bool
    anomaly_score: float | None = None
    cluster: int | None = None
    rare_cluster: bool = False
    newly_appeared: bool = False
    evidence: tuple[str, ...] = ()


class BehaviorAnalysisResult(BaseModel):
    """Aggregate behavior-analysis execution result."""

    model_config = ConfigDict(frozen=True)

    engine: str
    sample_count: int = Field(ge=0)
    model_executed: bool
    anomaly_count: int = Field(ge=0)
    assessments: tuple[DeviceBehaviorAssessment, ...]
    explanation: str


class BehaviorAnalysisRequest(BaseModel):
    """Bounded historical metadata supplied to the anomaly engine."""

    records: list[DeviceBehaviorRecord] = Field(
        min_length=1,
        max_length=10_000,
    )
    contamination: float = Field(default=0.1, ge=0.01, le=0.5)


class BehaviorAnalysisResponse(BaseModel):
    """Stable API envelope for behavior analysis."""

    success: bool
    message: str
    data: BehaviorAnalysisResult
    error: str | None = None


class WirelessSecurityFinding(BaseModel):
    """One evidence-backed wireless security finding."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    category: str
    title: str
    severity: str
    points: int = Field(ge=0, le=100)
    evidence: str
    recommendation: str


class WirelessRiskAssessment(BaseModel):
    """Capped deterministic wireless risk assessment."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    level: str
    assessment_confidence: int = Field(ge=0, le=100)
    findings: tuple[WirelessSecurityFinding, ...] = ()
    recommendations: tuple[str, ...] = ()
    rogue_ap_indicators: tuple[str, ...] = ()


class WirelessAssessmentRequest(BaseModel):
    """Normalized evidence accepted from earlier Module 5 endpoints."""

    access_points: list[AccessPointObservation] = Field(
        default_factory=list,
        max_length=2048,
    )
    clients: list[WirelessClientObservation] = Field(
        default_factory=list,
        max_length=10_000,
    )
    authentication_assessments: list[AuthenticationAssessment] = Field(
        default_factory=list,
        max_length=2048,
    )
    behavior: BehaviorAnalysisResult | None = None


class WirelessSecurityReport(BaseModel):
    """Final normalized Module 5 assessment report."""

    model_config = ConfigDict(frozen=True)

    generated_at: datetime
    access_point_count: int = Field(ge=0)
    client_count: int = Field(ge=0)
    anomalous_device_count: int = Field(ge=0)
    security_score: int = Field(ge=0, le=100)
    risk: WirelessRiskAssessment
    summary: str


class WirelessAssessmentResponse(BaseModel):
    """Stable API envelope for the final wireless report."""

    success: bool
    message: str
    data: WirelessSecurityReport
    error: str | None = None


class WirelessFullScanRequest(BaseModel):
    """Configuration for one consolidated Module 5 execution."""

    interface: str | None = Field(default=None, min_length=1, max_length=255)
    rescan: bool = True
    dhcp_lease_text: str | None = Field(default=None, max_length=1_000_000)
    include_mac_auth_lab: bool = False
    behavior_records: list[DeviceBehaviorRecord] = Field(
        default_factory=list,
        max_length=10_000,
    )
    contamination: float = Field(default=0.1, ge=0.01, le=0.5)

    @field_validator("interface")
    @classmethod
    def full_scan_interface_must_be_safe(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or any(character in normalized for character in "\r\n\0"):
            raise ValueError("Interface contains unsupported characters")
        return normalized


class WirelessFullScanResult(BaseModel):
    """All Module 5 stage results returned by one API call."""

    model_config = ConfigDict(frozen=True)

    interfaces: InterfaceDiscoveryResult
    access_points: AccessPointScanResult
    clients: ClientEnumerationResult
    authentication: AuthenticationAnalysisResult
    behavior: BehaviorAnalysisResult | None = None
    report: WirelessSecurityReport
    metrics: "WirelessScanMetrics"
    module_health: "WirelessModuleHealth"
    analysis: "WirelessPostureAnalysis"
    stages_completed: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    duration_ms: float = Field(ge=0)


class WirelessFullScanResponse(BaseModel):
    """Stable response envelope for consolidated Module 5 execution."""

    success: bool
    message: str
    data: WirelessFullScanResult
    error: str | None = None
    metadata: ResponseMetadata


class WirelessScanMetrics(BaseModel):
    """Observable counters and explicitly bounded coverage metrics."""

    model_config = ConfigDict(frozen=True)

    scan_duration_ms: float = Field(ge=0)
    devices_discovered: int = Field(ge=0)
    access_points_discovered: int = Field(ge=0)
    hidden_networks: int = Field(ge=0)
    rogue_ap_count: int | None = Field(default=None, ge=0)
    evil_twin_candidate_count: int = Field(default=0, ge=0)
    suspicious_devices: int = Field(ge=0)
    wireless_score: int = Field(ge=0, le=100)
    coverage_percentage: float | None = Field(default=None, ge=0, le=100)
    scan_completion_percentage: float = Field(ge=0, le=100)
    interfaces_scanned: int = Field(ge=0)
    iot_devices_found: int = Field(default=0, ge=0)
    bluetooth_devices_found: int = Field(default=0, ge=0)
    protocols_detected: int = Field(default=0, ge=0)
    scan_depth: str = "local-os-metadata"


class ModuleSubmoduleStatus(BaseModel):
    """Execution state for one Module 5 capability."""

    model_config = ConfigDict(frozen=True)

    status: str
    completion_percentage: float = Field(ge=0, le=100)
    detail: str


class WirelessModuleHealth(BaseModel):
    """Honest execution and capability coverage for the combined scan."""

    model_config = ConfigDict(frozen=True)

    module: str = "Wireless Full Scan"
    status: str
    completion_percentage: float = Field(ge=0, le=100)
    submodules: dict[str, ModuleSubmoduleStatus]


class WirelessPostureAnalysis(BaseModel):
    """Evidence-based wireless posture without generative speculation."""

    model_config = ConfigDict(frozen=True)

    engine: str = "deterministic-wireless-evidence-correlation"
    wireless_attack_surface: str
    rogue_ap_probability: float | None = Field(default=None, ge=0, le=1)
    evil_twin_probability: float | None = Field(default=None, ge=0, le=1)
    weak_encryption_networks: tuple[str, ...] = ()
    open_network_count: int = Field(default=0, ge=0)
    unauthorized_device_count: int | None = Field(default=None, ge=0)
    iot_exposure_score: int | None = Field(default=None, ge=0, le=100)
    overall_wireless_security_posture: str
    recommended_mitigations: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
