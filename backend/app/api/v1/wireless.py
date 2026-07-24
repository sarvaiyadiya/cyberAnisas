"""FastAPI boundary for Module 5 wireless intelligence."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.api_models import ResponseMetadata
from app.modules.wireless.models import (
    AccessPointScanRequest,
    AccessPointScanResponse,
    ClientEnumerationRequest,
    ClientEnumerationResponse,
    AuthenticationAnalysisRequest,
    AuthenticationAnalysisResponse,
    BehaviorAnalysisRequest,
    BehaviorAnalysisResponse,
    WirelessAssessmentRequest,
    WirelessAssessmentResponse,
    WirelessFullScanRequest,
    WirelessFullScanResponse,
)
from app.modules.wireless.service import (
    WirelessIntelligenceService,
    get_wireless_service,
)
from app.modules.wireless.exceptions import BehaviorEngineUnavailable

router = APIRouter(
    prefix="/wireless",
    tags=["Module 5 — Wireless Network Intelligence & MAC Analysis"],
)


@router.post(
    "/full-scan",
    response_model=WirelessFullScanResponse,
    summary="Run the complete Module 5 wireless analysis session",
    description=(
        "Runs interface discovery, access-point enumeration, passive client "
        "evidence collection, authentication analysis, optional historical "
        "behavior analysis, and final risk reporting in one request. Existing "
        "individual Module 5 endpoints remain available."
    ),
)
def run_wireless_full_scan(
    request: WirelessFullScanRequest,
    service: WirelessIntelligenceService = Depends(get_wireless_service),
) -> WirelessFullScanResponse:
    """Return all applicable Module 5 stages in one response."""
    try:
        result = service.run_full_scan(request)
    except BehaviorEngineUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    sources = [
        f"{result.access_points.platform.lower()}-native-wireless-scan",
        "passive-neighbor-table",
        "wireless-authentication-rules",
        "wireless-risk-assessment",
    ]
    if result.behavior and result.behavior.model_executed:
        sources.append(result.behavior.engine)
    return WirelessFullScanResponse(
        success=True,
        message="Complete Module 5 wireless analysis session completed",
        data=result,
        metadata=ResponseMetadata(
            sources_used=tuple(sources),
            confidence_score=(
                result.report.risk.assessment_confidence / 100
            ),
            lookup_duration_ms=round(result.duration_ms),
            detection_engine="ANISAS Module 5 Orchestrator",
            scan_mode="combined-local-session",
        ),
    )


@router.post(
    "/access-points",
    response_model=AccessPointScanResponse,
    summary="Enumerate nearby wireless access points",
    description=(
        "Executes a bounded, read-only local operating-system wireless scan "
        "and returns normalized access-point metadata. It does not connect to "
        "or modify any wireless network."
    ),
)
def scan_access_points(
    request: AccessPointScanRequest,
    service: WirelessIntelligenceService = Depends(get_wireless_service),
) -> AccessPointScanResponse:
    """Delegate access-point enumeration to the Module 5 service."""
    result = service.scan_access_points(
        interface=request.interface,
        rescan=request.rescan,
    )
    return AccessPointScanResponse(
        success=True,
        message="Wireless access-point enumeration completed",
        data=result,
        metadata=ResponseMetadata(
            sources_used=_access_point_sources(result),
            confidence_score=_access_point_confidence(result),
            lookup_duration_ms=round(result.duration_ms),
            detection_engine="ANISAS Wireless Enumeration",
            scan_mode="local-os-enumeration",
        ),
    )


def _access_point_sources(result) -> tuple[str, ...]:
    """Return only collectors and registries actually represented."""
    sources = [f"{result.platform.lower()}-native-wireless-scan"]
    if any(item.vendor_source_available for item in result.access_points):
        sources.append("IEEE MA-L OUI registry")
    return tuple(sources)


def _access_point_confidence(result) -> float:
    """Summarize evidence quality without treating absence as certainty."""
    if not result.access_points:
        return 0.0
    scores = [
        (item.vendor_confidence + item.device_class_confidence) / 200
        for item in result.access_points
    ]
    return round(sum(scores) / len(scores), 3)


@router.post(
    "/clients",
    response_model=ClientEnumerationResponse,
    summary="Enumerate passive wireless client evidence",
    description=(
        "Reads the local ARP or neighbor table and optionally parses bounded "
        "DHCP lease text. It performs no ping sweep, packet capture, or "
        "connection to discovered clients."
    ),
)
def enumerate_clients(
    request: ClientEnumerationRequest,
    service: WirelessIntelligenceService = Depends(get_wireless_service),
) -> ClientEnumerationResponse:
    """Delegate passive client enumeration to the Module 5 service."""
    result = service.enumerate_clients(
        interface=request.interface,
        dhcp_lease_text=request.dhcp_lease_text,
    )
    return ClientEnumerationResponse(
        success=True,
        message="Passive wireless client enumeration completed",
        data=result,
    )


@router.post(
    "/authentication",
    response_model=AuthenticationAnalysisResponse,
    summary="Analyze wireless authentication evidence",
    description=(
        "Classifies supplied AP security metadata and returns deterministic "
        "risk findings. It does not attempt credentials, connect to an AP, "
        "or change any MAC address."
    ),
)
def analyze_authentication(
    request: AuthenticationAnalysisRequest,
    service: WirelessIntelligenceService = Depends(get_wireless_service),
) -> AuthenticationAnalysisResponse:
    """Delegate authentication evidence analysis to Module 5."""
    result = service.analyze_authentication(
        access_points=request.access_points,
        include_mac_auth_lab=request.include_mac_auth_lab,
    )
    return AuthenticationAnalysisResponse(
        success=True,
        message="Wireless authentication analysis completed",
        data=result,
    )


@router.post(
    "/behavior",
    response_model=BehaviorAnalysisResponse,
    summary="Analyze historical wireless device behavior",
    description=(
        "Runs standardized Isolation Forest analysis on supplied aggregate "
        "metadata. It does not capture packets or collect traffic."
    ),
    responses={
        503: {"description": "The configured ML engine is unavailable."},
    },
)
def analyze_behavior(
    request: BehaviorAnalysisRequest,
    service: WirelessIntelligenceService = Depends(get_wireless_service),
) -> BehaviorAnalysisResponse:
    """Delegate bounded behavior analysis to the Module 5 service."""
    try:
        result = service.analyze_behavior(
            records=request.records,
            contamination=request.contamination,
        )
    except BehaviorEngineUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return BehaviorAnalysisResponse(
        success=True,
        message="Wireless behavior analysis completed",
        data=result,
    )


@router.post(
    "/report",
    response_model=WirelessAssessmentResponse,
    summary="Generate a wireless security assessment report",
    description=(
        "Correlates normalized outputs from Module 5 access-point, client, "
        "authentication, and behavior stages into findings and risk. Raw "
        "command output is not accepted or returned."
    ),
)
def generate_wireless_report(
    request: WirelessAssessmentRequest,
    service: WirelessIntelligenceService = Depends(get_wireless_service),
) -> WirelessAssessmentResponse:
    """Delegate assessment correlation and report generation."""
    result = service.generate_report(request)
    return WirelessAssessmentResponse(
        success=True,
        message="Wireless security assessment report generated",
        data=result,
    )
