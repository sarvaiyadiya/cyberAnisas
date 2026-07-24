"""FastAPI boundary for Module 4: Surveillance & IoT Fingerprinting."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.logger import get_logger
from app.modules.iot.exceptions import (
    InvalidTargetError,
    PortDiscoveryError,
    PortScanConfigurationError,
)
from app.modules.iot.models import (
    IoTHTTPFingerprintResponse,
    IoTPortDiscoveryRequest,
    IoTPortDiscoveryResponse,
)
from app.modules.iot.service import (
    IoTFingerprintingService,
    get_iot_service,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/iot",
    tags=["Module 4 — Surveillance & IoT Device Fingerprinting"],
)


@router.post(
    "/fingerprint",
    response_model=IoTHTTPFingerprintResponse,
    summary="Run surveillance and IoT fingerprinting",
    description=(
        "Discovers TCP ports and performs bounded banner, HTTP/HTTPS, TLS, "
        "RTSP, and ONVIF fingerprinting, then correlates service, vendor, "
        "device type, firmware, CVE candidates, risk, and inventory evidence. "
        "Accepts a direct `ip` body or an upstream ANISAS response containing "
        "`data.ip`."
    ),
    responses={
        200: {"description": "Module 4 fingerprinting completed."},
        422: {"description": "Invalid IPv4 address or port configuration."},
        500: {"description": "Fingerprinting could not be executed."},
    },
)
def fingerprint_iot_http(
    request: IoTPortDiscoveryRequest,
    service: IoTFingerprintingService = Depends(get_iot_service),
) -> IoTHTTPFingerprintResponse:
    """Execute the Module 4 HTTP pipeline through the service layer."""
    try:
        result = service.fingerprint_http(request.ip, request.ports)
    except (InvalidTargetError, PortScanConfigurationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except PortDiscoveryError as exc:
        logger.error("Module 4 HTTP fingerprinting failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="HTTP/HTTPS fingerprinting could not be completed",
        ) from exc

    return IoTHTTPFingerprintResponse(
        success=True,
        message="Surveillance and IoT fingerprinting completed",
        data=result,
    )


@router.post(
    "/ports/discover",
    response_model=IoTPortDiscoveryResponse,
    summary="Discover IoT and surveillance TCP ports",
    description=(
        "Phase 3 of Module 4. Performs bounded TCP connect discovery against "
        "one IPv4 address. Accepts either a direct body with `ip`, or an ANISAS "
        "upstream response envelope containing `data.ip`. It returns normalized "
        "observations and never exposes raw scanner output. Device fingerprint "
        "correlation is added in later Module 4 phases."
    ),
    responses={
        200: {"description": "Port discovery completed."},
        422: {"description": "Invalid IPv4 address or port configuration."},
        500: {"description": "Port discovery could not be executed."},
    },
)
def discover_iot_ports(
    request: IoTPortDiscoveryRequest,
    service: IoTFingerprintingService = Depends(get_iot_service),
) -> IoTPortDiscoveryResponse:
    """Delegate port discovery to the Module 4 service layer."""
    try:
        result = service.discover_ports(request.ip, request.ports)
    except (InvalidTargetError, PortScanConfigurationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except PortDiscoveryError as exc:
        logger.error("Module 4 port discovery failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Port discovery could not be completed",
        ) from exc

    return IoTPortDiscoveryResponse(
        success=True,
        message="TCP port discovery completed",
        data=result,
    )
