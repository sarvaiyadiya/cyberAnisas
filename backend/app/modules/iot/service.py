"""Application service boundary for Module 4."""

from collections.abc import Iterable

from app.modules.iot.detectors.ports import (
    DEFAULT_IOT_TCP_PORTS,
    PortDiscoveryEngine,
)
from app.modules.iot.detectors.http import HTTPFingerprintEngine
from app.modules.iot.detectors.banners import BannerFingerprintEngine
from app.modules.iot.detectors.services import ServiceDetectionEngine
from app.modules.iot.detectors.tls import TLSFingerprintEngine
from app.modules.iot.detectors.rtsp import RTSPDetectionEngine
from app.modules.iot.detectors.onvif import ONVIFDetectionEngine
from app.modules.iot.fingerprints.vendor import VendorFingerprintEngine
from app.modules.iot.risk import RiskAssessmentEngine
from app.modules.iot.summary import SecuritySummaryEngine
from app.modules.iot.fingerprints.classifier import DeviceClassificationEngine
from app.modules.iot.fingerprints.firmware import FirmwareDetectionEngine
from app.modules.iot.clients.cve_client import CVEIntelligenceClient
from app.modules.iot.report import InventoryReportEngine
from app.modules.iot.cache import IoTScanCache
from app.modules.iot.engine import IoTFingerprintEngine
from app.modules.iot.models import HTTPFingerprintScanResult, PortDiscoveryResult


class IoTFingerprintingService:
    """
    Stable entry point for API and future ANISAS modules.

    Later fingerprint engines will be composed here without changing callers.
    """

    def __init__(
        self,
        port_engine: PortDiscoveryEngine | None = None,
        http_engine: HTTPFingerprintEngine | None = None,
        banner_engine: BannerFingerprintEngine | None = None,
        service_engine: ServiceDetectionEngine | None = None,
        tls_engine: TLSFingerprintEngine | None = None,
        rtsp_engine: RTSPDetectionEngine | None = None,
        onvif_engine: ONVIFDetectionEngine | None = None,
        vendor_engine: VendorFingerprintEngine | None = None,
        risk_engine: RiskAssessmentEngine | None = None,
        summary_engine: SecuritySummaryEngine | None = None,
        classification_engine: DeviceClassificationEngine | None = None,
        firmware_engine: FirmwareDetectionEngine | None = None,
        cve_client: CVEIntelligenceClient | None = None,
        report_engine: InventoryReportEngine | None = None,
        scan_cache: IoTScanCache | None = None,
    ) -> None:
        self._port_engine = port_engine or PortDiscoveryEngine()
        self._engine = IoTFingerprintEngine(
            port_engine=self._port_engine,
            http_engine=http_engine,
            banner_engine=banner_engine,
            service_engine=service_engine,
            tls_engine=tls_engine,
            rtsp_engine=rtsp_engine,
            onvif_engine=onvif_engine,
            vendor_engine=vendor_engine,
            risk_engine=risk_engine,
            summary_engine=summary_engine,
            classification_engine=classification_engine,
            firmware_engine=firmware_engine,
            cve_client=cve_client,
            report_engine=report_engine,
        )
        self._scan_cache = scan_cache or IoTScanCache()

    def discover_ports(
        self,
        target: str,
        ports: Iterable[int] | None = None,
    ) -> PortDiscoveryResult:
        """Run the completed Phase 3 detector for one IPv4 target."""
        return self._port_engine.scan(
            target=target,
            ports=ports if ports is not None else DEFAULT_IOT_TCP_PORTS,
        )

    def fingerprint_http(
        self,
        target: str,
        ports: Iterable[int] | None = None,
    ) -> HTTPFingerprintScanResult:
        """Execute the integrated port-discovery and HTTP pipeline."""
        normalized_ports = tuple(ports) if ports is not None else None
        cached = self._scan_cache.get(target, normalized_ports)
        if cached is not None:
            return cached.model_copy(update={"cache_status": "HIT"})
        result = self._engine.fingerprint_http(
            target=target,
            ports=normalized_ports,
        )
        self._scan_cache.set(target, normalized_ports, result)
        return result


_service = IoTFingerprintingService()


def get_iot_service() -> IoTFingerprintingService:
    """FastAPI dependency provider for the Module 4 service."""
    return _service
