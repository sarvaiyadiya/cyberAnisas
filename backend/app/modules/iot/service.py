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
from app.modules.iot.models import PortState
from app.core.api_models import FindingRisk, ScanStatistics, ScanSummary


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
        """Discover ports and enrich open ports with bounded service evidence."""
        pipeline = self.fingerprint_http(target=target, ports=ports)
        services = {
            item.port: item
            for item in pipeline.service_detection.observations
        }
        banners = {
            item.port: item
            for item in pipeline.banner_discovery.observations
        }
        tls_ports = {
            item.port for item in pipeline.tls.observations if not item.error
        }
        observations = []
        high_risk = 0
        important = 0
        for item in pipeline.port_discovery.observations:
            service = services.get(item.port)
            banner = banners.get(item.port)
            risk = _service_risk(service.service if service else "Unknown")
            if risk.severity in {"High", "Critical"}:
                high_risk += 1
            if risk.severity in {"Medium", "High", "Critical"}:
                important += 1
            evidence = list(item.evidence)
            if service:
                evidence.extend(service.evidence)
            if banner and banner.normalized_banner:
                evidence.append(
                    f"Application banner: {banner.normalized_banner}"
                )
            observations.append(
                item.model_copy(
                    update={
                        "service": service.service if service else "Unknown",
                        "banner": (
                            banner.normalized_banner if banner else None
                        ),
                        "version": (
                            banner.normalized_banner if banner else None
                        ),
                        "product": service.product if service else None,
                        "tls_support": item.port in tls_ports,
                        "exploit_risk": risk.severity,
                        "service_fingerprint": (
                            service.product
                            if service and service.product
                            else banner.normalized_banner
                            if banner
                            else None
                        ),
                        "evidence": tuple(dict.fromkeys(evidence)),
                        "confidence": (
                            service.confidence / 100
                            if service
                            else item.confidence
                        ),
                        "detection_method": (
                            "Banner Analysis and Protocol Identification"
                            if service
                            else "Active Scan"
                        ),
                        "source": (
                            "service-detection-engine"
                            if service
                            else "tcp-connect"
                        ),
                        "risk": risk,
                    }
                )
            )
        port_result = pipeline.port_discovery
        return port_result.model_copy(
            update={
                "observations": tuple(observations),
                "duration_ms": pipeline.duration_ms,
                "exposure_score": pipeline.risk.score,
                "network_risk": pipeline.risk.level,
                "recommendations": pipeline.risk.recommendations,
                "summary": ScanSummary(
                    total_findings=len(port_result.open_ports),
                    important_findings=important,
                    high_risk_findings=high_risk,
                    conclusion=(
                        f"Identified {len(port_result.open_ports)} open "
                        f"service endpoint(s); {high_risk} have high or "
                        "critical exposure based on observed service evidence."
                    ),
                ),
                "statistics": ScanStatistics(
                    total_objects_scanned=port_result.scanned_port_count,
                    successful_detections=len(port_result.open_ports),
                    failed_detections=sum(
                        item.state is PortState.ERROR
                        for item in port_result.observations
                    ),
                    elapsed_scan_ms=pipeline.duration_ms,
                ),
                "capabilities": pipeline.capabilities,
            }
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


def _service_risk(service: str) -> FindingRisk:
    """Map an observed service to conservative exposure guidance."""
    normalized = service.upper()
    if normalized == "TELNET":
        return FindingRisk(
            severity="High",
            exposure_level="High",
            insecure_configurations=("Cleartext Telnet service exposed",),
            recommendations=("Disable Telnet and use managed SSH access.",),
            confidence=0.95,
        )
    if normalized in {"HTTP", "RTSP", "FTP"}:
        return FindingRisk(
            severity="Medium",
            exposure_level="Moderate",
            insecure_configurations=(
                f"{normalized} service is network-accessible",
            ),
            recommendations=(
                f"Restrict {normalized} exposure to trusted management networks.",
            ),
            confidence=0.9,
        )
    if normalized == "UNKNOWN":
        return FindingRisk(
            recommendations=(
                "Collect a protocol signature before assigning service risk.",
            ),
        )
    return FindingRisk(
        severity="Low",
        exposure_level="Limited",
        recommendations=("Restrict the service to required source networks.",),
        confidence=0.8,
    )
