"""Inventory report generation for the integrated Module 4 pipeline."""

from app.modules.iot.models import (
    BannerDiscoveryResult,
    CVEIntelligenceResult,
    DeviceClassificationResult,
    DeviceInventoryReport,
    FirmwareDetectionResult,
    HTTPFingerprintResult,
    ONVIFDetectionResult,
    PortDiscoveryResult,
    RiskAssessmentResult,
    RTSPDetectionResult,
    SecuritySummaryResult,
    ServiceDetectionResult,
    VendorDetectionResult,
)


class InventoryReportEngine:
    """Flatten normalized detector results without inventing device facts."""

    def generate(
        self,
        *,
        ports: PortDiscoveryResult,
        services: ServiceDetectionResult,
        banners: BannerDiscoveryResult,
        http: HTTPFingerprintResult,
        rtsp: RTSPDetectionResult,
        onvif: ONVIFDetectionResult,
        vendor: VendorDetectionResult,
        classification: DeviceClassificationResult,
        firmware: FirmwareDetectionResult,
        cves: CVEIntelligenceResult,
        risk: RiskAssessmentResult,
        summary: SecuritySummaryResult,
    ) -> DeviceInventoryReport:
        """Produce the single-device inventory record returned by the API."""
        titles = tuple(
            dict.fromkeys(
                item.title for item in http.observations if item.title
            )
        )
        products = tuple(
            dict.fromkeys(
                item.product
                for item in services.observations
                if item.product
            )
        )
        service_names = tuple(
            dict.fromkeys(item.service for item in services.observations)
        )
        http_server = next(
            (item.server for item in http.observations if item.server),
            None,
        )
        banner = next(
            (
                item.normalized_banner or item.banner
                for item in banners.observations
                if item.normalized_banner or item.banner
            ),
            None,
        )
        return DeviceInventoryReport(
            target=ports.target,
            device_detected=bool(ports.open_ports),
            device_type=classification.device_type,
            classification_confidence=classification.confidence,
            vendor=vendor.vendor,
            vendor_confidence=vendor.confidence,
            model=firmware.model,
            firmware=firmware.firmware,
            open_ports=ports.open_ports,
            services=service_names,
            http_titles=titles,
            http_server=http_server,
            http_title=titles[0] if titles else None,
            banner=banner,
            mac_vendor=None,
            server_products=products,
            onvif_status=onvif.status,
            rtsp_detected=any(item.detected for item in rtsp.observations),
            cve_candidates=tuple(item.cve_id for item in cves.records),
            known_cves=cves.records,
            risk_score=risk.score,
            risk_level=risk.level,
            summary=summary.text,
        )
