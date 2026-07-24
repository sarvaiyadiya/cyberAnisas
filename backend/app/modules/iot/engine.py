"""Orchestration engine for the Module 4 fingerprinting pipeline."""

from __future__ import annotations

import time
from collections.abc import Iterable

from app.core.logger import get_logger
from app.modules.iot.detectors.banners import BannerFingerprintEngine
from app.modules.iot.detectors.http import HTTPFingerprintEngine
from app.modules.iot.detectors.ports import (
    DEFAULT_IOT_TCP_PORTS,
    PortDiscoveryEngine,
)
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
from app.modules.iot.models import HTTPFingerprintScanResult, IoTCapabilityStatus

logger = get_logger(__name__)


class IoTFingerprintEngine:
    """
    Coordinate detectors while keeping protocol logic inside each detector.

    Detectors remain independently testable and are composed here without
    placing protocol logic in the service or API layers.
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
    ) -> None:
        self._port_engine = port_engine or PortDiscoveryEngine()
        self._http_engine = http_engine or HTTPFingerprintEngine()
        self._banner_engine = banner_engine or BannerFingerprintEngine()
        self._service_engine = service_engine or ServiceDetectionEngine()
        self._tls_engine = tls_engine or TLSFingerprintEngine()
        self._rtsp_engine = rtsp_engine or RTSPDetectionEngine()
        self._onvif_engine = onvif_engine or ONVIFDetectionEngine()
        self._vendor_engine = vendor_engine or VendorFingerprintEngine()
        self._risk_engine = risk_engine or RiskAssessmentEngine()
        self._summary_engine = summary_engine or SecuritySummaryEngine()
        self._classification_engine = (
            classification_engine or DeviceClassificationEngine()
        )
        self._firmware_engine = firmware_engine or FirmwareDetectionEngine()
        self._cve_client = cve_client or CVEIntelligenceClient()
        self._report_engine = report_engine or InventoryReportEngine()

    def fingerprint_http(
        self,
        target: str,
        ports: Iterable[int] | None = None,
    ) -> HTTPFingerprintScanResult:
        """Discover ports, then fingerprint confirmed open HTTP endpoints."""
        started = time.perf_counter()
        port_result = self._port_engine.scan(
            target=target,
            ports=ports if ports is not None else DEFAULT_IOT_TCP_PORTS,
        )
        banner_result = self._banner_engine.collect(
            target=port_result.target,
            open_ports=port_result.open_ports,
        )
        http_result = self._http_engine.collect(
            target=port_result.target,
            open_ports=port_result.open_ports,
        )
        tls_result = self._tls_engine.collect(
            target=port_result.target,
            open_ports=port_result.open_ports,
        )
        rtsp_result = self._rtsp_engine.detect(
            target=port_result.target,
            open_ports=port_result.open_ports,
        )
        onvif_result = self._onvif_engine.detect(
            target=port_result.target,
            open_ports=port_result.open_ports,
        )
        service_result = self._service_engine.detect(
            target=port_result.target,
            open_ports=port_result.open_ports,
            banners=banner_result,
            http=http_result,
            rtsp=rtsp_result,
        )
        vendor_result = self._vendor_engine.detect(
            ports=port_result,
            banners=banner_result,
            http=http_result,
            tls=tls_result,
            rtsp=rtsp_result,
        )
        classification_result = self._classification_engine.classify(
            services=service_result,
            banners=banner_result,
            http=http_result,
            rtsp=rtsp_result,
            onvif=onvif_result,
            vendor=vendor_result,
        )
        firmware_result = self._firmware_engine.detect(
            banners=banner_result,
            http=http_result,
        )
        cve_result = self._cve_client.lookup(
            vendor=vendor_result.vendor,
            model=firmware_result.model,
            firmware=firmware_result.firmware,
        )
        risk_result = self._risk_engine.assess(
            ports=port_result,
            http=http_result,
            tls=tls_result,
            rtsp=rtsp_result,
            onvif=onvif_result,
            vendor=vendor_result,
            cves=cve_result,
        )
        summary_result = self._summary_engine.generate(
            target=port_result.target,
            services=service_result,
            vendor=vendor_result,
            tls=tls_result,
            rtsp=rtsp_result,
            risk=risk_result,
        )
        report_result = self._report_engine.generate(
            ports=port_result,
            services=service_result,
            banners=banner_result,
            http=http_result,
            rtsp=rtsp_result,
            onvif=onvif_result,
            vendor=vendor_result,
            classification=classification_result,
            firmware=firmware_result,
            cves=cve_result,
            risk=risk_result,
            summary=summary_result,
        )
        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "HTTP/TLS pipeline complete target=%s open_ports=%d "
            "http_observations=%d tls_observations=%d rtsp_observations=%d",
            port_result.target,
            len(port_result.open_ports),
            len(http_result.observations),
            len(tls_result.observations),
            len(rtsp_result.observations),
        )
        return HTTPFingerprintScanResult(
            target=port_result.target,
            port_discovery=port_result,
            service_detection=service_result,
            banner_discovery=banner_result,
            http=http_result,
            tls=tls_result,
            rtsp=rtsp_result,
            onvif=onvif_result,
            vendor=vendor_result,
            classification=classification_result,
            firmware=firmware_result,
            cves=cve_result,
            risk=risk_result,
            summary=summary_result,
            report=report_result,
            capabilities=_capability_statuses(),
            duration_ms=duration_ms,
        )


def _capability_statuses() -> dict[str, IoTCapabilityStatus]:
    """Describe executed and unavailable engines without implying detection."""
    executed = {
        "tcp_connect": ("Active TCP connect", "Bounded TCP probes executed."),
        "banner": ("Bounded banner read", "Application banner engine executed."),
        "http": ("HTTP GET/HEAD", "Safe HTTP fingerprint engine executed."),
        "tls": ("TLS handshake", "TLS metadata engine executed."),
        "rtsp": ("RTSP OPTIONS", "RTSP detection engine executed."),
        "onvif": (
            "ONVIF device-service probe",
            "Unauthenticated ONVIF detection engine executed.",
        ),
        "service_correlation": (
            "Evidence correlation",
            "Port, banner and protocol evidence was correlated.",
        ),
    }
    capabilities = {
        name: IoTCapabilityStatus(
            status="executed",
            detection_method=method,
            detail=detail,
        )
        for name, (method, detail) in executed.items()
    }
    unsupported = {
        "snmp": "SNMP availability/version probing is not implemented.",
        "upnp": "UPnP discovery is not implemented.",
        "mdns": "mDNS discovery is not implemented.",
        "ssdp": "SSDP discovery is not implemented.",
        "mqtt": "MQTT application handshake detection is not implemented.",
        "coap": "CoAP detection is not implemented.",
        "modbus": "Modbus protocol detection is not implemented.",
        "bacnet": "BACnet protocol detection is not implemented.",
        "dnp3": "DNP3 protocol detection is not implemented.",
        "bluetooth": "Bluetooth device discovery is not implemented.",
    }
    capabilities.update(
        {
            name: IoTCapabilityStatus(
                status="not_implemented",
                detection_method="none",
                detail=detail,
            )
            for name, detail in unsupported.items()
        }
    )
    capabilities["default_credentials"] = IoTCapabilityStatus(
        status="not_tested",
        detection_method="none",
        detail="Credentials are not attempted by this safe fingerprint scan.",
    )
    capabilities["lifecycle"] = IoTCapabilityStatus(
        status="not_assessed",
        detection_method="none",
        detail=(
            "End-of-life and end-of-support require authoritative vendor "
            "lifecycle data."
        ),
    )
    return capabilities
