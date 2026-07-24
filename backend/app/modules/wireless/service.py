"""Application service boundary for Module 5."""

import time

from app.modules.wireless.collectors.interfaces import WirelessInterfaceCollector
from app.modules.wireless.collectors.access_points import AccessPointCollector
from app.modules.wireless.collectors.clients import WirelessClientCollector
from app.modules.wireless.analysis.oui import IEEEOUIRegistry
from app.modules.wireless.analysis.authentication import (
    AuthenticationAnalysisEngine,
)
from app.modules.wireless.analysis.mac_auth_lab import (
    build_mac_authentication_lab_guide,
)
from app.modules.wireless.analysis.behavior import BehaviorAnalysisEngine
from app.modules.wireless.analysis.assessment import WirelessRiskEngine
from app.modules.wireless.analysis.assessment import (
    assess_access_point_observation,
)
from app.modules.wireless.analysis.device_classification import (
    classify_access_point,
    classify_client_device,
)
from app.modules.wireless.report import WirelessReportEngine
from app.modules.wireless.models import (
    AccessPointScanResult,
    ClientEnumerationResult,
    AuthenticationAnalysisResult,
    AuthenticationEvidence,
    BehaviorAnalysisResult,
    DeviceBehaviorRecord,
    WirelessAssessmentRequest,
    WirelessSecurityReport,
    InterfaceDiscoveryResult,
    WirelessFullScanRequest,
    WirelessFullScanResult,
    WirelessScanMetrics,
    WirelessModuleHealth,
    WirelessPostureAnalysis,
    ModuleSubmoduleStatus,
)
from app.core.api_models import ScanStatistics, ScanSummary


class WirelessIntelligenceService:
    """Stable entry point for wireless intelligence operations."""

    def __init__(
        self,
        interface_collector: WirelessInterfaceCollector | None = None,
        access_point_collector: AccessPointCollector | None = None,
        oui_registry: IEEEOUIRegistry | None = None,
        client_collector: WirelessClientCollector | None = None,
        authentication_engine: AuthenticationAnalysisEngine | None = None,
        behavior_engine: BehaviorAnalysisEngine | None = None,
        risk_engine: WirelessRiskEngine | None = None,
        report_engine: WirelessReportEngine | None = None,
    ) -> None:
        self._interface_collector = (
            interface_collector or WirelessInterfaceCollector()
        )
        self._access_point_collector = (
            access_point_collector or AccessPointCollector()
        )
        self._oui_registry = oui_registry or IEEEOUIRegistry()
        self._client_collector = client_collector or WirelessClientCollector()
        self._authentication_engine = (
            authentication_engine or AuthenticationAnalysisEngine()
        )
        self._behavior_engine = behavior_engine or BehaviorAnalysisEngine()
        self._risk_engine = risk_engine or WirelessRiskEngine()
        self._report_engine = report_engine or WirelessReportEngine()

    def discover_interfaces(self) -> InterfaceDiscoveryResult:
        """Discover local wireless interfaces using read-only commands."""
        return self._interface_collector.collect()

    def scan_access_points(
        self,
        interface: str | None = None,
        rescan: bool = True,
    ) -> AccessPointScanResult:
        """Enumerate nearby APs without joining or modifying networks."""
        result = self._access_point_collector.collect(
            interface=interface,
            rescan=rescan,
        )
        enriched = []
        for access_point in result.access_points:
            vendor = self._oui_registry.lookup(access_point.bssid)
            device_class, class_confidence, _ = classify_access_point(
                ssid=access_point.ssid,
                vendor=vendor.vendor,
            )
            enriched.append(
                access_point.model_copy(
                    update={
                        "oui": vendor.oui,
                        "vendor": vendor.vendor,
                        "manufacturer": vendor.vendor,
                        "security_mode": access_point.authentication,
                        "cipher": access_point.encryption,
                        "vendor_confidence": vendor.confidence,
                        "vendor_source": vendor.source,
                        "vendor_source_available": vendor.source_available,
                        "locally_administered": vendor.locally_administered,
                        "device_class": device_class,
                        "device_class_confidence": class_confidence,
                        "beacon_observed": (
                            access_point.beacon_interval_ms is not None
                        ),
                        "dfs_channel": (
                            52 <= access_point.channel <= 144
                            if access_point.channel is not None
                            else None
                        ),
                        "mesh_detected": device_class == "Mesh",
                        "hotspot_detected": device_class == "Hotspot",
                        "suspicious_mac": (
                            access_point.suspicious_mac
                            or vendor.locally_administered
                        ),
                        "evidence": _access_point_evidence(access_point),
                        "confidence": 1.0,
                        "source": (
                            f"{result.platform.lower()}-native-wireless-scan"
                        ),
                        "risk": assess_access_point_observation(access_point),
                    }
                )
            )
        enriched = _mark_evil_twin_candidates(enriched)
        high_risk = sum(
            item.risk.severity in {"High", "Critical"} for item in enriched
        )
        important = sum(
            item.risk.severity in {"Medium", "High", "Critical"}
            for item in enriched
        )
        conclusion = (
            f"Detected {len(enriched)} wireless access point(s); "
            f"{high_risk} have high or critical observed risk."
            if enriched
            else "No access points were returned by the operating-system scan."
        )
        return result.model_copy(
            update={
                "access_points": tuple(enriched),
                "summary": ScanSummary(
                    total_findings=len(enriched),
                    important_findings=important,
                    high_risk_findings=high_risk,
                    conclusion=conclusion,
                ),
                "statistics": ScanStatistics(
                    total_objects_scanned=len(enriched),
                    successful_detections=len(enriched),
                    failed_detections=1 if result.error else 0,
                    elapsed_scan_ms=result.duration_ms,
                ),
            }
        )

    def enumerate_clients(
        self,
        interface: str | None = None,
        dhcp_lease_text: str | None = None,
    ) -> ClientEnumerationResult:
        """Return passive clients enriched with local IEEE OUI evidence."""
        result = self._client_collector.collect(
            interface=interface,
            dhcp_lease_text=dhcp_lease_text,
        )

        def enrich_clients(clients):
            mac_counts: dict[str, int] = {}
            oui_counts: dict[str, int] = {}
            for item in clients:
                mac_counts[item.mac] = mac_counts.get(item.mac, 0) + 1
                oui_counts[item.oui] = oui_counts.get(item.oui, 0) + 1
            enriched = []
            for client in clients:
                vendor = self._oui_registry.lookup(client.mac)
                device_type, _ = classify_client_device(
                    hostname=client.hostname,
                    vendor=vendor.vendor,
                )
                duplicate = mac_counts[client.mac] > 1
                enriched.append(
                    client.model_copy(
                        update={
                            "oui": vendor.oui,
                            "vendor": vendor.vendor,
                            "vendor_confidence": vendor.confidence,
                            "vendor_source": vendor.source,
                            "vendor_source_available": vendor.source_available,
                            "locally_administered": vendor.locally_administered,
                            "randomized_mac": vendor.locally_administered,
                            "duplicate_mac": duplicate,
                            "suspicious_mac": (
                                duplicate or vendor.locally_administered
                            ),
                            "device_type": device_type,
                            "rare_oui": (
                                len(clients) >= 3
                                and oui_counts[client.oui] == 1
                            ),
                            "unusual_vendor": vendor.vendor == "Unknown",
                        }
                    )
                )
            return tuple(enriched)

        return result.model_copy(
            update={
                "clients": enrich_clients(result.clients),
                "neighbor_candidates": enrich_clients(
                    result.neighbor_candidates
                ),
            }
        )

    def analyze_authentication(
        self,
        access_points: list[AuthenticationEvidence],
        include_mac_auth_lab: bool = True,
    ) -> AuthenticationAnalysisResult:
        """Analyze supplied security metadata without testing credentials."""
        assessments = tuple(
            self._authentication_engine.analyze(item)
            for item in access_points
        )
        highest = max(
            assessments,
            key=lambda item: item.risk_score,
        ).risk_level
        return AuthenticationAnalysisResult(
            assessments=assessments,
            highest_risk=highest,
            mac_authentication_lab=(
                build_mac_authentication_lab_guide()
                if include_mac_auth_lab
                else None
            ),
        )

    def analyze_behavior(
        self,
        records: list[DeviceBehaviorRecord],
        contamination: float = 0.1,
    ) -> BehaviorAnalysisResult:
        """Analyze supplied aggregate metadata without collecting traffic."""
        return self._behavior_engine.analyze(records, contamination)

    def generate_report(
        self,
        evidence: WirelessAssessmentRequest,
    ) -> WirelessSecurityReport:
        """Correlate normalized evidence and generate the final report."""
        risk = self._risk_engine.assess(
            access_points=evidence.access_points,
            clients=evidence.clients,
            authentication=evidence.authentication_assessments,
            behavior=evidence.behavior,
        )
        return self._report_engine.generate(
            access_point_count=len(evidence.access_points),
            client_count=len(evidence.clients),
            behavior=evidence.behavior,
            risk=risk,
        )

    def run_full_scan(
        self,
        request: WirelessFullScanRequest,
    ) -> WirelessFullScanResult:
        """Execute all applicable Module 5 stages in a single session."""
        started = time.perf_counter()
        interfaces = self.discover_interfaces()
        access_points = self.scan_access_points(
            interface=request.interface,
            rescan=request.rescan,
        )
        clients = self.enumerate_clients(
            interface=request.interface,
            dhcp_lease_text=request.dhcp_lease_text,
        )

        authentication_evidence = [
            AuthenticationEvidence(
                ssid=item.ssid,
                bssid=item.bssid,
                authentication=item.authentication,
                encryption=item.encryption,
                pmf_support=item.pmf_support,
            )
            for item in access_points.access_points
        ]
        if authentication_evidence:
            authentication = self.analyze_authentication(
                authentication_evidence,
                include_mac_auth_lab=request.include_mac_auth_lab,
            )
        else:
            authentication = AuthenticationAnalysisResult(
                assessments=(),
                highest_risk="Unknown",
                mac_authentication_lab=(
                    build_mac_authentication_lab_guide()
                    if request.include_mac_auth_lab
                    else None
                ),
            )

        behavior: BehaviorAnalysisResult | None = None
        if request.behavior_records:
            behavior = self.analyze_behavior(
                records=request.behavior_records,
                contamination=request.contamination,
            )

        report = self.generate_report(
            WirelessAssessmentRequest(
                access_points=list(access_points.access_points),
                clients=list(clients.clients),
                authentication_assessments=list(
                    authentication.assessments
                ),
                behavior=behavior,
            )
        )
        stages = [
            "interfaces",
            "access_points",
            "clients",
            "authentication",
        ]
        limitations = list(access_points.limitations)
        if behavior is not None:
            stages.append("behavior")
        else:
            limitations.append(
                "Behavior analysis was skipped because no historical "
                "behavior_records were supplied."
            )
        stages.append("report")
        metrics = _full_scan_metrics(
            interfaces=interfaces,
            access_points=access_points,
            clients=clients,
            report=report,
            duration_ms=(time.perf_counter() - started) * 1000,
        )
        health = _module_health(
            interfaces=interfaces,
            access_points=access_points,
            clients=clients,
            behavior=behavior,
        )
        analysis = _wireless_posture_analysis(
            access_points=access_points,
            report=report,
        )
        return WirelessFullScanResult(
            interfaces=interfaces,
            access_points=access_points,
            clients=clients,
            authentication=authentication,
            behavior=behavior,
            report=report,
            metrics=metrics,
            module_health=health,
            analysis=analysis,
            stages_completed=tuple(stages),
            limitations=tuple(dict.fromkeys(limitations)),
            duration_ms=(time.perf_counter() - started) * 1000,
        )


_service = WirelessIntelligenceService()


def get_wireless_service() -> WirelessIntelligenceService:
    """FastAPI dependency provider for Module 5."""
    return _service


def _access_point_evidence(access_point) -> tuple[str, ...]:
    """Build bounded evidence from fields exposed by the OS collector."""
    evidence = [f"BSSID observed: {access_point.bssid}"]
    if access_point.ssid:
        evidence.append(f"SSID observed: {access_point.ssid}")
    if access_point.channel is not None:
        evidence.append(f"Channel observed: {access_point.channel}")
    if access_point.authentication != "Unknown":
        evidence.append(
            f"Authentication observed: {access_point.authentication}"
        )
    if access_point.encryption != "Unknown":
        evidence.append(f"Encryption observed: {access_point.encryption}")
    return tuple(evidence)


def _mark_evil_twin_candidates(access_points):
    """Flag only conflicting same-SSID evidence, never mere SSID reuse."""
    groups: dict[str, list] = {}
    for item in access_points:
        if item.ssid.strip():
            groups.setdefault(item.ssid.strip().casefold(), []).append(item)
    updated = []
    for item in access_points:
        peers = groups.get(item.ssid.strip().casefold(), [])
        security_profiles = {
            (peer.authentication.casefold(), peer.encryption.casefold())
            for peer in peers
        }
        known_vendors = {
            peer.vendor for peer in peers if peer.vendor != "Unknown"
        }
        conflicting = len(peers) > 1 and (
            len(security_profiles) > 1 or len(known_vendors) > 1
        )
        probability = 0.65 if conflicting else None
        evidence = item.evidence
        if conflicting:
            evidence = evidence + (
                "Same SSID observed with conflicting security or vendor evidence",
            )
        updated.append(
            item.model_copy(
                update={
                    "evil_twin_probability": probability,
                    "evidence": evidence,
                }
            )
        )
    return updated


def _full_scan_metrics(
    *,
    interfaces,
    access_points,
    clients,
    report,
    duration_ms: float,
) -> WirelessScanMetrics:
    aps = access_points.access_points
    client_evidence = clients.clients + clients.neighbor_candidates
    suspicious = sum(item.suspicious_mac for item in aps) + sum(
        item.suspicious_mac for item in client_evidence
    )
    return WirelessScanMetrics(
        scan_duration_ms=duration_ms,
        devices_discovered=len(aps) + len(client_evidence),
        access_points_discovered=len(aps),
        hidden_networks=sum(item.hidden_ssid for item in aps),
        rogue_ap_count=None,
        evil_twin_candidate_count=sum(
            item.evil_twin_probability is not None for item in aps
        ),
        suspicious_devices=suspicious,
        wireless_score=report.security_score,
        coverage_percentage=None,
        scan_completion_percentage=100.0,
        interfaces_scanned=len(interfaces.interfaces),
        protocols_detected=len(
            {
                item.authentication
                for item in aps
                if item.authentication != "Unknown"
            }
        ),
    )


def _module_health(
    *,
    interfaces,
    access_points,
    clients,
    behavior,
) -> WirelessModuleHealth:
    wifi_status = (
        "completed_with_limitations"
        if access_points.error
        else "completed"
    )
    client_status = "completed_with_limitations" if clients.error else "completed"
    submodules = {
        "wifi_scan": ModuleSubmoduleStatus(
            status=wifi_status,
            completion_percentage=100 if not access_points.error else 50,
            detail=access_points.error or "OS wireless enumeration completed.",
        ),
        "bluetooth_scan": ModuleSubmoduleStatus(
            status="unsupported",
            completion_percentage=0,
            detail="No Bluetooth collector is implemented in Module 5.",
        ),
        "iot_discovery": ModuleSubmoduleStatus(
            status="separate_endpoint",
            completion_percentage=0,
            detail="IoT discovery is available under /api/v1/iot.",
        ),
        "client_evidence": ModuleSubmoduleStatus(
            status=client_status,
            completion_percentage=100 if not clients.error else 50,
            detail=clients.explanation,
        ),
        "wireless_security": ModuleSubmoduleStatus(
            status="completed",
            completion_percentage=100,
            detail="Authentication and configuration evidence was assessed.",
        ),
        "rogue_detection": ModuleSubmoduleStatus(
            status="limited",
            completion_percentage=50,
            detail=(
                "Evil-twin heuristics are available; authoritative rogue "
                "detection requires an approved AP baseline."
            ),
        ),
        "behavior_analysis": ModuleSubmoduleStatus(
            status="completed" if behavior else "not_requested",
            completion_percentage=100 if behavior else 0,
            detail=(
                behavior.explanation
                if behavior
                else "No historical behavior records were supplied."
            ),
        ),
        "risk_analysis": ModuleSubmoduleStatus(
            status="completed",
            completion_percentage=100,
            detail="Evidence-backed wireless risk analysis completed.",
        ),
    }
    requested_scores = (
        submodules["wifi_scan"].completion_percentage,
        submodules["client_evidence"].completion_percentage,
        submodules["wireless_security"].completion_percentage,
        submodules["rogue_detection"].completion_percentage,
        submodules["risk_analysis"].completion_percentage,
    )
    completion = round(sum(requested_scores) / len(requested_scores), 1)
    return WirelessModuleHealth(
        status=(
            "completed"
            if completion == 100
            else "completed_with_limitations"
        ),
        completion_percentage=completion,
        submodules=submodules,
    )


def _wireless_posture_analysis(
    *,
    access_points,
    report,
) -> WirelessPostureAnalysis:
    aps = access_points.access_points
    weak = tuple(
        sorted(
            {
                item.ssid or "<hidden>"
                for item in aps
                if (
                    "WEP" in f"{item.authentication} {item.encryption}".upper()
                    or (
                        "WPA" in item.authentication.upper()
                        and "WPA2" not in item.authentication.upper()
                        and "WPA3" not in item.authentication.upper()
                    )
                )
            }
        )
    )
    open_count = sum(
        "OPEN" in item.authentication.upper()
        or item.encryption.upper() == "NONE"
        for item in aps
    )
    evil_candidates = sum(
        item.evil_twin_probability is not None for item in aps
    )
    return WirelessPostureAnalysis(
        wireless_attack_surface=(
            f"{len(aps)} access point(s), {open_count} open network(s), "
            f"{len(weak)} weak-encryption network(s), and "
            f"{evil_candidates} evil-twin candidate observation(s)."
        ),
        rogue_ap_probability=None,
        evil_twin_probability=(
            max(
                (
                    item.evil_twin_probability or 0.0
                    for item in aps
                ),
                default=0.0,
            )
            if evil_candidates
            else None
        ),
        weak_encryption_networks=weak,
        open_network_count=open_count,
        unauthorized_device_count=None,
        iot_exposure_score=None,
        overall_wireless_security_posture=report.risk.level,
        recommended_mitigations=report.risk.recommendations,
        limitations=(
            "Rogue AP probability requires an approved infrastructure baseline.",
            "Unauthorized-device detection requires an asset allowlist.",
            "IoT exposure is assessed by the separate IoT endpoint.",
            "This is deterministic evidence correlation, not generative AI.",
        ),
    )
