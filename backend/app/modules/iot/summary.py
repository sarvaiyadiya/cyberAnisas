"""Evidence-grounded concise security summary generation."""

from __future__ import annotations

from app.modules.iot.models import (
    RiskAssessmentResult,
    RTSPDetectionResult,
    SecuritySummaryResult,
    ServiceDetectionResult,
    TLSFingerprintResult,
    VendorDetectionResult,
)

MAX_SUMMARY_WORDS = 100


class SecuritySummaryEngine:
    """Generate factual prose solely from completed detector results."""

    def generate(
        self,
        target: str,
        services: ServiceDetectionResult,
        vendor: VendorDetectionResult,
        tls: TLSFingerprintResult,
        rtsp: RTSPDetectionResult,
        risk: RiskAssessmentResult,
    ) -> SecuritySummaryResult:
        """Return a summary that never exceeds 100 whitespace-delimited words."""
        sentences: list[str] = []
        detected_services = sorted(
            {
                item.service
                for item in services.observations
                if item.status == "open"
            }
        )
        if detected_services:
            sentences.append(
                f"{target} exposes {', '.join(detected_services)}."
            )
        else:
            sentences.append(
                f"No open services were identified on the scanned ports for {target}."
            )

        if vendor.vendor != "Unknown":
            sentences.append(
                f"Vendor evidence indicates {vendor.vendor} "
                f"with {vendor.confidence}% confidence."
            )
        else:
            sentences.append("The vendor could not be determined reliably.")

        detected_rtsp = [item for item in rtsp.observations if item.detected]
        if detected_rtsp:
            unauthenticated = [
                item for item in detected_rtsp if not item.authentication_required
            ]
            if unauthenticated:
                ports = ", ".join(str(item.port) for item in unauthenticated)
                sentences.append(
                    f"RTSP responds without an authentication challenge on port(s) {ports}."
                )
            else:
                sentences.append("Detected RTSP services require authentication.")

        tls_issue_count = sum(
            len(item.security_issues) for item in tls.observations
        )
        if tls_issue_count:
            sentences.append(
                f"TLS analysis identified {tls_issue_count} security finding(s)."
            )

        sentences.append(
            f"Overall risk is {risk.level} ({risk.score}/100)."
        )
        if risk.recommendations:
            sentences.append(
                f"Priority action: {risk.recommendations[0]}"
            )

        text = _limit_words(" ".join(sentences), MAX_SUMMARY_WORDS)
        return SecuritySummaryResult(
            text=text,
            word_count=len(text.split()),
        )


def _limit_words(text: str, maximum: int) -> str:
    words = text.split()
    if len(words) <= maximum:
        return text
    return " ".join(words[:maximum]).rstrip(".,;:") + "."
