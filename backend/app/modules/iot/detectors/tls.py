"""Safe TLS handshake and X.509 certificate fingerprinting."""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.core.config import settings
from app.core.logger import get_logger
from app.modules.iot.exceptions import TLSConfigurationError
from app.modules.iot.fingerprints.signatures import match_vendor_signatures
from app.modules.iot.models import TLSFingerprintResult, TLSObservation
from app.modules.iot.utils import validate_ipv4

logger = get_logger(__name__)
DEFAULT_TLS_PORTS = frozenset({443, 8443})


@dataclass(frozen=True, slots=True)
class TLSHandshakeEvidence:
    """Raw handshake evidence retained only inside the detector boundary."""

    tls_version: str
    certificate_der: bytes
    validated: bool
    validation_error: str | None
    latency_ms: float
    cipher_suite: str | None = None
    cipher_bits: int | None = None


@dataclass(frozen=True, slots=True)
class TLSProbeConfig:
    """TLS connection limits."""

    timeout_seconds: float = settings.IOT_TLS_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 15:
            raise TLSConfigurationError(
                "TLS timeout must be greater than 0 and at most 15 seconds"
            )


TLSProber = Callable[[str, int, float], TLSHandshakeEvidence]


class TLSFingerprintEngine:
    """Collect TLS metadata without application requests or credentials."""

    def __init__(
        self,
        config: TLSProbeConfig | None = None,
        prober: TLSProber | None = None,
    ) -> None:
        self._config = config or TLSProbeConfig()
        self._prober = prober or _probe_tls

    def collect(
        self,
        target: str,
        open_ports: Iterable[int],
    ) -> TLSFingerprintResult:
        """Probe recognized open HTTPS ports on one IPv4 target."""
        canonical_target = str(validate_ipv4(target))
        ports = sorted(set(open_ports).intersection(DEFAULT_TLS_PORTS))
        started = time.perf_counter()
        observations = tuple(
            self._collect_one(canonical_target, port) for port in ports
        )
        return TLSFingerprintResult(
            target=canonical_target,
            observations=observations,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _collect_one(self, target: str, port: int) -> TLSObservation:
        try:
            evidence = self._prober(
                target,
                port,
                self._config.timeout_seconds,
            )
            return _parse_certificate(port, evidence)
        except (TimeoutError, socket.timeout):
            return TLSObservation(port=port, error="timeout")
        except (ssl.SSLError, OSError, ValueError) as exc:
            logger.debug(
                "TLS probe failed target=%s port=%d type=%s",
                target,
                port,
                type(exc).__name__,
            )
            return TLSObservation(port=port, error=type(exc).__name__)


def _probe_tls(target: str, port: int, timeout: float) -> TLSHandshakeEvidence:
    """Validate first, then reconnect unverified only to collect rejected certs."""
    started = time.perf_counter()
    validation_error: str | None = None
    try:
        context = ssl.create_default_context()
        version, certificate, cipher_suite, cipher_bits = _handshake(
            target, port, timeout, context
        )
        validated = True
    except ssl.SSLCertVerificationError as exc:
        validated = False
        validation_error = _validation_reason(exc)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        version, certificate, cipher_suite, cipher_bits = _handshake(
            target, port, timeout, context
        )

    return TLSHandshakeEvidence(
        tls_version=version,
        certificate_der=certificate,
        validated=validated,
        validation_error=validation_error,
        latency_ms=(time.perf_counter() - started) * 1000,
        cipher_suite=cipher_suite,
        cipher_bits=cipher_bits,
    )


def _handshake(
    target: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
) -> tuple[str, bytes, str | None, int | None]:
    with socket.create_connection((target, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        with context.wrap_socket(
            connection,
            server_hostname=target,
        ) as tls_socket:
            certificate = tls_socket.getpeercert(binary_form=True)
            if not certificate:
                raise ssl.SSLError("Peer did not provide a certificate")
            cipher = tls_socket.cipher()
            return (
                tls_socket.version() or "Unknown",
                certificate,
                cipher[0] if cipher else None,
                cipher[2] if cipher else None,
            )


def _parse_certificate(
    port: int,
    evidence: TLSHandshakeEvidence,
) -> TLSObservation:
    certificate = x509.load_der_x509_certificate(evidence.certificate_der)
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = common_names[0].value if common_names else None
    alt_names: tuple[str, ...] = ()
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        alt_names = tuple(
            sorted(
                {
                    str(value)
                    for value in (
                        extension.value.get_values_for_type(x509.DNSName)
                        + extension.value.get_values_for_type(x509.IPAddress)
                    )
                }
            )
        )
    except x509.ExtensionNotFound:
        pass

    valid_from = certificate.not_valid_before_utc
    valid_until = certificate.not_valid_after_utc
    now = datetime.now(timezone.utc)
    subject = certificate.subject.rfc4514_string() or None
    issuer = certificate.issuer.rfc4514_string() or None
    vendor_text = " ".join(
        value for value in (subject, issuer, common_name) if value
    ).lower()
    signature_algorithm = (
        certificate.signature_algorithm_oid._name
        or certificate.signature_algorithm_oid.dotted_string
    )
    self_signed = certificate.subject == certificate.issuer
    expired = now < valid_from or now > valid_until
    security_issues = _security_issues(
        tls_version=evidence.tls_version,
        cipher_suite=evidence.cipher_suite,
        signature_algorithm=signature_algorithm,
        self_signed=self_signed,
        expired=expired,
        validated=evidence.validated,
    )
    return TLSObservation(
        port=port,
        tls_version=evidence.tls_version,
        cipher_suite=evidence.cipher_suite,
        cipher_bits=evidence.cipher_bits,
        signature_algorithm=signature_algorithm,
        certificate_subject=subject,
        certificate_issuer=issuer,
        common_name=common_name,
        subject_alt_names=alt_names,
        serial_number=format(certificate.serial_number, "X"),
        valid_from=valid_from.isoformat(),
        valid_until=valid_until.isoformat(),
        self_signed=self_signed,
        expired=expired,
        certificate_validated=evidence.validated,
        validation_error=evidence.validation_error,
        vendor_hints=match_vendor_signatures(vendor_text),
        security_issues=security_issues,
        latency_ms=evidence.latency_ms,
        evidence=tuple(
            item
            for item in (
                f"Negotiated TLS version: {evidence.tls_version}",
                f"Certificate common name: {common_name}"
                if common_name
                else None,
            )
            if item
        ),
        confidence=0.98,
    )


def _validation_reason(exc: ssl.SSLCertVerificationError) -> str:
    """Return a bounded certificate reason without connection internals."""
    message = getattr(exc, "verify_message", None)
    return str(message or "certificate validation failed")[:256]


def _security_issues(
    tls_version: str,
    cipher_suite: str | None,
    signature_algorithm: str,
    self_signed: bool,
    expired: bool,
    validated: bool,
) -> tuple[str, ...]:
    """Return deterministic findings supported by observed TLS evidence."""
    issues: list[str] = []
    normalized_version = tls_version.lower().replace(" ", "")
    if normalized_version in {"tlsv1", "tlsv1.0", "tlsv1.1", "sslv3"}:
        issues.append(f"Obsolete TLS protocol negotiated: {tls_version}")
    if cipher_suite and any(
        marker in cipher_suite.upper()
        for marker in ("RC4", "3DES", "_DES_", "NULL", "EXPORT")
    ):
        issues.append(f"Weak cipher suite negotiated: {cipher_suite}")
    if any(
        marker in signature_algorithm.lower()
        for marker in ("sha1", "md5")
    ):
        issues.append(
            f"Weak certificate signature algorithm: {signature_algorithm}"
        )
    if self_signed:
        issues.append("Certificate appears self-signed")
    if expired:
        issues.append("Certificate is expired or not yet valid")
    if not validated:
        issues.append("Certificate validation failed")
    return tuple(issues)
