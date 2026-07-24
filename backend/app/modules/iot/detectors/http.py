"""HTTP/HTTPS fingerprint extraction for IoT and surveillance interfaces."""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Iterable, Mapping
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

from app.core.logger import get_logger
from app.modules.iot.clients.device_http import DeviceHTTPClient, DeviceHTTPResponse
from app.modules.iot.fingerprints.signatures import (
    HTTP_TECHNOLOGY_SIGNATURES,
    match_vendor_signatures,
)
from app.modules.iot.models import HTTPFingerprintResult, HTTPObservation
from app.modules.iot.utils import validate_ipv4

logger = get_logger(__name__)

HTTP_PORT_SCHEMES: Mapping[int, str] = {
    80: "http", 81: "http", 82: "http", 83: "http", 84: "http",
    85: "http", 88: "http", 443: "https", 8000: "http",
    8001: "http", 8080: "http", 8081: "http", 8088: "http",
    8443: "https", 8888: "http",
}
KNOWN_HTTP_PATHS: tuple[str, ...] = (
    "/",
    "/login.asp",
    "/doc/page/login.asp",
    "/ISAPI/",
    "/cgi-bin/",
    "/favicon.ico",
)
_LOGIN_TERMS = ("login", "log in", "sign in", "username", "password")
_SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
_SAFE_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
Fetcher = Callable[[str], DeviceHTTPResponse]


class HTTPFingerprintEngine:
    """Probe known HTTP ports and extract bounded, normalized evidence."""

    def __init__(self, fetcher: Fetcher | None = None) -> None:
        client = DeviceHTTPClient() if fetcher is None else None
        self._fetcher = fetcher or client.get  # type: ignore[union-attr]

    def collect(
        self,
        target: str,
        open_ports: Iterable[int],
        paths: Iterable[str] = KNOWN_HTTP_PATHS,
    ) -> HTTPFingerprintResult:
        """Collect HTTP evidence only from recognized open web ports."""
        canonical_target = str(validate_ipv4(target))
        web_ports = sorted(set(open_ports).intersection(HTTP_PORT_SCHEMES))
        safe_paths = _validate_paths(paths)
        started = time.perf_counter()
        observations: list[HTTPObservation] = []

        for port in web_ports:
            scheme = HTTP_PORT_SCHEMES[port]
            authority = (
                canonical_target
                if (scheme, port) in {("http", 80), ("https", 443)}
                else f"{canonical_target}:{port}"
            )
            for path in safe_paths:
                url = f"{scheme}://{authority}{path}"
                observations.append(self._fetch(url, port, scheme, path))

        return HTTPFingerprintResult(
            target=canonical_target,
            observations=tuple(observations),
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _fetch(
        self, url: str, port: int, scheme: str, path: str
    ) -> HTTPObservation:
        try:
            response = self._fetcher(url)
        except requests.Timeout:
            return _error_observation(url, port, scheme, path, "timeout")
        except (requests.RequestException, OSError) as exc:
            logger.debug("HTTP probe failed url=%s type=%s", url, type(exc).__name__)
            return _error_observation(url, port, scheme, path, type(exc).__name__)

        headers = response.headers
        content_type = _clean(headers.get("content-type"))
        redirect = _safe_redirect(headers.get("location"), url)
        authentication = _clean(headers.get("www-authenticate"))
        cookie_names = _cookie_names(headers.get("set-cookie"))
        server = _clean(headers.get("server"))
        x_powered_by = _clean(headers.get("x-powered-by"))
        safe_headers = _safe_response_headers(headers, redirect)
        expected_security_headers = (
            _SECURITY_HEADERS + ("strict-transport-security",)
            if scheme == "https"
            else _SECURITY_HEADERS
        )
        security_headers = {
            name: safe_headers[name]
            for name in expected_security_headers
            if name in safe_headers
        }
        missing_security_headers = tuple(
            name
            for name in expected_security_headers
            if name not in security_headers
        )

        if path == "/favicon.ico":
            return HTTPObservation(
                url=url, port=port, scheme=scheme, path=path,
                status_code=response.status_code, headers=safe_headers,
                server=server, x_powered_by=x_powered_by,
                authentication=authentication, cookie_names=cookie_names,
                security_headers=security_headers,
                missing_security_headers=missing_security_headers,
                redirect_location=redirect,
                favicon_sha256=(
                    hashlib.sha256(response.body).hexdigest()
                    if response.body and response.status_code < 400 else None
                ),
                content_type=content_type, bytes_received=len(response.body),
                latency_ms=response.latency_ms,
                tls_validation_failed=response.tls_validation_failed,
                truncated=response.truncated,
            )

        title, generator, page_text = _html_evidence(response.body, content_type)
        combined = " ".join(
            part
            for part in (
                server,
                x_powered_by,
                authentication,
                title,
                generator,
                page_text,
            )
            if part
        ).lower()
        return HTTPObservation(
            url=url, port=port, scheme=scheme, path=path,
            status_code=response.status_code, headers=safe_headers,
            title=title, server=server, x_powered_by=x_powered_by,
            authentication=authentication, cookie_names=cookie_names,
            meta_generator=generator, technologies=_technologies(combined),
            security_headers=security_headers,
            missing_security_headers=missing_security_headers,
            login_markers=tuple(term for term in _LOGIN_TERMS if term in combined),
            vendor_hints=_vendor_hints(combined), redirect_location=redirect,
            content_type=content_type, bytes_received=len(response.body),
            latency_ms=response.latency_ms,
            tls_validation_failed=response.tls_validation_failed,
            truncated=response.truncated,
        )


def _html_evidence(
    body: bytes, content_type: str | None
) -> tuple[str | None, str | None, str]:
    if not body or (content_type and "html" not in content_type.lower()):
        return None, None, ""
    soup = BeautifulSoup(body, "html.parser")
    title = _clean(soup.title.get_text(" ", strip=True)) if soup.title else None
    generator_tag = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    generator = _clean(str(generator_tag.get("content", ""))) if generator_tag else None
    page_text = _clean(soup.get_text(" ", strip=True)) or ""
    form_attributes: list[str] = []
    for element in soup.find_all(["form", "input", "button"], limit=100):
        for attribute in ("type", "name", "id", "placeholder", "action"):
            value = element.get(attribute)
            if value:
                form_attributes.append(str(value))
    searchable_text = f"{page_text} {' '.join(form_attributes)}".strip()
    return title, generator, searchable_text[:8192]


def _cookie_names(header: str | None) -> tuple[str, ...]:
    if not header:
        return ()
    cookie = SimpleCookie()
    try:
        cookie.load(header)
    except cookie.CookieError:
        return ()
    return tuple(sorted(cookie.keys()))


def _safe_redirect(location: str | None, source_url: str) -> str | None:
    cleaned = _clean(location)
    if not cleaned:
        return None
    parsed = urlsplit(cleaned)
    if parsed.scheme or parsed.netloc:
        if parsed.hostname != urlsplit(source_url).hostname:
            return "[external redirect withheld]"
    return cleaned[:512]


def _vendor_hints(text: str) -> tuple[str, ...]:
    return match_vendor_signatures(text)


def _technologies(text: str) -> tuple[str, ...]:
    """Identify technologies only when an explicit signature is observed."""
    return tuple(
        sorted(
            {
                technology
                for signature, technology in HTTP_TECHNOLOGY_SIGNATURES
                if signature in text
            }
        )
    )


def _safe_response_headers(
    headers: Mapping[str, str],
    safe_redirect: str | None,
) -> dict[str, str]:
    """Sanitize headers and exclude cookie values and credential material."""
    result: dict[str, str] = {}
    for index, (raw_name, raw_value) in enumerate(headers.items()):
        if index >= 64:
            break
        name = str(raw_name).strip().lower()
        if name in {"set-cookie", "authorization", "proxy-authorization"}:
            continue
        if name == "location":
            if safe_redirect:
                result[name] = safe_redirect
            continue
        cleaned = _clean(str(raw_value))
        if cleaned:
            result[name[:128]] = cleaned[:2048]
    return result


def _clean(value: str | None) -> str | None:
    if not value:
        return None
    return _SAFE_TEXT.sub("", str(value)).strip()[:8192] or None


def _validate_paths(paths: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for path in paths:
        if (
            not isinstance(path, str) or not path.startswith("/")
            or "://" in path or "\r" in path or "\n" in path
        ):
            raise ValueError("Unsafe HTTP fingerprint path")
        if path not in normalized:
            normalized.append(path)
    return tuple(normalized)


def _error_observation(
    url: str, port: int, scheme: str, path: str, error: str
) -> HTTPObservation:
    return HTTPObservation(
        url=url, port=port, scheme=scheme, path=path, error=error
    )
