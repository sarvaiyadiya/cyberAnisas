"""Hardened HTTP client for untrusted IoT management interfaces."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Mapping
import warnings

import requests
import urllib3

from app.core.config import settings
from app.modules.iot.exceptions import DeviceHTTPConfigurationError


@dataclass(frozen=True, slots=True)
class DeviceHTTPResponse:
    """Bounded response returned to the HTTP fingerprint detector."""

    url: str
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    truncated: bool
    latency_ms: float = 0.0
    tls_validation_failed: bool = False


@dataclass(frozen=True, slots=True)
class DeviceHTTPClientConfig:
    """HTTP safety and resource limits."""

    timeout_seconds: float = settings.IOT_HTTP_TIMEOUT_SECONDS
    max_bytes: int = settings.IOT_HTTP_MAX_BYTES

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 15:
            raise DeviceHTTPConfigurationError(
                "HTTP timeout must be greater than 0 and at most 15 seconds"
            )
        if not 1024 <= self.max_bytes <= 5 * 1024 * 1024:
            raise DeviceHTTPConfigurationError(
                "HTTP response limit must be between 1 KiB and 5 MiB"
            )


class DeviceHTTPClient:
    """
    Fetch device pages without redirects, proxies, credentials, or retries.

    Redirects are disabled so a scanned device cannot redirect the scanner to
    an unrelated destination. Embedded devices commonly use self-signed TLS,
    so certificate verification is deferred to the later TLS risk assessment.
    """

    def __init__(self, config: DeviceHTTPClientConfig | None = None) -> None:
        self._config = config or DeviceHTTPClientConfig()
        self._session = requests.Session()
        self._session.trust_env = False
        self._session.headers.update(
            {
                "User-Agent": settings.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.5",
                "Connection": "close",
            }
        )

    def get(self, url: str) -> DeviceHTTPResponse:
        """Fetch one explicit URL and return at most the configured byte limit."""
        started = time.perf_counter()
        tls_validation_failed = False
        try:
            response = self._request(url, verify=True)
        except requests.exceptions.SSLError:
            if not url.lower().startswith("https://"):
                raise
            tls_validation_failed = True
            # This suppression is scoped to the single fallback probe. Global
            # warning behavior and the session's verification remain unchanged.
            with warnings.catch_warnings():
                warnings.simplefilter(
                    "ignore",
                    urllib3.exceptions.InsecureRequestWarning,
                )
                response = self._request(url, verify=False)

        with response:
            body = bytearray()
            truncated = False
            for chunk in response.iter_content(chunk_size=16384):
                remaining = self._config.max_bytes - len(body)
                if remaining <= 0:
                    truncated = True
                    break
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break

            return DeviceHTTPResponse(
                url=url,
                status_code=response.status_code,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=bytes(body),
                truncated=truncated,
                latency_ms=(time.perf_counter() - started) * 1000,
                tls_validation_failed=tls_validation_failed,
            )

    def _request(self, url: str, verify: bool) -> requests.Response:
        return self._session.get(
            url,
            timeout=self._config.timeout_seconds,
            allow_redirects=False,
            verify=verify,
            stream=True,
        )
