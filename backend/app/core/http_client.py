"""
core/http_client.py

Shared HTTP client for all external API calls in ANISAS.

Design decisions:
- Returns Optional[dict] — callers receive None on failure instead of
  propagating exceptions, so one failing source cannot crash the whole pipeline.
- Logs every request and every failure for observability.
- Supports optional Bearer-token and custom headers per request.
"""

import requests
from requests.exceptions import Timeout, ConnectionError, HTTPError
from typing import Optional

from app.core.logger import get_logger
from app.core.config import settings

logger = get_logger(__name__)


class HTTPClient:
    """
    Thin wrapper around ``requests`` with logging, timeouts, and error handling.

    All methods return ``dict | None``.  A ``None`` return means the request
    failed; the error has already been logged at WARNING level.
    """

    def __init__(
        self,
        timeout: int | None = None,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        """
        Args:
            timeout:         Override default request timeout (seconds).
            default_headers: Headers merged into every request made by this
                             instance (e.g. ``{"Authorization": "Bearer …"}``).
        """
        self._timeout = timeout or settings.REQUEST_TIMEOUT
        self._default_headers: dict[str, str] = {
            "User-Agent": settings.USER_AGENT,
            "Accept": "application/json",
        }
        if default_headers:
            self._default_headers.update(default_headers)

    # ── Public interface ──────────────────────────────────────────────────────

    def get(
        self,
        url: str,
        params: dict | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Optional[dict]:
        """
        Perform an HTTP GET and return the parsed JSON body.

        Args:
            url:           Full URL to request.
            params:        Optional query-string parameters.
            extra_headers: Per-request headers (merged on top of defaults).

        Returns:
            Parsed JSON as ``dict``, or ``None`` if the request failed.
        """
        headers = {**self._default_headers}
        if extra_headers:
            headers.update(extra_headers)

        logger.debug("GET %s", url)

        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            return response.json()

        except Timeout:
            logger.warning("Timeout after %ss — GET %s", self._timeout, url)
        except ConnectionError as exc:
            logger.warning("Connection error — GET %s — %s", url, exc)
        except HTTPError as exc:
            logger.warning(
                "HTTP %s — GET %s — %s",
                exc.response.status_code,
                url,
                exc.response.text[:200],
            )
        except ValueError as exc:
            # requests.Response.json() raises ValueError on non-JSON bodies
            logger.warning("JSON decode error — GET %s — %s", url, exc)
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error — GET %s — %s", url, exc)

        return None