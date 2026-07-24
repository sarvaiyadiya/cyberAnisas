"""
modules/asn/clients/ipinfo.py

Client for the IPInfo API.

Docs: https://ipinfo.io/developers
Free tier: 50,000 requests/month (unauthenticated).
Authenticated: higher limits via IPINFO_TOKEN in .env.
"""

from typing import Optional
from app.core.http_client import HTTPClient
from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)

_IPINFO_BASE_URL = "https://ipinfo.io"


class IPInfoClient:
    """
    Wraps the IPInfo REST API.

    Automatically injects the Bearer token from ``settings.IPINFO_TOKEN``
    when one is configured, enabling the higher-rate authenticated tier.
    """

    def __init__(self) -> None:
        auth_headers: dict[str, str] = {}

        if settings.IPINFO_TOKEN:
            auth_headers["Authorization"] = f"Bearer {settings.IPINFO_TOKEN}"
            logger.debug("IPInfoClient: using authenticated requests.")
        else:
            logger.debug("IPInfoClient: running unauthenticated (50k req/month limit).")

        self._client = HTTPClient(default_headers=auth_headers)

    def lookup(self, ip: str) -> Optional[dict]:
        """
        Fetch basic intelligence for an IP address.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Raw JSON dict from IPInfo, or ``None`` if the request failed.
        """
        url = f"{_IPINFO_BASE_URL}/{ip}/json"
        logger.info("IPInfoClient: looking up %s", ip)
        return self._client.get(url)