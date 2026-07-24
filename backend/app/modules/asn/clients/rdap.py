"""
modules/asn/clients/rdap.py

Client for the RDAP (Registration Data Access Protocol) API.

RDAP is the standards-based successor to WHOIS, providing structured JSON
responses from Regional Internet Registries (ARIN, RIPE, APNIC, etc.).

Public endpoint: https://rdap.org — routes to the correct RIR automatically.
"""

from typing import Optional
from app.core.http_client import HTTPClient
from app.core.logger import get_logger

logger = get_logger(__name__)

_RDAP_BASE_URL = "https://rdap.org/ip"


class RDAPClient:
    """
    Client for querying RDAP registration data about an IP address.

    Uses rdap.org as a bootstrap aggregator that automatically proxies
    the request to the authoritative RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC).
    """

    def __init__(self) -> None:
        self._client = HTTPClient()

    def lookup(self, ip: str) -> Optional[dict]:
        """
        Fetch RDAP network registration data for an IP address.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Raw RDAP JSON dict, or ``None`` if the request failed.
        """
        url = f"{_RDAP_BASE_URL}/{ip}"
        logger.info("RDAPClient: looking up %s", ip)
        return self._client.get(url)