"""
modules/asn/clients/bgpview.py

Client for the BGPView public API.

Docs:   https://bgpview.docs.apiary.io/
Limits: No API key required. Fair-use rate limits apply.
"""

from typing import Optional
from app.core.http_client import HTTPClient
from app.core.logger import get_logger

logger = get_logger(__name__)

_BGPVIEW_BASE_URL = "https://api.bgpview.io"

# Maximum peers/upstreams/downstreams to return per direction.
# Prevents extremely large payloads for tier-1 ASNs.
_MAX_RELATIONSHIPS = 50


def _strip_asn_prefix(asn: str) -> str:
    """
    Normalise an ASN string to its numeric form.

    Args:
        asn: Raw ASN string, e.g. ``"AS15169"`` or ``"15169"``.

    Returns:
        Numeric string, e.g. ``"15169"``.
    """
    return asn.upper().lstrip("AS")


class BGPViewClient:
    """
    Client for the BGPView routing intelligence API.

    Covers:
    - ASN metadata      (GET /asn/{n})
    - Prefix lists      (GET /asn/{n}/prefixes)
    - Peers             (GET /asn/{n}/peers)
    - Upstreams         (GET /asn/{n}/upstreams)
    - Downstreams       (GET /asn/{n}/downstreams)
    """

    def __init__(self) -> None:
        self._client = HTTPClient()

    # ── ASN Intelligence ──────────────────────────────────────────────────────

    def get_asn(self, asn: str) -> Optional[dict]:
        """
        Retrieve metadata for an Autonomous System Number.

        Args:
            asn: ASN in any format (``"AS15169"`` or ``"15169"``).

        Returns:
            BGPView ASN JSON response, or ``None`` on failure.
        """
        asn_number = _strip_asn_prefix(asn)
        url = f"{_BGPVIEW_BASE_URL}/asn/{asn_number}"
        logger.info("BGPViewClient: fetching ASN details for AS%s", asn_number)
        return self._client.get(url)

    def get_prefixes(self, asn: str) -> Optional[dict]:
        """
        Retrieve all IPv4 and IPv6 prefixes announced by an ASN.

        Args:
            asn: ASN in any format (``"AS15169"`` or ``"15169"``).

        Returns:
            BGPView prefix JSON response, or ``None`` on failure.
        """
        asn_number = _strip_asn_prefix(asn)
        url = f"{_BGPVIEW_BASE_URL}/asn/{asn_number}/prefixes"
        logger.info("BGPViewClient: fetching prefixes for AS%s", asn_number)
        return self._client.get(url)

    # ── BGP Relationships ─────────────────────────────────────────────────────

    def get_peers(self, asn: str) -> Optional[dict]:
        """
        Retrieve direct BGP peers for an ASN.

        Args:
            asn: ASN in any format.

        Returns:
            BGPView peers JSON response, or ``None`` on failure.
        """
        asn_number = _strip_asn_prefix(asn)
        url = f"{_BGPVIEW_BASE_URL}/asn/{asn_number}/peers"
        logger.info("BGPViewClient: fetching peers for AS%s", asn_number)
        return self._client.get(url)

    def get_upstreams(self, asn: str) -> Optional[dict]:
        """
        Retrieve upstream transit providers for an ASN.

        Args:
            asn: ASN in any format.

        Returns:
            BGPView upstreams JSON response, or ``None`` on failure.
        """
        asn_number = _strip_asn_prefix(asn)
        url = f"{_BGPVIEW_BASE_URL}/asn/{asn_number}/upstreams"
        logger.info("BGPViewClient: fetching upstreams for AS%s", asn_number)
        return self._client.get(url)

    def get_downstreams(self, asn: str) -> Optional[dict]:
        """
        Retrieve downstream customer networks for an ASN.

        Args:
            asn: ASN in any format.

        Returns:
            BGPView downstreams JSON response, or ``None`` on failure.
        """
        asn_number = _strip_asn_prefix(asn)
        url = f"{_BGPVIEW_BASE_URL}/asn/{asn_number}/downstreams"
        logger.info("BGPViewClient: fetching downstreams for AS%s", asn_number)
        return self._client.get(url)
