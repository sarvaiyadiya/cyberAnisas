"""
modules/asn/clients/ripe_stat.py

Client for the RIPE STAT public REST API.

RIPE STAT (https://stat.ripe.net/docs/data_api) is a globally authoritative
BGP data source operated by RIPE NCC. It provides:

  - Announced prefix lists for any ASN                 (/data/announced-prefixes)
  - Routing status for any IP or prefix                (/data/routing-status)
  - ASN neighbours (peers, upstreams, downstreams)     (/data/asn-neighbours)
  - RPKI validation status                             (/data/rpki-validation)
  - Geographic origin routing data                     (/data/geolocation)

All endpoints are public, require no API key, and impose no strict rate limit
under fair-use conditions.

This client is the primary FALLBACK when BGPView is unreachable.
"""

from typing import Optional
from app.core.http_client import HTTPClient
from app.core.logger import get_logger

logger = get_logger(__name__)

_RIPE_STAT_BASE = "https://stat.ripe.net/data"
_SOURCEAPP = "ANISAS-intelligence"


def _normalize_asn(asn: str) -> str:
    """Strip 'AS' prefix, returning the numeric string."""
    return asn.upper().lstrip("AS")


class RIPEStatClient:
    """
    Client for RIPE STAT data API endpoints.

    Used as fallback BGP intelligence source when BGPView is unavailable.
    All responses follow the RIPE STAT envelope:
      ``{"data": {...}, "data_call_status": "..."}``
    """

    def __init__(self) -> None:
        self._client = HTTPClient()

    def get_announced_prefixes(self, asn: str) -> Optional[dict]:
        """
        Get all prefixes currently announced by an ASN.

        Endpoint: GET /data/announced-prefixes/data.json?resource=AS{n}

        Args:
            asn: ASN string (``"AS15169"`` or ``"15169"``).

        Returns:
            RIPE STAT response dict, or ``None`` on failure.
        """
        asn_num = _normalize_asn(asn)
        url = f"{_RIPE_STAT_BASE}/announced-prefixes/data.json"
        params = {"resource": f"AS{asn_num}", "sourceapp": _SOURCEAPP}
        logger.info("RIPEStatClient: fetching announced prefixes for AS%s", asn_num)
        return self._client.get(url, params=params)

    def get_asn_neighbours(self, asn: str) -> Optional[dict]:
        """
        Get BGP neighbours (peers, upstreams, downstreams) for an ASN.

        Endpoint: GET /data/asn-neighbours/data.json?resource=AS{n}

        Args:
            asn: ASN string.

        Returns:
            RIPE STAT neighbours response, or ``None`` on failure.
        """
        asn_num = _normalize_asn(asn)
        url = f"{_RIPE_STAT_BASE}/asn-neighbours/data.json"
        params = {"resource": f"AS{asn_num}", "sourceapp": _SOURCEAPP}
        logger.info("RIPEStatClient: fetching ASN neighbours for AS%s", asn_num)
        return self._client.get(url, params=params)

    def get_rpki_validation(self, asn: str, prefix: str) -> Optional[dict]:
        """
        Validate an ASN+prefix pair against RPKI Route Origin Authorizations.

        Endpoint: GET /data/rpki-validation/data.json?resource=AS{n}&prefix={p}

        Args:
            asn:    ASN string.
            prefix: CIDR prefix string (e.g. ``"8.8.8.0/24"``).

        Returns:
            RIPE STAT RPKI validation response, or ``None`` on failure.
        """
        asn_num = _normalize_asn(asn)
        url = f"{_RIPE_STAT_BASE}/rpki-validation/data.json"
        params = {
            "resource": f"AS{asn_num}",
            "prefix": prefix,
            "sourceapp": _SOURCEAPP,
        }
        logger.info(
            "RIPEStatClient: RPKI validation for AS%s / %s", asn_num, prefix
        )
        return self._client.get(url, params=params)

    def get_routing_status(self, ip: str) -> Optional[dict]:
        """
        Get BGP routing status for a specific IP address or prefix.

        Endpoint: GET /data/routing-status/data.json?resource={ip}

        Args:
            ip: IP address or CIDR prefix string.

        Returns:
            RIPE STAT routing status response, or ``None`` on failure.
        """
        url = f"{_RIPE_STAT_BASE}/routing-status/data.json"
        params = {"resource": ip, "sourceapp": _SOURCEAPP}
        logger.info("RIPEStatClient: fetching routing status for %s", ip)
        return self._client.get(url, params=params)

    def get_asn_overview(self, asn: str) -> Optional[dict]:
        """
        Get high-level ASN overview including name and description.

        Endpoint: GET /data/as-overview/data.json?resource=AS{n}

        Args:
            asn: ASN string.

        Returns:
            RIPE STAT AS overview response, or ``None`` on failure.
        """
        asn_num = _normalize_asn(asn)
        url = f"{_RIPE_STAT_BASE}/as-overview/data.json"
        params = {"resource": f"AS{asn_num}", "sourceapp": _SOURCEAPP}
        logger.info("RIPEStatClient: fetching ASN overview for AS%s", asn_num)
        return self._client.get(url, params=params)

    def get_routing_history(self, resource: str) -> Optional[dict]:
        """Return bounded-source routing history for an ASN or prefix."""
        normalized = (
            f"AS{_normalize_asn(resource)}"
            if resource.upper().startswith("AS")
            else resource
        )
        url = f"{_RIPE_STAT_BASE}/routing-history/data.json"
        params = {
            "resource": normalized,
            "max_rows": 100,
            "include_first_hop": "true",
            "normalise_visibility": "true",
            "sourceapp": _SOURCEAPP,
        }
        logger.info(
            "RIPEStatClient: fetching routing history for %s",
            normalized,
        )
        return self._client.get(url, params=params)
