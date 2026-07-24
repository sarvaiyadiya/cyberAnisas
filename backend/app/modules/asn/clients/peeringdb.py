"""
modules/asn/clients/peeringdb.py

Client for the PeeringDB public API.

PeeringDB is the authoritative global database for Internet Exchange Points
and network peering information.

Docs:  https://www.peeringdb.com/apidocs/
Auth:  No key required for read access. Optional Bearer token for higher limits.
"""

from typing import Optional
from app.core.http_client import HTTPClient
from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)

_PEERINGDB_BASE_URL = "https://www.peeringdb.com/api"


def _normalize_asn(asn: str) -> str:
    """Strip AS prefix from an ASN string, returning the numeric portion."""
    return asn.upper().lstrip("AS")


class PeeringDBClient:
    """
    Client for the PeeringDB REST API.

    Provides:
    - Network profile (NOC/abuse contacts, website, peering policy, info type)
    - Internet Exchange membership list
    - Organisation-level multi-ASN detection
    """

    def __init__(self) -> None:
        auth_headers: dict[str, str] = {}

        if settings.PEERINGDB_TOKEN:
            auth_headers["Authorization"] = f"Api-Key {settings.PEERINGDB_TOKEN}"
            logger.debug("PeeringDBClient: using authenticated requests.")
        else:
            logger.debug("PeeringDBClient: running unauthenticated.")

        self._client = HTTPClient(default_headers=auth_headers)

    # ── Public interface ──────────────────────────────────────────────────────

    def get_network_by_asn(self, asn: str) -> Optional[dict]:
        """
        Retrieve the PeeringDB network record for an ASN.

        Args:
            asn: ASN string (``"AS15169"`` or ``"15169"``).

        Returns:
            PeeringDB ``net`` object dict (wrapping ``data`` array), or ``None``.
        """
        asn_number = _normalize_asn(asn)
        url = f"{_PEERINGDB_BASE_URL}/net"
        params = {"asn": asn_number, "depth": 2}
        logger.info("PeeringDBClient: fetching network for AS%s", asn_number)
        return self._client.get(url, params=params)

    def get_ix_memberships(self, net_id: int) -> Optional[dict]:
        """
        Retrieve Internet Exchange memberships for a PeeringDB network ID.

        Args:
            net_id: PeeringDB internal network identifier.

        Returns:
            ``netixlan`` list response, or ``None`` on failure.
        """
        url = f"{_PEERINGDB_BASE_URL}/netixlan"
        params = {"net_id": net_id, "depth": 1}
        logger.info("PeeringDBClient: fetching IXP memberships for net_id=%d", net_id)
        return self._client.get(url, params=params)

    def get_org_networks(self, org_id: int) -> Optional[dict]:
        """
        Retrieve all networks belonging to a PeeringDB organisation.

        Used for multi-ASN detection — returns every ASN under the same org.

        Args:
            org_id: PeeringDB internal organisation identifier.

        Returns:
            ``net`` list response for the org, or ``None`` on failure.
        """
        url = f"{_PEERINGDB_BASE_URL}/net"
        params = {"org_id": org_id}
        logger.info("PeeringDBClient: fetching org networks for org_id=%d", org_id)
        return self._client.get(url, params=params)
