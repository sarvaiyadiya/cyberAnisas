"""
modules/asn/parsers/peeringdb_parser.py

Parser for the PeeringDB public API response.

Responsibility: Convert raw PeeringDB JSON → typed ``PeeringDBData`` model.
No networking. No business logic. Pure transformation.

PeeringDB network object reference:
    https://www.peeringdb.com/apidocs/#tag/Network
"""

from typing import Optional
from app.modules.asn.models import PeeringDBData
from app.core.logger import get_logger

logger = get_logger(__name__)


class PeeringDBParser:
    """
    Converts raw PeeringDB API responses into a structured ``PeeringDBData`` object.

    Handles:
    - Contact email extraction by role (NOC, Abuse, Policy, Technical)
    - IXP name list from netixlan response
    - Multi-ASN detection from org-networks response
    - Graceful handling of missing or restricted fields (PeeringDB hides some
      contact details for unauthenticated requests)
    """

    @staticmethod
    def parse_network(
        network_data: Optional[dict],
        ixp_data: Optional[dict] = None,
        org_networks_data: Optional[dict] = None,
    ) -> PeeringDBData:
        """
        Parse PeeringDB network, IXP, and org-network responses.

        Args:
            network_data:      Response from ``GET /api/net?asn={n}&depth=2``.
            ixp_data:          Response from ``GET /api/netixlan?net_id={id}``.
            org_networks_data: Response from ``GET /api/net?org_id={id}``
                               (for multi-ASN detection).

        Returns:
            Populated :class:`PeeringDBData` instance.
        """
        if not network_data:
            return PeeringDBData()

        records = network_data.get("data", [])
        if not records:
            logger.debug("PeeringDBParser: no network records in response")
            return PeeringDBData()

        net = records[0]  # Primary network record

        website = net.get("website") or None
        peering_policy = net.get("policy_general") or None
        info_type = net.get("info_type") or None

        noc_email, abuse_email, support_email = PeeringDBParser._extract_emails(net)

        exchanges = PeeringDBParser._extract_exchanges(ixp_data)
        related_asns = PeeringDBParser._extract_org_asns(org_networks_data)

        logger.debug(
            "PeeringDBParser: policy=%s, type=%s, exchanges=%d, related_asns=%d",
            peering_policy,
            info_type,
            len(exchanges),
            len(related_asns),
        )

        return PeeringDBData(
            website=website,
            noc_email=noc_email,
            abuse_email=abuse_email,
            support_email=support_email,
            peering_policy=peering_policy,
            info_type=info_type,
            internet_exchanges=exchanges,
            related_asns=related_asns,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_emails(
        net: dict,
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract NOC, abuse, and support email addresses from a PeeringDB net object.

        PeeringDB uses a ``poc_set`` (Points of Contact) list with role labels.
        Unauthenticated requests may receive redacted email addresses.

        Returns:
            Tuple of (noc_email, abuse_email, support_email).
        """
        noc_email: Optional[str] = None
        abuse_email: Optional[str] = None
        support_email: Optional[str] = None

        poc_set = net.get("poc_set") or []

        for poc in poc_set:
            role = (poc.get("role") or "").lower()
            email = (poc.get("email") or "").strip() or None

            if not email:
                continue

            if role == "noc" and noc_email is None:
                noc_email = email
            elif role == "abuse" and abuse_email is None:
                abuse_email = email
            elif role in ("technical", "support", "policy") and support_email is None:
                support_email = email

        # Fallback: use top-level email fields if poc_set is absent
        if noc_email is None:
            noc_email = net.get("info_email") or None
        if abuse_email is None:
            abuse_email = net.get("abuse_email") or None

        return noc_email, abuse_email, support_email

    @staticmethod
    def _extract_exchanges(ixp_data: Optional[dict]) -> list[str]:
        """
        Build a list of Internet Exchange names from a netixlan response.

        Args:
            ixp_data: Response from ``GET /api/netixlan?net_id={id}``.

        Returns:
            Deduplicated list of IXP name strings.
        """
        if not ixp_data:
            return []

        seen: set[str] = set()
        exchanges: list[str] = []

        for entry in ixp_data.get("data", []):
            name = (entry.get("name") or "").strip()
            if name and name not in seen:
                seen.add(name)
                exchanges.append(name)

        return exchanges

    @staticmethod
    def _extract_org_asns(org_networks_data: Optional[dict]) -> list[str]:
        """
        Extract all ASNs belonging to the same PeeringDB organisation.

        Used for multi-ASN detection. An org like Google LLC has many ASNs
        (AS15169, AS36040, AS19527, etc.).

        Args:
            org_networks_data: Response from ``GET /api/net?org_id={id}``.

        Returns:
            Sorted list of ASN strings (``"AS{n}"``), deduplicated.
        """
        if not org_networks_data:
            return []

        seen: set[int] = set()
        asns: list[str] = []

        for net in org_networks_data.get("data", []):
            try:
                asn_num = int(net.get("asn", 0))
            except (ValueError, TypeError):
                continue

            if asn_num and asn_num not in seen:
                seen.add(asn_num)
                asns.append(f"AS{asn_num}")

        # Return sorted numerically for deterministic output
        return sorted(asns, key=lambda x: int(x[2:]))
