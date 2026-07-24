"""
modules/asn/parsers/bgp_parser.py

Parser for the BGPView API response.

Responsibility: Convert raw BGPView JSON → typed ``BGPInfo`` model.
No networking. No business logic. Pure transformation.
"""

from typing import Optional
from app.modules.asn.models import BGPInfo
from app.core.logger import get_logger

logger = get_logger(__name__)


class BGPParser:
    """
    Converts raw BGPView API responses (ASN + prefixes) into a
    structured ``BGPInfo`` object.

    Two separate BGPView calls are merged here:
    - ``/asn/{asn}``          → name, description, country
    - ``/asn/{asn}/prefixes`` → ipv4_prefixes, ipv6_prefixes
    """

    @staticmethod
    def parse(
        asn_data: Optional[dict],
        prefix_data: Optional[dict],
        asn: Optional[str] = None,
    ) -> BGPInfo:
        """
        Parse BGPView ASN and prefix API responses.

        Args:
            asn_data:    Response from ``GET /asn/{asn}``.
            prefix_data: Response from ``GET /asn/{asn}/prefixes``.
            asn:         The raw ASN string (e.g. ``"AS15169"``), used as fallback.

        Returns:
            Populated :class:`BGPInfo` instance.
            All fields remain ``None`` / empty lists if data is missing.
        """
        name: Optional[str] = None
        description: Optional[str] = None
        country: Optional[str] = None
        ipv4: list[str] = []
        ipv6: list[str] = []

        # ── ASN metadata ──────────────────────────────────────────────────────
        if asn_data and isinstance(asn_data.get("data"), dict):
            details = asn_data["data"]
            name = details.get("name")
            description = details.get("description")
            country = details.get("country_code")

        # ── Prefix lists ──────────────────────────────────────────────────────
        if prefix_data and isinstance(prefix_data.get("data"), dict):
            pdata = prefix_data["data"]

            for item in pdata.get("ipv4_prefixes", []):
                prefix = item.get("prefix")
                if prefix:
                    ipv4.append(prefix)

            for item in pdata.get("ipv6_prefixes", []):
                prefix = item.get("prefix")
                if prefix:
                    ipv6.append(prefix)

        prefix_count = len(ipv4) + len(ipv6)

        logger.debug(
            "BGPParser: name=%s, ipv4=%d, ipv6=%d, total=%d",
            name,
            len(ipv4),
            len(ipv6),
            prefix_count,
        )

        return BGPInfo(
            asn_number=asn,
            name=name,
            description=description,
            country=country,
            ipv4_prefixes=ipv4,
            ipv6_prefixes=ipv6,
            prefix_count=prefix_count,
        )