"""
modules/asn/parsers/ipinfo_parser.py

Parser for the IPInfo API response.

Responsibility: Convert raw IPInfo JSON → typed ``IPInfoData`` model.
No networking. No business logic. Pure transformation.
"""

from typing import Optional
from app.modules.asn.models import IPInfoData
from app.core.logger import get_logger

logger = get_logger(__name__)


class IPInfoParser:
    """
    Converts the raw IPInfo API JSON response into a structured ``IPInfoData`` object.

    IPInfo org field format: ``"AS15169 Google LLC"``
    This parser splits it into separate ``asn`` and ``organization`` fields.
    """

    @staticmethod
    def parse(data: dict) -> IPInfoData:
        """
        Parse a raw IPInfo JSON response.

        Args:
            data: Raw dict returned by the IPInfo API.

        Returns:
            Populated :class:`IPInfoData` instance.
        """
        asn: Optional[str] = None
        isp: Optional[str] = None
        organization: Optional[str] = None

        org_field: str = data.get("org", "") or ""

        if org_field.upper().startswith("AS"):
            # Format: "AS15169 Google LLC"
            parts = org_field.split(" ", 1)
            asn = parts[0]  # e.g. "AS15169"

            if len(parts) > 1:
                isp = parts[1]        # e.g. "Google LLC"
                organization = isp    # same value — may be enriched later by RDAP

        elif org_field:
            # Fallback: org field present but no AS prefix
            organization = org_field

        logger.debug(
            "IPInfoParser: parsed ASN=%s, ISP=%s, country=%s",
            asn,
            isp,
            data.get("country"),
        )

        return IPInfoData(
            asn=asn,
            isp=isp,
            organization=organization,
            country=data.get("country"),
            hostname=data.get("hostname"),
            city=data.get("city"),
            region=data.get("region"),
            timezone=data.get("timezone"),
        )