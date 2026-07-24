"""
modules/asn/parsers/bgp_peers_parser.py

Parser for BGPView peer/upstream/downstream relationship endpoints.

Responsibility: Convert raw BGPView relationship JSON → ``BGPRelationshipsData``.
No networking. No business logic. Pure transformation.
"""

from typing import Optional
from app.modules.asn.models import BGPRelationshipsData
from app.core.logger import get_logger

logger = get_logger(__name__)

# Cap results per direction to keep response payloads manageable.
_MAX_PER_DIRECTION = 50


def _deduplicate_asns(entries: list[dict]) -> list[dict[str, str]]:
    """
    Merge IPv4 and IPv6 peer lists, deduplicating by ASN number.

    Args:
        entries: List of dicts with ``asn`` (int) and ``name`` (str) keys.

    Returns:
        Deduplicated list of ``{"asn": "AS{n}", "name": "..."}`` dicts,
        limited to ``_MAX_PER_DIRECTION`` entries.
    """
    seen: set[int] = set()
    result: list[dict[str, str]] = []

    for item in entries:
        try:
            asn_num = int(item.get("asn", 0))
            name = str(item.get("name", "") or "")
        except (ValueError, TypeError):
            continue

        if asn_num and asn_num not in seen:
            seen.add(asn_num)
            result.append({"asn": f"AS{asn_num}", "name": name})

        if len(result) >= _MAX_PER_DIRECTION:
            break

    return result


class BGPPeersParser:
    """
    Converts raw BGPView peer/upstream/downstream API responses into a
    structured ``BGPRelationshipsData`` object.

    BGPView returns separate IPv4 and IPv6 lists for each relationship type.
    This parser merges and deduplicates them by ASN number.
    """

    @staticmethod
    def parse(
        peers_data: Optional[dict],
        upstreams_data: Optional[dict],
        downstreams_data: Optional[dict],
    ) -> BGPRelationshipsData:
        """
        Parse BGPView relationship responses.

        Args:
            peers_data:      Response from ``GET /asn/{n}/peers``.
            upstreams_data:  Response from ``GET /asn/{n}/upstreams``.
            downstreams_data: Response from ``GET /asn/{n}/downstreams``.

        Returns:
            Populated :class:`BGPRelationshipsData`. Empty lists if data absent.
        """
        peers = BGPPeersParser._extract_peers(peers_data)
        upstreams = BGPPeersParser._extract_upstreams(upstreams_data)
        downstreams = BGPPeersParser._extract_downstreams(downstreams_data)

        logger.debug(
            "BGPPeersParser: peers=%d, upstreams=%d, downstreams=%d",
            len(peers),
            len(upstreams),
            len(downstreams),
        )

        return BGPRelationshipsData(
            peers=peers,
            upstreams=upstreams,
            downstreams=downstreams,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_peers(data: Optional[dict]) -> list[dict[str, str]]:
        """Merge ipv4_peers + ipv6_peers, deduplicate by ASN."""
        if not data or not isinstance(data.get("data"), dict):
            return []

        raw = data["data"]
        combined = list(raw.get("ipv4_peers", [])) + list(raw.get("ipv6_peers", []))
        return _deduplicate_asns(combined)

    @staticmethod
    def _extract_upstreams(data: Optional[dict]) -> list[dict[str, str]]:
        """Merge ipv4_upstreams + ipv6_upstreams, deduplicate by ASN."""
        if not data or not isinstance(data.get("data"), dict):
            return []

        raw = data["data"]
        combined = list(raw.get("ipv4_upstreams", [])) + list(raw.get("ipv6_upstreams", []))
        return _deduplicate_asns(combined)

    @staticmethod
    def _extract_downstreams(data: Optional[dict]) -> list[dict[str, str]]:
        """Merge ipv4_downstreams + ipv6_downstreams, deduplicate by ASN."""
        if not data or not isinstance(data.get("data"), dict):
            return []

        raw = data["data"]
        combined = list(raw.get("ipv4_downstreams", [])) + list(raw.get("ipv6_downstreams", []))
        return _deduplicate_asns(combined)
