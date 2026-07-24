"""
modules/asn/parsers/ripe_stat_parser.py

Parser for RIPE STAT API responses.

Responsibility: Convert raw RIPE STAT JSON → typed internal models.
No networking. No business logic. Pure transformation.

RIPE STAT API reference: https://stat.ripe.net/docs/data_api
"""

from typing import Optional
from app.core.logger import get_logger

logger = get_logger(__name__)

# Maximum prefixes to include in the full list.
# RIPE STAT can return thousands — cap to avoid payload bloat.
_MAX_PREFIXES_RETURNED = 100
_SAMPLE_SIZE = 10


class RIPEStatParser:
    """
    Converts raw RIPE STAT API responses into typed dicts/structures.

    Handles:
    - Announced prefix enumeration (IPv4 + IPv6 separation)
    - ASN neighbours (peers, upstreams, downstreams by type field)
    - RPKI validation state
    - AS overview (name, description)
    - Graceful handling of missing or malformed RIPE STAT envelopes
    """

    # ── Announced Prefixes ────────────────────────────────────────────────────

    @staticmethod
    def parse_announced_prefixes(data: Optional[dict]) -> dict:
        """
        Parse the ``/data/announced-prefixes`` RIPE STAT response.

        RIPE STAT envelope: ``data.prefixes[{prefix, timelines}]``

        Returns:
            Dict with keys:
              - ``ipv4`` (list[str]): IPv4 prefixes
              - ``ipv6`` (list[str]): IPv6 prefixes
              - ``total`` (int): total count
        """
        empty = {"ipv4": [], "ipv6": [], "total": 0}

        if not data:
            return empty

        inner = data.get("data", {})
        if not isinstance(inner, dict):
            return empty

        prefixes_raw = inner.get("prefixes", [])
        if not isinstance(prefixes_raw, list):
            return empty

        ipv4: list[str] = []
        ipv6: list[str] = []

        for entry in prefixes_raw:
            prefix = (entry.get("prefix") or "").strip()
            if not prefix:
                continue

            if ":" in prefix:  # IPv6 contains colons
                ipv6.append(prefix)
            else:
                ipv4.append(prefix)

        logger.debug(
            "RIPEStatParser(prefixes): ipv4=%d, ipv6=%d",
            len(ipv4),
            len(ipv6),
        )

        return {
            "ipv4": sorted(ipv4),
            "ipv6": sorted(ipv6),
            "total": len(ipv4) + len(ipv6),
        }

    # ── ASN Neighbours ────────────────────────────────────────────────────────

    @staticmethod
    def parse_asn_neighbours(data: Optional[dict]) -> dict:
        """
        Parse the ``/data/asn-neighbours`` RIPE STAT response.

        RIPE STAT types: ``left`` (upstream), ``right`` (downstream), ``uncertain``

        Returns:
            Dict with keys:
              - ``peers`` (list[dict])
              - ``upstreams`` (list[dict])
              - ``downstreams`` (list[dict])
              - ``peer_count`` (int)
              - ``upstream_count`` (int)
              - ``downstream_count`` (int)
        """
        empty = {
            "peers": [],
            "upstreams": [],
            "downstreams": [],
            "peer_count": 0,
            "upstream_count": 0,
            "downstream_count": 0,
        }

        if not data:
            return empty

        inner = data.get("data", {})
        if not isinstance(inner, dict):
            return empty

        neighbours = inner.get("neighbours", [])
        if not isinstance(neighbours, list):
            return empty

        peers: list[dict] = []
        upstreams: list[dict] = []
        downstreams: list[dict] = []

        for nb in neighbours:
            asn_num = nb.get("asn")
            nb_type = (nb.get("type") or "").lower()
            power = nb.get("power", 0)  # Higher = more traffic volume

            if asn_num is None:
                continue

            entry = {"asn": f"AS{asn_num}", "name": ""}

            # RIPE STAT uses "left" = provider (upstream), "right" = customer (downstream)
            if nb_type == "left":
                upstreams.append(entry)
            elif nb_type == "right":
                downstreams.append(entry)
            else:
                # "uncertain" or missing — treat as peer
                peers.append(entry)

        logger.debug(
            "RIPEStatParser(neighbours): peers=%d, upstreams=%d, downstreams=%d",
            len(peers),
            len(upstreams),
            len(downstreams),
        )

        return {
            "peers": peers[:50],
            "upstreams": upstreams[:50],
            "downstreams": downstreams[:50],
            "peer_count": len(peers),
            "upstream_count": len(upstreams),
            "downstream_count": len(downstreams),
        }

    # ── RPKI Validation ───────────────────────────────────────────────────────

    @staticmethod
    def parse_rpki_validation(data: Optional[dict]) -> dict:
        """
        Parse the ``/data/rpki-validation`` RIPE STAT response.

        RIPE STAT states: ``valid``, ``invalid``, ``unknown``, ``not-found``

        Returns:
            Dict with keys:
              - ``status`` (str): "valid", "invalid", "unknown", or "unavailable"
              - ``roas`` (list[dict]): Route Origin Authorizations found
              - ``source`` (str): "RIPE STAT RPKI"
        """
        if not data:
            return {"status": "unavailable", "roas": [], "source": "RIPE STAT RPKI"}

        inner = data.get("data", {})
        if not isinstance(inner, dict):
            return {"status": "unavailable", "roas": [], "source": "RIPE STAT RPKI"}

        # RIPE STAT returns a "validating_roas" list and overall "status"
        status_raw = (inner.get("status") or "unknown").lower()

        # Normalize status labels
        _STATUS_MAP = {
            "valid": "valid",
            "invalid": "invalid",
            "unknown": "unknown",
            "not-found": "not-found",
        }
        status = _STATUS_MAP.get(status_raw, "unknown")

        # Extract individual ROAs
        roas: list[dict] = []
        for roa in inner.get("validating_roas", []):
            try:
                roas.append({
                    "origin": f"AS{roa.get('origin', '')}",
                    "prefix": roa.get("prefix", ""),
                    "max_length": roa.get("max_length"),
                    "validity": roa.get("validity", "unknown"),
                })
            except (KeyError, TypeError):
                continue

        logger.debug("RIPEStatParser(rpki): status=%s, roas=%d", status, len(roas))

        return {
            "status": status,
            "roas": roas,
            "source": "RIPE STAT RPKI",
        }

    # ── AS Overview ───────────────────────────────────────────────────────────

    @staticmethod
    def parse_as_overview(data: Optional[dict]) -> dict:
        """
        Parse the ``/data/as-overview`` RIPE STAT response.

        Returns:
            Dict with keys:
              - ``name`` (str|None)
              - ``description`` (str|None)
              - ``country`` (str|None)
              - ``announced`` (bool): whether the ASN is currently routing
        """
        empty = {"name": None, "description": None, "country": None, "announced": None}

        if not data:
            return empty

        inner = data.get("data", {})
        if not isinstance(inner, dict):
            return empty

        # "holder" is the human-readable name in RIPE STAT
        holder = inner.get("holder") or None
        announced = inner.get("announced")

        # Some fields live in "resource" sub-dict
        block = inner.get("block", {})
        description = block.get("desc") or None
        country = block.get("country") or None

        logger.debug("RIPEStatParser(overview): holder=%s, announced=%s", holder, announced)

        return {
            "name": holder,
            "description": description,
            "country": country,
            "announced": announced,
        }

    # ── Routing Status ────────────────────────────────────────────────────────

    @staticmethod
    def parse_routing_status(data: Optional[dict]) -> dict:
        """
        Parse ``/data/routing-status`` for a specific IP to extract origin ASN.

        Returns:
            Dict with ``origin_asns`` (list[str]) and ``is_routed`` (bool).
        """
        empty = {"origin_asns": [], "is_routed": False}

        if not data:
            return empty

        inner = data.get("data", {})
        if not isinstance(inner, dict):
            return empty

        origin_asns: list[str] = []

        # "first_seen" / "last_seen" / "origins" may appear
        for origin in inner.get("origins", []):
            asn_str = str(origin.get("origin", "")).strip()
            if asn_str and asn_str.isdigit():
                origin_asns.append(f"AS{asn_str}")

        is_routed = bool(origin_asns)

        logger.debug(
            "RIPEStatParser(routing): origin_asns=%s, routed=%s",
            origin_asns,
            is_routed,
        )

        return {"origin_asns": origin_asns, "is_routed": is_routed}
