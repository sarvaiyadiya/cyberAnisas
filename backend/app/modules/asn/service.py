"""
modules/asn/service.py

ASN & ISP Intelligence Engine — Business Logic Layer (Module 1).

Responsibility:
  - Orchestrate calls across six intelligence sources:
      1. IPInfo       — Basic ASN, ISP, geolocation
      2. Team Cymru   — Fallback ASN resolution (when IPInfo returns none)
      3. RDAP         — Network registration, CIDR, registry, contacts, dates
      4. BGPView      — Prefix lists, ASN metadata, peers, upstreams, downstreams
      5. RIPE STAT    — BGP fallback (prefix lists, neighbours, RPKI, AS overview)
      6. PeeringDB    — ISP profile, NOC/abuse contacts, IXPs, multi-ASN
  - Merge results into a single ``ASNData`` model.
  - Compute a rule-based AI risk profile from collected data.
  - Track data provenance (which source provided which field).
  - Build response metadata (deterministic confidence scoring, timing, completeness).
  - Cache completed lookups to avoid hammering public APIs.

Architecture contract:
  - No HTTP code lives here.  All networking delegated to clients/.
  - No JSON parsing lives here.  All transformation delegated to parsers/.
  - One source failing NEVER crashes the pipeline.
  - No field is ever overwritten by a null/empty value from a later source.
  - isp_profile is ALWAYS populated when an ASN is resolved.
  - multi_asn is ALWAYS a structured object — never null.
"""

import time
import datetime
from typing import Optional, Dict, List

from app.core.logger import get_logger
from app.core.cache import TTLCache
from app.core.config import settings

from app.modules.asn.models import (
    ASNData,
    ISPProfile,
    ASNRelationships,
    SampledRelationshipList,
    AnnouncedPrefixes,
    RPKIStatus,
    MultiASNInfo,
    ResponseMetadata,
    ConfidenceBreakdown,
    AIRiskProfile,
    PaginatedList,
)

# ── Clients ───────────────────────────────────────────────────────────────────
from app.modules.asn.clients.ipinfo import IPInfoClient
from app.modules.asn.clients.rdap import RDAPClient
from app.modules.asn.clients.bgpview import BGPViewClient
from app.modules.asn.clients.peeringdb import PeeringDBClient
from app.modules.asn.clients.cymru import CymruClient
from app.modules.asn.clients.ripe_stat import RIPEStatClient

# ── Parsers ───────────────────────────────────────────────────────────────────
from app.modules.asn.parsers.ipinfo_parser import IPInfoParser
from app.modules.asn.parsers.rdap_parser import RDAPParser
from app.modules.asn.parsers.bgp_parser import BGPParser
from app.modules.asn.parsers.bgp_peers_parser import BGPPeersParser
from app.modules.asn.parsers.peeringdb_parser import PeeringDBParser
from app.modules.asn.parsers.ripe_stat_parser import RIPEStatParser

logger = get_logger(__name__)

# ── Module-level singletons ───────────────────────────────────────────────────
_ipinfo_client = IPInfoClient()
_rdap_client = RDAPClient()
_bgpview_client = BGPViewClient()
_peeringdb_client = PeeringDBClient()
_cymru_client = CymruClient()
_ripe_stat_client = RIPEStatClient()

# ── TTL cache ─────────────────────────────────────────────────────────────────
_cache: TTLCache = TTLCache(ttl_seconds=settings.CACHE_TTL_SECONDS)

# ── Display limits ────────────────────────────────────────────────────────────
_IXP_SAMPLE_SIZE = 20
_PREFIX_SAMPLE_SIZE = 20
_RELATIONSHIP_SAMPLE_SIZE = 20   # reduced from 50 to keep payload manageable


# =============================================================================
# Public API
# =============================================================================


def get_asn_information(ip: str) -> ASNData:
    """
    Perform a full ASN & ISP intelligence lookup for the given IP address.

    Queries six independent sources in order:
      1. IPInfo    — ASN, ISP, geolocation
      2. Cymru     — Fallback ASN resolution (zero rate-limit)
      3. RDAP      — Network registration, dates, contacts
      4. BGPView   — Prefix lists + ASN metadata + relationships
      5. RIPE STAT — BGP fallback (prefix lists, neighbours, RPKI, AS overview)
      6. PeeringDB — ISP profile, IXPs, multi-ASN

    Guarantees:
      - Each source is isolated in try/except; one failure never crashes the pipeline.
      - No field is ever overwritten by a null/empty value from a later source.
      - ``isp_profile`` is always populated when an ASN is resolved.
      - ``multi_asn`` is always a structured object (never null).

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        :class:`ASNData` with all available intelligence fields populated.
    """
    start_time = time.monotonic()

    # ── Cache hit ─────────────────────────────────────────────────────────────
    cached = _cache.get(ip)
    if cached is not None:
        logger.info("Cache HIT for %s — returning cached result", ip)
        if cached.metadata:
            cached.metadata.cache_status = "HIT"
        return cached

    logger.info("=== ASN Intelligence lookup STARTED for %s ===", ip)

    sources_queried: list[str] = []
    provenance: Dict[str, str] = {}
    asn: Optional[str] = None

    # BGP data availability flags — used by AI layer to distinguish
    # "BGP unavailable" from "BGP queried but zero prefixes confirmed"
    bgp_data_available: bool = False
    bgp_sources_tried: list[str] = []

    # Accumulated contact data from RDAP (used to seed isp_profile fallback)
    rdap_noc_email: Optional[str] = None
    rdap_abuse_email: Optional[str] = None

    result = ASNData(ip=ip)

    # =========================================================================
    # SOURCE 1 — IPInfo
    # =========================================================================
    try:
        raw_ipinfo = _ipinfo_client.lookup(ip)

        if raw_ipinfo:
            ipinfo = IPInfoParser.parse(raw_ipinfo)
            sources_queried.append("IPInfo")

            result.asn = ipinfo.asn
            result.isp = ipinfo.isp
            result.organization = ipinfo.organization
            result.country = ipinfo.country
            result.hostname = ipinfo.hostname
            result.city = ipinfo.city
            result.region = ipinfo.region
            result.timezone = ipinfo.timezone

            asn = ipinfo.asn

            _prov(provenance, "asn", "IPInfo", ipinfo.asn)
            _prov(provenance, "isp", "IPInfo", ipinfo.isp)
            _prov(provenance, "organization", "IPInfo", ipinfo.organization)
            _prov(provenance, "country", "IPInfo", ipinfo.country)
            _prov(provenance, "hostname", "IPInfo", ipinfo.hostname)
            _prov(provenance, "city", "IPInfo", ipinfo.city)
            _prov(provenance, "region", "IPInfo", ipinfo.region)
            _prov(provenance, "timezone", "IPInfo", ipinfo.timezone)

            logger.info("IPInfo: OK — ASN=%s, country=%s", asn, ipinfo.country)
        else:
            logger.warning("IPInfo: returned no data for %s", ip)

    except Exception as exc:  # noqa: BLE001
        logger.error("IPInfo: unexpected error for %s — %s", ip, exc)

    # =========================================================================
    # SOURCE 2 — Team Cymru (fallback ASN resolution)
    # Only runs when IPInfo returned no ASN.
    # =========================================================================
    if not asn:
        try:
            cymru_raw = _cymru_client.lookup(ip)

            if cymru_raw:
                sources_queried.append("TeamCymru")
                asn = cymru_raw.get("asn")
                result.asn = asn

                _prov(provenance, "asn", "TeamCymru", asn)

                # Never overwrite valid values
                if cymru_raw.get("country") and not result.country:
                    result.country = cymru_raw["country"]
                    _prov(provenance, "country", "TeamCymru", result.country)

                if cymru_raw.get("registry") and not result.registry:
                    result.registry = cymru_raw["registry"].upper()
                    _prov(provenance, "registry", "TeamCymru", result.registry)

                if cymru_raw.get("name") and not result.isp:
                    result.isp = cymru_raw["name"]
                    _prov(provenance, "isp", "TeamCymru", result.isp)

                logger.info("TeamCymru: OK — ASN=%s, prefix=%s", asn, cymru_raw.get("prefix"))
            else:
                logger.warning("TeamCymru: returned no data for %s", ip)

        except Exception as exc:  # noqa: BLE001
            logger.error("TeamCymru: unexpected error for %s — %s", ip, exc)

    # =========================================================================
    # SOURCE 3 — RDAP
    # =========================================================================
    try:
        raw_rdap = _rdap_client.lookup(ip)

        if raw_rdap:
            rdap = RDAPParser.parse(raw_rdap)
            sources_queried.append("RDAP")

            result.network_handle = rdap.handle
            result.network_name = rdap.network_name
            result.network_description = rdap.network_description
            result.registry = rdap.registry or result.registry
            result.whois_server = rdap.whois_server
            result.allocation_type = rdap.allocation_type
            result.network_status = rdap.status
            result.start_address = rdap.start_address
            result.end_address = rdap.end_address
            result.cidr_prefixes = rdap.cidr_prefixes
            result.registration_date = rdap.registration_date
            result.allocation_date = rdap.allocation_date
            result.last_changed_date = rdap.last_changed_date
            result.date_semantics = rdap.date_type_note

            # Never overwrite valid organization
            if rdap.organization and not result.organization:
                result.organization = rdap.organization
                _prov(provenance, "organization", "RDAP", rdap.organization)

            # Stash RDAP contact data for later ISP profile merge
            rdap_noc_email = rdap.noc_email
            rdap_abuse_email = rdap.abuse_email

            _prov(provenance, "network_handle", "RDAP", rdap.handle)
            _prov(provenance, "network_name", "RDAP", rdap.network_name)
            _prov(provenance, "registry", "RDAP", rdap.registry)
            _prov(provenance, "whois_server", "RDAP", rdap.whois_server)
            _prov(provenance, "allocation_type", "RDAP", rdap.allocation_type)
            _prov(provenance, "network_status", "RDAP", rdap.status)
            _prov(provenance, "start_address", "RDAP", rdap.start_address)
            _prov(provenance, "end_address", "RDAP", rdap.end_address)
            _prov(provenance, "cidr_prefixes", "RDAP", rdap.cidr_prefixes or None)
            _prov(provenance, "registration_date", "RDAP", rdap.registration_date)
            _prov(provenance, "allocation_date", "RDAP", rdap.allocation_date)
            _prov(provenance, "last_changed_date", "RDAP", rdap.last_changed_date)
            _prov(provenance, "network_description", "RDAP", rdap.network_description)
            _prov(provenance, "date_semantics", "RDAP", rdap.date_type_note)

            logger.info(
                "RDAP: OK — handle=%s, registry=%s, prefixes=%d, reg=%s",
                rdap.handle,
                rdap.registry,
                len(rdap.cidr_prefixes),
                rdap.registration_date,
            )
        else:
            logger.warning("RDAP: returned no data for %s", ip)

    except Exception as exc:  # noqa: BLE001
        logger.error("RDAP: unexpected error for %s — %s", ip, exc)

    # =========================================================================
    # SOURCE 4 — BGPView  (requires ASN)
    # =========================================================================
    bgpview_prefix_success = False
    bgpview_rel_success = False

    if asn:
        # ── 4a: ASN metadata + prefix lists ──────────────────────────────────
        try:
            bgp_sources_tried.append("BGPView")
            raw_asn_data = _bgpview_client.get_asn(asn)
            raw_prefix_data = _bgpview_client.get_prefixes(asn)

            bgp = BGPParser.parse(
                asn_data=raw_asn_data,
                prefix_data=raw_prefix_data,
                asn=asn,
            )

            # Only set BGP fields if the source returned useful data
            bgp_contributed = any([bgp.name, bgp.description, bgp.ipv4_prefixes, bgp.ipv6_prefixes])

            if bgp_contributed:
                sources_queried.append("BGPView")
                bgpview_prefix_success = True
                bgp_data_available = True

                result.origin_asn = bgp.asn_number or result.origin_asn
                _merge_str(result, "bgp_name", bgp.name, provenance, "BGPView")
                _merge_str(result, "bgp_description", bgp.description, provenance, "BGPView")
                _merge_str(result, "bgp_country", bgp.country, provenance, "BGPView")

                v4 = bgp.ipv4_prefixes
                v6 = bgp.ipv6_prefixes
                result.ipv4_prefixes = v4[:_PREFIX_SAMPLE_SIZE]
                result.ipv6_prefixes = v6[:_PREFIX_SAMPLE_SIZE]
                result.prefix_count = bgp.prefix_count

                result.announced_prefixes = _build_announced_prefixes(v4, v6, bgp.prefix_count, "BGPView")

                _prov(provenance, "origin_asn", "BGPView", bgp.asn_number)
                _prov(provenance, "ipv4_prefixes", "BGPView", v4 or None)
                _prov(provenance, "ipv6_prefixes", "BGPView", v6 or None)
                _prov(provenance, "prefix_count", "BGPView", bgp.prefix_count or None)
                _prov(provenance, "announced_prefixes", "BGPView", bgp.prefix_count or None)

            logger.info(
                "BGPView(prefixes): %s — name=%s, v4=%d, v6=%d",
                "OK" if bgp_contributed else "no data",
                bgp.name,
                len(bgp.ipv4_prefixes),
                len(bgp.ipv6_prefixes),
            )

        except Exception as exc:  # noqa: BLE001
            logger.error("BGPView(prefixes): unexpected error for %s — %s", ip, exc)

        # ── 4b: BGP relationships ─────────────────────────────────────────────
        try:
            raw_peers = _bgpview_client.get_peers(asn)
            raw_upstreams = _bgpview_client.get_upstreams(asn)
            raw_downstreams = _bgpview_client.get_downstreams(asn)

            rels = BGPPeersParser.parse(
                peers_data=raw_peers,
                upstreams_data=raw_upstreams,
                downstreams_data=raw_downstreams,
            )

            if rels.peers or rels.upstreams or rels.downstreams:
                bgpview_rel_success = True
                result.relationships = _build_relationships(
                    rels.peers, rels.upstreams, rels.downstreams, "BGPView"
                )
                _prov(provenance, "relationships", "BGPView", "peers/upstreams/downstreams")

                logger.info(
                    "BGPView(relationships): peers=%d, upstreams=%d, downstreams=%d",
                    len(rels.peers),
                    len(rels.upstreams),
                    len(rels.downstreams),
                )
            else:
                logger.info("BGPView(relationships): no relationship data returned")

        except Exception as exc:  # noqa: BLE001
            logger.error("BGPView(relationships): unexpected error for %s — %s", ip, exc)

    else:
        logger.warning("BGPView: skipped for %s — no ASN available", ip)

    # =========================================================================
    # SOURCE 5 — RIPE STAT  (BGP fallback + RPKI)
    # =========================================================================
    if asn:
        bgp_sources_tried.append("RIPE STAT")

        # ── 5a: BGP prefix + ASN overview fallback ────────────────────────────
        if not bgpview_prefix_success:
            try:
                raw_prefixes = _ripe_stat_client.get_announced_prefixes(asn)
                raw_overview = _ripe_stat_client.get_asn_overview(asn)

                prefix_result = RIPEStatParser.parse_announced_prefixes(raw_prefixes)
                overview_result = RIPEStatParser.parse_as_overview(raw_overview)

                ripe_contributed = (
                    prefix_result["total"] > 0
                    or overview_result.get("name")
                    or overview_result.get("description")
                )

                if ripe_contributed:
                    if "RIPE STAT" not in sources_queried:
                        sources_queried.append("RIPE STAT")
                    bgp_data_available = True

                    # Fill BGP metadata — never overwrite existing values
                    _merge_str(result, "bgp_name", overview_result.get("name"), provenance, "RIPE STAT")
                    _merge_str(result, "bgp_description", overview_result.get("description"), provenance, "RIPE STAT")
                    _merge_str(result, "bgp_country", overview_result.get("country"), provenance, "RIPE STAT")

                    if prefix_result["total"] > 0:
                        v4 = prefix_result["ipv4"]
                        v6 = prefix_result["ipv6"]

                        result.ipv4_prefixes = v4[:_PREFIX_SAMPLE_SIZE]
                        result.ipv6_prefixes = v6[:_PREFIX_SAMPLE_SIZE]
                        result.prefix_count = prefix_result["total"]
                        result.announced_prefixes = _build_announced_prefixes(
                            v4, v6, prefix_result["total"], "RIPE STAT"
                        )

                        if not result.origin_asn:
                            result.origin_asn = asn
                            _prov(provenance, "origin_asn", "RIPE STAT", asn)

                        _prov(provenance, "ipv4_prefixes", "RIPE STAT", v4 or None)
                        _prov(provenance, "ipv6_prefixes", "RIPE STAT", v6 or None)
                        _prov(provenance, "prefix_count", "RIPE STAT", prefix_result["total"])
                        _prov(provenance, "announced_prefixes", "RIPE STAT", prefix_result["total"])

                    logger.info(
                        "RIPE STAT(BGP): OK — name=%s, prefixes=%d",
                        result.bgp_name,
                        result.prefix_count,
                    )
                else:
                    logger.info("RIPE STAT(BGP): no data returned for %s", asn)

            except Exception as exc:  # noqa: BLE001
                logger.error("RIPE STAT(prefixes): unexpected error for %s — %s", ip, exc)

        # ── 5b: BGP relationships fallback ────────────────────────────────────
        if not bgpview_rel_success:
            try:
                raw_neighbours = _ripe_stat_client.get_asn_neighbours(asn)
                nb_result = RIPEStatParser.parse_asn_neighbours(raw_neighbours)

                nb_contributed = (
                    nb_result["peer_count"]
                    or nb_result["upstream_count"]
                    or nb_result["downstream_count"]
                )

                if nb_contributed:
                    if "RIPE STAT" not in sources_queried:
                        sources_queried.append("RIPE STAT")

                    result.relationships = _build_relationships(
                        nb_result["peers"],
                        nb_result["upstreams"],
                        nb_result["downstreams"],
                        "RIPE STAT",
                        peer_count=nb_result["peer_count"],
                        upstream_count=nb_result["upstream_count"],
                        downstream_count=nb_result["downstream_count"],
                    )
                    _prov(
                        provenance,
                        "relationships",
                        "RIPE STAT",
                        f"peers={nb_result['peer_count']}",
                    )

                    logger.info(
                        "RIPE STAT(neighbours): peers=%d, upstreams=%d, downstreams=%d",
                        nb_result["peer_count"],
                        nb_result["upstream_count"],
                        nb_result["downstream_count"],
                    )
                else:
                    logger.info("RIPE STAT(neighbours): no neighbour data for %s", asn)

            except Exception as exc:  # noqa: BLE001
                logger.error("RIPE STAT(neighbours): unexpected error for %s — %s", ip, exc)

        # ── 5c: RPKI validation ───────────────────────────────────────────────
        primary_prefix = (result.cidr_prefixes or [None])[0]

        if primary_prefix:
            try:
                raw_rpki = _ripe_stat_client.get_rpki_validation(asn, primary_prefix)
                rpki_result = RIPEStatParser.parse_rpki_validation(raw_rpki)

                if "RIPE STAT" not in sources_queried:
                    sources_queried.append("RIPE STAT")

                result.rpki = RPKIStatus(
                    status=rpki_result["status"],
                    roas=rpki_result["roas"],
                    validated_prefix=primary_prefix,
                    source=rpki_result["source"],
                )
                _prov(provenance, "rpki", "RIPE STAT", rpki_result["status"])

                logger.info(
                    "RIPE STAT(RPKI): status=%s for %s / %s",
                    rpki_result["status"],
                    asn,
                    primary_prefix,
                )

            except Exception as exc:  # noqa: BLE001
                logger.error("RIPE STAT(RPKI): unexpected error — %s", exc)

        else:
            result.rpki = RPKIStatus(
                status="unavailable",
                roas=[],
                validated_prefix=None,
                source="RIPE STAT RPKI",
            )
            logger.info("RIPE STAT(RPKI): skipped — no CIDR prefix available")

    # =========================================================================
    # SOURCE 6 — PeeringDB  (requires ASN)
    # =========================================================================
    pdb_contributed = False

    if asn:
        try:
            pdb_network_raw = _peeringdb_client.get_network_by_asn(asn)

            if pdb_network_raw:
                records = pdb_network_raw.get("data", [])
                net_id: Optional[int] = None
                org_id: Optional[int] = None

                if records:
                    net_id = records[0].get("id")
                    org_id = records[0].get("org_id")

                pdb_ixp_raw = _peeringdb_client.get_ix_memberships(net_id) if net_id else None
                pdb_org_raw = _peeringdb_client.get_org_networks(org_id) if org_id else None

                pdb = PeeringDBParser.parse_network(
                    network_data=pdb_network_raw,
                    ixp_data=pdb_ixp_raw,
                    org_networks_data=pdb_org_raw,
                )

                pdb_has_data = any([
                    pdb.website,
                    pdb.noc_email,
                    pdb.abuse_email,
                    pdb.peering_policy,
                    pdb.info_type,
                    pdb.internet_exchanges,
                ])

                if pdb_has_data:
                    pdb_contributed = True
                    sources_queried.append("PeeringDB")

                    # Build paginated IXP list
                    ixp_total = len(pdb.internet_exchanges)
                    ixp_paginated = PaginatedList(
                        count=ixp_total,
                        sample=pdb.internet_exchanges[:_IXP_SAMPLE_SIZE],
                        complete_available=(ixp_total <= _IXP_SAMPLE_SIZE),
                    )

                    # Build full ISP profile from PeeringDB
                    # Then merge in RDAP contacts for any gaps (Task 1 / Task 8)
                    result.isp_profile = ISPProfile(
                        website=pdb.website,
                        noc_email=pdb.noc_email or rdap_noc_email,   # RDAP fallback
                        abuse_email=pdb.abuse_email or rdap_abuse_email,  # RDAP fallback
                        support_email=pdb.support_email,
                        peering_policy=pdb.peering_policy,
                        info_type=pdb.info_type,
                        internet_exchanges=ixp_paginated,
                        profile_sources=_profile_sources(
                            pdb, rdap_noc_email, rdap_abuse_email
                        ),
                    )

                    # Multi-ASN detection — structured object (Task 2)
                    result.multi_asn = _build_multi_asn(
                        primary_asn=asn,
                        related_asns=pdb.related_asns,
                        organization=result.organization or result.isp,
                    )

                    _prov(provenance, "multi_asn", "PeeringDB", pdb.related_asns or None)
                    _prov(provenance, "isp_profile.website", "PeeringDB", pdb.website)
                    _prov(provenance, "isp_profile.noc_email", "PeeringDB", pdb.noc_email or rdap_noc_email)
                    _prov(provenance, "isp_profile.abuse_email", "PeeringDB", pdb.abuse_email or rdap_abuse_email)
                    _prov(provenance, "isp_profile.peering_policy", "PeeringDB", pdb.peering_policy)
                    _prov(provenance, "isp_profile.info_type", "PeeringDB", pdb.info_type)
                    _prov(provenance, "isp_profile.internet_exchanges", "PeeringDB", pdb.internet_exchanges or None)

                    logger.info(
                        "PeeringDB: OK — policy=%s, type=%s, ixps=%d, related_asns=%d",
                        pdb.peering_policy,
                        pdb.info_type,
                        len(pdb.internet_exchanges),
                        len(pdb.related_asns),
                    )
                else:
                    logger.info("PeeringDB: network found but no usable data for %s", asn)
            else:
                logger.warning("PeeringDB: no network found for %s", asn)

        except Exception as exc:  # noqa: BLE001
            logger.error("PeeringDB: unexpected error for %s — %s", ip, exc)

    # =========================================================================
    # TASK 1 / TASK 8 — ISP Profile fallback from RDAP
    # If PeeringDB contributed nothing, build a minimal isp_profile from RDAP.
    # This ensures isp_profile is NEVER null when an ASN was resolved.
    # =========================================================================
    if asn and not pdb_contributed:
        has_rdap_contacts = rdap_noc_email or rdap_abuse_email
        if has_rdap_contacts:
            result.isp_profile = ISPProfile(
                noc_email=rdap_noc_email,
                abuse_email=rdap_abuse_email,
                internet_exchanges=PaginatedList(count=0, sample=[], complete_available=True),
                profile_sources=["RDAP"],
            )
            _prov(provenance, "isp_profile.noc_email", "RDAP", rdap_noc_email)
            _prov(provenance, "isp_profile.abuse_email", "RDAP", rdap_abuse_email)
            logger.info("ISP profile: built from RDAP contacts (PeeringDB unavailable)")

        # Always ensure multi_asn is a structured object (Task 2)
        result.multi_asn = _build_multi_asn(
            primary_asn=asn,
            related_asns=[],
            organization=result.organization or result.isp,
        )
        _prov(provenance, "multi_asn", "derived", "single-ASN")

    elif not asn:
        # No ASN at all — set a minimal explaining multi_asn
        result.multi_asn = MultiASNInfo(
            detected=False,
            reason="No ASN could be resolved for this IP address. Multi-ASN detection requires a valid ASN.",
            primary_asn=None,
            related_asns=[],
            relationship_type=None,
        )

    # =========================================================================
    # AI Risk Layer  (pure rule-based — no hallucination)
    # =========================================================================
    try:
        result.ai_risk = _compute_ai_risk(result, bgp_data_available, bgp_sources_tried)
        logger.info(
            "AI Risk: type=%s, tags=%s, level=%s",
            result.ai_risk.network_type,
            result.ai_risk.network_tags,
            result.ai_risk.risk_level,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("AI Risk: failed to compute for %s — %s", ip, exc)

    # =========================================================================
    # Finalize
    # =========================================================================
    result.sources_queried = sources_queried
    result.data_provenance = provenance

    elapsed_ms = int((time.monotonic() - start_time) * 1000)
    result.metadata = _build_metadata(result, sources_queried, elapsed_ms, "MISS")

    logger.info(
        "=== ASN Intelligence lookup COMPLETE for %s | sources=%s | %dms ===",
        ip,
        sources_queried,
        elapsed_ms,
    )

    if settings.CACHE_TTL_SECONDS > 0:
        _cache.set(ip, result)

    return result


# =============================================================================
# Builder helpers
# =============================================================================


def _build_announced_prefixes(
    v4: List[str],
    v6: List[str],
    total: int,
    source: str,
) -> AnnouncedPrefixes:
    """Construct a compact AnnouncedPrefixes object with remaining counts."""
    s4 = v4[:_PREFIX_SAMPLE_SIZE]
    s6 = v6[:_PREFIX_SAMPLE_SIZE]
    return AnnouncedPrefixes(
        total_ipv4=len(v4),
        total_ipv6=len(v6),
        total=total,
        sample_ipv4=s4,
        sample_ipv6=s6,
        remaining_ipv4=max(0, len(v4) - len(s4)),
        remaining_ipv6=max(0, len(v6) - len(s6)),
        complete_available=(len(v4) <= _PREFIX_SAMPLE_SIZE and len(v6) <= _PREFIX_SAMPLE_SIZE),
        source=source,
    )


def _build_sampled_relationship(
    entries: List[Dict[str, str]],
    total_override: Optional[int] = None,
) -> SampledRelationshipList:
    """
    Build a SampledRelationshipList with count/sample/remaining.

    Args:
        entries:        Full list of relationship dicts (asn, name).
        total_override: Override for the total count (used when RIPE STAT
                        reports more items than what's in the sample list).
    """
    total = total_override if total_override is not None else len(entries)
    sample = entries[:_RELATIONSHIP_SAMPLE_SIZE]
    remaining = max(0, total - len(sample))
    return SampledRelationshipList(total=total, sample=sample, remaining=remaining)


def _build_relationships(
    peers: List[Dict[str, str]],
    upstreams: List[Dict[str, str]],
    downstreams: List[Dict[str, str]],
    source: str,
    peer_count: Optional[int] = None,
    upstream_count: Optional[int] = None,
    downstream_count: Optional[int] = None,
) -> ASNRelationships:
    """
    Construct an ASNRelationships object with SampledRelationshipList for each direction.

    When peer_count/upstream_count/downstream_count are supplied (from RIPE STAT),
    they are used as the authoritative total rather than len(list), since RIPE STAT
    may return more neighbours than are in the sample.
    """
    pc = peer_count if peer_count is not None else len(peers)
    uc = upstream_count if upstream_count is not None else len(upstreams)
    dc = downstream_count if downstream_count is not None else len(downstreams)

    peers_sampled = _build_sampled_relationship(peers, pc)
    ups_sampled = _build_sampled_relationship(upstreams, uc)
    downs_sampled = _build_sampled_relationship(downstreams, dc)

    return ASNRelationships(
        peer_count=pc,
        upstream_count=uc,
        downstream_count=dc,
        peers=peers_sampled,
        upstreams=ups_sampled,
        downstreams=downs_sampled,
        transit_providers=ups_sampled,
        customer_networks=downs_sampled,
        data_source=source,
    )


def _profile_sources(
    pdb,
    rdap_noc: Optional[str],
    rdap_abuse: Optional[str],
) -> List[str]:
    """Determine which sources contributed to the ISP profile."""
    srcs: List[str] = []
    pdb_fields = [pdb.website, pdb.noc_email, pdb.abuse_email, pdb.peering_policy, pdb.info_type]
    if any(pdb_fields):
        srcs.append("PeeringDB")
    # RDAP only contributed if PeeringDB was missing the contact
    if (rdap_noc and not pdb.noc_email) or (rdap_abuse and not pdb.abuse_email):
        srcs.append("RDAP")
    return srcs


# =============================================================================
# Multi-ASN builder (Task 2)
# =============================================================================


def _build_multi_asn(
    primary_asn: Optional[str],
    related_asns: List[str],
    organization: Optional[str],
) -> MultiASNInfo:
    """
    Build a structured MultiASNInfo object. ALWAYS returns a non-null result.

    Args:
        primary_asn:   The ASN directly serving the queried IP.
        related_asns:  All ASNs belonging to the same PeeringDB org.
        organization:  Organisation name.

    Returns:
        Populated :class:`MultiASNInfo`.
    """
    others = [a for a in related_asns if a != primary_asn]
    detected = len(others) > 0

    if not detected:
        return MultiASNInfo(
            detected=False,
            reason=(
                "No additional autonomous systems associated with this organisation "
                "were identified in PeeringDB records."
            ),
            organization=organization,
            primary_asn=primary_asn,
            related_asns=[],
            relationship_type=None,
        )

    total = len(related_asns)
    reason = (
        f"PeeringDB records show {total} autonomous system(s) registered under "
        f"'{organization or 'this organisation'}'. "
        f"These are sibling ASNs owned by the same entity, used for traffic engineering, "
        f"geographic distribution, or separate service lines."
    )

    return MultiASNInfo(
        detected=True,
        reason=reason,
        organization=organization,
        primary_asn=primary_asn,
        related_asns=others,
        relationship_type="Organisation-owned",
    )


# =============================================================================
# Deterministic confidence scoring (Task 5)
# =============================================================================


def _build_metadata(
    data: ASNData,
    sources: List[str],
    elapsed_ms: int,
    cache_status: str,
) -> ResponseMetadata:
    """
    Build the ResponseMetadata block with deterministic confidence scoring.

    Scoring weights (must sum to 1.0):
      RIR / RDAP data     = 40%  (registry, network_handle, registration_date, cidr_prefixes)
      BGP routing data    = 20%  (bgp_name, prefix_count, announced_prefixes)
      RPKI validation     = 15%  (rpki with non-unavailable status)
      Reverse DNS         = 05%  (hostname resolved)
      ISP profile         = 10%  (isp_profile with at least one contact or policy)
      Relationships       = 05%  (relationships with non-zero counts)
      Cross-validation    = 05%  (ASN confirmed by ≥2 independent sources)

    Each sub-score is proportional — i.e. if only 2 of 4 RIR fields are present,
    rir score = 0.40 * (2/4) = 0.20.
    """
    # ── Completeness tracking ─────────────────────────────────────────────────
    _TRACKED: list[tuple[str, object]] = [
        ("asn", data.asn),
        ("isp", data.isp),
        ("organization", data.organization),
        ("country", data.country),
        ("hostname", data.hostname),
        ("city", data.city),
        ("registry", data.registry),
        ("whois_server", data.whois_server),
        ("network_handle", data.network_handle),
        ("network_name", data.network_name),
        ("allocation_type", data.allocation_type),
        ("registration_date", data.registration_date),
        ("allocation_date", data.allocation_date),
        ("cidr_prefixes", data.cidr_prefixes or None),
        ("origin_asn", data.origin_asn),
        ("bgp_name", data.bgp_name),
        ("bgp_description", data.bgp_description),
        ("prefix_count", data.prefix_count or None),
        ("announced_prefixes", data.announced_prefixes),
        ("rpki", data.rpki),
        ("isp_profile", data.isp_profile),
        ("relationships", data.relationships),
        ("multi_asn", data.multi_asn if (data.multi_asn and data.multi_asn.primary_asn) else None),
        ("ai_risk", data.ai_risk),
    ]

    completed: list[str] = []
    missing: list[str] = []

    for field_name, value in _TRACKED:
        if value is not None and value != [] and value != 0 and value != "":
            completed.append(field_name)
        else:
            missing.append(field_name)

    # ── Deterministic breakdown ───────────────────────────────────────────────
    # RIR (40%): 4 key RIR fields, each worth 10%
    rir_fields = ["registry", "network_handle", "registration_date", "cidr_prefixes"]
    rir_score = round(0.40 * (sum(1 for f in rir_fields if f in completed) / len(rir_fields)), 4)

    # BGP (20%): 3 key BGP fields, each worth ~6.67%
    bgp_fields = ["bgp_name", "prefix_count", "announced_prefixes"]
    bgp_score = round(0.20 * (sum(1 for f in bgp_fields if f in completed) / len(bgp_fields)), 4)

    # RPKI (15%): binary — present and not "unavailable"
    rpki_score = 0.0
    if data.rpki and data.rpki.status not in ("unavailable", "unknown"):
        rpki_score = 0.15

    # Reverse DNS (5%): hostname resolved
    rdns_score = 0.05 if "hostname" in completed else 0.0

    # ISP profile (10%): binary — at least one non-empty field
    isp_score = 0.0
    if data.isp_profile:
        isp_fields = [
            data.isp_profile.website,
            data.isp_profile.noc_email,
            data.isp_profile.abuse_email,
            data.isp_profile.peering_policy,
            data.isp_profile.info_type,
        ]
        if any(isp_fields):
            isp_score = 0.10

    # Relationships (5%): binary — at least one direction non-zero
    rel_score = 0.0
    if data.relationships and (
        data.relationships.peer_count
        or data.relationships.upstream_count
        or data.relationships.downstream_count
    ):
        rel_score = 0.05

    # Cross-validation (5%): ASN confirmed by ≥2 independent source families
    # IPInfo + RDAP, or IPInfo + RIPE STAT, or Cymru + RDAP, etc.
    rir_sources = {"RDAP", "TeamCymru"}
    bgp_sources_set = {"BGPView", "RIPE STAT"}
    ip_sources = {"IPInfo"}
    source_set = set(sources)

    cross_score = 0.0
    # Cross-validate: if both a geolocation source AND an RIR source responded
    if (source_set & ip_sources) and (source_set & rir_sources):
        cross_score += 0.025
    # And if both a geolocation/RIR AND a BGP source responded
    if source_set & bgp_sources_set:
        cross_score += 0.025
    cross_score = round(min(cross_score, 0.05), 4)

    breakdown = ConfidenceBreakdown(
        rir=rir_score,
        bgp=bgp_score,
        rpki=rpki_score,
        rdns=rdns_score,
        isp_profile=isp_score,
        relationships=rel_score,
        cross_validation=cross_score,
    )

    overall = round(
        breakdown.rir + breakdown.bgp + breakdown.rpki + breakdown.rdns
        + breakdown.isp_profile + breakdown.relationships + breakdown.cross_validation,
        2,
    )
    overall = min(overall, 1.0)

    return ResponseMetadata(
        confidence_score=overall,
        confidence_breakdown=breakdown,
        sources_used=sources,
        completed_fields=completed,
        missing_fields=missing,
        lookup_duration_ms=elapsed_ms,
        generated_at=datetime.datetime.utcnow().isoformat() + "Z",
        cache_status=cache_status,
    )


# =============================================================================
# AI Risk Engine (Task 6 — expanded to 18 network types)
# =============================================================================


# ── Network classification keyword sets ───────────────────────────────────────
_KW_CLOUD = frozenset({
    "amazon", "aws", "google", "azure", "microsoft", "digitalocean",
    "vultr", "linode", "hetzner", "ovh", "alibaba", "oracle cloud",
    "ibm cloud", "rackspace", "kamatera", "scaleway", "upcloud",
    "equinix metal", "packet", "tencent cloud", "huawei cloud",
})
_KW_CDN = frozenset({
    "cloudflare", "fastly", "akamai", "cdn77", "stackpath", "limelight",
    "belugacdn", "bunny", "keycdn", "edgio", "verizon media", "yahoo", "edgecast",
    "level3 cdn", "incapsula", "imperva", "section.io",
})
_KW_VPN = frozenset({
    "vpn", "private internet access", "nordvpn", "expressvpn", "mullvad",
    "protonvpn", "hidemyass", "cyberghost", "surfshark", "ipvanish",
    "windscribe", "tunnelbear", "hotspot shield", "hide.me", "airvpn",
    "vyprvpn", "torguard", "perfect privacy", "ivpn",
})
_KW_HOSTING = frozenset({
    "hosting", "datacenter", "data center", "colocation", "colo",
    "dedicated server", "vps", "serverius", "choopa", "multacom",
    "psychz", "quadranet", "path network", "sharktech", "tzulo",
    "hostwinds", "10zig", "iweb", "webnx", "reliablesite",
})
_KW_TELECOM = frozenset({
    "telecom", "telephone", "telco", "cable", "broadband", "fiber",
    "mobile", "cellular", "wireless", "vodafone", "t-mobile",
    "verizon", "comcast", "at&t", "sprint", "orange",
    "deutsche telekom", "british telecom", "bt group", "sky",
    "charter", "cox", "centurylink", "lumen", "swisscom",
    "singtel", "softbank", "ntt", "kddi", "telstra", "telenet",
    "bell canada", "rogers", "shaw", "telus",
})
_KW_MOBILE = frozenset({
    "mobile", "cellular", "wireless", "lte", "4g", "5g",
    "t-mobile", "sprint", "vodafone", "orange", "three",
    "ee ", " ee", "o2", "boost mobile", "cricket wireless",
    "metro pcs", "us cellular", "dish network",
})
_KW_SATELLITE = frozenset({
    "satellite", "starlink", "viasat", "hughes", "inmarsat",
    "ses ", " ses", "eutelsat", "intelsat", "iridium",
    "kpn satellite", "yahsat", "o3b",
})
_KW_DNS = frozenset({
    "dns", "resolver", "nameserver", "recursive dns",
    "google public dns", "cloudflare dns", "quad9",
    "opendns", "norton dns", "comodo secure", "neustar",
    "verisign", "umbrella",
})
_KW_ANYCAST = frozenset({
    "anycast", "root server", "root-server", "i.root-servers",
    "k.root-servers", "distributed dns",
})
_KW_GOV = frozenset({
    "government", "federal", "ministry", "defence", "defense",
    "military", "army", "navy", "air force", "nasa", "dod",
    "department of", "pentagon", "gchq", "nsa ", " nsa",
    "intelligence agency", "homeland", "fbi ", " fbi", "cia ",
})
_KW_EDU = frozenset({
    "university", "college", "academic", "research", "institute",
    "school", "edu ", " edu", "stanford", "mit ", " mit",
    "harvard", "nist", "nih ", " nih", "cern", "géant",
    "internet2", "canarie", "renater", "dfn ",
})
_KW_FINANCE = frozenset({
    "bank", "financial", "finance", "trading", "exchange",
    "investment", "insurance", "credit union", "stock exchange",
    "morgan stanley", "goldman sachs", "jp morgan", "citadel",
    "nasdaq", "nyse", "swift", "clearinghouse",
})
_KW_ENTERPRISE = frozenset({
    "enterprise", "corporate", "corporation", "inc.", " inc ",
    "ltd.", " ltd ", "llc", "gmbh", "s.a.", "plc",
})
_KW_BACKBONE = frozenset({
    "backbone", "transit", "tier-1", "tier 1",
    "level 3", "level3", "cogent", "telia", "ntt", "lumen",
    "hurricane electric", "he.net", "zayo", "gtc", "as174",
    "as3356", "as2914",
})
_KW_RESIDENTIAL = frozenset({
    "residential", "consumer", "home", "dsl", "adsl", "xdsl",
    "dialup", "dial-up", "ppp", "subscriber",
})
_KW_PROXY = frozenset({
    "proxy", "anonymizer", "tor ", " tor", "exit node",
    "privacy network", "relay",
})
_KW_PRIVATE = frozenset({
    "private", "internal", "intranet", "non-public", "not advertised",
    "reserved", "rfc1918",
})
_KW_RESEARCH = frozenset({
    "research network", "network research", "merit network",
    "internet society", "isoc", "ripe ncc", "arin research",
    "caida", "team cymru", "shadowserver",
})
_KW_EDGE = frozenset({
    "edge", "edge computing", "cdn edge", "pop ", " pop",
    "point of presence", "edge node",
})

# PeeringDB info_type → primary network_type
_PEERINGDB_TYPE_MAP: dict[str, str] = {
    "Content": "Cloud Provider / CDN",
    "Cable/DSL/ISP": "Internet Service Provider",
    "NSP": "Network Service Provider / Global Backbone",
    "Enterprise": "Enterprise Network",
    "Educational/Research": "Academic / Research Network",
    "Non-Profit": "Non-Profit Network",
    "Route Server": "Route Server / IXP",
    "Network": "Transit / Backbone Network",
    "Government": "Government Network",
}

# Major well-known operator names (reduces false positives in risk scoring)
_MAJOR_OPERATORS = frozenset({
    "google", "cloudflare", "amazon", "microsoft", "apple",
    "meta", "facebook", "akamai", "fastly", "comcast", "verizon",
    "at&t", "deutsche telekom", "orange", "bt group", "sky",
    "telia", "cogent", "lumen", "centurylink", "level 3", "level3",
    "ntt", "softbank", "kddi", "singtel", "hurricane electric",
    "zayo", "charter", "rogers", "telus", "bell canada",
    "vodafone", "t-mobile", "swisscom", "telstra",
})


def _compute_ai_risk(
    data: ASNData,
    bgp_data_available: bool,
    bgp_sources_tried: List[str],
) -> AIRiskProfile:
    """
    Compute a rule-based NLP risk classification with multi-label network tags.

    Key design principles:
      - Every statement in ``summary`` corresponds to a field already in ``data``.
      - No external calls. No speculation. No hallucination.
      - Multi-label classification: a network can be both a CDN and a DNS Resolver.
      - Distinguishes "BGP data unavailable" from "confirmed zero prefixes".
      - Risk score is additive: negative decrements lower risk, positive raise it.

    Returns:
        Populated :class:`AIRiskProfile` with network_type, network_tags, risk_level,
        risk_indicators, and summary.
    """
    indicators: list[str] = []
    risk_score: int = 0

    # Combine all text signals for classification
    org = (data.organization or data.isp or "").lower()
    bgp_text = (data.bgp_name or data.bgp_description or "").lower()
    combined = org + " " + bgp_text
    info_type = (data.isp_profile.info_type if data.isp_profile else None) or ""

    # ── Multi-label classification (Task 6 — 18 types) ────────────────────────
    tags: list[str] = []

    # 1. Start with PeeringDB's authoritative classification
    if info_type in _PEERINGDB_TYPE_MAP:
        tags.append(_PEERINGDB_TYPE_MAP[info_type])

    # 2. Apply keyword rules for additional tags
    if _kw(combined, _KW_DNS) or "dns" in org:
        tags.append("DNS Resolver")
    if _kw(combined, _KW_ANYCAST):
        tags.append("Anycast Network")
    if _kw(combined, _KW_CDN) and "CDN" not in " ".join(tags):
        tags.append("Content Delivery Network")
    if _kw(combined, _KW_CLOUD) and "Cloud" not in " ".join(tags):
        tags.append("Cloud Provider")
    if _kw(combined, _KW_VPN):
        tags.append("VPN Provider")
    if _kw(combined, _KW_PROXY):
        tags.append("Proxy Network")
    if _kw(combined, _KW_MOBILE):
        tags.append("Mobile Carrier")
    if _kw(combined, _KW_SATELLITE):
        tags.append("Satellite Provider")
    if _kw(combined, _KW_GOV):
        tags.append("Government Network")
    if _kw(combined, _KW_EDU) and "Academic" not in " ".join(tags):
        tags.append("Educational Institution")
    if _kw(combined, _KW_FINANCE):
        tags.append("Financial Institution")
    if _kw(combined, _KW_BACKBONE) and "Backbone" not in " ".join(tags):
        tags.append("Global Backbone")
    if _kw(combined, _KW_TELECOM) and "Service Provider" not in " ".join(tags):
        tags.append("Telecommunications Provider")
    if _kw(combined, _KW_HOSTING) and "Hosting" not in " ".join(tags):
        tags.append("Hosting Provider")
    if _kw(combined, _KW_RESIDENTIAL):
        tags.append("Residential ISP")
    if _kw(combined, _KW_RESEARCH):
        tags.append("Research Network")
    if _kw(combined, _KW_EDGE):
        tags.append("Edge Network")
    if _kw(combined, _KW_PRIVATE):
        tags.append("Private Infrastructure")
    if _kw(combined, _KW_ENTERPRISE) and not tags:
        # Only add Enterprise if no more specific type was found
        tags.append("Enterprise Network")

    # Deduplicate while preserving order
    seen_tags: set[str] = set()
    unique_tags: list[str] = []
    for t in tags:
        if t not in seen_tags:
            seen_tags.add(t)
            unique_tags.append(t)
    tags = unique_tags

    # Primary network_type: first tag, or fallback
    if tags:
        network_type = tags[0]
    else:
        network_type = "Unknown / Other"
        tags = ["Unknown / Other"]

    # ── Risk scoring ──────────────────────────────────────────────────────────
    if _kw(org, _MAJOR_OPERATORS):
        indicators.append("Major established global network operator")
        risk_score -= 2

    if data.registry:
        indicators.append(f"Registered with {data.registry} (authoritative RIR)")
        risk_score -= 1

    if data.registration_date:
        indicators.append(f"Network block registered on {data.registration_date}")

    # RPKI
    if data.rpki:
        if data.rpki.status == "valid":
            indicators.append("RPKI validation: VALID (ROA matches origin ASN)")
            risk_score -= 1
        elif data.rpki.status == "invalid":
            indicators.append("RPKI validation: INVALID (possible route hijack or misconfiguration)")
            risk_score += 2
        elif data.rpki.status == "not-found":
            indicators.append("RPKI validation: NOT-FOUND (no ROA registered)")
            risk_score += 1
        elif data.rpki.status == "unavailable":
            indicators.append("RPKI validation: unavailable (source did not respond)")

    # ISP profile signals
    if data.isp_profile:
        if data.isp_profile.noc_email:
            indicators.append("NOC contact registered in PeeringDB")
            risk_score -= 1

        if data.isp_profile.peering_policy in ("Open", "Selective"):
            indicators.append(f"BGP peering policy: {data.isp_profile.peering_policy}")
            risk_score -= 1

        if data.isp_profile.internet_exchanges and data.isp_profile.internet_exchanges.count > 0:
            count = data.isp_profile.internet_exchanges.count
            indicators.append(f"Active at {count} Internet Exchange Point(s)")
            risk_score -= 1

    # BGP prefix assessment
    if data.prefix_count > 500:
        indicators.append(f"Hyperscale network: {data.prefix_count} announced BGP prefixes (confirmed)")
        risk_score -= 2
    elif data.prefix_count > 100:
        indicators.append(f"Large-scale network: {data.prefix_count} announced BGP prefixes (confirmed)")
        risk_score -= 1
    elif data.prefix_count > 10:
        indicators.append(f"Announces {data.prefix_count} BGP prefixes (confirmed)")
    elif data.prefix_count > 0:
        indicators.append(f"Announces {data.prefix_count} BGP prefix(es) (confirmed)")
    elif bgp_data_available and data.prefix_count == 0:
        indicators.append("No announced BGP prefixes detected (confirmed by BGP sources)")
        risk_score += 1
    elif not bgp_data_available and bgp_sources_tried:
        src_str = ", ".join(bgp_sources_tried)
        indicators.append(f"BGP prefix data unavailable ({src_str} did not respond)")

    # Relationship signals
    if data.relationships:
        total_nb = (
            data.relationships.peer_count
            + data.relationships.upstream_count
            + data.relationships.downstream_count
        )
        if total_nb > 500:
            indicators.append(f"Tier-1/hyperscale BGP footprint: {total_nb} total neighbours")
            risk_score -= 1
        elif total_nb > 0:
            indicators.append(
                f"BGP relationships: {data.relationships.peer_count} peers, "
                f"{data.relationships.upstream_count} upstreams, "
                f"{data.relationships.downstream_count} downstreams"
            )

    # Multi-ASN
    if data.multi_asn and data.multi_asn.detected:
        count = len(data.multi_asn.related_asns) + 1
        indicators.append(f"Organisation operates {count} autonomous system(s)")

    # Negative signals
    if not data.asn:
        indicators.append("No ASN could be resolved for this IP")
        risk_score += 3

    if not data.registry:
        indicators.append("No Regional Internet Registry record found")
        risk_score += 2

    if "VPN Provider" in tags:
        indicators.append("Network associated with VPN / anonymization services")
        risk_score += 2

    if "Proxy Network" in tags:
        indicators.append("Network associated with proxy / anonymization infrastructure")
        risk_score += 2

    if "Hosting Provider" in tags and not _kw(org, _MAJOR_OPERATORS):
        indicators.append("Hosting / datacenter provider — frequently used for abuse traffic")
        risk_score += 1

    if data.allocation_type and data.allocation_type.upper() in ("REALLOCATED", "REASSIGNED"):
        indicators.append(f"Allocation type '{data.allocation_type}' — sub-allocated block")
        risk_score += 1

    # ── Risk level determination ──────────────────────────────────────────────
    if risk_score <= -2:
        risk_level = "LOW"
    elif risk_score <= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    summary = _build_summary(data, network_type, tags, risk_level, bgp_data_available, bgp_sources_tried)

    return AIRiskProfile(
        network_type=network_type,
        network_tags=tags,
        risk_level=risk_level,
        risk_indicators=indicators,
        summary=summary,
    )


def _build_summary(
    data: ASNData,
    network_type: str,
    tags: List[str],
    risk_level: str,
    bgp_data_available: bool,
    bgp_sources_tried: List[str],
) -> str:
    """
    Construct a plain-English intelligence summary from collected fields only.

    Every sentence is derived from a non-null field in ``data``.
    No sentences are generated when the underlying data is absent.
    BGP unavailability is accurately stated, never fabricated as "no prefixes".
    """
    parts: list[str] = []

    org_str = data.organization or data.isp or "an unidentified organization"
    asn_str = data.asn or "unknown ASN"

    # Multi-tag label string
    tags_str = " / ".join(tags[:4]) if tags else network_type

    parts.append(
        f"This IP address ({data.ip}) belongs to {org_str} ({asn_str}), "
        f"classified as: {tags_str}."
    )

    if data.registry and data.network_name:
        parts.append(
            f"The network block '{data.network_name}' is registered with {data.registry}."
        )
    elif data.registry:
        parts.append(f"The network is registered with {data.registry}.")

    if data.start_address and data.end_address:
        cidr_str = (f" ({', '.join(data.cidr_prefixes[:3])})" if data.cidr_prefixes else "")
        parts.append(f"Allocated range: {data.start_address} — {data.end_address}{cidr_str}.")

    if data.registration_date:
        ts = f"Registered {data.registration_date}"
        if data.last_changed_date:
            ts += f", last updated {data.last_changed_date}"
        parts.append(ts + ".")

    # BGP
    if data.prefix_count > 0:
        parts.append(
            f"The ASN announces {data.prefix_count} BGP prefix(es) "
            f"({data.announced_prefixes.total_ipv4 if data.announced_prefixes else len(data.ipv4_prefixes)} IPv4, "
            f"{data.announced_prefixes.total_ipv6 if data.announced_prefixes else len(data.ipv6_prefixes)} IPv6)."
        )
    elif bgp_data_available and data.prefix_count == 0:
        parts.append("BGP sources confirm no active prefix announcements for this ASN.")
    elif bgp_sources_tried:
        src_str = " and ".join(bgp_sources_tried)
        parts.append(f"BGP prefix data was unavailable ({src_str} did not respond).")

    # RPKI
    if data.rpki and data.rpki.status not in ("unavailable", "unknown"):
        parts.append(
            f"RPKI validation for {data.rpki.validated_prefix}: {data.rpki.status.upper()}."
        )

    # ISP profile
    if data.isp_profile:
        if data.isp_profile.peering_policy:
            parts.append(f"Peering policy: {data.isp_profile.peering_policy}.")
        if data.isp_profile.internet_exchanges and data.isp_profile.internet_exchanges.count > 0:
            count = data.isp_profile.internet_exchanges.count
            sample = data.isp_profile.internet_exchanges.sample
            ixp_str = ", ".join(str(x) for x in sample[:4])
            parts.append(f"Present at {count} IXP(s) including: {ixp_str}.")

    # Relationships
    if data.relationships:
        pc = data.relationships.peer_count
        uc = data.relationships.upstream_count
        dc = data.relationships.downstream_count
        if pc or uc or dc:
            parts.append(
                f"BGP relationships: {pc} peer(s), {uc} upstream(s), {dc} downstream(s)."
            )

    # Multi-ASN
    if data.multi_asn and data.multi_asn.detected:
        total = len(data.multi_asn.related_asns) + 1
        all_asns = ([data.multi_asn.primary_asn] if data.multi_asn.primary_asn else []) + data.multi_asn.related_asns
        sample_asns = ", ".join(all_asns[:6])
        parts.append(
            f"The organisation operates {total} autonomous system(s): {sample_asns}."
        )

    parts.append(f"Overall risk assessment: {risk_level}.")

    return " ".join(parts)


# =============================================================================
# Internal utilities
# =============================================================================


def _kw(text: str, keywords: frozenset) -> bool:
    """Return True if any keyword from the frozenset appears as a substring in text."""
    return any(kw in text for kw in keywords)


def _merge_str(
    result: ASNData,
    field: str,
    value: Optional[str],
    provenance: Dict[str, str],
    source: str,
) -> None:
    """
    Set a string field on ``result`` only if the field is currently empty/None.

    Implements the "never overwrite valid data with null" contract.
    """
    if not value:
        return
    current = getattr(result, field, None)
    if not current:
        setattr(result, field, value)
        _prov(provenance, field, source, value)


def _prov(
    provenance: Dict[str, str],
    field: str,
    source: str,
    value: object,
) -> None:
    """Record provenance for a field only when the value is truthy."""
    if value is not None and value != [] and value != "" and value != 0:
        provenance[field] = source