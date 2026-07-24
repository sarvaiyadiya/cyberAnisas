"""
modules/asn/models.py

Pydantic models for the ASN & ISP Intelligence Engine (Module 1).

Layer responsibilities:
  - Request/response validation at the API boundary.
  - Internal structured data transferred between service ↔ parsers.

Naming conventions:
  - *Request   — inbound API payload
  - *Response  — outbound API payload
  - *Data/*Info — internal data container (parsed from a single source)
  - ASNData    — merged result combining all sources
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, IPvAnyAddress, Field


# =============================================================================
# Internal per-source models  (service → parsers boundary)
# =============================================================================


class IPInfoData(BaseModel):
    """Structured data parsed from the IPInfo API response."""

    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    hostname: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None


class RDAPInfo(BaseModel):
    """Structured data parsed from an RDAP registry response."""

    handle: Optional[str] = None
    network_name: Optional[str] = None
    network_description: Optional[str] = None
    registry: Optional[str] = None
    whois_server: Optional[str] = None
    allocation_type: Optional[str] = None
    status: Optional[str] = None
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    cidr_prefixes: List[str] = Field(default_factory=list)
    organization: Optional[str] = None
    # Differentiated date fields (Task 4)
    registration_date: Optional[str] = None    # eventAction == "registration"
    last_changed_date: Optional[str] = None    # eventAction == "last changed"
    allocation_date: Optional[str] = None      # alias/same as registration for RDAP
    date_type_note: Optional[str] = None       # human note about what each date means
    noc_email: Optional[str] = None
    abuse_email: Optional[str] = None


class BGPInfo(BaseModel):
    """Structured data parsed from the BGPView ASN + prefix API responses."""

    asn_number: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    country: Optional[str] = None
    ipv4_prefixes: List[str] = Field(default_factory=list)
    ipv6_prefixes: List[str] = Field(default_factory=list)
    prefix_count: int = 0


class BGPRelationshipsData(BaseModel):
    """Structured BGP peering relationships from BGPView."""

    peers: List[Dict[str, str]] = Field(default_factory=list)
    upstreams: List[Dict[str, str]] = Field(default_factory=list)
    downstreams: List[Dict[str, str]] = Field(default_factory=list)


class PeeringDBData(BaseModel):
    """Structured data parsed from the PeeringDB public API."""

    website: Optional[str] = None
    noc_email: Optional[str] = None
    abuse_email: Optional[str] = None
    support_email: Optional[str] = None
    peering_policy: Optional[str] = None
    info_type: Optional[str] = None
    internet_exchanges: List[str] = Field(default_factory=list)
    # All ASNs belonging to the same PeeringDB organisation (multi-ASN)
    related_asns: List[str] = Field(default_factory=list)


class CymruData(BaseModel):
    """Structured data parsed from the Team Cymru whois response."""

    asn: Optional[str] = None
    prefix: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None
    allocated: Optional[str] = None
    name: Optional[str] = None


# =============================================================================
# Response sub-models  (API boundary)
# =============================================================================


class PaginatedList(BaseModel):
    """
    Compact representation for large lists (IXPs, prefixes, peers).

    Instead of flooding the response with hundreds of items,
    returns a count + a manageable sample, with a flag indicating
    whether additional items exist.
    """

    count: int = Field(description="Total number of items.")
    sample: List[Any] = Field(
        default_factory=list,
        description="First N items. See 'count' for the true total.",
    )
    complete_available: bool = Field(
        True,
        description="True if 'sample' contains the complete list; False if truncated.",
    )


class SampledRelationshipList(BaseModel):
    """
    Compact representation for a single BGP relationship direction (peers/upstreams/downstreams).

    Exposes total count, a representative sample, and the number of items
    beyond the sample — so clients know how many entries they are not seeing.
    """

    total: int = Field(0, description="Total number of entries in this direction.")
    sample: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Representative sample (up to N entries). Each has 'asn' and 'name'.",
    )
    remaining: int = Field(
        0,
        description="Number of entries not included in 'sample' (total - len(sample)).",
    )


class ISPProfile(BaseModel):
    """
    ISP / Organisation contact and peering profile.

    Populated primarily from PeeringDB with RDAP as fallback.
    Always present when an ASN was resolved (never null for a valid lookup).
    """

    website: Optional[str] = Field(None, description="Organisation website URL.")
    noc_email: Optional[str] = Field(None, description="Network Operations Centre contact email.")
    abuse_email: Optional[str] = Field(None, description="Abuse reporting email address.")
    support_email: Optional[str] = Field(None, description="General support contact.")
    peering_policy: Optional[str] = Field(
        None,
        description="BGP peering policy (Open / Selective / Restrictive / No).",
    )
    info_type: Optional[str] = Field(
        None,
        description="Network type as classified by PeeringDB (e.g. Content, Cable/DSL/ISP).",
    )
    internet_exchanges: PaginatedList = Field(
        default_factory=lambda: PaginatedList(count=0, sample=[], complete_available=True),
        description="Internet Exchanges where this network is present.",
    )
    # Source tracking — which source provided this profile
    profile_sources: List[str] = Field(
        default_factory=list,
        description="Sources that contributed fields to this profile (PeeringDB, RDAP, etc.).",
    )


class ASNRelationships(BaseModel):
    """
    BGP routing relationships for the queried ASN.

    Exposes counts + sampled lists (with remaining counts) to avoid
    payload bloat for large Tier-1/hyperscaler ASNs.
    """

    # ── Aggregate counts (always present) ─────────────────────────────────────
    peer_count: int = Field(0, description="Total number of direct BGP peers.")
    upstream_count: int = Field(0, description="Total number of upstream transit providers.")
    downstream_count: int = Field(0, description="Total number of downstream customer networks.")

    # ── Sampled lists with remaining counts (Task 7) ──────────────────────────
    peers: SampledRelationshipList = Field(
        default_factory=SampledRelationshipList,
        description="Direct BGP peers — sample + total/remaining counts.",
    )
    upstreams: SampledRelationshipList = Field(
        default_factory=SampledRelationshipList,
        description="Transit providers (upstream ASNs) — sample + counts.",
    )
    downstreams: SampledRelationshipList = Field(
        default_factory=SampledRelationshipList,
        description="Customer networks (downstream ASNs) — sample + counts.",
    )

    # ── Semantic aliases ───────────────────────────────────────────────────────
    transit_providers: SampledRelationshipList = Field(
        default_factory=SampledRelationshipList,
        description="Alias for upstreams — transit providers for this ASN.",
    )
    customer_networks: SampledRelationshipList = Field(
        default_factory=SampledRelationshipList,
        description="Alias for downstreams — networks that transit through this ASN.",
    )

    # ── Data provenance ────────────────────────────────────────────────────────
    data_source: Optional[str] = Field(
        None,
        description="Source that provided relationship data (BGPView or RIPE STAT).",
    )


class AnnouncedPrefixes(BaseModel):
    """
    Structured prefix enumeration for a queried ASN.

    Returns counts + samples to avoid payload bloat for large ASNs.
    """

    total_ipv4: int = Field(0, description="Total IPv4 prefixes announced.")
    total_ipv6: int = Field(0, description="Total IPv6 prefixes announced.")
    total: int = Field(0, description="Combined total prefix count.")
    sample_ipv4: List[str] = Field(
        default_factory=list,
        description="Sample of IPv4 prefixes (first N). See total_ipv4 for true count.",
    )
    sample_ipv6: List[str] = Field(
        default_factory=list,
        description="Sample of IPv6 prefixes (first N). See total_ipv6 for true count.",
    )
    remaining_ipv4: int = Field(
        0,
        description="IPv4 prefixes beyond the sample (total_ipv4 - len(sample_ipv4)).",
    )
    remaining_ipv6: int = Field(
        0,
        description="IPv6 prefixes beyond the sample (total_ipv6 - len(sample_ipv6)).",
    )
    complete_available: bool = Field(
        True,
        description="False when the full list exceeds the sample size.",
    )
    source: Optional[str] = Field(None, description="Source that provided this prefix data.")


class RPKIStatus(BaseModel):
    """
    RPKI / Route Origin Validation status for the queried prefix.

    Populated from RIPE STAT RPKI validation endpoint.
    """

    status: str = Field(
        "unavailable",
        description=(
            "RPKI validation result: "
            "'valid' (ROA found, matches origin ASN), "
            "'invalid' (ROA found, does not match), "
            "'not-found' (no ROA exists), "
            "'unknown' (could not determine), "
            "'unavailable' (RPKI source unreachable)."
        ),
    )
    roas: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Route Origin Authorizations found. Each has origin, prefix, max_length, validity.",
    )
    validated_prefix: Optional[str] = Field(None, description="The prefix that was validated.")
    source: str = Field("unknown", description="Source that performed the validation.")


class MultiASNInfo(BaseModel):
    """
    Structured multi-ASN detection result.

    ALWAYS present in the response — never null.
    Explains WHY additional ASNs appear alongside the primary one,
    or explicitly states that no additional ASNs were found.
    """

    detected: bool = Field(False, description="True if the organisation uses more than one ASN.")
    reason: str = Field(
        "No additional autonomous systems associated with this organisation were identified.",
        description="Human-readable explanation of why multiple ASNs exist, or why none were found.",
    )
    organization: Optional[str] = Field(None, description="Organisation name owning the ASNs.")
    primary_asn: Optional[str] = Field(None, description="The ASN directly serving this IP.")
    related_asns: List[str] = Field(
        default_factory=list,
        description="All other ASNs belonging to the same organisation.",
    )
    relationship_type: Optional[str] = Field(
        None,
        description=(
            "Nature of the ASN relationship when multiple ASNs exist: "
            "'Organisation-owned', 'Sibling ASN', 'Historical ASN', "
            "'Customer ASN', 'Transit ASN'."
        ),
    )


class ConfidenceBreakdown(BaseModel):
    """
    Deterministic confidence breakdown by intelligence category.

    Each score represents the contribution of that category to the total
    confidence_score (sum of all equals the overall score).
    Maximum values per category:
      rir          = 0.40
      bgp          = 0.20
      rpki         = 0.15
      rdns         = 0.05
      isp_profile  = 0.10
      relationships= 0.05
      cross_valid  = 0.05
    """

    rir: float = Field(0.0, description="RIR / RDAP data confidence (max 0.40).")
    bgp: float = Field(0.0, description="BGP routing data confidence (max 0.20).")
    rpki: float = Field(0.0, description="RPKI validation confidence (max 0.15).")
    rdns: float = Field(0.0, description="Reverse DNS resolution confidence (max 0.05).")
    isp_profile: float = Field(0.0, description="ISP profile data confidence (max 0.10).")
    relationships: float = Field(0.0, description="BGP relationship intelligence confidence (max 0.05).")
    cross_validation: float = Field(
        0.0,
        description="Cross-source agreement bonus confidence (max 0.05).",
    )


class ResponseMetadata(BaseModel):
    """
    Observability metadata for the intelligence lookup response.

    Provides deterministic confidence scoring, completeness tracking,
    and timing information.
    """

    confidence_score: float = Field(
        0.0,
        description=(
            "0.0–1.0 overall confidence score. Sum of all breakdown components. "
            "Based on: RIR data (40%), BGP (20%), RPKI (15%), rDNS (5%), "
            "ISP profile (10%), relationships (5%), cross-validation (5%)."
        ),
    )
    confidence_breakdown: ConfidenceBreakdown = Field(
        default_factory=ConfidenceBreakdown,
        description="Per-category breakdown of the confidence score.",
    )
    sources_used: List[str] = Field(
        default_factory=list,
        description="Intelligence sources that contributed data to this response.",
    )
    completed_fields: List[str] = Field(
        default_factory=list,
        description="Top-level ASNData fields that contain non-null data.",
    )
    missing_fields: List[str] = Field(
        default_factory=list,
        description="Top-level ASNData fields that remain null or empty.",
    )
    lookup_duration_ms: Optional[int] = Field(
        None,
        description="Total wall-clock time for the lookup in milliseconds.",
    )
    generated_at: str = Field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z",
        description="ISO 8601 UTC timestamp when this response was generated.",
    )
    cache_status: str = Field(
        "MISS",
        description="'HIT' if result came from cache, 'MISS' if freshly computed.",
    )


class AIRiskProfile(BaseModel):
    """
    Rule-based NLP risk classification.

    Generated entirely from collected public intelligence — no hallucination.
    All claims in ``summary`` are traceable to fields in the parent ``ASNData``.
    """

    network_type: str = Field(
        description="Primary classified network type (e.g. 'Cloud Provider', 'Residential ISP').",
    )
    network_tags: List[str] = Field(
        default_factory=list,
        description=(
            "Multi-label network classification tags that apply to this network. "
            "Examples: 'Cloud Provider', 'DNS Resolver', 'Anycast Network', "
            "'Global Backbone', 'CDN', 'VPN Provider', 'Mobile Carrier', etc."
        ),
    )
    risk_level: str = Field(description="Assessed risk level: LOW, MEDIUM, or HIGH.")
    risk_indicators: List[str] = Field(
        default_factory=list,
        description="Human-readable indicators that informed the risk classification.",
    )
    summary: str = Field(description="Plain-English intelligence summary. Factual statements only.")


# =============================================================================
# Merged intelligence result  (canonical Module 1 output)
# =============================================================================


class ASNData(BaseModel):
    """
    Merged intelligence result combining IPInfo, RDAP, BGPView, PeeringDB,
    RIPE STAT, and Team Cymru data into a single production-quality intelligence document.
    """

    # ── Target ───────────────────────────────────────────────────────────────
    ip: str = Field(description="The queried IP address.")

    # ── Basic ASN / ISP (IPInfo + Cymru fallback) ─────────────────────────────
    asn: Optional[str] = Field(None, description="Autonomous System Number, e.g. AS15169.")
    isp: Optional[str] = Field(None, description="Internet Service Provider name.")
    organization: Optional[str] = Field(None, description="Organisation operating the ASN.")
    country: Optional[str] = Field(None, description="Two-letter ISO country code.")
    hostname: Optional[str] = Field(None, description="Reverse DNS hostname.")
    city: Optional[str] = Field(None, description="City (from IPInfo geolocation).")
    region: Optional[str] = Field(None, description="Region / state (from IPInfo geolocation).")
    timezone: Optional[str] = Field(None, description="IANA timezone string.")

    # ── RDAP Network Registration ─────────────────────────────────────────────
    network_handle: Optional[str] = Field(None, description="RDAP network handle.")
    network_name: Optional[str] = Field(None, description="Registered network name.")
    network_description: Optional[str] = Field(None, description="Network description from RDAP remarks.")
    registry: Optional[str] = Field(
        None,
        description="Regional Internet Registry (ARIN / RIPE NCC / APNIC / LACNIC / AFRINIC).",
    )
    whois_server: Optional[str] = Field(None, description="WHOIS server hostname for this block.")
    allocation_type: Optional[str] = Field(
        None,
        description="Allocation type from RDAP (e.g. DIRECT ALLOCATION, REALLOCATED, REASSIGNED).",
    )
    network_status: Optional[str] = Field(None, description="Network status (e.g. active).")
    start_address: Optional[str] = Field(None, description="First IP in the allocated block.")
    end_address: Optional[str] = Field(None, description="Last IP in the allocated block.")
    cidr_prefixes: List[str] = Field(
        default_factory=list,
        description="CIDR prefixes from RDAP registration.",
    )

    # ── Registration date fields (Task 4 — differentiated) ────────────────────
    registration_date: Optional[str] = Field(
        None,
        description=(
            "Date this network block was first registered with the RIR. "
            "Corresponds to RDAP eventAction='registration'."
        ),
    )
    allocation_date: Optional[str] = Field(
        None,
        description=(
            "Date this block was allocated/assigned. "
            "For ARIN/RIPE/APNIC records this is the same as registration_date "
            "unless the RDAP record distinguishes them explicitly."
        ),
    )
    last_changed_date: Optional[str] = Field(
        None,
        description=(
            "Date of the most recent modification to the RDAP registration record. "
            "Corresponds to RDAP eventAction='last changed'."
        ),
    )
    date_semantics: Optional[str] = Field(
        None,
        description=(
            "Human-readable note clarifying what registration_date and last_changed_date "
            "represent for this specific record (e.g. 'ARIN: registration=first allocation date, "
            "last_changed=last record update')."
        ),
    )

    # ── BGP Routing Intelligence ───────────────────────────────────────────────
    origin_asn: Optional[str] = Field(None, description="Origin ASN confirmed by BGP source.")
    bgp_name: Optional[str] = Field(None, description="ASN human name from BGP source.")
    bgp_description: Optional[str] = Field(None, description="ASN description from BGP source.")
    bgp_country: Optional[str] = Field(
        None,
        description="Country associated with the ASN in BGP routing data.",
    )
    # Backward-compatible flat lists (sample only)
    ipv4_prefixes: List[str] = Field(
        default_factory=list,
        description="Sample of IPv4 prefixes announced by the ASN.",
    )
    ipv6_prefixes: List[str] = Field(
        default_factory=list,
        description="Sample of IPv6 prefixes announced by the ASN.",
    )
    prefix_count: int = Field(0, description="Total announced BGP prefixes (IPv4 + IPv6).")

    # ── Full Prefix Enumeration ───────────────────────────────────────────────
    announced_prefixes: Optional[AnnouncedPrefixes] = Field(
        None,
        description="Full prefix enumeration with counts + samples + remaining counts.",
    )

    # ── RPKI / Routing Security ───────────────────────────────────────────────
    rpki: Optional[RPKIStatus] = Field(
        None,
        description="RPKI Route Origin Validation status for the primary CIDR.",
    )

    # ── ISP / Organisation Profile ────────────────────────────────────────────
    isp_profile: Optional[ISPProfile] = Field(
        None,
        description=(
            "ISP contact and peering profile. Present whenever an ASN was resolved. "
            "Sources: PeeringDB (primary), RDAP (fallback for contact emails)."
        ),
    )

    # ── BGP Relationships ─────────────────────────────────────────────────────
    relationships: Optional[ASNRelationships] = Field(
        None,
        description="BGP peering relationships with counts + sampled lists.",
    )

    # ── Multi-ASN Detection ───────────────────────────────────────────────────
    multi_asn: MultiASNInfo = Field(
        default_factory=lambda: MultiASNInfo(
            detected=False,
            reason="Multi-ASN detection has not run yet.",
            primary_asn=None,
        ),
        description=(
            "Structured multi-ASN detection result. "
            "Always present — never null. "
            "detected=False means only one ASN was identified."
        ),
    )

    # ── AI Risk Layer ─────────────────────────────────────────────────────────
    ai_risk: Optional[AIRiskProfile] = Field(
        None,
        description=(
            "Rule-based NLP risk classification with multi-label network tags. "
            "Based solely on collected public intelligence — no hallucination."
        ),
    )

    # ── Data Provenance ───────────────────────────────────────────────────────
    data_provenance: Dict[str, str] = Field(
        default_factory=dict,
        description="Maps each intelligence field to the source that provided it.",
    )

    # ── Response Metadata ─────────────────────────────────────────────────────
    metadata: Optional[ResponseMetadata] = Field(
        None,
        description=(
            "Observability metadata: deterministic confidence score with breakdown, "
            "completeness tracking, timing, cache status."
        ),
    )

    # ── Pipeline Metadata ─────────────────────────────────────────────────────
    sources_queried: List[str] = Field(
        default_factory=list,
        description="Intelligence sources that responded with data for this lookup.",
    )


# =============================================================================
# API boundary models
# =============================================================================


class ASNLookupRequest(BaseModel):
    """Request body for the ASN lookup endpoint."""

    ip: IPvAnyAddress = Field(description="IPv4 or IPv6 address to look up.")

    model_config = {
        "json_schema_extra": {
            "examples": [{"ip": "8.8.8.8"}]
        }
    }


class ASNLookupResponse(BaseModel):
    """Standardised API response envelope for Module 1."""

    success: bool
    message: str
    data: Optional[ASNData] = None
    error: Optional[str] = None