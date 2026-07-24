"""Pure derived intelligence builders for Module 1."""

from app.modules.asn.models import (
    ASNData,
    BGPHealth,
    DNSIntelligence,
    GeolocationConfidence,
    HistoricalRouting,
    OrganizationIntelligence,
    VisualizationData,
)


def build_dns_intelligence(data: ASNData) -> DNSIntelligence:
    hostname = data.hostname
    domain = None
    if hostname and "." in hostname:
        labels = hostname.rstrip(".").split(".")
        domain = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
    return DNSIntelligence(
        ptr_hostname=hostname,
        registered_domain_hint=domain,
        forward_confirmed=None,
        confidence=0.6 if hostname else 0.0,
        evidence=([f"PTR hostname observed: {hostname}"] if hostname else []),
    )


def build_organization_intelligence(data: ASNData) -> OrganizationIntelligence:
    profile = data.isp_profile
    contacts = []
    if profile:
        contacts = [
            value
            for value in (
                profile.noc_email,
                profile.abuse_email,
                profile.support_email,
            )
            if value
        ]
    related = data.multi_asn.related_asns if data.multi_asn else []
    ixp_count = (
        profile.internet_exchanges.count
        if profile and profile.internet_exchanges
        else 0
    )
    sources = list(dict.fromkeys(
        (profile.profile_sources if profile else []) + data.sources_queried
    ))
    evidence_count = sum(
        bool(value)
        for value in (
            data.organization or data.isp,
            profile.website if profile else None,
            contacts,
            data.asn,
        )
    )
    return OrganizationIntelligence(
        name=data.organization or data.isp,
        network_type=(
            profile.info_type
            if profile and profile.info_type
            else data.ai_risk.network_type if data.ai_risk else None
        ),
        website=profile.website if profile else None,
        contact_emails=contacts,
        primary_asn=data.asn,
        related_asns=related,
        internet_exchange_count=ixp_count,
        confidence=round(evidence_count / 4, 2),
        sources=sources,
    )


def build_bgp_health(data: ASNData) -> BGPHealth:
    findings = []
    recommendations = []
    score = 40
    rpki = data.rpki.status if data.rpki else "unavailable"
    if data.prefix_count > 0:
        score += 20
        findings.append(f"{data.prefix_count} announced prefix(es) observed")
    else:
        recommendations.append("Verify that the ASN has visible route announcements.")
    if rpki == "valid":
        score += 30
        findings.append("Primary route origin is RPKI valid")
    elif rpki == "invalid":
        score = max(score - 40, 0)
        findings.append("Primary route origin is RPKI invalid")
        recommendations.append("Correct the ROA or route-origin announcement immediately.")
    elif rpki == "not-found":
        findings.append("No matching ROA was found")
        recommendations.append("Publish ROAs for announced production prefixes.")
    else:
        recommendations.append("Re-run RPKI validation when the source is available.")
    relationship_count = 0
    if data.relationships:
        relationship_count = (
            data.relationships.peer_count
            + data.relationships.upstream_count
            + data.relationships.downstream_count
        )
        if relationship_count:
            score += 10
    score = min(score, 100)
    status = "healthy" if score >= 80 else "degraded" if score >= 50 else "at_risk"
    return BGPHealth(
        score=score,
        status=status,
        rpki_status=rpki,
        announced_prefix_count=data.prefix_count,
        relationship_count=relationship_count,
        findings=findings,
        recommendations=recommendations,
    )


def build_geolocation_confidence(data: ASNData) -> GeolocationConfidence:
    evidence = []
    sources = []
    agreement = None
    score = 0.0
    if data.country:
        score += 0.45
        sources.append("IPInfo")
        evidence.append(f"IP geolocation country: {data.country}")
    if data.bgp_country:
        score += 0.25
        sources.append("BGP")
        evidence.append(f"BGP registration country: {data.bgp_country}")
    if data.country and data.bgp_country:
        agreement = data.country.upper() == data.bgp_country.upper()
        score += 0.25 if agreement else 0.0
        evidence.append(
            "Country sources agree" if agreement else "Country sources disagree"
        )
    if data.city or data.region:
        score += 0.05
    return GeolocationConfidence(
        score=round(min(score, 1.0), 2),
        country_agreement=agreement,
        evidence=evidence,
        sources=list(dict.fromkeys(sources)),
    )


def build_visualization(data: ASNData) -> VisualizationData:
    nodes = []
    edges = []
    if not data.asn:
        return VisualizationData()
    nodes.append({"id": data.asn, "type": "asn", "label": data.bgp_name or data.asn})
    truncated = False
    relationships = data.relationships
    if relationships:
        directions = (
            ("peer", relationships.peers.sample),
            ("upstream", relationships.upstreams.sample),
            ("downstream", relationships.downstreams.sample),
        )
        for relation, entries in directions:
            for entry in entries[:20]:
                asn = entry.get("asn") if isinstance(entry, dict) else None
                if not asn:
                    continue
                node_id = str(asn)
                nodes.append({"id": node_id, "type": "asn", "label": entry.get("name") or node_id})
                edges.append({"source": data.asn, "target": node_id, "relationship": relation})
            truncated = truncated or len(entries) > 20
    for prefix in (data.ipv4_prefixes + data.ipv6_prefixes)[:20]:
        nodes.append({"id": prefix, "type": "prefix", "label": prefix})
        edges.append({"source": data.asn, "target": prefix, "relationship": "announces"})
    return VisualizationData(nodes=nodes, edges=edges, truncated=truncated)


def build_historical_routing(raw: dict | None) -> HistoricalRouting:
    """Flatten a bounded sample of RIPE STAT routing-history timelines."""
    data = raw.get("data", {}) if isinstance(raw, dict) else {}
    origins = data.get("by_origin", [])
    if not isinstance(origins, list):
        return HistoricalRouting(status="unavailable", detail="Invalid source response.")
    events = []
    for origin_item in origins:
        origin = origin_item.get("origin")
        for prefix_item in origin_item.get("prefixes", []):
            prefix = prefix_item.get("prefix")
            for timeline in prefix_item.get("timelines", []):
                events.append(
                    {
                        "origin": origin,
                        "prefix": prefix,
                        "starttime": timeline.get("starttime"),
                        "endtime": timeline.get("endtime"),
                        "visibility": timeline.get("visibility"),
                        "full_peers_seeing": timeline.get(
                            "full_peers_seeing"
                        ),
                    }
                )
                if len(events) >= 20:
                    return HistoricalRouting(
                        status="available",
                        events=events,
                        source="RIPE STAT Routing History",
                        detail="Bounded sample; additional history may exist.",
                    )
    return HistoricalRouting(
        status="available" if isinstance(origins, list) else "unavailable",
        events=events,
        source="RIPE STAT Routing History",
        detail=(
            f"Returned {len(events)} bounded routing timeline event(s)."
        ),
    )
