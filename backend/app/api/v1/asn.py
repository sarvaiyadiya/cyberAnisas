"""
api/v1/asn.py

FastAPI router for Module 1 — ASN & ISP Intelligence Engine.

Route: POST /api/v1/asn/lookup
"""

import time
from fastapi import APIRouter, HTTPException, status
from app.core.logger import get_logger
from app.core.cache import TTLCache
from app.core.config import settings
from app.modules.asn.models import ASNLookupRequest, ASNLookupResponse
from app.modules.asn.service import get_asn_information

logger = get_logger(__name__)

router = APIRouter(
    prefix="/asn",
    tags=["Module 1 — ASN & ISP Intelligence"],
)


@router.post(
    "/lookup",
    response_model=ASNLookupResponse,
    summary="ASN & ISP Intelligence Lookup",
    description=(
        "Perform a full ASN & ISP intelligence lookup against six public sources: "
        "**IPInfo** (geolocation), **Team Cymru** (ASN fallback), **RDAP** (network registration), "
        "**BGPView** (prefix lists + relationships), **RIPE STAT** (BGP fallback + RPKI validation), "
        "and **PeeringDB** (ISP profile + IXPs + multi-ASN). "
        "Returns a merged, provenance-annotated intelligence document including "
        "NOC/abuse contacts, multi-ASN detection, BGP relationships, RPKI status, "
        "prefix enumeration, and a rule-based AI risk classification. "
        "Response includes observability metadata (confidence score, timing, completeness)."
    ),
    responses={
        200: {"description": "Lookup completed. Partial results returned when some sources are unavailable."},
        422: {"description": "Invalid IP address format."},
        500: {"description": "Internal server error."},
    },
)
def asn_lookup(request: ASNLookupRequest) -> ASNLookupResponse:
    """
    Full ASN & ISP intelligence lookup.

    Queries six independent sources in sequence:
    1. **IPInfo**    — ASN, ISP name, geolocation
    2. **Team Cymru** — Fallback ASN resolution (whois-based, zero rate-limit)
    3. **RDAP**      — Network registration, CIDR, registry, contacts, dates
    4. **BGPView**   — Prefix lists, ASN metadata, peers, upstreams, downstreams
    5. **RIPE STAT** — BGP fallback (prefix lists, neighbours, RPKI validation)
    6. **PeeringDB** — Website, NOC/abuse email, IXP memberships, multi-ASN detection

    Results include:
    - Rule-based AI risk classification and factual NLP summary
    - Data provenance map (field → source)
    - Response metadata (confidence score, timing, cache status, completeness)
    - RPKI / Route Origin Validation status
    - Announced prefix enumeration with counts + samples
    - Structured multi-ASN detection with relationship type explanation

    Partial results are returned gracefully when sources are unreachable.
    """
    ip_str = str(request.ip)
    logger.info("API: POST /asn/lookup — ip=%s", ip_str)

    try:
        data = get_asn_information(ip_str)

        sources_label = ", ".join(data.sources_queried) or "none"

        return ASNLookupResponse(
            success=True,
            message=f"ASN intelligence lookup completed for {ip_str} (sources: {sources_label}).",
            data=data,
        )

    except Exception as exc:  # noqa: BLE001
        logger.error("API: unhandled error during lookup for %s — %s", ip_str, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "ASN lookup failed due to an internal server error.",
                "error": str(exc),
            },
        ) from exc
