"""Tests for Module 1 derived and optional intelligence."""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.modules.asn.clients.threat_intel import (
    AbuseIPDBClient,
    VirusTotalClient,
)
from app.modules.asn.enrichment import (
    build_bgp_health,
    build_dns_intelligence,
    build_geolocation_confidence,
    build_historical_routing,
    build_organization_intelligence,
    build_visualization,
)
from app.modules.asn.models import (
    ASNData,
    ASNRelationships,
    ISPProfile,
    MultiASNInfo,
    PaginatedList,
    RPKIStatus,
    SampledRelationshipList,
)


class FakeHTTPClient:
    def __init__(self, payload):
        self.payload = payload

    def get(self, url, params=None, extra_headers=None):
        return self.payload


class ASNEnrichmentTests(unittest.TestCase):
    def _data(self) -> ASNData:
        return ASNData(
            ip="8.8.8.8",
            asn="AS15169",
            isp="Google LLC",
            organization="Google LLC",
            country="US",
            bgp_country="US",
            hostname="dns.google",
            prefix_count=2,
            ipv4_prefixes=["8.8.8.0/24"],
            rpki=RPKIStatus(status="valid", validated_prefix="8.8.8.0/24"),
            isp_profile=ISPProfile(
                website="https://google.com",
                internet_exchanges=PaginatedList(
                    count=2,
                    sample=["IX-A", "IX-B"],
                ),
                profile_sources=["PeeringDB"],
            ),
            multi_asn=MultiASNInfo(
                detected=True,
                primary_asn="AS15169",
                related_asns=["AS36040"],
            ),
            relationships=ASNRelationships(
                peer_count=1,
                peers=SampledRelationshipList(
                    total=1,
                    sample=[{"asn": "AS64500", "name": "Example Peer"}],
                ),
            ),
            sources_queried=["IPInfo", "RDAP", "RIPE STAT", "PeeringDB"],
        )

    def test_derived_intelligence_is_evidence_based(self) -> None:
        data = self._data()
        dns = build_dns_intelligence(data)
        organization = build_organization_intelligence(data)
        health = build_bgp_health(data)
        geo = build_geolocation_confidence(data)
        graph = build_visualization(data)

        self.assertEqual(dns.ptr_hostname, "dns.google")
        self.assertEqual(organization.primary_asn, "AS15169")
        self.assertEqual(organization.internet_exchange_count, 2)
        self.assertEqual(health.status, "healthy")
        self.assertTrue(geo.country_agreement)
        self.assertGreater(geo.score, 0)
        self.assertTrue(graph.nodes)
        self.assertTrue(graph.edges)

    def test_optional_sources_report_not_configured_without_keys(self) -> None:
        self.assertEqual(
            AbuseIPDBClient(api_key="").lookup("8.8.8.8").status,
            "not_configured",
        )
        self.assertEqual(
            VirusTotalClient(api_key="").lookup("8.8.8.8").status,
            "not_configured",
        )

    def test_routing_history_is_bounded_and_normalized(self) -> None:
        result = build_historical_routing(
            {
                "data": {
                    "by_origin": [
                        {
                            "origin": "15169",
                            "prefixes": [
                                {
                                    "prefix": "8.8.8.0/24",
                                    "timelines": [
                                        {
                                            "starttime": "2026-01-01T00:00:00",
                                            "endtime": "2026-02-01T00:00:00",
                                            "visibility": 0.95,
                                            "full_peers_seeing": 100,
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            }
        )

        self.assertEqual(result.status, "available")
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0]["prefix"], "8.8.8.0/24")

    def test_optional_source_payloads_are_normalized(self) -> None:
        abuse = AbuseIPDBClient(
            api_key="test",
            client=FakeHTTPClient(
                {
                    "data": {
                        "abuseConfidenceScore": 75,
                        "totalReports": 4,
                        "lastReportedAt": "2026-01-01T00:00:00Z",
                        "usageType": "Data Center/Web Hosting/Transit",
                    }
                }
            ),
        ).lookup("203.0.113.10")
        reputation = VirusTotalClient(
            api_key="test",
            client=FakeHTTPClient(
                {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 2,
                                "suspicious": 1,
                                "harmless": 7,
                                "undetected": 10,
                            }
                        }
                    }
                }
            ),
        ).lookup("203.0.113.10")

        self.assertEqual(abuse.status, "available")
        self.assertTrue(abuse.malicious)
        self.assertEqual(reputation.status, "available")
        self.assertEqual(reputation.malicious_engines, 2)
        self.assertGreater(reputation.score, 0)

    def test_production_api_exposes_new_domains_without_proxying(self) -> None:
        data = self._data()
        data.dns_intelligence = build_dns_intelligence(data)
        data.organization_intelligence = build_organization_intelligence(data)
        data.bgp_health = build_bgp_health(data)
        data.geolocation_confidence = build_geolocation_confidence(data)
        data.visualization = build_visualization(data)

        with patch("app.api.v1.asn.get_asn_information", return_value=data):
            response = TestClient(app).post(
                "/api/v1/asn/lookup",
                json={"ip": "8.8.8.8"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()["data"]
        self.assertEqual(payload["dns_intelligence"]["ptr_hostname"], "dns.google")
        self.assertEqual(payload["bgp_health"]["status"], "healthy")
        self.assertTrue(payload["visualization"]["nodes"])
        self.assertEqual(
            payload["threat_intelligence"]["status"],
            "not_configured",
        )


if __name__ == "__main__":
    unittest.main()
