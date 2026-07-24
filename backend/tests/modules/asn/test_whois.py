"""Tests for bounded authoritative WHOIS collection."""

import socket
import unittest

from app.modules.asn.clients.whois import WHOISClient
from app.modules.asn.parsers.whois_parser import parse_whois_response

ARIN_RESPONSE = """
NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        LVLT-GOGL-8-8-8
OrgName:        Google LLC
Country:        US
RegDate:        2014-03-14
Updated:        2023-12-28
OrgAbuseEmail:  network-abuse@google.com
"""


class WHOISTests(unittest.TestCase):
    def test_parser_returns_structured_evidence(self) -> None:
        result = parse_whois_response("whois.arin.net", ARIN_RESPONSE)

        self.assertEqual(result.status, "available")
        self.assertEqual(result.network_name, "LVLT-GOGL-8-8-8")
        self.assertEqual(result.organization, "Google LLC")
        self.assertEqual(result.country, "US")
        self.assertEqual(result.cidrs, ["8.8.8.0/24"])
        self.assertIn("network-abuse@google.com", result.abuse_emails)
        self.assertGreater(result.confidence, 0)

    def test_client_is_bounded_and_uses_authoritative_server(self) -> None:
        calls = []

        def connector(server, query, timeout, max_bytes):
            calls.append((server, query, timeout, max_bytes))
            return ARIN_RESPONSE.encode()

        result = WHOISClient(connector=connector).lookup(
            "whois.arin.net",
            "8.8.8.8",
        )

        self.assertEqual(result.status, "available")
        self.assertEqual(calls[0][0], "whois.arin.net")
        self.assertEqual(calls[0][1], "8.8.8.8")
        self.assertLessEqual(calls[0][3], 65_536)

    def test_client_rejects_arbitrary_referral_server(self) -> None:
        result = WHOISClient(
            connector=lambda *args: b"should not execute"
        ).lookup("attacker.example", "8.8.8.8")

        self.assertEqual(result.status, "unsupported_server")

    def test_timeout_is_sanitized(self) -> None:
        def timeout(*args):
            raise socket.timeout("sensitive detail")

        result = WHOISClient(connector=timeout).lookup(
            "whois.arin.net",
            "8.8.8.8",
        )

        self.assertEqual(result.status, "timeout")
        self.assertNotIn("sensitive", result.error)


if __name__ == "__main__":
    unittest.main()
