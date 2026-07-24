"""Tests for passive client enumeration and the production API."""

import subprocess
import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.modules.wireless.analysis.oui import IEEEOUIRegistry
from app.modules.wireless.collectors.clients import WirelessClientCollector
from app.modules.wireless.parsers.clients import (
    parse_dhcp_leases,
    parse_linux_neighbors,
    parse_windows_arp,
)
from app.modules.wireless.service import (
    WirelessIntelligenceService,
    get_wireless_service,
)

WINDOWS_ARP = """
Interface: 192.168.1.10 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.1           00-1a-2b-44-55-66     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
"""


class ClientEnumerationTests(unittest.TestCase):
    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_parses_windows_unicast_entries(self) -> None:
        clients = parse_windows_arp(WINDOWS_ARP, "Wi-Fi")

        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].ip, "192.168.1.1")
        self.assertEqual(clients[0].mac, "00:1A:2B:44:55:66")

    def test_parses_linux_neighbor_state_and_interface(self) -> None:
        clients = parse_linux_neighbors(
            "192.168.1.2 dev wlan0 lladdr 00:1a:2b:11:22:33 REACHABLE\n"
        )

        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].status, "active")
        self.assertEqual(clients[0].interface, "wlan0")

    def test_parses_isc_and_dnsmasq_leases(self) -> None:
        leases = """
lease 192.168.1.3 {
  hardware ethernet 00:1a:2b:aa:bb:cc;
  binding state active;
  client-hostname "camera";
}
1700000000 00:1a:2b:dd:ee:ff 192.168.1.4 laptop *
"""
        clients = parse_dhcp_leases(leases)

        self.assertEqual(len(clients), 2)
        self.assertEqual(
            {item.hostname for item in clients},
            {"camera", "laptop"},
        )

    def test_api_returns_vendor_enriched_passive_clients(self) -> None:
        collector = WirelessClientCollector(
            runner=lambda command, timeout: subprocess.CompletedProcess(
                command,
                0,
                stdout=WINDOWS_ARP,
                stderr="",
            ),
            platform_name="Windows",
        )
        service = WirelessIntelligenceService(
            client_collector=collector,
            oui_registry=IEEEOUIRegistry(
                records={"001A2B": "Example Networks Inc."}
            ),
        )
        app.dependency_overrides[get_wireless_service] = lambda: service

        response = TestClient(app).post(
            "/api/v1/wireless/clients",
            json={"interface": "Wi-Fi"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["data"]["clients"], [])
        self.assertFalse(payload["data"]["wireless_capture_available"])
        self.assertIn(
            "unconfirmed",
            payload["data"]["explanation"].lower(),
        )
        client = payload["data"]["neighbor_candidates"][0]
        self.assertEqual(client["vendor"], "Example Networks Inc.")
        self.assertTrue(client["vendor_source_available"])
        self.assertEqual(client["sources"], ["arp"])
        self.assertFalse(client["confirmed_wireless"])
        self.assertIsNotNone(client["last_seen"])
        self.assertNotIn("raw_output", payload["data"])


if __name__ == "__main__":
    unittest.main()
