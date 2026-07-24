"""Unit tests for safe wireless interface discovery."""

import subprocess
import unittest

from app.modules.wireless.collectors.interfaces import WirelessInterfaceCollector
from app.modules.wireless.models import WirelessInterfaceStatus
from app.modules.wireless.parsers.interfaces import (
    parse_linux_nmcli_interfaces,
    parse_windows_interfaces,
)


class WirelessInterfaceTests(unittest.TestCase):
    def test_parses_windows_interface(self) -> None:
        output = """
    Name                   : Wi-Fi
    Description            : Intel(R) Wireless Adapter
    State                  : connected
"""
        interfaces = parse_windows_interfaces(output)

        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0].name, "Wi-Fi")
        self.assertEqual(
            interfaces[0].status,
            WirelessInterfaceStatus.CONNECTED,
        )

    def test_parses_only_linux_wifi_devices(self) -> None:
        output = "wlan0:wifi:connected\neth0:ethernet:connected\n"
        interfaces = parse_linux_nmcli_interfaces(output)

        self.assertEqual([item.name for item in interfaces], ["wlan0"])

    def test_collector_uses_argument_list_and_normalizes_result(self) -> None:
        observed_command = None

        def runner(command, timeout):
            nonlocal observed_command
            observed_command = tuple(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="Name : Wi-Fi\nState : disconnected\n",
                stderr="",
            )

        result = WirelessInterfaceCollector(
            runner=runner,
            platform_name="Windows",
        ).collect()

        self.assertEqual(
            observed_command,
            ("netsh", "wlan", "show", "interfaces"),
        )
        self.assertTrue(result.command_available)
        self.assertEqual(result.interfaces[0].name, "Wi-Fi")

    def test_missing_command_is_sanitized(self) -> None:
        def runner(command, timeout):
            raise FileNotFoundError("sensitive path")

        result = WirelessInterfaceCollector(
            runner=runner,
            platform_name="Linux",
        ).collect()

        self.assertFalse(result.command_available)
        self.assertEqual(result.error, "Wireless command is not installed")
        self.assertNotIn("sensitive", result.error)


if __name__ == "__main__":
    unittest.main()
