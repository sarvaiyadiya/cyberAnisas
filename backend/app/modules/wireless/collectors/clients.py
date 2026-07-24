"""Safe passive neighbor-table collection for Module 5."""

from __future__ import annotations

import platform
import subprocess
import time
from collections.abc import Callable, Sequence

from app.core.logger import get_logger
from app.modules.wireless.exceptions import UnsupportedPlatformError
from app.modules.wireless.models import ClientEnumerationResult
from app.modules.wireless.parsers.clients import (
    merge_clients,
    parse_dhcp_leases,
    parse_linux_neighbors,
    parse_windows_arp,
)

logger = get_logger(__name__)

CommandRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]
MAX_COMMAND_OUTPUT = 1_000_000


def _run_command(
    command: Sequence[str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )


class WirelessClientCollector:
    """Read existing local neighbor metadata without active probing."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        platform_name: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("Client command timeout must be 0.1-30 seconds")
        self._runner = runner or _run_command
        self._platform = platform_name or platform.system()
        self._timeout = timeout_seconds

    def collect(
        self,
        interface: str | None = None,
        dhcp_lease_text: str | None = None,
    ) -> ClientEnumerationResult:
        """Collect passive neighbors and merge optional imported leases."""
        started = time.perf_counter()
        leases = (
            parse_dhcp_leases(dhcp_lease_text)
            if dhcp_lease_text
            else ()
        )
        try:
            command, parser = self._command(interface)
            result = self._runner(command, self._timeout)
            output = (result.stdout or "")[:MAX_COMMAND_OUTPUT]
            neighbors = (
                parser(output, interface) if result.returncode == 0 else ()
            )
            clients = merge_clients(neighbors, leases)
            available = True
            error = (
                None
                if result.returncode == 0
                else "Neighbor command failed; verify interface and permissions"
            )
        except FileNotFoundError:
            clients = leases
            available = False
            error = "Neighbor command is not installed"
        except subprocess.TimeoutExpired:
            clients = leases
            available = True
            error = "Neighbor command timed out"
        except OSError:
            clients = leases
            available = False
            error = "Neighbor command could not be executed"
        except UnsupportedPlatformError:
            clients = leases
            available = False
            error = (
                f"Passive client enumeration is unsupported on "
                f"{self._platform}"
            )

        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Passive client enumeration platform=%s clients=%d",
            self._platform,
            len(clients),
        )
        return ClientEnumerationResult(
            platform=self._platform,
            interface=interface,
            clients=(),
            neighbor_candidates=clients,
            wireless_capture_available=False,
            explanation=(
                "No wireless association capture is available. ARP, neighbor, "
                "and DHCP records are unconfirmed network-neighbor candidates, "
                "not confirmed Wi-Fi clients."
            ),
            command_available=available,
            duration_ms=duration_ms,
            error=error,
        )

    def _command(self, interface: str | None):
        normalized = self._platform.lower()
        if normalized == "windows":
            return ("arp", "-a"), parse_windows_arp
        if normalized == "linux":
            command = ["ip", "neigh", "show"]
            if interface:
                command.extend(("dev", interface))
            return tuple(command), parse_linux_neighbors
        raise UnsupportedPlatformError(
            f"Client enumeration is unsupported on {self._platform}"
        )
