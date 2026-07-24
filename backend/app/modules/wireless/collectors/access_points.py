"""Safe cross-platform access-point enumeration."""

from __future__ import annotations

import platform
import subprocess
import time
from collections.abc import Callable, Sequence

from app.core.logger import get_logger
from app.modules.wireless.exceptions import UnsupportedPlatformError
from app.modules.wireless.models import AccessPointScanResult
from app.modules.wireless.parsers.access_points import (
    parse_linux_access_points,
    parse_windows_access_points,
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


class AccessPointCollector:
    """Enumerate nearby AP metadata without connecting to a network."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        platform_name: str | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 60:
            raise ValueError("Access-point command timeout must be 0.1-60 seconds")
        self._runner = runner or _run_command
        self._platform = platform_name or platform.system()
        self._timeout = timeout_seconds

    def collect(
        self,
        interface: str | None = None,
        rescan: bool = True,
    ) -> AccessPointScanResult:
        """Return normalized AP observations and sanitized command errors."""
        started = time.perf_counter()
        try:
            command, parser = self._command(interface, rescan)
            result = self._runner(command, self._timeout)
            output = (result.stdout or "")[:MAX_COMMAND_OUTPUT]
            access_points = (
                parser(output, interface) if result.returncode == 0 else ()
            )
            available = True
            error = (
                None
                if result.returncode == 0
                else _scan_error(output, result.stderr or "")
            )
        except FileNotFoundError:
            access_points = ()
            available = False
            error = "Wireless scan command is not installed"
        except subprocess.TimeoutExpired:
            access_points = ()
            available = True
            error = "Wireless scan command timed out"
        except OSError:
            access_points = ()
            available = False
            error = "Wireless scan command could not be executed"
        except UnsupportedPlatformError:
            access_points = ()
            available = False
            error = (
                f"Wireless access-point scanning is unsupported on "
                f"{self._platform}"
            )

        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Access-point scan platform=%s access_points=%d",
            self._platform,
            len(access_points),
        )
        return AccessPointScanResult(
            platform=self._platform,
            interface=interface,
            access_points=access_points,
            command_available=available,
            duration_ms=duration_ms,
            limitations=(
                "RSSI in dBm is unavailable from this operating-system scan.",
                "Beacon interval and WPS/PMF state are returned only when the operating system exposes them.",
                "First seen represents the first observation in this scan; no historical tracking was used.",
                "Country and geolocation are unavailable from the local operating-system scan and are not inferred.",
            ),
            error=error,
        )

    def _command(self, interface: str | None, rescan: bool):
        normalized = self._platform.lower()
        if normalized == "windows":
            return (
                ("netsh", "wlan", "show", "networks", "mode=bssid"),
                parse_windows_access_points,
            )
        if normalized == "linux":
            command = [
                "nmcli",
                "-t",
                "-f",
                "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes" if rescan else "no",
            ]
            if interface:
                command.extend(("ifname", interface))
            return tuple(command), parse_linux_access_points
        raise UnsupportedPlatformError(
            f"Access-point enumeration is unsupported on {self._platform}"
        )


def _scan_error(stdout: str, stderr: str) -> str:
    """Map known command failures without exposing operating-system output."""
    normalized = f"{stdout} {stderr}".lower()
    if "location permission" in normalized or "location services" in normalized:
        return (
            "Windows location access is required for Wi-Fi scan results; "
            "enable Location services and permit the application to access location"
        )
    if "wireless autoconfig" in normalized or "wlansvc" in normalized:
        return "The Windows WLAN AutoConfig service is not running"
    if "no wireless interface" in normalized or "no wireless adapter" in normalized:
        return "No enabled wireless adapter is available"
    return (
        "Wireless scan command failed; verify that a Wi-Fi adapter is enabled, "
        "the WLAN service is running, and the process has scan permission"
    )
