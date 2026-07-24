"""Safe cross-platform wireless interface discovery."""

from __future__ import annotations

import platform
import subprocess
import time
from collections.abc import Callable, Sequence

from app.core.logger import get_logger
from app.modules.wireless.exceptions import UnsupportedPlatformError
from app.modules.wireless.models import InterfaceDiscoveryResult
from app.modules.wireless.parsers.interfaces import (
    parse_linux_nmcli_interfaces,
    parse_windows_interfaces,
)

logger = get_logger(__name__)

CommandRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]
MAX_COMMAND_OUTPUT = 256_000


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


class WirelessInterfaceCollector:
    """Collect local interface metadata without privileges or state changes."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        platform_name: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("Interface command timeout must be 0.1-30 seconds")
        self._runner = runner or _run_command
        self._platform = platform_name or platform.system()
        self._timeout = timeout_seconds

    def collect(self) -> InterfaceDiscoveryResult:
        """Return normalized interface data and sanitized failure metadata."""
        started = time.perf_counter()
        command, parser = self._command_and_parser()
        try:
            result = self._runner(command, self._timeout)
            output = (result.stdout or "")[:MAX_COMMAND_OUTPUT]
            interfaces = parser(output) if result.returncode == 0 else ()
            error = None if result.returncode == 0 else "Wireless command failed"
            available = True
        except FileNotFoundError:
            interfaces = ()
            available = False
            error = "Wireless command is not installed"
        except subprocess.TimeoutExpired:
            interfaces = ()
            available = True
            error = "Wireless command timed out"
        except OSError:
            interfaces = ()
            available = False
            error = "Wireless command could not be executed"

        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Wireless interface discovery platform=%s interfaces=%d",
            self._platform,
            len(interfaces),
        )
        return InterfaceDiscoveryResult(
            platform=self._platform,
            interfaces=interfaces,
            command_available=available,
            duration_ms=duration_ms,
            error=error,
        )

    def _command_and_parser(self):
        normalized = self._platform.lower()
        if normalized == "windows":
            return (
                ("netsh", "wlan", "show", "interfaces"),
                parse_windows_interfaces,
            )
        if normalized == "linux":
            return (
                ("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"),
                parse_linux_nmcli_interfaces,
            )
        raise UnsupportedPlatformError(
            f"Wireless interface discovery is unsupported on {self._platform}"
        )
