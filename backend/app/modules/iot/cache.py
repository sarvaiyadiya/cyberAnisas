"""Module 4 scan-result cache built on the shared thread-safe TTL cache."""

from collections.abc import Iterable

from app.core.cache import TTLCache
from app.core.config import settings
from app.modules.iot.detectors.ports import DEFAULT_IOT_TCP_PORTS
from app.modules.iot.models import HTTPFingerprintScanResult


class IoTScanCache:
    """Cache immutable scan results using target and normalized port scope."""

    def __init__(
        self,
        ttl_seconds: int = settings.IOT_CACHE_TTL_SECONDS,
    ) -> None:
        if ttl_seconds < 0:
            raise ValueError("IoT cache TTL cannot be negative")
        self._enabled = ttl_seconds > 0
        self._cache = TTLCache(ttl_seconds=max(ttl_seconds, 1))

    @staticmethod
    def key(target: str, ports: Iterable[int] | None) -> str:
        """Build a stable key without relying on caller port ordering."""
        normalized = tuple(
            sorted(
                set(
                    ports
                    if ports is not None
                    else DEFAULT_IOT_TCP_PORTS
                )
            )
        )
        return f"{target}|{','.join(str(port) for port in normalized)}"

    def get(
        self,
        target: str,
        ports: Iterable[int] | None,
    ) -> HTTPFingerprintScanResult | None:
        """Return a cached immutable result when caching is enabled."""
        if not self._enabled:
            return None
        value = self._cache.get(self.key(target, ports))
        return value if isinstance(value, HTTPFingerprintScanResult) else None

    def set(
        self,
        target: str,
        ports: Iterable[int] | None,
        result: HTTPFingerprintScanResult,
    ) -> None:
        """Store a completed result; failed scans never reach this method."""
        if self._enabled:
            self._cache.set(self.key(target, ports), result)

    def clear(self) -> None:
        """Clear entries, primarily for application lifecycle and tests."""
        self._cache.clear()
