"""
core/cache.py

Lightweight TTL-based in-memory cache for ANISAS.

Design:
  - Pure stdlib implementation — zero new dependencies.
  - Thread-safe for single-process uvicorn workers.
  - Used to avoid hammering public APIs on repeated lookups of the same IP.
  - Default TTL: 5 minutes (configurable via settings).

Usage:
    from app.core.cache import lookup_cache
    cached = lookup_cache.get("8.8.8.8")
    if cached is None:
        result = expensive_lookup("8.8.8.8")
        lookup_cache.set("8.8.8.8", result)
"""

import time
import threading
from typing import Any, Optional

from app.core.logger import get_logger

logger = get_logger(__name__)


class TTLCache:
    """
    Thread-safe dictionary-backed cache with per-entry time-to-live expiry.

    Expired entries are evicted lazily on the next ``get()`` call for that key,
    or eagerly via ``purge_expired()``.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        """
        Args:
            ttl_seconds: How long each cached entry stays valid (default 5 min).
        """
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    # ── Public interface ──────────────────────────────────────────────────────

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve a cached value by key.

        Returns:
            The cached value, or ``None`` if absent or expired.
        """
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None

            value, expires_at = entry
            if time.monotonic() >= expires_at:
                del self._store[key]
                logger.debug("Cache: expired entry evicted for key=%s", key)
                return None

            logger.debug("Cache: HIT for key=%s", key)
            return value

    def set(self, key: str, value: Any) -> None:
        """
        Store a value with TTL expiry.

        Args:
            key:   Cache key (e.g. the IP address string).
            value: Value to store.
        """
        with self._lock:
            expires_at = time.monotonic() + self._ttl
            self._store[key] = (value, expires_at)
            logger.debug("Cache: SET key=%s (expires in %ds)", key, self._ttl)

    def invalidate(self, key: str) -> None:
        """Remove a single entry from the cache."""
        with self._lock:
            self._store.pop(key, None)

    def purge_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed.
        """
        now = time.monotonic()
        with self._lock:
            expired_keys = [k for k, (_, exp) in self._store.items() if now >= exp]
            for k in expired_keys:
                del self._store[k]
        if expired_keys:
            logger.debug("Cache: purged %d expired entries", len(expired_keys))
        return len(expired_keys)

    def clear(self) -> None:
        """Remove all entries from the cache."""
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        """Current number of entries (including potentially expired ones)."""
        with self._lock:
            return len(self._store)


# ── Module-level singleton ────────────────────────────────────────────────────
# Import this object wherever caching is needed.
lookup_cache: TTLCache = TTLCache(ttl_seconds=300)  # overridden in service.py
