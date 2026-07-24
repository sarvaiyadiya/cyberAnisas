"""Local IEEE MA-L registry lookup for MAC vendor evidence."""

from __future__ import annotations

from pathlib import Path
import string
from threading import Lock

from app.core.logger import get_logger
from app.modules.wireless.models import MACVendorResult
from app.modules.wireless.parsers.oui import parse_ieee_oui_csv
from app.modules.wireless.utils import normalize_mac

logger = get_logger(__name__)

DEFAULT_IEEE_CACHE = Path(__file__).resolve().parent.parent / "data" / "oui.csv"
MAX_IEEE_CACHE_BYTES = 25_000_000


class IEEEOUIRegistry:
    """Load a bounded local IEEE MA-L CSV once and perform exact OUI lookups."""

    def __init__(
        self,
        cache_path: Path | None = None,
        records: dict[str, str] | None = None,
    ) -> None:
        self._cache_path = cache_path or DEFAULT_IEEE_CACHE
        self._records = (
            {
                _normalize_prefix(prefix): vendor.strip()[:500]
                for prefix, vendor in records.items()
                if _normalize_prefix(prefix) and vendor.strip()
            }
            if records is not None
            else None
        )
        self._lock = Lock()

    def lookup(self, mac: str) -> MACVendorResult:
        """Return exact cached IEEE evidence without online fallback."""
        normalized = normalize_mac(mac)
        if normalized is None:
            raise ValueError("A valid 48-bit MAC address is required")
        oui = normalized[:8]
        locally_administered = bool(int(normalized[:2], 16) & 0x02)
        if locally_administered:
            return MACVendorResult(
                mac=normalized,
                oui=oui,
                source_available=self.source_available,
                locally_administered=True,
            )

        records = self._load()
        vendor = records.get(oui.replace(":", ""))
        return MACVendorResult(
            mac=normalized,
            oui=oui,
            vendor=vendor or "Unknown",
            confidence=100 if vendor else 0,
            source="IEEE MA-L" if vendor else None,
            source_available=bool(records),
            locally_administered=False,
        )

    @property
    def source_available(self) -> bool:
        """Whether at least one valid IEEE record is loaded."""
        return bool(self._load())

    def _load(self) -> dict[str, str]:
        if self._records is not None:
            return self._records
        with self._lock:
            if self._records is not None:
                return self._records
            self._records = self._read_cache()
            return self._records

    def _read_cache(self) -> dict[str, str]:
        try:
            size = self._cache_path.stat().st_size
            if size > MAX_IEEE_CACHE_BYTES:
                logger.warning("IEEE OUI cache exceeds the permitted size")
                return {}
            content = self._cache_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            logger.info("IEEE OUI cache is not available")
            return {}
        records = parse_ieee_oui_csv(content)
        logger.info("Loaded %d IEEE MA-L assignments", len(records))
        return records


def _normalize_prefix(value: str) -> str:
    normalized = "".join(
        character for character in value if character in string.hexdigits
    )
    normalized = normalized.upper()
    return normalized if len(normalized) == 6 else ""
