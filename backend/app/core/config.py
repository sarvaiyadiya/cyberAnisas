"""
core/config.py

Application-wide configuration loaded from environment variables.
Uses Pydantic's BaseSettings for validation and type safety.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """
    Central settings object for ANISAS.

    All configuration values are read once at startup from the environment.
    Access via the module-level `settings` singleton.
    """

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "ANISAS"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Advanced Network Intelligence & Security Analysis System — "
        "A multi-module cybersecurity intelligence platform."
    )
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # ── HTTP Client ───────────────────────────────────────────────────────────
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "15"))
    USER_AGENT: str = "ANISAS/1.0 (github.com/anisas)"

    # ── External API Keys ─────────────────────────────────────────────────────
    IPINFO_TOKEN: str | None = os.getenv("IPINFO_TOKEN") or None
    # PeeringDB works without auth but rate-limits are higher with a token.
    PEERINGDB_TOKEN: str | None = os.getenv("PEERINGDB_TOKEN") or None
    NVD_API_KEY: str | None = os.getenv("NVD_API_KEY") or None

    # ── Caching ───────────────────────────────────────────────────────────────
    # How long (seconds) a completed ASN lookup is held in the in-memory cache.
    # Set to 0 to disable caching.
    CACHE_TTL_SECONDS: int = int(os.getenv("CACHE_TTL_SECONDS", "300"))

    # IoT fingerprinting scanner
    IOT_CONNECT_TIMEOUT_SECONDS: float = float(
        os.getenv("IOT_CONNECT_TIMEOUT_SECONDS", "0.75")
    )
    IOT_SCAN_WORKERS: int = int(os.getenv("IOT_SCAN_WORKERS", "64"))
    IOT_BANNER_TIMEOUT_SECONDS: float = float(
        os.getenv("IOT_BANNER_TIMEOUT_SECONDS", "1.5")
    )
    IOT_BANNER_MAX_BYTES: int = int(os.getenv("IOT_BANNER_MAX_BYTES", "4096"))
    IOT_HTTP_TIMEOUT_SECONDS: float = float(
        os.getenv("IOT_HTTP_TIMEOUT_SECONDS", "3.0")
    )
    IOT_HTTP_MAX_BYTES: int = int(os.getenv("IOT_HTTP_MAX_BYTES", "1048576"))
    IOT_TLS_TIMEOUT_SECONDS: float = float(
        os.getenv("IOT_TLS_TIMEOUT_SECONDS", "3.0")
    )
    IOT_RTSP_TIMEOUT_SECONDS: float = float(
        os.getenv("IOT_RTSP_TIMEOUT_SECONDS", "2.0")
    )
    IOT_RTSP_MAX_BYTES: int = int(os.getenv("IOT_RTSP_MAX_BYTES", "8192"))
    IOT_VENDOR_MIN_CONFIDENCE: int = int(
        os.getenv("IOT_VENDOR_MIN_CONFIDENCE", "30")
    )
    IOT_DEVICE_MIN_CONFIDENCE: int = int(
        os.getenv("IOT_DEVICE_MIN_CONFIDENCE", "50")
    )
    IOT_CVE_MAX_RESULTS: int = int(os.getenv("IOT_CVE_MAX_RESULTS", "5"))
    IOT_CACHE_TTL_SECONDS: int = int(
        os.getenv("IOT_CACHE_TTL_SECONDS", "60")
    )

    # ── API Prefixes ──────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"


# Module-level singleton — import this everywhere
settings = Settings()
