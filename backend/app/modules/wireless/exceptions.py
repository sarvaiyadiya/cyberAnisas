"""Domain exceptions for Module 5."""


class WirelessIntelligenceError(Exception):
    """Base exception for expected wireless intelligence failures."""


class UnsupportedPlatformError(WirelessIntelligenceError):
    """Raised when no safe collector exists for the operating system."""


class WirelessCommandError(WirelessIntelligenceError):
    """Raised when an operating-system wireless command cannot execute."""


class BehaviorEngineUnavailable(WirelessIntelligenceError):
    """Raised when the configured behavior-analysis backend is unavailable."""
