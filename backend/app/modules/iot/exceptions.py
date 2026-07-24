"""Domain exceptions for the independent IoT fingerprinting module."""


class IoTError(Exception):
    """Base class for expected IoT fingerprinting failures."""


class InvalidTargetError(IoTError, ValueError):
    """Raised when a scan target is not a valid IPv4 address."""


class PortScanConfigurationError(IoTError, ValueError):
    """Raised when port scanner configuration is unsafe or invalid."""


class PortDiscoveryError(IoTError):
    """Raised when port discovery cannot produce a trustworthy result."""


class BannerConfigurationError(IoTError, ValueError):
    """Raised when banner collection limits are invalid."""


class DeviceHTTPConfigurationError(IoTError, ValueError):
    """Raised when device HTTP collection limits are invalid."""


class TLSConfigurationError(IoTError, ValueError):
    """Raised when TLS probing limits are invalid."""


class RTSPConfigurationError(IoTError, ValueError):
    """Raised when RTSP probing limits are invalid."""


class VendorConfigurationError(IoTError, ValueError):
    """Raised when vendor-correlation thresholds are invalid."""
