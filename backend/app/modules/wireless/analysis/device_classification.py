"""Conservative access-point device-class correlation."""


def classify_access_point(
    *,
    ssid: str,
    vendor: str,
) -> tuple[str, int, tuple[str, ...]]:
    """Classify only to the specificity supported by AP observations."""
    normalized = f"{ssid} {vendor}".lower()
    if any(token in normalized for token in ("mesh", "deco", "orbi", "velop")):
        return "Mesh", 75, ("Mesh product or SSID indicator observed",)
    if any(
        token in normalized
        for token in ("hotspot", "mobile hotspot", "mifi", "tether")
    ):
        return "Hotspot", 70, ("Hotspot product or SSID indicator observed",)
    return "Access Point", 60, ("The BSSID was observed advertising Wi-Fi",)


def classify_client_device(
    *,
    hostname: str | None,
    vendor: str,
) -> tuple[str, int]:
    """Return a conservative class from explicit hostname/vendor indicators."""
    normalized = f"{hostname or ''} {vendor}".lower()
    signatures = (
        ("Printer", ("printer", "laserjet", "epson", "brother")),
        ("Camera", ("camera", "hikvision", "dahua", "vivotek")),
        ("Smartphone", ("iphone", "android", "pixel", "phone")),
        ("Laptop", ("laptop", "notebook", "macbook")),
        ("Desktop", ("desktop", "workstation")),
        ("IoT", ("iot", "sensor", "thermostat", "smart plug")),
    )
    for device_type, tokens in signatures:
        if any(token in normalized for token in tokens):
            return device_type, 70
    return "Unknown", 0
