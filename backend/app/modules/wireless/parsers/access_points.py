"""Pure parsers for sanitized Windows and Linux access-point scans."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from app.modules.wireless.models import AccessPointObservation
from app.modules.wireless.utils import normalize_mac

_SSID_LINE = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
_BSSID_LINE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)


def parse_windows_access_points(
    output: str,
    interface: str | None = None,
) -> tuple[AccessPointObservation, ...]:
    """Parse ``netsh wlan show networks mode=bssid`` output."""
    ssid = ""
    authentication = "Unknown"
    encryption = "Unknown"
    current: dict[str, object] | None = None
    observations: list[AccessPointObservation] = []
    observed_at = datetime.now(timezone.utc)

    def finish() -> None:
        nonlocal current
        if not current:
            return
        bssid = normalize_mac(str(current.get("bssid", "")))
        if bssid:
            channel = _integer(current.get("channel"))
            frequency = _channel_frequency(channel)
            observations.append(
                AccessPointObservation(
                    ssid=str(current.get("ssid", "")),
                    bssid=bssid,
                    channel=channel,
                    frequency_mhz=frequency,
                    band=_frequency_band(frequency),
                    signal_percent=_percentage(current.get("signal")),
                    authentication=str(
                        current.get("authentication", "Unknown")
                    ),
                    encryption=str(current.get("encryption", "Unknown")),
                    pmf_support=str(current.get("pmf", "Unknown")),
                    hidden_ssid=not bool(str(current.get("ssid", "")).strip()),
                    wps_enabled=_boolean(current.get("wps")),
                    beacon_interval_ms=_integer(
                        current.get("beacon interval")
                    ),
                    first_seen=observed_at,
                    last_seen=observed_at,
                    interface=interface,
                    oui=bssid[:8],
                )
            )
        current = None

    for line in output.splitlines():
        ssid_match = _SSID_LINE.match(line)
        if ssid_match:
            finish()
            ssid = ssid_match.group(1).strip()
            authentication = "Unknown"
            encryption = "Unknown"
            continue
        bssid_match = _BSSID_LINE.match(line)
        if bssid_match:
            finish()
            current = {
                "ssid": ssid,
                "bssid": bssid_match.group(1).strip(),
                "authentication": authentication,
                "encryption": encryption,
            }
            continue
        key, value = _key_value(line)
        if key == "authentication":
            authentication = value or "Unknown"
            if current:
                current["authentication"] = authentication
        elif key == "encryption":
            encryption = value or "Unknown"
            if current:
                current["encryption"] = encryption
        elif current and key in {"signal", "channel", "beacon interval"}:
            current[key] = value
        elif current and key.startswith("wps"):
            current["wps"] = value
        elif current and key in {
            "protected management frames",
            "management frame protection",
        }:
            current["pmf"] = value or "Unknown"

    finish()
    return _deduplicate(observations)


def parse_linux_access_points(
    output: str,
    interface: str | None = None,
) -> tuple[AccessPointObservation, ...]:
    """Parse terse nmcli SSID/BSSID/channel/frequency/signal/security rows."""
    observations: list[AccessPointObservation] = []
    observed_at = datetime.now(timezone.utc)
    for line in output.splitlines():
        fields = _split_escaped(line)
        if len(fields) < 6:
            continue
        ssid, raw_bssid, channel, frequency, signal, security = fields[:6]
        bssid = normalize_mac(raw_bssid)
        if not bssid:
            continue
        authentication, encryption = _linux_security(security)
        parsed_frequency = _integer(frequency)
        observations.append(
            AccessPointObservation(
                ssid=ssid,
                bssid=bssid,
                channel=_integer(channel),
                frequency_mhz=parsed_frequency,
                band=_frequency_band(parsed_frequency),
                signal_percent=_percentage(signal),
                authentication=authentication,
                encryption=encryption,
                hidden_ssid=not bool(ssid.strip()),
                first_seen=observed_at,
                last_seen=observed_at,
                interface=interface,
                oui=bssid[:8],
            )
        )
    return _deduplicate(observations)


def _key_value(line: str) -> tuple[str, str]:
    if ":" not in line:
        return "", ""
    key, value = line.split(":", 1)
    return key.strip().lower(), value.strip()


def _split_escaped(line: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def _integer(value: object) -> int | None:
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else None


def _percentage(value: object) -> int | None:
    parsed = _integer(value)
    return min(parsed, 100) if parsed is not None else None


def _boolean(value: object) -> bool | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"yes", "enabled", "true", "configured", "supported"}:
        return True
    if normalized in {"no", "disabled", "false", "not configured"}:
        return False
    return None


def _channel_frequency(channel: int | None) -> int | None:
    if channel is None:
        return None
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if 32 <= channel <= 177:
        return 5000 + channel * 5
    return None


def _frequency_band(frequency_mhz: int | None) -> str:
    if frequency_mhz is None:
        return "Unknown"
    if 2400 <= frequency_mhz < 2500:
        return "2.4GHz"
    if 4900 <= frequency_mhz < 5925:
        return "5GHz"
    if 5925 <= frequency_mhz <= 7125:
        return "6GHz"
    return "Unknown"


def _linux_security(security: str) -> tuple[str, str]:
    normalized = security.strip()
    if not normalized or normalized == "--":
        return "Open", "None"
    upper = normalized.upper()
    if "WPA3" in upper or "SAE" in upper:
        return "WPA3", normalized
    if "WPA2" in upper:
        return "WPA2", normalized
    if "WPA1" in upper or upper == "WPA":
        return "WPA", normalized
    if "WEP" in upper:
        return "Open/System or Shared Key", "WEP"
    return normalized, normalized


def _deduplicate(
    observations: list[AccessPointObservation],
) -> tuple[AccessPointObservation, ...]:
    counts: dict[str, int] = {}
    unique: dict[str, AccessPointObservation] = {}
    for item in observations:
        counts[item.bssid] = counts.get(item.bssid, 0) + 1
        unique[item.bssid] = item
    unique = {
        bssid: item.model_copy(
            update={
                "duplicate_mac": counts[bssid] > 1,
                "suspicious_mac": counts[bssid] > 1,
            }
        )
        for bssid, item in unique.items()
    }
    return tuple(unique[bssid] for bssid in sorted(unique))
