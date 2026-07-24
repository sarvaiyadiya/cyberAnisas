"""
modules/asn/clients/cymru.py

Client for the Team Cymru IP-to-ASN whois service.

Team Cymru provides a free public whois-based service that maps any IP address
to its origin ASN, prefix, country, registry, allocation date, and AS name.
It requires no API key and has no rate limit.

Protocol: Raw TCP socket to whois.cymru.com:43 with newline-terminated queries.
Ref:      https://www.team-cymru.com/ip-asn-mapping.html

This client is used as a FALLBACK when IPInfo does not return an ASN,
ensuring the intelligence pipeline always has a best-effort ASN value.
"""

import socket
from typing import Optional

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)

_CYMRU_HOST = "whois.cymru.com"
_CYMRU_PORT = 43
_QUERY_TEMPLATE = "begin\nverbose\n{ip}\nend\n"


class CymruClient:
    """
    Team Cymru IP-to-ASN lookup client.

    Uses the bulk whois protocol (port 43) for zero-dependency, high-reliability
    ASN resolution that doesn't depend on HTTP availability.
    """

    def __init__(self, timeout: int | None = None) -> None:
        self._timeout = timeout or settings.REQUEST_TIMEOUT

    def lookup(self, ip: str) -> Optional[dict]:
        """
        Resolve ASN information for an IP address via Team Cymru whois.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Dict with keys: asn, prefix, country, registry, allocated, name.
            Returns ``None`` if the query fails or returns no result.
        """
        logger.info("CymruClient: looking up %s", ip)

        try:
            raw = self._whois_query(ip)
            if raw:
                return self._parse(raw)
            logger.warning("CymruClient: empty response for %s", ip)
            return None

        except socket.timeout:
            logger.warning("CymruClient: timeout for %s (host=%s)", ip, _CYMRU_HOST)
            return None
        except OSError as exc:
            logger.warning("CymruClient: socket error for %s — %s", ip, exc)
            return None
        except Exception as exc:  # noqa: BLE001
            logger.error("CymruClient: unexpected error for %s — %s", ip, exc)
            return None

    # ── Private helpers ───────────────────────────────────────────────────────

    def _whois_query(self, ip: str) -> Optional[str]:
        """
        Open a TCP connection to whois.cymru.com and send the bulk query.

        Returns:
            Raw response string, or ``None`` on failure.
        """
        query = _QUERY_TEMPLATE.format(ip=ip).encode("utf-8")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect((_CYMRU_HOST, _CYMRU_PORT))
            sock.sendall(query)

            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)

        return b"".join(chunks).decode("utf-8", errors="replace")

    @staticmethod
    def _parse(response: str) -> Optional[dict]:
        """
        Parse a Team Cymru verbose bulk-mode response.

        Expected format per data line:
            ``{ASN} | {IP} | {Prefix} | {CC} | {Registry} | {Allocated} | {AS Name}``

        Args:
            response: Raw whois response string.

        Returns:
            Parsed dict, or ``None`` if no valid data line found.
        """
        for line in response.splitlines():
            line = line.strip()

            # Skip headers, blank lines, and status messages
            if not line or "|" not in line:
                continue
            if "Bulk mode" in line or "AS Name" in line:
                continue

            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 7:
                continue

            asn_raw = parts[0].strip()
            if not asn_raw.isdigit():
                continue

            return {
                "asn": f"AS{asn_raw}",
                "prefix": parts[2].strip() or None,
                "country": parts[3].strip() or None,
                "registry": parts[4].strip().upper() or None,
                "allocated": parts[5].strip() or None,
                "name": parts[6].strip() or None,
            }

        return None
