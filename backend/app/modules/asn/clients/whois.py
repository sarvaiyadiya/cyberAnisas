"""Safe, bounded direct WHOIS client for authoritative RIR servers."""

from __future__ import annotations

import socket
from collections.abc import Callable

from app.modules.asn.models import WHOISIntelligence
from app.modules.asn.parsers.whois_parser import parse_whois_response

MAX_WHOIS_BYTES = 65_536
AUTHORITATIVE_SERVERS = frozenset(
    {
        "whois.arin.net",
        "whois.ripe.net",
        "whois.apnic.net",
        "whois.lacnic.net",
        "whois.afrinic.net",
    }
)
WHOISConnector = Callable[[str, str, float, int], bytes]


def _query_server(
    server: str,
    query: str,
    timeout: float,
    max_bytes: int,
) -> bytes:
    chunks = []
    received = 0
    with socket.create_connection((server, 43), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(f"{query}\r\n".encode("ascii", errors="strict"))
        while received < max_bytes:
            chunk = connection.recv(min(4096, max_bytes - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
    return b"".join(chunks)


class WHOISClient:
    """Query one trusted RIR server without following arbitrary referrals."""

    def __init__(
        self,
        connector: WHOISConnector | None = None,
        timeout_seconds: float = 5.0,
        max_bytes: int = MAX_WHOIS_BYTES,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 10:
            raise ValueError("WHOIS timeout must be between 0.1 and 10 seconds")
        if not 1024 <= max_bytes <= MAX_WHOIS_BYTES:
            raise ValueError("WHOIS response limit must be 1024-65536 bytes")
        self._connector = connector or _query_server
        self._timeout = timeout_seconds
        self._max_bytes = max_bytes

    def lookup(self, server: str | None, query: str) -> WHOISIntelligence:
        normalized_server = (server or "").strip().lower().rstrip(".")
        if normalized_server not in AUTHORITATIVE_SERVERS:
            return WHOISIntelligence(
                status="unsupported_server",
                server=normalized_server or None,
                error="WHOIS server is not in the authoritative RIR allowlist",
            )
        try:
            payload = self._connector(
                normalized_server,
                query,
                self._timeout,
                self._max_bytes,
            )
        except (TimeoutError, socket.timeout):
            return WHOISIntelligence(
                status="timeout",
                server=normalized_server,
                error="WHOIS query timed out",
            )
        except (OSError, UnicodeError) as exc:
            return WHOISIntelligence(
                status="unavailable",
                server=normalized_server,
                error=type(exc).__name__,
            )
        bounded = payload[: self._max_bytes]
        text = bounded.decode("utf-8", errors="replace")
        return parse_whois_response(normalized_server, text)
