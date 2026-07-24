"""
modules/asn/parsers/rdap_parser.py

Parser for the RDAP (Registration Data Access Protocol) API response.

Responsibility: Convert raw RDAP JSON → typed ``RDAPInfo`` model.
No networking. No business logic. Pure transformation.

RDAP JSON reference: https://tools.ietf.org/html/rfc7483
"""

from typing import Optional
from app.modules.asn.models import RDAPInfo
from app.core.logger import get_logger

logger = get_logger(__name__)


class RDAPParser:
    """
    Converts the raw RDAP JSON response into a structured ``RDAPInfo`` object.

    Handles:
    - CIDR prefix extraction from ``cidr0_cidrs`` (both v4 and v6).
    - Registrant organisation from nested vCard arrays.
    - Registry extraction from RDAP ``links`` (self-link domain).
    - Registration and last-changed dates from ``events`` array.
    - NOC and abuse contact emails from entity vCards.
    - Network description from ``remarks``.
    - Graceful handling of missing or malformed fields.
    """

    @staticmethod
    def parse(data: dict) -> RDAPInfo:
        """
        Parse a raw RDAP JSON response.

        Args:
            data: Raw dict returned by the RDAP API.

        Returns:
            Populated :class:`RDAPInfo` instance.
        """
        cidr_prefixes: list[str] = RDAPParser._extract_cidrs(data)
        organization: Optional[str] = RDAPParser._extract_organization(data)
        registry: Optional[str] = RDAPParser._extract_registry(data)
        status: Optional[str] = RDAPParser._extract_status(data)
        registration_date, last_changed, allocation_date = RDAPParser._extract_dates(data)
        noc_email, abuse_email = RDAPParser._extract_contact_emails(data)
        network_description: Optional[str] = RDAPParser._extract_description(data)

        # Build human-readable note about what each date field means
        date_type_note: Optional[str] = None
        if registration_date or last_changed:
            rir_label = registry or "RIR"
            date_type_note = (
                f"{rir_label}: registration_date = date this block was first registered/allocated "
                f"(RDAP eventAction='registration'); "
                f"last_changed_date = date the registration record was most recently modified "
                f"(RDAP eventAction='last changed')."
            )

        logger.debug(
            "RDAPParser: handle=%s, name=%s, registry=%s, prefixes=%d, reg_date=%s",
            data.get("handle"),
            data.get("name"),
            registry,
            len(cidr_prefixes),
            registration_date,
        )

        return RDAPInfo(
            handle=data.get("handle"),
            network_name=data.get("name"),
            network_description=network_description,
            registry=registry,
            whois_server=data.get("port43"),
            allocation_type=data.get("type"),
            status=status,
            start_address=data.get("startAddress"),
            end_address=data.get("endAddress"),
            cidr_prefixes=cidr_prefixes,
            organization=organization,
            registration_date=registration_date,
            last_changed_date=last_changed,
            allocation_date=allocation_date,
            date_type_note=date_type_note,
            noc_email=noc_email,
            abuse_email=abuse_email,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_cidrs(data: dict) -> list[str]:
        """
        Extract CIDR prefixes from the ``cidr0_cidrs`` field.

        Supports both IPv4 (``v4prefix``) and IPv6 (``v6prefix``) entries.
        """
        prefixes: list[str] = []

        for item in data.get("cidr0_cidrs", []):
            try:
                if "v4prefix" in item:
                    prefixes.append(f"{item['v4prefix']}/{item['length']}")
                elif "v6prefix" in item:
                    prefixes.append(f"{item['v6prefix']}/{item['length']}")
            except (KeyError, TypeError):
                continue

        return prefixes

    @staticmethod
    def _extract_organization(data: dict) -> Optional[str]:
        """
        Walk the ``entities`` array to find the registrant organisation name
        from its vCard representation.
        """
        for entity in data.get("entities", []):
            if "registrant" not in entity.get("roles", []):
                continue

            vcard = entity.get("vcardArray", [])

            # vCard structure: ["vcard", [[field_name, params, type, value], ...]]
            if len(vcard) < 2:
                continue

            for field in vcard[1]:
                try:
                    if field[0] == "fn":
                        return str(field[3])
                except (IndexError, TypeError):
                    continue

        return None

    @staticmethod
    def _extract_registry(data: dict) -> Optional[str]:
        """
        Infer the authoritative RIR from the self-link URL in the RDAP response.

        e.g. ``https://rdap.arin.net/registry/ip/8.8.8.0/24`` → ``"ARIN"``
        """
        registry_map = {
            "arin.net": "ARIN",
            "ripe.net": "RIPE NCC",
            "apnic.net": "APNIC",
            "lacnic.net": "LACNIC",
            "afrinic.net": "AFRINIC",
        }

        for link in data.get("links", []):
            href: str = link.get("href", "")
            for domain, name in registry_map.items():
                if domain in href:
                    return name

        return None

    @staticmethod
    def _extract_status(data: dict) -> Optional[str]:
        """Return the first status value from the ``status`` list, if present."""
        status_list = data.get("status", [])

        if isinstance(status_list, list) and status_list:
            return status_list[0]

        return None

    @staticmethod
    def _extract_dates(data: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse the RDAP ``events`` array for registration and last-changed dates.

        RDAP event types:
          - ``registration``  — The date the resource was first registered (= allocation date).
          - ``last changed``  — The date the RDAP record was most recently modified.

        For all five RIRs (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC), the
        ``registration`` event maps directly to the original allocation date.
        A separate ``allocation`` event does not exist in the RDAP spec.

        Returns:
            Tuple of (registration_date, last_changed_date, allocation_date).
            allocation_date == registration_date for all standard RDAP records.
        """
        registration_date: Optional[str] = None
        last_changed: Optional[str] = None
        allocation_date: Optional[str] = None

        for event in data.get("events", []):
            action = event.get("eventAction", "").lower()
            date_str = event.get("eventDate", "")

            if not date_str:
                continue

            # Truncate to date portion: "1992-12-01T00:00:00Z" → "1992-12-01"
            date_only = date_str.split("T")[0] if "T" in date_str else date_str

            if action == "registration" and registration_date is None:
                registration_date = date_only
                # In RDAP, registration == original allocation date
                allocation_date = date_only
            elif action in ("last changed", "last_changed") and last_changed is None:
                last_changed = date_only

        return registration_date, last_changed, allocation_date

    @staticmethod
    def _extract_contact_emails(data: dict) -> tuple[Optional[str], Optional[str]]:
        """
        Walk all entities to extract NOC and abuse email addresses.

        RDAP entities may have roles like ``["technical", "abuse", "noc"]``.

        Returns:
            Tuple of (noc_email, abuse_email).
        """
        noc_email: Optional[str] = None
        abuse_email: Optional[str] = None

        _NOC_ROLES = {"noc", "technical"}
        _ABUSE_ROLES = {"abuse"}

        for entity in data.get("entities", []):
            roles = {r.lower() for r in entity.get("roles", [])}
            vcard = entity.get("vcardArray", [])

            if len(vcard) < 2:
                continue

            email: Optional[str] = None
            for field in vcard[1]:
                try:
                    if field[0] == "email":
                        email = str(field[3])
                        break
                except (IndexError, TypeError):
                    continue

            if not email:
                continue

            if roles & _ABUSE_ROLES and abuse_email is None:
                abuse_email = email
            if roles & _NOC_ROLES and noc_email is None:
                noc_email = email

            # Also recurse into sub-entities
            for sub_entity in entity.get("entities", []):
                sub_roles = {r.lower() for r in sub_entity.get("roles", [])}
                sub_vcard = sub_entity.get("vcardArray", [])

                if len(sub_vcard) < 2:
                    continue

                sub_email: Optional[str] = None
                for field in sub_vcard[1]:
                    try:
                        if field[0] == "email":
                            sub_email = str(field[3])
                            break
                    except (IndexError, TypeError):
                        continue

                if not sub_email:
                    continue

                if sub_roles & _ABUSE_ROLES and abuse_email is None:
                    abuse_email = sub_email
                if sub_roles & _NOC_ROLES and noc_email is None:
                    noc_email = sub_email

        return noc_email, abuse_email

    @staticmethod
    def _extract_description(data: dict) -> Optional[str]:
        """
        Extract network description from RDAP ``remarks`` field.

        Remarks contain human-readable descriptions of the network.
        """
        for remark in data.get("remarks", []):
            title = remark.get("title", "").lower()
            if title in ("description", "network description", ""):
                descriptions = remark.get("description", [])
                if descriptions:
                    return " ".join(str(d) for d in descriptions[:3])

        return None
