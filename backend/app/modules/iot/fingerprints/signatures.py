"""Reusable deterministic signature data for IoT fingerprint correlation."""

# These are evidence hints, not final classifications. The vendor engine will
# later combine them with HTTP, RTSP, ONVIF, model, and port observations.
BANNER_VENDOR_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("hikvision", "Hikvision"),
    ("hikvision-webs", "Hikvision"),
    ("dahua", "Dahua"),
    ("dhip", "Dahua"),
    ("axis communications", "Axis"),
    ("axis", "Axis"),
    ("hanwha", "Hanwha"),
    ("wisenet", "Hanwha"),
    ("uniview", "Uniview"),
    ("unv", "Uniview"),
    ("bosch security", "Bosch"),
    ("bosch", "Bosch"),
    ("vivotek", "Vivotek"),
    ("reolink", "Reolink"),
    ("ubiquiti", "Ubiquiti"),
    ("unifi", "Ubiquiti"),
    ("synology", "Synology"),
    ("qnap", "QNAP"),
    ("mikrotik", "MikroTik"),
    ("routeros", "MikroTik"),
    ("tp-link", "TP-Link"),
    ("tplink", "TP-Link"),
    ("netgear", "Netgear"),
    ("canon", "Canon"),
    ("hewlett-packard", "HP"),
    ("hp laserjet", "HP"),
    ("epson", "Epson"),
)

VENDOR_PORT_HINTS: dict[int, tuple[str, int]] = {
    37777: ("Dahua", 35),
    8000: ("Hikvision", 10),
}

VENDOR_PATH_HINTS: tuple[tuple[str, str, int], ...] = (
    ("/ISAPI/", "Hikvision", 35),
    ("/doc/page/login.asp", "Hikvision", 25),
)


HTTP_TECHNOLOGY_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("nginx", "nginx"),
    ("apache", "Apache HTTP Server"),
    ("microsoft-iis", "Microsoft IIS"),
    ("caddy", "Caddy"),
    ("express", "Express"),
    ("node.js", "Node.js"),
    ("nodejs", "Node.js"),
    ("php", "PHP"),
    ("asp.net", "ASP.NET"),
    ("wordpress", "WordPress"),
    ("react", "React"),
    ("angular", "Angular"),
    ("vue.js", "Vue.js"),
)


SERVICE_PRODUCT_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("openssh", "SSH", "OpenSSH"),
    ("dropbear", "SSH", "Dropbear SSH"),
    ("vsftpd", "FTP", "vsFTPd"),
    ("proftpd", "FTP", "ProFTPD"),
    ("filezilla server", "FTP", "FileZilla Server"),
    ("postfix", "SMTP", "Postfix"),
    ("exim", "SMTP", "Exim"),
    ("nginx", "HTTP", "nginx"),
    ("apache", "HTTP", "Apache HTTP Server"),
    ("microsoft-iis", "HTTP", "Microsoft IIS"),
    ("caddy", "HTTP", "Caddy"),
)


def match_vendor_signatures(text: str) -> tuple[str, ...]:
    """Return vendors explicitly supported by normalized textual evidence."""
    normalized = text.lower()
    return tuple(
        sorted(
            {
                vendor
                for signature, vendor in BANNER_VENDOR_SIGNATURES
                if signature in normalized
            }
        )
    )
