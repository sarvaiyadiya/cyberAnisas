"""Static safety guidance for an authorized MAC-authentication lab."""

from app.modules.wireless.models import MACAuthenticationLabGuide


def build_mac_authentication_lab_guide() -> MACAuthenticationLabGuide:
    """Return documentation only; no command or MAC-changing capability."""
    return MACAuthenticationLabGuide(
        automated_mac_change=False,
        purpose=(
            "Demonstrate in an isolated authorized lab that a MAC address is "
            "an observable identifier and is not a cryptographic identity."
        ),
        safety_checklist=(
            "Use only equipment and devices owned by or explicitly authorized for the lab.",
            "Isolate the lab from production, guest, and neighboring wireless networks.",
            "Record the original adapter configuration before the demonstration.",
            "Do not capture credentials, user traffic, or unrelated wireless frames.",
            "Stop immediately if the test affects any device outside the approved scope.",
        ),
        demonstration_steps=(
            "Configure a lab access point to allow a designated test-device MAC.",
            "Record the allow-list decision and connection result for that test device.",
            "Using vendor documentation, discuss that software-defined MAC identifiers can change.",
            "Explain that another lab-controlled device presenting the allowed identifier could bypass identifier-only filtering.",
            "Restore the lab configuration and verify that WPA2/WPA3 or 802.1X remains the actual authentication control.",
        ),
        conclusion=(
            "MAC filtering may support inventory policy but must not replace "
            "cryptographic wireless authentication."
        ),
    )
