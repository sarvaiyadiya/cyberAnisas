"""OpenAPI registration tests for Module 4."""

import unittest

from app.main import app
from app.modules.iot.models import IoTPortDiscoveryRequest


class Module4RegistrationTests(unittest.TestCase):
    def test_module_4_port_route_is_registered(self) -> None:
        schema = app.openapi()
        path = "/api/v1/iot/ports/discover"

        self.assertIn(path, schema["paths"])
        operation = schema["paths"][path]["post"]
        self.assertIn(
            "Module 4 — Surveillance & IoT Device Fingerprinting",
            operation["tags"],
        )

    def test_accepts_module_1_response_as_input(self) -> None:
        request = IoTPortDiscoveryRequest.model_validate(
            {
                "success": True,
                "message": "ASN lookup completed",
                "data": {
                    "ip": "8.8.8.8",
                    "asn": "AS15169",
                    "organization": "Google LLC",
                },
            }
        )

        self.assertEqual(request.ip, "8.8.8.8")
        self.assertIsNone(request.ports)

    def test_direct_input_remains_supported(self) -> None:
        request = IoTPortDiscoveryRequest.model_validate(
            {"ip": "192.168.1.20", "ports": [80, 554]}
        )
        self.assertEqual(request.ip, "192.168.1.20")
        self.assertEqual(request.ports, [80, 554])


if __name__ == "__main__":
    unittest.main()
