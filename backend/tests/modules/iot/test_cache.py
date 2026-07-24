"""Tests for the bounded Module 4 scan cache."""

import unittest

from app.modules.iot.cache import IoTScanCache


class IoTScanCacheTests(unittest.TestCase):
    def test_key_is_independent_of_port_order_and_duplicates(self) -> None:
        cache = IoTScanCache(ttl_seconds=60)

        first = cache.key("192.168.1.20", [443, 80, 443])
        second = cache.key("192.168.1.20", [80, 443])

        self.assertEqual(first, second)

    def test_zero_ttl_disables_cache(self) -> None:
        cache = IoTScanCache(ttl_seconds=0)

        self.assertIsNone(cache.get("192.168.1.20", [80]))


if __name__ == "__main__":
    unittest.main()
