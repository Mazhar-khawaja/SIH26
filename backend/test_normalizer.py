import unittest
from app.normalizer.normalizer import Normalizer
from app.models.event_schema import UniversalEvent


class TestNormalizer(unittest.TestCase):
    def setUp(self):
        self.normalizer = Normalizer()

    def test_normalize_basic(self):
        parsed = {
            "source_type": "json",
            "raw_event": '{"src": "1.1.1.1"}',
            "src": "1.1.1.1",
            "dst": "2.2.2.2",
            "sport": "1234",
            "dport": "80",
            "act": "ALLOW",
            "sev": "INFO",
            "parser": "json",
            "parse_status": "success",
        }

        event = self.normalizer.normalize(parsed)
        self.assertIsInstance(event, UniversalEvent)
        self.assertEqual(event.source_ip, "1.1.1.1")
        self.assertEqual(event.destination_ip, "2.2.2.2")
        self.assertEqual(event.source_port, 1234)
        self.assertEqual(event.destination_port, 80)
        self.assertEqual(event.action, "ALLOW")
        self.assertEqual(event.severity, "INFO")
        self.assertEqual(event.raw_event, '{"src": "1.1.1.1"}')


if __name__ == "__main__":
    unittest.main()
