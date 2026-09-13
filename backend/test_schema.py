import unittest
from app.models.event_schema import UniversalEvent


class TestEventSchema(unittest.TestCase):
    def test_schema_instantiation(self):
        event = UniversalEvent(
            event_id="ULPF-TEST-001",
            raw_event="test log event",
            source_type="syslog",
            source_ip="192.168.1.1",
        )
        self.assertEqual(event.event_id, "ULPF-TEST-001")
        self.assertEqual(event.raw_event, "test log event")
        self.assertEqual(event.source_type, "syslog")
        self.assertEqual(event.source_ip, "192.168.1.1")


if __name__ == "__main__":
    unittest.main()
