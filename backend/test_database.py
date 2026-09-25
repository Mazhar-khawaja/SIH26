import unittest
from app.storage.database import Database
import os

class TestDatabase(unittest.TestCase):
    def setUp(self):
        # Use an in-memory SQLite database for testing
        self.db = Database("sqlite:///:memory:")

    def test_save_and_get_event(self):
        event = {
            "event_id": "EVT-123",
            "timestamp": "2026-08-20T14:32:10",
            "source_ip": "10.0.0.1",
            "raw_event": "raw log",
            "extracted_data": {"key": "value"}
        }
        # Provide a mock callback to simulate calculate_chain_hash
        def mock_callback(raw, prev):
            return "chain123"

        self.db.save_event(event, raw_hash="hash123", integrity_callback=mock_callback)

        saved = self.db.get_event("EVT-123")
        self.assertIsNotNone(saved)
        self.assertEqual(saved["source_ip"], "10.0.0.1")
        self.assertEqual(saved["raw_hash"], "hash123")
        self.assertEqual(saved["chain_hash"], "chain123")
        self.assertEqual(saved["extracted_data"]["key"], "value")

    def test_get_all_events_and_count(self):
        event1 = {"event_id": "EVT-1", "raw_event": "log1"}
        event2 = {"event_id": "EVT-2", "raw_event": "log2"}
        self.db.save_event(event1)
        self.db.save_event(event2)

        self.assertEqual(self.db.count_events(), 2)
        events = self.db.get_all_events()
        self.assertEqual(len(events), 2)

    def test_clear_events(self):
        event = {"event_id": "EVT-1", "raw_event": "log1"}
        self.db.save_event(event)
        self.db.clear_events()
        self.assertEqual(self.db.count_events(), 0)

if __name__ == "__main__":
    unittest.main()
