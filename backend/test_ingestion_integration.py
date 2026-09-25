import unittest
from unittest.mock import patch
from app.ingestion.ingestion_manager import IngestionManager

class TestIngestionIntegration(unittest.TestCase):
    def setUp(self):
        self.manager = IngestionManager("sqlite:///:memory:")

    @patch("app.search.search_service.SearchService.index_event")
    def test_opensearch_failure_preserves_postgres_row(self, mock_index):
        # Simulate OpenSearch exception caught by service
        mock_index.return_value = False

        log = '{"event": "login", "user": "test_user"}'

        # Ingestion should still succeed and return hashes
        result = self.manager.process_log(log)

        event_id = result["event"]["event_id"]

        # Check DB
        db_count = self.manager.count_events()
        self.assertEqual(db_count, 1)

        db_event = self.manager.get_event(event_id)
        self.assertIsNotNone(db_event)
        self.assertEqual(db_event["event_id"], event_id)
        self.assertEqual(db_event["raw_event"], log)
        self.assertEqual(db_event["chain_hash"], result["integrity"]["chain_hash"])
        self.assertEqual(db_event["raw_hash"], result["integrity"]["sha256"])

    @patch("app.search.search_service.SearchService.index_event")
    def test_successful_ingestion(self, mock_index):
        mock_index.return_value = True

        log = '{"event": "logout", "user": "admin"}'

        result = self.manager.process_log(log)
        event_id = result["event"]["event_id"]

        db_count = self.manager.count_events()
        self.assertEqual(db_count, 1)

        db_event = self.manager.get_event(event_id)
        self.assertIsNotNone(db_event)
        self.assertEqual(db_event["event_id"], event_id)
        self.assertEqual(db_event["raw_event"], log)

if __name__ == "__main__":
    unittest.main()
