import unittest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.api.main import app
from app.config.settings import settings
from app.kafka.producer import ULPFProducer
from app.kafka.worker import ULPFWorker

client = TestClient(app)

class TestKafkaIntegration(unittest.TestCase):
    def setUp(self):
        self.api_key = settings.api_key

    @patch('app.api.main.get_producer')
    def test_bulk_ingestion_api(self, mock_get_producer):
        mock_producer = MagicMock()
        mock_producer.connected = True
        mock_producer.send_bulk.return_value = 2
        mock_get_producer.return_value = mock_producer

        payload = {
            "logs": ["log 1", "log 2"]
        }

        response = client.post("/api/v1/events/bulk", json=payload, headers={"X-API-Key": self.api_key})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "accepted")
        self.assertEqual(data["accepted_count"], 2)

    @patch('app.kafka.producer.KafkaProducer')
    def test_producer_send_bulk(self, mock_kafka_producer):
        producer = ULPFProducer(bootstrap_servers="dummy:9092")
        self.assertTrue(producer.connected)

        accepted = producer.send_bulk(["log1", "log2", ""], "req-1")
        self.assertEqual(accepted, 2)
        # Verify producer.send was called twice for valid logs
        self.assertEqual(mock_kafka_producer.return_value.send.call_count, 2)

    @patch('app.kafka.worker.KafkaConsumer')
    @patch('app.kafka.worker.get_producer')
    def test_worker_processing_retry_and_dlq(self, mock_get_producer, mock_kafka_consumer):
        # We simulate a processor function that fails
        def failing_processor(log):
            raise ValueError("Simulated processing error")

        mock_producer = MagicMock()
        mock_get_producer.return_value = mock_producer

        worker = ULPFWorker(failing_processor)
        self.assertTrue(worker.connected)

        # Test max retries
        payload = {"log": "test log", "attempts": settings.kafka_max_retries}
        worker.process_message(payload)

        # Since it fails and attempts >= max_retries, it should go to DLQ
        mock_producer.send_dlq.assert_called_once()
        self.assertEqual(mock_producer.producer.send.call_count, 0)

        # Reset and test retry (pushing back to topic)
        mock_producer.send_dlq.reset_mock()
        mock_producer.producer.send.reset_mock()

        payload_retry = {"log": "test log", "attempts": 0}
        # Avoid real sleep in tests
        with patch('time.sleep', return_value=None):
            worker.process_message(payload_retry)

        # Should be pushed back to main topic, not DLQ
        mock_producer.send_dlq.assert_not_called()
        mock_producer.producer.send.assert_called_once()

if __name__ == "__main__":
    unittest.main()
