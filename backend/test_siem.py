import unittest
from unittest.mock import patch, MagicMock
from app.integrations.siem.service import SIEMIntegrationService
from app.integrations.siem.rest_connector import RESTSIEMConnector
from app.config.settings import settings
import requests

class TestSIEMIntegration(unittest.TestCase):
    def setUp(self):
        settings.siem_enabled = True
        settings.siem_url = "http://mock-siem:9999/events"
        settings.siem_api_key = "secret_key"
        settings.siem_token = "secret_token"
        settings.siem_max_retries = 2
        settings.siem_retry_backoff_seconds = 0 # no wait for tests

        self.service = SIEMIntegrationService()
        self.connector = self.service.connector

    def test_payload_construction(self):
        event = {
            "event_id": "EV-123",
            "timestamp": "2023-01-01T00:00:00Z",
            "source_ip": "10.0.0.1",
            "raw_event": "raw log here",
            "internal_secret": "should not be included"
        }
        analytics = {
            "anomaly": True,
            "anomaly_score": 95,
            "rule_matches": [{"rule": "X"}]
        }

        payload = self.service._construct_payload(event, analytics)

        self.assertEqual(payload["event_id"], "EV-123")
        self.assertEqual(payload["source_ip"], "10.0.0.1")
        self.assertEqual(payload["anomaly"], True)
        self.assertEqual(payload["anomaly_score"], 95)
        self.assertNotIn("internal_secret", payload)

    @patch('app.integrations.siem.rest_connector.requests.post')
    def test_successful_request(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        result = self.connector.send_event({"data": "test"})
        self.assertTrue(result)

        # Check authentication headers are sent
        called_kwargs = mock_post.call_args.kwargs
        self.assertEqual(called_kwargs["headers"]["X-API-Key"], "secret_key")
        self.assertEqual(called_kwargs["headers"]["Authorization"], "Bearer secret_token")
        self.assertEqual(called_kwargs["headers"]["Content-Type"], "application/json")

    @patch('app.integrations.siem.rest_connector.requests.post')
    def test_http_429_retry(self, mock_post):
        # 2 failures (429), 1 success (200)
        resp_429 = MagicMock()
        resp_429.status_code = 429

        resp_200 = MagicMock()
        resp_200.status_code = 200

        mock_post.side_effect = [resp_429, resp_429, resp_200]

        result = self.connector.send_event({"test": 1})
        self.assertTrue(result)
        self.assertEqual(mock_post.call_count, 3)

    @patch('app.integrations.siem.rest_connector.requests.post')
    def test_http_500_retry(self, mock_post):
        resp_500 = MagicMock()
        resp_500.status_code = 500
        mock_post.return_value = resp_500

        result = self.connector.send_event({"test": 1})
        self.assertFalse(result)
        self.assertEqual(mock_post.call_count, 3) # initial + 2 retries

    @patch('app.integrations.siem.rest_connector.requests.post')
    def test_http_401_no_retry(self, mock_post):
        resp_401 = MagicMock()
        resp_401.status_code = 401
        mock_post.return_value = resp_401

        result = self.connector.send_event({"test": 1})
        self.assertFalse(result)
        self.assertEqual(mock_post.call_count, 1) # No retry on permanent auth failure

    def test_disabled_siem(self):
        settings.siem_enabled = False
        result = self.service.forward_event({"test": 1})
        self.assertFalse(result)

        status = self.service.status()
        self.assertFalse(status["enabled"])

if __name__ == '__main__':
    unittest.main()
