import unittest
from fastapi.testclient import TestClient

from app.api.main import app
from app.config.settings import settings

client = TestClient(app)

class TestAPIV1(unittest.TestCase):
    def test_health_endpoint(self):
        response = client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_ready_endpoint(self):
        response = client.get("/api/v1/ready")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ready"})

    def test_stats_endpoint(self):
        response = client.get("/api/v1/stats", headers={"X-API-Key": settings.api_key})
        self.assertEqual(response.status_code, 200)
        self.assertIn("total_events", response.json())

    def test_events_lifecycle(self):
        # Ingest an event
        log = '{"timestamp":"2026-08-20T14:32:10","sourceAddress":"10.10.10.5","destinationAddress":"10.10.10.20","destinationPort":22,"action":"blocked"}'
        response = client.post("/api/v1/events", json={"log": log}, headers={"X-API-Key": settings.api_key})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("event", data)
        event_id = data["event"]["event_id"]

        # Get event
        response = client.get(f"/api/v1/events/{event_id}", headers={"X-API-Key": settings.api_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["event_id"], event_id)

        # Verify event
        response = client.get(f"/api/v1/events/{event_id}/verify", headers={"X-API-Key": settings.api_key})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["hash_verified"])

    def test_config_loading(self):
        self.assertIsNotNone(settings.app_name)
        self.assertEqual(settings.app_name, "ULPF")

    def test_analytics_api_endpoints(self):
        headers = {"X-API-Key": settings.api_key}
        res = client.get("/api/v1/analytics/alerts", headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("items", res.json())

        res = client.get("/api/v1/analytics/stats", headers=headers)
        self.assertEqual(res.status_code, 200)

        res = client.get("/api/v1/analytics/events/unknown-event", headers=headers)
        self.assertEqual(res.status_code, 404)

if __name__ == "__main__":
    unittest.main()
