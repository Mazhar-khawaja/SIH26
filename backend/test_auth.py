import unittest
from fastapi.testclient import TestClient
from app.api.main import app
from app.config.settings import settings
import jwt
from app.security.auth import Role

client = TestClient(app)

class TestAuthAndSecurity(unittest.TestCase):
    def setUp(self):
        self.valid_api_key = settings.api_key
        self.invalid_api_key = "wrong_key"
        self.admin_jwt = jwt.encode({"sub": "admin1", "role": Role.ADMIN}, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        self.analyst_jwt = jwt.encode({"sub": "analyst1", "role": Role.ANALYST}, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        self.viewer_jwt = jwt.encode({"sub": "viewer1", "role": Role.VIEWER}, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def test_unauthorized_access(self):
        response = client.get("/api/v1/stats")
        self.assertEqual(response.status_code, 401)

    def test_invalid_api_key(self):
        response = client.get("/api/v1/stats", headers={"X-API-Key": self.invalid_api_key})
        self.assertEqual(response.status_code, 401)

    def test_valid_api_key_admin_access(self):
        response = client.get("/api/v1/stats", headers={"X-API-Key": self.valid_api_key})
        self.assertEqual(response.status_code, 200)

    def test_viewer_access_denied_to_post(self):
        # Viewer tries to POST an event (analyst+ required)
        log = 'CEF:0|Vendor|Product|1.0|100|Event|5|src=10.0.0.1'
        response = client.post("/api/v1/events", json={"log": log}, headers={"Authorization": f"Bearer {self.viewer_jwt}"})
        self.assertEqual(response.status_code, 403)

    def test_analyst_access_to_post(self):
        log = 'CEF:0|Vendor|Product|1.0|100|Event|5|src=10.0.0.1'
        response = client.post("/api/v1/events", json={"log": log}, headers={"Authorization": f"Bearer {self.analyst_jwt}"})
        self.assertEqual(response.status_code, 200)

    def test_viewer_access_to_get(self):
        response = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {self.viewer_jwt}"})
        self.assertEqual(response.status_code, 200)

    def test_rate_limit(self):
        # We simulate multiple requests to trigger rate limit on upload
        for _ in range(11):
            response = client.post(
                "/api/v1/upload",
                files={"file": ("test.log", b"test log\n", "text/plain")},
                headers={"X-API-Key": self.valid_api_key}
            )
            if response.status_code == 429:
                break
        self.assertEqual(response.status_code, 429)

if __name__ == "__main__":
    unittest.main()
