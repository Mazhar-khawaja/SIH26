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

    def test_cloudtrail_useridentity_username(self):
        parsed = {"userIdentity": {"userName": "admin"}}
        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.user, "admin")

    def test_cloudtrail_useridentity_principalid(self):
        parsed = {"userIdentity": {"principalId": "ABC123"}}
        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.user, "ABC123")

    def test_cloudtrail_useridentity_arn(self):
        parsed = {"userIdentity": {"arn": "arn:aws:iam::123:user/admin"}}
        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.user, "arn:aws:iam::123:user/admin")

    def test_cloudtrail_useridentity_string(self):
        parsed = {"userIdentity": "admin"}
        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.user, "admin")

    def test_cloudtrail_useridentity_missing(self):
        parsed = {"userIdentity": {}}
        event = self.normalizer.normalize(parsed)
        self.assertIsNone(event.user)

if __name__ == "__main__":
    unittest.main()
