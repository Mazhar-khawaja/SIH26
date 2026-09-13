import unittest
from app.parsers.json_parser import JSONParser
from app.normalizer.normalizer import Normalizer


class TestJSONParser(unittest.TestCase):
    def setUp(self):
        self.parser = JSONParser()
        self.normalizer = Normalizer()

    def test_name(self):
        self.assertEqual(self.parser.name, "json")

    def test_can_parse_valid(self):
        log = '{"event": "login", "source_ip": "192.168.1.1", "action": "allow"}'
        self.assertTrue(self.parser.can_parse(log))

    def test_can_parse_invalid(self):
        self.assertFalse(self.parser.can_parse("not json"))
        self.assertFalse(self.parser.can_parse("[1, 2, 3]"))
        self.assertFalse(self.parser.can_parse(""))

    def test_parse_valid_json(self):
        log = '{"source_ip": "192.168.1.10", "destination_ip": "10.0.0.1", "source_port": 12345, "action": "ALLOW"}'
        result = self.parser.parse(log)

        self.assertEqual(result["source_type"], "json")
        self.assertEqual(result["raw_event"], log)
        self.assertEqual(result["source_ip"], "192.168.1.10")
        self.assertEqual(result["destination_ip"], "10.0.0.1")
        self.assertEqual(result["source_port"], 12345)
        self.assertEqual(result["action"], "ALLOW")

    def test_normalization_integration(self):
        log = '{"src": "172.16.0.1", "dst": "10.0.0.1", "act": "ALLOW", "sev": "HIGH"}'
        parsed = self.parser.parse(log)
        parsed["parser"] = self.parser.name
        parsed["parse_status"] = "success"

        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.source_ip, "172.16.0.1")
        self.assertEqual(event.destination_ip, "10.0.0.1")
        self.assertEqual(event.action, "ALLOW")
        self.assertEqual(event.severity, "HIGH")
        self.assertEqual(event.raw_event, log)


if __name__ == "__main__":
    unittest.main()
