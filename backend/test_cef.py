import unittest
from app.parsers.cef_parser import CEFParser
from app.normalizer.normalizer import Normalizer


class TestCEFParser(unittest.TestCase):
    def setUp(self):
        self.parser = CEFParser()
        self.normalizer = Normalizer()

    def test_name(self):
        self.assertEqual(self.parser.name, "cef")

    def test_can_parse_valid(self):
        log = "CEF:0|Security|ThreatManager|1.0|100|Malware Detected|5|src=10.0.0.1 dst=192.168.1.1 spt=1234 dpt=80 act=blocked"
        self.assertTrue(self.parser.can_parse(log))

    def test_can_parse_invalid(self):
        self.assertFalse(self.parser.can_parse("Not CEF log"))
        self.assertFalse(self.parser.can_parse('{"json": "log"}'))

    def test_parse_valid_cef(self):
        log = "CEF:0|Security|ThreatManager|1.0|100|Malware Detected|5|src=10.0.0.1 dst=192.168.1.1 spt=1234 dpt=80 act=blocked"
        result = self.parser.parse(log)

        self.assertEqual(result["source_type"], "cef")
        self.assertEqual(result["cef_version"], "0")
        self.assertEqual(result["device_vendor"], "Security")
        self.assertEqual(result["device_product"], "ThreatManager")
        self.assertEqual(result["device_version"], "1.0")
        self.assertEqual(result["signature_id"], "100")
        self.assertEqual(result["event_name"], "Malware Detected")
        self.assertEqual(result["severity"], "5")
        self.assertEqual(result["src"], "10.0.0.1")
        self.assertEqual(result["dst"], "192.168.1.1")
        self.assertEqual(result["spt"], "1234")
        self.assertEqual(result["dpt"], "80")
        self.assertEqual(result["act"], "blocked")
        self.assertEqual(result["raw_event"], log)

    def test_normalization_integration(self):
        log = "CEF:0|Vendor|Product|1.0|200|Access Denied|8|src=192.168.1.5 dst=10.0.0.2 dpt=22 act=deny"
        parsed = self.parser.parse(log)
        parsed["parser"] = self.parser.name
        parsed["parse_status"] = "success"

        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.source_ip, "192.168.1.5")
        self.assertEqual(event.destination_ip, "10.0.0.2")
        self.assertEqual(event.destination_port, 22)
        self.assertEqual(event.action, "deny")
        self.assertEqual(event.source, "Product")
        self.assertEqual(event.raw_event, log)


if __name__ == "__main__":
    unittest.main()
