import unittest
from app.parsers.leef_parser import LEEFParser
from app.normalizer.normalizer import Normalizer


class TestLEEFParser(unittest.TestCase):
    def setUp(self):
        self.parser = LEEFParser()
        self.normalizer = Normalizer()

    def test_name(self):
        self.assertEqual(self.parser.name, "leef")

    def test_can_parse_valid(self):
        log = "LEEF:2.0|Vendor|Product|1.0|4624|src=192.168.1.10\tdst=10.0.0.1"
        self.assertTrue(self.parser.can_parse(log))

        log_v1 = "LEEF:1.0|CustomVendor|Firewall|2.5|101|src=10.1.1.1"
        self.assertTrue(self.parser.can_parse(log_v1))

    def test_can_parse_invalid(self):
        self.assertFalse(self.parser.can_parse("CEF:0|Vendor|Product|1.0|100|Event|5|src=1.1.1.1"))
        self.assertFalse(self.parser.can_parse("Not a LEEF log"))
        self.assertFalse(self.parser.can_parse(""))

    def test_parse_valid_leef_fields(self):
        log = "LEEF:2.0|PaloAlto|PAN-OS|10.0|1001|src=192.168.1.100\tdst=10.0.0.5\tsport=54321\tdport=443\tproto=TCP\tact=ALLOW\tsev=Informational"

        result = self.parser.parse(log)

        self.assertEqual(result["source_type"], "leef")
        self.assertEqual(result["raw_event"], log)
        self.assertEqual(result["leef_version"], "2.0")
        self.assertEqual(result["vendor"], "PaloAlto")
        self.assertEqual(result["device_vendor"], "PaloAlto")
        self.assertEqual(result["product"], "PAN-OS")
        self.assertEqual(result["device_product"], "PAN-OS")
        self.assertEqual(result["version"], "10.0")
        self.assertEqual(result["event_id"], "1001")

        # Extensions
        self.assertEqual(result["src"], "192.168.1.100")
        self.assertEqual(result["dst"], "10.0.0.5")
        self.assertEqual(result["sport"], "54321")
        self.assertEqual(result["dport"], "443")
        self.assertEqual(result["proto"], "TCP")
        self.assertEqual(result["act"], "ALLOW")
        self.assertEqual(result["sev"], "Informational")

    def test_tab_separated_fields(self):
        log = "LEEF:1.0|Vendor|App|1.0|99|usrName=admin\tdevTime=2026-09-13T10:00:00Z"
        result = self.parser.parse(log)

        self.assertEqual(result["usrName"], "admin")
        self.assertEqual(result["devTime"], "2026-09-13T10:00:00Z")

    def test_raw_preservation(self):
        log = "LEEF:2.0|V|P|1|1|key=val"
        result = self.parser.parse(log)
        self.assertEqual(result["raw_event"], log)

    def test_malformed_leef_raises_value_error(self):
        log = "LEEF:invalid_header_with_too_few_pipes"
        with self.assertRaises(ValueError):
            self.parser.parse(log)

    def test_normalization_integration(self):
        log = "LEEF:2.0|CheckPoint|FW|1.0|LoginSuccess|src=192.168.1.20\tdst=10.0.0.100\tsport=1234\tdport=22\tact=ALLOW"
        parsed = self.parser.parse(log)
        parsed["parser"] = self.parser.name
        parsed["parse_status"] = "success"

        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.source_ip, "192.168.1.20")
        self.assertEqual(event.destination_ip, "10.0.0.100")
        self.assertEqual(event.source_port, 1234)
        self.assertEqual(event.destination_port, 22)
        self.assertEqual(event.action, "ALLOW")
        self.assertEqual(event.source, "FW")
        self.assertEqual(event.raw_event, log)


if __name__ == "__main__":
    unittest.main()
