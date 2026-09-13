import unittest
from app.parsers.csv_parser import CSVParser
from app.normalizer.normalizer import Normalizer


class TestCSVParser(unittest.TestCase):
    def setUp(self):
        self.parser = CSVParser()
        self.normalizer = Normalizer()

    def test_name(self):
        self.assertEqual(self.parser.name, "csv")

    def test_can_parse_valid_multiline(self):
        log = "timestamp,src,dst,sport,dport,proto,act,sev\n2026-09-13T10:00:00Z,192.168.1.10,10.0.0.1,12345,80,TCP,ALLOW,INFO"
        self.assertTrue(self.parser.can_parse(log))

    def test_can_parse_invalid(self):
        self.assertFalse(self.parser.can_parse("just a plain text string without commas"))
        self.assertFalse(self.parser.can_parse("CEF:0|Vendor|Product|1.0|100|Event|5|src=1.1.1.1"))
        self.assertFalse(self.parser.can_parse("<xml><tag>123</tag></xml>"))
        self.assertFalse(self.parser.can_parse('{"json": "data"}'))
        self.assertFalse(self.parser.can_parse(""))

    def test_parse_valid_csv_header_extraction(self):
        log = "timestamp,src,dst,sport,dport,proto,act,sev\n2026-09-13T10:00:00Z,192.168.1.10,10.0.0.1,12345,80,TCP,ALLOW,HIGH"

        result = self.parser.parse(log)

        self.assertEqual(result["source_type"], "csv")
        self.assertEqual(result["raw_event"], log)

        # Original fields
        self.assertEqual(result["src"], "192.168.1.10")
        self.assertEqual(result["dst"], "10.0.0.1")
        self.assertEqual(result["sport"], "12345")
        self.assertEqual(result["dport"], "80")

        # Alias fields
        self.assertEqual(result["source_ip"], "192.168.1.10")
        self.assertEqual(result["destination_ip"], "10.0.0.1")
        self.assertEqual(result["source_port"], "12345")
        self.assertEqual(result["destination_port"], "80")
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["action"], "ALLOW")
        self.assertEqual(result["severity"], "HIGH")

    def test_different_column_ordering(self):
        log = "action,destination_ip,source_ip,destination_port\nALLOW,10.0.0.5,172.16.0.2,443"
        result = self.parser.parse(log)

        self.assertEqual(result["action"], "ALLOW")
        self.assertEqual(result["destination_ip"], "10.0.0.5")
        self.assertEqual(result["source_ip"], "172.16.0.2")
        self.assertEqual(result["destination_port"], "443")

    def test_quoted_values(self):
        log = 'timestamp,src,msg\n"2026-09-13T10:00:00Z","192.168.1.10","User logged in, access granted"'
        result = self.parser.parse(log)

        self.assertEqual(result["source_ip"], "192.168.1.10")
        self.assertEqual(result["msg"], "User logged in, access granted")

    def test_raw_preservation(self):
        log = "col1,col2\nval1,val2"
        result = self.parser.parse(log)
        self.assertEqual(result["raw_event"], log)

    def test_malformed_csv_raises_value_error(self):
        log = "plain text line without structure"
        with self.assertRaises(ValueError):
            self.parser.parse(log)

    def test_normalization_integration(self):
        log = "src,dst,sport,dport,act\n192.168.1.50,10.0.0.1,5000,80,ALLOW"
        parsed = self.parser.parse(log)
        parsed["parser"] = self.parser.name
        parsed["parse_status"] = "success"

        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.destination_ip, "10.0.0.1")
        self.assertEqual(event.source_port, 5000)
        self.assertEqual(event.destination_port, 80)
        self.assertEqual(event.action, "ALLOW")
        self.assertEqual(event.raw_event, log)


if __name__ == "__main__":
    unittest.main()
