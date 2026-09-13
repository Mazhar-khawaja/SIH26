import unittest
from app.parsers.xml_parser import XMLParser
from app.normalizer.normalizer import Normalizer


class TestXMLParser(unittest.TestCase):
    def setUp(self):
        self.parser = XMLParser()
        self.normalizer = Normalizer()

    def test_name(self):
        self.assertEqual(self.parser.name, "xml")

    def test_can_parse_valid(self):
        valid_xml = "<security_event><source_ip>192.168.1.100</source_ip></security_event>"
        self.assertTrue(self.parser.can_parse(valid_xml))

    def test_can_parse_with_declaration(self):
        valid_xml = '<?xml version="1.0"?><Event><EventID>4624</EventID></Event>'
        self.assertTrue(self.parser.can_parse(valid_xml))

    def test_can_parse_invalid(self):
        self.assertFalse(self.parser.can_parse("not xml at all"))
        self.assertFalse(self.parser.can_parse("<unclosed_tag>123"))
        self.assertFalse(self.parser.can_parse(""))

    def test_parse_valid_xml_extraction(self):
        log = (
            "<security_event>"
            "<source_ip>192.168.1.50</source_ip>"
            "<destination_ip>10.0.0.1</destination_ip>"
            "<source_port>54321</source_port>"
            "<destination_port>443</destination_port>"
            "<action>ALLOW</action>"
            "<protocol>TCP</protocol>"
            "<severity>HIGH</severity>"
            "</security_event>"
        )

        result = self.parser.parse(log)

        self.assertEqual(result["source_type"], "xml")
        self.assertEqual(result["raw_event"], log)
        self.assertEqual(result["source_ip"], "192.168.1.50")
        self.assertEqual(result["destination_ip"], "10.0.0.1")
        self.assertEqual(result["source_port"], "54321")
        self.assertEqual(result["destination_port"], "443")
        self.assertEqual(result["action"], "ALLOW")
        self.assertEqual(result["protocol"], "TCP")

    def test_parse_windows_event_xml(self):
        log = (
            "<Event>"
            "<System>"
            "<EventID>4624</EventID>"
            '<TimeCreated SystemTime="2026-09-13T10:00:00Z"/>'
            "</System>"
            "<EventData>"
            '<Data Name="TargetUserName">Administrator</Data>'
            '<Data Name="IpAddress">192.168.1.50</Data>'
            "</EventData>"
            "</Event>"
        )

        result = self.parser.parse(log)

        self.assertEqual(result["source_type"], "xml")
        self.assertEqual(result["raw_event"], log)
        self.assertEqual(result["TargetUserName"], "Administrator")
        self.assertEqual(result["IpAddress"], "192.168.1.50")
        self.assertEqual(result["EventID"], "4624")

    def test_raw_preservation(self):
        log = "  <event><id>123</id></event>  "
        result = self.parser.parse(log)
        self.assertEqual(result["raw_event"], log)

    def test_malformed_xml_raises_value_error(self):
        log = "<broken><tag>value</broken>"
        with self.assertRaises(ValueError):
            self.parser.parse(log)

    def test_normalization_integration(self):
        log = "<event><src>192.168.1.10</src><dst>10.0.0.5</dst><action>DENY</action></event>"
        parsed = self.parser.parse(log)
        parsed["parser"] = self.parser.name
        parsed["parse_status"] = "success"

        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.source_ip, "192.168.1.10")
        self.assertEqual(event.destination_ip, "10.0.0.5")
        self.assertEqual(event.action, "DENY")
        self.assertEqual(event.raw_event, log)


if __name__ == "__main__":
    unittest.main()
