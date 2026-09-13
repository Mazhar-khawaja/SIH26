import unittest
from app.parsers.syslog_parser import SyslogParser
from app.normalizer.normalizer import Normalizer


class TestSyslogParser(unittest.TestCase):
    def setUp(self):
        self.parser = SyslogParser()
        self.normalizer = Normalizer()

    def test_name(self):
        self.assertEqual(self.parser.name, "syslog")

    def test_can_parse_valid(self):
        log = "<134>Sep 13 22:00:00 myhost firewall: src=192.168.1.1 dst=10.0.0.1 action=ALLOW"
        self.assertTrue(self.parser.can_parse(log))

    def test_can_parse_invalid(self):
        self.assertFalse(self.parser.can_parse("Not syslog format"))
        self.assertFalse(self.parser.can_parse('{"json": "data"}'))
        self.assertFalse(self.parser.can_parse(""))

    def test_parse_valid_syslog(self):
        log = "<134>Sep 13 22:00:00 myhost src=192.168.1.50 dst=10.0.0.1 sport=5000 dport=80 action=ALLOW"
        result = self.parser.parse(log)

        self.assertEqual(result["source_type"], "syslog")
        self.assertEqual(result["raw_event"], log)
        self.assertEqual(result["priority"], 134)
        self.assertEqual(result["timestamp"], "Sep 13 22:00:00")
        self.assertEqual(result["source"], "myhost")
        self.assertEqual(result["src"], "192.168.1.50")
        self.assertEqual(result["dst"], "10.0.0.1")
        self.assertEqual(result["action"], "ALLOW")

    def test_normalization_integration(self):
        log = "<134>Sep 13 22:00:00 app1 src=192.168.1.50 dst=10.0.0.1 act=DENY"
        parsed = self.parser.parse(log)
        parsed["parser"] = self.parser.name
        parsed["parse_status"] = "success"

        event = self.normalizer.normalize(parsed)
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.destination_ip, "10.0.0.1")
        self.assertEqual(event.action, "DENY")
        self.assertEqual(event.raw_event, log)


if __name__ == "__main__":
    unittest.main()
