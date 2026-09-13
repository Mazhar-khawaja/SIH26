import unittest
from app.parsers.parser_manager import ParserManager


class TestParserManager(unittest.TestCase):
    def setUp(self):
        self.manager = ParserManager()

    def test_list_parsers(self):
        parsers = self.manager.list_parsers()
        self.assertIn("syslog", parsers)
        self.assertIn("json", parsers)
        self.assertIn("cef", parsers)
        self.assertIn("xml", parsers)
        self.assertIn("csv", parsers)
        self.assertIn("leef", parsers)

    def test_detect_parser_syslog(self):
        log = "<134>Sep 13 22:00:00 myhost test=1"
        parser = self.manager.detect_parser(log)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.name, "syslog")

    def test_detect_parser_json(self):
        log = '{"event": "login"}'
        parser = self.manager.detect_parser(log)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.name, "json")

    def test_detect_parser_cef(self):
        log = "CEF:0|Vendor|Product|1.0|100|Name|5|src=1.1.1.1"
        parser = self.manager.detect_parser(log)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.name, "cef")

    def test_detect_parser_xml(self):
        log = "<event><id>1</id></event>"
        parser = self.manager.detect_parser(log)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.name, "xml")

    def test_detect_parser_csv(self):
        log = "src,dst,action\n192.168.1.1,10.0.0.1,ALLOW"
        parser = self.manager.detect_parser(log)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.name, "csv")

    def test_detect_parser_leef(self):
        log = "LEEF:2.0|Vendor|Product|1.0|100|src=1.1.1.1"
        parser = self.manager.detect_parser(log)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.name, "leef")

    def test_parse_empty_log_raises_error(self):
        with self.assertRaises(ValueError):
            self.manager.parse("")

    def test_parse_unknown_log(self):
        log = "Plain unrecognized text string"
        result = self.manager.parse(log)
        self.assertEqual(result["source_type"], "unknown")
        self.assertEqual(result["raw_event"], log)
        self.assertIsNone(result["parser"])


if __name__ == "__main__":
    unittest.main()
