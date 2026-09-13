import unittest
from typing import Any, Dict
from app.parsers.base_parser import BaseParser
from app.parsers.parser_manager import ParserManager


class BrokenParser(BaseParser):
    @property
    def name(self) -> str:
        return "broken"

    def can_parse(self, log: str) -> bool:
        raise RuntimeError("Simulated failure inside can_parse")

    def parse(self, log: str) -> Dict[str, Any]:
        raise RuntimeError("Simulated failure inside parse")


class CustomTestParser(BaseParser):
    def __init__(self, parser_name: str = "custom"):
        self._name = parser_name

    @property
    def name(self) -> str:
        return self._name

    def can_parse(self, log: str) -> bool:
        return "CUSTOM_FLAG" in log

    def parse(self, log: str) -> Dict[str, Any]:
        return {
            "source_type": self._name,
            "raw_event": log,
            "custom_field": "test_value",
        }


class TestAdvancedParserManager(unittest.TestCase):
    def setUp(self):
        self.manager = ParserManager()

    def test_default_registered_parsers(self):
        supported = self.manager.list_parsers()
        expected = ["json", "cef", "leef", "syslog", "xml", "csv"]
        self.assertEqual(supported, expected)

    def test_register_parser(self):
        custom = CustomTestParser("my_custom")
        self.manager.register_parser(custom, priority=5)

        self.assertIn("my_custom", self.manager.list_parsers())
        self.assertEqual(self.manager.list_parsers()[0], "my_custom")

    def test_duplicate_parser_prevention(self):
        custom1 = CustomTestParser("duplicate_test")
        custom2 = CustomTestParser("duplicate_test")

        self.manager.register_parser(custom1)
        with self.assertRaises(ValueError):
            self.manager.register_parser(custom2)

    def test_unregister_parser(self):
        self.assertIn("xml", self.manager.list_parsers())
        self.manager.unregister_parser("xml")
        self.assertNotIn("xml", self.manager.list_parsers())

        with self.assertRaises(KeyError):
            self.manager.unregister_parser("xml")

    def test_enable_disable_parser(self):
        self.assertIn("json", self.manager.list_parsers())

        # Disable json parser
        self.manager.disable_parser("json")
        self.assertNotIn("json", self.manager.list_parsers())

        # Attempt to parse json log when json parser is disabled
        json_log = '{"src": "1.1.1.1"}'
        result = self.manager.parse(json_log)
        # Should not match json parser while disabled
        self.assertNotEqual(result.get("parser"), "json")

        # Enable json parser back
        self.manager.enable_parser("json")
        self.assertIn("json", self.manager.list_parsers())

        result_enabled = self.manager.parse(json_log)
        self.assertEqual(result_enabled.get("parser"), "json")

    def test_parser_priority_deterministic_detection(self):
        p1 = CustomTestParser("high_priority")
        p2 = CustomTestParser("low_priority")

        self.manager.register_parser(p1, priority=1)
        self.manager.register_parser(p2, priority=999)

        log = "CUSTOM_FLAG log entry"
        detected = self.manager.detect_parser(log)
        self.assertIsNotNone(detected)
        self.assertEqual(detected.name, "high_priority")

    def test_parser_failure_handling_in_can_parse(self):
        broken = BrokenParser()
        self.manager.register_parser(broken, priority=1)

        # Broken parser will throw exception in can_parse, but manager must safely skip it
        json_log = '{"src": "10.0.0.1"}'
        result = self.manager.parse(json_log)

        self.assertEqual(result.get("parser"), "json")
        self.assertEqual(result.get("parse_status"), "success")

    def test_unknown_format_handling(self):
        unknown_log = "THIS_LOG_IS_COMPLETELY_UNRECOGNIZED_AND_UNSTRUCTURED 12345"
        result = self.manager.parse(unknown_log)

        self.assertEqual(result["source_type"], "unknown")
        self.assertEqual(result["raw_event"], unknown_log)
        self.assertIsNone(result["parser"])
        self.assertEqual(result["parse_status"], "unknown")

    def test_add_parser_backward_compatibility(self):
        custom = CustomTestParser("add_parser_test")
        self.manager.add_parser(custom)
        self.assertIn("add_parser_test", self.manager.list_parsers())


if __name__ == "__main__":
    unittest.main()
