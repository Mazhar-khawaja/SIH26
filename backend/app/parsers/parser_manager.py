from typing import Any, Dict, List

from .base_parser import BaseParser
from .syslog_parser import SyslogParser
from .json_parser import JSONParser
from .cef_parser import CEFParser


class ParserManager:
    """Manage supported ULPF parsers and detect log formats."""

    def __init__(self) -> None:
        self.parsers: List[BaseParser] = [
            SyslogParser(),
            JSONParser(),
            CEFParser(),
        ]

    def detect_parser(self, log: str) -> BaseParser | None:
        """Return a matching parser, or None for an unknown format."""
        for parser in self.parsers:
            if parser.can_parse(log):
                return parser
        return None

    def parse(self, log: str) -> Dict[str, Any]:
        """Parse supported logs and safely pass unknown logs downstream."""
        if not log or not log.strip():
            raise ValueError("Log cannot be empty")

        log = log.strip()
        parser = self.detect_parser(log)

        if parser is None:
            return {
                "source_type": "unknown",
                "raw_event": log,
                "parser": None,
                "parse_status": "unknown",
            }

        result = parser.parse(log)
        result["parser"] = parser.name
        result["parse_status"] = "success"
        return result

    def add_parser(self, parser: BaseParser) -> None:
        if not isinstance(parser, BaseParser):
            raise TypeError("Parser must inherit from BaseParser")
        self.parsers.append(parser)

    def list_parsers(self) -> List[str]:
        return [parser.name for parser in self.parsers]
