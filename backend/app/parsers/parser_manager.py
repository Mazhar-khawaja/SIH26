from typing import Any, Dict, List

from .base_parser import BaseParser
from .syslog_parser import SyslogParser
from .json_parser import JSONParser
from .cef_parser import CEFParser


class ParserManager:
    """
    Manages all available ULPF parsers and automatically
    selects the appropriate parser for an incoming log.
    """

    def __init__(self) -> None:
        self.parsers: List[BaseParser] = [
            SyslogParser(),
            JSONParser(),
            CEFParser(),
        ]

    def detect_parser(self, log: str) -> BaseParser:
        """
        Automatically detect the parser that can handle the log.
        """
        for parser in self.parsers:
            if parser.can_parse(log):
                return parser

        raise ValueError("Unsupported or unknown log format")

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Detect the appropriate parser and parse the log.
        """
        parser = self.detect_parser(log)

        result = parser.parse(log)

        result["parser"] = parser.name

        return result

    def add_parser(self, parser: BaseParser) -> None:
        """
        Add a new parser without modifying the existing pipeline.
        """
        if not isinstance(parser, BaseParser):
            raise TypeError("Parser must inherit from BaseParser")

        self.parsers.append(parser)

    def list_parsers(self) -> List[str]:
        """
        Return the names of all registered parsers.
        """
        return [parser.name for parser in self.parsers]