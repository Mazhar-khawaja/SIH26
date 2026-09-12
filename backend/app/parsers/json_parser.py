import json
from typing import Any, Dict

from .base_parser import BaseParser


class JSONParser(BaseParser):
    """
    Parser for JSON-formatted security events.
    """

    @property
    def name(self) -> str:
        return "json"

    def can_parse(self, log: str) -> bool:
        """
        Detect whether the log is valid JSON.
        """
        if not log:
            return False

        try:
            data = json.loads(log)
            return isinstance(data, dict)
        except (json.JSONDecodeError, TypeError):
            return False

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Parse a JSON security event into a dictionary.
        """
        log = log.strip()

        if not self.can_parse(log):
            raise ValueError("Log is not valid JSON format")

        data = json.loads(log)

        # Preserve the original event
        result: Dict[str, Any] = {
            "source_type": "json",
            "raw_event": log,
        }

        # Add all fields from the JSON event
        result.update(data)

        return result