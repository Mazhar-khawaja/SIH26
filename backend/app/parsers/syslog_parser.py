import re
from typing import Any, Dict

from .base_parser import BaseParser


class SyslogParser(BaseParser):
    """
    Parser for basic Syslog security events.
    """

    @property
    def name(self) -> str:
        return "syslog"

    def can_parse(self, log: str) -> bool:
        """
        Detect whether the log looks like a Syslog event.
        """
        if not log:
            return False

        # Common Syslog priority format: <134>
        if re.match(r"^<\d+>", log.strip()):
            return True

        return False

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Extract common security fields from a Syslog event.
        """
        log = log.strip()

        if not self.can_parse(log):
            raise ValueError("Log does not appear to be Syslog format")

        result: Dict[str, Any] = {
            "source_type": "syslog",
            "raw_event": log,
        }

        # Extract Syslog priority
        priority_match = re.match(r"^<(\d+)>", log)

        if priority_match:
            result["priority"] = int(priority_match.group(1))

        # Extract timestamp
        timestamp_match = re.search(
            r"^<\d+>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            log,
        )

        if timestamp_match:
            result["timestamp"] = timestamp_match.group(1)
                    # Extract the Syslog device/application name
        source_match = re.match(
            r"^<\d+>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)",
            log,
        )

        if source_match:
            result["source"] = source_match.group(1)

        # Extract key=value fields
        fields = re.findall(
            r'(\w+)=("[^"]*"|\S+)',
            log
        )

        for key, value in fields:
            value = value.strip('"')
            result[key] = value

        return result