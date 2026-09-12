import re
from typing import Any, Dict

from .base_parser import BaseParser


class CEFParser(BaseParser):
    """
    Parser for Common Event Format (CEF) security events.
    """

    @property
    def name(self) -> str:
        return "cef"

    def can_parse(self, log: str) -> bool:
        """
        Detect whether the log follows the CEF format.
        """
        if not log:
            return False

        return log.strip().startswith("CEF:")

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Parse a CEF event into extracted fields.
        """
        log = log.strip()

        if not self.can_parse(log):
            raise ValueError("Log does not appear to be CEF format")

        result: Dict[str, Any] = {
            "source_type": "cef",
            "raw_event": log,
        }

        # Remove the CEF prefix
        cef_data = log[4:]

        # CEF format:
        # CEF:Version|Device Vendor|Device Product|Device Version|
        # Signature ID|Name|Severity|Extension

        header_and_extension = cef_data.split("|", 7)

        if len(header_and_extension) < 8:
            raise ValueError("Invalid CEF format")

        result["cef_version"] = header_and_extension[0]
        result["device_vendor"] = header_and_extension[1]
        result["device_product"] = header_and_extension[2]
        result["device_version"] = header_and_extension[3]
        result["signature_id"] = header_and_extension[4]
        result["event_name"] = header_and_extension[5]
        result["severity"] = header_and_extension[6]

        extension = header_and_extension[7]

        # Extract key=value extension fields
        fields = re.findall(
            r'(\w+)=("[^"]*"|\S+)',
            extension
        )

        for key, value in fields:
            result[key] = value.strip('"')

        return result