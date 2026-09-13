import re
from typing import Any, Dict
from .base_parser import BaseParser


class LEEFParser(BaseParser):
    """
    Parser for Log Event Extended Format (LEEF) security events.
    Supports LEEF 1.0 and LEEF 2.0.
    """

    @property
    def name(self) -> str:
        return "leef"

    def can_parse(self, log: str) -> bool:
        """
        Detect whether the log follows the LEEF format.
        """
        if not log or not log.strip():
            return False

        return log.strip().startswith("LEEF:")

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Parse a LEEF event into extracted header and extension fields.
        """
        if not log or not log.strip():
            raise ValueError("Log cannot be empty")

        stripped = log.strip()

        if not self.can_parse(stripped):
            raise ValueError("Log does not appear to be LEEF format")

        result: Dict[str, Any] = {
            "source_type": "leef",
            "raw_event": log,
        }

        # Format: LEEF:Version|Vendor|Product|Version|EventID|[Delimiter|]Extension
        leef_data = stripped[5:]  # strip 'LEEF:'

        parts = leef_data.split("|")

        if len(parts) < 5:
            raise ValueError("Invalid LEEF format: Header requires at least 5 pipe-separated fields")

        result["leef_version"] = parts[0]
        result["vendor"] = parts[1]
        result["device_vendor"] = parts[1]
        result["product"] = parts[2]
        result["device_product"] = parts[2]
        result["version"] = parts[3]
        result["device_version"] = parts[3]

        event_id = parts[4]
        extension_str = ""
        delimiter = "\t"

        # Check if extension was separated by tab/space right after EventID instead of pipe
        if "\t" in event_id:
            event_id, ext_part = event_id.split("\t", 1)
            extension_str = ext_part
        elif "=" in event_id:
            # Handle space/tab separated event_id and key=val
            match = re.search(r"[\s\t]+(\w+=)", event_id)
            if match:
                idx = match.start()
                extension_str = event_id[idx:].strip()
                event_id = event_id[:idx].strip()

        result["event_id"] = event_id
        result["signature_id"] = event_id

        if len(parts) >= 6:
            # In LEEF 2.0, if 6th field is a single character or hex code (like 0x09 or ^), it specifies delimiter
            possible_delim = parts[5]
            if len(parts) >= 7 and (len(possible_delim) <= 4 and ("x" in possible_delim or len(possible_delim) == 1)):
                if possible_delim.startswith("0x"):
                    try:
                        delimiter = chr(int(possible_delim, 16))
                    except ValueError:
                        delimiter = possible_delim
                else:
                    delimiter = possible_delim
                additional_ext = "|".join(parts[6:])
            else:
                additional_ext = "|".join(parts[5:])

            if extension_str:
                extension_str = extension_str + delimiter + additional_ext
            else:
                extension_str = additional_ext

        if extension_str:
            self._parse_extension(extension_str, delimiter, result)

        return result

    @staticmethod
    def _parse_extension(extension_str: str, delimiter: str, result: Dict[str, Any]) -> None:
        """
        Extract key=value extension fields split by delimiter (default TAB).
        """
        # Split by specified delimiter or fallback to tab/space key=val patterns
        items = extension_str.split(delimiter) if delimiter in extension_str else [extension_str]

        for item in items:
            item = item.strip()
            if not item:
                continue

            # Fallback regex search for key=val if delimiter split didn't isolate single pairs
            if "\t" in item:
                sub_items = item.split("\t")
            else:
                sub_items = [item]

            for sub in sub_items:
                sub = sub.strip()
                if "=" in sub:
                    key, val = sub.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"')
                    result[key] = val
