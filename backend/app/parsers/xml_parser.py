import xml.etree.ElementTree as ET
from typing import Any, Dict
from .base_parser import BaseParser


class XMLParser(BaseParser):
    """
    Parser for XML-formatted security events.
    """

    @property
    def name(self) -> str:
        return "xml"

    def can_parse(self, log: str) -> bool:
        """
        Detect whether the log is valid XML.
        """
        if not log or not log.strip():
            return False

        stripped = log.strip()
        if not (stripped.startswith("<") or stripped.startswith("<?xml")):
            return False

        try:
            ET.fromstring(stripped)
            return True
        except Exception:
            return False

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Parse an XML security event into extracted fields.
        """
        if not log or not log.strip():
            raise ValueError("Log cannot be empty")

        stripped = log.strip()

        if not self.can_parse(stripped):
            raise ValueError("Log does not appear to be XML format")

        try:
            root = ET.fromstring(stripped)
        except Exception as error:
            raise ValueError(f"Malformed XML: {error}") from error

        result: Dict[str, Any] = {
            "source_type": "xml",
            "raw_event": log,
        }

        # Extract XML fields recursively
        extracted = self._extract_element(root)
        if isinstance(extracted, dict):
            result.update(extracted)
            self._promote_nested_keys(extracted, result)
        else:
            result["content"] = extracted

        # Map common field aliases if available
        self._apply_common_aliases(result)

        return result

    def _promote_nested_keys(self, source_dict: Dict[str, Any], target_dict: Dict[str, Any]) -> None:
        """
        Promote leaf keys from nested dicts to top-level if not already present.
        """
        for k, v in source_dict.items():
            if isinstance(v, dict):
                self._promote_nested_keys(v, target_dict)
            elif not isinstance(v, list) and k not in target_dict:
                target_dict[k] = v

    def _extract_element(self, element: ET.Element) -> Any:
        """
        Recursively extract tags, attributes, and text from an XML element.
        """
        data: Dict[str, Any] = {}

        # Capture element attributes
        for key, value in element.attrib.items():
            data[key] = value

        # Handle child elements
        children = list(element)
        if children:
            for child in children:
                tag = self._clean_tag(child.tag)
                child_data = self._extract_element(child)

                # Special handling for Windows Event Log <Data Name="Key">Value</Data>
                if tag.lower() == "data" and isinstance(child_data, dict) and "Name" in child_data:
                    data_name = child_data["Name"]
                    data_val = child_data.get("text", "")
                    data[data_name] = data_val
                elif tag in data:
                    # Collect multiple children with the same tag as a list
                    if not isinstance(data[tag], list):
                        data[tag] = [data[tag]]
                    data[tag].append(child_data)
                else:
                    data[tag] = child_data
        else:
            text = (element.text or "").strip()
            if data:
                if text:
                    data["text"] = text
            else:
                return text

        return data

    @staticmethod
    def _clean_tag(tag: str) -> str:
        """
        Remove XML namespace prefix if present (e.g., {http://...}Tag -> Tag).
        """
        if "}" in tag:
            return tag.split("}", 1)[1]
        return tag

    @staticmethod
    def _apply_common_aliases(data: Dict[str, Any]) -> None:
        """
        Populate common security field names from XML tag variations.
        """
        alias_map = {
            "source_ip": ["source_ip", "src", "SourceAddress", "SourceIP", "src_ip", "IpAddress"],
            "destination_ip": ["destination_ip", "dst", "DestinationAddress", "DestinationIP", "dst_ip"],
            "source_port": ["source_port", "sport", "SourcePort", "src_port"],
            "destination_port": ["destination_port", "dport", "DestinationPort", "dst_port"],
            "action": ["action", "act", "Action"],
            "protocol": ["protocol", "proto", "Protocol"],
            "severity": ["severity", "sev", "Severity", "Level"],
            "timestamp": ["timestamp", "time", "TimeCreated", "EventTime", "SystemTime", "Date"],
            "event_type": ["event_type", "eventType", "EventID", "EventId", "name", "Task"],
        }

        for target_key, candidate_keys in alias_map.items():
            if target_key not in data:
                for candidate in candidate_keys:
                    val = data.get(candidate)
                    if val is not None and not isinstance(val, (dict, list)):
                        data[target_key] = val
                        break
