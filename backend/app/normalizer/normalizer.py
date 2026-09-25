from typing import Any, Dict
from uuid import uuid4

from app.models.event_schema import UniversalEvent


class Normalizer:
    """
    Converts parser-specific fields into the ULPF Universal Event Schema.
    """

    FIELD_MAPPINGS = {
        "source_ip": ["source_ip", "src", "sourceAddress", "source_address", "src_ip", "SourceIP", "srcAddress", "sourceIpAddress", "sourceIPAddress"],
        "destination_ip": ["destination_ip", "dst", "destinationAddress", "destination_address", "dst_ip", "DestinationIP", "dstAddress"],
        "source_port": ["source_port", "sport", "sourcePort", "source_port_number", "src_port", "SourcePort"],
        "destination_port": ["destination_port", "dport", "dpt", "destinationPort", "destination_port_number", "dst_port", "DestinationPort"],
        "action": ["action", "act", "Action", "eventName", "eventAction"],
        "protocol": ["protocol", "proto", "Protocol", "app"],
        "severity": ["severity", "sev", "Severity", "Level"],
        "timestamp": ["timestamp", "time", "devTime", "TimeCreated", "EventTime", "SystemTime", "date", "eventTime", "creationTime"],
        "event_type": ["event_type", "eventType", "event_name", "name", "event_id", "EventID", "signature_id", "RecordNumber"],
        "user": ["user", "username", "duser", "suser", "userIdentity", "principalId"],
        "hostname": ["hostname", "host", "dhost", "shost", "Computer"],
        "application": ["application", "app", "ProviderName"],
    }

    def _get_value(self, parsed_data: Dict[str, Any], field_names: list[str]) -> Any:
        for field_name in field_names:
            if field_name in parsed_data:
                return parsed_data[field_name]
        return None

    def normalize(self, parsed_data: Dict[str, Any]) -> UniversalEvent:
        event_id = f"ULPF-{uuid4().hex[:12].upper()}"

        source_ip = self._get_value(parsed_data, self.FIELD_MAPPINGS["source_ip"])
        dest_ip = self._get_value(parsed_data, self.FIELD_MAPPINGS["destination_ip"])

        # Create known top-level fields
        normalized_data: Dict[str, Any] = {
            "event_id": event_id,
            "timestamp": self._get_value(parsed_data, self.FIELD_MAPPINGS["timestamp"]),
            "source": parsed_data.get("device_product") or parsed_data.get("product") or parsed_data.get("source") or parsed_data.get("eventSource"),
            "vendor": parsed_data.get("vendor") or parsed_data.get("device_vendor"),
            "product": parsed_data.get("product") or parsed_data.get("device_product"),
            "category": parsed_data.get("category") or parsed_data.get("eventCategory"),
            "source_ip": source_ip if source_ip != "-" else None,
            "source_type": parsed_data.get("source_type", "unknown"),
            "source_port": self._convert_port(self._get_value(parsed_data, self.FIELD_MAPPINGS["source_port"])),
            "destination": parsed_data.get("destination"),
            "destination_ip": dest_ip if dest_ip != "-" else None,
            "destination_port": self._convert_port(self._get_value(parsed_data, self.FIELD_MAPPINGS["destination_port"])),
            "protocol": self._get_value(parsed_data, self.FIELD_MAPPINGS["protocol"]),
            "event_type": str(self._get_value(parsed_data, self.FIELD_MAPPINGS["event_type"])) if self._get_value(parsed_data, self.FIELD_MAPPINGS["event_type"]) else None,
            "action": self._get_value(parsed_data, self.FIELD_MAPPINGS["action"]),
            "severity": str(self._get_value(parsed_data, self.FIELD_MAPPINGS["severity"])) if self._get_value(parsed_data, self.FIELD_MAPPINGS["severity"]) else None,
            "user": self._extract_user(self._get_value(parsed_data, self.FIELD_MAPPINGS["user"])),
            "hostname": self._get_value(parsed_data, self.FIELD_MAPPINGS["hostname"]),
            "application": self._get_value(parsed_data, self.FIELD_MAPPINGS["application"]),
            "raw_event": parsed_data.get("raw_event", ""),
            "extracted_data": parsed_data.get("extracted_data", {}),
            "parser": parsed_data.get("parser"),
            "parser_version": parsed_data.get("parser_version"),
            "parse_status": parsed_data.get("parse_status", "success"),
            "confidence": parsed_data.get("confidence"),
            "extensions": {},
            "metadata": {
                "source_type": parsed_data.get("source_type", "unknown")
            }
        }

        # Put anything in extracted_data into extensions
        if "extracted_data" in parsed_data and isinstance(parsed_data["extracted_data"], dict):
            normalized_data["extensions"].update(parsed_data["extracted_data"])

        # Push all unmapped leftover keys to extensions
        known_keys = set([v for lst in self.FIELD_MAPPINGS.values() for v in lst])
        for k, v in parsed_data.items():
            if k not in known_keys and k not in normalized_data and k not in ["raw_event", "parser", "parser_version", "parse_status", "extracted_data"]:
                normalized_data["extensions"][k] = v

        return UniversalEvent(**normalized_data)

    @staticmethod
    def _convert_port(value: Any) -> int | None:
        """
        Convert a port value to an integer when possible.
        """
        if value is None:
            return None

        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _extract_user(value: Any) -> str | None:
        """
        Extract user string safely, handling CloudTrail userIdentity dictionaries.
        """
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            return value.get("userName") or value.get("principalId") or value.get("arn")
        return None