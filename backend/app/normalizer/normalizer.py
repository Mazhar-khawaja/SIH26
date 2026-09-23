from typing import Any, Dict
from uuid import uuid4

from app.models.event_schema import UniversalEvent


class Normalizer:
    """
    Converts parser-specific fields into the ULPF Universal Event Schema.
    """

    FIELD_MAPPINGS = {
        "source_ip": [
            "source_ip",
            "src",
            "sourceAddress",
            "source_address",
            "src_ip",
            "SourceIP",
            "srcAddress",
        ],
        "destination_ip": [
            "destination_ip",
            "dst",
            "destinationAddress",
            "destination_address",
            "dst_ip",
            "DestinationIP",
            "dstAddress",
        ],
        "source_port": [
            "source_port",
            "sport",
            "sourcePort",
            "source_port_number",
            "src_port",
            "SourcePort",
        ],
        "destination_port": [
            "destination_port",
            "dport",
            "dpt",
            "destinationPort",
            "destination_port_number",
            "dst_port",
            "DestinationPort",
        ],
        "action": [
            "action",
            "act",
            "Action",
        ],
        "protocol": [
            "protocol",
            "proto",
            "Protocol",
        ],
        "severity": [
            "severity",
            "sev",
            "Severity",
            "Level",
        ],
        "timestamp": [
            "timestamp",
            "time",
            "devTime",
            "TimeCreated",
            "EventTime",
            "SystemTime",
            "date",
        ],
        "event_type": [
            "event_type",
            "eventType",
            "event_name",
            "name",
            "event_id",
            "EventID",
            "signature_id",
        ],
    }

    def _get_value(
        self,
        parsed_data: Dict[str, Any],
        field_names: list[str],
    ) -> Any:
        """
        Return the first available value from the supplied field names.
        """
        for field_name in field_names:
            if field_name in parsed_data:
                return parsed_data[field_name]

        return None

    def normalize(self, parsed_data: Dict[str, Any]) -> UniversalEvent:
        """
        Convert parser output into a UniversalEvent.
        """
                # Merge extracted vendor fields with parser output so that
        # unknown/vendor formats can also be normalized using the
        # existing FIELD_MAPPINGS aliases.
        extracted_data = parsed_data.get("extracted_data") or {}

        normalization_data = {
            **extracted_data,
            **parsed_data,
        }

        event_id = f"ULPF-{uuid4().hex[:12].upper()}"

        normalized_data: Dict[str, Any] = {
            "event_id": event_id,
            "timestamp": self._get_value(
                normalization_data,
                self.FIELD_MAPPINGS["timestamp"],
            ),
            "source": parsed_data.get("device_product")
            or parsed_data.get("product")
            or parsed_data.get("source")
            or parsed_data.get("vendor")
            or parsed_data.get("device_vendor"),
            "source_type": parsed_data.get("source_type"),
            "source_ip": self._get_value(
                normalization_data,
                self.FIELD_MAPPINGS["source_ip"],
            ),
            "source_port": self._convert_port(
                self._get_value(
                    normalization_data,
                    self.FIELD_MAPPINGS["source_port"],
                )
            ),
            "destination_ip": self._get_value(
                normalization_data,
                self.FIELD_MAPPINGS["destination_ip"],
            ),
            "destination_port": self._convert_port(
                self._get_value(
                    normalization_data,
                    self.FIELD_MAPPINGS["destination_port"],
                )
            ),
            "protocol": self._get_value(
                normalization_data,
                self.FIELD_MAPPINGS["protocol"],
            ),
            "event_type": self._get_value(
                normalization_data,
                self.FIELD_MAPPINGS["event_type"],
            ),
            "action": self._get_value(
                normalization_data,
                self.FIELD_MAPPINGS["action"],
            ),
            "severity": self._get_value(
                normalization_data,
                self.FIELD_MAPPINGS["severity"],
            ),
            "raw_event": parsed_data.get("raw_event", ""),
            "extracted_data": parsed_data.get("extracted_data") or {},
            "parser": parsed_data.get("parser")
            or parsed_data.get("source_type"),
            "parse_status": parsed_data.get("parse_status", "success"),
        }

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