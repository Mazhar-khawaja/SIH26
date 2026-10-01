import hashlib
import json
from typing import Dict, Any
class IntegrityChecker:
    """
    Provides tamper-evident integrity checks for raw log events.
    """

    @staticmethod
    def calculate_hash(raw_event: str) -> str:
        """
        Calculate SHA-256 hash of the exact raw event.
        """
        if not isinstance(raw_event, str):
            raise TypeError("Raw event must be a string")

        return hashlib.sha256(
            raw_event.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def verify_hash(raw_event: str, expected_hash: str) -> bool:
        """
        Verify whether a raw event matches its expected SHA-256 hash.
        """
        actual_hash = IntegrityChecker.calculate_hash(raw_event)

        return actual_hash == expected_hash

    @staticmethod
    def _canonicalize(event: Dict[str, Any]) -> str:
        fields_to_protect = [
            "event_id", "timestamp", "event_type", "source_ip", "destination_ip", 
            "source_port", "destination_port", "user", "hostname", "application", 
            "vendor", "product", "category", "severity", "action", "parser", 
            "parser_version", "quality_score", "confidence", "extensions", "metadata",
            "source", "source_type", "destination", "protocol", "device"
        ]
        
        payload = {}
        for key in fields_to_protect:
            if key in event:
                payload[key] = event[key]
                
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False,
            default=str
        )

    @staticmethod
    def calculate_normalized_hash(event: Dict[str, Any]) -> str:
        """
        Calculate SHA-256 hash of the canonical Universal Event.
        """
        canonical_str = IntegrityChecker._canonicalize(event)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_normalized_hash(event: Dict[str, Any], expected_hash: str) -> bool:
        """
        Verify whether the normalized event matches its expected SHA-256 hash.
        """
        if not expected_hash:
            return False
        actual_hash = IntegrityChecker.calculate_normalized_hash(event)
        return actual_hash == expected_hash

    @staticmethod
    def calculate_chain_hash(
        raw_event: str,
        previous_hash: str = "",
    ) -> str:
        """
        Calculate a tamper-evident chain hash.

        The current hash depends on both the current raw event
        and the hash of the previous event.
        """
        if not isinstance(raw_event, str):
            raise TypeError("Raw event must be a string")

        if not isinstance(previous_hash, str):
            raise TypeError("Previous hash must be a string")

        chain_data = previous_hash + raw_event

        return hashlib.sha256(
            chain_data.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def verify_chain_hash(
        raw_event: str,
        previous_hash: str,
        expected_hash: str,
    ) -> bool:
        """
        Verify whether the current event belongs to the
        expected tamper-evident hash chain.
        """
        actual_hash = IntegrityChecker.calculate_chain_hash(
            raw_event,
            previous_hash,
        )

        return actual_hash == expected_hash