import hashlib


class IntegrityChecker:
    """
    Generates a SHA-256 hash for a raw log event.

    The hash helps verify that the raw event has not been
    modified after ingestion.
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
        Verify whether a raw event matches its expected hash.
        """
        actual_hash = IntegrityChecker.calculate_hash(raw_event)

        return actual_hash == expected_hash