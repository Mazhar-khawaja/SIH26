import hashlib


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