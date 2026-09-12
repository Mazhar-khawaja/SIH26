from typing import Any, Dict, List


class QualityChecker:
    """
    Performs basic quality checks on parsed/normalized events.
    """

    REQUIRED_FIELDS = [
        "event_id",
        "source_type",
        "raw_event",
    ]

    IMPORTANT_FIELDS = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "action",
    ]

    def check(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate the completeness and quality of an event.
        """

        missing_required: List[str] = []
        missing_important: List[str] = []

        for field in self.REQUIRED_FIELDS:
            value = event.get(field)

            if value is None or value == "":
                missing_required.append(field)

        for field in self.IMPORTANT_FIELDS:
            value = event.get(field)

            if value is None or value == "":
                missing_important.append(field)

        if missing_required:
            status = "invalid"
        elif missing_important:
            status = "partial"
        else:
            status = "complete"

        return {
            "status": status,
            "missing_required_fields": missing_required,
            "missing_important_fields": missing_important,
            "quality_score": self._calculate_score(
                missing_required,
                missing_important,
            ),
        }

    @staticmethod
    def _calculate_score(
        missing_required: List[str],
        missing_important: List[str],
    ) -> int:
        """
        Calculate a simple 0-100 quality score.
        """

        score = 100

        score -= len(missing_required) * 25
        score -= len(missing_important) * 10

        return max(0, score)