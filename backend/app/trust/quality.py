import ipaddress
from typing import Any, Dict, List


class QualityChecker:
    """Deterministic, explainable confidence and data-quality checks."""

    REQUIRED_FIELDS = ["event_id", "source_type", "raw_event"]
    IMPORTANT_FIELDS = ["timestamp", "source_ip", "destination_ip", "action"]
    QUALITY_FIELDS = [
        "timestamp", "source_ip", "destination_ip", "source_port",
        "destination_port", "protocol", "event_type", "action", "severity",
    ]

    def check(self, event: Dict[str, Any]) -> Dict[str, Any]:
        missing_required = [f for f in self.REQUIRED_FIELDS if not event.get(f)]
        missing_important = [f for f in self.IMPORTANT_FIELDS if not event.get(f)]
        missing_fields = [f for f in self.QUALITY_FIELDS if not event.get(f)]

        completeness = round(
            (len(self.QUALITY_FIELDS) - len(missing_fields))
            / len(self.QUALITY_FIELDS) * 100
        )

        validity_checks = []
        for field in ["source_ip", "destination_ip"]:
            value = event.get(field)
            if not value:
                validity_checks.append(True)
            else:
                try:
                    ipaddress.ip_address(value)
                    validity_checks.append(True)
                except ValueError:
                    validity_checks.append(False)

        for field in ["source_port", "destination_port"]:
            value = event.get(field)
            if value is None or value == "":
                validity_checks.append(True)
            else:
                validity_checks.append(isinstance(value, int) and 1 <= value <= 65535)

        validity = round(sum(validity_checks) / len(validity_checks) * 100) if validity_checks else 100

        consistency_checks = []
        src = event.get("source_ip")
        dst = event.get("destination_ip")
        if src and dst:
            consistency_checks.append(src != dst)

        sport = event.get("source_port")
        dport = event.get("destination_port")
        if sport is not None and dport is not None:
            consistency_checks.append(sport != dport)

        if event.get("action") is not None:
            consistency_checks.append(bool(str(event.get("action")).strip()))

        consistency = round(
            sum(consistency_checks) / len(consistency_checks) * 100
        ) if consistency_checks else 100

        score = round(
            completeness * 0.50 + validity * 0.30 + consistency * 0.20
        )

        if missing_required or validity < 50:
            status = "invalid"
        elif score < 70:
            status = "partial"
        else:
            status = "complete"

        warnings: List[str] = []
        if missing_important:
            warnings.append("Important fields are missing: " + ", ".join(missing_important))
        if validity < 100:
            warnings.append("One or more IP/port values are invalid.")
        if consistency < 100:
            warnings.append("One or more event fields are inconsistent.")

        return {
            "status": status,
            "quality_score": score,
            "confidence": round(score / 100, 2),
            "checks": {
                "completeness": completeness,
                "validity": validity,
                "consistency": consistency,
            },
            "missing_required_fields": missing_required,
            "missing_important_fields": missing_important,
            "missing_fields": missing_fields,
            "warnings": warnings,
        }
