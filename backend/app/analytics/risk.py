from typing import Any, Dict
from app.analytics.models import AnalyticsResult

class RiskScorer:
    def calculate(self, event: Dict[str, Any], partial_result: AnalyticsResult) -> Dict[str, Any]:
        score = 0

        # Base score from event severity
        severity = str(event.get("severity", "")).lower()
        if severity == "critical":
            score += 50
        elif severity == "high":
            score += 30
        elif severity == "medium":
            score += 15
        elif severity == "low":
            score += 5

        # Add score from rule detections
        if partial_result.detected:
            score += len(partial_result.rule_matches) * 20
            if "repeated_failed_login" in partial_result.rule_matches:
                score += 15
            if "suspicious_command" in partial_result.rule_matches:
                score += 40

        # Add score from anomaly
        if partial_result.anomaly:
            # anomaly_score is 0.0 to 1.0, map to max 30
            score += int(partial_result.anomaly_score * 30)

        # Ensure bounds 0-100
        score = max(0, min(100, score))

        return {
            "score": score,
            "severity": self._map_severity(score)
        }

    def _map_severity(self, score: int) -> str:
        if score < 25:
            return "low"
        if score < 50:
            return "medium"
        if score < 75:
            return "high"
        return "critical"
