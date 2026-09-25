from typing import Any, Dict
from app.analytics.models import AnalyticsResult
from app.analytics.rules import RuleEngine
from app.analytics.anomaly import AnomalyDetector
from app.analytics.risk import RiskScorer
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.analytics.engine")

class AnalyticsEngine:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector()
        self.risk_scorer = RiskScorer()

    def analyze(self, event: Dict[str, Any]) -> AnalyticsResult:
        result = AnalyticsResult(event_id=event.get("event_id", "unknown"))

        try:
            # 1. Rule Detections
            rule_results = self.rule_engine.evaluate(event)
            if rule_results:
                result.detected = True
                for r in rule_results:
                    result.detections.append(r["name"])
                    result.reasons.append(r["reason"])
                    result.rule_matches.append(r["name"])

            # 2. Anomaly Detection
            anomaly_result = self.anomaly_detector.detect(event)
            result.anomaly = anomaly_result["is_anomaly"]
            result.anomaly_score = anomaly_result["score"]
            if anomaly_result["is_anomaly"]:
                result.reasons.append(anomaly_result["reason"])

            # 3. Risk Scoring
            risk_result = self.risk_scorer.calculate(event, result)
            result.risk_score = risk_result["score"]
            result.severity = risk_result["severity"]

        except Exception as e:
            logger.error(f"Analytics engine failed for event {event.get('event_id')}", error=e)
            result.reasons.append("Analytics execution partially failed")

        return result
