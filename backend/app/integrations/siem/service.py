from typing import Dict, Any, Optional
from app.integrations.siem.rest_connector import RESTSIEMConnector
from app.config.settings import settings
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.integrations.siem")

class SIEMIntegrationService:
    def __init__(self):
        self.connector = RESTSIEMConnector()

    def _construct_payload(self, event: Dict[str, Any], analytics: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        # Serialize a safe copy without mutating original
        payload = {
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "source": event.get("source"),
            "source_ip": event.get("source_ip"),
            "source_port": event.get("source_port"),
            "destination_ip": event.get("destination_ip"),
            "destination_port": event.get("destination_port"),
            "protocol": event.get("protocol"),
            "action": event.get("action"),
            "severity": event.get("severity"),
            "user": event.get("user"),
            "device": event.get("device"),
            "hostname": event.get("hostname"),
            "application": event.get("application"),
            "vendor": event.get("vendor"),
            "product": event.get("product"),
            "category": event.get("category"),
            "parser": event.get("parser"),
            "parser_version": event.get("parser_version"),
            "quality_score": event.get("quality_score"),
            "confidence": event.get("confidence"),
            "integrity_hash": event.get("integrity_hash"),
            "previous_hash": event.get("previous_hash"),
            "chain_hash": event.get("chain_hash"),
            "raw_event": event.get("raw_event")
        }

        if analytics:
            payload["anomaly"] = analytics.get("anomaly")
            payload["anomaly_score"] = analytics.get("anomaly_score")
            payload["risk_score"] = analytics.get("risk_score")
            payload["detections"] = analytics.get("rule_matches", [])
            payload["reasons"] = analytics.get("reasons", [])

        return payload

    def forward_event(self, event: Dict[str, Any], analytics: Optional[Dict[str, Any]] = None) -> bool:
        if not settings.siem_enabled:
            return False

        try:
            payload = self._construct_payload(event, analytics)
            success = self.connector.send_event(payload)
            if success:
                logger.info("SIEM_EVENT_SENT", event_id=event.get("event_id"), success=True)
            else:
                logger.warning("SIEM_EVENT_FAILED", event_id=event.get("event_id"), success=False)
            return success
        except Exception as e:
            logger.error("SIEM_EVENT_FAILED", event_id=event.get("event_id"), error=e, success=False)
            return False

    def test_connection(self) -> Dict[str, Any]:
        if not settings.siem_enabled:
            return {"status": "failed", "reason": "SIEM integration disabled"}

        test_payload = {
            "event_id": "TEST-0000",
            "message": "ULPF SIEM Integration Test",
            "source": "ULPF_TEST"
        }

        try:
            success = self.connector.send_event(test_payload)
            logger.info("SIEM_TEST", success=success)
            return {"status": "success" if success else "failed", "reachable": success}
        except Exception as e:
            logger.error("SIEM_TEST", success=False, error=e)
            return {"status": "error", "error": str(e)}

    def status(self) -> Dict[str, Any]:
        health = self.connector.health_check()
        return {
            "enabled": settings.siem_enabled,
            "connector_type": "REST",
            **health
        }
