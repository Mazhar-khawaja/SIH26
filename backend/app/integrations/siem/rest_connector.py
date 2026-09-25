import requests
import time
from typing import Dict, Any, List
from app.integrations.siem.base import BaseSIEMConnector
from app.config.settings import settings
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.integrations.siem.rest")

class RESTSIEMConnector(BaseSIEMConnector):
    def __init__(self):
        self.url = settings.siem_url
        self.timeout = settings.siem_timeout
        self.verify_tls = settings.siem_verify_tls
        self.max_retries = settings.siem_max_retries
        self.backoff = settings.siem_retry_backoff_seconds

        self.headers = {"Content-Type": "application/json"}
        if settings.siem_api_key:
            self.headers["X-API-Key"] = settings.siem_api_key
        if settings.siem_token:
            self.headers["Authorization"] = f"Bearer {settings.siem_token}"

    def _execute_with_retry(self, payload: Any) -> bool:
        if not self.url:
            logger.warning("SIEM URL not configured")
            return False

        retries = 0
        while retries <= self.max_retries:
            try:
                response = requests.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_tls
                )

                if response.status_code in [200, 201, 202, 204]:
                    return True

                # Do not retry permanent errors
                if response.status_code in [400, 401, 403]:
                    logger.error(f"Permanent SIEM rejection {response.status_code}")
                    return False

                # Retry transient errors
                if response.status_code in [429] or response.status_code >= 500:
                    retries += 1
                    if retries <= self.max_retries:
                        time.sleep(self.backoff * retries)
                        continue

            except requests.exceptions.RequestException as e:
                retries += 1
                if retries <= self.max_retries:
                    time.sleep(self.backoff * retries)
                    continue
                logger.error("SIEM request failed", error=e)
                return False

        return False

    def send_event(self, event: Dict[str, Any]) -> bool:
        return self._execute_with_retry(event)

    def send_events(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0

        # If external SIEM supports array bulk ingest natively
        success = self._execute_with_retry(events)
        if success:
            return len(events)

        # Fallback to individual
        count = 0
        for ev in events:
            if self.send_event(ev):
                count += 1
        return count

    def health_check(self) -> Dict[str, Any]:
        if not self.url:
            return {"configured": False, "reachable": False}

        try:
            # Send an empty or OPTIONS ping if possible, or just a GET
            # For a generic REST, a generic GET might 405 but prove reachability
            res = requests.options(self.url, timeout=3, verify=self.verify_tls)
            return {"configured": True, "reachable": True, "status": res.status_code}
        except Exception as e:
            return {"configured": True, "reachable": False, "error": str(e)}
