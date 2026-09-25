from typing import Any, Dict, List
import time
from app.config.settings import settings

class RuleEngine:
    def __init__(self):
        # In a real distributed system, this state would be in Redis or OpenSearch
        # For P2.5B, we use a simple in-memory tracker for the single instance
        self.failed_logins = {} # ip -> [timestamps]
        self.ip_activity = {}   # ip -> [timestamps]

    def _cleanup_old_events(self, history: List[float], window: int, now: float) -> List[float]:
        return [ts for ts in history if now - ts <= window]

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, str]]:
        results = []
        now = time.time()
        source_ip = event.get("source_ip")

        # 1. Repeated Failed Login
        action = str(event.get("action", "")).lower()
        event_type = str(event.get("event_type", "")).lower()

        is_auth_failure = (
            "fail" in action or
            "fail" in event_type or
            str(event.get("severity") or "").lower() == "error" and ("auth" in event_type or "login" in event_type)
        )

        if is_auth_failure and source_ip:
            history = self.failed_logins.get(source_ip, [])
            history = self._cleanup_old_events(history, settings.failed_login_window_seconds, now)
            history.append(now)
            self.failed_logins[source_ip] = history

            if len(history) >= settings.failed_login_threshold:
                results.append({
                    "name": "repeated_failed_login",
                    "reason": f"{len(history)} failed login events from {source_ip} within {settings.failed_login_window_seconds}s"
                })

        # 2. Unusual Source IP Activity (Spike)
        if source_ip:
            activity = self.ip_activity.get(source_ip, [])
            activity = self._cleanup_old_events(activity, settings.source_ip_window_seconds, now)
            activity.append(now)
            self.ip_activity[source_ip] = activity

            if len(activity) >= settings.source_ip_event_threshold:
                results.append({
                    "name": "source_ip_spike",
                    "reason": f"Excessive activity: {len(activity)} events from {source_ip} within {settings.source_ip_window_seconds}s"
                })

        # 3. Abnormal Destination Port
        dst_port = event.get("destination_port")
        protocol = str(event.get("protocol", "")).lower()
        if dst_port and protocol:
            unusual = False
            if protocol == "http" and dst_port not in (80, 8080, 443, 8443):
                unusual = True
            elif protocol == "ssh" and dst_port != 22:
                unusual = True

            if unusual:
                results.append({
                    "name": "abnormal_destination_port",
                    "reason": f"Port {dst_port} is unusual for protocol {protocol}"
                })

        # 4. Suspicious Command
        extensions = event.get("extensions", {})
        command = extensions.get("command") or extensions.get("process_command_line") or ""
        command = str(command).lower()
        if command and any(suspicious in command for suspicious in ["rm -rf", "wget", "curl", "nc -e", "base64 -d"]):
            results.append({
                "name": "suspicious_command",
                "reason": f"Suspicious command execution detected: {command[:50]}"
            })

        return results
