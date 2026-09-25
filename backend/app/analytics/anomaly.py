from typing import Any, Dict
import time
from app.config.settings import settings

class AnomalyDetector:
    def __init__(self):
        # Lightweight sliding window baseline tracker
        self.windows = [] # list of event counts per 10-second window
        self.current_window_start = int(time.time() / 10) * 10
        self.current_count = 0

    def _update_baseline(self):
        now = int(time.time() / 10) * 10
        if now > self.current_window_start:
            # Shift windows
            self.windows.append(self.current_count)
            if len(self.windows) > 100: # Keep last ~16 minutes of 10s windows
                self.windows = self.windows[-100:]
            self.current_window_start = now
            self.current_count = 1
        else:
            self.current_count += 1

    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        self._update_baseline()

        if len(self.windows) < settings.min_baseline_samples:
            return {
                "is_anomaly": False,
                "score": 0.0,
                "reason": "insufficient baseline data"
            }

        mean = sum(self.windows) / len(self.windows)
        variance = sum((x - mean) ** 2 for x in self.windows) / len(self.windows)
        std_dev = variance ** 0.5

        if std_dev == 0:
            return {
                "is_anomaly": False,
                "score": 0.0,
                "reason": "zero standard deviation in baseline"
            }

        # Z-score for current count
        z_score = (self.current_count - mean) / std_dev

        if z_score >= settings.anomaly_zscore_threshold:
            # Score scales from 0.5 to 1.0 based on how far past threshold
            score = min(1.0, 0.5 + ((z_score - settings.anomaly_zscore_threshold) * 0.1))
            return {
                "is_anomaly": True,
                "score": round(score, 2),
                "reason": f"Event rate is {z_score:.2f} standard deviations above baseline"
            }

        return {
            "is_anomaly": False,
            "score": 0.0,
            "reason": ""
        }
