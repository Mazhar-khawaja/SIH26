from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class AnalyticsResult(BaseModel):
    event_id: str
    detected: bool = False
    anomaly: bool = False
    anomaly_score: float = Field(0.0, ge=0.0, le=1.0)
    risk_score: int = Field(0, ge=0, le=100)
    severity: str = "low"
    detections: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    rule_matches: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
