from typing import Any, Dict
from app.analytics.engine import AnalyticsEngine
from app.search.search_service import SearchService
from app.config.settings import settings
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.analytics.service")

class AnalyticsService:
    def __init__(self):
        self.engine = AnalyticsEngine()
        self.search = SearchService()

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any] | None:
        if not settings.analytics_enabled:
            return None

        try:
            result = self.engine.analyze(event)
            dict_res = result.model_dump()
            self.search.index_analytics(dict_res)
            return dict_res
        except Exception as e:
            logger.error(f"Failed to process analytics for event {event.get('event_id')}", error=e)
            return None
