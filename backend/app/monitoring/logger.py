import logging
import json
from datetime import datetime, timezone
import traceback
from typing import Any, Dict

from app.config.settings import settings

class StructuredLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        # Avoid adding handlers if they already exist
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            self.logger.setLevel(settings.log_level.upper())
            self.logger.addHandler(handler)
            self.logger.propagate = False

    def _log(self, level: int, message: str, **kwargs: Any) -> None:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": logging.getLevelName(level),
            "service": settings.app_name,
            "message": message,
        }
        log_entry.update(kwargs)

        # Log as JSON string for structured logging
        self.logger.log(level, json.dumps(log_entry))

    def info(self, message: str, **kwargs: Any) -> None:
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, error: Exception = None, **kwargs: Any) -> None:
        if error:
            kwargs["error"] = str(error)
            kwargs["traceback"] = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        self._log(logging.ERROR, message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, message, **kwargs)

def get_logger(name: str) -> StructuredLogger:
    return StructuredLogger(name)
