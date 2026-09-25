from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseSIEMConnector(ABC):
    @abstractmethod
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send a single event to the SIEM."""
        pass

    @abstractmethod
    def send_events(self, events: List[Dict[str, Any]]) -> int:
        """Send multiple events to the SIEM. Returns number of successful events."""
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Verify SIEM connectivity and configuration."""
        pass
