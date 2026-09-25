from typing import Dict, Any, List, Optional
from app.parsers.base_parser import BaseParser
from app.parsers.plugin_metadata import PluginMetadata
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.plugin_registry")

class PluginRegistry:
    def __init__(self):
        self._registry: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, parser: BaseParser, priority: int = 100, enabled: bool = True, metadata: Optional[PluginMetadata] = None) -> None:
        if name in self._registry:
            raise ValueError(f"Parser with name '{name}' is already registered")

        self._registry[name] = {
            "parser": parser,
            "priority": priority,
            "enabled": enabled,
            "metadata": metadata,
            "health": "healthy"
        }

    def unregister(self, name: str) -> None:
        if name not in self._registry:
            raise KeyError(f"Parser '{name}' is not registered")
        del self._registry[name]

    def enable(self, name: str) -> None:
        if name not in self._registry:
            raise KeyError(f"Parser '{name}' is not registered")
        self._registry[name]["enabled"] = True

    def disable(self, name: str) -> None:
        if name not in self._registry:
            raise KeyError(f"Parser '{name}' is not registered")
        self._registry[name]["enabled"] = False

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self._registry.get(name)

    def list_all(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "enabled": item["enabled"],
                "priority": item["priority"],
                "health": item["health"],
                "metadata": item["metadata"].model_dump() if item["metadata"] else None
            }
            for name, item in self._registry.items()
        ]

    def get_sorted_items(self) -> List[Dict[str, Any]]:
        return sorted(
            self._registry.values(),
            key=lambda x: (x["priority"], x["parser"].name)
        )

    def mark_unhealthy(self, name: str, error: str) -> None:
        if name in self._registry:
            self._registry[name]["health"] = f"unhealthy: {error}"
            logger.warning(f"Parser '{name}' marked as unhealthy: {error}")

    def clear(self):
        self._registry.clear()
