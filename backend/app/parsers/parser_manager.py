import logging
from typing import Any, Dict, List, Optional

from .base_parser import BaseParser
from .syslog_parser import SyslogParser
from .json_parser import JSONParser
from .cef_parser import CEFParser
from .xml_parser import XMLParser
from .csv_parser import CSVParser
from .leef_parser import LEEFParser

import os
from .plugin_registry import PluginRegistry
from .plugin_loader import PluginLoader

logger = logging.getLogger(__name__)

class ParserManager:
    """
    Manage supported ULPF parsers, dynamic registration, priority detection,
    enable/disable states, and unknown format handling.
    """

    def __init__(self, plugins_dir: str = None) -> None:
        self.registry = PluginRegistry()
        if plugins_dir is None:
            plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "plugins")
        self.plugins_dir = os.path.abspath(plugins_dir)

        # Register default supported parsers with deterministic priorities
        self.register_parser(JSONParser(), priority=10)
        self.register_parser(CEFParser(), priority=20)
        self.register_parser(LEEFParser(), priority=30)
        self.register_parser(SyslogParser(), priority=40)
        self.register_parser(XMLParser(), priority=50)
        self.register_parser(CSVParser(), priority=60)

        self.reload_plugins()

    def reload_plugins(self):
        # Remove dynamically loaded plugins first
        to_remove = [item["name"] for item in self.registry.list_all() if item["metadata"] is not None]
        for name in to_remove:
            self.registry.unregister(name)

        loader = PluginLoader(self.plugins_dir)
        loaded = loader.load_plugins()
        for name, data in loaded.items():
            # Avoid duplicate built-in name crashes
            if self.registry.get(name):
                logger.warning(f"Plugin '{name}' conflicts with existing parser, skipping.")
                continue
            self.registry.register(
                name=name,
                parser=data["parser"],
                priority=data["priority"],
                enabled=data["enabled"],
                metadata=data["metadata"]
            )

    @property
    def parsers(self) -> List[BaseParser]:
        return [item["parser"] for item in self.registry.get_sorted_items() if item["enabled"]]

    def register_parser(self, parser: BaseParser, priority: int = 100, enabled: bool = True) -> None:
        if not isinstance(parser, BaseParser):
            raise TypeError("Parser must inherit from BaseParser")
        name = parser.name
        if not name or not isinstance(name, str):
            raise ValueError("Parser must have a valid non-empty string name")
        self.registry.register(name, parser, priority, enabled)

    def unregister_parser(self, name: str) -> None:
        self.registry.unregister(name)

    def enable_parser(self, name: str) -> None:
        self.registry.enable(name)

    def disable_parser(self, name: str) -> None:
        self.registry.disable(name)

    def get_parser(self, name: str) -> Optional[BaseParser]:
        item = self.registry.get(name)
        return item["parser"] if item else None

    def get_parser_info(self, name: str) -> Optional[Dict[str, Any]]:
        item = self.registry.get(name)
        if not item:
            return None
        meta = item.get("metadata")
        return {
            "name": name,
            "enabled": item["enabled"],
            "priority": item["priority"],
            "health": item["health"],
            "version": meta.version if meta else "built-in",
            "parser": item["parser"]
        }

    def list_parsers(self) -> List[str]:
        return [item["parser"].name for item in self.registry.get_sorted_items() if item["enabled"]]

    def list_all_parsers(self) -> List[Dict[str, Any]]:
        return self.registry.list_all()

    def detect_parser(self, log: str) -> Optional[BaseParser]:
        if not log or not log.strip():
            return None

        for item in self.registry.get_sorted_items():
            if not item["enabled"]:
                continue

            parser: BaseParser = item["parser"]
            try:
                if parser.can_parse(log):
                    return parser
            except Exception as error:
                logger.warning(f"Parser '{parser.name}' raised an error during detection: {error}")
                self.registry.mark_unhealthy(parser.name, str(error))
                continue

        return None

    def parse(self, log: str) -> Dict[str, Any]:
        if not log or not log.strip():
            raise ValueError("Log cannot be empty")

        raw_log = log
        parse_input = log.strip()
        parser = self.detect_parser(parse_input)

        if parser is None:
            return {
                "source_type": "unknown",
                "raw_event": raw_log,
                "parser": None,
                "parse_status": "unknown",
                "confidence": 0.0,
            }

        try:
            result = parser.parse(parse_input)
            result["parser"] = parser.name
            result["raw_event"] = raw_log

            # Attach parser version if from a plugin
            item = self.registry.get(parser.name)
            if item and item.get("metadata"):
                result["parser_version"] = item["metadata"].version

            result["parse_status"] = "success"
            if "confidence" not in result:
                result["confidence"] = 1.0
            return result
        except Exception as error:
            logger.warning(f"Parser '{parser.name}' failed to parse log: {error}")
            self.registry.mark_unhealthy(parser.name, str(error))
            return {
                "source_type": "unknown",
                "raw_event": raw_log,
                "parser": parser.name,
                "parse_status": "error",
                "error": str(error),
                "confidence": 0.0,
            }

    def add_parser(self, parser: BaseParser) -> None:
        self.register_parser(parser)
