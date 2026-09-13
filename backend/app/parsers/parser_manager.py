import logging
from typing import Any, Dict, List, Optional

from .base_parser import BaseParser
from .syslog_parser import SyslogParser
from .json_parser import JSONParser
from .cef_parser import CEFParser
from .xml_parser import XMLParser
from .csv_parser import CSVParser
from .leef_parser import LEEFParser

logger = logging.getLogger(__name__)


class ParserManager:
    """
    Manage supported ULPF parsers, dynamic registration, priority detection,
    enable/disable states, and unknown format handling.
    """

    def __init__(self) -> None:
        # Internal registry: name -> {"parser": BaseParser, "priority": int, "enabled": bool}
        self._registry: Dict[str, Dict[str, Any]] = {}

        # Register default supported parsers with deterministic priorities
        self.register_parser(JSONParser(), priority=10)
        self.register_parser(CEFParser(), priority=20)
        self.register_parser(LEEFParser(), priority=30)
        self.register_parser(SyslogParser(), priority=40)
        self.register_parser(XMLParser(), priority=50)
        self.register_parser(CSVParser(), priority=60)

    @property
    def parsers(self) -> List[BaseParser]:
        """
        Backward compatibility property returning list of active BaseParser instances.
        """
        active = [
            item["parser"]
            for item in self._get_sorted_items()
            if item["enabled"]
        ]
        return active

    def register_parser(
        self,
        parser: BaseParser,
        priority: int = 100,
        enabled: bool = True,
    ) -> None:
        """
        Register a new parser dynamically with priority and duplicate protection.
        """
        if not isinstance(parser, BaseParser):
            raise TypeError("Parser must inherit from BaseParser")

        name = parser.name
        if not name or not isinstance(name, str):
            raise ValueError("Parser must have a valid non-empty string name")

        if name in self._registry:
            raise ValueError(f"Parser with name '{name}' is already registered")

        self._registry[name] = {
            "parser": parser,
            "priority": priority,
            "enabled": enabled,
        }

    def unregister_parser(self, name: str) -> None:
        """
        Unregister a parser by name.
        """
        if name not in self._registry:
            raise KeyError(f"Parser '{name}' is not registered")
        del self._registry[name]

    def enable_parser(self, name: str) -> None:
        """
        Enable a registered parser.
        """
        if name not in self._registry:
            raise KeyError(f"Parser '{name}' is not registered")
        self._registry[name]["enabled"] = True

    def disable_parser(self, name: str) -> None:
        """
        Disable a registered parser.
        """
        if name not in self._registry:
            raise KeyError(f"Parser '{name}' is not registered")
        self._registry[name]["enabled"] = False

    def get_parser(self, name: str) -> Optional[BaseParser]:
        """
        Retrieve a registered parser instance by name.
        """
        item = self._registry.get(name)
        return item["parser"] if item else None

    def get_parser_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve metadata for a registered parser.
        """
        item = self._registry.get(name)
        if not item:
            return None
        return {
            "name": name,
            "enabled": item["enabled"],
            "priority": item["priority"],
            "parser": item["parser"],
        }

    def list_parsers(self) -> List[str]:
        """
        Return names of currently enabled parsers in deterministic priority order.
        """
        return [
            item["parser"].name
            for item in self._get_sorted_items()
            if item["enabled"]
        ]

    def list_all_parsers(self) -> List[Dict[str, Any]]:
        """
        Return metadata list for all registered parsers.
        """
        return [
            {
                "name": item["parser"].name,
                "enabled": item["enabled"],
                "priority": item["priority"],
            }
            for item in self._get_sorted_items()
        ]

    def detect_parser(self, log: str) -> Optional[BaseParser]:
        """
        Detect matching parser using deterministic priority ordering and safe error isolation.
        """
        if not log or not log.strip():
            return None

        for item in self._get_sorted_items():
            if not item["enabled"]:
                continue

            parser: BaseParser = item["parser"]
            try:
                if parser.can_parse(log):
                    return parser
            except Exception as error:
                logger.warning(
                    "Parser '%s' raised an error during detection: %s",
                    parser.name,
                    error,
                )
                continue

        return None

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Parse supported logs and safely pass unknown logs downstream.
        """
        if not log or not log.strip():
            raise ValueError("Log cannot be empty")

        log = log.strip()
        parser = self.detect_parser(log)

        if parser is None:
            return {
                "source_type": "unknown",
                "raw_event": log,
                "parser": None,
                "parse_status": "unknown",
            }

        try:
            result = parser.parse(log)
            result["parser"] = parser.name
            result["parse_status"] = "success"
            return result
        except Exception as error:
            logger.warning(
                "Parser '%s' failed to parse log: %s",
                parser.name,
                error,
            )
            return {
                "source_type": "unknown",
                "raw_event": log,
                "parser": parser.name,
                "parse_status": "error",
                "error": str(error),
            }

    def add_parser(self, parser: BaseParser) -> None:
        """
        Backward compatibility wrapper for registering a new parser.
        """
        self.register_parser(parser)

    def _get_sorted_items(self) -> List[Dict[str, Any]]:
        """
        Return internal registry items sorted deterministically by priority.
        """
        return sorted(
            self._registry.values(),
            key=lambda x: (x["priority"], x["parser"].name),
        )
