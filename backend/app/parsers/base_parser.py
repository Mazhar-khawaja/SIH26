from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseParser(ABC):
    """
    Base interface for all ULPF log parsers.

    Every parser must:
    1. Identify whether it can handle a log.
    2. Parse the log into a common dictionary format.
    """

    @abstractmethod
    def can_parse(self, log: str) -> bool:
        """
        Return True if this parser can handle the given log.
        """
        pass

    @abstractmethod
    def parse(self, log: str) -> Dict[str, Any]:
        """
        Parse the raw log and return extracted fields.
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the parser name.
        """
        pass