from abc import ABC, abstractmethod
from typing import List
from app.intelligence.models import ClassificationResult, FieldMappingSuggestion

class AIProvider(ABC):
    @abstractmethod
    def classify_format(self, log: str) -> ClassificationResult:
        pass

    @abstractmethod
    def suggest_field_mapping(self, log: str, format_hint: str) -> List[FieldMappingSuggestion]:
        pass
