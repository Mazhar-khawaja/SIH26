from typing import Any, Dict

from app.parsers.parser_manager import ParserManager
from app.normalizer.normalizer import Normalizer
from app.trust.integrity import IntegrityChecker
from app.trust.quality import QualityChecker
from app.trust.unknown_detection import UnknownFormatDetector
from app.storage.database import Database


class IngestionManager:
    """
    Coordinates the complete ULPF ingestion pipeline.

    Flow:
    Raw Log
        ↓
    Parser Detection
        ↓
    Parsing
        ↓
    Normalization
        ↓
    Integrity Check
        ↓
    Quality Check
        ↓
    SQLite Storage
    """

    def __init__(self, database_path: str = "data/ulpf.db") -> None:
        self.parser_manager = ParserManager()
        self.normalizer = Normalizer()
        self.integrity_checker = IntegrityChecker()
        self.quality_checker = QualityChecker()
        self.unknown_detector = UnknownFormatDetector()
        self.database = Database(database_path)

    def process_log(self, log: str) -> Dict[str, Any]:
        """
        Process one raw log through the complete ULPF pipeline.
        """

        if not log or not log.strip():
            raise ValueError("Log cannot be empty")

        # 1. Detect format and parse
        parsed_data = self.parser_manager.parse(log)

        # 2. Normalize into Universal Event Schema
        normalized_event = self.normalizer.normalize(parsed_data)

        event = normalized_event.model_dump()

        # 3. Calculate integrity hash
        raw_hash = self.integrity_checker.calculate_hash(
            event["raw_event"]
        )

        # 4. Check event quality
        quality_result = self.quality_checker.check(event)

        # 5. Check whether parser format is supported
        format_result = self.unknown_detector.check(
            event.get("parser")
        )

        # 6. Store event
        self.database.save_event(
            event=event,
            raw_hash=raw_hash,
            quality=quality_result,
        )

        # 7. Return complete processing result
        return {
            "event": event,
            "integrity": {
                "sha256": raw_hash,
                "verified": self.integrity_checker.verify_hash(
                    event["raw_event"],
                    raw_hash,
                ),
            },
            "quality": quality_result,
            "format": format_result,
        }

    def supported_formats(self) -> list[str]:
        """
        Return all currently supported log formats.
        """
        return self.parser_manager.list_parsers()

    def get_event(self, event_id: str) -> Dict[str, Any] | None:
        """
        Retrieve an event from storage using its Event ID.
        """
        return self.database.get_event(event_id)

    def get_all_events(self) -> list[Dict[str, Any]]:
        """
        Retrieve all stored events.
        """
        return self.database.get_all_events()

    def count_events(self) -> int:
        """
        Return the number of stored events.
        """
        return self.database.count_events()