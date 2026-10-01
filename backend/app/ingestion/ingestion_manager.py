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
    SHA-256 Integrity Hash
        ↓
    Tamper-Evident Chain Hash
        ↓
    Quality Check
        ↓
    SQLite Storage
    """

    def __init__(self, database_path: str = None) -> None:
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

        # 2. Analyze format and extract any identifiable data
        format_result = self.unknown_detector.check(
            parsed_data.get("parser"),
            parsed_data.get("raw_event", log),
        )

        if parsed_data.get("parser") is None:
            if not hasattr(self, "intelligence_service"):
                from app.intelligence.service import IntelligenceService
                self.intelligence_service = IntelligenceService()

            ai_res = self.intelligence_service.classify_log(log)
            format_result["intelligence"] = ai_res.model_dump(mode="json")
            parsed_data["confidence"] = ai_res.confidence

        parsed_data["extracted_data"] = format_result.get("extracted_data", {})

        # 3. Normalize into Universal Event Schema
        normalized_event = self.normalizer.normalize(parsed_data)

        event = normalized_event.model_dump(mode="json")

        # 4. Calculate SHA-256 hash of the exact raw event
        raw_hash = self.integrity_checker.calculate_hash(
            event["raw_event"]
        )

        # 5. Check event quality
        quality_result = self.quality_checker.check(event)
        event["quality_score"] = quality_result["quality_score"]

        # Calculate Normalized Hash AFTER quality and confidence are set
        event["hash_version"] = 2
        normalized_hash = self.integrity_checker.calculate_normalized_hash(event)
        event["normalized_hash"] = normalized_hash

        # 6. Store event with concurrency-safe chain hashing
        prev_h, chain_h = self.database.save_event(
            event=event,
            raw_hash=raw_hash,
            quality=quality_result,
            format=format_result,
            integrity_callback=self.integrity_checker.calculate_chain_hash
        )

        # 7. Update event with returned hashes
        event["integrity_hash"] = raw_hash
        event["previous_hash"] = prev_h
        event["chain_hash"] = chain_h
        previous_hash = prev_h
        chain_hash = chain_h

        # 8. Index event in OpenSearch
        if not hasattr(self, "search_service"):
            from app.search.search_service import SearchService
            self.search_service = SearchService()
        self.search_service.index_event(event)

        # 9. Run Analytics
        analytics_result = None
        if not hasattr(self, "analytics_service"):
            from app.analytics.service import AnalyticsService
            self.analytics_service = AnalyticsService()
        analytics_result = self.analytics_service.analyze_event(event)

        # 10. Run SIEM Integration
        if not hasattr(self, "siem_service"):
            from app.integrations.siem.service import SIEMIntegrationService
            self.siem_service = SIEMIntegrationService()
        self.siem_service.forward_event(event, analytics_result)

        # 11. Verify the newly created hashes
        hash_verified = self.integrity_checker.verify_hash(
            event["raw_event"],
            raw_hash,
        )

        normalized_verified = self.integrity_checker.verify_normalized_hash(
            event,
            normalized_hash,
        )

        chain_verified = self.integrity_checker.verify_chain_hash(
            event["raw_event"],
            previous_hash or "",
            chain_hash,
        )

        # 11. Return complete processing result
        return {
            "event": event,
            "integrity": {
                "sha256": raw_hash,
                "normalized_hash": normalized_hash,
                "hash_version": 2,
                "previous_hash": previous_hash or None,
                "chain_hash": chain_hash,
                "verified": hash_verified,
                "normalized_verified": normalized_verified,
                "chain_verified": chain_verified,
            },
            "quality": quality_result,
            "format": format_result,
        }

    def verify_event(self, event_id: str) -> Dict[str, Any] | None:
        """
        Verify the integrity of a stored event.
        """

        event = self.database.get_event(event_id)

        if event is None:
            return None

        raw_event = event.get("raw_event", "")
        raw_hash = event.get("raw_hash")
        normalized_hash = event.get("normalized_hash")
        hash_version = event.get("hash_version", 1)
        previous_hash = event.get("previous_hash") or ""
        chain_hash = event.get("chain_hash")

        hash_verified = False
        normalized_verified = True
        chain_verified = False

        if raw_hash:
            hash_verified = self.integrity_checker.verify_hash(
                raw_event,
                raw_hash,
            )

        if hash_version >= 2 and normalized_hash:
            normalized_verified = self.integrity_checker.verify_normalized_hash(
                event,
                normalized_hash,
            )

        if chain_hash:
            chain_verified = self.integrity_checker.verify_chain_hash(
                raw_event,
                previous_hash,
                chain_hash,
            )

        tamper_detected = not (hash_verified and normalized_verified and chain_verified)

        return {
            "event_id": event_id,
            "integrity_hash": raw_hash,
            "normalized_hash": normalized_hash,
            "hash_version": hash_version,
            "previous_hash": previous_hash or None,
            "chain_hash": chain_hash,
            "hash_verified": hash_verified,
            "normalized_verified": normalized_verified,
            "chain_verified": chain_verified,
            "tamper_detected": tamper_detected,
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