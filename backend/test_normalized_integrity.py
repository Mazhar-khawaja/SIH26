import pytest
from app.trust.integrity import IntegrityChecker
from app.ingestion.ingestion_manager import IngestionManager

def test_canonicalization_ordering():
    event1 = {
        "event_id": "1",
        "extensions": {"a": 1, "b": 2},
        "source_ip": "1.1.1.1"
    }
    
    event2 = {
        "source_ip": "1.1.1.1",
        "extensions": {"b": 2, "a": 1},
        "event_id": "1"
    }
    
    hash1 = IntegrityChecker.calculate_normalized_hash(event1)
    hash2 = IntegrityChecker.calculate_normalized_hash(event2)
    assert hash1 == hash2

def test_canonicalization_null_handling():
    event1 = {
        "event_id": "1",
        "extensions": {},
        "source_ip": None
    }
    
    event2 = {
        "event_id": "1",
        "extensions": {}
    }
    
    hash1 = IntegrityChecker.calculate_normalized_hash(event1)
    hash2 = IntegrityChecker.calculate_normalized_hash(event2)
    # They should NOT be equal, None is explicitly null in JSON, missing is omitted
    assert hash1 != hash2

from unittest.mock import patch, MagicMock

@patch("app.search.search_service.SearchService.__init__")
@patch("app.search.search_service.SearchService.index_event")
@patch("app.analytics.service.AnalyticsService.analyze_event")
@patch("app.integrations.siem.service.SIEMIntegrationService.forward_event")
def test_legacy_compatibility(mock_siem, mock_analytics, mock_index, mock_search_init):
    mock_search_init.return_value = None
    mock_index.return_value = True
    mock_analytics.return_value = {}
    manager = IngestionManager("sqlite:///:memory:")
    log = "TEST LEGACY LOG"
    
    raw_hash = manager.integrity_checker.calculate_hash(log)
    chain_hash = manager.integrity_checker.calculate_chain_hash(log, "")
    
    # Fake a legacy event directly into DB
    legacy_event = {
        "event_id": "legacy-1",
        "raw_event": log,
        "source_ip": "1.1.1.1"
    }
    
    # We bypass process_log to manually insert a legacy event (version=1, normalized_hash=None)
    with manager.database.get_session() as session:
        from app.storage.models import EventModel
        existing = EventModel(
            event_id=legacy_event["event_id"],
            raw_event=log,
            source_ip="1.1.1.1",
            raw_hash=raw_hash,
            hash_version=1,
            normalized_hash=None,
            previous_hash="",
            chain_hash=chain_hash
        )
        session.add(existing)
        session.commit()
    
    # Verify legacy event
    res = manager.verify_event("legacy-1")
    assert res["hash_verified"] is True
    assert res["normalized_verified"] is True
    assert res["tamper_detected"] is False

@patch("app.search.search_service.SearchService.__init__")
@patch("app.search.search_service.SearchService.index_event")
@patch("app.analytics.service.AnalyticsService.analyze_event")
@patch("app.integrations.siem.service.SIEMIntegrationService.forward_event")
def test_new_event_integrity(mock_siem, mock_analytics, mock_index, mock_search_init):
    mock_search_init.return_value = None
    mock_index.return_value = True
    mock_analytics.return_value = {}
    manager = IngestionManager("sqlite:///:memory:")
    log = '{"source_ip": "2.2.2.2", "severity": "HIGH", "action": "DROP"}'
    
    result = manager.process_log(log)
    event_id = result["event"]["event_id"]
    
    res = manager.verify_event(event_id)
    assert res["hash_version"] == 2
    assert res["hash_verified"] is True
    assert res["normalized_verified"] is True
    assert res["tamper_detected"] is False
    
    # Tamper tests
    def tamper_and_verify(field, new_value):
        with manager.database.get_session() as session:
            from app.storage.models import EventModel
            model = session.query(EventModel).filter_by(event_id=event_id).first()
            setattr(model, field, new_value)
            session.commit()
        return manager.verify_event(event_id)
    
    # B. source_ip
    res = tamper_and_verify("source_ip", "9.9.9.9")
    assert res["normalized_verified"] is False
    
    # Reset
    tamper_and_verify("source_ip", "2.2.2.2")
    
    # C. severity
    res = tamper_and_verify("severity", "LOW")
    assert res["normalized_verified"] is False
    
    # A. raw_event
    res = tamper_and_verify("raw_event", "TAMPERED")
    assert res["hash_verified"] is False
    # Since raw_event is modified, both raw_hash and chain_hash fail. normalized_hash might pass or fail depending on if raw_event is included, but it isn't. So normalized_verified is True.
    assert res["tamper_detected"] is True
