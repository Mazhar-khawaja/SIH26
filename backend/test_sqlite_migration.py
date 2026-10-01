import os
import sqlite3
import pytest
from app.ingestion.ingestion_manager import IngestionManager
from app.trust.integrity import IntegrityChecker

@pytest.fixture
def legacy_db_path(tmp_path):
    db_path = tmp_path / "legacy_ulpf.db"
    
    # Create the old schema
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE events (
            event_id VARCHAR PRIMARY KEY,
            timestamp VARCHAR,
            source VARCHAR,
            source_type VARCHAR,
            source_ip VARCHAR,
            source_port INTEGER,
            destination_ip VARCHAR,
            destination_port INTEGER,
            protocol VARCHAR,
            event_type VARCHAR,
            action VARCHAR,
            severity VARCHAR,
            raw_event VARCHAR NOT NULL,
            extracted_data VARCHAR,
            extensions VARCHAR,
            metadata_fields VARCHAR,
            raw_hash VARCHAR,
            chain_hash VARCHAR,
            user VARCHAR,
            device VARCHAR,
            hostname VARCHAR,
            application VARCHAR,
            vendor VARCHAR,
            product VARCHAR,
            category VARCHAR,
            parser VARCHAR,
            parser_version VARCHAR,
            parse_status VARCHAR,
            quality_status VARCHAR,
            quality_score INTEGER,
            confidence FLOAT,
            format VARCHAR,
            created_at DATETIME
        )
    """)
    
    # Insert a legacy event
    raw_event = "legacy raw log string"
    raw_hash = IntegrityChecker.calculate_hash(raw_event)
    chain_hash = IntegrityChecker.calculate_chain_hash(raw_event, "")
    
    cursor.execute("""
        INSERT INTO events (
            event_id, raw_event, raw_hash, chain_hash, extracted_data, extensions, metadata_fields
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, ("legacy-1", raw_event, raw_hash, chain_hash, "{}", "{}", "{}"))
    
    cursor.execute("""
        CREATE TABLE chain_state (
            id INTEGER PRIMARY KEY,
            latest_chain_hash VARCHAR
        )
    """)
    cursor.execute("INSERT INTO chain_state (id, latest_chain_hash) VALUES (1, ?)", (chain_hash,))
    
    conn.commit()
    conn.close()
    
    return str(db_path)

def test_sqlite_schema_migration(legacy_db_path):
    # Initialize app pointing to legacy DB
    manager = IngestionManager(f"sqlite:///{legacy_db_path}")
    
    # Verify missing columns were added
    conn = sqlite3.connect(legacy_db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(events)")
    columns = {row[1] for row in cursor.fetchall()}
    conn.close()
    
    assert "destination" in columns
    assert "normalized_hash" in columns
    assert "hash_version" in columns
    assert "previous_hash" in columns
    
    # Verify the old event is still present and valid
    legacy_event = manager.get_event("legacy-1")
    assert legacy_event is not None
    assert legacy_event["raw_event"] == "legacy raw log string"
    assert legacy_event["hash_version"] == 1
    assert legacy_event["normalized_hash"] is None
    
    # Legacy event should pass verification
    ver_res = manager.verify_event("legacy-1")
    assert ver_res["hash_verified"] is True
    assert ver_res["chain_verified"] is True
    assert ver_res["tamper_detected"] is False
    
    # Process a NEW event
    new_res = manager.process_log("new raw log string")
    new_event_id = new_res["event"]["event_id"]
    
    new_event = manager.get_event(new_event_id)
    assert new_event is not None
    assert new_event["hash_version"] == 2
    assert new_event["normalized_hash"] is not None
    assert new_event["previous_hash"] is not None
    assert new_event["chain_hash"] is not None
    
    new_ver = manager.verify_event(new_event_id)
    assert new_ver["hash_verified"] is True
    assert new_ver["normalized_verified"] is True
    assert new_ver["chain_verified"] is True
    assert new_ver["tamper_detected"] is False
