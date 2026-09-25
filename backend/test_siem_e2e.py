import time
import requests
import sys
import os
import subprocess
sys.path.insert(0, os.path.abspath('./test'))
from mock_siem_server import app
from app.ingestion.ingestion_manager import IngestionManager
from app.config.settings import settings
from app.storage.database import Database

if __name__ == "__main__":
    print("--- STARTING MOCK SIEM ---")

    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "mock_siem_server:app", "--app-dir", "test", "--host", "127.0.0.1", "--port", "9999"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(3) # wait for server to start

    try:
        settings.siem_enabled = True
        settings.siem_url = "http://127.0.0.1:9999/events"
        settings.analytics_enabled = True # to include analytics

        # clear db for clean test
        db = Database()
        db.clear_events()

        print("--- SENDING EVENT TO INGESTION MANAGER ---")
        manager = IngestionManager()

        log = '<34>Oct 11 22:14:15 mymachine su: su root failed for joe on /dev/pts/2'

        # 1. process_log
        res = manager.process_log(log)
        event_id = res["event"]["event_id"]
        integrity_hash = res["integrity"]["sha256"]

        print(f"Ingested event: {event_id}")
        print(f"Integrity hash: {integrity_hash}")

        # 2. Check SIEM received
        print("--- FETCHING FROM MOCK SIEM ---")
        siem_resp = requests.get("http://127.0.0.1:9999/events")
        siem_data = siem_resp.json()

        assert len(siem_data) == 1, "SIEM should have received 1 event"
        siem_event = siem_data[0]

        assert siem_event["event_id"] == event_id, "Event ID mismatch"
        assert siem_event["integrity_hash"] == integrity_hash, "Integrity Hash mismatch"
        assert siem_event["raw_event"] == log, "Raw event was altered!"
        print("SUCCESS: Mock SIEM received the exact UniversalEvent structure!")

        # 3. Simulate SIEM Outage
        print("--- SIMULATING SIEM OUTAGE ---")
        settings.siem_url = "http://127.0.0.1:9998/events" # wrong port

        log2 = '<34>Oct 11 22:15:15 mymachine su: su admin failed'
        res2 = manager.process_log(log2)
        event_id_2 = res2["event"]["event_id"]

        print(f"Ingested event 2 (SIEM unreachable): {event_id_2}")

        db_event = db.get_event(event_id_2)
        assert db_event is not None, "Event MUST be in primary DB even if SIEM fails!"
        print("SUCCESS: Primary DB still contains the event after SIEM failure!")
        print("SUCCESS: Core ingestion does NOT block or crash when SIEM is unreachable!")

        print("\n--- ALL E2E TESTS PASSED ---")
    except Exception as e:
        print(f"FAILED: {e}")
    finally:
        server_process.terminate()
        server_process.wait()
