import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


class Database:
    """
    SQLite storage layer for ULPF.

    Stores the original raw event, its normalized representation,
    and tamper-evident integrity information.
    """

    def __init__(self, database_path: str = "data/ulpf.db") -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._create_tables()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path)

    def _create_tables(self) -> None:
        """
        Create the events table if it does not already exist.
        """

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    source TEXT,
                    source_type TEXT,
                    source_ip TEXT,
                    source_port INTEGER,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol TEXT,
                    event_type TEXT,
                    action TEXT,
                    severity TEXT,
                    raw_event TEXT NOT NULL,
                    extracted_data TEXT,
                    raw_hash TEXT,
                    previous_hash TEXT,
                    chain_hash TEXT,
                    parser TEXT,
                    parse_status TEXT,
                    quality_status TEXT,
                    quality_score INTEGER,
                    format TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            connection.commit()

            # Add tamper-evident columns to an existing database
            # if they are missing.
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(events)"
                ).fetchall()
            }

            if "previous_hash" not in columns:
                connection.execute(
                    "ALTER TABLE events ADD COLUMN previous_hash TEXT"
                )

            if "chain_hash" not in columns:
                connection.execute(
                    "ALTER TABLE events ADD COLUMN chain_hash TEXT"
                )

            if "extracted_data" not in columns:
                connection.execute(
                    "ALTER TABLE events ADD COLUMN extracted_data TEXT"
                )

            if "format" not in columns:
                connection.execute(
                    "ALTER TABLE events ADD COLUMN format TEXT"
                )

            connection.commit()

    def save_event(
        self,
        event: Dict[str, Any],
        raw_hash: str | None = None,
        quality: Dict[str, Any] | None = None,
        previous_hash: str | None = None,
        chain_hash: str | None = None,
        format: Dict[str, Any] | None = None,
    ) -> None:
        """
        Store a normalized event and its integrity information.
        """

        quality = quality or {}
        format = format or {}
        detected_format = format.get("format")

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id,
                    timestamp,
                    source,
                    source_type,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    protocol,
                    event_type,
                    action,
                    severity,
                    raw_event,
                    extracted_data,
                    raw_hash,
                    previous_hash,
                    chain_hash,
                    parser,
                    parse_status,
                    quality_status,
                    quality_score,
                    format
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("event_id"),
                    event.get("timestamp"),
                    event.get("source"),
                    event.get("source_type"),
                    event.get("source_ip"),
                    event.get("source_port"),
                    event.get("destination_ip"),
                    event.get("destination_port"),
                    event.get("protocol"),
                    event.get("event_type"),
                    event.get("action"),
                    event.get("severity"),
                    event.get("raw_event"),
                    json.dumps(event.get("extracted_data") or {}),
                    raw_hash,
                    previous_hash,
                    chain_hash,
                    event.get("parser"),
                    event.get("parse_status"),
                    quality.get("status"),
                    quality.get("quality_score"),
                    detected_format,
                ),
            )

            connection.commit()

    def get_event(self, event_id: str) -> Dict[str, Any] | None:
        """
        Retrieve one event using its Event ID.
        """

        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                "SELECT * FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()

            if row is None:
                return None

            return dict(row)

    def get_all_events(self) -> List[Dict[str, Any]]:
        """
        Retrieve all stored events.
        """

        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT *
                FROM events
                ORDER BY created_at DESC
                """
            ).fetchall()

            return [dict(row) for row in rows]

    def count_events(self) -> int:
        """
        Return the total number of stored events.
        """

        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()

            return int(row[0])

    def get_latest_chain_hash(self) -> str | None:
        """
        Return the chain hash of the most recently stored event.
        """

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT chain_hash
                FROM events
                WHERE chain_hash IS NOT NULL
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1
                """
            ).fetchone()

            if row is None:
                return None

            return row[0]

    def clear_events(self) -> None:
        """
        Remove all stored events.
        """

        with self._connect() as connection:
            connection.execute("DELETE FROM events")
            connection.commit()
    def close(self) -> None:
        """
        Close the database connection.

        Database operations use short-lived connections, so there is
        normally no persistent connection to close. This method exists
        for compatibility with tests and callers that expect an
        explicit cleanup operation.
        """
        return None