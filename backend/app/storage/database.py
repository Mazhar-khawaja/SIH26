import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy import create_engine, desc, text
from sqlalchemy.orm import sessionmaker, Session

from app.storage.models import Base, EventModel, ChainState
from app.config.settings import settings

class Database:
    """
    SQLAlchemy storage layer for ULPF.

    Supports SQLite for development and PostgreSQL for production.
    """

    def __init__(self, database_path: Optional[str] = None, database_url: Optional[str] = None) -> None:
        url = database_url or settings.database_url
        if database_path:
            if database_path.startswith("sqlite://") or database_path.startswith("postgresql://"):
                # Force psycopg2 for SQLAlchemy 2.0+ compatibility
                url = database_path.replace("postgresql://", "postgresql+psycopg2://")
            else:
                url = f"sqlite:///{database_path}"

        # SQLite needs check_same_thread=False for FastAPI
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
            # Extract path and create parent directory
            if url != "sqlite:///:memory:":
                db_path = url.replace("sqlite:///", "")
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        url = url.replace("postgresql://", "postgresql+psycopg2://")
        self.engine = create_engine(url, connect_args=connect_args)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self._create_tables()

    def _create_tables(self) -> None:
        """
        Create tables if they don't exist.
        """
        Base.metadata.create_all(bind=self.engine)

        with self.engine.connect() as conn:
            existing_columns = set()
            if self.engine.dialect.name == "sqlite":
                result = conn.execute(text("PRAGMA table_info(events)"))
                existing_columns = {row[1] for row in result.fetchall()}
            elif self.engine.dialect.name == "postgresql":
                result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'events'"))
                existing_columns = {row[0] for row in result.fetchall()}

            if existing_columns:
                from app.storage.models import EventModel
                import sqlalchemy

                for col in EventModel.__table__.columns:
                    col_name = col.name
                    if col_name not in existing_columns:
                        if isinstance(col.type, sqlalchemy.Integer):
                            if col_name == "hash_version":
                                col_type = "INTEGER DEFAULT 1"
                            else:
                                col_type = "INTEGER"
                        elif isinstance(col.type, sqlalchemy.Float):
                            col_type = "DOUBLE PRECISION" if self.engine.dialect.name == "postgresql" else "FLOAT"
                        elif isinstance(col.type, sqlalchemy.DateTime):
                            col_type = "TIMESTAMP"
                        else:
                            col_type = "VARCHAR"

                        conn.execute(text(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}"))
                conn.commit()

    def get_session(self) -> Session:
        return self.SessionLocal()

    def save_event(
        self,
        event: Dict[str, Any],
        raw_hash: str | None = None,
        quality: Dict[str, Any] | None = None,
        format: Dict[str, Any] | None = None,
        integrity_callback: Optional[Any] = None,
        # Keep old kwargs for backward compatibility if needed, but not used in the callback flow
        previous_hash: str | None = None,
        chain_hash: str | None = None,
    ) -> tuple[Optional[str], Optional[str]]:
        quality = quality or {}
        format = format or {}
        detected_format = format.get("format")

        with self.get_session() as session:
            # Handle chain state for concurrency
            if integrity_callback:
                query = session.query(ChainState).filter_by(id=1)
                if self.engine.dialect.name == "postgresql":
                    query = query.with_for_update()

                state = query.first()
                if not state:
                    state = ChainState(id=1, latest_chain_hash="")
                    session.add(state)
                    session.flush()

                prev_h = state.latest_chain_hash or ""
                calc_chain_h = integrity_callback(event.get("raw_event"), prev_h)

                previous_hash = prev_h if prev_h else None
                chain_hash = calc_chain_h

                state.latest_chain_hash = chain_hash

            # Handle INSERT OR REPLACE semantics
            existing = session.query(EventModel).filter_by(event_id=event.get("event_id")).first()
            if not existing:
                existing = EventModel(event_id=event.get("event_id"))
                session.add(existing)

            existing.timestamp = event.get("timestamp")
            existing.source = event.get("source")
            existing.source_type = event.get("source_type")
            existing.source_ip = event.get("source_ip")
            existing.source_port = event.get("source_port")
            existing.destination = event.get("destination")
            existing.destination_ip = event.get("destination_ip")
            existing.destination_port = event.get("destination_port")
            existing.protocol = event.get("protocol")
            existing.event_type = event.get("event_type")
            existing.action = event.get("action")
            existing.severity = event.get("severity")

            existing.user = event.get("user")
            existing.device = event.get("device")
            existing.hostname = event.get("hostname")
            existing.application = event.get("application")
            existing.vendor = event.get("vendor")
            existing.product = event.get("product")
            existing.category = event.get("category")
            existing.parser_version = event.get("parser_version")
            existing.confidence = event.get("confidence")

            existing.raw_event = event.get("raw_event")
            existing.extracted_data = json.dumps(event.get("extracted_data") or {})
            existing.extensions = json.dumps(event.get("extensions") or {})
            existing.metadata_fields = json.dumps(event.get("metadata") or {})
            existing.raw_hash = raw_hash
            existing.normalized_hash = event.get("normalized_hash")
            existing.hash_version = event.get("hash_version", 1)
            existing.previous_hash = previous_hash
            existing.chain_hash = chain_hash
            existing.parser = event.get("parser")
            existing.parse_status = event.get("parse_status")
            existing.quality_status = quality.get("status")
            existing.quality_score = quality.get("quality_score")
            existing.format = detected_format

            session.commit()

            return previous_hash, chain_hash

    def _model_to_dict(self, model: EventModel) -> Dict[str, Any]:
        result = {c.name: getattr(model, c.name) for c in model.__table__.columns}
        if result.get("extracted_data"):
            result["extracted_data"] = json.loads(result["extracted_data"])
        if result.get("extensions") and isinstance(result["extensions"], str):
            result["extensions"] = json.loads(result["extensions"])
        if result.get("metadata_fields") and isinstance(result["metadata_fields"], str):
            result["metadata"] = json.loads(result["metadata_fields"])
        elif "metadata_fields" in result:
            result["metadata"] = result["metadata_fields"]
        # Format created_at to string to match SQLite behaviour in legacy code
        if result.get("created_at"):
            result["created_at"] = result["created_at"].strftime('%Y-%m-%d %H:%M:%S')
        return result

    def get_event(self, event_id: str) -> Dict[str, Any] | None:
        with self.get_session() as session:
            model = session.query(EventModel).filter_by(event_id=event_id).first()
            if not model:
                return None
            return self._model_to_dict(model)

    def get_all_events(self) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            models = session.query(EventModel).order_by(desc(EventModel.created_at)).all()
            return [self._model_to_dict(m) for m in models]

    def count_events(self) -> int:
        with self.get_session() as session:
            return session.query(EventModel).count()

    def get_latest_chain_hash(self) -> str | None:
        with self.get_session() as session:
            model = session.query(EventModel).filter(
                EventModel.chain_hash.isnot(None)
            ).order_by(
                desc(EventModel.created_at)
            ).first()
            if not model:
                return None
            return model.chain_hash

    def clear_events(self) -> None:
        with self.get_session() as session:
            session.query(EventModel).delete()
            session.commit()

    # --- Intelligence Persistence Methods ---

    def save_approval(self, approval_dict: Dict[str, Any]) -> None:
        from app.storage.models import MappingApprovalModel
        with self.get_session() as session:
            existing = session.query(MappingApprovalModel).filter_by(approval_id=approval_dict["approval_id"]).first()
            if not existing:
                existing = MappingApprovalModel(approval_id=approval_dict["approval_id"])
                session.add(existing)

            existing.classification_id = approval_dict.get("classification_id")
            existing.log = approval_dict.get("log")
            existing.format_prediction = approval_dict.get("format_prediction")
            existing.status = approval_dict.get("status")
            existing.suggestions = json.dumps(approval_dict.get("suggestions", []))
            existing.approved_by = approval_dict.get("approved_by")
            existing.approved_at = approval_dict.get("approved_at")
            existing.rejected_by = approval_dict.get("rejected_by")
            existing.rejected_at = approval_dict.get("rejected_at")
            existing.notes = approval_dict.get("notes")

            session.commit()

    def get_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        from app.storage.models import MappingApprovalModel
        with self.get_session() as session:
            model = session.query(MappingApprovalModel).filter_by(approval_id=approval_id).first()
            if not model:
                return None
            result = {c.name: getattr(model, c.name) for c in model.__table__.columns}
            if result.get("suggestions"):
                result["suggestions"] = json.loads(result["suggestions"])
            if result.get("created_at"):
                result["created_at"] = result["created_at"].isoformat()
            return result

    def list_approvals(self) -> List[Dict[str, Any]]:
        from app.storage.models import MappingApprovalModel
        with self.get_session() as session:
            models = session.query(MappingApprovalModel).order_by(desc(MappingApprovalModel.created_at)).all()
            results = []
            for model in models:
                res = {c.name: getattr(model, c.name) for c in model.__table__.columns}
                if res.get("suggestions"):
                    res["suggestions"] = json.loads(res["suggestions"])
                if res.get("created_at"):
                    res["created_at"] = res["created_at"].isoformat()
                results.append(res)
            return results