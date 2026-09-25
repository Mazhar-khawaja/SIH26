from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class EventModel(Base):
    __tablename__ = "events"

    event_id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, index=True)
    source = Column(String)
    source_type = Column(String)
    source_ip = Column(String, index=True)
    source_port = Column(Integer)
    destination_ip = Column(String, index=True)
    destination_port = Column(Integer)
    protocol = Column(String)
    event_type = Column(String, index=True)
    action = Column(String)
    severity = Column(String)
    raw_event = Column(String, nullable=False)
    extracted_data = Column(String)
    extensions = Column(String)
    metadata_fields = Column(String)

    raw_hash = Column(String)
    previous_hash = Column(String)
    chain_hash = Column(String)

    user = Column(String)
    device = Column(String)
    hostname = Column(String)
    application = Column(String)

    vendor = Column(String)
    product = Column(String)
    category = Column(String)

    parser = Column(String)
    parser_version = Column(String)
    parse_status = Column(String)

    quality_status = Column(String)
    quality_score = Column(Integer)
    confidence = Column(Integer)

    format = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class ChainState(Base):
    __tablename__ = "chain_state"

    id = Column(Integer, primary_key=True)
    latest_chain_hash = Column(String)

class MappingApprovalModel(Base):
    __tablename__ = "mapping_approvals"

    approval_id = Column(String, primary_key=True, index=True)
    classification_id = Column(String)
    log = Column(String, nullable=False)
    format_prediction = Column(String)
    status = Column(String)
    suggestions = Column(String) # Stored as JSON string
    approved_by = Column(String)
    approved_at = Column(String)
    rejected_by = Column(String)
    rejected_at = Column(String)
    notes = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
