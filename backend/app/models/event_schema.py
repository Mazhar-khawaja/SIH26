from pydantic import BaseModel, Field
from typing import Any, Dict, Optional


class UniversalEvent(BaseModel):
    """
    Universal Event Schema for normalized security events.
    """

    event_id: str = Field(..., description="Unique ULPF event identifier")

    timestamp: Optional[str] = None

    source: Optional[str] = None
    source_type: Optional[str] = None

    source_ip: Optional[str] = None
    source_port: Optional[int] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    protocol: Optional[str] = None

    event_type: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None

    extracted_data: Dict[str, Any] = Field(default_factory=dict)

    raw_event: str = Field(
        ...,
        description="Original raw event preserved without modification"
    )

    parser: Optional[str] = None
    parse_status: str = "success"

    # Tamper-Evident Log fields
    integrity_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    chain_hash: Optional[str] = None