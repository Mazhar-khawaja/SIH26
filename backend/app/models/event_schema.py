import ipaddress
from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, Optional

class UniversalEvent(BaseModel):
    """
    Universal Event Schema for normalized security events.
    """

    event_id: str = Field(..., description="Unique ULPF event identifier")
    timestamp: Optional[str] = None
    event_type: Optional[str] = None

    source: Optional[str] = None
    source_type: Optional[str] = None

    source_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)

    destination: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = Field(None, ge=0, le=65535)

    protocol: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None

    user: Optional[str] = None
    device: Optional[str] = None
    hostname: Optional[str] = None
    application: Optional[str] = None

    vendor: Optional[str] = None
    product: Optional[str] = None
    category: Optional[str] = None

    raw_event: str = Field(..., description="Original raw event preserved without modification")

    parser: Optional[str] = None
    parser_version: Optional[str] = None
    parse_status: str = "success"

    quality_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    confidence: Optional[float] = Field(None, ge=0.0, le=100.0)

    extracted_data: Dict[str, Any] = Field(default_factory=dict)

    integrity_hash: Optional[str] = None
    normalized_hash: Optional[str] = None
    hash_version: int = 1
    previous_hash: Optional[str] = None
    chain_hash: Optional[str] = None

    extensions: Dict[str, Any] = Field(default_factory=dict, description="Vendor specific fields")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Processing metadata")

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip() or v == "-":
            return None
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v