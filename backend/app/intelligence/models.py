from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid
from datetime import datetime, timezone

class ClassificationResult(BaseModel):
    classification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    format: str = "unknown"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    matched_patterns: List[str] = Field(default_factory=list)
    suggested_parser: Optional[Dict[str, Any]] = None
    status: str = "suggestion"

class FieldMappingSuggestion(BaseModel):
    source_field: str
    target_field: str
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reason: str

class MappingApproval(BaseModel):
    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    classification_id: str
    log: str
    format_prediction: str
    suggestions: List[FieldMappingSuggestion] = Field(default_factory=list)
    status: str = "suggestion" # suggestion, approved, rejected
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rejected_by: Optional[str] = None
    rejected_at: Optional[str] = None
    notes: Optional[str] = None
