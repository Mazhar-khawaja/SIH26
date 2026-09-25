from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.intelligence.providers.local import LocalProvider
from app.intelligence.models import ClassificationResult, MappingApproval, FieldMappingSuggestion
from app.config.settings import settings
from app.monitoring.logger import get_logger
from app.storage.database import Database

logger = get_logger("ulpf.intelligence.service")

class IntelligenceService:
    def __init__(self, database: Optional[Database] = None):
        self.provider = LocalProvider()
        self.db = database or Database()

    def classify_log(self, log: str) -> ClassificationResult:
        if not settings.intelligence_enabled:
            return ClassificationResult(
                reasons=["Intelligence module is disabled by configuration"]
            )
        try:
            return self.provider.classify_format(log)
        except Exception as e:
            logger.error("Provider classification failed", error=e)
            return ClassificationResult(reasons=["Internal classification error"])

    def generate_mapping(self, log: str, format_hint: str) -> MappingApproval:
        try:
            suggestions = self.provider.suggest_field_mapping(log, format_hint)
            result = self.classify_log(log)

            approval = MappingApproval(
                classification_id=result.classification_id,
                log=log,
                format_prediction=result.format,
                suggestions=suggestions
            )

            self.db.save_approval(approval.model_dump())
            return approval
        except Exception as e:
            logger.error("Mapping generation failed", error=e)
            raise e

    def get_approval(self, approval_id: str) -> Optional[MappingApproval]:
        data = self.db.get_approval(approval_id)
        if not data:
            return None
        return MappingApproval(**data)

    def list_approvals(self) -> List[MappingApproval]:
        records = self.db.list_approvals()
        return [MappingApproval(**r) for r in records]

    def approve_mapping(self, approval_id: str, username: str) -> Optional[MappingApproval]:
        approval = self.get_approval(approval_id)
        if not approval:
            return None
        approval.status = "approved"
        approval.approved_by = username
        approval.approved_at = datetime.now(timezone.utc).isoformat()
        self.db.save_approval(approval.model_dump())
        return approval

    def reject_mapping(self, approval_id: str, username: str) -> Optional[MappingApproval]:
        approval = self.get_approval(approval_id)
        if not approval:
            return None
        approval.status = "rejected"
        approval.rejected_by = username
        approval.rejected_at = datetime.now(timezone.utc).isoformat()
        self.db.save_approval(approval.model_dump())
        return approval
