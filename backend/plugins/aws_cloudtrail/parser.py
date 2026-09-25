import json
from typing import Any, Dict
from app.parsers.base_parser import BaseParser

class AWSCloudTrailParser(BaseParser):
    def can_parse(self, log: str) -> bool:
        try:
            data = json.loads(log)
            if "Records" in data and isinstance(data["Records"], list):
                if len(data["Records"]) > 0 and "eventSource" in data["Records"][0]:
                    return data["Records"][0].get("eventSource") == "s3.amazonaws.com" or "amazonaws.com" in data["Records"][0].get("eventSource", "")
        except:
            pass
        return False

    def parse(self, log: str) -> Dict[str, Any]:
        data = json.loads(log)
        record = data["Records"][0]

        return {
            "source_type": "aws:cloudtrail",
            "vendor": "AWS",
            "product": "CloudTrail",
            "timestamp": record.get("eventTime"),
            "event_type": record.get("eventName"),
            "action": "API_CALL",
            "source_ip": record.get("sourceIPAddress"),
            "user": record.get("userIdentity", {}).get("principalId") or record.get("userIdentity", {}).get("userName"),
            "application": record.get("userAgent"),
            "severity": "INFO" if not record.get("errorCode") else "ERROR",
            "raw_event": log,
            "extracted_data": {
                "requestID": record.get("requestID"),
                "eventID": record.get("eventID"),
                "awsRegion": record.get("awsRegion")
            }
        }

    @property
    def name(self) -> str:
        return "aws_cloudtrail"
