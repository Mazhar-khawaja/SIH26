import re
from typing import Any, Dict
from app.parsers.base_parser import BaseParser

class CiscoASAParser(BaseParser):
    def can_parse(self, log: str) -> bool:
        return "%ASA-" in log

    def parse(self, log: str) -> Dict[str, Any]:
        # Example format:
        # Sep 24 10:00:00 10.0.0.1 %ASA-4-106023: Deny tcp src outside:192.168.1.1/1234 dst inside:10.0.0.2/80 by access-group "acl_outside"

        parsed = {
            "source_type": "cisco:asa",
            "vendor": "Cisco",
            "product": "ASA",
            "raw_event": log,
            "extracted_data": {}
        }

        asa_regex = r"%ASA-(?P<severity>\d)-(?P<message_id>\d+):(?P<message>.*)"
        match = re.search(asa_regex, log)
        if match:
            parsed["severity"] = match.group("severity")
            parsed["event_type"] = match.group("message_id")

            message = match.group("message")
            parsed["extracted_data"]["cisco_message"] = message.strip()

            if "Deny tcp" in message or "Deny udp" in message or "Teardown" in message:
                parsed["action"] = "Deny" if "Deny" in message else "Teardown"

                # Extract IPs loosely
                src_match = re.search(r"src [a-zA-Z0-9_\-]+:(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)", message)
                if src_match:
                    parsed["source_ip"] = src_match.group("src_ip")
                    parsed["source_port"] = src_match.group("src_port")

                dst_match = re.search(r"dst [a-zA-Z0-9_\-]+:(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)", message)
                if dst_match:
                    parsed["destination_ip"] = dst_match.group("dst_ip")
                    parsed["destination_port"] = dst_match.group("dst_port")

        return parsed

    @property
    def name(self) -> str:
        return "cisco_asa"
