import json
import re
from typing import Any, Dict


class UnknownFormatDetector:
    """Explainable detector for supported and unsupported log formats."""

    SUPPORTED_FORMATS = {"syslog", "json", "cef"}

    def extract_identifiable_data(self, log: str) -> Dict[str, str]:
        """Extract generic key=value pairs even when the format is unsupported."""
        extracted: Dict[str, str] = {}
        for key, value in re.findall(r"(?:^|[|\s])([A-Za-z_][A-Za-z0-9_-]*)=([^|\s]+)", log.strip()):
            extracted[key] = value.strip().strip('\"\'')
        return extracted

    def detect(self, log: str) -> Dict[str, Any]:
        if not log or not log.strip():
            return {
                "status": "invalid",
                "supported": False,
                "format": "unknown",
                "confidence": 0.0,
                "message": "Log is empty",
                "candidates": [],
            }

        log = log.strip()
        extracted_data = self.extract_identifiable_data(log)
        candidates = []

        if log.startswith("CEF:"):
            candidates.append({
                "format": "cef",
                "confidence": 1.0,
                "reason": "Log starts with the CEF signature 'CEF:'.",
            })

        try:
            parsed = json.loads(log)
            if isinstance(parsed, dict):
                candidates.append({
                    "format": "json",
                    "confidence": 1.0,
                    "reason": "Log is valid JSON containing an object.",
                })
        except (json.JSONDecodeError, TypeError):
            pass

        if re.match(r"^<\d+>", log):
            candidates.append({
                "format": "syslog",
                "confidence": 1.0,
                "reason": "Log starts with a Syslog priority value such as <134>.",
            })

        key_value_matches = re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_-]*)=([^\s]+)", log
        )
        if key_value_matches:
            candidates.append({
                "format": "vendor-key-value",
                "confidence": 0.75,
                "reason": "Log contains key=value fields but does not match a supported format.",
            })

        if "|" in log and len(log.split("|")) >= 2:
            candidates.append({
                "format": "pipe-delimited",
                "confidence": 0.70,
                "reason": "Log contains multiple pipe-separated sections.",
            })

        if log.startswith("<") and log.endswith(">") and re.search(r"<[A-Za-z][^>]*>", log):
            candidates.append({
                "format": "xml",
                "confidence": 0.70,
                "reason": "Log appears to contain XML-style tags.",
            })

        if "," in log and "=" not in log and len(log.split(",")) >= 3:
            candidates.append({
                "format": "csv-like",
                "confidence": 0.60,
                "reason": "Log contains several comma-separated values.",
            })

        supported = [c for c in candidates if c["format"] in self.SUPPORTED_FORMATS]
        if supported:
            best = max(supported, key=lambda c: c["confidence"])
            return {
                "status": "supported",
                "supported": True,
                "format": best["format"],
                "confidence": best["confidence"],
                "message": f"Detected supported format: {best['format']}",
                "reason": best["reason"],
                "candidates": candidates,
                "extracted_data": extracted_data,
            }

        if candidates:
            best = max(candidates, key=lambda c: c["confidence"])
            return {
                "status": "unknown",
                "supported": False,
                "format": "unknown",
                "confidence": best["confidence"],
                "message": "Format is not currently supported by ULPF.",
                "reason": best["reason"],
                "suggested_format": best["format"],
                "suggestion": (
                    f"The log appears to be {best['format']}. "
                    "A dedicated parser can be added in a future version."
                ),
                "candidates": candidates,
                "extracted_data": extracted_data,
            }

        return {
            "status": "unknown",
            "supported": False,
            "format": "unknown",
            "confidence": 0.0,
            "message": "Unable to identify the log format.",
            "reason": "The log does not match any known format signature.",
            "suggested_format": None,
            "suggestion": "Analyze the vendor documentation and create a dedicated parser for this format.",
            "candidates": [],
            "extracted_data": extracted_data,
        }

    def check(self, parser_name: str | None, raw_log: str | None = None) -> Dict[str, Any]:
        if parser_name:
            parser_lower = parser_name.lower()
            if parser_lower in self.SUPPORTED_FORMATS:
                return {
                    "status": "supported",
                    "supported": True,
                    "format": parser_lower,
                    "confidence": 1.0,
                    "message": f"Supported format: {parser_lower}",
                    "reason": "ULPF parser successfully recognized the log.",
                    "extracted_data": self.extract_identifiable_data(raw_log or ""),
                    "candidates": [{
                        "format": parser_lower,
                        "confidence": 1.0,
                        "reason": "ULPF parser successfully recognized the log.",
                    }],
                }

        return self.detect(raw_log or "")
