import json
import re
from typing import Any, Dict, Iterable


class UnknownFormatDetector:
    """
    Explainable detector for supported and unsupported log formats.

    The detector can receive the currently registered parser formats so that
    parser support and format-analysis support do not become inconsistent.
    """

    DEFAULT_SUPPORTED_FORMATS = {
        "syslog",
        "json",
        "cef",
        "xml",
        "csv",
        "leef",
    }

    FIELD_ALIASES = {
        "source_ip": [
            "source_ip",
            "src_ip",
            "src",
            "source",
            "sourceaddress",
            "sourceaddressip",
            "sourceip",
            "srcaddress",
        ],
        "destination_ip": [
            "destination_ip",
            "dst_ip",
            "dst",
            "destination",
            "destinationaddress",
            "destinationip",
            "dstaddress",
        ],
        "source_port": [
            "source_port",
            "src_port",
            "sport",
            "sourceport",
            "source_port_number",
        ],
        "destination_port": [
            "destination_port",
            "dst_port",
            "dport",
            "destinationport",
            "destination_port_number",
        ],
        "protocol": [
            "protocol",
            "proto",
        ],
        "action": [
            "action",
            "act",
        ],
        "severity": [
            "severity",
            "sev",
            "level",
        ],
        "timestamp": [
            "timestamp",
            "time",
            "eventtime",
            "devtime",
            "date",
        ],
        "event_type": [
            "event_type",
            "eventtype",
            "event_name",
            "eventname",
            "eventid",
            "event_id",
            "type",
        ],
    }

    def __init__(
        self,
        supported_formats: Iterable[str] | None = None,
    ) -> None:
        self.supported_formats = {
            str(value).lower()
            for value in (
                supported_formats
                if supported_formats is not None
                else self.DEFAULT_SUPPORTED_FORMATS
            )
        }

    def update_supported_formats(
        self,
        supported_formats: Iterable[str],
    ) -> None:
        self.supported_formats = {
            str(value).lower()
            for value in supported_formats
        }

    def extract_identifiable_data(
        self,
        log: str,
    ) -> Dict[str, str]:
        """Extract generic key=value pairs."""
        extracted: Dict[str, str] = {}

        pattern = (
            r"(?:^|[|\s])"
            r"([A-Za-z_][A-Za-z0-9_-]*)="
            r"([^|\s]+)"
        )

        for key, value in re.findall(pattern, log.strip()):
            extracted[key] = value.strip().strip("\"'")

        return extracted

    def suggest_field_mappings(
        self,
        extracted_data: Dict[str, Any],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Suggest mappings from vendor/source field names to ULPF fields.

        This is deterministic and explainable; it does not pretend to be
        an AI model.
        """
        suggestions: Dict[str, Dict[str, Any]] = {}

        normalized_keys = {
            str(key).lower().replace("-", "_"): key
            for key in extracted_data
        }

        for target_field, aliases in self.FIELD_ALIASES.items():
            for alias in aliases:
                normalized_alias = alias.lower().replace("-", "_")

                if normalized_alias in normalized_keys:
                    original_key = normalized_keys[normalized_alias]

                    suggestions[target_field] = {
                        "source_field": original_key,
                        "confidence": 1.0
                        if normalized_alias == target_field
                        else 0.90,
                        "reason": (
                            f"Field '{original_key}' matches the "
                            f"known alias for '{target_field}'."
                        ),
                    }
                    break

        return suggestions

    def _build_candidates(
        self,
        log: str,
    ) -> list[Dict[str, Any]]:
        candidates: list[Dict[str, Any]] = []

        if log.startswith("CEF:"):
            candidates.append(
                {
                    "format": "cef",
                    "confidence": 1.0,
                    "reason": "Log starts with the CEF signature 'CEF:'.",
                }
            )

        if log.startswith("LEEF:"):
            candidates.append(
                {
                    "format": "leef",
                    "confidence": 1.0,
                    "reason": "Log starts with the LEEF signature 'LEEF:'.",
                }
            )

        try:
            parsed = json.loads(log)

            if isinstance(parsed, dict):
                candidates.append(
                    {
                        "format": "json",
                        "confidence": 1.0,
                        "reason": (
                            "Log is valid JSON containing an object."
                        ),
                    }
                )
        except (json.JSONDecodeError, TypeError):
            pass

        if re.match(r"^<\d+>", log):
            candidates.append(
                {
                    "format": "syslog",
                    "confidence": 1.0,
                    "reason": (
                        "Log starts with a Syslog priority value."
                    ),
                }
            )

        if (
            log.startswith("<")
            and log.endswith(">")
            and re.search(r"<[A-Za-z][^>]*>", log)
        ):
            candidates.append(
                {
                    "format": "xml",
                    "confidence": 0.90,
                    "reason": (
                        "Log appears to contain XML-style tags."
                    ),
                }
            )

        if "," in log and "=" not in log:
            parts = log.split(",")

            if len(parts) >= 3:
                candidates.append(
                    {
                        "format": "csv",
                        "confidence": 0.70,
                        "reason": (
                            "Log contains several comma-separated "
                            "fields."
                        ),
                    }
                )

        key_value_matches = re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_-]*)=([^\s]+)",
            log,
        )

        if key_value_matches:
            candidates.append(
                {
                    "format": "vendor-key-value",
                    "confidence": 0.75,
                    "reason": (
                        "Log contains key=value fields but does not "
                        "match a known structured signature."
                    ),
                }
            )

        if "|" in log and len(log.split("|")) >= 2:
            candidates.append(
                {
                    "format": "pipe-delimited",
                    "confidence": 0.70,
                    "reason": (
                        "Log contains multiple pipe-separated sections."
                    ),
                }
            )

        return candidates

    def detect(self, log: str) -> Dict[str, Any]:
        if not log or not log.strip():
            return {
                "status": "invalid",
                "supported": False,
                "format": "unknown",
                "confidence": 0.0,
                "message": "Log is empty",
                "candidates": [],
                "extracted_data": {},
                "field_mapping_suggestions": {},
            }

        log = log.strip()

        extracted_data = self.extract_identifiable_data(log)
        field_mapping_suggestions = self.suggest_field_mappings(
            extracted_data
        )

        candidates = self._build_candidates(log)

        supported_candidates = [
            candidate
            for candidate in candidates
            if candidate["format"].lower()
            in self.supported_formats
        ]

        if supported_candidates:
            best = max(
                supported_candidates,
                key=lambda candidate: candidate["confidence"],
            )

            return {
                "status": "supported",
                "supported": True,
                "format": best["format"],
                "confidence": best["confidence"],
                "message": (
                    f"Detected supported format: "
                    f"{best['format']}"
                ),
                "reason": best["reason"],
                "candidates": candidates,
                "extracted_data": extracted_data,
                "field_mapping_suggestions": (
                    field_mapping_suggestions
                ),
            }

        if candidates:
            best = max(
                candidates,
                key=lambda candidate: candidate["confidence"],
            )

            return {
                "status": "unknown",
                "supported": False,
                "format": "unknown",
                "confidence": best["confidence"],
                "message": (
                    "Format is not currently supported by ULPF."
                ),
                "reason": best["reason"],
                "suggested_format": best["format"],
                "suggestion": (
                    f"The log appears to be "
                    f"{best['format']}."
                ),
                "candidates": candidates,
                "extracted_data": extracted_data,
                "field_mapping_suggestions": (
                    field_mapping_suggestions
                ),
            }

        return {
            "status": "unknown",
            "supported": False,
            "format": "unknown",
            "confidence": 0.0,
            "message": "Unable to identify the log format.",
            "reason": (
                "The log does not match any known format signature."
            ),
            "suggested_format": None,
            "suggestion": (
                "Create a parser or mapping configuration "
                "for this vendor format."
            ),
            "candidates": [],
            "extracted_data": extracted_data,
            "field_mapping_suggestions": (
                field_mapping_suggestions
            ),
        }

    def check(
        self,
        parser_name: str | None,
        raw_log: str | None = None,
    ) -> Dict[str, Any]:
        """
        If a registered parser already recognized the event, trust that
        parser result rather than re-classifying the same event as unknown.
        """

        if parser_name:
            parser_lower = parser_name.lower()

            if parser_lower in self.supported_formats:
                extracted_data = self.extract_identifiable_data(
                    raw_log or ""
                )

                return {
                    "status": "supported",
                    "supported": True,
                    "format": parser_lower,
                    "confidence": 1.0,
                    "message": (
                        f"Supported format: {parser_lower}"
                    ),
                    "reason": (
                        "ULPF parser successfully recognized "
                        "the log."
                    ),
                    "extracted_data": extracted_data,
                    "field_mapping_suggestions": (
                        self.suggest_field_mappings(
                            extracted_data
                        )
                    ),
                    "candidates": [
                        {
                            "format": parser_lower,
                            "confidence": 1.0,
                            "reason": (
                                "ULPF parser successfully "
                                "recognized the log."
                            ),
                        }
                    ],
                }

        return self.detect(raw_log or "")