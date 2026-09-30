import json
import re
from typing import List
from app.intelligence.providers.base import AIProvider
from app.intelligence.models import ClassificationResult, FieldMappingSuggestion

class LocalProvider(AIProvider):
    """
    Offline-first heuristic AI provider. Does not use external APIs.
    Simulates ML classification through robust regex, structure analysis, and scoring.
    """

    def classify_format(self, log: str) -> ClassificationResult:
        if not log or not log.strip():
            return ClassificationResult(reasons=["Empty log provided"])

        log = log.strip()
        candidates = []

        # 1. JSON
        try:
            parsed = json.loads(log)
            if isinstance(parsed, dict):
                candidates.append({
                    "format": "json", "confidence": 0.95,
                    "reasons": ["Valid JSON object structure detected"],
                    "patterns": ["json_structure"]
                })
                # Check for AWS CloudTrail
                if "Records" in parsed and isinstance(parsed["Records"], list):
                    candidates.append({
                        "format": "aws_cloudtrail", "confidence": 0.99,
                        "reasons": ["AWS CloudTrail 'Records' array detected inside JSON"],
                        "patterns": ["aws_cloudtrail_json"]
                    })
        except Exception:
            pass

        # 2. CEF
        if log.startswith("CEF:"):
            parts = log.split("|")
            if len(parts) >= 7:
                candidates.append({
                    "format": "cef", "confidence": 0.98,
                    "reasons": ["CEF signature and header pipe delimiters detected"],
                    "patterns": ["cef_header"]
                })
            else:
                candidates.append({
                    "format": "cef", "confidence": 0.60,
                    "reasons": ["CEF signature detected but missing standard fields"],
                    "patterns": ["cef_partial"]
                })

        # 3. LEEF
        if log.startswith("LEEF:"):
            candidates.append({
                "format": "leef", "confidence": 0.98,
                "reasons": ["LEEF signature detected"],
                "patterns": ["leef_header"]
            })

        # 4. Syslog
        if re.match(r"^<\d+>", log):
            candidates.append({
                "format": "syslog", "confidence": 0.90,
                "reasons": ["Syslog PRI <PRI> header detected"],
                "patterns": ["syslog_pri"]
            })
            if "ASA-" in log:
                candidates.append({
                    "format": "cisco_asa", "confidence": 0.95,
                    "reasons": ["Cisco ASA message identifier found in Syslog"],
                    "patterns": ["cisco_asa_id"]
                })

        # 5. XML / Windows Event
        if log.startswith("<") and log.endswith(">"):
            if "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">" in log:
                candidates.append({
                    "format": "windows_event", "confidence": 0.98,
                    "reasons": ["Windows Event XML namespace detected"],
                    "patterns": ["windows_xml"]
                })
            else:
                candidates.append({
                    "format": "xml", "confidence": 0.85,
                    "reasons": ["General XML structure detected"],
                    "patterns": ["xml_tags"]
                })

        # 6. CSV
        if "," in log and "=" not in log and "{" not in log and len(log.split(",")) > 3:
            candidates.append({
                "format": "csv", "confidence": 0.75,
                "reasons": ["Comma delimited fields without key-value pairing"],
                "patterns": ["csv_delimiters"]
            })

        # 7. Generic Key/Value
        kv_matches = list(re.finditer(r"(?:^|[|\s,])([A-Za-z_][A-Za-z0-9_-]*)[=:]([^|\s,]+)", log))
        if len(kv_matches) >= 3 and not any(c["format"] in ["json", "xml", "cef", "leef"] for c in candidates):
            candidates.append({
                "format": "unknown", "confidence": min(0.8, 0.2 + (len(kv_matches) * 0.1)),
                "reasons": [f"Detected generic key-value structure with {len(kv_matches)} fields"],
                "patterns": ["generic_kv"]
            })

        if not candidates:
            return ClassificationResult(
                format="unknown",
                confidence=0.0,
                reasons=["Input does not match any known format signature", "No structural indicators found"],
            )

        best = max(candidates, key=lambda c: c["confidence"])

        # Ambiguity check
        ambiguous = [c for c in candidates if c["confidence"] >= best["confidence"] - 0.1 and c["format"] != best["format"]]
        if ambiguous and best["confidence"] < 0.95:
            reasons = [f"Ambiguous: Log resembles {best['format']} and {', '.join([c['format'] for c in ambiguous])}"]
            reasons.extend(best["reasons"])
            return ClassificationResult(
                format="unknown",
                confidence=best["confidence"] - 0.2, # Lower confidence due to ambiguity
                reasons=reasons,
                matched_patterns=best["patterns"]
            )

        return ClassificationResult(
            format=best["format"],
            confidence=best["confidence"],
            reasons=best["reasons"],
            matched_patterns=best["patterns"],
            suggested_parser={"name": best["format"], "format": best["format"]} if best["confidence"] >= 0.8 else None
        )

    def suggest_field_mapping(self, log: str, format_hint: str) -> List[FieldMappingSuggestion]:
        # Extract generic kv
        extracted = {}
        for key, value in re.findall(r"(?:^|[|\s,])([A-Za-z_][A-Za-z0-9_-]*)[=:]([^|\s,]+)", log.strip()):
            extracted[key.lower()] = value

        if format_hint == "json":
            try:
                parsed = json.loads(log)
                if isinstance(parsed, dict):
                    for k, v in parsed.items():
                        extracted[k.lower()] = str(v)
            except Exception:
                pass

        suggestions = []

        # Universal Event Schema targets
        targets = {
            "source_ip": ["src", "src_ip", "sourceaddress", "clientip", "sip", "source"],
            "destination_ip": ["dst", "dst_ip", "destinationaddress", "serverip", "dip", "dest"],
            "source_port": ["spt", "src_port", "sourceport", "sport"],
            "destination_port": ["dpt", "dst_port", "destinationport", "dport", "port"],
            "protocol": ["proto", "protocol"],
            "action": ["act", "action", "status", "outcome"],
            "user": ["usr", "user", "username", "account"],
            "severity": ["sev", "severity", "level"]
        }

        for u_field, aliases in targets.items():
            for raw_k, raw_v in extracted.items():
                if raw_k in aliases:
                    suggestions.append(FieldMappingSuggestion(
                        source_field=raw_k,
                        target_field=u_field,
                        confidence=0.9,
                        reason=f"Field '{raw_k}' strongly matches Universal Schema field '{u_field}'"
                    ))
                    break
                elif any(a in raw_k for a in aliases):
                    suggestions.append(FieldMappingSuggestion(
                        source_field=raw_k,
                        target_field=u_field,
                        confidence=0.6,
                        reason=f"Field '{raw_k}' partially matches '{u_field}'"
                    ))
                    break

        return suggestions
