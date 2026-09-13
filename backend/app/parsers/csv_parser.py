import csv
import io
from typing import Any, Dict, List
from .base_parser import BaseParser


class CSVParser(BaseParser):
    """
    Parser for CSV-formatted security events using header-based column mapping.
    """

    @property
    def name(self) -> str:
        return "csv"

    def can_parse(self, log: str) -> bool:
        """
        Detect whether the log is a valid header-based CSV event.
        """
        if not log or not log.strip():
            return False

        stripped = log.strip()

        # Rejection rules for other structured formats
        if (
            stripped.startswith("CEF:")
            or stripped.startswith("LEEF:")
            or stripped.startswith("<")
            or stripped.startswith("{")
        ):
            return False

        # Must contain at least one comma
        if "," not in stripped:
            return False

        try:
            reader = list(csv.reader(io.StringIO(stripped)))
            # Requires at least a header row and a data row, OR a valid multi-column header structure
            if len(reader) >= 2:
                header = reader[0]
                data_row = reader[1]
                if len(header) >= 2 and len(data_row) > 0 and len(header) == len(data_row):
                    # Ensure headers look like valid column names (not pure numbers)
                    if any(col.strip() and not col.strip().isdigit() for col in header):
                        return True
            elif len(reader) == 1:
                # Single-line key=value comma separated or single line header check
                row = reader[0]
                if len(row) >= 2 and all("=" in field for field in row if field.strip()):
                    return True
            return False
        except Exception:
            return False

    def parse(self, log: str) -> Dict[str, Any]:
        """
        Parse CSV log into a dictionary using header column names.
        """
        if not log or not log.strip():
            raise ValueError("Log cannot be empty")

        stripped = log.strip()

        if not self.can_parse(stripped):
            raise ValueError("Log does not appear to be CSV format")

        try:
            reader = list(csv.reader(io.StringIO(stripped)))
        except Exception as error:
            raise ValueError(f"Malformed CSV: {error}") from error

        result: Dict[str, Any] = {
            "source_type": "csv",
            "raw_event": log,
        }

        extracted_fields: Dict[str, Any] = {}

        if len(reader) >= 2:
            headers = [h.strip() for h in reader[0]]
            values = [v.strip() for v in reader[1]]

            for header, val in zip(headers, values):
                extracted_fields[header] = val
        elif len(reader) == 1:
            # Handle key=value comma-separated format
            row = reader[0]
            for item in row:
                if "=" in item:
                    k, v = item.split("=", 1)
                    extracted_fields[k.strip()] = v.strip()

        result.update(extracted_fields)

        # Support common aliases while preserving original fields
        alias_map = {
            "src": "source_ip",
            "dst": "destination_ip",
            "sport": "source_port",
            "dport": "destination_port",
            "proto": "protocol",
            "act": "action",
            "sev": "severity",
        }

        for orig_key, alias_key in alias_map.items():
            if orig_key in extracted_fields and alias_key not in result:
                result[alias_key] = extracted_fields[orig_key]

        return result
