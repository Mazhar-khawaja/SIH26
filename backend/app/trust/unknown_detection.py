from typing import Any, Dict


class UnknownFormatDetector:
    """
    Identifies whether a log format is supported by ULPF.
    """

    SUPPORTED_FORMATS = {
        "syslog",
        "json",
        "cef",
    }

    def check(self, parser_name: str | None) -> Dict[str, Any]:
        """
        Check whether the detected parser is supported.
        """

        if parser_name is None:
            return {
                "status": "unknown",
                "supported": False,
                "message": "No parser detected",
            }

        if parser_name.lower() in self.SUPPORTED_FORMATS:
            return {
                "status": "supported",
                "supported": True,
                "message": f"Supported format: {parser_name}",
            }

        return {
            "status": "unknown",
            "supported": False,
            "message": f"Unsupported format: {parser_name}",
        }