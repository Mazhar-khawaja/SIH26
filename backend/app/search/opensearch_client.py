from opensearchpy import OpenSearch
from app.config.settings import settings
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.opensearch")

class OpenSearchClient:
    _instance = None

    @classmethod
    def get_client(cls):
        if not settings.opensearch_enabled:
            return None

        if cls._instance is None:
            kwargs = {
                "hosts": [settings.opensearch_url],
                "timeout": settings.opensearch_timeout,
                "use_ssl": settings.opensearch_url.startswith("https"),
                "verify_certs": False
            }
            if settings.opensearch_username and settings.opensearch_password:
                kwargs["http_auth"] = (settings.opensearch_username, settings.opensearch_password)

            cls._instance = OpenSearch(**kwargs)
        return cls._instance

    @classmethod
    def is_available(cls) -> bool:
        client = cls.get_client()
        if not client:
            return False
        try:
            return client.ping()
        except Exception:
            return False

    @classmethod
    def health_check(cls) -> str:
        client = cls.get_client()
        if not client:
            return "disabled"
        try:
            if client.ping():
                return "healthy"
            return "unreachable"
        except Exception as e:
            return f"error: {str(e)}"
