from app.search.opensearch_client import OpenSearchClient
from app.config.settings import settings
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.index_manager")

class IndexManager:
    def __init__(self):
        self.client = OpenSearchClient.get_client()
        self.index_name = settings.opensearch_index

    def setup_index(self):
        if not self.client or not settings.opensearch_enabled:
            return

        try:
            if not self.client.indices.exists(index=self.index_name):
                mapping = {
                    "mappings": {
                        "properties": {
                            "event_id": {"type": "keyword"},
                            "timestamp": {"type": "date"},
                            "event_type": {"type": "keyword"},
                            "source": {"type": "keyword"},
                            "source_ip": {"type": "ip"},
                            "source_port": {"type": "integer"},
                            "destination": {"type": "keyword"},
                            "destination_ip": {"type": "ip"},
                            "destination_port": {"type": "integer"},
                            "protocol": {"type": "keyword"},
                            "action": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "user": {"type": "keyword"},
                            "device": {"type": "keyword"},
                            "hostname": {"type": "keyword"},
                            "application": {"type": "keyword"},
                            "vendor": {"type": "keyword"},
                            "product": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "parser": {"type": "keyword"},
                            "parser_version": {"type": "keyword"},
                            "quality_score": {"type": "float"},
                            "confidence": {"type": "float"},
                            "integrity_hash": {"type": "keyword"},
                            "previous_hash": {"type": "keyword"},
                            "chain_hash": {"type": "keyword"},
                            "raw_event": {"type": "text"},
                            "extensions": {"type": "object"},
                            "metadata": {"type": "object"}
                        }
                    }
                }
                self.client.indices.create(index=self.index_name, body=mapping)
                logger.info(f"Created OpenSearch index: {self.index_name}")
        except Exception as e:
            logger.error(f"Failed to setup OpenSearch index {self.index_name}", error=e)

        try:
            analytics_index = settings.opensearch_analytics_index
            if not self.client.indices.exists(index=analytics_index):
                mapping = {
                    "mappings": {
                        "properties": {
                            "event_id": {"type": "keyword"},
                            "detected": {"type": "boolean"},
                            "anomaly": {"type": "boolean"},
                            "anomaly_score": {"type": "float"},
                            "risk_score": {"type": "integer"},
                            "severity": {"type": "keyword"},
                            "detections": {"type": "keyword"},
                            "reasons": {"type": "text"},
                            "rule_matches": {"type": "keyword"},
                            "timestamp": {"type": "date"}
                        }
                    }
                }
                self.client.indices.create(index=analytics_index, body=mapping)
                logger.info(f"Created OpenSearch analytics index: {analytics_index}")
        except Exception as e:
            logger.error(f"Failed to setup OpenSearch index {settings.opensearch_analytics_index}", error=e)
