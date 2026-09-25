from typing import Any, Dict, Optional
from app.search.opensearch_client import OpenSearchClient
from app.search.index_manager import IndexManager
from app.config.settings import settings
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.search_service")

class SearchService:
    def __init__(self):
        self.client = OpenSearchClient.get_client()
        self.index_name = settings.opensearch_index
        IndexManager().setup_index()

    def index_event(self, event: Dict[str, Any]) -> bool:
        if not self.client or not settings.opensearch_enabled:
            return False

        try:
            event_id = event.get("event_id")
            if not event_id:
                logger.warning("Event missing event_id, cannot index securely")
                return False

            self.client.index(
                index=self.index_name,
                body=event,
                id=event_id,
                refresh=True
            )
            return True
        except Exception as e:
            logger.error(f"OpenSearch indexing failed for event {event.get('event_id')}", error=e)
            return False

    def search_events(
        self,
        q: Optional[str] = None,
        event_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        parser: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        severity: Optional[str] = None,
        action: Optional[str] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        if not self.client or not settings.opensearch_enabled:
            return {"items": [], "total": 0, "page": page, "page_size": page_size}

        must_queries = []

        if q:
            must_queries.append({"multi_match": {"query": q, "fields": ["raw_event", "event_type", "user", "hostname"]}})
        if event_id:
            must_queries.append({"term": {"event_id": event_id}})
        if vendor:
            must_queries.append({"term": {"vendor": vendor}})
        if product:
            must_queries.append({"term": {"product": product}})
        if parser:
            must_queries.append({"term": {"parser": parser}})
        if event_type:
            must_queries.append({"term": {"event_type": event_type}})
        if source_ip:
            must_queries.append({"term": {"source_ip": source_ip}})
        if destination_ip:
            must_queries.append({"term": {"destination_ip": destination_ip}})
        if severity:
            must_queries.append({"term": {"severity": severity}})
        if action:
            must_queries.append({"term": {"action": action}})

        query = {"match_all": {}} if not must_queries else {"bool": {"must": must_queries}}
        from_offset = (page - 1) * page_size

        try:
            res = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "from": from_offset,
                    "size": page_size,
                    "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}]
                }
            )

            hits = res.get("hits", {})
            total = hits.get("total", {}).get("value", 0)
            items = [hit["_source"] for hit in hits.get("hits", [])]

            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size
            }
        except Exception as e:
            logger.error("OpenSearch search failed", error=e)
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "error": str(e)}

    def index_analytics(self, result: Dict[str, Any]) -> bool:
        if not self.client or not settings.opensearch_enabled:
            return False
        try:
            self.client.index(
                index=settings.opensearch_analytics_index,
                body=result,
                id=result["event_id"],
                refresh=True
            )
            return True
        except Exception as e:
            logger.error(f"OpenSearch analytics indexing failed for event {result.get('event_id')}", error=e)
            return False

    def get_analytics(self, event_id: str) -> Optional[Dict[str, Any]]:
        if not self.client or not settings.opensearch_enabled:
            return None
        try:
            res = self.client.get(index=settings.opensearch_analytics_index, id=event_id)
            return res.get("_source")
        except Exception:
            return None

    def search_analytics(
        self,
        severity: Optional[str] = None,
        risk_min: Optional[int] = None,
        risk_max: Optional[int] = None,
        anomaly: Optional[bool] = None,
        detected: Optional[bool] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        if not self.client or not settings.opensearch_enabled:
            return {"items": [], "total": 0, "page": page, "page_size": page_size}

        must_queries = []
        if severity:
            must_queries.append({"term": {"severity": severity}})
        if risk_min is not None or risk_max is not None:
            range_q = {}
            if risk_min is not None:
                range_q["gte"] = risk_min
            if risk_max is not None:
                range_q["lte"] = risk_max
            must_queries.append({"range": {"risk_score": range_q}})
        if anomaly is not None:
            must_queries.append({"term": {"anomaly": anomaly}})
        if detected is not None:
            must_queries.append({"term": {"detected": detected}})

        query = {"match_all": {}} if not must_queries else {"bool": {"must": must_queries}}
        from_offset = (page - 1) * page_size

        try:
            res = self.client.search(
                index=settings.opensearch_analytics_index,
                body={
                    "query": query,
                    "from": from_offset,
                    "size": page_size,
                    "sort": [{"timestamp": {"order": "desc"}}]
                }
            )

            hits = res.get("hits", {})
            total = hits.get("total", {}).get("value", 0)
            items = [hit["_source"] for hit in hits.get("hits", [])]
            return {"items": items, "total": total, "page": page, "page_size": page_size}
        except Exception as e:
            logger.error("OpenSearch analytics search failed", error=e)
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "error": str(e)}

    def get_analytics_stats(self) -> Dict[str, Any]:
        if not self.client or not settings.opensearch_enabled:
            return {}
        try:
            res = self.client.search(
                index=settings.opensearch_analytics_index,
                body={
                    "size": 0,
                    "aggs": {
                        "severity_count": {"terms": {"field": "severity"}},
                        "anomalies": {"filter": {"term": {"anomaly": True}}},
                        "detections": {"filter": {"term": {"detected": True}}}
                    }
                }
            )
            aggs = res.get("aggregations", {})
            return {
                "total_analyzed": res.get("hits", {}).get("total", {}).get("value", 0),
                "severity_counts": {b["key"]: b["doc_count"] for b in aggs.get("severity_count", {}).get("buckets", [])},
                "anomalies": aggs.get("anomalies", {}).get("doc_count", 0),
                "detections": aggs.get("detections", {}).get("doc_count", 0)
            }
        except Exception as e:
            logger.error("OpenSearch analytics stats failed", error=e)
            return {}
