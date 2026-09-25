import time
from typing import Any, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.ingestion.ingestion_manager import IngestionManager
from app.config.settings import settings
from app.monitoring.logger import get_logger
from app.security.auth import allow_admin, allow_analyst, allow_viewer
from app.kafka.worker import run_worker_in_background
from app.kafka.producer import get_producer

logger = get_logger("ulpf.api")
manager = IngestionManager()
limiter = Limiter(key_func=get_remote_address)
worker_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker_instance
    logger.info("Starting ULPF API service")
    # Start Kafka worker in background
    # worker_instance = run_worker_in_background(manager.process_log)
    yield
    if worker_instance:
        worker_instance.stop()
    logger.info("Shutting down ULPF API service gracefully")


app = FastAPI(
    title=settings.app_name,
    description="Lossless, traceable and vendor-agnostic security log preprocessing.",
    version="0.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LogRequest(BaseModel):
    log: str = Field(..., max_length=100000, description="Raw event string")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    try:
        response = await call_next(request)
        status_code = response.status_code
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", error=e)
        raise e

    process_time = (time.time() - start_time) * 1000
    logger.info(
        f"{request.method} {request.url.path} completed",
        method=request.method,
        path=request.url.path,
        status_code=status_code,
        processing_time_ms=f"{process_time:.2f}"
    )
    return response


# --- v1 API Routes ---

@app.get("/api/v1/")
@app.get("/")
def root() -> Dict[str, str]:
    return {
        "application": settings.app_name,
        "environment": settings.app_env,
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/api/v1/health")
@app.get("/health")
def health() -> Dict[str, str]:
    from app.search.opensearch_client import OpenSearchClient
    return {
        "status": "healthy",
        "database": "healthy",
        "opensearch": OpenSearchClient.health_check()
    }


@app.get("/api/v1/ready")
def ready() -> Dict[str, str]:
    return {"status": "ready"}


@app.get("/api/v1/formats")
@app.get("/formats")
def supported_formats() -> Dict[str, Any]:
    return {"supported_formats": manager.supported_formats()}


@app.post("/api/v1/events")
@app.post("/events")
@limiter.limit(settings.rate_limit)
def process_event(request: Request, payload: LogRequest, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    start_time = time.time()
    try:
        result = manager.process_log(payload.log)
        process_time = (time.time() - start_time) * 1000
        logger.info(
            "Processed event successfully",
            event_id=result.get("event", {}).get("event_id"),
            parser=result.get("event", {}).get("parser"),
            processing_time_ms=f"{process_time:.2f}",
            user=user.get("type")
        )
        return result
    except ValueError as error:
        logger.warning("Value error during event processing", error=error)
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        logger.error("Failed to process event", error=error)
        raise HTTPException(status_code=500, detail="Internal processing error")

class BulkLogRequest(BaseModel):
    logs: list[str] = Field(..., max_items=10000, description="List of raw event strings")

@app.post("/api/v1/events/bulk")
@limiter.limit(settings.upload_rate_limit)
def process_bulk_events(request: Request, payload: BulkLogRequest, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    import uuid
    request_id = str(uuid.uuid4())

    producer = get_producer()
    if not producer.connected:
        raise HTTPException(status_code=503, detail="Kafka producer is currently disconnected. Cannot accept bulk ingestion.")

    try:
        accepted = producer.send_bulk(payload.logs, request_id)
        return {
            "request_id": request_id,
            "status": "accepted",
            "accepted_count": accepted,
            "rejected_count": len(payload.logs) - accepted,
            "queue": settings.kafka_topic
        }
    except Exception as e:
        logger.error("Failed to send bulk events to Kafka", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to enqueue events")

@app.get("/api/v1/events")
@app.get("/events")
def get_events(user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    events = manager.get_all_events()
    return {"count": len(events), "events": events}


@app.get("/api/v1/search/events")
def search_events(
    q: str = None,
    event_id: str = None,
    vendor: str = None,
    product: str = None,
    parser: str = None,
    event_type: str = None,
    source_ip: str = None,
    destination_ip: str = None,
    severity: str = None,
    action: str = None,
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(allow_viewer)
) -> Dict[str, Any]:
    from app.search.search_service import SearchService
    search_service = SearchService()
    return search_service.search_events(
        q=q, event_id=event_id, vendor=vendor, product=product, parser=parser,
        event_type=event_type, source_ip=source_ip, destination_ip=destination_ip,
        severity=severity, action=action, page=page, page_size=page_size
    )


@app.get("/api/v1/events/{event_id}")
@app.get("/events/{event_id}")
def get_event(event_id: str, user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    event = manager.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/api/v1/analytics/events/{event_id}")
def get_analytics(event_id: str, user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    from app.search.search_service import SearchService
    search_service = SearchService()
    res = search_service.get_analytics(event_id)
    if not res:
        raise HTTPException(status_code=404, detail="Analytics not found for event")
    return res


@app.get("/api/v1/analytics/alerts")
def get_alerts(
    severity: str = None,
    risk_min: int = None,
    risk_max: int = None,
    anomaly: bool = None,
    detected: bool = None,
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(allow_viewer)
) -> Dict[str, Any]:
    from app.search.search_service import SearchService
    search_service = SearchService()
    return search_service.search_analytics(
        severity=severity, risk_min=risk_min, risk_max=risk_max,
        anomaly=anomaly, detected=detected, page=page, page_size=page_size
    )


@app.get("/api/v1/analytics/stats")
def get_analytics_stats(user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    from app.search.search_service import SearchService
    search_service = SearchService()
    return search_service.get_analytics_stats()


@app.get("/api/v1/events/{event_id}/verify")
@app.get("/events/{event_id}/verify")
def verify_event(event_id: str, user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    result = manager.verify_event(event_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return result


@app.get("/api/v1/stats")
@app.get("/stats")
def get_stats(user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    return {
        "total_events": manager.count_events(),
        "supported_formats": manager.supported_formats(),
    }


# --- Intelligence API Routes ---

class IntelligenceClassifyRequest(BaseModel):
    log: str

class IntelligenceMapRequest(BaseModel):
    log: str
    format: str = "unknown"

@app.post("/api/v1/intelligence/classify")
def classify_unknown_log(request: IntelligenceClassifyRequest, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    from app.intelligence.service import IntelligenceService
    service = IntelligenceService()
    result = service.classify_log(request.log)
    return result.model_dump()

@app.post("/api/v1/intelligence/map")
def generate_field_mapping(request: IntelligenceMapRequest, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    from app.intelligence.service import IntelligenceService
    service = IntelligenceService()
    approval = service.generate_mapping(request.log, request.format)
    return approval.model_dump()

@app.post("/api/v1/intelligence/approve/{approval_id}")
@app.post("/api/v1/intelligence/approve")
def approve_mapping(approval_id: str = None, id: str = None, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    target_id = approval_id or id
    from app.intelligence.service import IntelligenceService
    service = IntelligenceService()
    approval = service.approve_mapping(target_id, user.get("sub", "analyst"))
    if not approval:
        raise HTTPException(status_code=404, detail="Mapping suggestion not found")
    return approval.model_dump()

@app.post("/api/v1/intelligence/reject/{approval_id}")
@app.post("/api/v1/intelligence/reject")
def reject_mapping(approval_id: str = None, id: str = None, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    target_id = approval_id or id
    from app.intelligence.service import IntelligenceService
    service = IntelligenceService()
    approval = service.reject_mapping(target_id, user.get("sub", "analyst"))
    if not approval:
        raise HTTPException(status_code=404, detail="Mapping suggestion not found")
    return approval.model_dump()

@app.get("/api/v1/intelligence/suggestions")
def list_suggestions(user: dict = Depends(allow_analyst)) -> list:
    from app.intelligence.service import IntelligenceService
    service = IntelligenceService()
    return [a.model_dump() for a in service.list_approvals()]

@app.get("/api/v1/intelligence/suggestions/{approval_id}")
def get_suggestion(approval_id: str, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    from app.intelligence.service import IntelligenceService
    service = IntelligenceService()
    approval = service.get_approval(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Mapping suggestion not found")
    return approval.model_dump()


# --- SIEM Integration Routes ---

@app.get("/api/v1/integrations/siem/status")
def siem_status(user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    from app.integrations.siem.service import SIEMIntegrationService
    service = SIEMIntegrationService()
    return service.status()

@app.post("/api/v1/integrations/siem/test")
def siem_test(user: dict = Depends(allow_admin)) -> Dict[str, Any]:
    from app.integrations.siem.service import SIEMIntegrationService
    service = SIEMIntegrationService()
    return service.test_connection()

@app.post("/api/v1/integrations/siem/enable")
def siem_enable(user: dict = Depends(allow_admin)) -> Dict[str, Any]:
    # In a real app we would persist to DB or update `.env`
    settings.siem_enabled = True
    return {"status": "success", "siem_enabled": True}

@app.post("/api/v1/integrations/siem/disable")
def siem_disable(user: dict = Depends(allow_admin)) -> Dict[str, Any]:
    settings.siem_enabled = False
    return {"status": "success", "siem_enabled": False}


@app.post("/api/v1/upload")
@app.post("/upload")
@limiter.limit(settings.upload_rate_limit)
async def upload_log_file(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(allow_analyst)
) -> Dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")

    allowed_extensions = {".log", ".txt"}
    filename = file.filename.lower()
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        raise HTTPException(status_code=400, detail="Only .log and .txt files are supported")

    content = await file.read()
    if len(content) > 5 * 1024 * 1024:  # 5 MB max for file upload
        raise HTTPException(status_code=413, detail="File too large")

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text")

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    processed = []
    failed = []

    start_time = time.time()
    for line_number, line in enumerate(lines, start=1):
        try:
            result = manager.process_log(line)
            processed.append({"line": line_number, "result": result})
        except Exception as error:
            failed.append({"line": line_number, "error": str(error), "raw_event": line})

    process_time = (time.time() - start_time) * 1000
    logger.info(
        f"Processed batch upload of {len(lines)} lines",
        processed_count=len(processed),
        failed_count=len(failed),
        processing_time_ms=f"{process_time:.2f}",
        user=user.get("type")
    )

    return {
        "filename": file.filename,
        "total_lines": len(lines),
        "processed_count": len(processed),
        "failed_count": len(failed),
        "processed": processed,
        "failed": failed,
    }


# --- Parser Plugin API Routes ---

@app.get("/api/v1/parsers")
@app.get("/parsers")
def list_parsers(user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    return {"parsers": manager.parser_manager.list_all_parsers()}


@app.get("/api/v1/parsers/{name}")
def get_parser(name: str, user: dict = Depends(allow_viewer)) -> Dict[str, Any]:
    info = manager.parser_manager.get_parser_info(name)
    if not info:
        raise HTTPException(status_code=404, detail="Parser not found")
    return {k: v for k, v in info.items() if k != "parser"}


@app.post("/api/v1/parsers/{name}/enable")
def enable_parser(name: str, user: dict = Depends(allow_admin)) -> Dict[str, Any]:
    try:
        manager.parser_manager.enable_parser(name)
        return {"status": "success", "message": f"Parser {name} enabled"}
    except KeyError:
        raise HTTPException(status_code=404, detail="Parser not found")


@app.post("/api/v1/parsers/{name}/disable")
def disable_parser(name: str, user: dict = Depends(allow_admin)) -> Dict[str, Any]:
    try:
        manager.parser_manager.disable_parser(name)
        return {"status": "success", "message": f"Parser {name} disabled"}
    except KeyError:
        raise HTTPException(status_code=404, detail="Parser not found")


@app.post("/api/v1/parsers/reload")
def reload_parsers(user: dict = Depends(allow_admin)) -> Dict[str, Any]:
    manager.parser_manager.reload_plugins()
    return {"status": "success", "message": "Plugins reloaded successfully"}


@app.get("/api/v1/parsers/{name}/health")
def parser_health(name: str, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    info = manager.parser_manager.get_parser_info(name)
    if not info:
        raise HTTPException(status_code=404, detail="Parser not found")
    return {"name": name, "health": info.get("health", "unknown")}


class ParserTestRequest(BaseModel):
    log: str


@app.post("/api/v1/parsers/{name}/test")
def test_parser(name: str, request: ParserTestRequest, user: dict = Depends(allow_analyst)) -> Dict[str, Any]:
    info = manager.parser_manager.get_parser_info(name)
    if not info:
        raise HTTPException(status_code=404, detail="Parser not found")

    parser = info["parser"]
    try:
        if not parser.can_parse(request.log):
            return {"status": "failed", "reason": "Parser rejected log"}

        result = parser.parse(request.log)
        return {
            "parser_name": name,
            "parser_version": info.get("version", "built-in"),
            "status": "success",
            "parsed_result": result
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}