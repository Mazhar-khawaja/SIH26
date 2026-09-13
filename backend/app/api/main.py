from typing import Any, Dict

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.ingestion.ingestion_manager import IngestionManager


app = FastAPI(
    title="ULPF - Universal Log Pre-processing Framework",
    description="Lossless, traceable and vendor-agnostic security log preprocessing.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = IngestionManager()


class LogRequest(BaseModel):
    log: str


@app.get("/")
def root() -> Dict[str, str]:
    return {
        "application": "ULPF",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {
        "status": "healthy",
    }


@app.get("/formats")
def supported_formats() -> Dict[str, Any]:
    return {
        "supported_formats": manager.supported_formats(),
    }


@app.post("/events")
def process_event(request: LogRequest) -> Dict[str, Any]:
    try:
        return manager.process_log(request.log)

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Processing failed: {error}",
        ) from error


@app.get("/events")
def get_events() -> Dict[str, Any]:
    events = manager.get_all_events()

    return {
        "count": len(events),
        "events": events,
    }


@app.get("/events/{event_id}")
def get_event(event_id: str) -> Dict[str, Any]:
    event = manager.get_event(event_id)

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    return event


@app.get("/events/{event_id}/verify")
def verify_event(event_id: str) -> Dict[str, Any]:
    result = manager.verify_event(event_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    return result


@app.get("/stats")
def get_stats() -> Dict[str, Any]:
    return {
        "total_events": manager.count_events(),
        "supported_formats": manager.supported_formats(),
    }


@app.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
) -> Dict[str, Any]:

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected",
        )

    allowed_extensions = {".log", ".txt"}

    filename = file.filename.lower()

    if not any(
        filename.endswith(ext)
        for ext in allowed_extensions
    ):
        raise HTTPException(
            status_code=400,
            detail="Only .log and .txt files are supported",
        )

    content = await file.read()

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=400,
            detail="File must be UTF-8 encoded text",
        ) from error

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    if not lines:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty",
        )

    processed = []
    failed = []

    for line_number, line in enumerate(lines, start=1):
        try:
            result = manager.process_log(line)

            processed.append(
                {
                    "line": line_number,
                    "result": result,
                }
            )

        except Exception as error:
            failed.append(
                {
                    "line": line_number,
                    "error": str(error),
                    "raw_event": line,
                }
            )

    return {
        "filename": file.filename,
        "total_lines": len(lines),
        "processed_count": len(processed),
        "failed_count": len(failed),
        "processed": processed,
        "failed": failed,
    }