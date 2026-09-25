import uvicorn
from fastapi import FastAPI, Request
from typing import Dict, Any, List

app = FastAPI(title="Mock SIEM Server")
received_events: List[Dict[str, Any]] = []

@app.post("/events")
async def receive_events(request: Request):
    payload = await request.json()

    if isinstance(payload, list):
        received_events.extend(payload)
    else:
        received_events.append(payload)

    return {"status": "success", "count": len(payload) if isinstance(payload, list) else 1}

@app.get("/events")
def get_events():
    return received_events

@app.delete("/events")
def clear_events():
    received_events.clear()
    return {"status": "cleared"}

@app.options("/events")
def options_check():
    return {}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9999)
