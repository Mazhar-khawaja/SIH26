import pytest
from fastapi.testclient import TestClient
from app.api.main import app, limiter

client = TestClient(app)

# The default analyst API key defined in auth.py
HEADERS = {"X-API-Key": "default_api_key_change_me"}

@pytest.fixture(autouse=True)
def reset_limiter():
    limiter.reset()

def test_single_line_log():
    log = "<134>Sep 30 10:15:22 firewall01 TEST\n"
    response = client.post("/api/v1/events", json={"log": log}, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["event"]["raw_event"] == log

def test_multiple_ordinary_lines():
    log_content = "LOG A\nLOG B\nLOG C"
    files = {"file": ("test.log", log_content, "text/plain")}
    response = client.post("/api/v1/upload", files=files, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    
    # Expect 3 events
    assert data["processed_count"] + data["failed_count"] == 3
    
    # They will likely fail to parse since 'LOG A' isn't valid for any strict parser,
    # but they should be processed as unknown and their raw_event preserved.
    # Actually wait, failed events are also returned in data["failed"]
    events = data["processed"] + data["failed"]
    raw_events = []
    for e in events:
        if "result" in e:
            raw_events.append(e["result"].get("event", {}).get("raw_event"))
        else:
            raw_events.append(e.get("raw_event"))
    
    assert "LOG A\n" in raw_events
    assert "LOG B\n" in raw_events
    assert "LOG C" in raw_events

def test_multiline_ssh_event():
    log_content = (
        "2026-09-30T10:00:00Z server-02 sshd:\n"
        "Failed password for admin\n"
        "from 10.20.15.44\n"
        "port 49152 ssh2\n"
    )
    files = {"file": ("test.log", log_content, "text/plain")}
    response = client.post("/api/v1/upload", files=files, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    
    assert data["processed_count"] + data["failed_count"] == 1
    events = data["processed"] + data["failed"]
    raw_event = events[0]["result"]["event"]["raw_event"] if "result" in events[0] else events[0]["raw_event"]
    assert raw_event == log_content

def test_multiple_multiline_events():
    log_content = (
        "2026-09-30T10:00:00Z server-02 sshd:\n"
        "Failed password\n"
        "2026-09-30T10:05:00Z server-02 sshd:\n"
        "Accepted password\n"
    )
    files = {"file": ("test.log", log_content, "text/plain")}
    response = client.post("/api/v1/upload", files=files, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    
    assert data["processed_count"] + data["failed_count"] == 2
    events = sorted(data["processed"] + data["failed"], key=lambda x: x["line"])
    
    raw1 = events[0]["result"]["event"]["raw_event"] if "result" in events[0] else events[0]["raw_event"]
    raw2 = events[1]["result"]["event"]["raw_event"] if "result" in events[1] else events[1]["raw_event"]
    
    assert raw1 == "2026-09-30T10:00:00Z server-02 sshd:\nFailed password\n"
    assert raw2 == "2026-09-30T10:05:00Z server-02 sshd:\nAccepted password\n"

def test_leading_trailing_whitespace():
    log = "  TEST LOG  \n"
    response = client.post("/api/v1/events", json={"log": log}, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["event"]["raw_event"] == log

def test_crlf():
    log_content = "LOG A\r\nLOG B\r\n"
    files = {"file": ("test.log", log_content, "text/plain")}
    response = client.post("/api/v1/upload", files=files, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    
    assert data["processed_count"] + data["failed_count"] == 2
    events = sorted(data["processed"] + data["failed"], key=lambda x: x["line"])
    
    raw1 = events[0]["result"]["event"]["raw_event"] if "result" in events[0] else events[0]["raw_event"]
    raw2 = events[1]["result"]["event"]["raw_event"] if "result" in events[1] else events[1]["raw_event"]
    
    assert raw1 == "LOG A\r\n"
    assert raw2 == "LOG B\r\n"

def test_blank_lines():
    log_content = "LOG A\n\nLOG B\n"
    files = {"file": ("test.log", log_content, "text/plain")}
    response = client.post("/api/v1/upload", files=files, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    
    assert data["processed_count"] + data["failed_count"] == 2
    events = sorted(data["processed"] + data["failed"], key=lambda x: x["line"])
    
    raw1 = events[0]["result"]["event"]["raw_event"] if "result" in events[0] else events[0]["raw_event"]
    raw2 = events[1]["result"]["event"]["raw_event"] if "result" in events[1] else events[1]["raw_event"]
    
    # LOG A\n\n belongs to LOG A because blank line gets appended to current event 
    # Or if LOG A was not multiline capable, does it?
    # Actually my logic says: if not line.strip(): if current_event: current_event += line
    # So LOG A\n\n becomes one event, and LOG B\n becomes second.
    assert raw1 == "LOG A\n\n"
    assert raw2 == "LOG B\n"

def test_trailing_newline():
    log = "LOG\n"
    response = client.post("/api/v1/events", json={"log": log}, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["event"]["raw_event"] == log

def test_large_file():
    log_content = ("LOG ENTRY\n" * 100)
    files = {"file": ("test.log", log_content, "text/plain")}
    response = client.post("/api/v1/upload", files=files, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["processed_count"] + data["failed_count"] == 100
    events = data["processed"] + data["failed"]
    # Verify exact preservation
    raw1 = events[0]["result"]["event"]["raw_event"] if "result" in events[0] else events[0]["raw_event"]
    assert raw1 == "LOG ENTRY\n"

def test_json_multiline():
    log_content = '{\n  "key": "val"\n}\n{\n  "key2": "val2"\n}\n'
    files = {"file": ("test.log", log_content, "text/plain")}
    response = client.post("/api/v1/upload", files=files, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    
    assert data["processed_count"] + data["failed_count"] == 2
    events = sorted(data["processed"] + data["failed"], key=lambda x: x["line"])
    
    raw1 = events[0]["result"]["event"]["raw_event"] if "result" in events[0] else events[0]["raw_event"]
    raw2 = events[1]["result"]["event"]["raw_event"] if "result" in events[1] else events[1]["raw_event"]
    
    assert raw1 == '{\n  "key": "val"\n}\n'
    assert raw2 == '{\n  "key2": "val2"\n}\n'
