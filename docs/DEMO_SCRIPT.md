# ULPF Demo Video Script (Max 2 Minutes)

**0:00 - 0:15 | Problem + ULPF Overview**
*Visual: Title slide "ULPF - Universal Log Processing Framework", followed by a diagram of disparate logs.*
**Speaker:** "Security teams are overwhelmed by diverse, unstructured log formats. Our solution, ULPF, is a vendor-agnostic framework that ingests, normalizes, and enriches logs into a Universal Event Schema without losing raw data."

**0:15 - 0:35 | Dashboard**
*Visual: ULPF Frontend Dashboard at `localhost:5173` showing metrics.*
**Speaker:** "Here is the ULPF dashboard. It provides a real-time overview of system health, ingested events, and overall analytics. Our backend is powered by FastAPI, Kafka, and OpenSearch."

**0:35 - 1:00 | Submit Diverse Security Log**
*Visual: Navigate to 'Submit Log'. Paste a raw Cisco ASA Syslog.*
**Speaker:** "Let's submit a raw Cisco ASA firewall log. This log is completely unstructured. When we hit submit, our high-throughput API ingests the event and routes it to our dynamic Parser Manager."

**1:00 - 1:20 | Show Parsing + Universal Event Schema**
*Visual: The UI displays the successfully parsed JSON output (UES format).*
**Speaker:** "ULPF automatically identified the log as Cisco ASA and applied the correct plugin. It normalized it into our Universal Event Schema (UES), extracting fields like source IP, action, and severity, while retaining a cryptographic hash of the raw log for integrity."

**1:20 - 1:40 | Show Analytics / Risk / Intelligence**
*Visual: Navigate to the Analytics tab or click on the Event Details.*
**Speaker:** "Behind the scenes, our Kafka-driven worker engine processed the event. It assigned a risk score based on the event's severity and context, and flagged potential anomalies, providing immediate actionable intelligence."

**1:40 - 1:55 | Show PostgreSQL / Persistence / SIEM Capability**
*Visual: Briefly show Adminer/Database UI or the API JSON response indicating SIEM readiness.*
**Speaker:** "The enriched event is persisted losslessly in PostgreSQL and indexed in OpenSearch. This structured intelligence is now ready to be securely forwarded to any downstream SIEM."

**1:55 - 2:00 | Final Result**
*Visual: Back to Dashboard overview, showing updated stats.*
**Speaker:** "ULPF simplifies log management, reduces SIEM costs, and accelerates threat detection. Thank you."
