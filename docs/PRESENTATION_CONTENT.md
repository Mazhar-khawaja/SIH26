# ULPF Technical Presentation (5 Slides)

## Slide 1 — Problem & Motivation
**Title: The Log Chaos Challenge**
- **Diverse Formats:** Security tools generate logs in disparate, proprietary formats.
- **High Costs & Noise:** SIEMs are overwhelmed by noisy, unstructured data, inflating ingestion costs.
- **Vendor Lock-in:** Switching analytical tools requires rewriting parsing rules.
- **Data Integrity:** Normalization often strips raw log context, hampering forensics.

## Slide 2 — Proposed Solution / ULPF
**Title: Universal Log Processing Framework (ULPF)**
- **Vendor-Agnostic Normalization:** Converts diverse logs into a standardized Universal Event Schema (UES).
- **Lossless & Traceable:** Retains the original raw log and generates a cryptographic hash for tamper evidence.
- **Pre-SIEM Processing:** Filters, enriches, and structures data *before* it reaches the SIEM, reducing noise and cost.
- **Dynamic Extensibility:** Hot-pluggable parser architecture.

## Slide 3 — Technical Approach & Architecture
**Title: Scalable & Modular Architecture**
- **Ingestion Layer:** High-performance API using FastAPI.
- **Message Broker:** Apache Kafka for asynchronous processing and high burst tolerance.
- **Processing Engine:** Python workers executing dynamic parser plugins (e.g., AWS CloudTrail, Cisco ASA).
- **Storage & Search:** PostgreSQL for relational state and OpenSearch for rapid analytics.

## Slide 4 — Technical Advantages / Feasibility / Challenges
**Title: Why ULPF Stands Out**
- **Advantages:** Open-source foundation, easily deployable via Docker, strictly typed schema (Pydantic).
- **Feasibility:** Built using industry-standard tools (Kafka, Postgres) ensuring enterprise readiness.
- **Challenges Overcome:** Managed complex schema mapping through a modular, plugin-based Parser Manager that evaluates logs without hardcoded rules.

## Slide 5 — Prototype / Results / Impact
**Title: Impact & Future Scope**
- **Results:** Successfully parses and enriches complex logs (syslog, JSON) locally with minimal latency.
- **Impact:** Decreases SIEM ingestion costs by dropping noise; speeds up incident response via standardized fields.
- **Future:** AI-driven dynamic log classification, more out-of-the-box vendor plugins, and native SOAR integration.
