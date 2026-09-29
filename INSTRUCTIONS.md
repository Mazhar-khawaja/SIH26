# ULPF - Detailed Evaluation Instructions

This document provides a step-by-step guide for evaluators/instructors to install and demonstrate the ULPF (Universal Log Processing Framework).

## 1. Installation & Environment Setup

### 1.1 Prerequisites
Ensure you have the following installed on your machine:
- Docker and Docker Compose
- Node.js (v18+) and npm
- Git

### 1.2 Start Backend Infrastructure
1. Open a terminal and navigate to the project root directory (`SIH26`).
2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. Build and launch all backend services (PostgreSQL, Kafka, OpenSearch, FastAPI, Worker):
   ```bash
   docker compose up --build -d
   ```
4. Verify the containers are healthy. You can run `docker compose ps` and wait until `postgres`, `kafka`, and `opensearch` report as `healthy` or `running`.

### 1.3 Start the Frontend UI
1. Open a new terminal window/tab.
2. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
3. Install dependencies and start the Vite dev server:
   ```bash
   npm install
   npm run dev
   ```
4. The frontend will be accessible at `http://localhost:5173`.

---

## 2. Demonstration Procedure

### Step 1: Explore the Dashboard
1. Open `http://localhost:5173` in a web browser.
2. The main dashboard displays an overview of ingested events, analytics stats, and system health.

### Step 2: Submit a Log (Parsing & UES)
1. In the frontend, locate the log ingestion/submission area.
2. Use a sample Cisco ASA log:
   `%ASA-4-106023: Deny tcp src outside:192.168.1.1/1234 dst inside:10.0.0.1/80 by access-group "outside_in"`
3. Submit the log.
4. Observe the response: ULPF dynamically routes the log to the `cisco_asa` parser plugin, normalizes it into the **Universal Event Schema (UES)**, and preserves the raw log hash for integrity.

### Step 3: View Analytics & Risk Scoring
1. Navigate to the Event Details or Analytics section for the submitted log.
2. Note that the backend automatically computes a **Risk Score** based on the event attributes (e.g., severity level 4 translates to a specific risk).
3. Check the OpenSearch integration backend which indexes this enriched data for fast querying.

### Step 4: Verify Persistence and SIEM Readiness
1. Open the Adminer database UI at `http://localhost:8081`.
2. Login with PostgreSQL credentials (System: PostgreSQL, Server: `postgres`, User: `ulpf`, Password: `ulpf_password`, Database: `ulpf`).
3. Query the `events` table to verify the lossless storage and structural integrity of the parsed log.

## 3. Teardown
To stop all services and preserve data, run:
```bash
docker compose stop
```
To stop and completely remove all containers and volumes (resetting the database):
```bash
docker compose down -v
```
