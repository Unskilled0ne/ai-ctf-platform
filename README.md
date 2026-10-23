# AI Security CTF Platform 🎯🏁

**Containerized Multi-Tenant Capture-the-Flag Arena for Adversarial AI & Application Security.**  
*Engineered by [Vasilis Tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Multi--Container-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A containerized, multi-tenant capture-the-flag (CTF) arena specifically designed for hands-on adversarial AI, LLM red teaming, and traditional application security testing.

The platform simulates an automotive engineering enterprise deploying autonomous AI agents and microservices. Competitors exploit vulnerabilities ranging from prompt injection and RAG persona impersonation to WebSocket sidechannels and microservice pivoting.

---

## Architecture Overview

The platform uses an isolated multi-container architecture with per-team sandbox orchestration, centralized live scoring, and dynamic per-instance flag generation:

```
                                  +----------------------------+
                                  |    Live Standings Display  |
                                  |  (Leaderboard Dashboard)   |
                                  +--------------^-------------+
                                                 |
                                         WebSocket / HTTP
                                                 |
+---------------------+           +--------------+-------------+
|   Competitor Browser| --------> |    CTF Ingest Service      |
| (Terminal Interface)|           |      (:8000 / FastAPI)     |
+----------+----------+           +--------------^-------------+
           |                                     |
           | HTTP / WS                           | HTTP Submit
           v                                     |
+------------------------------------------------+-------------+
|                    Spawner / Orchestrator (:9000)             |
|  - Generates isolated Docker containers per participant/team |
|  - Injects dynamic HMAC salts for unguessable flag derivation |
+--------------------------------------------------------------+
                               |
                               | Spawns
                               v
               +-------------------------------+
               |    Per-Team Challenge Pod     |
               |       (:8001 / Docker)        |
               |                               |
               |  - LangChain / LLM Services   |
               |  - SQLite Parts Database      |
               |  - WebSocket Telemetry Stream |
               |  - Internal RAG Knowledge Base|
               +-------------------------------+
```

### Core Components

1. **Challenge Pod (`main.py`)**:
   - FastAPI application exposing vulnerable application endpoints, LLM agent personas, and internal services.
   - Built-in phase gate: Phase 2 challenges remain cryptographically locked until all Phase 1 flags are submitted and verified.
2. **Challenge Orchestrator (`spawner.py`)**:
   - Manages container lifecycles via the Docker Engine API.
   - Allocates dedicated host ports per team, handles container expiration timeouts, and tracks participant tokens.
3. **Dashboard Ingest Microservice (`ingest_service/main.py`)**:
   - Collects verified flag submissions, tracks first bloods, and streams live standings to the leaderboard UI via WebSockets.
4. **Interactive Hacker Terminal (`Challenge-Terminal.html`)**:
   - Cyberpunk-styled terminal interface with built-in tabbed challenge prompts, API tester, and live flag submission modal.
5. **Live Standings Dashboard (`ctf_leaderboard_dashboard.html`)**:
   - Real-time score matrix displaying team progress, solved challenges, solve rates, and timeline charts.

---

## Challenge Matrix

The arena features 10 progressive challenges divided into two locked phases:

### Phase 1: Perimeter & Edge Services

| Challenge | Attack Vector | Description | Points |
| :--- | :--- | :--- | :--- |
| **SQL_INJECTION** | SQL Injection | Exploit unsanitized input in parts catalog search to bypass filter logic and dump system records. | 100 |
| **PROMPT_INJECTION** | Direct Prompt Injection | Jailbreak the automotive customer service assistant to bypass system instructions and disclose engineering parameters. | 100 |
| **EMPLOYEE_IDOR** | Broken Object Level Auth | Enumerate non-public internal personnel records through unauthenticated directory queries. | 100 |
| **LOCAL_FILE** | Path Traversal | Traverse directory barriers in inspection log endpoints to extract configuration artifacts. | 100 |
| **MEMORY_LEAK** | Memory Exposure | Analyze unscrubbed debug memory dumps to recover encrypted key material. | 100 |
| **WS_SIDECHANNEL** | Telemetry Sidechannel | Intercept and filter high-frequency WebSocket diagnostic telemetry bursts to capture runtime artifacts. | 100 |

### Phase 2: Internal Mesh & Agent Escalation *(Unlocked after Phase 1)*

| Challenge | Attack Vector | Description | Points |
| :--- | :--- | :--- | :--- |
| **NGDSA_WELCOME** | Portal Escalation | Unravel initial authorization artifacts revealed upon phase gate transition. | 150 |
| **RAG_IMPERSONATE** | RAG Context Hijack | Craft semantic queries tricking the internal RAG assistant into accepting a spoofed admin role and exposing confidential escalation tokens. | 200 |
| **INTERNAL_SERVICE** | Microservice SSRF | Forge requests through the internal telemetry ingestion gateway to trigger unauthorized state mutations. | 250 |
| **SOURCE_REVERSE** | Reverse Engineering | Analyze obfuscated shrouded key structures and XOR keystreams to calculate the master cryptographic flag. | 300 |

---

## Dynamic Anti-Cheat Flag Architecture

To eliminate flag sharing across teams during competitive events, all flags are generated dynamically at container launch using keyed HMAC-SHA256 derivation:

```python
flag = f"NGDSA{{{challenge_name}_{HMAC_SHA256(SPAWNER_FLAG_SECRET_SALT, team_token + challenge_name)[:12]}}}"
```

- Every container instance receives an isolated `SPAWNER_FLAG_SECRET_SALT` and team identifier.
- Flags captured by Team A are mathematically invalid when submitted by Team B.
- Static flags or hardcoded secrets are completely absent from the source code.

---

## Getting Started

### Prerequisites

- Python 3.10+
- Docker Engine & Docker Compose
- `pip` or virtual environment

### 1. Standalone Local Execution (Development Mode)

Run a single challenge instance directly without the Docker spawner:

```bash
# Clone the repository
git clone https://github.com/Unskilled0ne/ai-ctf-platform.git
cd ai-ctf-platform

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run challenge pod
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
```

Open `http://localhost:8001` in your browser to launch the Challenge Terminal.

### 2. Multi-Tenant Event Deployment (Orchestrator Mode)

For running competitions with multiple teams:

```bash
# Build the challenge container image
docker build -t ai-ctf-platform:latest .

# Install orchestrator dependencies
pip install -r spawner_requirements.txt

# Configure environment
export PUBLIC_HOST="127.0.0.1"
export SPAWNER_ADMIN_KEY="supersecret_adminkey"
export SPAWNER_FLAG_SECRET_SALT="competitor_isolation_salt_98765"

# Launch spawner
uvicorn spawner:app --host 0.0.0.0 --port 9000
```

- **Spawner Portal**: `http://localhost:9000` (Teams enter a handle to spawn their dedicated container).
- **Admin Teardown**: `POST http://localhost:9000/api/teardown` with header `X-Admin-Key`.

### 3. Centralized Ingest & Leaderboard

```bash
cd ingest_service
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `ctf_leaderboard_dashboard.html` in any modern web browser to view real-time score updates, first blood notifications, and submission velocities.

---

## Security Model

The challenge platform is explicitly designed as an educational vulnerable target:
- Intended vulnerabilities are confined to application-layer logic, LLM system prompt boundaries, and SQLite sandbox files.
- Container isolation prevents host escalation when deployed using the Docker orchestrator.
- Always deploy behind an isolated network boundary during public competitions.

---

## License

MIT License. Designed and maintained by Vasilis Tsiamouras.
