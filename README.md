# Multi-Agent AI Swarm Security

## Inter-Agent Authorization and Autonomous Mesh Guardrails

### Project Overview

This project demonstrates security controls for communication between multiple AI agents using Python and Flask.

It focuses on authentication, delegated authorization, prompt-injection filtering, rate limiting, and protection against unauthorized direct agent access.

### Architecture

| Component | Role | Port |
|---|---|---|
| Agent A | Supervisor Agent | 5001 |
| Security Gateway | Controls agent communication | 5000 |
| Agent B | Code Runner Agent | 5002 |
| Agent C | Data Retrieval Agent | 5003 |

### Security Features

- JWT authentication using HS256.
- Scoped authorization using recipient and permitted-tool claims.
- Five-minute JWT expiration.
- Gateway client authentication.
- Additional gateway authentication for Agents B and C.
- Allowlisted agent actions.
- Prompt-injection pattern filtering.
- Inspection of agent responses.
- Rate limiting: 10 requests per minute.
- Rejection of unauthorized direct requests.

### Technology Stack

- Python 3
- Flask
- Flask-Limiter
- PyJWT
- Requests
- VMware Ubuntu

### Installation

Clone the repository from its actual GitHub URL:

```bash
git clone YOUR_ACTUAL_REPOSITORY_URL
cd multi-agent-swarm-security
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Security Configuration

The application requires three local secret files:

- security/.jwt_secret
- security/.gateway_client_secret
- security/.agent_gateway_secret

These files must contain independently generated random secrets. They are excluded from Git tracking and must never be uploaded to GitHub.

### Security Test Results

| Security Test | Observed Result |
|---|---|
| Forged JWT rejection | Passed |
| Expired JWT rejection | Passed |
| Unauthorized tool rejection | Passed |
| Wrong recipient rejection | Passed |
| Unsigned direct request to Agent B | HTTP 403 |
| Unsigned direct request to Agent C | HTTP 403 |
| Direct request with JWT but no gateway authentication | HTTP 403 |
| Prompt-injection request filtering | HTTP 403 |
| Suspicious agent-response filtering | HTTP 502 |
| Gateway rate limiting | HTTP 429 |

### Running Tests

Run these commands from the project directory with the virtual environment activated:

```bash
PYTHONPATH=. python tests/test_jwt.py
PYTHONPATH=. python tests/test_jwt_security.py
PYTHONPATH=. python tests/test_gateway_sanitization.py
```

### Project Limitations and Future Improvements

This project is a local security proof of concept, not a production-ready platform.

- Agent A currently runs separately and is not yet integrated into complete gateway-based orchestration.
- Shared-secret authentication requires stronger production key management and rotation.
- Production deployment should use TLS-protected service communication.
- Prompt-injection detection relies on configured pattern matching and cannot detect every possible attack.
- Rate limiting uses in-memory storage, so counters reset when the gateway restarts.

### Project Objective

Demonstrate practical security controls for multi-agent systems, including delegated authorization, least-privilege access, secure inter-agent communication, and resistance to unauthorized lateral movement.
