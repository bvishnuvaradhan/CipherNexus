# 🛡️ AI Multi-Agent Cybersecurity Defense System

A full-stack, production-grade **Security Operations Center (SOC)** dashboard powered by a **multi-agent AI architecture** with real-time threat detection, agent-to-agent communication, and **Explainable AI (XAI)** reasoning.

---

## 📸 Platform Overview

| Page | Description |
|---|---|
| **Dashboard** | Live SOC overview — threat level, attack chart, agent status, alert feed |
| **Agents** | Detailed agent ops, A2A protocol diagram, live communication feed |
| **Logs** | Full log table with severity/agent/search filters and live mode |
| **Threat Alerts** | All alerts with severity stats, confidence scores, per-agent breakdown |
| **Attack Simulator** | Inject synthetic attacks (brute force, port scan, exfiltration, etc.) |
| **Responses** | Commander's automated responses with full XAI reasoning chains |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React Frontend                        │
│  Dashboard · Agents · Logs · Alerts · Sim · Responses   │
│         Axios REST  ←→  WebSocket (live push)            │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP + WS
┌──────────────────────▼──────────────────────────────────┐
│                  FastAPI Backend                         │
│                                                          │
│  ┌──────────┐  A2A Bus  ┌───────────┐   ┌───────────┐  │
│  │  Sentry  │ ────────► │ Commander │ ◄─ │ Detective │  │
│  │ (Network)│           │(Decisions)│   │  (Logs)   │  │
│  └──────────┘           └───────────┘   └───────────┘  │
│                               │                          │
│                    XAI Reasoning Engine                  │
│                    WebSocket Broadcaster                 │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                    MongoDB                               │
│   alerts · logs · agent_messages · responses · attacks  │
└─────────────────────────────────────────────────────────┘
```

### The Three Agents

| Agent | Role | Detection |
|---|---|---|
| **Sentry** | Network Defense | Traffic spikes, port scans, suspicious IPs |
| **Detective** | Log Intelligence | Brute force, suspicious logins, data exfiltration |
| **Commander** | Decision Engine | Cross-agent correlation → XAI response |

### A2A Communication Protocol (JSON)

```json
// Sentry → Commander
{ "from": "Sentry", "to": "Commander", "event": "traffic_spike", "ip": "192.168.1.21", "severity": "high" }

// Commander → Detective (verification query)
{ "from": "Commander", "to": "Detective", "event": "verify_ip", "ip": "192.168.1.21", "message_type": "query" }

// Detective → Commander (result)
{ "from": "Detective", "to": "Commander", "event": "ip_verification_result",
  "payload": { "failed_logins": 5, "threat_level": "brute_force", "confidence": 0.87 } }
```

### Explainable AI (XAI) Example

```
Action:     Block IP 192.168.1.21
Confidence: 0.92
Signals:
  1. [Sentry]    Traffic spike detected from 192.168.1.21
  2. [Detective] 5 failed root login attempts confirmed
  3. [Commander] Threat severity: HIGH — immediate response warranted
Reasoning:  Traffic Spike Detected by Sentry Agent from IP 192.168.1.21 →
            Cross-correlated with 5 failed login attempts confirmed by Detective Agent →
            Severity classified as HIGH — immediate response warranted.
```

---

## 🚀 Quick Start

### Option A — Docker Compose (recommended)

```bash
git clone <repo>
cd ai-cyber-defense

docker-compose up --build
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Option B — Manual

#### 1. Backend

```bash
cd backend
pip install -r requirements.txt

# Optional: start MongoDB locally
# mongod --dbpath ./data/db

uvicorn main:app --reload --port 8000
```

#### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

### Demo Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `cyber2026` | SOC Admin |
| `analyst` | `soc2026` | SOC Analyst |
| `demo` | `demo` | Demo User |

---

## 📁 Project Structure

```
├── docker-compose.yml
│
├── backend/
│   ├── main.py                     # FastAPI app, lifespan hooks
│   ├── requirements.txt
│   ├── Dockerfile
│   │
│   ├── agents/
│   │   ├── sentry.py               # Network monitoring agent
│   │   ├── detective.py            # Log intelligence agent
│   │   ├── commander.py            # Decision engine + XAI
│   │   └── orchestrator.py         # Agent wiring + background loops
│   │
│   ├── database/
│   │   ├── connection.py           # Motor async MongoDB client
│   │   ├── mock_store.py           # In-memory fallback store
│   │   └── repository.py           # Unified data access layer
│   │
│   ├── models/
│   │   └── schemas.py              # All Pydantic models + enums
│   │
│   ├── routes/
│   │   ├── auth.py                 # POST /auth/login
│   │   ├── alerts.py               # GET /alerts, /alerts/threat-level
│   │   ├── logs.py                 # GET /logs, /logs/agent-messages
│   │   ├── agents.py               # GET /agents
│   │   ├── responses.py            # GET /responses
│   │   └── simulator.py            # POST /simulate-attack
│   │
│   └── websocket/
│       └── manager.py              # WS /ws/alerts — live event push
│
└── frontend/
    ├── index.html
    ├── vite.config.js
    ├── tailwind.config.js
    ├── Dockerfile
    │
    └── src/
        ├── main.jsx
        ├── App.jsx                 # Router + ProtectedRoute
        ├── index.css               # Cyber SOC theme
        │
        ├── context/
        │   └── AuthContext.jsx     # Auth state + login/logout
        │
        ├── services/
        │   ├── api.js              # Axios + all API calls
        │   └── websocket.js        # Auto-reconnect WS hook
        │
        ├── layouts/
        │   └── MainLayout.jsx      # Sidebar + topbar + outlet
        │
        ├── components/
        │   ├── ui.jsx              # SeverityBadge, StatCard, ConfidenceBar…
        │   └── AgentFeed.jsx       # A2A communication feed component
        │
        └── pages/
            ├── Login.jsx
            ├── Dashboard.jsx       # Main SOC view
            ├── Agents.jsx          # Agent ops + A2A diagram
            ├── Logs.jsx            # Log monitoring table
            ├── ThreatAlerts.jsx    # Threat alert list
            ├── Simulator.jsx       # Attack injection UI
            └── Responses.jsx       # XAI response viewer
```

---

## 🔌 API Reference

### REST Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/auth/login` | Authenticate and get token |
| GET | `/alerts` | List alerts (filter by severity) |
| GET | `/alerts/threat-level` | Current threat level + score |
| GET | `/alerts/stats` | Alert counts by severity |
| GET | `/logs` | System & agent logs |
| GET | `/logs/agent-messages` | A2A message history |
| GET | `/agents` | All agent statuses |
| GET | `/responses` | Automated response log |
| GET | `/responses/stats` | Response counts by status |
| POST | `/simulate-attack` | Trigger attack simulation |

### WebSocket

```
ws://localhost:8000/ws/alerts
```

**Message types pushed to clients:**

| Type | Payload |
|---|---|
| `alert` | New threat alert |
| `agent_message` | A2A communication |
| `response` | Automated response with XAI |
| `threat_level` | Updated threat score |
| `log` | New log entry |
| `status` | Agent status update |
| `heartbeat` | Keep-alive (every 30s) |

---

## 🎨 Design System

| Token | Value | Usage |
|---|---|---|
| Background | `#020817` (slate-950) | Page background |
| Card | `#0f172a` (slate-900) | Component cards |
| Border | `#1e293b` (slate-800) | Card borders |
| Primary | `#22d3ee` (cyan-400) | Accent, links, focus |
| Alert | `#f43f5e` (rose-500) | Critical, blocked |
| Success | `#10b981` (emerald-400) | Resolved, online |
| Warning | `#eab308` (yellow-400) | Medium, monitoring |
| Font Display | Exo 2 | Headings, metrics |
| Font Mono | JetBrains Mono | Code, labels, data |

---

## ⚙️ Environment Variables

### Backend
```env
MONGO_URL=mongodb://localhost:27017
DB_NAME=cyber_defense
```

### Frontend
```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/alerts
```

---

## 🧪 Running Without MongoDB

The backend includes a full **in-memory mock store** that activates automatically when MongoDB is unreachable. All features work identically — data resets on restart.

---

Built with FastAPI · React · Tailwind CSS · MongoDB · WebSockets · Recharts
