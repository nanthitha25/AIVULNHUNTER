# 🛡️ AivulnHunter — Autonomous AI Security Testing & Red-Teaming Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Next.js 15](https://img.shields.io/badge/Next.js-15%2B-black.svg)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4%2B-38B2AC.svg)](https://tailwindcss.com/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM_Top_10-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Q-Learning](https://img.shields.io/badge/RL-Q--Learning-orange.svg)]()

> **AivulnHunter** is an enterprise-grade automated security testing and red-teaming platform engineered to identify vulnerabilities in LLM-powered applications, autonomous AI agents, and modern APIs. It features a decoupled **4-agent sequential pipeline**, an adaptive **Q-learning reinforcement engine**, real-time **WebSocket progress streaming**, an **AI Firewall pre-screening layer**, and an **Explainable AI (XAI) security copilot** backed by Anthropic Claude 3.5 Sonnet and Google Gemini.

---

## 📌 Table of Contents

- [The Problem](#-the-problem)
- [The Solution](#-the-solution)
- [Key Use Cases](#-key-use-cases)
- [System Architecture](#-system-architecture)
- [The Four Core Agents](#-the-four-core-agents)
  - [1. Target Profiling Agent](#1-target-profiling-agent)
  - [2. Attack Strategy Agent](#2-attack-strategy-agent)
  - [3. Execution Agent & Plugin Registry](#3-execution-agent--plugin-registry)
  - [4. Vulnerability Observer Agent & XAI](#4-vulnerability-observer-agent--xai)
  - [Auxiliary Layers: AI Firewall & MCP Agent](#auxiliary-layers-ai-firewall--mcp-reasoning-agent)
- [Adaptive Q-Learning Engine](#-adaptive-q-learning-engine)
- [Technology Stack](#-technology-stack)
- [Dual-Provider AI Copilot & Fallback Architecture](#-dual-provider-ai-copilot--fallback-architecture)
- [Directory Structure](#-directory-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Configuration (.env)](#configuration-env)
  - [Running with Docker Compose](#running-with-docker-compose)
  - [Running Locally](#running-locally)
- [License](#-license)

---

## 🚨 The Problem

The rapid proliferation of Large Language Models (LLMs) and autonomous agents has introduced a radically new attack surface that legacy security tools (SAST, DAST, WAFs) were never built to handle:

1. **Non-Deterministic Exploit Vectors**: Threats like **Direct/Indirect Prompt Injection**, **Jailbreaking**, and **System Prompt Leakage** exploit model semantics rather than traditional memory corruption or binary vulnerabilities.
2. **Autonomous Agent Hazards**: Agents granted external tools (shell execution, SQL queries, web scrapers, payment APIs) can be manipulated via **Tool Argument Injection** or **Excessive Agency** to perform unauthorized, destructive actions.
3. **Memory & Context Poisoning**: Malicious context injected into long-term vector stores or chat memory can persist across user sessions, turning the AI agent into an insider threat.
4. **Lack of Adaptive Testing**: Traditional scanners run static, hardcoded checks in sequential order, squandering time and compute on ineffective attack rules.

---

## 💡 The Solution

**AivulnHunter** delivers an end-to-end autonomous penetration testing platform purpose-built for the AI era:

- 🤖 **Autonomous Multi-Agent Orchestration**: Deconstructs scanning into discrete, specialized agent roles (Reconnaissance, Planning, Execution, Observation) ensuring zero single points of failure.
- 🧠 **Q-Learning Prioritization**: Employs reinforcement learning to learn which attack rules succeed against target profiles, dynamically ordering tests to detect critical vulnerabilities faster.
- 🛡️ **OWASP LLM & API Top-10 Coverage**: Out-of-the-box scanner plugins targeting Prompt Injections (LLM01), Insecure Output Handling (LLM02), Memory Poisoning (LLM03/AGENT02), Excessive Agency (LLM08/AGENT03), and BOLA (API01).
- ⚡ **Real-Time Glassmorphic Dashboard**: Next.js 15 frontend streaming live percentage progress, per-agent activity, and findings via low-latency WebSockets.
- 📄 **C-Suite & Developer PDF Reports**: Generates auditable security reports with risk matrices, technical impacts, reproduction evidence, and code-level remediation snippets.

---

## 🎯 Key Use Cases

| Persona / Context | Use Case |
| :--- | :--- |
| **DevSecOps & CI/CD** | Automated security gate prior to deploying new LLM prompts, agent configurations, or API updates to staging/production. |
| **AI Red Teams & Penetration Testers** | Comprehensive black-box and grey-box audits of conversational AI endpoints and autonomous agent tools without manual scripting. |
| **Enterprise Security Compliance** | Auditing third-party LLM integrations against the OWASP Top 10 for LLMs and generating formal PDF assessment certificates. |
| **Developers & Engineers** | Interactive AI Security Copilot providing instant root-cause analysis, proof-of-concept payloads, and defensive code snippets. |

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph Frontend["Frontend Layer (Next.js 15 + Tailwind CSS)"]
        UI["Dashboard & Scan Controls<br/>(page.tsx, ScanModal.tsx)"]
        WSClient["WebSocket Client<br/>(websocket.ts)"]
        AIChat["AI Security Assistant UI<br/>(AiAssistant.tsx)"]
    end

    subgraph API["Backend API Layer (FastAPI ASGI)"]
        Router["API Routers<br/>(/api/v1/scans, /auth, /assistant, /ws)"]
        AuthGuard["JWT & RBAC Guard<br/>(bcrypt + AdminGuard)"]
        WSManager["WebSocket Connection Manager<br/>(ws_manager.py)"]
    end

    subgraph Security["Pre-Execution Defense"]
        Firewall["AI Firewall & Sanitizer<br/>(ai_firewall.py)"]
    end

    subgraph Agents["Autonomous Multi-Agent Pipeline (pipeline_service.py)"]
        Profiler["1. Profiling Agent<br/>(profiling_agent.py)"]
        Strategy["2. Attack Strategy Agent<br/>(strategy_agent.py)"]
        Executor["3. Execution Agent & Plugins<br/>(execution_agent.py + plugins/)"]
        Observer["4. Vulnerability Observer Agent<br/>(observer_agent.py)"]
        MCPAgent["3B. MCP Reasoning Agent<br/>(mcp_agent.py)"]
    end

    subgraph Intelligence["Intelligence & Learning"]
        RL["Q-Learning Adaptive Engine<br/>(rule_prioritizer.py / learner.py)"]
        RAG["RAG Rule Search<br/>(rag_service.py)"]
        AICascade["LLM Copilot Cascade<br/>(Claude 3.5 Sonnet -> Gemini Flash)"]
    end

    subgraph Storage["Persistence Layer"]
        DB[("PostgreSQL / SQLite<br/>(SQLAlchemy 2.0 ORM)")]
    end

    %% Client Interactions
    UI -->|POST /api/v1/scans| Router
    WSClient <-->|ws://.../ws/scan/{id}| WSManager
    AIChat -->|POST /api/v1/assistant/chat| Router

    %% Backend Routing & Pre-check
    Router --> AuthGuard
    Router --> Firewall
    Firewall -->|Sanitized Target & Payload| Agents

    %% Sequential Agent Flow
    Profiler -->|Target Classification & Risk Tier| Strategy
    Strategy -->|Optimized Attack Plan| Executor
    Executor -->|Payload Execution| MCPAgent
    Executor -->|Raw Traces & HTTP Responses| Observer
    Observer -->|RL Reward Feedback (+2, +1, -0.1)| RL
    RL -->|Priority Weights| DB
    Observer -->|Validated Vulnerabilities| DB

    %% Real-Time Telemetry
    Agents -.->|Progress % & Stage Updates| WSManager
    WSManager -.->|Live JSON Event Streaming| WSClient

    %% Copilot
    AIChat --> RAG
    RAG -->|OWASP Context & Findings| AICascade
```

---

## 🤖 The Four Core Agents

The scanning workflow is orchestrated by `PipelineService` ([pipeline_service.py](backend/services/pipeline_service.py)). Rather than executing monolithic scripts, four specialized agents pass immutable state dictionaries sequentially:

### 1. Target Profiling Agent
- **File**: [`backend/agents/core/profiling_agent.py`](backend/agents/core/profiling_agent.py)
- **Role**: Non-destructive reconnaissance and digital footprinting.
- **How it works**: Sends diagnostic HTTP probes to analyze response headers (e.g., `openai-model`, `server: uvicorn/gunicorn`), path patterns, status codes, and latency.
- **Output**: Fingerprints the target into a classification tier:
  - `LLM_API` (Chat completions, prompt endpoints)
  - `AGENT` (Tool-using autonomous workflows)
  - `REST_API` (CRUD API services)
  - `WEB_APP` (Frontend / browser interfaces)
  - Assesses baseline risk (`HIGH`, `MEDIUM`, `LOW`).

### 2. Attack Strategy Agent
- **File**: [`backend/agents/core/strategy_agent.py`](backend/agents/core/strategy_agent.py)
- **Role**: Intelligent test plan compilation and pruning.
- **How it works**: Queries enabled security rules from the database and filters out incompatible vectors (e.g., skips LLM prompt injection against static REST APIs).
- **Prioritization Algorithm**: Sorts applicable rules using a composite tuple:
  $$\text{Priority Key} = (\text{Severity Rank}, -\text{RL Priority Score})$$
  High-risk and historically high-yield rules execute first, while low-risk targets are pruned of low-severity checks to conserve bandwidth and execution time.

### 3. Execution Agent & Plugin Registry
- **File**: [`backend/agents/core/execution_agent.py`](backend/agents/core/execution_agent.py)
- **Role**: Adversarial payload delivery and response capture.
- **How it works**: Queries the [`AgentRegistry`](backend/agents/registry.py) to dispatch target payloads via specialized `ScannerPlugin` implementations:
  - `DirectInjectionScanner` (`LLM01`): Tests instruction override and system prompt leakage.
  - `InsecureOutputScanner` (`LLM02`): Evaluates unsafe code, script, or toxic content generation.
  - `MemoryPoisoningScanner` (`AGENT02` / `LLM03`): Probes vector memory retention of malicious context.
  - `ToolArgumentInjectionScanner` (`AGENT01` / `LLM07`): Detects command injection through agent tool calls.
  - `AdvancedBOLAScanner` (`API01`): Validates object-level authorization across tenant IDs.
  - `JSONScanner` / `CSVScanner`: Performs offline semantic scanning of uploaded chat logs and datasets.

### 4. Vulnerability Observer Agent & XAI
- **File**: [`backend/agents/core/observer_agent.py`](backend/agents/core/observer_agent.py)
- **Role**: Exploit verification, Explainable AI (XAI) synthesis, and RL feedback.
- **How it works**: Evaluates raw execution traces, confirms true positives, normalizes severity ratings, and enriches findings with remediation blueprints from [`mitigations.py`](backend/agents/core/mitigations.py).
- **RL Feedback Calculation**: Emits reward signals back into the Q-learning engine:
  - `+2.0`: Confirmed Critical or High-severity exploit.
  - `+1.0`: Confirmed Medium or Low-severity exploit.
  - `-0.1`: Negative check / benign response (penalty to optimize scanning efficiency).

### Auxiliary Layers: AI Firewall & MCP Reasoning Agent
- **AI Firewall (`ai_firewall.py`)**: Intercepts inbound scan requests with regex heuristics to prevent adversarial users from turning AivulnHunter into an SSRF proxy or weaponized injection channel.
- **MCP Reasoning Agent (`mcp_agent.py`)**: Implements Model Context Protocol (MCP) tool invocation with strict JSON schema validation, enabling dynamic multi-step exploit generation.

---

## 📈 Adaptive Q-Learning Engine

Unlike static vulnerability scanners that run tests in an arbitrary sequence, AivulnHunter incorporates an adaptive **Q-Learning prioritization model** ([`backend/rl/learner.py`](backend/rl/learner.py)):

$$Q(s, a) \leftarrow Q(s, a) + \alpha \cdot \left[ r - Q(s, a) \right]$$

- $Q(s, a)$: Priority score of a security rule for a target category (clamped to $[0.0, 10.0]$).
- $\alpha = 0.1$: Learning rate.
- $r$: Reward feedback supplied by the `ObserverAgent`.

Over successive scan runs across an enterprise environment, rules that consistently uncover critical vulnerabilities gain higher priority scores, progressively reducing the average time-to-exploit (TTE).

---

## 💻 Technology Stack

| Layer | Technologies | Justification |
| :--- | :--- | :--- |
| **Backend API** | Python 3.10+, FastAPI, Uvicorn | High-performance asynchronous ASGI runtime with native concurrency for non-blocking network I/O. |
| **Frontend UI** | Next.js 15, React 19, TypeScript, Tailwind CSS | Modular React architecture, glassmorphic design system, and fast server-side rendering. |
| **Real-Time Push** | FastAPI WebSockets, Custom `ConnectionManager` | Low-latency bi-directional event streaming pushing granular agent updates to clients. |
| **Database & ORM** | PostgreSQL (Prod) / SQLite (Dev), SQLAlchemy 2.0 | Zero-setup local SQLite fallback with production PostgreSQL connection pooling. |
| **AI & LLM Services** | Anthropic Claude 3.5 Sonnet, Google Gemini Flash | Dual-model fallback architecture powering the RAG-assisted vulnerability copilot. |
| **Reporting Engine** | ReportLab (Python), jsPDF + AutoTable (Client) | Executive and developer-grade PDF reports with vulnerability charts and remediation steps. |
| **Security & Auth** | JWT (`python-jose`), `bcrypt`, RBAC `AdminGuard` | Secure stateless session authentication and role-based endpoint isolation. |

---

## 🧠 Dual-Provider AI Copilot & Fallback Architecture

The built-in AI Security Assistant ([`backend/ai/assistant.py`](backend/ai/assistant.py)) features a resilient multi-tier fallback architecture:

```
[User Query] ──► [AI Firewall Inspection]
                       │ (Pass)
                       ▼
              [RAG Rule Retrieval]
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
[Anthropic Claude 3.5 Sonnet]   (Rate limit / Timeout)
         │                           │
         │ (Success)                 ▼
         │                 [Google Gemini Flash]
         │                           │
         │                           │ (If unreachable)
         │                           ▼
         └─────────────► [Deterministic Structured Fallback]
```

Every response strictly follows the standardized Security Copilot format:
1. 🔍 **Definition** (Simple explanation of the vulnerability)
2. ⚠️ **Why it is dangerous** (Real-world business and technical risk)
3. 💣 **Real-world example** (Concrete API/agent exploit demonstration)
4. 🛡️ **How to fix it** (Actionable code snippet and mitigation guideline)
5. 📌 **In AivulnHunter context** (Detection methodology and rule mapping)

---

## 📁 Directory Structure

```text
AivulnHunter/
├── backend/
│   ├── main.py                     # FastAPI application entry point & router mounting
│   ├── config.py                   # Application settings & environment variables
│   ├── ws_manager.py               # WebSocket connection manager for live scan progress
│   ├── agents/
│   │   ├── base.py                 # BaseAgent & ScannerPlugin abstract base classes
│   │   ├── registry.py             # Dynamic scanner plugin registry
│   │   ├── core/                   # 4 Core Agents (Profiler, Strategy, Executor, Observer)
│   │   └── plugins/                # OWASP LLM, API, and file scanner implementations
│   ├── ai/
│   │   ├── assistant.py            # AI Security Assistant orchestrator with fallback
│   │   ├── claude_client.py        # Anthropic Claude 3.5 Sonnet client
│   │   └── gemini_client.py        # Google Gemini client
│   ├── auth/                       # JWT token generation and password verification
│   ├── database/                   # SQLAlchemy ORM models, connections, and CRUD modules
│   ├── rl/                         # Q-learning algorithms and rule priority scoring
│   ├── routes/                     # API routers (scans, auth, rules, assistant, admin)
│   ├── security/                   # AI Firewall and input sanitization layer
│   └── services/                   # Scan pipeline orchestrator, RAG service, PDF report generator
├── frontend-next/
│   ├── app/
│   │   ├── page.tsx                # Glassmorphic security dashboard
│   │   ├── scans/                  # Scan history and detailed vulnerability drilldown
│   │   ├── admin/                  # Security rule management & system telemetry
│   │   └── components/             # Reusable UI (AiAssistant, ScanModal, Nav)
│   ├── lib/
│   │   ├── api.ts                  # REST API client
│   │   └── websocket.ts            # WebSocket connection manager with auto-reconnect
│   └── public/                     # Static UI assets
├── docs/                           # Architecture diagrams and specifications
├── mock_targets.py                 # Standalone vulnerable LLM, API, and agent mock service
├── docker-compose.yml              # Multi-container orchestration
└── Dockerfile                      # Backend container configuration
```

---

## 🚀 Getting Started

### Prerequisites

- **Python**: 3.10 or higher
- **Node.js**: 18.0 or higher
- **npm** or **yarn**
- **Git**

### Configuration (.env)

Create a `.env` file in the project root:

```env
# Database (Defaults to SQLite if omitted)
DATABASE_URL=sqlite:///./aivuln.db

# JWT Secret
SECRET_KEY=your-super-secret-jwt-key-change-in-production

# AI Copilot Providers (Optional - structured fallback used if omitted)
ANTHROPIC_API_KEY=your_anthropic_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# Environment Mode
ENV=development
```

---

### Running with Docker Compose

To spin up the complete platform (Backend, Frontend, and Database) with a single command:

```bash
docker-compose up --build
```

- **Frontend Dashboard**: `http://localhost:3000`
- **Backend API & Swagger Docs**: `http://localhost:8000/docs`

---

### Running Locally

#### 1. Start the Mock Vulnerable Target (Port 8080)
In a dedicated terminal, start the local mock targets to test exploits safely:
```bash
python3 mock_targets.py
```

#### 2. Start the Backend API (Port 8000)
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 3. Start the Next.js Frontend (Port 3000)
```bash
cd frontend-next
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser. Click **"🎮 Try Demo"** for instant access without credentials, or log in with your administrative account!

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
