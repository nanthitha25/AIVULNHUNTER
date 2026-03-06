# AIVulnHunter Architecture Document

AIVulnHunter is an advanced, automated security testing platform designed specifically to identify, exploit, and report vulnerabilities in LLM Applications, AI Agents, and standard APIs. It uses an agentic Model Context Protocol (MCP) orchestration pipeline to perform safe, controlled red-teaming.

## High-Level Architecture Diagram

```mermaid
graph TD
    subgraph Frontend [Frontend Client]
        UI[React / HTML5 Dashboard]
        AuthUI[Authentication UI]
        ScanUI[Scan & Configuration]
        ReportsUI[Scan History & PDF Reports]
    end

    subgraph Backend [FastAPI Backend]
        API[FastAPI Router]
        Auth[JWT Auth & RBAC Guard]
        Limits[Rate & Scan Limiter]
        
        API --> Auth
        API --> Limits
        
        subgraph Orchestration [MCP Agent Orchestrator]
            MCPBus[MCP Event Bus]
            
            ProfileAgent[Target Profiling Agent]
            StrategyAgent[Attack Strategy Agent]
            ExecutorAgent[Exploit Executor Agent]
            ObserverAgent[Vulnerability Observer Agent]
            
            MCPBus <--> ProfileAgent
            MCPBus <--> StrategyAgent
            MCPBus <--> ExecutorAgent
            MCPBus <--> ObserverAgent
        end
        
        API --> Orchestration
    end

    subgraph CoreServices [Core Services]
        RLEngine[Reinforcement Learning Engine]
        PDFGen[ReportLab PDF Generator]
    end

    subgraph Database [Storage Layer]
        SQLite[(SQLite Database)]
        DB_Users[Users & Roles]
        DB_Rules[OWASP AI/API Rules]
        DB_Scans[Scan History & Results]
        
        SQLite --- DB_Users
        SQLite --- DB_Rules
        SQLite --- DB_Scans
    end

    subgraph Target [Test Subjects]
        TargetAPI[REST/GraphQL API]
        TargetLLM[LLM Endpoint]
        TargetAgent[AI Agent System]
    end

    %% Connections
    Frontend -->|REST (JSON)| Backend
    Orchestration -->|Rule Tuning| RLEngine
    Orchestration <-->|Fetch Rules / Save Results| Database
    API <--> Database
    API -->|Generate Report| PDFGen
    
    ExecutorAgent ==>|Adversarial Payloads| Target
    Target ==>|Evaluated Responses| ObserverAgent
```

## Core Components

### 1. Frontend Client
- **Tech Stack:** HTML5, CSS3, JavaScript (Vite build system).
- **Features:** User authentication, RBAC admin controls, scan configuration, real-time timeline tracking, and PDF report downloads.

### 2. FastAPI Backend
- **Tech Stack:** Python 3.11, FastAPI, Uvicorn, Python-JOSE (for JWT), Pydantic.
- **Features:** Serves robust REST APIs containing scan logic, rule management, active demo modes, and RBAC authentication guards restricting endpoints to Users or Admins.
- **Scan Limiter:** Enforces strict execution quotas (e.g., 3 free scans) before requiring account upgrades.

### 3. MCP Agent Orchestrator
The core exploitation engine operates on a Model Context Protocol (MCP) simulated event bus to decouple processing and provide fully auditable scan chains.
- **Target Profiling Agent:** Determines if the target is an API, LLM, or AI Agent, probing for reachability and structure.
- **Attack Strategy Agent:** Dynamically queries the database for active OWASP rules filtered by the target type and compiles a tailored attack plan.
- **Exploit Executor Agent:** Safely dispatches the adversarial inputs (e.g., Prompt Injections, SSRF tokens) to the external target.
- **Vulnerability Observer Agent:** Evaluates the target's response against deterministic detection patterns to assign confidence and risk scores.

### 4. Reinforcement Learning (RL) Engine
A local heuristic engine that autonomously adjusts rule priorities and severities based on historical success and false-positive rates gathered during scans. If an attack payload successfully exploits an endpoint repeatedly, its RL effectiveness score is dynamically increased.

### 5. Storage Layer (SQLite)
A local, serverless configuration utilizing relational structures:
1. **Users:** Handles hashed credentials, JWT tracking, and global roles (`admin` vs `user`).
2. **Rules:** A fully extensible, dynamic table of attack vectors tied directly to the **OWASP Top 10 for LLM Applications and APIs**.
3. **Scans & Results:** Persists scanning metrics and vulnerability specifics for compliance tracking and historical PDF regeneration.

### 6. PDF Report Generator
Leverages **ReportLab Platypus** to instantly assemble professional, enterprise-grade threat posture reports containing full Risk Distributions, Severity Maps, Exploit Evidence, and Actionable Mitigations.
