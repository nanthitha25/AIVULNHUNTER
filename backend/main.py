"""
AIVulnHunter - FastAPI Application Entry Point

Architecture:
    Frontend → API Backend → Scan Pipeline → Rule Engine → Report Generator

Registered Routers:
    /auth          - Authentication & JWT token issuance
    /scan          - Vulnerability scanning (free-tier limit enforced)
    /rules         - Security rule management (admin only)
    /admin         - Admin dashboard: RL Map, scan logs, user management
    /demo          - Demo mode: pre-populated scan example
    /report        - PDF report download
    /rl            - RL heatmap (existing)
    /rl-stats      - RL stats (existing)
    /scan-ws       - WebSocket scan progress (existing)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import sys

if __name__ == "__main__":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

# Existing routers
from backend.routes.scan_ws   import router as scan_ws_router
from backend.routes.rl        import router as rl_router
from backend.routes.rl_stats  import router as rl_stats_router
from backend.routes.report    import router as report_router

# Extended / replaced routers
from backend.routes.auth      import router as auth_router
from backend.routes.scan      import router as scan_router
from backend.routes.rules     import router as rules_router

# New routers
from backend.routes.admin     import router as admin_router
from backend.routes.demo      import router as demo_router

# Initialize database on startup
from backend.database.sqlite_db import init_db
init_db()

app = FastAPI(
    title="AIVulnHunter API",
    description=(
        "Professional AI Security Testing Platform — "
        "OWASP LLM Top-10 scanning, MCP agent orchestration, and controlled red teaming."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register all routers ─────────────────────────────────────────── #
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(scan_ws_router)
app.include_router(rules_router)
app.include_router(admin_router)
app.include_router(demo_router)
app.include_router(rl_router)
app.include_router(rl_stats_router)
app.include_router(report_router)

# ── Mount frontend static files ───────────────────────────────────── #
frontend_path = Path(__file__).resolve().parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

@app.get("/health")
def health_check():
    """Platform health check endpoint."""
    return {
        "status": "OK",
        "platform": "AIVulnHunter",
        "version": "2.0.0",
        "docs": "/docs",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
