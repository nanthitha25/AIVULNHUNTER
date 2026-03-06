"""
AIVulnHunter - FastAPI Application Entry Point

Architecture:
    Frontend → API Backend → Scan Pipeline → Rule Engine → Report Generator

NOTE: Static file serving has been removed from this file.
      Open frontend HTML files directly from the filesystem, e.g.
        file:///C:/Users/nanth/Downloads/.../frontend/index.html
      or serve them from a separate static server (e.g. VS Code Live Server).
      The API allows cross-origin requests from all origins (CORS enabled).
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
from backend.routes.assistant import router as assistant_router

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

# Allow all origins so the frontend (opened as a local file or on any port) can call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routers only — no static file mounts ─────────────────────── #
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(scan_ws_router)
app.include_router(rules_router)
app.include_router(admin_router)
app.include_router(demo_router)
app.include_router(rl_router)
app.include_router(rl_stats_router)
app.include_router(report_router)
app.include_router(assistant_router)


@app.get("/health")
def health_check():
    """Platform health check endpoint."""
    return {
        "status": "OK",
        "platform": "AIVulnHunter",
        "version": "2.0.0",
        "docs": "/docs",
    }


@app.get("/")
def root():
    return {
        "message": "AIVulnHunter API is running.",
        "docs": "http://localhost:8000/docs",
        "frontend": "Open frontend/index.html directly in your browser",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
