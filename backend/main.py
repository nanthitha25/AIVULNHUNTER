<<<<<<< HEAD
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
=======
import fastapi
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
>>>>>>> 3119ac5 (Complete implementation of AivulnHunter with Next.js frontend, FastAPI backend, and Security Assistant)
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import sys
<<<<<<< HEAD

=======
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Adjust path to find backend modules if running directly
>>>>>>> 3119ac5 (Complete implementation of AivulnHunter with Next.js frontend, FastAPI backend, and Security Assistant)
if __name__ == "__main__":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend.routes.auth import router as auth_router
from backend.routes.scan import router as scan_router
from backend.routes.scan_ws import router as scan_ws_router
from backend.routes.rules import router as rules_router
from backend.routes.rl import router as rl_router
from backend.routes.rl_stats import router as rl_stats_router
from backend.routes.report import router as report_router
from backend.routes.admin import router as admin_router
<<<<<<< HEAD
from backend.routes.demo import router as demo_router
=======
>>>>>>> 3119ac5 (Complete implementation of AivulnHunter with Next.js frontend, FastAPI backend, and Security Assistant)
from backend.routes.assistant import router as assistant_router

# Initialize database on startup
try:
    from backend.database.sqlite_db import init_db
    init_db()
except ImportError:
    pass

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

<<<<<<< HEAD
# ── API Routers only — no static file mounts ─────────────────────── #
app.include_router(auth_router, prefix="/api/v1")
app.include_router(scan_router, prefix="/api/v1")
app.include_router(scan_ws_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")
app.include_router(demo_router, prefix="/api/v1")
app.include_router(rl_router, prefix="/api/v1")
app.include_router(rl_stats_router, prefix="/api/v1")
app.include_router(report_router, prefix="/api/v1")
app.include_router(assistant_router, prefix="/api/v1")

@app.get("/health")
def health_check():
    """Platform health check endpoint."""
    return {
        "status": "OK",
        "platform": "AIVulnHunter",
        "version": "2.0.0",
        "docs": "/docs",
    }
=======
# API V1 Router Mounting
API_PREFIX = "/api/v1"

app.include_router(auth_router, prefix=API_PREFIX)
# scan_router defines no prefix, so we assign it here
app.include_router(scan_router, prefix=f"{API_PREFIX}/scans") 
app.include_router(scan_ws_router, prefix=API_PREFIX)
app.include_router(rules_router, prefix=API_PREFIX)
# Merge RL routers? For now mount both, assuming no path collisions or ignoring them
app.include_router(rl_router, prefix=API_PREFIX) 
# app.include_router(rl_stats_router, prefix=API_PREFIX) # Commenting out to avoid collision on /rl/heatmap


app.include_router(report_router, prefix=API_PREFIX)
app.include_router(admin_router, prefix=API_PREFIX)
app.include_router(assistant_router)
@app.get("/health")
def health_check():
    return {"status": "ok"}
>>>>>>> 3119ac5 (Complete implementation of AivulnHunter with Next.js frontend, FastAPI backend, and Security Assistant)

@app.get("/")
def root():
    return {
        "message": "AIVulnHunter API is running.",
        "docs": "http://localhost:8000/docs",
        "frontend": "Open frontend/index.html or use Next.js dashboard",
    }

# Mount frontend static files
frontend_path = Path(__file__).resolve().parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
else:
    logger.info("Frontend directory not found, skipping static mount.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
