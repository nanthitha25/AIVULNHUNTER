from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import sys
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Adjust path to find backend modules if running directly
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
from backend.routes.demo import router as demo_router
from backend.routes.assistant import router as assistant_router

# Initialize database on startup
try:
    from backend.database.sqlite_db import init_db
    init_db()
except ImportError:
    logger.warning("Could not initialize database - sqlite_db.init_db not found")

app = FastAPI(
    title="AIVulnHunter API",
    description=(
        "Professional AI Security Testing Platform — "
        "OWASP LLM Top-10 scanning, MCP agent orchestration, and controlled red teaming."
    ),
    version="2.0.0",
)

# Allow all origins so the frontend can call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API V1 Router Mounting
API_PREFIX = "/api/v1"

app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(scan_router, prefix=f"{API_PREFIX}/scans") 
app.include_router(scan_ws_router, prefix=API_PREFIX)
app.include_router(rules_router, prefix=API_PREFIX)
app.include_router(rl_router, prefix=API_PREFIX) 
app.include_router(rl_stats_router, prefix=API_PREFIX)
app.include_router(report_router, prefix=API_PREFIX)
app.include_router(admin_router, prefix=API_PREFIX)
app.include_router(assistant_router, prefix=API_PREFIX)
app.include_router(demo_router, prefix=API_PREFIX)

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "platform": "AIVulnHunter",
        "version": "2.0.0"
    }

@app.get("/")
def root():
    return {
        "message": "AIVulnHunter API is running.",
        "docs": "http://localhost:8000/docs",
        "frontend": "Open frontend/index.html or use Next.js dashboard",
    }

# Legacy frontend mounting removed during cleanup.
# The project now exclusively uses the Next.js frontend in frontend-next/

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
