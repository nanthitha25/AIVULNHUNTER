from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

# Adjust path to find backend modules if running directly
import sys
if __name__ == "__main__":
    # Add project root to path
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend.routes.auth import router as auth_router
from backend.routes.scan import router as scan_router
from backend.routes.scan_ws import router as scan_ws_router
from backend.routes.rules import router as rules_router
from backend.routes.rl import router as rl_router
from backend.routes.rl_stats import router as rl_stats_router
from backend.routes.report import router as report_router

app = FastAPI(title="AivulnHunter API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(scan_ws_router)
app.include_router(rules_router)
app.include_router(rl_router)
app.include_router(rl_stats_router)
app.include_router(report_router)

# Mount frontend static files
frontend_path = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

@app.get("/")
def root():
    return {"status": "Backend OK", "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    # Make sure we run the app from the package context
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
