from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os
import json
import asyncio
from scan_api import router as scan_router
from rules_api import router as rules_router
from auth import router as auth_router
from report_generator import generate_report
from admin_config import ADMIN_USERNAME, ADMIN_PASSWORD

# Ensure reports directory exists
os.makedirs("reports", exist_ok=True)

app = FastAPI(title="AivulnHunter API")

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(rules_router)
app.include_router(auth_router, prefix="/auth")


@app.websocket("/ws/scan/{target_id}")
async def scan_ws(ws: WebSocket, target_id: str):
    """WebSocket endpoint for real-time scan progress.
    
    Streams agent status updates during vulnerability scanning.
    
    Args:
        ws: WebSocket connection
        target_id: Target system ID being scanned
    """
    await ws.accept()

    await ws.send_json({"agent": "profile", "status": "RUNNING"})
    await asyncio.sleep(1)

    await ws.send_json({"agent": "strategy", "status": "RUNNING"})
    await asyncio.sleep(1)

    await ws.send_json({"agent": "exec", "status": "RUNNING"})
    await asyncio.sleep(1)

    await ws.send_json({"agent": "observer", "status": "RUNNING"})
    await asyncio.sleep(1)

    await ws.send_json({"done": True})

@app.post("/report/pdf")
def generate_pdf_report(data: dict):
    """Generate PDF report from scan data."""
    generate_report(data, "report.pdf")
    return {"status": "PDF generated", "file": "report.pdf"}

@app.get("/report/pdf")
def download_pdf():
    """Download the generated PDF report."""
    return FileResponse("report.pdf", filename="ai_vulnerability_report.pdf")

@app.get("/report/{scan_id}")
def generate_pdf_by_scan_id(scan_id: str):
    """Generate and download PDF report for a specific scan ID."""
    file_path = f"reports/{scan_id}.pdf"
    generate_report({"target": scan_id, "results": []}, file_path)
    return FileResponse(file_path, filename=f"scan_report_{scan_id}.pdf")

@app.get("/rl/priorities")
def get_rl_priorities():
    """Get RL-learned rule priorities sorted by priority.
    
    Returns:
        List of rule priority scores from Q-learning:
        [{"rule": "Prompt Injection", "priority": 0.92}, ...]
    """
    try:
        with open("rl/rule_scores.json") as f:
            scores = json.load(f)
        
        # Convert to array format sorted by priority (descending)
        priorities = [
            {"rule": rule, "priority": round(score, 2)}
            for rule, score in scores.items()
        ]
        priorities.sort(key=lambda x: x["priority"], reverse=True)
        
        return priorities
    except FileNotFoundError:
        return []

