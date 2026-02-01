from fastapi import APIRouter, HTTPException, Depends, Response
import json
import os
import uuid
from datetime import datetime
from typing import Dict, Any

from backend.agents.target_profiling import target_profiling
from backend.agents.attack_strategy import build_attack_plan
from backend.agents.executor import execute_attacks
from backend.agents.observer import analyze_results
from backend.report_generator import generate_report
from backend.routes.auth import get_current_admin
from backend.routes.rules import rules_db
from backend.ws_manager import manager

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "ai_systems.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# In-memory scan storage
scans: Dict[str, Dict[str, Any]] = {}

# Ensure reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)


@router.post("/scan")
async def scan_target(
    target_id: str, 
    target_type: str = "llm", 
    admin: str = Depends(get_current_admin)
):
    """
    Start a vulnerability scan on the target with real-time progress updates.
    
    This endpoint supports both:
    1. Dataset-based scans: Use a target_id that exists in ai_systems.json
    2. URL-based scans: Use any URL as target_id (will be probed in real-time)
    
    Pipeline:
    1. Target Profiling Agent - 25% (probes the target in real-time)
    2. Attack Strategy Agent - 50%
    3. Attack Execution Agent - 75%
    4. Analysis & XAI Agent - 100%
    
    Args:
        target_id: Either a dataset ID (e.g., "llm_001") or a URL (e.g., "http://localhost:9000/chat")
        target_type: Scan type (llm, api, quick, full)
        admin: Authenticated admin user
        
    Returns:
        Scan results with profile, attacks, and analysis
    """
    # Check if target_id is a URL or dataset ID
    is_url = target_id.startswith("http://") or target_id.startswith("https://")
    
    if is_url:
        # URL-based scanning - probe the target directly
        target = {
            "id": target_id,
            "name": target_id,
            "type": "LIVE_URL",
            "url": target_id
        }
    else:
        # Dataset-based scanning
        if not os.path.exists(DATASET_PATH):
            raise HTTPException(status_code=500, detail="Dataset missing")

        with open(DATASET_PATH) as f:
            systems = json.load(f)

        if target_id not in systems:
            raise HTTPException(status_code=404, detail="Target not found")

        target = systems[target_id]
    
    # Generate scan_id early for WebSocket tracking
    scan_id = str(uuid.uuid4())

    # 2️⃣ Run agents with WebSocket progress updates
    
    # Step 1: Target Profiling (25%) - REAL-TIME PROBING
    await manager.send_progress(scan_id, "Target Profiling", 25, "Probing target system...")
    profile = target_profiling(target_id if is_url else target.get("url", target_id))
    
    # Show target info in progress
    reachability = "Reachable" if profile.get("reachable") else "Unreachable"
    await manager.send_progress(
        scan_id, 
        "Target Profiling", 
        25, 
        f"{reachability} - {profile.get('type', 'UNKNOWN')}"
    )
    
    # Step 2: Attack Strategy (50%)
    await manager.send_progress(scan_id, "Attack Strategy", 50, "Building attack plan...")
    attacks = build_attack_plan(profile, rules_db, target_type)
    await manager.send_progress(scan_id, "Attack Strategy", 50, f"Generated {len(attacks)} attack vectors")
    
    # Step 3: Attack Execution (75%)
    total_attacks = len(attacks)
    await manager.send_progress(scan_id, "Attack Execution", 55, f"Executing {total_attacks} security checks...")
    
    # Execute attacks against the target URL
    target_url = target_id if is_url else target.get("url", target_id)
    execution_results = execute_attacks(attacks, target_url)
    
    for i, result in enumerate(execution_results):
        # Progress from 55% to 75%
        attack_progress = 55 + (20 * (i + 1) / max(total_attacks, 1))
        status_indicator = "[VULNERABLE]" if result.get("status") == "VULNERABLE" else "[SECURE]"
        await manager.send_progress(
            scan_id, 
            "Attack Execution", 
            int(attack_progress),
            f"{status_indicator} {result.get('attack', f'Attack {i+1}')}"
        )
    
    # Step 4: Analysis & XAI (100%)
    await manager.send_progress(scan_id, "Analysis & XAI", 90, "Generating explainable AI analysis...")
    analysis = analyze_results(execution_results)
    await manager.send_progress(scan_id, "Analysis & XAI", 100, "Scan complete!")

    # 3️⃣ Generate scan_id and store results
    timestamp = datetime.utcnow().isoformat()
    
    scan_result = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "target": target,
        "target_url": target_url,
        "profile": profile,
        "attacks": attacks,
        "results": analysis,
        "explainable_ai": analysis,
        "scan_type": target_type,
        "is_live_scan": is_url
    }
    
    scans[scan_id] = scan_result
    
    # 4️⃣ Generate PDF report
    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
    generate_report(scan_result, report_path)
    
    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "target": target,
        "target_url": target_url,
        "profile": profile,
        "attacks": attacks,
        "results": analysis,
        "explainable_ai": analysis,
        "report_url": f"/scan/{scan_id}/report",
        "is_live_scan": is_url
    }


@router.get("/scan/{scan_id}")
def get_scan_result(scan_id: str, admin: str = Depends(get_current_admin)):
    """Get scan result by ID"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@router.get("/scan/{scan_id}/report")
def download_scan_report(scan_id: str, admin: str = Depends(get_current_admin)):
    """Download PDF report for a scan"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
    if not os.path.exists(report_path):
        # Generate report if it doesn't exist
        generate_report(scans[scan_id], report_path)
    
    with open(report_path, "rb") as f:
        report_content = f.read()
    
    return Response(
        content=report_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}_report.pdf"}
    )


@router.get("/scans")
def list_scans(admin: str = Depends(get_current_admin)):
    """List all scans"""
    return [
        {
            "scan_id": sid, 
            "timestamp": s["timestamp"], 
            "target_url": s.get("target_url", s.get("target", {}).get("name", "Unknown")),
            "is_live_scan": s.get("is_live_scan", False)
        } 
        for sid, s in scans.items()
    ]


@router.post("/scan/quick")
async def quick_scan(target_url: str, admin: str = Depends(get_current_admin)):
    """
    Quick health check scan for a target URL.
    
    Performs basic reachability and type detection without full attack execution.
    """
    scan_id = str(uuid.uuid4())
    
    # Quick profiling
    await manager.send_progress(scan_id, "Quick Check", 25, "Probing target...")
    profile = target_profiling(target_url)
    
    await manager.send_progress(scan_id, "Quick Check", 100, "Complete!")
    
    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "profile": profile,
        "status": "completed"
    }

