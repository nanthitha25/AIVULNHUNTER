"""
Scan Pipeline Orchestrator - Coordinates the multi-agent scanning process

User Input → Target Profiling → Attack Strategy → Executor → Observer → Results
"""

from backend.agents.target_profiling import target_profiling
from backend.agents.attack_strategy import build_attack_plan
from backend.agents.executor import execute_rule
from backend.agents.observer import observe
from backend.services.rl_engine import update_rl
from backend.ws_manager import manager
import uuid

# Global storage for scan results (in production, use a database)
SCANS_DB = {}

def run_scan_pipeline(target: str, rules_db: list = None, scan_id: str = None):
    """
    Execute the full scan pipeline for a given target.
    
    Args:
        target: The URL or identifier of the target to scan
        rules_db: List of security rules to test (optional, uses defaults if None)
        scan_id: Optional scan ID for WebSocket progress updates
        
    Returns:
        Dictionary containing:
        - scan_id: Unique identifier for the scan
        - status: "success" or "error"
        - target: The target that was scanned
        - profile: Target profiling information
        - results: List of vulnerability scan results
    """
    # Generate scan ID if not provided
    if scan_id is None:
        scan_id = str(uuid.uuid4())
    
    results = []
    
    # Load dynamic rules from rules.json if none provided
    if rules_db is None or len(rules_db) == 0:
        try:
            import json
            from pathlib import Path
            
            # Try to locate rules.json relative to this file
            base_dir = Path(__file__).resolve().parent.parent
            rules_path = base_dir / "rules" / "rules.json"
            
            with open(rules_path) as f:
                rules_db = json.load(f)
            print(f"[Pipeline] Loaded {len(rules_db)} rules from database")
        except Exception as e:
            print(f"[Pipeline] Error loading rules: {e}, using defaults")
            rules_db = [
                {
                    "id": "1",
                    "name": "Prompt Injection",
                    "owasp": "LLM01",
                    "severity": "HIGH",
                    "priority": 1
                },
                {
                    "id": "3",
                    "name": "Training Data Poisoning",
                    "owasp": "LLM03",
                    "severity": "CRITICAL",
                    "priority": 1
                },
                {
                    "id": "5",
                    "name": "Supply Chain Vulnerabilities",
                    "owasp": "LLM05",
                    "severity": "CRITICAL",
                    "priority": 1
                },
                {
                    "id": "8",
                    "name": "Excessive Agency",
                    "owasp": "LLM08",
                    "severity": "CRITICAL",
                    "priority": 1
                }
            ]
    
    # Initialize scan result storage
    SCANS_DB[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "status": "running",
        "profile": {},
        "results": [],
        "rl_scores": {}
    }
    
    # Send WebSocket progress updates
    async def send_progress(agent: str, progress: int, details: str = ""):
        """Helper to send progress to WebSocket clients."""
        try:
            await manager.send_progress(scan_id, agent, progress, details)
        except Exception as e:
            print(f"[Pipeline] WebSocket send error: {e}")
    
    # 1️⃣ Target Profiling (0-25%)
    import asyncio
    
    async def run_with_progress():
        nonlocal results
        
        # Step 1: Target Profiling
        await send_progress("Target Profiling", 5, "Starting target analysis...")
        await asyncio.sleep(0.5)  # Small delay for visual effect
        
        profile = target_profiling(target)
        await send_progress("Target Profiling", 25, f"Target type: {profile.get('type', 'UNKNOWN')}")
        
        SCANS_DB[scan_id]["profile"] = profile
        
        if not profile["reachable"]:
            SCANS_DB[scan_id]["status"] = "error"
            SCANS_DB[scan_id]["results"] = []
            await send_progress("Target Profiling", 25, "Target not reachable")
            await manager.send_error(scan_id, "Target is not reachable")
            return {
                "scan_id": scan_id,
                "status": "error",
                "message": "Target is not reachable",
                "target": target,
                "profile": profile,
                "results": []
            }
        
        # Step 2: Attack Strategy (25-50%)
        await send_progress("Attack Strategy", 30, "Analyzing attack vectors...")
        await asyncio.sleep(0.3)
        
        # Use the profiled target type to guide the attack strategy
        detected_type = profile.get("type", "WEB_APP")
        attack_plan = build_attack_plan(profile, rules_db, scan_type=detected_type)
        await send_progress("Attack Strategy", 50, f"Plan created with {len(attack_plan)} attacks (Mode: {detected_type})")
        
        # Step 3: Execute + Observe for each attack (50-100%)
        total_attacks = len(attack_plan)
        
        for i, attack in enumerate(attack_plan):
            attack_name = attack.get("name", f"Attack {i+1}")
            attack_progress = 50 + int((i / total_attacks) * 40)
            
            await send_progress("Executor", attack_progress, f"Executing: {attack_name}")
            
            try:
                # execute_rule expects (rule, target)
                execution = execute_rule(attack, target)
                observed = observe(execution)
                
                # RL update happens HERE - update rules based on scan result
                rule_id = observed.get("rule_id")
                status = observed.get("status", "UNKNOWN")
                
                # Find and update the matching rule in rules_db
                if rules_db:
                    for rule in rules_db:
                        if rule.get("id") == rule_id:
                            update_rl(rule, status)
                            # Store RL score
                            SCANS_DB[scan_id]["rl_scores"][rule["name"]] = rule.get("rl_score", 0)
                            break
                
                results.append(observed)
                SCANS_DB[scan_id]["results"] = results
                
            except Exception as e:
                print(f"[Pipeline] Error executing rule {attack.get('name')}: {e}")
                results.append({
                    "rule_id": attack.get("id", "unknown"),
                    "name": attack.get("name", "Unknown"),
                    "owasp": attack.get("owasp", "N/A"),
                    "severity": attack.get("severity", "UNKNOWN"),
                    "status": "ERROR",
                    "error": str(e),
                    "explanation": "Scan encountered an error during execution",
                    "mitigation": "Check target availability and try again"
                })
                SCANS_DB[scan_id]["results"] = results
        
        # Step 4: Observer - Final analysis (90-100%)
        await send_progress("Observer", 90, "Generating vulnerability report...")
        await asyncio.sleep(0.3)
        
        vuln_count = len([r for r in results if r.get("status") == "VULNERABLE"])
        await send_progress("Observer", 100, f"Scan complete. Found {vuln_count} vulnerabilities")
        
        # Mark scan as complete
        SCANS_DB[scan_id]["status"] = "success"
        
        return {
            "scan_id": scan_id,
            "status": "success",
            "target": target,
            "profile": profile,
            "results": results
        }
    
    async def run_wrapper():
        try:
            await run_with_progress()
        except Exception as e:
            print(f"[Pipeline] Error: {e}")
            SCANS_DB[scan_id]["status"] = "error"

    # Use existing loop if available (FastAPI / Uvicorn), otherwise create new
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(run_wrapper())
        else:
            loop.run_until_complete(run_wrapper())
    except RuntimeError:
        asyncio.run(run_wrapper())

    return {
        "scan_id": scan_id,
        "target": target,
        "status": "started",
        "results_url": f"/scan/{scan_id}"
    }


def get_scan_result(scan_id: str) -> dict:
    """Get a previously run scan result by ID."""
    return SCANS_DB.get(scan_id, None)

