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
            with open("backend/rules/rules.json") as f:
                rules_db = json.load(f)
            print(f"[Pipeline] Loaded {len(rules_db)} rules from database")
        except Exception as e:
            print(f"[Pipeline] Error loading rules: {e}, using defaults")
            rules_db = [
                {
                    "id": "1",
                    "name": "Prompt Injection",
                    "owasp_id": "LLM01",
                    "severity": "HIGH",
                    "priority": 1
                },
                {
                    "id": "2",
                    "name": "Data Leakage",
                    "owasp_id": "LLM02",
                    "severity": "MEDIUM",
                    "priority": 2
                },
                {
                    "id": "3",
                    "name": "Information Disclosure",
                    "owasp_id": "LLM03",
                    "severity": "LOW",
                    "priority": 3
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
        
        attack_plan = build_attack_plan(profile, rules_db)
        await send_progress("Attack Strategy", 50, f"Plan created with {len(attack_plan)} attacks")
        
        # Step 3: Execute + Observe for each attack (50-100%)
        total_attacks = len(attack_plan)
        
        for i, attack in enumerate(attack_plan):
            attack_name = attack.get("rule", {}).get("name", f"Attack {i+1}")
            attack_progress = 50 + int((i / total_attacks) * 40)
            
            await send_progress("Executor", attack_progress, f"Executing: {attack_name}")
            
            try:
                execution = execute_rule(target, attack)
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
                results.append({
                    "rule_id": attack["rule"].get("id", "unknown"),
                    "name": attack["rule"].get("name", "Unknown"),
                    "owasp": attack["rule"].get("owasp", "N/A"),
                    "severity": attack["rule"].get("severity", "UNKNOWN"),
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
    
    # Run the async pipeline
    import asyncio
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_with_progress())
        loop.close()
        return result
    except Exception as e:
        print(f"[Pipeline] Error: {e}")
        SCANS_DB[scan_id]["status"] = "error"
        return {
            "scan_id": scan_id,
            "status": "error",
            "message": str(e),
            "target": target,
            "profile": {},
            "results": []
        }


def get_scan_result(scan_id: str) -> dict:
    """Get a previously run scan result by ID."""
    return SCANS_DB.get(scan_id, None)

