"""
Scan Pipeline Orchestrator with PostgreSQL Integration
Coordinates the multi-agent scanning process with database persistence

User Input → Target Profiling → Attack Strategy → Executor → Observer → Results
"""

from backend.agents.target_profiling import target_profiling
from backend.agents.attack_strategy import build_attack_plan
from backend.agents.executor import execute_rule
from backend.agents.observer import observe
from backend.database.connection import SessionLocal
from backend.database import crud_scans, crud_rules
from backend.ws_manager import manager
import uuid
import asyncio
from datetime import datetime


def run_scan_pipeline(target: str, scan_id: str = None, user_id: uuid.UUID = None):
    """
    Execute the full scan pipeline for a given target with PostgreSQL persistence.
    
    Args:
        target: The URL or identifier of the target to scan
        scan_id: Optional scan ID (will be generated if not provided)
        user_id: Optional user ID who initiated the scan
        
    Returns:
        Dictionary containing:
        - scan_id: Unique identifier for the scan
        - status: "started", "success" or "error"
        - target: The target that was scanned
        - results_url: URL to fetch results
    """
    # Get database session
    db = SessionLocal()
    
    try:
        # Generate scan ID if not provided
        if scan_id is None:
            scan_id = str(uuid.uuid4())
        else:
            scan_id = str(scan_id)
        
        scan_uuid = uuid.UUID(scan_id)
        
        # Create scan record in database
        scan = crud_scans.create_scan(
            db=db,
            target=target,
            user_id=user_id,
            scan_type="full"
        )
        
        # Update scan_id to match database record
        scan_id = str(scan.id)
        scan_uuid = scan.id
        
        # Log scan start
        crud_scans.add_scan_log(
            db=db,
            scan_id=scan_uuid,
            agent_name="Pipeline",
            log_level="INFO",
            message=f"Scan started for target: {target}"
        )
        
        # Load rules from database
        rules = crud_rules.get_rules(db, enabled_only=True)
        
        # Convert SQLAlchemy models to dictionaries for compatibility
        rules_db = [
            {
                "id": str(rule.id),
                "name": rule.name,
                "owasp": rule.owasp,
                "severity": rule.severity,
                "priority": rule.priority,
                "description": rule.description or "",
                "enabled": rule.enabled,
                "target_types": rule.target_types or []
            }
            for rule in rules
        ]
        
        print(f"[Pipeline] Loaded {len(rules_db)} rules from database")
        
        # Run async scan workflow
        async def run_with_progress():
            results = []
            
            # Update scan status to running
            crud_scans.update_scan_status(db, scan_uuid, "running")
            
            # Send WebSocket progress updates
            async def send_progress(agent: str, progress: int, details: str = ""):
                """Helper to send progress to WebSocket clients."""
                try:
                    await manager.send_progress(scan_id, agent, progress, details)
                except Exception as e:
                    print(f"[Pipeline] WebSocket send error: {e}")
            
            # Step 1: Target Profiling (0-25%)
            await send_progress("Target Profiling", 5, "Starting target analysis...")
            await asyncio.sleep(0.5)
            
            profile = target_profiling(target)
            await send_progress("Target Profiling", 25, f"Target type: {profile.get('type', 'UNKNOWN')}")
            
            # Update scan with profile
            crud_scans.update_scan_status(db, scan_uuid, "running", profile=profile)
            
            crud_scans.add_scan_log(
                db=db,
                scan_id=scan_uuid,
                agent_name="TargetProfiling",
                log_level="INFO",
                message=f"Target profiled as {profile.get('type')}",
                details=profile
            )
            
            if not profile["reachable"]:
                crud_scans.update_scan_status(db, scan_uuid, "failed")
                crud_scans.add_scan_log(
                    db=db,
                    scan_id=scan_uuid,
                    agent_name="TargetProfiling",
                    log_level="ERROR",
                    message="Target is not reachable"
                )
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
            
            detected_type = profile.get("type", "WEB_APP")
            attack_plan = build_attack_plan(profile, rules_db, scan_type=detected_type)
            await send_progress("Attack Strategy", 50, f"Plan created with {len(attack_plan)} attacks (Mode: {detected_type})")
            
            crud_scans.add_scan_log(
                db=db,
                scan_id=scan_uuid,
                agent_name="AttackStrategy",
                log_level="INFO",
                message=f"Attack plan created with {len(attack_plan)} rules"
            )
            
            # Step 3: Execute + Observe for each attack (50-100%)
            total_attacks = len(attack_plan)
            
            for i, attack in enumerate(attack_plan):
                attack_name = attack.get("name", f"Attack {i+1}")
                attack_progress = 50 + int((i / total_attacks) * 40)
                
                await send_progress("Executor", attack_progress, f"Executing: {attack_name}")
                
                try:
                    # Execute rule
                    execution = execute_rule(attack, target)
                    observed = observe(execution)
                    
                    # Add rule metadata
                    observed["rule_id"] = attack.get("id")
                    observed["name"] = attack.get("name")
                    observed["owasp"] = attack.get("owasp")
                    observed["severity"] = attack.get("severity")
                    
                    # Store vulnerability in database
                    crud_scans.add_vulnerability(
                        db=db,
                        scan_id=scan_uuid,
                        rule_id=int(attack.get("id")) if attack.get("id") else None,
                        name=observed.get("name", attack_name),
                        owasp=observed.get("owasp", "UNKNOWN"),
                        severity=observed.get("severity", "MEDIUM"),
                        status=observed.get("status", "UNKNOWN"),
                        confidence=observed.get("confidence", 0.5),
                        explanation=observed.get("explanation", ""),
                        mitigation=observed.get("mitigation", ""),
                        evidence=observed.get("evidence", ""),
                        error_message=observed.get("error", "")
                    )
                    
                    # Update RL weights
                    rule_id = int(attack.get("id")) if attack.get("id") else None
                    if rule_id:
                        success = observed.get("status") == "VULNERABLE"
                        crud_rules.update_rl_weight(db, rule_id, success=success)
                    
                    results.append(observed)
                    
                    crud_scans.add_scan_log(
                        db=db,
                        scan_id=scan_uuid,
                        agent_name="Executor",
                        log_level="INFO",
                        message=f"Executed {attack_name}: {observed.get('status')}",
                        details=observed
                    )
                    
                except Exception as e:
                    print(f"[Pipeline] Error executing rule {attack.get('name')}: {e}")
                    error_result = {
                        "rule_id": attack.get("id", "unknown"),
                        "name": attack.get("name", "Unknown"),
                        "owasp": attack.get("owasp", "N/A"),
                        "severity": attack.get("severity", "UNKNOWN"),
                        "status": "ERROR",
                        "error": str(e),
                        "explanation": "Scan encountered an error during execution",
                        "mitigation": "Check target availability and try again",
                        "confidence": 0.0
                    }
                    
                    # Store error in database
                    crud_scans.add_vulnerability(
                        db=db,
                        scan_id=scan_uuid,
                        rule_id=int(attack.get("id")) if attack.get("id") else None,
                        name=error_result["name"],
                        owasp=error_result["owasp"],
                        severity=error_result["severity"],
                        status="ERROR",
                        confidence=0.0,
                        explanation=error_result["explanation"],
                        mitigation=error_result["mitigation"],
                        error_message=str(e)
                    )
                    
                    results.append(error_result)
                    
                    crud_scans.add_scan_log(
                        db=db,
                        scan_id=scan_uuid,
                        agent_name="Executor",
                        log_level="ERROR",
                        message=f"Error executing {attack_name}: {str(e)}"
                    )
            
            # Step 4: Observer - Final analysis (90-100%)
            await send_progress("Observer", 90, "Generating vulnerability report...")
            await asyncio.sleep(0.3)
            
            vuln_count = len([r for r in results if r.get("status") == "VULNERABLE"])
            await send_progress("Observer", 100, f"Scan complete. Found {vuln_count} vulnerabilities")
            
            # Mark scan as complete in database
            crud_scans.complete_scan(
                db=db,
                scan_id=scan_uuid,
                vulnerabilities_found=vuln_count,
                total_rules_tested=len(attack_plan)
            )
            
            crud_scans.add_scan_log(
                db=db,
                scan_id=scan_uuid,
                agent_name="Observer",
                log_level="INFO",
                message=f"Scan completed. Found {vuln_count} vulnerabilities out of {len(attack_plan)} tests"
            )
            
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
                crud_scans.update_scan_status(db, scan_uuid, "failed")
                crud_scans.add_scan_log(
                    db=db,
                    scan_id=scan_uuid,
                    agent_name="Pipeline",
                    log_level="CRITICAL",
                    message=f"Scan failed: {str(e)}"
                )
        
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
    
    finally:
        db.close()


def get_scan_result(scan_id: str) -> dict:
    """
    Get a previously run scan result by ID from database.
    
    Args:
        scan_id: UUID of the scan
        
    Returns:
        Dictionary with scan details and vulnerabilities
    """
    db = SessionLocal()
    
    try:
        scan_uuid = uuid.UUID(scan_id)
        scan = crud_scans.get_scan(db, scan_uuid)
        
        if not scan:
            return None
        
        # Get vulnerabilities
        vulnerabilities = crud_scans.get_scan_vulnerabilities(db, scan_uuid)
        
        # Convert to dictionary format
        results = [
            {
                "rule_id": str(v.rule_id) if v.rule_id else None,
                "name": v.name,
                "owasp": v.owasp,
                "severity": v.severity,
                "status": v.status,
                "confidence": v.confidence,
                "explanation": v.explanation,
                "mitigation": v.mitigation,
                "evidence": v.evidence,
                "error": v.error_message
            }
            for v in vulnerabilities
        ]
        
        return {
            "scan_id": str(scan.id),
            "target": scan.target,
            "status": scan.status,
            "profile": scan.profile,
            "results": results,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "total_rules_tested": scan.total_rules_tested,
            "vulnerabilities_found": scan.vulnerabilities_found
        }
    
    finally:
        db.close()
