import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.database import crud_scans, crud_rules
from backend.agents.registry import registry
from backend.agents.core.profiling_agent import ProfilingAgent
from backend.agents.core.strategy_agent import StrategyAgent
from backend.agents.core.execution_agent import ExecutionAgent
from backend.agents.core.observer_agent import ObserverAgent
from backend.agents.core.mcp_agent import MCPAgent
from backend.agents.mcp_tools import execute_mcp_tool
from backend.agents.plugins.llm_scanners import (
    DirectInjectionScanner, InsecureOutputScanner, TrainingDataPoisoningScanner,
    DoSScanner, SupplyChainScanner, SensitiveDisclosureScanner, 
    InsecurePluginScanner, ExcessiveAgencyScanner, OverrelianceScanner, ModelTheftScanner
)
from backend.agents.plugins.api_scanners import ApiAuthScanner
from backend.agents.plugins.api_advanced_scanners import (
    AdvancedBOLAScanner, ParameterTamperingScanner, MassAssignmentScanner,
    InjectionFuzzScanner, AdvancedRateLimitScanner
)
from backend.agents.plugins.agent_advanced_scanners import (
    ToolArgumentInjectionScanner, MemoryPoisoningScanner, AutonomousEscalationScanner,
    AdvancedPromptExtractionScanner, ToolChainingExfiltrationScanner
)
from backend.agents.plugins.file_scanners import JSONScanner, CSVScanner
from backend.ws_manager import manager
from backend.security.ai_firewall import ai_firewall

logger = logging.getLogger(__name__)

class PipelineService:
    """
    Orchestrates the multi-agent vulnerability scanning workflow.
    Replaces the legacy scan_pipeline_db.py.
    """
    def __init__(self):
        # Initialize Core Agents
        self.profiler = ProfilingAgent("profiler")
        self.strategy = StrategyAgent("strategy")
        self.executor = ExecutionAgent("executor")
        self.observer = ObserverAgent("observer")
        self.mcp_agent = MCPAgent("mcp_agent")
        
        # Register Plugins (In a real app, this might be dynamic/config-driven)
        self._register_default_plugins()

    def _register_default_plugins(self):
        """Register all built-in scanner plugins."""
        scanners = [
            DirectInjectionScanner, InsecureOutputScanner, TrainingDataPoisoningScanner,
            DoSScanner, SupplyChainScanner, SensitiveDisclosureScanner,
            InsecurePluginScanner, ExcessiveAgencyScanner, OverrelianceScanner,
            ModelTheftScanner, ApiAuthScanner,
            AdvancedBOLAScanner, ParameterTamperingScanner, MassAssignmentScanner,
            InjectionFuzzScanner, AdvancedRateLimitScanner,
            ToolArgumentInjectionScanner, MemoryPoisoningScanner, AutonomousEscalationScanner,
            AdvancedPromptExtractionScanner, ToolChainingExfiltrationScanner,
            JSONScanner, CSVScanner
        ]
        for scanner_cls in scanners:
            registry.register_scanner(scanner_cls)

    async def run_scan(self, db: Session, scan_id: uuid.UUID) -> Dict[str, Any]:
        """
        Execute a full scan pipeline for an existing scan record.
        """
        await asyncio.sleep(1) # Give WS client time to connect
        scan_db = crud_scans.get_scan(db, scan_id)
        if not scan_db:
            logger.error(f"Scan {scan_id} not found in database.")
            return {"scan_id": str(scan_id), "status": "failed", "error": "Scan record not found"}

        target = scan_db.target
        logger.info(f"Starting scan {scan_id} for target: {target}")

        crud_scans.update_scan_status(db, scan_db.id, "running", profile={})
        
        try:
            # Pre-Phase: AI Firewall Layer
            logger.info(f"Pre-Phase: AI Firewall Security Check for {target}")
            await manager.send_progress(str(scan_db.id), "Firewall", 5, "Inspecting target for security threats...")
            
            # Use current target as payload for initial firewall check
            firewall_result = await ai_firewall.inspect(target, target=target)
            
            if firewall_result["decision"] == "BLOCK":
                logger.warning(f"Firewall BLOCKED scan for {target}: {firewall_result['reason']}")
                await manager.send_error(str(scan_db.id), f"Security Blocked: {firewall_result['reason']}")
                
                # Analyze via Observer for consistent reporting
                analysis = await self.observer.process({
                    "result": {
                        "status": "BLOCKED",
                        "owasp": "AI-FIREWALL-BLOCK",
                        "severity": "HIGH",
                        "findings": f"Firewall blocked request: {firewall_result['reason']}",
                        "mitigation": "Review the blocked payload for malicious patterns and source IP.",
                        "is_vulnerable": True,
                        "confidence_score": firewall_result["confidence"]
                    },
                    "context": {"target": target}
                })

                # Persist the block event as a vulnerability finding
                crud_scans.add_vulnerability(
                    db,
                    scan_id=scan_db.id,
                    rule_id=None,
                    name="AI Firewall Block",
                    owasp="AI-FIREWALL",
                    severity=analysis["severity"],
                    status="BLOCKED",
                    confidence=analysis["confidence_score"],
                    explanation=analysis["findings"],
                    mitigation=analysis["mitigation_steps"],
                    evidence=f"Blocked payload for target: {target}"
                )
                
                # Update status to failed but with vulnerability record
                crud_scans.update_scan_status(db, scan_db.id, "failed", profile={"firewall_blocked": True, "reason": firewall_result["reason"]})
                return {"scan_id": str(scan_db.id), "status": "failed", "error": f"Firewall Blocked: {firewall_result['reason']}"}
            
            if firewall_result["decision"] == "SANITIZE":
                logger.info(f"Firewall SANITIZED target input: {target}")
                target = firewall_result["sanitized_payload"]
                await manager.send_progress(str(scan_db.id), "Firewall", 8, "Input sanitized by security layer")

            # Phase 1: Target Profiling
            if scan_db.scan_type == "file_upload":
                logger.info("Phase 1: Profiling (Bypassed for file upload)")
                profile = {"type": "FILE", "reachable": True, "risk_level": "MEDIUM"}
            else:
                logger.info("Phase 1: Profiling Target")
                await manager.send_progress(str(scan_db.id), "TargetProfiling", 10, "Profiling target...")
                profile = await self.profiler.process({"target": target})
                
                # Update DB with profile
                crud_scans.update_scan_status(db, scan_db.id, "running", profile=profile)
                
                if not profile.get("reachable"):
                    logger.error(f"Target {target} is unreachable. Aborting.")
                    await manager.send_error(str(scan_db.id), "Target is not reachable")
                    crud_scans.update_scan_status(db, scan_db.id, "failed", profile=profile)
                    return {"scan_id": str(scan_db.id), "status": "failed", "error": "Target unreachable"}

                await manager.send_progress(str(scan_db.id), "TargetProfiling", 25, f"Target type: {profile.get('type')}")

            # Special case for file upload scan
            if scan_db.scan_type == "file_upload":
                await manager.send_progress(str(scan_db.id), "Scanner", 40, "Scanning file content...")
                file_content = scan_db.meta_data.get("content", "")
                target_filename = scan_db.target.lower()
                
                if target_filename.endswith('.json'):
                    scanner = JSONScanner("json_scanner")
                elif target_filename.endswith('.csv'):
                    scanner = CSVScanner("csv_scanner")
                else:
                    logger.error(f"Unsupported file type for {target}")
                    crud_scans.update_scan_status(db, scan_db.id, "failed")
                    return {"scan_id": str(scan_id), "status": "failed", "error": "Unsupported file type"}
                
                scan_output = await scanner.process({"content": file_content})
                results = scan_output.get("results", [])
                
                for res in results:
                    crud_scans.add_vulnerability(
                        db,
                        scan_id=scan_db.id,
                        rule_id=None,
                        name=res["name"],
                        owasp=res["owasp"],
                        severity=res["severity"],
                        status=res["status"] if "status" in res else "VULNERABLE",
                        confidence=res["confidence_score"],
                        explanation=res["findings"],
                        mitigation=res["mitigation_steps"],
                        evidence=res.get("evidence_snippet")
                    )
                
                # Completion for file scan
                crud_scans.complete_scan(
                    db,
                    scan_id=scan_db.id,
                    vulnerabilities_found=len(results),
                    total_rules_tested=1
                )
                await manager.send_progress(str(scan_db.id), "Scanner", 100, f"Scan complete. Found {len(results)} vulnerabilities.")
                return {"scan_id": str(scan_db.id), "status": "completed", "vulnerabilities": len(results)}

            # Phase 2: Standard Strategy Generation
            logger.info("Phase 2: Generating Attack Strategy")
            await manager.send_progress(str(scan_db.id), "Strategy", 30, "Generating attack strategy...")
            
            # Fetch enabled rules from DB
            db_rules = crud_rules.get_rules(db, enabled_only=True)
            rules_data = [
                {
                    "id": str(r.id),
                    "name": r.name,
                    "owasp": r.owasp,
                    "severity": r.severity,
                    "priority_score": self._get_rule_priority(db, r.id),
                    "tags": [] 
                }
                for r in db_rules
            ]
            
            strategy_output = await self.strategy.process({
                "profile": profile,
                "rules": rules_data
            })
            attack_plan = strategy_output.get("plan", [])
            
            logger.info(f"Strategy created: {len(attack_plan)} steps")
            await manager.send_progress(str(scan_db.id), "Strategy", 40, f"Plan created: {len(attack_plan)} checks")

            # 4. Standard Execution Loop
            logger.info("Phase 3: Executing Attack Plan")
            scan_results = []
            total_checks = len(attack_plan)
            
            for index, rule in enumerate(attack_plan):
                # meaningful progress calculation (40% to 70%)
                progress = 40 + int((index / max(1, total_checks)) * 30)
                await manager.send_progress(str(scan_db.id), "Executor", progress, f"Executing: {rule.get('name', 'Rule')}")
                
                # Execute
                exec_output = await self.executor.process({
                    "target": target,
                    "rule": rule,
                    "scan_id": str(scan_db.id)
                })
                
                results = exec_output.get("results", [])
                
                for res in results:
                    print(f"DEBUG raw result for {rule['name']}: {res}", flush=True)
                    # Observe & Analyze
                    analysis = await self.observer.process({
                        "result": res,
                        "context": {"target": target, "profile": profile}
                    })
                    print(f"DEBUG analysis for {rule['name']}: {analysis}", flush=True)
                    
                    # Store Vulnerability
                    if analysis["is_vulnerable"]:
                        crud_scans.add_vulnerability(
                            db, 
                            scan_id=scan_db.id,
                            rule_id=int(rule["id"]),
                            name=rule["name"],
                            owasp=rule.get("owasp", ""),
                            severity=analysis["severity"],
                            status="VULNERABLE",
                            confidence=analysis["confidence_score"],
                            explanation=analysis["findings"],
                            mitigation=analysis["mitigation_steps"],
                            evidence=analysis.get("evidence_snippet")
                        )
                    
                    # Update RL Weights
                    self._update_rl_weight(db, rule["id"], analysis["rl_reward"])
                    
                    scan_results.append(analysis)
                    
            import os
            env = os.environ.get("ENV", "development")
            use_advanced_mcp = (scan_db.scan_type == "advanced_mcp" and env != "production")
            
            if use_advanced_mcp:
                try:
                    # MCP Optional Augmentation Path
                    logger.info("Phase 3B: MCP Advanced Augmentation")
                    await manager.send_progress(str(scan_db.id), "MCPAgent", 75, "Generating advanced reasoning tool calls...")
                    
                    mcp_output = await self.mcp_agent.process({
                        "target": target,
                        "profile": profile
                    })
                    tool_calls = mcp_output.get("tool_calls", [])
                    
                    logger.info(f"MCPAgent produced {len(tool_calls)} tool calls.")
                    await manager.send_progress(str(scan_db.id), "MCPAgent", 80, f"Running {len(tool_calls)} MCP tools...")
                    
                    total_mcp_checks = len(tool_calls)
                    total_checks += total_mcp_checks
                    for index, tool_call in enumerate(tool_calls):
                        progress = 80 + int((index / max(1, total_mcp_checks)) * 10)
                        t_name = tool_call.get("name", "UnknownTool")
                        await manager.send_progress(str(scan_db.id), "MCPAgent", progress, f"Executing MCP Tool: {t_name}")
                        
                        # Execute
                        ctx = {"target": target, "profile": profile, "scan_id": str(scan_db.id)}
                        res = await execute_mcp_tool(tool_call, ctx)
                        
                        logger.info(f"[MCP_AGENT] raw result for {t_name}: {res}")
                        # Observe & Analyze using standard Observer
                        analysis = await self.observer.process({
                            "result": res,
                            "context": ctx
                        })
                        logger.info(f"[MCP_AGENT] analysis for {t_name}: {analysis}")
                        
                        # Store Vulnerability
                        if analysis["is_vulnerable"]:
                            crud_scans.add_vulnerability(
                                db, 
                                scan_id=scan_db.id,
                                rule_id=None, # MCP tools might not map directly to DB rules initially
                                name=res.get("scan_rule", t_name),
                                owasp=res.get("owasp", "Custom"),
                                severity=analysis["severity"],
                                status="VULNERABLE",
                                confidence=analysis["confidence_score"],
                                explanation=analysis["findings"],
                                mitigation=analysis["mitigation_steps"],
                                evidence=analysis.get("evidence_snippet")
                            )
                        
                        scan_results.append(analysis)
                except Exception as e:
                    logger.error(f"[MCP_AGENT] failed safely: {e}", exc_info=True)

            # 5. Completion
            await manager.send_progress(str(scan_db.id), "Observer", 90, "Finalizing report...")
            vulnerabilities_count = sum(1 for r in scan_results if r["is_vulnerable"])
            crud_scans.complete_scan(
                db, 
                scan_id=scan_db.id, 
                vulnerabilities_found=vulnerabilities_count,
                total_rules_tested=total_checks
            )
            
            logger.info(f"Scan {scan_id} completed. Found {vulnerabilities_count} vulnerabilities.")
            await manager.send_progress(str(scan_db.id), "Observer", 100, f"Scan complete. Found {vulnerabilities_count} vulnerabilities.")
            
            return {
                "scan_id": str(scan_db.id),
                "status": "completed",
                "vulnerabilities": vulnerabilities_count,
                "results": scan_results
            }

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            crud_scans.update_scan_status(db, scan_db.id, "failed", profile={})
            await manager.send_error(str(scan_db.id), f"Scan failed: {str(e)}")
            return {"scan_id": str(scan_db.id), "status": "failed", "error": str(e)}

    def _get_rule_priority(self, db: Session, rule_id: int) -> float:
        """Helper to get RL priority score from database."""
        try:
            rl_weight = crud_rules.get_rl_weight(db, rule_id)
            if rl_weight:
                return rl_weight.priority_score
            return 1.0 # Default baseline
        except Exception as e:
            logger.error(f"Error fetching rule priority: {e}")
            return 1.0

    def _update_rl_weight(self, db: Session, rule_id: str, reward: float):
        """Helper to update RL weights in database."""
        try:
            crud_rules.update_rl_weight(db, int(rule_id), reward=reward)
        except Exception as e:
            logger.error(f"Failed to update RL weight: {e}")

# Singleton instance
pipeline_service = PipelineService()
