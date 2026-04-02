from typing import Dict, Any, List
import logging
import asyncio
from backend.agents.base import BaseAgent
from backend.agents.registry import registry

logger = logging.getLogger(__name__)

class ExecutionAgent(BaseAgent):
    """
    Agent responsible for executing the attack plan using registered scanner plugins.
    """
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single rule or a batch of rules.
        Expects 'target' and 'rules' (list) or 'rule' (single) in input_data.
        """
        target = input_data.get("target")
        rules = input_data.get("rules", [])
        scan_id = input_data.get("scan_id")
        
        if not target:
            raise ValueError("Target is required for execution")

        results = []
        
        # Handle single rule or list
        if not rules and input_data.get("rule"):
            rules = [input_data.get("rule")]

        logger.info(f"Executing {len(rules)} rules against {target}")

        for rule in rules:
            rule_code = rule.get("owasp")
            if not rule_code:
                logger.warning(f"Rule missing OWASP code: {rule}")
                continue

            # Find the appropriate scanner plugin
            # For this MVP, we might map generic LLM scanners to a single plugin 
            # or have specific plugins for each rule.
            # Using a simplified lookup for now.
            scanner = registry.get_scanner_for_rule(rule_code)
            
            if scanner:
                try:
                    logger.info(f"Running scanner {scanner.agent_id} for {rule_code}")
                    # Prepare context
                    context = {
                        "rule": rule,
                        "scan_id": scan_id
                    }
                    
                    # Execute
                    result = await scanner.scan(target, context)
                    
                    # Augment result with metadata
                    result["rule_id"] = rule.get("id")
                    result["owasp"] = rule_code
                    result["scan_id"] = scan_id
                    
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Error executing scanner for {rule_code}: {e}")
                    results.append({
                        "status": "ERROR",
                        "rule_id": rule.get("id"),
                        "owasp": rule_code,
                        "error": str(e)
                    })
            else:
                logger.warning(f"No scanner registered for rule {rule_code}")
                results.append({
                    "status": "SKIPPED",
                    "rule_id": rule.get("id"),
                    "owasp": rule_code,
                    "reason": "No scanner plugin found"
                })

        return {"results": results}
