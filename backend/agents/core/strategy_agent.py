from typing import Dict, Any, List
import logging
from backend.agents.base import BaseAgent
# In a real scenario we would import the DB session to fetch rules, 
# but for now we'll assume rules are passed in or fetched via a helper.

logger = logging.getLogger(__name__)

class StrategyAgent(BaseAgent):
    """
    Agent responsible for building the attack plan based on target profile.
    Refactored from original attack_strategy.py.
    """
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build an attack plan.
        Expects 'profile' and 'rules' in input_data.
        """
        profile = input_data.get("profile")
        rules = input_data.get("rules", [])
        
        if not profile:
            raise ValueError("Target profile is required for strategy generation")

        logger.info(f"Generating strategy for target type: {profile.get('type')}")
        
        target_type = profile.get("type", "WEB_APP")
        risk_level = profile.get("risk_level", "MEDIUM")
        
        # Filter rules based on target type
        relevant_rules = self._filter_rules(rules, target_type)
        
        # Prioritize rules
        sorted_rules = self._prioritize_rules(relevant_rules, risk_level)
        
        logger.info(f"Strategy generated: {len(sorted_rules)} rules selected")
        
        return {
            "plan": sorted_rules,
            "rule_count": len(sorted_rules),
            "estimated_duration": len(sorted_rules) * 5 # Rough estimate
        }

    def _filter_rules(self, rules: List[Dict], target_type: str) -> List[Dict]:
        """Filter rules based on target compatibility."""
        filtered = []
        for rule in rules:
            rule_tags = rule.get("tags", [])
            owasp_code = rule.get("owasp", "")
            
            if target_type == "LLM_API":
                # Match rules with LLM in owasp code or tags
                if "LLM" in owasp_code or "LLM" in rule_tags:
                    filtered.append(rule)
            elif target_type == "REST_API":
                if "API" in owasp_code or "API" in rule_tags:
                    filtered.append(rule)
            elif target_type == "AGENT":
                if "AGENT" in owasp_code or "AGENT" in rule_tags:
                    filtered.append(rule)
            else:
                # Web App - include generic, non-LLM, non-AGENT rules
                if "LLM" not in owasp_code and "AGENT" not in owasp_code:
                    filtered.append(rule)
                
        return filtered

    def _prioritize_rules(self, rules: List[Dict], risk_level: str) -> List[Dict]:
        """Sort rules by severity, RL priority, and risk context."""
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        
        # Sort key: 
        # 1. Severity (Ascending index)
        # 2. RL Priority Score (Descending)
        sorted_rules = sorted(
            rules,
            key=lambda r: (
                severity_order.get(r.get("severity", "LOW").upper(), 3),
                -float(r.get("priority_score", 0)) # RL weight
            )
        )
        
        # Risk-based pruning
        if risk_level == "LOW":
            # Only run critical/high/medium for low risk targets to save resources
            return [r for r in sorted_rules if r.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]]
            
        return sorted_rules
