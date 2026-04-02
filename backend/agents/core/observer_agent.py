from typing import Dict, Any
import logging
from backend.agents.base import BaseAgent
from backend.agents.core.mitigations import PROFESSIONAL_MITIGATIONS
from datetime import datetime

logger = logging.getLogger(__name__)

class ObserverAgent(BaseAgent):
    """
    Agent responsible for analyzing execution results, scoring (if needed),
    and formatting the output for the database/report.
    """
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a scan result.
        Expects 'result' and 'context' in input_data.
        """
        raw_result = input_data.get("result")
        
        if not raw_result:
            raise ValueError("No result to analyze")

        logger.info(f"Analyzing result for rule {raw_result.get('owasp', 'UNKNOWN')}")
        
        # In a more advanced version, this would check against baseline, 
        # use an LLM to interpret the evidence, etc.
        # For now, we normalize the statuses and calculate a final severity.
        
        # Support both new contract and old format for backward compatibility
        status = raw_result.get("status", "UNKNOWN")
        is_vulnerable = raw_result.get("is_vulnerable", status in ["VULNERABLE", "HIGH", "CRITICAL", "t", True])
        severity = self._normalize_severity(raw_result)
        
        # Resolve raw mitigation and explanation fields (handle multiple naming conventions)
        raw_mitigation = raw_result.get("mitigation_steps") or raw_result.get("mitigation", "No specific mitigation provided")
        raw_explanation = raw_result.get("findings") or raw_result.get("explanation", "No explanation provided")

        analysis = {
            "processed_at": datetime.utcnow().isoformat(),
            "is_vulnerable": is_vulnerable,
            "severity": severity,
            "confidence_score": raw_result.get("confidence_score", raw_result.get("confidence", 0.0)),
            # expose both naming conventions for compatibility
            "findings": raw_explanation,
            "explanation": raw_explanation,          # ← frontend reads this
            "mitigation_steps": raw_mitigation,
            "mitigation": raw_mitigation,            # ← frontend reads this
            "evidence_snippet": str(raw_result.get("evidence_snippet", raw_result.get("evidence", "")))[:500],
            "evidence": str(raw_result.get("evidence_snippet", raw_result.get("evidence", "")))[:500],  # ← PDF reads this
        }
        
        # Inject professional structured mitigation from OWASP code mapping
        owasp_code = raw_result.get("owasp", "").upper().strip()
        if owasp_code and owasp_code in PROFESSIONAL_MITIGATIONS:
            professional_data = PROFESSIONAL_MITIGATIONS[owasp_code]
            if professional_data:  # guard against None alias entries
                analysis["risk_overview"] = professional_data.get("risk_overview", raw_explanation)
                # Keep explanation for backward compatibility
                analysis["explanation"] = analysis["risk_overview"]
                analysis["technical_impact"] = professional_data.get("technical_impact", "")
                analysis["mitigation"] = professional_data.get("recommended_mitigation", raw_mitigation)
                analysis["secure_example"] = professional_data.get("secure_implementation_example", "")
                analysis["severity_justification"] = professional_data.get("severity_justification", "")
                # Keep report_template for PDF renderer (it has executive_summary, etc.)
                analysis["report_template"] = professional_data

        # Calculate RL Reward
        # +2 for finding High/Critical vuln
        # +1 for Medium/Low
        # -0.1 for False Positive/Nothing (small penalty to encourage efficiency)
        if analysis["is_vulnerable"]:
             if analysis["severity"] in ["CRITICAL", "HIGH"]:
                 analysis["rl_reward"] = 2.0
             else:
                 analysis["rl_reward"] = 1.0
        else:
             analysis["rl_reward"] = -0.1

        return analysis

    def _normalize_severity(self, result: Dict) -> str:
        # If the result already has a severity, trust it, otherwise infer from status or rule
        severity = result.get("severity")
        if severity:
            return str(severity).upper()
             
        status = result.get("status", "").upper()
        if status == "VULNERABLE":
             return "MEDIUM" # Default
        return "INFO"
