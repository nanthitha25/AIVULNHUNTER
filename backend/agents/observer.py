"""
Observer Agent - Vulnerability Explanation Module

Provides explanations for detected vulnerabilities including
reasons for detection and recommended mitigations.
"""

from typing import Dict, Any


def explain(results: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Generate explanations for vulnerability scan results.
    
    Args:
        results: Dictionary mapping vulnerability names to their status
        
    Returns:
        Dictionary with detailed explanations for each vulnerability
    """
    explanations = {}
    for vuln, status in results.items():
        explanations[vuln] = {
            "status": status,
            "why_detected": get_reason(vuln),
            "mitigation": get_fix(vuln)
        }
    return explanations


def get_reason(vuln: str) -> str:
    """Get the reason why a vulnerability was detected.
    
    Args:
        vuln: Name of the vulnerability
        
    Returns:
        Explanation of why the vulnerability was detected
    """
    reasons = {
        "Prompt Injection": "System and user prompts are not isolated",
        "Broken Authentication": "Missing or weak authentication controls",
        "Agent Escalation": "Agent has unrestricted tool access",
        "Insecure Output Handling": "Model outputs are not properly sanitized",
        "Training Data Poisoning": "Training data may contain malicious examples",
        "Denial of Service": "System lacks proper resource limits"
    }
    return reasons.get(vuln, "Best practice violation detected")


def get_fix(vuln: str) -> str:
    """Get the recommended fix for a vulnerability.
    
    Args:
        vuln: Name of the vulnerability
        
    Returns:
        Recommended mitigation steps
    """
    fixes = {
        "Prompt Injection": "Implement system prompt isolation",
        "Broken Authentication": "Use OAuth/JWT with expiry",
        "Agent Escalation": "Restrict agent permissions",
        "Insecure Output Handling": "Sanitize and validate all model outputs",
        "Training Data Poisoning": "Use data validation and provenance checking",
        "Denial of Service": "Implement rate limiting and resource quotas"
    }
    return fixes.get(vuln, "Apply OWASP recommended mitigation")


def explain_single(vuln: str, status: str) -> Dict[str, str]:
    """Explain a single vulnerability.
    
    Args:
        vuln: Name of the vulnerability
        status: Detection status
        
    Returns:
        Explanation dictionary
    """
    return {
        "status": status,
        "why_detected": get_reason(vuln),
        "mitigation": get_fix(vuln)
    }

