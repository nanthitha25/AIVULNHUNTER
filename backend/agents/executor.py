"""
Exploitation Agent (SAFE, SIMULATED)

IMPORTANT: This is security testing, NOT hacking.
All checks are simulated and safe - no actual exploitation occurs.

This agent performs simulated vulnerability checks based on rule definitions.
"""


def execute_rule(rule: dict, target: str) -> dict:
    """
    Execute a simulated vulnerability check for the given rule.
    
    Args:
        rule: Security rule to check
        target: Target URL/system
        
    Returns:
        dict with status, explanation, and mitigation
    """
    owasp_id = rule.get("owasp", "").upper()
    severity = rule.get("severity", "MEDIUM").upper()
    rule_name = rule.get("name", "Unknown Rule")
    
    # Simulated vulnerability detection logic
    # In production, this would be replaced with actual security tests
    
    # LLM01: Prompt Injection - Check for LLM-related targets
    if owasp_id == "LLM01":
        # Simulate that LLM targets are vulnerable to prompt injection
        vulnerable = "llm" in target.lower() or "chat" in target.lower()
        
        return {
            "status": "FAILED" if vulnerable else "PASSED",
            "explanation": (
                "Target appears to be an LLM system that may accept untrusted instructions. "
                "Prompt injection attacks could manipulate model behavior."
                if vulnerable else
                "No evidence of prompt injection vulnerability detected."
            ),
            "mitigation": (
                "Implement prompt sanitization, input validation, and output filtering. "
                "Use separate model instances for untrusted input."
                if vulnerable else
                "Continue monitoring for new prompt injection techniques."
            )
        }
    
    # LLM02: Insecure Output Handling
    elif owasp_id == "LLM02":
        vulnerable = severity in ["HIGH", "CRITICAL"]
        
        return {
            "status": "FAILED" if vulnerable else "PASSED",
            "explanation": (
                "Model outputs may contain sensitive information or be vulnerable to manipulation."
                if vulnerable else
                "Output handling appears to have proper safeguards."
            ),
            "mitigation": (
                "Implement output validation, content filtering, and rate limiting on responses."
                if vulnerable else
                "Maintain current output handling security measures."
            )
        }
    
    # LLM03: Training Data Poisoning
    elif owasp_id == "LLM03":
        return {
            "status": "PASSED",
            "explanation": "Training data integrity cannot be assessed through external testing.",
            "mitigation": "Ensure training data comes from trusted sources and implement data validation pipelines."
        }
    
    # LLM04: Model Denial of Service
    elif owasp_id == "LLM04":
        vulnerable = severity in ["HIGH", "CRITICAL"]
        
        return {
            "status": "FAILED" if vulnerable else "PASSED",
            "explanation": (
                "Target may be vulnerable to resource exhaustion attacks."
                if vulnerable else
                "Rate limiting and resource protections appear to be in place."
            ),
            "mitigation": (
                "Implement request throttling, timeouts, and resource quotas."
                if vulnerable else
                "Continue monitoring for DoS attempts."
            )
        }
    
    # LLM05: Supply Chain Vulnerabilities
    elif owasp_id == "LLM05":
        return {
            "status": "PASSED",
            "explanation": "Supply chain security requires internal audit of dependencies.",
            "mitigation": "Regularly audit third-party libraries and model sources."
        }
    
    # LLM06: Sensitive Information Disclosure
    elif owasp_id == "LLM06":
        vulnerable = severity in ["HIGH", "CRITICAL"]
        
        return {
            "status": "FAILED" if vulnerable else "PASSED",
            "explanation": (
                "Model may reveal sensitive information in responses."
                if vulnerable else
                "No sensitive information disclosure patterns detected."
            ),
            "mitigation": (
                "Implement PII detection and redaction in outputs."
                if vulnerable else
                "Continue monitoring for information leakage."
            )
        }
    
    # Generic API security checks
    elif owasp_id.startswith("API"):
        vulnerable = severity in ["HIGH", "CRITICAL"]
        
        return {
            "status": "FAILED" if vulnerable else "PASSED",
            "explanation": f"API security check for {rule_name}.",
            "mitigation": f"Review and implement security controls for {rule_name}."
        }
    
    # Default behavior for unknown rules
    else:
        # Simulate a 50/50 chance of finding issues for demo purposes
        # In production, this would be replaced with actual security tests
        import random
        is_vulnerable = random.random() < 0.3  # 30% chance for demo
        
        return {
            "status": "FAILED" if is_vulnerable else "PASSED",
            "explanation": f"Security check for {rule_name} completed.",
            "mitigation": (
                f"Review and address {rule_name} security concerns."
                if is_vulnerable else
                f"No immediate concerns for {rule_name}."
            )
        }


def execute_attacks(attacks: list) -> list:
    """
    Execute multiple attack simulations.
    
    Args:
        attacks: List of attack dictionaries
        
    Returns:
        List of execution results
    """
    results = []
    for attack in attacks:
        # Convert rule format to expected format for execute_rule
        result = execute_rule(attack, attack.get("target", ""))
        results.append({
            "attack": attack.get("name", "Unknown Attack"),
            "status": result["status"],
            "confidence": 0.8 if result["status"] == "FAILED" else 0.2,
            "explanation": result.get("explanation", ""),
            "mitigation": result.get("mitigation", "")
        })
    return results
