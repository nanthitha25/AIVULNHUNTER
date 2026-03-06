"""
Attack Strategy Agent

Selects relevant security rules based on target profile and scan type.
"""


def build_attack_plan(profile: dict, rules: list, scan_type: str = "FULL") -> list:
    """
    Build an attack plan by selecting relevant rules.
    
    Args:
        profile: Target profile from profiling agent
        rules: List of available security rules
        scan_type: Type of scan (FULL, LLM, API)
        
    Returns:
        List of rules to execute in the scan
    """
    if not rules:
        return []
    
    target_type = profile.get("type", "WEB_APP")
    risk_level = profile.get("risk_level", "MEDIUM")
    
    # Filter rules based on scan type
    if scan_type == "LLM":
        # Focus on LLM-specific vulnerabilities (OWASP LLM01-LLM06)
        relevant_rules = [
            r for r in rules 
            if r.get("owasp", "").startswith("LLM")
        ]
    elif scan_type == "API":
        # Focus on API security (OWASP API1-API10)
        relevant_rules = [
            r for r in rules 
            if r.get("owasp", "").startswith("API")
        ]
    else:
        # FULL scan - use all relevant rules
        relevant_rules = rules.copy()
    
    # Prioritize rules by severity and priority
    # Higher severity and priority first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    
    sorted_rules = sorted(
        relevant_rules,
        key=lambda r: (
            severity_order.get(r.get("severity", "LOW"), 3),
            -r.get("priority", 0)
        )
    )
    
    # For HIGH risk targets, include more rules
    # For LOW risk targets, focus on critical/high severity
    if risk_level == "HIGH":
        return sorted_rules  # All prioritized rules
    elif risk_level == "MEDIUM":
        # Skip low priority, low severity rules
        return [
            r for r in sorted_rules
            if r.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]
            or r.get("priority", 0) >= 3
        ]
    else:
        # Low risk - only critical and high
        return [
            r for r in sorted_rules
            if r.get("severity") in ["CRITICAL", "HIGH"]
        ]
