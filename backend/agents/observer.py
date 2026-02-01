from typing import List, Dict
from ..rl.rule_prioritizer import rl_engine

# Attack explanation mapping with context-specific details
ATTACK_EXPLANATIONS = {
    "SQL Injection Test": {
        "why": "User input is concatenated directly into database queries without proper sanitization or parameterized queries, allowing attackers to manipulate query logic",
        "mitigation": "Use parameterized queries (prepared statements), input validation, ORM libraries, and least privilege database accounts",
        "owasp": "A03:2021 - Injection"
    },
    "Prompt Override Test": {
        "why": "LLM accepts and executes instructions from untrusted user input without proper prompt isolation or context separation",
        "mitigation": "Implement prompt hardening, input filtering, context separation, instruction separation markers, and output validation",
        "owasp": "LLM01: Prompt Injection"
    },
    "Permission Escalation Test": {
        "why": "Agent or system has excessive privileges that can be exploited to perform actions beyond intended authorization boundaries",
        "mitigation": "Implement role-based access control (RBAC), least privilege principle, permission boundaries, and action validation",
        "owasp": "A01:2021 - Broken Access Control"
    },
    "Data Leakage Test": {
        "why": "System exposes sensitive information in responses due to improper output handling or over-inclusion in training/prompt context",
        "mitigation": "Implement output filtering, data classification, context sanitization, and response validation",
        "owasp": "LLM06: Sensitive Information Disclosure"
    },
    "Training Data Poisoning Test": {
        "why": "Malicious data introduced during model training compromises model behavior, integrity, or introduces backdoors",
        "mitigation": "Data provenance verification, data sanitization pipelines, adversarial robustness testing, and training process monitoring",
        "owasp": "LLM03: Training Data Poisoning"
    },
    "Goal Hijacking Test": {
        "why": "Agent's goals or objectives can be redirected by adversarial inputs, causing it to pursue unintended objectives",
        "mitigation": "Goal validation, context isolation, output monitoring, and explicit objective boundaries",
        "owasp": "LLM05: Model Denial of Service"
    },
    "Model Theft Test": {
        "why": "Adversaries can extract model information, weights, or capabilities through carefully crafted queries and responses",
        "mitigation": "Rate limiting, query filtering, output perturbation, and access logging",
        "owasp": "A06:2021 - Vulnerable and Outdated Components"
    },
    "Default / Weak Credentials Test": {
        "why": "System uses easily guessable or hardcoded credentials that can be exploited through brute force or credential stuffing",
        "mitigation": "Enforce strong password policies, implement account lockout, use multi-factor authentication, and eliminate hardcoded credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures"
    }
}

# Fallback explanation for unknown attacks
DEFAULT_EXPLANATION = {
    "why": "Insufficient security controls allow exploitation of system vulnerabilities through untrusted inputs or improper access controls",
    "mitigation": "Implement defense in depth: input validation, output encoding, access controls, monitoring, and regular security assessments",
    "owasp": "N/A"
}


def _get_severity(confidence: float) -> str:
    """Determine severity level based on confidence score."""
    if confidence >= 0.9:
        return "CRITICAL"
    elif confidence >= 0.7:
        return "HIGH"
    elif confidence >= 0.5:
        return "MEDIUM"
    else:
        return "LOW"


def _normalize_attack_name(attack: str) -> str:
    """Normalize attack name to match keys in ATTACK_EXPLANATIONS."""
    # Remove "Test" suffix if present for matching
    normalized = attack.replace(" Test", "")
    
    # Direct lookup
    for key in ATTACK_EXPLANATIONS:
        if normalized in key or key in attack:
            return key
    
    return attack


def analyze_results(results):
    """Generate context-specific explanations for attack results.
    
    Args:
        results: List of attack execution results with 'attack', 'status', 'confidence'
        
    Returns:
        List of explanation dictionaries with attack details, why, mitigation, severity, and OWASP reference
    """
    explanations = []
    for r in results:
        attack_name = r.get("attack", "Unknown Attack")
        normalized_attack = _normalize_attack_name(attack_name)
        
        # Get explanation from mapping or use default
        explanation = ATTACK_EXPLANATIONS.get(
            normalized_attack, 
            DEFAULT_EXPLANATION.copy()
        )
        
        # Calculate severity based on confidence and vulnerability status
        is_vulnerable = r.get("status", "").upper() == "VULNERABLE"
        confidence = r.get("confidence", 0.0)
        
        # Adjust severity calculation based on vulnerability status
        if is_vulnerable:
            severity = _get_severity(confidence)
        else:
            severity = "INFO"  # Not vulnerable, informational only
        
        # Build rule info for RL
        rule = {
            "id": explanation["owasp"],
            "name": normalized_attack,
            "severity": severity
        }
        
        # RL: Update rule priority based on vulnerability findings
        q_score = rl_engine.update(rule, r)
        priority = rl_engine.get_priority(q_score)
        
        print(f"[RL] Updated Q-score for {explanation['owasp']}: {q_score} (Priority: {priority})")
        
        explanations.append({
            "attack": attack_name,
            "why": explanation["why"],
            "mitigation": explanation["mitigation"],
            "severity": severity,
            "confidence": confidence,
            "owasp_reference": explanation["owasp"],
            "status": r.get("status", "UNKNOWN"),
            "q_score": q_score,
            "priority": priority
        })
    
    return explanations


def observe(rule, execution):
    """
    Generate explainable observation for a single rule execution.
    
    This function integrates with the RL engine to automatically update
    rule priorities based on scan results.
    
    Args:
        rule: The security rule that was tested
        execution: The execution result (status, explanation, mitigation)
        
    Returns:
        Dictionary with rule details, execution results, and RL-based priority
    """
    # Update RL with this rule's result
    q_score = rl_engine.update(rule, execution)
    priority = rl_engine.get_priority(q_score)
    
    return {
        "rule_id": rule.get("id", rule.get("rule_id", "unknown")),
        "name": rule.get("name", "Unknown"),
        "owasp": rule.get("owasp", "N/A"),
        "severity": rule.get("severity", "MEDIUM"),
        "status": execution.get("status", "UNKNOWN"),
        "explanation": execution.get("explanation", ""),
        "mitigation": execution.get("mitigation", ""),
        "q_score": q_score,
        "new_priority": priority
    }

