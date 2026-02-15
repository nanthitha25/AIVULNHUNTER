"""
Observer Agent with LLM Integration

This agent uses Ollama (Llama 2) for advanced AI-powered analysis
of vulnerability findings. It provides explainable AI (XAI) outputs
with detailed explanations and mitigation recommendations.

Requires:
- Ollama installed: brew install ollama
- Model pulled: ollama run llama2
"""

from typing import List, Dict
from backend.rl.learner import update_rule_priority

# Import LLM client if available
try:
    from ..llm.ollama_client import OllamaClient, analyze_with_llm
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    # Fallback when Ollama is not installed
    def analyze_with_llm(target, attack_type, findings):
        return None


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
    "Model Denial of Service Test": {
        "why": "Attacker overwhelms the model with resource-intensive requests, causing degradation or denial of service",
        "mitigation": "Implement rate limiting, resource quotas, and input validation to prevent resource exhaustion",
        "owasp": "LLM04: Model Denial of Service"
    },
    "Supply Chain Vulnerabilities Test": {
        "why": "Dependency on compromised third-party models, data, or plugins allows attackers to compromise the system",
        "mitigation": "Maintain SBOM, scan dependencies, and verify integrity of third-party components",
        "owasp": "LLM05: Supply Chain Vulnerabilities"
    },
    "Insecure Plugin Design Test": {
        "why": "Plugins accept insecure inputs or perform unsafe actions without proper validation or authorization",
        "mitigation": "Enforce strict input validation, least privilege, and user confirmation for plugin actions",
        "owasp": "LLM07: Insecure Plugin Design"
    },
    "Excessive Agency Test": {
        "why": "Model is granted excessive permissions or autonomy to perform sensitive actions without human oversight",
        "mitigation": "Implement human-in-the-loop, granular permissions, and limit autonomous capabilities",
        "owasp": "LLM08: Excessive Agency"
    },
    "Overreliance Test": {
        "why": "Users or systems blindly trust model outputs, leading to errors or security issues from hallucinations",
        "mitigation": "Implement uncertainty markers, verifying outputs, and user education on AI limitations",
        "owasp": "LLM09: Overreliance"
    },
    "Model Theft Test": {
        "why": "Adversaries can extract model information, weights, or capabilities through carefully crafted queries",
        "mitigation": "Rate limiting, query filtering, and monitoring for extraction patterns",
        "owasp": "LLM10: Model Theft"
    },
    "Default / Weak Credentials Test": {
        "why": "System uses easily guessable or hardcoded credentials that can be exploited through brute force or credential stuffing",
        "mitigation": "Enforce strong password policies, implement account lockout, use multi-factor authentication, and eliminate hardcoded credentials",
        "owasp": "API02: Broken Authentication"
    },
    "Goal Hijacking Test": {
        "why": "Agent's goals or objectives can be redirected by adversarial inputs, causing it to pursue unintended objectives",
        "mitigation": "Goal validation, context isolation, output monitoring, and explicit objective boundaries",
        "owasp": "LLM01: Prompt Injection"
    }
}

# Fallback explanation for unknown attacks
DEFAULT_EXPLANATION = {
    "why": "Insufficient security controls allow exploitation of system vulnerabilities through untrusted inputs or improper access controls",
    "mitigation": "Implement defense in depth: input validation, output encoding, access controls, monitoring, and regular security assessments",
    "owasp": "N/A"
}


def _get_severity(confidence: float, status: str) -> str:
    """Determine severity level based on confidence score and status."""
    if status.upper() == "SECURE" or status.upper() == "PASSED":
        return "INFO"
    
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


def analyze_results(results: List[Dict], target_url: str = None) -> List[Dict]:
    """
    Generate context-specific explanations for attack results.
    
    This is the main observer function that processes scan results
    and produces explainable AI outputs.
    
    Args:
        results: List of attack execution results with 'attack', 'status', 'confidence'
        target_url: Optional target URL for LLM analysis
        
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
        is_vulnerable = r.get("status", "").upper() in ["VULNERABLE", "FAILED"]
        confidence = r.get("confidence", 0.0)
        
        # Determine severity
        severity = _get_severity(confidence, r.get("status", ""))
        
        # Try LLM analysis if available and target is provided
        llm_analysis = None
        if LLM_AVAILABLE and target_url and is_vulnerable:
            llm_analysis = analyze_with_llm(target_url, attack_name, r)
        
        # Use LLM analysis if available, otherwise use static mapping
        if llm_analysis:
            final_explanation = llm_analysis.explanation
            final_mitigation = llm_analysis.mitigation
            final_severity = llm_analysis.severity
            confidence = llm_analysis.confidence
        else:
            final_explanation = explanation["why"]
            final_mitigation = explanation["mitigation"]
            final_severity = severity
        
        explanations.append({
            "attack": attack_name,
            "why": final_explanation,
            "mitigation": final_mitigation,
            "severity": final_severity,
            "confidence": confidence,
            "owasp_reference": explanation["owasp"],
            "status": r.get("status", "UNKNOWN"),
            "evidence": r.get("evidence", "")
        })
        
        # RL: Update rule priority based on vulnerability findings
        rule_id = explanation["owasp"]
        reward = 2 if final_severity in ["CRITICAL", "HIGH"] else 1
        try:
            new_priority = update_rule_priority(rule_id, reward)
            print(f"[RL] Updated priority for {rule_id}: {new_priority:.3f}")
        except Exception:
            pass  # RL learner may not be initialized
    
    return explanations


def explain_with_llm(attack_name: str, owasp_ref: str, target: str) -> Dict:
    """
    Get detailed LLM-powered explanation for an attack.
    
    Args:
        attack_name: Name of the attack
        owasp_ref: OWASP reference
        target: Target system URL
        
    Returns:
        Dictionary with explanation, mitigation, and risk details
    """
    if not LLM_AVAILABLE:
        return {
            "explanation": "LLM not available. Install Ollama for advanced analysis.",
            "mitigation": "Review static mitigation guidelines.",
            "attack_vector": "Analysis unavailable"
        }
    
    client = OllamaClient()
    if not client.is_available():
        return {
            "explanation": "Ollama not running. Start with: ollama run llama2",
            "mitigation": "Configure Ollama for advanced analysis.",
            "attack_vector": "LLM unavailable"
        }
    
    explanation = client.explain_attack(attack_name, owasp_ref)
    mitigation = client.generate_mitigation(attack_name, "MEDIUM", target)
    
    return {
        "explanation": explanation,
        "mitigation": mitigation,
        "attack_vector": attack_name
    }


# Import OllamaClient at module level for LLM analysis
try:
    from ..llm.ollama_client import OllamaClient
except ImportError:
    OllamaClient = None


def get_llm_analysis(target: str, attack_type: str, findings: Dict) -> Dict:
    """
    Get advanced LLM analysis for a vulnerability finding.
    
    Args:
        target: Target URL
        attack_type: Type of attack
        findings: Test results
        
    Returns:
        Dictionary with LLM-generated analysis
    """
    if not OllamaClient:
        return {
            "error": "Ollama client not available",
            "message": "Install Ollama and run: ollama run llama2"
        }
    
    client = OllamaClient()
    if not client.is_available():
        return {
            "error": "Ollama not running",
            "message": "Start Ollama and pull a model: ollama run llama2"
        }
    
    analysis = client.analyze_vulnerability(target, attack_type, findings)
    
    return {
        "explanation": analysis.explanation,
        "severity": analysis.severity,
        "confidence": analysis.confidence,
        "mitigation": analysis.mitigation,
        "attack_vector": analysis.attack_vector
    }


# ========== SIMPLE OBSERVE FUNCTION (for pipeline) ==========
def observe(result: dict):
    """
    Simple observer function for the scan pipeline.
    Analyzes execution result and adds explanation + mitigation.
    
    Args:
        result: Execution result from execute_rule
        
    Returns:
        Result with explanation and mitigation added
    """
    if result["status"] == "FAILED":
        result["explanation"] = "System responded unexpectedly to adversarial input"
        result["mitigation"] = "Apply strict input validation and output filtering"
    else:
        result["explanation"] = "System handled the input safely"
        result["mitigation"] = "No action required"
    
    return result
