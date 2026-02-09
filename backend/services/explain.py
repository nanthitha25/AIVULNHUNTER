"""
Explanation Generator for Vulnerability Detections

This module provides explainable AI (XAI) functionality for explaining
why certain vulnerabilities were detected during security scans.
"""

from typing import Dict, List, Optional


# Explanation templates for different vulnerability types
EXPLANATIONS = {
    "Prompt Injection": {
        "why": "The model responded to a crafted adversarial prompt revealing unsafe behavior. The injection attempted to override system instructions through role-playing, ignore commands, or leak sensitive information.",
        "mitigation": "Apply input sanitization, system prompt hardening, and instruction-layer defenses. Use prompt filtering and output validation."
    },
    "Data Leakage": {
        "why": "The model exposed sensitive information in its response that should have been filtered or redacted. This could include PII, credentials, or internal system details.",
        "mitigation": "Implement content filtering, PII detection and redaction, and output sanitization pipelines."
    },
    "Insecure Output Handling": {
        "why": "The model generated output that could be exploited for secondary attacks or contains potentially dangerous content without proper safeguards.",
        "mitigation": "Apply output validation, content filtering, and response length limits. Use safe decoding and sanitization."
    },
    "Model Stealing": {
        "why": "The model may have provided information that could be used to reverse-engineer or replicate the AI system's architecture or capabilities.",
        "mitigation": "Limit detailed model information exposure, use rate limiting, and implement query anomaly detection."
    },
    "Jailbreak Attack": {
        "why": "The model bypassed safety constraints through complex multi-turn reasoning or persona manipulation techniques.",
        "mitigation": "Implement conversation-level context monitoring, safety layer enforcement, and behavioral analysis."
    },
    "Hallucination": {
        "why": "The model generated factually incorrect or fabricated information that could mislead users or downstream systems.",
        "mitigation": "Implement fact-checking, confidence scoring, and source verification for generated content."
    },
    "Denial of Service": {
        "why": "The input triggered excessive resource consumption or processing time that could degrade service availability.",
        "mitigation": "Apply input complexity limits, timeout enforcement, and resource quota management."
    }
}


def explain_detection(rule: str, evidence: str = "", context: Dict = None) -> Dict:
    """
    Generate an explanation for why a vulnerability was detected.
    
    Args:
        rule: The vulnerability rule name (e.g., "Prompt Injection")
        evidence: The specific evidence found during the scan
        context: Additional context about the detection
        
    Returns:
        Dictionary containing explanation details
    """
    # Get base explanation for the rule type
    base = EXPLANATIONS.get(rule, {
        "why": "An anomalous pattern was detected in the model's behavior that indicates potential security risk.",
        "mitigation": "Review the input and apply standard security hardening measures."
    })
    
    explanation = {
        "rule": rule,
        "why": base["why"],
        "evidence": evidence or "Automated detection during security scan",
        "mitigation": base["mitigation"]
    }
    
    # Add context if provided
    if context:
        explanation["context"] = context
    
    return explanation


def explain_results(scan_results: List[Dict]) -> List[Dict]:
    """
    Generate explanations for all scan results.
    
    Args:
        scan_results: List of scan result dictionaries
        
    Returns:
        List of results with explanation fields added
    """
    explained = []
    
    for result in scan_results:
        rule = result.get("name") or result.get("rule") or result.get("attack", "Unknown")
        evidence = result.get("evidence", "")
        
        # Get explanation
        explanation = explain_detection(rule, evidence)
        
        # Merge with original result
        explained_result = {
            **result,
            "explanation": {
                "why": explanation["why"],
                "evidence": explanation["evidence"],
                "mitigation": explanation["mitigation"]
            }
        }
        
        explained.append(explained_result)
    
    return explained


def get_supported_rules() -> List[str]:
    """Return list of supported rules with explanations."""
    return list(EXPLANATIONS.keys())

