"""
Ollama LLM Integration for AI-Powered Vulnerability Analysis

This module provides integration with Ollama (Llama 2, Mistral, etc.)
for advanced AI-driven security analysis and explanation generation.

Requirements:
- Ollama installed: brew install ollama
- Model pulled: ollama run llama2
- API running on: http://localhost:11434
"""

import requests
import json
from typing import Dict, List, Optional
from dataclasses import dataclass


# Ollama Configuration
OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama2"


@dataclass
class LLMAnalysis:
    """Result from LLM analysis"""
    explanation: str
    severity: str
    confidence: float
    mitigation: str
    attack_vector: str


class OllamaClient:
    """
    Client for interacting with Ollama LLM API.
    
    Used for:
    - Explaining vulnerability findings
    - Generating mitigation recommendations
    - Analyzing attack patterns
    - Risk assessment
    """
    
    def __init__(self, base_url: str = OLLAMA_BASE_URL, model: str = DEFAULT_MODEL):
        self.base_url = base_url
        self.model = model
        self.api_url = f"{base_url}/api/generate"
    
    def is_available(self) -> bool:
        """Check if Ollama is running and model is available"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                return any(m["name"].startswith(self.model) for m in models)
            return False
        except Exception:
            return False
    
    def analyze_vulnerability(
        self,
        target: str,
        attack_type: str,
        findings: Dict
    ) -> LLMAnalysis:
        """
        Use LLM to analyze a vulnerability finding.
        
        Args:
            target: Target system URL or identifier
            attack_type: Type of attack (e.g., "Prompt Injection")
            findings: Dictionary containing test results
            
        Returns:
            LLMAnalysis with explanation, severity, confidence, and mitigation
        """
        prompt = self._build_analysis_prompt(target, attack_type, findings)
        
        response = self._generate(prompt)
        
        return self._parse_response(response, attack_type)
    
    def explain_attack(self, attack_name: str, owasp_ref: str) -> str:
        """
        Get detailed explanation of an attack type from LLM.
        
        Args:
            attack_name: Name of the attack
            owasp_ref: OWASP reference (e.g., "LLM01")
            
        Returns:
            Detailed explanation string
        """
        prompt = f"""
Explain the following AI/LLM security vulnerability:

Attack: {attack_name}
OWASP Reference: {owasp_ref}

Provide:
1. What the vulnerability is
2. How attackers exploit it
3. Real-world impact
4. Why it's critical for AI systems

Keep the explanation technical but accessible.
"""
        
        return self._generate(prompt)
    
    def generate_mitigation(
        self,
        attack_name: str,
        severity: str,
        context: str = ""
    ) -> str:
        """
        Generate specific mitigation recommendations.
        
        Args:
            attack_name: Name of the attack
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            context: Additional context about the target
            
        Returns:
            Mitigation recommendations
        """
        prompt = f"""
Generate specific mitigation steps for:

Vulnerability: {attack_name}
Severity: {severity}
Context: {context}

Provide actionable mitigation recommendations in this format:
1. [Immediate Action]
2. [Short-term Fix]
3. [Long-term Strategy]
4. [Testing Verification]

Be specific and technical.
"""
        
        return self._generate(prompt)
    
    def assess_risk(
        self,
        target_type: str,
        vulnerabilities: List[Dict]
    ) -> Dict:
        """
        Use LLM to perform overall risk assessment.
        
        Args:
            target_type: Type of target (LLM, API, WEB_APP)
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Risk assessment dictionary
        """
        vuln_summary = "\n".join([
            f"- {v.get('attack', 'Unknown')}: {v.get('status', 'Unknown')}"
            for v in vulnerabilities
        ])
        
        prompt = f"""
Perform a risk assessment for this AI system:

Target Type: {target_type}
Vulnerabilities Found:
{vuln_summary}

Provide:
1. Overall Risk Score (1-10)
2. Critical Findings Summary
3. Recommended Priority Actions
4. Compliance Impact (OWASP, NIST, etc.)

Return as JSON with keys: risk_score, critical_findings, priority_actions, compliance_impact
"""
        
        response = self._generate(prompt)
        
        try:
            # Try to parse as JSON
            return json.loads(response)
        except json.JSONDecodeError:
            # Return structured fallback
            return {
                "risk_score": 5,
                "critical_findings": response[:500],
                "priority_actions": "Review findings manually",
                "compliance_impact": "Assessment incomplete"
            }
    
    def _build_analysis_prompt(
        self,
        target: str,
        attack_type: str,
        findings: Dict
    ) -> str:
        """Build analysis prompt for LLM"""
        status = findings.get("status", "UNKNOWN")
        evidence = findings.get("evidence", "N/A")
        confidence = findings.get("confidence", 0.5)
        
        return f"""
Analyze this security finding for an AI/LLM system:

Target: {target}
Attack Type: {attack_type}
Status: {status}
Confidence: {confidence:.0%}
Evidence: {evidence}

Provide analysis in this format:
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
EXPLANATION: [2-3 sentence explanation of the finding]
MITIGATION: [Specific steps to fix this issue]
ATTACK_VECTOR: [How this attack would work]
"""
    
    def _generate(self, prompt: str) -> str:
        """Generate response from Ollama"""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,  # Lower for more consistent results
                "top_p": 0.9,
                "max_tokens": 1024
            }
        }
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=60)
            response.raise_for_status()
            return response.json().get("response", "").strip()
        except requests.exceptions.RequestException as e:
            return f"Error communicating with Ollama: {str(e)}"
        except json.JSONDecodeError:
            return "Error parsing Ollama response"
    
    def _parse_response(self, response: str, attack_type: str) -> LLMAnalysis:
        """Parse LLM response into structured analysis"""
        # Default values
        severity = "MEDIUM"
        explanation = "Analysis unavailable"
        mitigation = "Review findings manually"
        attack_vector = attack_type
        
        lines = response.split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("SEVERITY:"):
                severity = line.replace("SEVERITY:", "").strip().upper()
            elif line.startswith("EXPLANATION:"):
                explanation = line.replace("EXPLANATION:", "").strip()
            elif line.startswith("MITIGATION:"):
                mitigation = line.replace("MITIGATION:", "").strip()
            elif line.startswith("ATTACK_VECTOR:"):
                attack_vector = line.replace("ATTACK_VECTOR:", "").strip()
        
        # Determine confidence from response
        confidence = 0.7 if "HIGH" in severity else (0.5 if "MEDIUM" in severity else 0.3)
        
        return LLMAnalysis(
            explanation=explanation,
            severity=severity,
            confidence=confidence,
            mitigation=mitigation,
            attack_vector=attack_vector
        )


# Global client instance
ollama_client = OllamaClient()


def analyze_with_llm(target: str, attack_type: str, findings: Dict) -> Optional[LLMAnalysis]:
    """
    Convenience function to analyze vulnerability with LLM.
    
    Returns None if Ollama is not available.
    """
    if ollama_client.is_available():
        return ollama_client.analyze_vulnerability(target, attack_type, findings)
    return None


# Example usage and testing
if __name__ == "__main__":
    client = OllamaClient()
    
    print("Checking Ollama availability...")
    if client.is_available():
        print("✅ Ollama is available!")
        
        # Test analysis
        test_findings = {
            "status": "VULNERABLE",
            "confidence": 0.8,
            "evidence": "Model accepted prompt injection"
        }
        
        result = client.analyze_vulnerability(
            target="http://localhost:9000/chat",
            attack_type="Prompt Injection",
            findings=test_findings
        )
        
        print(f"\n📊 Analysis Result:")
        print(f"  Severity: {result.severity}")
        print(f"  Explanation: {result.explanation}")
        print(f"  Mitigation: {result.mitigation}")
    else:
        print("❌ Ollama not available. Start with:")
        print("  brew install ollama")
        print("  ollama run llama2")
