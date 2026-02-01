"""
LLM Analysis API Routes

Provides endpoints for AI-powered vulnerability analysis using Ollama (Llama 2).
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any

from .auth import get_current_admin
from .rules import rules_db

router = APIRouter(prefix="/llm", tags=["LLM Analysis"])


class AnalysisRequest(BaseModel):
    target: str
    attack_type: str
    findings: Dict[str, Any]


class ExplanationRequest(BaseModel):
    attack_name: str
    owasp_ref: str
    target: str


@router.post("/analyze")
async def analyze_vulnerability(
    request: AnalysisRequest,
    admin=Depends(get_current_admin)
):
    """
    Analyze a vulnerability finding using LLM (Ollama).
    
    Requires Ollama to be running with Llama 2 or similar model.
    
    Request body:
    - target: Target URL or identifier
    - attack_type: Type of attack (e.g., "Prompt Injection")
    - findings: Dictionary with status, confidence, evidence
    """
    try:
        from ..llm.ollama_client import analyze_with_llm
        
        result = analyze_with_llm(
            target=request.target,
            attack_type=request.attack_type,
            findings=request.findings
        )
        
        if result:
            return {
                "success": True,
                "analysis": {
                    "explanation": result.explanation,
                    "severity": result.severity,
                    "confidence": result.confidence,
                    "mitigation": result.mitigation,
                    "attack_vector": result.attack_vector
                }
            }
        else:
            return {
                "success": False,
                "error": "LLM not available",
                "message": "Start Ollama with: ollama run llama2",
                "fallback": "Using static analysis rules"
            }
            
    except ImportError:
        return {
            "success": False,
            "error": "Ollama client not installed",
            "message": "Create backend/llm/ollama_client.py"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/explain")
async def explain_attack(request: ExplanationRequest, admin=Depends(get_current_admin)):
    """
    Get detailed explanation of an attack type from LLM.
    
    Request body:
    - attack_name: Name of the attack
    - owasp_ref: OWASP reference
    - target: Target system for context
    """
    try:
        from ..llm.ollama_client import OllamaClient
        
        client = OllamaClient()
        
        if not client.is_available():
            return {
                "success": False,
                "error": "Ollama not running",
                "message": "Start Ollama and run: ollama run llama2"
            }
        
        explanation = client.explain_attack(request.attack_name, request.owasp_ref)
        mitigation = client.generate_mitigation(
            request.attack_name, 
            "MEDIUM", 
            request.target
        )
        
        return {
            "success": True,
            "explanation": explanation,
            "mitigation": mitigation
        }
        
    except ImportError:
        return {
            "success": False,
            "error": "Ollama client not found"
        }


@router.get("/status")
async def llm_status(admin=Depends(get_current_admin)):
    """Check if Ollama LLM is available."""
    try:
        from ..llm.ollama_client import OllamaClient
        
        client = OllamaClient()
        available = client.is_available()
        
        return {
            "llm_available": available,
            "model": "llama2",
            "api_url": "http://localhost:11434",
            "instructions": "Run: brew install ollama && ollama run llama2" if not available else None
        }
    except ImportError:
        return {
            "llm_available": False,
            "error": "Ollama client not configured",
            "instructions": "Create backend/llm/ollama_client.py"
        }


@router.post("/risk-assessment")
async def risk_assessment(
    target_type: str,
    vulnerabilities: list,
    admin=Depends(get_current_admin)
):
    """
    Perform overall risk assessment using LLM.
    
    Args:
        target_type: Type of target (LLM, API, WEB_APP)
        vulnerabilities: List of vulnerability findings
    """
    try:
        from ..llm.ollama_client import OllamaClient
        
        client = OllamaClient()
        
        if not client.is_available():
            return {
                "success": False,
                "error": "Ollama not available"
            }
        
        assessment = client.assess_risk(target_type, vulnerabilities)
        
        return {
            "success": True,
            "assessment": assessment
        }
        
    except ImportError:
        return {
            "success": False,
            "error": "LLM client not available"
        }
