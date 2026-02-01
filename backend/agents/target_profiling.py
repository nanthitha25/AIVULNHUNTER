"""
Target Profiling Agent

Performs real-time probing to identify target type (LLM, API, Web App) 
and assess initial reachability and risk level.
"""

import requests
from typing import Optional


def target_profiling(target: str) -> dict:
    """
    Probe the target in real-time to determine its type, reachability, and risk.
    
    This function performs actual HTTP requests to the target URL to:
    1. Check if the target is reachable
    2. Identify the target type based on response headers and patterns
    3. Assess initial risk level
    
    Args:
        target: URL of the target system (e.g., http://localhost:9000/chat)
        
    Returns:
        dict with:
        - reachable: Boolean indicating if target responded
        - type: Target type (LLM, API, WEB_APP)
        - risk_level: Risk assessment (HIGH, MEDIUM, LOW)
        - target: Original target URL
        - profile_timestamp: ISO timestamp
        - headers: Relevant response headers (if reachable)
        - error: Error message (if not reachable)
    """
    profile = {
        "reachable": False,
        "type": "UNKNOWN",
        "risk_level": "MEDIUM",
        "target": target,
        "profile_timestamp": "auto",
        "headers": {},
        "error": None
    }
    
    try:
        # Perform real-time HTTP probe
        # Use GET with timeout to check reachability
        response = requests.get(target, timeout=5, allow_redirects=True)
        
        profile["reachable"] = True
        profile["status_code"] = response.status_code
        profile["headers"] = dict(response.headers)
        
        # Identify target type based on URL patterns and response
        target_lower = target.lower()
        
        # Check URL patterns for LLM indicators
        if any(indicator in target_lower for indicator in [
            "llm", "chat", "openai", "anthropic", "claude", 
            "gpt", "completion", "embeddings", "model"
        ]):
            profile["type"] = "LLM"
        # Check for API indicators
        elif any(indicator in target_lower for indicator in [
            "/api/", "/v1/", "/api/v", "/rest", "/endpoint"
        ]):
            profile["type"] = "API"
        # Check response content-type for API indicators
        elif "application/json" in response.headers.get("content-type", "").lower():
            profile["type"] = "API"
        else:
            profile["type"] = "WEB_APP"
        
        # Assess risk level based on target type and response
        # LLMs have higher risk due to prompt injection possibilities
        if profile["type"] == "LLM":
            profile["risk_level"] = "HIGH"
        elif response.status_code >= 400:
            profile["risk_level"] = "LOW"  # Target has errors, lower immediate risk
        else:
            profile["risk_level"] = "MEDIUM"
        
        # Additional checks for LLM-specific headers
        if profile["type"] == "LLM":
            # Check for OpenAI-style headers
            if "openai-model" in response.headers:
                profile["llm_model"] = response.headers["openai-model"]
            
            # Check for rate limit headers (indicates real LLM service)
            if "x-ratelimit-limit" in response.headers:
                profile["has_rate_limiting"] = True
        
    except requests.exceptions.Timeout:
        profile["error"] = "Connection timed out (5s)"
        profile["risk_level"] = "LOW"
    except requests.exceptions.ConnectionError:
        profile["error"] = "Connection failed - target not reachable"
        profile["risk_level"] = "LOW"
    except requests.exceptions.RequestException as e:
        profile["error"] = f"Request failed: {str(e)}"
        profile["risk_level"] = "LOW"
    except Exception as e:
        profile["error"] = f"Unexpected error: {str(e)}"
        profile["risk_level"] = "LOW"
    
    return profile


def quick_check(target: str) -> dict:
    """
    Lightweight reachability check for the target.
    
    Args:
        target: URL to check
        
    Returns:
        dict with reachable status and latency
    """
    result = {
        "target": target,
        "reachable": False,
        "latency_ms": None,
        "error": None
    }
    
    import time
    start = time.time()
    
    try:
        response = requests.head(target, timeout=3)
        result["reachable"] = response.status_code < 400
        result["latency_ms"] = int((time.time() - start) * 1000)
        result["status_code"] = response.status_code
    except Exception as e:
        result["error"] = str(e)
    
    return result

