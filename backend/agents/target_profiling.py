"""
Target Profiling Agent

Identifies the target type (LLM, API, Web App) and assesses initial risk level.
"""


def target_profiling(target: str) -> dict:
    """
    Profile the target to determine its type and risk level.
    
    Args:
        target: URL or identifier of the target system
        
    Returns:
        dict with target type and risk assessment
    """
    target_lower = target.lower()
    
    # Detect target type based on URL patterns
    if "llm" in target_lower or "openai" in target_lower or "anthropic" in target_lower:
        target_type = "LLM_API"
    elif "/api/" in target_lower or target_lower.endswith("/api") or "api" in target_lower:
        target_type = "REST_API"
    elif "/graphql" in target_lower or target_lower.endswith(".graphql"):
        target_type = "GRAPHQL"
    else:
        target_type = "WEB_APP"
    
    # Initial risk assessment based on target type
    # LLMs are generally higher risk due to prompt injection possibilities
    risk_level = "HIGH" if target_type in ["LLM_API", "GRAPHQL"] else "MEDIUM"
    
    return {
        "type": target_type,
        "risk_level": risk_level,
        "target": target,
        "profile_timestamp": "auto"
    }
