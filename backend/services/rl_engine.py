from datetime import datetime

# In-memory storage for rule weights (would be persisted in production)
RULE_WEIGHTS = {
    "Prompt Injection": 0.92,
    "Data Leakage": 0.78,
    "Insecure Output Handling": 0.65,
    "Model Stealing": 0.41,
    "Jailbreak Attack": 0.88,
    "Hallucination": 0.55,
    "Denial of Service": 0.32
}


def get_rule_weights():
    """
    Get the current rule priority weights for the heatmap.
    
    Returns:
        List of dictionaries with rule names and priority weights.
    """
    return [
        {"rule": rule, "weight": weight} 
        for rule, weight in RULE_WEIGHTS.items()
    ]


def update_rl(rule, status):
    """
    Update RL score for a rule based on scan result.
    
    Args:
        rule: The rule dictionary to update
        status: The observed status from the scan ("FAILED", "PASSED", etc.)
    
    Returns:
        Updated rule dictionary
    """
    # Reward: positive for finding vulnerabilities (rule FAILED means attack worked)
    reward = 2 if status == "FAILED" else -1
    
    # Update RL score
    rule["rl_score"] = rule.get("rl_score", 0) + reward
    
    # Add to history
    rule.setdefault("history", []).append({
        "timestamp": datetime.utcnow().isoformat(),
        "status": status,
        "reward": reward
    })
    
    # Priority update (clipped between 1-10)
    # Base priority of 5, adjusted by RL score
    rule["priority"] = max(1, min(10, int(rule["rl_score"] / 2 + 5)))
    
    return rule


def reset_rl(rule):
    """
    Reset RL score and history for a rule.
    
    Args:
        rule: The rule dictionary to reset
    
    Returns:
        Reset rule dictionary
    """
    rule["rl_score"] = 0
    rule["history"] = []
    rule["priority"] = 5  # Default priority
    return rule

