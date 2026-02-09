import json
import os
from datetime import datetime

# Q-Learning state storage
Q = {}
Q_FILE = "backend/rl/rule_scores.json"

# Severity weights for RL rule prioritization
SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.3,
    "INFO": 0.1
}

# Track failure rates
FAILURE_RATES = {}

def load_q_values():
    """Load Q-values from JSON file."""
    if os.path.exists(Q_FILE):
        with open(Q_FILE) as f:
            return json.load(f)
    return {}

def save_q_values(q_values):
    """Save Q-values to JSON file."""
    with open(Q_FILE, "w") as f:
        json.dump(q_values, f, indent=2)

def update_rule_priority(rule_id, reward, alpha=0.1):
    """Update rule priority using Q-learning algorithm.
    
    Q-learning update: Q(s,a) = Q(s,a) + α * (reward - Q(s,a))
    
    Args:
        rule_id: The rule identifier (e.g., OWASP reference or attack name)
        reward: Reward value for the state-action pair
        alpha: Learning rate (default 0.1)
        
    Returns:
        Updated Q-value for the rule
    """
    global Q
    Q = load_q_values()
    
    # Initialize Q-value if not present (default 0.5)
    if rule_id not in Q:
        Q[rule_id] = 0.5
    
    # Q-learning update
    Q[rule_id] = Q[rule_id] + alpha * (reward - Q[rule_id])
    
    # Clamp to valid range [0, 1]
    Q[rule_id] = min(1.0, max(0.0, Q[rule_id]))
    
    # Save updated Q-values
    save_q_values(Q)
    
    return Q[rule_id]

def update_rule_score(rule, success):
    """Update the score for a rule based on attack success/failure.
    
    Args:
        rule: Name of the attack rule
        success: Boolean indicating if attack was successful
    """
    with open(Q_FILE) as f:
        scores = json.load(f)

    reward = 0.05 if success else -0.02
    scores[rule] = min(1.0, max(0.0, scores.get(rule, 0.5) + reward))

    with open(Q_FILE, "w") as f:
        json.dump(scores, f, indent=2)


# === Phase 5: RL Rule Prioritization ===
# Formula: priority = severity_weight * failure_rate

def update_failure_rate(rule_id, failed: bool):
    """Track failure rate for a rule.
    
    Args:
        rule_id: The rule identifier
        failed: Boolean indicating if the attack failed (True = system is vulnerable)
    """
    global FAILURE_RATES
    
    if rule_id not in FAILURE_RATES:
        FAILURE_RATES[rule_id] = {"total": 0, "failures": 0}
    
    FAILURE_RATES[rule_id]["total"] += 1
    if failed:
        FAILURE_RATES[rule_id]["failures"] += 1
    
    return get_failure_rate(rule_id)

def get_failure_rate(rule_id):
    """Get the current failure rate for a rule.
    
    Args:
        rule_id: The rule identifier
        
    Returns:
        Failure rate as a float between 0 and 1
    """
    data = FAILURE_RATES.get(rule_id, {"total": 0, "failures": 0})
    if data["total"] == 0:
        return 0.5  # Default 50% failure rate if no data
    return data["failures"] / data["total"]

def calculate_rl_priority(severity: str, failure_rate: float = None) -> float:
    """Calculate rule priority using RL formula.
    
    Phase 5: priority = severity_weight * failure_rate
    
    Args:
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        failure_rate: Override failure rate (optional)
        
    Returns:
        Calculated priority between 0 and 1
    """
    severity_weight = SEVERITY_WEIGHTS.get(severity.upper(), 0.5)
    
    if failure_rate is None:
        failure_rate = 0.5  # Default if not provided
    
    priority = severity_weight * failure_rate
    
    # Clamp to valid range [0, 1]
    return min(1.0, max(0.0, priority))

def update_rule_priority_rl(rule_id: str, severity: str, attack_failed: bool):
    """Update rule priority using Phase 5 RL algorithm.
    
    Formula: priority = severity_weight * failure_rate
    
    Args:
        rule_id: The rule identifier (e.g., OWASP reference)
        severity: Severity level
        attack_failed: True if the target system was vulnerable (attack succeeded)
        
    Returns:
        Updated priority value
    """
    # Update failure rate tracking
    failure_rate = update_failure_rate(rule_id, attack_failed)
    
    # Calculate priority
    priority = calculate_rl_priority(severity, failure_rate)
    
    # Store the calculated priority
    Q = load_q_values()
    Q[rule_id] = priority
    save_q_values(Q)
    
    return priority

def get_rl_priority(rule_id: str, default_severity: str = "MEDIUM") -> dict:
    """Get current RL priority for a rule.
    
    Args:
        rule_id: The rule identifier
        default_severity: Default severity to use if not in tracking
        
    Returns:
        Dictionary with priority info
    """
    Q = load_q_values()
    failure_rate = get_failure_rate(rule_id)
    severity_weight = SEVERITY_WEIGHTS.get(default_severity.upper(), 0.5)
    
    return {
        "rule_id": rule_id,
        "priority": Q.get(rule_id, 0.5),
        "failure_rate": failure_rate,
        "severity_weight": severity_weight,
        "calculated": severity_weight * failure_rate
    }

