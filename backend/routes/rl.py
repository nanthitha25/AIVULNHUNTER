"""
RL Heatmap API - Provides data for the rule priority heatmap visualization
"""

from fastapi import APIRouter, Depends
from ...auth import get_current_admin
from ...rl.rule_prioritizer import rl_engine
from ...routes.rules import rules_db

router = APIRouter(prefix="/rl", tags=["RL"])


@router.get("/heatmap")
def rl_heatmap(admin=Depends(get_current_admin)):
    """
    Get data for the rule priority heatmap.
    
    Returns a list of rules with their Q-scores and severity levels
    for visualization in the frontend.
    
    Returns:
        List of dictionaries containing:
        - rule_id: Unique identifier for the rule
        - rule: Rule name
        - severity: Severity level (LOW/MEDIUM/HIGH/CRITICAL)
        - q_score: Current Q-score from RL
        - priority: Calculated priority (1-4)
    """
    data = []
    
    # Get Q-scores from RL engine
    q_scores = rl_engine.get_all_scores()
    
    for rule in rules_db:
        rule_id = str(rule.get("id", rule.get("rule_id", "")))
        q_score = q_scores.get(rule_id, 0)
        priority = rl_engine.get_priority(q_score)
        
        data.append({
            "rule_id": rule_id,
            "rule": rule.get("name", "Unknown"),
            "severity": rule.get("severity", "MEDIUM"),
            "q_score": q_score,
            "priority": priority
        })
    
    return {
        "rules": data,
        "total_rules": len(data),
        "max_q_score": max(q_scores.values()) if q_scores else 0,
        "avg_q_score": sum(q_scores.values()) / len(q_scores) if q_scores else 0
    }


@router.get("/metrics")
def rl_metrics(admin=Depends(get_current_admin)):
    """
    Get detailed RL metrics for all rules.
    
    Returns the complete metrics storage including Q-scores,
    priorities, and rule names.
    """
    return {
        "metrics": rl_engine.get_metrics(),
        "q_table": rl_engine.get_all_scores()
    }


@router.get("/q_score/{rule_id}")
def get_rule_q_score(rule_id: str, admin=Depends(get_current_admin)):
    """
    Get the Q-score for a specific rule.
    
    Args:
        rule_id: The rule ID to query
        
    Returns:
        Q-score and priority for the rule
    """
    q_score = rl_engine.get_q_score(rule_id)
    priority = rl_engine.get_priority(q_score)
    
    return {
        "rule_id": rule_id,
        "q_score": q_score,
        "priority": priority
    }


@router.post("/reset")
def reset_rl_metrics(admin=Depends(get_current_admin)):
    """
    Reset all RL metrics (for testing purposes).
    
    Returns success message after clearing Q-table and metrics.
    """
    from ...rl.rule_prioritizer import RULE_METRICS
    from ...rl.rule_prioritizer import RuleRL
    
    # Create new engine instance
    global rl_engine
    rl_engine = RuleRL()
    
    # Clear metrics storage
    RULE_METRICS.clear()
    
    return {"message": "RL metrics have been reset"}

