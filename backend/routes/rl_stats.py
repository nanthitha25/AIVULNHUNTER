"""
RL Stats API - Provides data for the heatmap visualization
Uses real RL scores computed from scan results
"""

from fastapi import APIRouter, Depends
from auth import require_role
from services.scan_pipeline import SCANS_DB
from rules.rules import load_rules
import json

router = APIRouter(prefix="/rl", tags=["RL"])

# In-memory RL scores storage (persisted to file)
RL_SCORES_FILE = "backend/rl/rule_scores.json"

def load_rl_scores():
    """Load RL scores from file."""
    try:
        with open(RL_SCORES_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_rl_scores(scores):
    """Save RL scores to file."""
    with open(RL_SCORES_FILE, "w") as f:
        json.dump(scores, f, indent=2)

def compute_aggregate_rl_scores():
    """
    Compute aggregate RL scores from all scan results.
    Returns list of rule scores with real data.
    """
    scores = load_rl_scores()
    
    # Get all rules from rules database
    try:
        rules = load_rules()
    except:
        rules = []
    
    # If no saved scores and no rules, return default values
    if not scores and not rules:
        return [
            {"rule": "Prompt Injection", "owasp": "LLM01", 
             "severity": "HIGH", "q_score": 0.5, "priority": 1},
            {"rule": "Data Leakage", "owasp": "LLM02", 
             "severity": "MEDIUM", "q_score": 0.5, "priority": 2},
            {"rule": "Information Disclosure", "owasp": "LLM03", 
             "severity": "LOW", "q_score": 0.5, "priority": 3}
        ]
    
    # If no saved scores but have rules, return rules with default scores
    if not scores:
        return [
            {"rule": r.get("name", "Unknown"), "owasp": r.get("owasp", "N/A"), 
             "severity": r.get("severity", "MEDIUM"), "q_score": 0.5, "priority": r.get("priority", 5)}
            for r in rules[:5]  # Return first 5 rules
        ]
    
    # Merge rules with scores
    result = []
    for rule in rules:
        rule_name = rule.get("name", "Unknown")
        q_score = scores.get(rule_name, 0.5)
        
        # Compute priority from Q-score
        priority = 5
        if q_score >= 2.5:
            priority = 1
        elif q_score >= 1.5:
            priority = 2
        elif q_score >= 0.5:
            priority = 3
        else:
            priority = 4
        
        result.append({
            "rule": rule_name,
            "owasp": rule.get("owasp", "N/A"),
            "severity": rule.get("severity", "MEDIUM"),
            "q_score": q_score,
            "priority": priority
        })
    
    return result

@router.get("/heatmap")
def get_heatmap(admin=Depends(require_role("admin"))):
    """Get RL heatmap data for visualization"""
    scores = compute_aggregate_rl_scores()
    return {
        "total_rules": len(scores),
        "avg_q_score": sum(s["q_score"] for s in scores) / len(scores) if scores else 0,
        "max_q_score": max(s["q_score"] for s in scores) if scores else 0,
        "rules": scores
    }

@router.get("/scores")
def get_rl_scores(admin=Depends(require_role("admin"))):
    """Get raw RL scores for all rules"""
    scores = load_rl_scores()
    return {"scores": scores}

@router.post("/scores/{rule_name}")
def update_rl_score(rule_name: str, body: dict, admin=Depends(require_role("admin"))):
    """Manually update RL score for a rule"""
    scores = load_rl_scores()
    scores[rule_name] = body.get("score", 0.5)
    save_rl_scores(scores)
    return {"status": "updated", "rule": rule_name, "score": scores[rule_name]}

@router.get("/stats")
def get_stats(admin=Depends(require_role("admin"))):
    """Get RL statistics"""
    scores = compute_aggregate_rl_scores()
    return {
        "scores": scores,
        "total_rules": len(scores),
        "avg_q_score": sum(s["q_score"] for s in scores) / len(scores) if scores else 0,
        "max_q_score": max(s["q_score"] for s in scores) if scores else 0,
        "high_risk": len([s for s in scores if s["q_score"] > 0.7]),
        "medium_risk": len([s for s in scores if 0.4 < s["q_score"] <= 0.7]),
        "low_risk": len([s for s in scores if s["q_score"] <= 0.4])
    }

@router.post("/reset")
def reset_rl_scores(admin=Depends(require_role("admin"))):
    """Reset all RL scores to default"""
    scores = {
        "Prompt Injection": 0.5,
        "Data Leakage": 0.5,
        "Information Disclosure": 0.5,
        "Auth Bypass": 0.5,
        "Model Manipulation": 0.5
    }
    save_rl_scores(scores)
    return {"status": "reset", "scores": scores}

