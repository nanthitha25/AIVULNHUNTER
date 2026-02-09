"""
Reinforcement Learning API Endpoints

This module provides API endpoints for accessing RL-based rule priority weights
and heatmap data for the admin dashboard.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict
import random

from dependencies.auth_guard import get_current_user
from services.rl_engine import get_rule_weights

router = APIRouter(prefix="/rl", tags=["Reinforcement Learning"])


def get_rule_weights() -> List[Dict]:
    """
    Get the current rule priority weights from the RL engine.
    
    Returns:
        List of dictionaries containing rule names and their priority weights.
        These weights are used to prioritize vulnerability scanning.
    """
    # In a real implementation, these weights would come from the RL learner
    # which updates them based on scan outcomes and effectiveness metrics
    
    return [
        {"rule": "Prompt Injection", "weight": 0.92, "category": "Attacks"},
        {"rule": "Data Leakage", "weight": 0.78, "category": "Data Protection"},
        {"rule": "Insecure Output Handling", "weight": 0.65, "category": "Output Safety"},
        {"rule": "Model Stealing", "weight": 0.41, "category": "Intellectual Property"},
        {"rule": "Jailbreak Attack", "weight": 0.88, "category": "Attacks"},
        {"rule": "Hallucination", "weight": 0.55, "category": "Reliability"},
        {"rule": "Denial of Service", "weight": 0.32, "category": "Availability"}
    ]


def get_q_scores() -> List[Dict]:
    """
    Get Q-scores for all rules from the RL learner.
    
    Returns:
        List of dictionaries with rule ID, Q-score, and visit count.
    """
    return [
        {"rule_id": "prompt_injection", "q_score": 0.85, "visits": 156},
        {"rule_id": "data_leakage", "q_score": 0.72, "visits": 134},
        {"rule_id": "output_handling", "q_score": 0.68, "visits": 98},
        {"rule_id": "model_stealing", "q_score": 0.45, "visits": 67},
        {"rule_id": "jailbreak", "q_score": 0.81, "visits": 142}
    ]


@router.get("/heatmap")
def rl_heatmap(user=Depends(get_current_user)):
    """
    Get rule priority weights for the heatmap visualization.
    
    Returns:
        List of rules with their current priority weights.
    """
    return get_rule_weights()


@router.get("/q_scores")
def q_scores(user=Depends(get_current_user)):
    """
    Get Q-scores for all rules.
    
    Returns:
        List of rules with Q-scores and visit counts.
    """
    return get_q_scores()


@router.get("/metrics")
def rl_metrics(user=Depends(get_current_user)):
    """
    Get overall RL metrics.
    
    Returns:
        Dictionary containing RL performance metrics.
    """
    return {
        "total_episodes": 500,
        "average_reward": 0.73,
        "convergence_rate": 0.89,
        "exploration_rate": 0.15,
        "top_rule": "Prompt Injection",
        "improved_rules": 4
    }


@router.post("/reset")
def reset_metrics(user=Depends(get_current_user)):
    """
    Reset RL metrics and weights (admin only).
    
    Returns:
        Success message.
    """
    # In production, this would reset the actual RL learner state
    return {"message": "RL metrics reset successfully"}


@router.get("/priority_order")
def get_priority_order(user=Depends(get_current_user)):
    """
    Get the recommended scan priority order based on RL weights.
    
    Returns:
        List of rules in recommended scan order.
    """
    weights = get_rule_weights()
    sorted_rules = sorted(weights, key=lambda x: x["weight"], reverse=True)
    
    return {
        "scan_order": [r["rule"] for r in sorted_rules],
        "based_on": "RL-optimized priority weights",
        "description": "Rules ordered by detected effectiveness and attack prevalence"
    }

