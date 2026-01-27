"""
Reinforcement Learning Module for Rule Scoring

Tracks and updates scores for vulnerability detection rules
based on execution results.
"""

from typing import Dict

# Global dictionary to store rule scores
rule_scores: Dict[str, int] = {}


def update_rule(rule_name: str, detected: bool) -> None:
    """Update the score for a rule based on detection result.
    
    Args:
        rule_name: Name of the vulnerability rule
        detected: Whether the vulnerability was detected (True) or safe (False)
    """
    if rule_name not in rule_scores:
        rule_scores[rule_name] = 0
    rule_scores[rule_name] += 1 if detected else -1


def get_scores() -> Dict[str, int]:
    """Get all rule scores.
    
    Returns:
        Dictionary mapping rule names to their scores
    """
    return rule_scores


def reset_scores() -> None:
    """Reset all rule scores to zero."""
    global rule_scores
    rule_scores = {}


def get_top_rules(limit: int = 5) -> Dict[str, int]:
    """Get the top N rules by score.
    
    Args:
        limit: Maximum number of rules to return
        
    Returns:
        Dictionary of top rules sorted by score
    """
    sorted_rules = sorted(rule_scores.items(), key=lambda x: x[1], reverse=True)
    return dict(sorted_rules[:limit])

