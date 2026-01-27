"""
AI Redteam Project - Reinforcement Learning Module

Implements RL-based attack optimization for vulnerability assessment.
"""

# Global rule scores for RL-based attack optimization
rule_scores = {}


def update_score(rule, success):
    """
    Update the score for a rule based on execution success.
    
    Args:
        rule: Rule name or identifier
        success: Boolean indicating if the attack was successful
    """
    rule_scores[rule] = rule_scores.get(rule, 0) + (1 if success else -1)


def get_rule_scores():
    """Get all rule scores."""
    return rule_scores


def reset_scores():
    """Reset all rule scores."""
    global rule_scores
    rule_scores = {}


class AttackOptimizer:
    """
    High-level attack optimization using RL.
    
    Learns from successful/failed attacks to optimize future strategies.
    """
    
    def __init__(self, config: Optional[dict] = None):
        """
        Initialize the attack optimizer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
    
    def optimize_attack(self, strategy: List[dict]) -> List[dict]:
        """
        Optimize attack strategy based on learned scores.
        
        Args:
            strategy: Original attack strategy
            
        Returns:
            Optimized strategy with high-score rules prioritized
        """
        # Sort rules by their learned scores
        optimized = sorted(strategy, key=lambda r: rule_scores.get(r.get("name", ""), 0), reverse=True)
        return optimized
    
    def record_result(self, rule: str, success: bool):
        """
        Record an attack result for learning.
        
        Args:
            rule: Rule name
            success: Whether the attack was successful
        """
        update_score(rule, success)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get training metrics."""
        return {
            "total_rules": len(rule_scores),
            "rule_scores": get_rule_scores()
        }

