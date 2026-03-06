"""
Reinforcement Learning Rule Prioritizer

Uses Q-learning to dynamically adjust rule priorities based on scan results.
Higher Q-scores indicate rules that frequently detect vulnerabilities.
"""

SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# In-memory storage for rule metrics
RULE_METRICS = {}


class RuleRL:
    """
    Q-Learning based rule prioritizer.
    
    The agent learns which rules are most effective at detecting vulnerabilities
    and adjusts their priorities accordingly.
    """
    
    def __init__(self):
        self.q_table = {}  # rule_id → Q-score
    
    def update(self, rule, scan_result):
        """
        Update Q-score for a rule based on scan result.
        
        Args:
            rule: The security rule that was tested
            scan_result: Result of the scan (status: PASSED/FAILED)
            
        Returns:
            Updated Q-score for the rule
        """
        rule_id = str(rule.get("id", rule.get("rule_id", "unknown")))
        severity = rule.get("severity", "MEDIUM")
        failed = 1 if scan_result.get("status", "").upper() == "FAILED" else 0
        
        # Calculate reward: severity weight * failure indicator
        reward = SEVERITY_WEIGHT.get(severity, 1) * failed
        
        # Q-learning update: Q(s,a) = Q(s,a) + α * (reward - Q(s,a))
        # Using learning rate α = 0.1
        old_q = self.q_table.get(rule_id, 0)
        new_q = old_q + 0.1 * (reward - old_q)
        
        # Store with 2 decimal precision
        self.q_table[rule_id] = round(new_q, 2)
        
        # Update metrics storage
        RULE_METRICS[rule_id] = {
            "q_score": self.q_table[rule_id],
            "priority": self.get_priority(self.q_table[rule_id]),
            "rule_name": rule.get("name", "Unknown"),
            "severity": severity
        }
        
        return self.q_table[rule_id]
    
    def get_priority(self, q_score):
        """
        Convert Q-score to priority (1-4).
        
        Priority mapping:
        - Q >= 2.5: Priority 1 (Critical - most effective)
        - Q >= 1.5: Priority 2 (High)
        - Q >= 0.5: Priority 3 (Medium)
        - Q < 0.5:  Priority 4 (Low)
        
        Args:
            q_score: The Q-score to convert
            
        Returns:
            Priority level (1-4)
        """
        if q_score >= 2.5:
            return 1
        elif q_score >= 1.5:
            return 2
        elif q_score >= 0.5:
            return 3
        else:
            return 4
    
    def get_q_score(self, rule_id):
        """Get the current Q-score for a rule."""
        return self.q_table.get(str(rule_id), 0)
    
    def get_all_scores(self):
        """Get all Q-scores."""
        return self.q_table.copy()
    
    def get_metrics(self):
        """Get all rule metrics."""
        return RULE_METRICS.copy()


# Global RL engine instance
rl_engine = RuleRL()

