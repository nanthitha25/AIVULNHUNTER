"""
Database CRUD operations for rules and RL weights
"""

from sqlalchemy.orm import Session
from typing import List, Optional

from backend.database.models import Rule, RLWeight


def get_rules(
    db: Session,
    enabled_only: bool = True,
    target_type: Optional[str] = None
) -> List[Rule]:
    """
    Get all rules, optionally filtered
    
    Args:
        db: Database session
        enabled_only: Only return enabled rules
        target_type: Filter by target type (e.g., 'LLM_API')
    
    Returns:
        List of Rule objects
    """
    query = db.query(Rule)
    
    if enabled_only:
        query = query.filter(Rule.enabled == True)
    
    if target_type:
        query = query.filter(Rule.target_types.contains([target_type]))
    
    return query.order_by(Rule.priority).all()


def get_rule(db: Session, rule_id: int) -> Optional[Rule]:
    """Get rule by ID"""
    return db.query(Rule).filter(Rule.id == rule_id).first()


def create_rule(
    db: Session,
    name: str,
    owasp: str,
    severity: str,
    priority: int = 1,
    description: str = "",
    target_types: List[str] = None,
    enabled: bool = True
) -> Rule:
    """Create a new rule"""
    rule = Rule(
        name=name,
        owasp=owasp,
        severity=severity,
        priority=priority,
        description=description,
        target_types=target_types or ["LLM_API"],
        enabled=enabled
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    
    # Create corresponding RL weight
    rl_weight = RLWeight(
        rule_id=rule.id,
        weight=0.5,
        priority_score=0.5
    )
    db.add(rl_weight)
    db.commit()
    
    return rule


def update_rule(
    db: Session,
    rule_id: int,
    **kwargs
) -> Optional[Rule]:
    """Update rule fields"""
    rule = get_rule(db, rule_id)
    if rule:
        for key, value in kwargs.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        db.commit()
        db.refresh(rule)
    return rule


def delete_rule(db: Session, rule_id: int) -> bool:
    """Delete a rule (cascades to RL weights)"""
    rule = get_rule(db, rule_id)
    if rule:
        db.delete(rule)
        db.commit()
        return True
    return False


def get_rl_weight(db: Session, rule_id: int) -> Optional[RLWeight]:
    """Get RL weight for a rule"""
    return db.query(RLWeight).filter(RLWeight.rule_id == rule_id).first()


def update_rl_weight(
    db: Session,
    rule_id: int,
    success: bool,
    learning_rate: float = 0.1
) -> Optional[RLWeight]:
    """
    Update RL weight based on scan result
    
    Args:
        db: Database session
        rule_id: Rule ID
        success: Whether the rule found a vulnerability
        learning_rate: Learning rate for weight update
    
    Returns:
        Updated RLWeight object
    """
    rl_weight = get_rl_weight(db, rule_id)
    
    if not rl_weight:
        # Create if doesn't exist
        rl_weight = RLWeight(rule_id=rule_id)
        db.add(rl_weight)
    
    # Update counts
    rl_weight.total_scans += 1
    if success:
        rl_weight.success_count += 1
    else:
        rl_weight.failure_count += 1
    
    # Update priority score using simple RL
    reward = 2 if success else 0
    rl_weight.priority_score = rl_weight.priority_score + learning_rate * reward
    
    # Normalize to [0, 1]
    rl_weight.priority_score = max(0.0, min(1.0, rl_weight.priority_score))
    
    db.commit()
    db.refresh(rl_weight)
    return rl_weight


def get_all_rl_weights(db: Session) -> List[RLWeight]:
    """Get all RL weights ordered by priority score"""
    return db.query(RLWeight).order_by(RLWeight.priority_score.desc()).all()
