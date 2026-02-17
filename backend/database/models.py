"""
SQLAlchemy ORM models for AivulnHunter database
Maps Python classes to PostgreSQL tables
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, 
    ForeignKey, TIMESTAMP, ARRAY, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from backend.database.connection import Base


class User(Base):
    """User account model for authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), default='user')
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login = Column(TIMESTAMP(timezone=True))
    
    # Relationships
    scans = relationship("Scan", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(username='{self.username}', role='{self.role}')>"


class APIKey(Base):
    """API keys for programmatic access"""
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    key_hash = Column(String(255), nullable=False)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    expires_at = Column(TIMESTAMP(timezone=True))
    last_used_at = Column(TIMESTAMP(timezone=True))
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    def __repr__(self):
        return f"<APIKey(name='{self.name}', user_id='{self.user_id}')>"


class Rule(Base):
    """Security testing rules (OWASP mappings)"""
    __tablename__ = "rules"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    owasp = Column(String(50), nullable=False)
    severity = Column(String(50), nullable=False)
    priority = Column(Integer, default=1)
    description = Column(Text)
    enabled = Column(Boolean, default=True)
    target_types = Column(ARRAY(Text))  # ['LLM_API', 'WEB_APP', 'GENERIC_API']
    metadata = Column(JSONB, default={})
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    rl_weight = relationship("RLWeight", back_populates="rule", uselist=False)
    vulnerabilities = relationship("Vulnerability", back_populates="rule")
    
    __table_args__ = (
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name='check_severity'
        ),
    )
    
    def __repr__(self):
        return f"<Rule(id={self.id}, name='{self.name}', owasp='{self.owasp}')>"


class RLWeight(Base):
    """Reinforcement learning weights for adaptive scanning"""
    __tablename__ = "rl_weights"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey('rules.id', ondelete='CASCADE'), nullable=False, unique=True)
    weight = Column(Float, default=0.5)
    priority_score = Column(Float, default=0.5)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    total_scans = Column(Integer, default=0)
    last_updated = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    rule = relationship("Rule", back_populates="rl_weight")
    
    def __repr__(self):
        return f"<RLWeight(rule_id={self.rule_id}, priority_score={self.priority_score})>"


class Scan(Base):
    """Scan execution history and results"""
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'))
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), default='full')
    status = Column(String(50), default='pending')
    profile = Column(JSONB, default={})
    started_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    completed_at = Column(TIMESTAMP(timezone=True))
    duration_seconds = Column(Integer)
    total_rules_tested = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    metadata = Column(JSONB, default={})
    
    # Relationships
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'cancelled')",
            name='check_status'
        ),
    )
    
    def __repr__(self):
        return f"<Scan(id='{self.id}', target='{self.target}', status='{self.status}')>"


class Vulnerability(Base):
    """Detected vulnerabilities from scans"""
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    rule_id = Column(Integer, ForeignKey('rules.id', ondelete='SET NULL'))
    name = Column(String(255), nullable=False)
    owasp = Column(String(50), nullable=False)
    severity = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    confidence = Column(Float, default=0.5)
    explanation = Column(Text)
    mitigation = Column(Text)
    evidence = Column(Text)
    error_message = Column(Text)
    detected_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    metadata = Column(JSONB, default={})
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    rule = relationship("Rule", back_populates="vulnerabilities")
    
    __table_args__ = (
        CheckConstraint(
            "status IN ('VULNERABLE', 'SECURE', 'WARNING', 'ERROR', 'CHECK_MANUAL')",
            name='check_vuln_status'
        ),
    )
    
    def __repr__(self):
        return f"<Vulnerability(name='{self.name}', severity='{self.severity}', status='{self.status}')>"


class AgentRegistry(Base):
    """Registry of available scanning agents"""
    __tablename__ = "agents_registry"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)
    version = Column(String(50), nullable=False)
    type = Column(String(100), nullable=False)  # 'scanner', 'analyzer', 'reporter'
    description = Column(Text)
    enabled = Column(Boolean, default=True)
    config = Column(JSONB, default={})
    health_status = Column(String(50), default='unknown')
    last_health_check = Column(TIMESTAMP(timezone=True))
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        CheckConstraint(
            "health_status IN ('healthy', 'degraded', 'unhealthy', 'unknown')",
            name='check_health_status'
        ),
    )
    
    def __repr__(self):
        return f"<AgentRegistry(name='{self.name}', version='{self.version}', status='{self.health_status}')>"


class ScanLog(Base):
    """Detailed execution logs for debugging and audit"""
    __tablename__ = "scan_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    agent_name = Column(String(255))
    log_level = Column(String(50), default='INFO')
    message = Column(Text, nullable=False)
    details = Column(JSONB, default={})
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="logs")
    
    __table_args__ = (
        CheckConstraint(
            "log_level IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')",
            name='check_log_level'
        ),
    )
    
    def __repr__(self):
        return f"<ScanLog(scan_id='{self.scan_id}', level='{self.log_level}', message='{self.message[:50]}...')>"
