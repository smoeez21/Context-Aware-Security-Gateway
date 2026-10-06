from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from sqlalchemy.orm import relationship

from app.database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


# ============================================================
# 1. AGENTS
# ============================================================

class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)

    agent_code = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )

    name = Column(
        String(100),
        nullable=False
    )

    department = Column(
        String(100),
        nullable=False
    )

    role = Column(
        String(100),
        nullable=False
    )

    status = Column(
        String(20),
        nullable=False,
        default="ACTIVE"
    )

    credential_hash = Column(
        String(255),
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    policies = relationship(
        "Policy",
        back_populates="agent"
    )

    requests = relationship(
        "AccessRequest",
        back_populates="agent"
    )


# ============================================================
# 2. RESOURCES
# ============================================================

class Resource(Base):
    __tablename__ = "resources"

    id = Column(Integer, primary_key=True, index=True)

    resource_code = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )

    name = Column(
        String(100),
        unique=True,
        nullable=False
    )

    resource_type = Column(
        String(50),
        nullable=False
    )

    sensitivity = Column(
        String(20),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    policies = relationship(
        "Policy",
        back_populates="resource"
    )

    requests = relationship(
        "AccessRequest",
        back_populates="resource"
    )


# ============================================================
# 3. POLICIES
# ============================================================

class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(
        Integer,
        ForeignKey("agents.id"),
        nullable=False
    )

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        nullable=False
    )

    action = Column(
        String(20),
        nullable=False
    )

    destination = Column(
        String(20),
        nullable=False,
        default="INTERNAL"
    )

    effect = Column(
        String(20),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    agent = relationship(
        "Agent",
        back_populates="policies"
    )

    resource = relationship(
        "Resource",
        back_populates="policies"
    )

    __table_args__ = (
        UniqueConstraint(
            "agent_id",
            "resource_id",
            "action",
            "destination",
            name="uq_policy_rule"
        ),
    )


# ============================================================
# 4. REQUESTS
# ============================================================

class AccessRequest(Base):
    __tablename__ = "requests"

    id = Column(Integer, primary_key=True, index=True)

    request_code = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True
    )

    agent_id = Column(
        Integer,
        ForeignKey("agents.id"),
        nullable=True
    )

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        nullable=True
    )

    presented_agent_code = Column(
        String(50),
        nullable=False
    )

    action = Column(
        String(20),
        nullable=False
    )

    destination = Column(
        String(20),
        nullable=False
    )

    authentication_status = Column(
        String(30),
        nullable=True
    )

    authorization_status = Column(
        String(30),
        nullable=True
    )

    decision = Column(
        String(30),
        nullable=True
    )

    status = Column(
        String(30),
        nullable=False,
        default="RECEIVED"
    )

    requested_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    agent = relationship(
        "Agent",
        back_populates="requests"
    )

    resource = relationship(
        "Resource",
        back_populates="requests"
    )

    risk_assessment = relationship(
        "RiskAssessment",
        back_populates="request",
        uselist=False
    )

    approval = relationship(
        "Approval",
        back_populates="request",
        uselist=False
    )

    audit_log = relationship(
        "AuditLog",
        back_populates="request",
        uselist=False
    )


# ============================================================
# 5. RISK ASSESSMENTS
# ============================================================

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)

    request_id = Column(
        Integer,
        ForeignKey("requests.id"),
        unique=True,
        nullable=False
    )

    risk_score = Column(
        Integer,
        nullable=False
    )

    risk_level = Column(
        String(20),
        nullable=False
    )

    permission_violation = Column(
        Boolean,
        default=False
    )

    sensitive_resource = Column(
        Boolean,
        default=False
    )

    external_destination = Column(
        Boolean,
        default=False
    )

    unusual_activity = Column(
        Boolean,
        default=False
    )

    high_frequency = Column(
        Boolean,
        default=False
    )

    suspicious_sequence = Column(
        Boolean,
        default=False
    )

    reasons = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    request = relationship(
        "AccessRequest",
        back_populates="risk_assessment"
    )


# ============================================================
# 6. APPROVALS
# ============================================================

class Approval(Base):
    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, index=True)

    request_id = Column(
        Integer,
        ForeignKey("requests.id"),
        unique=True,
        nullable=False
    )

    status = Column(
        String(30),
        nullable=False,
        default="PENDING"
    )

    reviewed_by = Column(
        String(100),
        nullable=True
    )

    admin_comment = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    request = relationship(
        "AccessRequest",
        back_populates="approval"
    )


# ============================================================
# 7. AUDIT LOGS
# ============================================================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    request_id = Column(
        Integer,
        ForeignKey("requests.id"),
        unique=True,
        nullable=False
    )

    agent_code = Column(
        String(50),
        nullable=False
    )

    action = Column(
        String(20),
        nullable=False
    )

    resource_name = Column(
        String(100),
        nullable=False
    )

    destination = Column(
        String(20),
        nullable=False
    )

    risk_score = Column(
        Integer,
        nullable=True
    )

    risk_level = Column(
        String(20),
        nullable=True
    )

    decision = Column(
        String(30),
        nullable=False
    )

    reason = Column(
        Text,
        nullable=True
    )

    final_outcome = Column(
        String(50),
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False
    )

    request = relationship(
        "AccessRequest",
        back_populates="audit_log"
    )