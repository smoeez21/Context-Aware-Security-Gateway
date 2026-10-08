
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
)

from app.database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


# ============================================================
# SIMULATED RESOURCE STATE
# ============================================================

class ResourceState(Base):
    __tablename__ = "resource_states"

    id = Column(
        Integer,
        primary_key=True,
    )

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        unique=True,
        nullable=False,
    )

    content_json = Column(
        Text,
        nullable=False,
        default="{}",
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


# ============================================================
# RESOURCE EXECUTION RECORD
# ============================================================

class ResourceExecution(Base):
    __tablename__ = "resource_executions"

    id = Column(
        Integer,
        primary_key=True,
    )

    request_id = Column(
        Integer,
        ForeignKey("requests.id"),
        unique=True,
        nullable=False,
    )

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        nullable=False,
    )

    action = Column(
        String(20),
        nullable=False,
    )

    result_json = Column(
        Text,
        nullable=False,
    )

    executed_at = Column(
        DateTime(timezone=True),
        default=utc_now,
    )


# ============================================================
# PENDING REQUEST PAYLOAD
# ============================================================

class RequestPayload(Base):
    __tablename__ = "request_payloads"

    id = Column(
        Integer,
        primary_key=True,
    )

    request_id = Column(
        Integer,
        ForeignKey("requests.id"),
        unique=True,
        nullable=False,
    )

    payload_json = Column(
        Text,
        nullable=False,
    )
