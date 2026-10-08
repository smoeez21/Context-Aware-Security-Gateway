
import pytest

from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app

from app.database.database import (
    Base,
    get_db,
)

# Register all tables.
from app.database import models
from app.database import execution_models

from app.database.models import (
    Agent,
    Resource,
    Policy,
    AccessRequest,
    AuditLog,
    Approval,
)

from app.database.execution_models import (
    ResourceExecution,
)


@pytest.fixture
def environment(tmp_path, monkeypatch):

    monkeypatch.setenv(
        "ADMIN_API_KEY",
        "phase7-test-admin-secret",
    )

    database_file = tmp_path / "phase7_test.db"

    engine = create_engine(
        f"sqlite:///{database_file}",
        connect_args={
            "check_same_thread": False
        },
    )

    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    db = TestingSession()

    from app.security.credentials import hash_credential

    agent = Agent(
        agent_code="AGENT-SALES-001",
        name="Sales Agent",
        department="Sales",
        role="Sales Representative",
        status="ACTIVE",
        credential_hash=hash_credential(
            "sales-demo-key"
        ),
    )

    sales = Resource(
        resource_code="RES-SALES",
        name="Sales Data",
        resource_type="FILE",
        sensitivity="MEDIUM",
    )

    customer = Resource(
        resource_code="RES-CUSTOMERS",
        name="Customer Data",
        resource_type="DATABASE",
        sensitivity="HIGH",
    )

    salary = Resource(
        resource_code="RES-SALARY",
        name="Employee Salary",
        resource_type="DATABASE",
        sensitivity="CRITICAL",
    )

    db.add_all([
        agent,
        sales,
        customer,
        salary,
    ])

    db.flush()

    db.add_all([
        Policy(
            agent_id=agent.id,
            resource_id=sales.id,
            action="READ",
            destination="INTERNAL",
            effect="ALLOW",
        ),
        Policy(
            agent_id=agent.id,
            resource_id=customer.id,
            action="SEND",
            destination="EXTERNAL",
            effect="ALLOW",
        ),
        Policy(
            agent_id=agent.id,
            resource_id=salary.id,
            action="READ",
            destination="INTERNAL",
            effect="DENY",
        ),
    ])

    db.commit()
    db.close()

    def override_get_db():
        session = TestingSession()

        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client, TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def send_request(
    client,
    resource_code,
    action,
    destination,
):

    return client.post(
        "/access-request",
        json={
            "agent_code": "AGENT-SALES-001",
            "credential": "sales-demo-key",
            "resource_code": resource_code,
            "action": action,
            "destination": destination,
        },
    )


def test_allow_executes_resource(environment):

    client, Session = environment

    response = send_request(
        client,
        "RES-SALES",
        "READ",
        "INTERNAL",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"] == "ALLOW"
    assert data["status"] == "EXECUTED"

    with Session() as db:
        assert db.query(ResourceExecution).count() == 1
        assert db.query(AuditLog).count() == 1


def test_block_prevents_execution(environment):

    client, Session = environment

    response = send_request(
        client,
        "RES-SALARY",
        "READ",
        "INTERNAL",
    )

    data = response.json()

    assert data["decision"] == "BLOCK"

    with Session() as db:
        assert db.query(ResourceExecution).count() == 0
        assert db.query(AuditLog).count() == 1


def test_human_approval_workflow(environment):

    client, Session = environment

    response = send_request(
        client,
        "RES-CUSTOMERS",
        "SEND",
        "EXTERNAL",
    )

    data = response.json()

    assert data["decision"] == "HUMAN_APPROVAL"
    assert data["status"] == "PENDING_APPROVAL"

    with Session() as db:
        approval = db.query(Approval).first()

        assert approval.status == "PENDING"

        approval_id = approval.id

        assert db.query(ResourceExecution).count() == 0

    response = client.post(
        f"/approvals/{approval_id}/approve",
        headers={
            "x-admin-key": "phase7-test-admin-secret"
        },
        json={
            "comment": "Approved for testing."
        },
    )

    assert response.status_code == 200

    assert (
        response.json()["final_outcome"]
        == "EXECUTED"
    )

    with Session() as db:
        assert db.query(ResourceExecution).count() == 1

        approval = db.get(Approval, approval_id)
        assert approval.status == "APPROVED"


def test_admin_key_required(environment):

    client, Session = environment

    response = client.get("/approvals")

    assert response.status_code == 401

    response = client.get("/audit-logs")

    assert response.status_code == 401


def test_unknown_resource_is_audited(environment):

    client, Session = environment

    response = send_request(
        client,
        "RES-DOES-NOT-EXIST",
        "READ",
        "INTERNAL",
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"

    with Session() as db:
        assert db.query(AuditLog).count() == 1
        assert db.query(ResourceExecution).count() == 0


def test_cannot_approve_twice(environment):

    client, Session = environment

    response = send_request(
        client,
        "RES-CUSTOMERS",
        "SEND",
        "EXTERNAL",
    )

    assert response.json()["decision"] == "HUMAN_APPROVAL"

    with Session() as db:
        approval_id = db.query(Approval).first().id

    path = f"/approvals/{approval_id}/approve"

    headers = {
        "x-admin-key": "phase7-test-admin-secret"
    }

    first = client.post(
        path,
        headers=headers,
        json={"comment": "First review"},
    )

    assert first.status_code == 200

    second = client.post(
        path,
        headers=headers,
        json={"comment": "Second review"},
    )

    assert second.status_code == 409

    with Session() as db:
        assert db.query(ResourceExecution).count() == 1
