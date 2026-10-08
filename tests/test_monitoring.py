
import pytest

from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app

from app.database.database import (
    Base,
    get_db,
)

from app.database import models
from app.database import execution_models


@pytest.fixture
def monitoring_client(tmp_path, monkeypatch):

    monkeypatch.setenv(
        "ADMIN_API_KEY",
        "test-admin-key",
    )

    database_file = tmp_path / "monitoring.db"

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

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    try:
        yield client
    finally:
        client.close()
        app.dependency_overrides.clear()
        engine.dispose()


def test_monitoring_requires_admin(monitoring_client):

    response = monitoring_client.get(
        "/monitoring/dashboard"
    )

    assert response.status_code == 401


def test_monitoring_returns_overview(monitoring_client):

    response = monitoring_client.get(
        "/monitoring/dashboard",
        headers={
            "x-admin-key": "test-admin-key"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "overview" in data
    assert "decision_distribution" in data
    assert "risk_distribution" in data
    assert "agent_activity" in data
    assert "resource_activity" in data
    assert "recent_requests" in data


def test_empty_database_statistics(monitoring_client):

    response = monitoring_client.get(
        "/monitoring/dashboard",
        headers={
            "x-admin-key": "test-admin-key"
        },
    )

    data = response.json()

    assert data["overview"]["total_requests"] == 0
    assert data["overview"]["pending_approvals"] == 0


def test_invalid_admin_key(monitoring_client):

    response = monitoring_client.get(
        "/monitoring/dashboard",
        headers={
            "x-admin-key": "wrong-key"
        },
    )

    assert response.status_code == 401
