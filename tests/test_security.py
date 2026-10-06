from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_authorized_sales_access():

    response = client.post(
        "/access-request",
        json={
            "agent_code": "AGENT-SALES-001",
            "credential": "sales-demo-key",
            "resource_code": "RES-SALES",
            "action": "READ",
            "destination": "INTERNAL"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["authentication_status"]
        == "SUCCESS"
    )

    assert (
        data["authorization_status"]
        == "ALLOWED"
    )

    assert data["decision"] == "ALLOW"


def test_unauthorized_salary_access():

    response = client.post(
        "/access-request",
        json={
            "agent_code": "AGENT-SALES-001",
            "credential": "sales-demo-key",
            "resource_code": "RES-SALARY",
            "action": "READ",
            "destination": "INTERNAL"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["authentication_status"]
        == "SUCCESS"
    )

    assert (
        data["authorization_status"]
        == "DENIED"
    )

    assert data["decision"] == "BLOCK"


def test_invalid_authentication():

    response = client.post(
        "/access-request",
        json={
            "agent_code": "AGENT-SALES-001",
            "credential": "wrong-key",
            "resource_code": "RES-SALES",
            "action": "READ",
            "destination": "INTERNAL"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["authentication_status"]
        == "FAILED"
    )

    assert data["decision"] == "BLOCK"