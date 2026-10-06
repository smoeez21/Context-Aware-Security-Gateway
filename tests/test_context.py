from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_external_context():

    response = client.post(
        "/access-request",
        json={
            "agent_code": "AGENT-SALES-001",
            "credential": "sales-demo-key",
            "resource_code": "RES-CUSTOMERS",
            "action": "SEND",
            "destination": "EXTERNAL"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["resource_sensitivity"]
        == "HIGH"
    )

    assert (
        data["context"][
            "external_destination"
        ]
        is True
    )