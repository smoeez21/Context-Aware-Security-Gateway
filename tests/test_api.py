from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_home():

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "running"


def test_get_agents():

    response = client.get("/agents")

    assert response.status_code == 200

    assert isinstance(
        response.json(),
        list
    )


def test_get_resources():

    response = client.get("/resources")

    assert response.status_code == 200

    assert isinstance(
        response.json(),
        list
    )