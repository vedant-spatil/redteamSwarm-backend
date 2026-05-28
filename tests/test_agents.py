from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_agents_endpoint():
    response = client.get("/agents")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
