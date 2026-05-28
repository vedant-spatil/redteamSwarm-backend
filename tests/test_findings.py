from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_findings_endpoint():
    response = client.get("/findings")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
