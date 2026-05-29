from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_start_swarm():
    response = client.post(
        "/swarm/start",
        json={
            "target_url": "http://localhost:8000",
            "agent_count": 2,
        }
    )

    assert response.status_code == 200
    assert response.json()["status"] == "started"

def test_stop_swarm():
    response = client.post("/swarm/stop")

    assert response.status_code == 200
    assert response.json()["status"] == "stopped"
