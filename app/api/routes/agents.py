from fastapi import APIRouter

from app.orchestrator.swarm_manager import swarm_manager

router = APIRouter(prefix="/agents", tags=["agents"])

@router.get("")
def list_agents():
    return [
        {
            "agent_id": a.agent_id,
            "focus_area": a.focus_area,
        }
        for a in swarm_manager.agents
    ]