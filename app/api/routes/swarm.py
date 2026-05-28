from fastapi import APIRouter

from app.schemas.swarm import SwarmConfig
from app.orchestrator.swarm_manager import swarm_manager

router = APIRouter(prefix="/swarm", tags=["swarm"])

@router.post("/start")
async def start_swarm(config: SwarmConfig):
    await swarm_manager.start(
        config.target_url,
        config.agent_count,
    )

    return {
        "status": "started"
    }


@router.post("/stop")
async def stop_swarm():
    await swarm_manager.stop()

    return {
        "status": "stopped"
    }