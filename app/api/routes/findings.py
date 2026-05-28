from fastapi import APIRouter

from app.orchestrator.swarm_manager import (
    swarm_manager
)

router = APIRouter(
    prefix="/findings",
    tags=["findings"]
)

@router.get("")
def get_findings():

    return swarm_manager.findings