from pydantic import BaseModel

class SwarmConfig(BaseModel):
    target_url: str
    agent_count: int = 4

class SwarmStatus(BaseModel):
    running: bool
    target_url: str
    agent_count: int