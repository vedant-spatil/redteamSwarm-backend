from pydantic import BaseModel

class AgentStatus(BaseModel):
    agent_id: str
    focus_area: str
    status: str