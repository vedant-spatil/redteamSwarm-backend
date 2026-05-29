from pydantic import BaseModel

class ForumEntry(BaseModel):
    agent_id: str
    message: str