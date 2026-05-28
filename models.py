from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime
import uuid


class SwarmConfig(BaseModel):
    target_url: str
    agent_count: int = Field(default=4, ge=1, le=8)
    max_runtime_seconds: int = Field(default=3600)
    ollama_model: str = "qwen2.5-coder:3b"
    ollama_host: str = "http://localhost:11434"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    vuln_type: str
    description: str
    evidence: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    agent_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    confirmed: bool = False


class ForumEntry(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    agent_id: str
    focus_area: str
    message: str
    finding_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class AgentStatus(BaseModel):
    agent_id: str
    focus_area: str
    status: Literal["idle", "running", "blocked", "done", "error"]
    current_task: str = ""
    finding_count: int = 0
    iteration: int = 0
    last_seen: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    error_msg: Optional[str] = None


class SwarmStatus(BaseModel):
    running: bool
    target_url: str = ""
    agent_count: int = 0
    agents: List[AgentStatus] = []
    finding_count: int = 0
    start_time: Optional[str] = None


class LogEntry(BaseModel):
    agent_id: str
    level: Literal["INFO", "WARN", "ERROR", "TOOL", "FINDING"]
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())