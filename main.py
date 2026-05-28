"""
FastAPI backend for the Red Team Vulnerability Swarm.

Routes:
  POST /swarm/start      — launch the swarm
  POST /swarm/stop       — stop all agents
  GET  /swarm/status     — current swarm state
  GET  /findings         — all vulnerability findings
  GET  /forum            — recent forum entries
  GET  /logs             — rolling live log feed
  DELETE /reset          — clear all state

Run with:
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List

from models import SwarmConfig, SwarmStatus, Finding, ForumEntry, LogEntry, AgentStatus
from orchestrator import orchestrator
from forum import forum

app = FastAPI(
    title="Red Team Vulnerability Swarm",
    description="Multi-agent autonomous security testing framework",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/swarm/start", response_model=SwarmStatus, tags=["swarm"])
def start_swarm(config: SwarmConfig):
    return orchestrator.start(config)

@app.post("/swarm/stop", response_model=SwarmStatus, tags=["swarm"])
def stop_swarm():
    return orchestrator.stop()

@app.get("/swarm/status", response_model=SwarmStatus, tags=["swarm"])
def swarm_status():
    return orchestrator.get_status()

@app.get("/agents", response_model=List[AgentStatus], tags=["agents"])
def list_agents():
    return orchestrator.get_agent_statuses()

@app.get("/findings", response_model=List[Finding], tags=["findings"])
def get_findings():
    """Return all vulnerability findings, newest first."""
    findings = forum.get_findings()
    return sorted(findings, key=lambda f: f.timestamp, reverse=True)

@app.get("/findings/summary", tags=["findings"])
def findings_summary():
    findings = forum.get_findings()
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    by_type: dict = {}
    for f in findings:
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

    return {
        "total": len(findings),
        "by_severity": counts,
        "by_type": by_type,
        "confirmed": sum(1 for f in findings if f.confirmed),
    }

@app.get("/forum", response_model=List[ForumEntry], tags=["forum"])
def get_forum(limit: int = 50):
    """Return recent forum entries (agent communications)."""
    return forum.get_entries(limit)

@app.get("/logs", response_model=List[LogEntry], tags=["logs"])
def get_logs(limit: int = 100):
    """Return rolling live log feed."""
    return forum.get_logs(limit)

@app.delete("/reset", tags=["admin"])
def reset():
    orchestrator.stop()
    forum.reset()
    return {"status": "reset"}

@app.get("/health", tags=["admin"])
def health():
    return {"status": "ok"}