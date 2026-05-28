"""
Swarm Orchestrator.

Manages the lifecycle of parallel autonomous agents, mirroring the
paper's "team of parallel AARs" pattern. Each agent runs in its own
background thread (cheap vs. separate processes — fine for I/O-bound
LLM calls).

Key design choice from the paper:
  "Directed: assign each AAR a different research direction. This makes
   hill-climbing much faster and yields higher final PGR."

We seed each agent with a distinct focus area from FOCUS_AREAS.
"""
import threading
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from models import SwarmConfig, SwarmStatus, AgentStatus
from agent import Agent, FOCUS_AREAS
from forum import forum


class Orchestrator:
    """
    Manages N parallel agents probing a single target.
    Thread-safe — multiple FastAPI requests can call it concurrently.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._agents: Dict[str, Agent] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._config: Optional[SwarmConfig] = None
        self._start_time: Optional[str] = None
        self._running = False

    # ------------------------------------------------------------------ #
    #  Start / Stop                                                        #
    # ------------------------------------------------------------------ #

    def start(self, config: SwarmConfig) -> SwarmStatus:
        with self._lock:
            if self._running:
                self.stop()

            forum.reset()
            self._config = config
            self._agents = {}
            self._threads = {}
            self._start_time = datetime.utcnow().isoformat()
            self._running = True

        # Assign distinct focus areas (like "directed" condition in the paper)
        focus_areas = FOCUS_AREAS[:config.agent_count]
        # If more agents than focus areas, cycle
        while len(focus_areas) < config.agent_count:
            focus_areas.append(FOCUS_AREAS[len(focus_areas) % len(FOCUS_AREAS)])

        for i in range(config.agent_count):
            agent_id = f"agent-{uuid.uuid4().hex[:6]}"
            agent = Agent(
                agent_id=agent_id,
                target_url=config.target_url,
                focus_area=focus_areas[i],
                ollama_model=config.ollama_model,
                ollama_host=config.ollama_host,
            )
            t = threading.Thread(target=agent.run, daemon=True, name=agent_id)

            with self._lock:
                self._agents[agent_id] = agent
                self._threads[agent_id] = t

            t.start()

        return self.get_status()

    def stop(self) -> SwarmStatus:
        with self._lock:
            self._running = False
            for agent in self._agents.values():
                agent.stop()

        # Wait briefly for threads to notice the stop signal
        for t in self._threads.values():
            t.join(timeout=2.0)

        return self.get_status()

    # ------------------------------------------------------------------ #
    #  Status                                                              #
    # ------------------------------------------------------------------ #

    def get_status(self) -> SwarmStatus:
        with self._lock:
            agents = [a.get_status() for a in self._agents.values()]
            findings = forum.get_findings()

        return SwarmStatus(
            running=self._running,
            target_url=self._config.target_url if self._config else "",
            agent_count=len(self._agents),
            agents=agents,
            finding_count=len(findings),
            start_time=self._start_time,
        )

    def get_agent_statuses(self) -> List[AgentStatus]:
        with self._lock:
            return [a.get_status() for a in self._agents.values()]

    @property
    def is_running(self) -> bool:
        return self._running


# Module-level singleton
orchestrator = Orchestrator()