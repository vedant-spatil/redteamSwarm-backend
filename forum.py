"""
Shared Forum — the key architectural component from the Anthropic AAR paper.

Parallel agents read and write findings here asynchronously. This prevents
"entropy collapse" (all agents repeating the same failed attacks) by letting
agents learn from each other's successes and failures.

All state is persisted to a local JSON file so it survives agent restarts.
"""
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from models import Finding, ForumEntry, LogEntry

FORUM_PATH = Path("./state/forum.json")
FINDINGS_PATH = Path("./state/findings.json")
LOGS_PATH = Path("./state/logs.json")

MAX_LOGS = 500


class SharedForum:
    """
    Thread-safe shared forum for multi-agent communication.

    Agents write findings and observations here. Other agents read it
    before deciding what to try next — mirroring the paper's insight
    that "local access lets agents discover relevant findings they
    wouldn't have known to search for."
    """

    def __init__(self):
        self._lock = threading.Lock()
        FORUM_PATH.parent.mkdir(exist_ok=True)
        self._ensure_files()

    def _ensure_files(self):
        for path, default in [
            (FORUM_PATH, []),
            (FINDINGS_PATH, []),
            (LOGS_PATH, []),
        ]:
            if not path.exists():
                path.write_text(json.dumps(default))

    # ------------------------------------------------------------------ #
    #  Forum entries (agent observations, pivots, dead-ends)              #
    # ------------------------------------------------------------------ #

    def post(self, entry: ForumEntry):
        with self._lock:
            entries = json.loads(FORUM_PATH.read_text())
            entries.append(entry.model_dump())
            FORUM_PATH.write_text(json.dumps(entries, indent=2))

    def get_entries(self, limit: int = 50) -> List[ForumEntry]:
        with self._lock:
            raw = json.loads(FORUM_PATH.read_text())
        return [ForumEntry(**e) for e in raw[-limit:]]

    def get_summary_for_agent(self, agent_id: str) -> str:
        """
        Compact summary of recent forum activity, injected into the agent's
        system prompt. Mirrors the paper's "local agentic search" finding:
        agents should read everything rather than keyword-search.
        """
        entries = self.get_entries(30)
        if not entries:
            return "Forum is empty — you are the first agent. Start probing!"

        lines = []
        for e in entries[-20:]:
            tag = "🔴" if e.finding_id else "💬"
            other = " (YOU)" if e.agent_id == agent_id else f" [Agent-{e.agent_id[-4:]}]"
            lines.append(f"{tag}{other} [{e.focus_area}] {e.message}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    #  Vulnerability findings (graded, scored)                            #
    # ------------------------------------------------------------------ #

    def add_finding(self, finding: Finding):
        with self._lock:
            findings = json.loads(FINDINGS_PATH.read_text())
            findings.append(finding.model_dump())
            FINDINGS_PATH.write_text(json.dumps(findings, indent=2))

        # Also post a brief note to the forum so other agents see it
        self.post(ForumEntry(
            agent_id=finding.agent_id,
            focus_area=finding.vuln_type,
            message=f"[{finding.severity}] Found {finding.vuln_type}: {finding.description[:80]}",
            finding_id=finding.id,
        ))

    def get_findings(self) -> List[Finding]:
        with self._lock:
            raw = json.loads(FINDINGS_PATH.read_text())
        return [Finding(**f) for f in raw]

    def has_finding_for(self, url: str, param: Optional[str], vuln_type: str) -> bool:
        """Prevent agents from duplicating confirmed findings."""
        findings = self.get_findings()
        for f in findings:
            if f.url == url and f.vuln_type == vuln_type and f.parameter == param:
                return True
        return False

    # ------------------------------------------------------------------ #
    #  Logs (rolling window for the frontend live feed)                   #
    # ------------------------------------------------------------------ #

    def log(self, entry: LogEntry):
        with self._lock:
            logs = json.loads(LOGS_PATH.read_text())
            logs.append(entry.model_dump())
            if len(logs) > MAX_LOGS:
                logs = logs[-MAX_LOGS:]
            LOGS_PATH.write_text(json.dumps(logs, indent=2))

    def get_logs(self, limit: int = 100) -> List[LogEntry]:
        with self._lock:
            raw = json.loads(LOGS_PATH.read_text())
        return [LogEntry(**e) for e in raw[-limit:]]

    # ------------------------------------------------------------------ #
    #  Reset                                                               #
    # ------------------------------------------------------------------ #

    def reset(self):
        with self._lock:
            FORUM_PATH.write_text("[]")
            FINDINGS_PATH.write_text("[]")
            LOGS_PATH.write_text("[]")


# Module-level singleton — imported by agent.py, orchestrator.py, main.py
forum = SharedForum()